// SPDX-License-Identifier: Apache-2.0\n// SPDX-License-Identifier: Apache-2.0\n// Package aggregator implements the Phase 3 rolling-window flow aggregator.
//
// DESIGN NOTE — telemetry visibility (read before tuning thresholds):
// kernel-space/src/main.rs::emit_and_return() gates ALL ring buffer emission
// (including clean XDP_PASS packets, DropReason::None) behind CONFIG_MAP's
// severity threshold, and additionally throttles EVENTS to a hard cap of
// ~10,000 records/sec sustained (100µs/token) with a 1,000-record burst
// (LOG_RATE_LIMIT_MAP in kernel-space/src/main.rs). Two implications:
//
//  1. The consuming daemon MUST set CONFIG_MAP to LogLevelDebug (severity 1),
//     not Info/Warn/Error, or DropReason::None (clean-pass) packets never
//     reach this aggregator and every feature below silently degrades to
//     "violations only" — useless for baseline IATStdDev/PortEntropy.
//  2. Under genuine line-rate attack, EVENTS delivers a RATE-LIMITED SAMPLE
//     of the true packet stream, not an exact trace. PacketCount/ForwardCount/
//     ReverseCount below are sample counts within the kernel's logging budget,
//     not literal line-rate packet counts. Treat FlowFeatures as a proxy
//     signal for the ML layer, not an audited counter.
package aggregator

import (
	"context"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"user-space/pkg/types"
)

// WindowInterval is the rolling aggregation window per the Phase 3 spec.
const WindowInterval = 100 * time.Millisecond

// Cardinality bounds. A source-fanning attacker can generate millions of
// unique 5-tuples per second; without a cap, map growth becomes the DoS
// vector against the control plane itself. Once a shard is saturated, NEW
// flow keys are silently not tracked for that window (existing flows keep
// accumulating normally) — this mirrors the kernel's fail-open posture on
// malformed packets: bounded memory takes priority over exhaustive tracking.
const (
	numShards        = 16
	maxFlowsPerShard = 16384 // 16 * 16384 = 262,144 concurrently tracked flows/window
	maxPortsPerSrcIP = 256   // distinct dst ports tracked per source IP before overflow bucket
	overflowPortKey  = 0xFFFF
	outputBufferSize = 4096

	// minIATSamplesForVariance guards against small-sample variance collapse.
	// Welford's algorithm is statistically unreliable at low N: a 2-5 packet
	// health-check probe or an HTTP/2 multiplexed burst can produce a
	// near-zero IAT std-dev purely from having too few samples to show real
	// spread, not because the sender is a mechanically-timed bot. Below this
	// threshold we report a neutral baseline instead of the (misleading)
	// computed value — see neutralIATStdDevNS.
	minIATSamplesForVariance = 30

	// neutralIATStdDevNS is returned in place of a statistically unreliable
	// low-N variance estimate. Chosen comfortably above synFloodTree's ~2ms
	// suspicion threshold (inference/trees.go) so an under-sampled flow reads
	// as "jittered/organic" by default rather than "mechanically periodic" —
	// i.e. the guard fails open toward NOT flagging, which is the correct
	// direction for a false-positive remediation control.
	neutralIATStdDevNS = 5_000_000.0 // 5ms

	// TCP control-flag bit values (mirrors common::tcp_flags on the Rust
	// side) used to derive the SYN / (ACK+PSH) fallback ratio in inference.
	tcpFlagSYN = 0x02
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10

	protocolTCP = 6
)

// FlowKey is the canonical, direction-independent 5-tuple. Both directions of
// a single conversation (A:sport->B:dport and its reply B:dport->A:sport)
// hash to the same bucket by sorting on (IP, port).
//
// ASSUMPTION (state if wrong): AI-IDA is deployed inline (bridge/router
// placement) such that a single XDP ingress hook observes both directions of
// a flow traversing the interface. If instead this is an edge/uplink-only
// sensor that only ever sees one direction, ReverseCount will stay ~0 for
// every flow and RatioFlow degenerates to ForwardCount/1 — still usable as a
// volumetric signal, just not a literal inbound:outbound ratio. Adjust the
// canonicalization below (e.g. keying on ingress ifindex instead of IP
// ordering) if that's the real topology.
type FlowKey struct {
	IPLo, IPHi     uint32
	PortLo, PortHi uint16
	Protocol       uint8
}

func canonicalize(m *types.FlowPacketMeta) (key FlowKey, srcIsLo bool) {
	if m.SrcIP < m.DstIP || (m.SrcIP == m.DstIP && m.SrcPort <= m.DstPort) {
		return FlowKey{IPLo: m.SrcIP, IPHi: m.DstIP, PortLo: m.SrcPort, PortHi: m.DstPort, Protocol: m.Protocol}, true
	}
	return FlowKey{IPLo: m.DstIP, IPHi: m.SrcIP, PortLo: m.DstPort, PortHi: m.SrcPort, Protocol: m.Protocol}, false
}

// shardIndex is a cheap multiplicative mix (Knuth's constant) — no
// allocation, no hash.Hash boxing, adequate distribution for shard routing.
func (k FlowKey) shardIndex() uint32 {
	h := k.IPLo*2654435761 ^ k.IPHi*40503 ^ uint32(k.PortLo)<<16 ^ uint32(k.PortHi) ^ uint32(k.Protocol)
	return h % numShards
}

func srcIPShardIndex(srcIP uint32) uint32 {
	return (srcIP * 2654435761) % numShards
}

// flowAccumulator holds streaming state for one canonical flow across the
// current window. IAT variance is computed online via Welford's algorithm
// (O(1) memory, single pass) rather than buffering timestamps — required
// discipline given a single flow can legitimately see thousands of packets
// inside a 100ms window.
type flowAccumulator struct {
	firstSrcIP, firstDstIP     uint32
	firstSrcPort, firstDstPort uint16
	protocol                   uint8

	packetCount    uint64
	forwardCount   uint64
	reverseCount   uint64
	synCount       uint64 // TCP packets with SYN set (any ACK state)
	ackPshCount    uint64 // TCP packets with ACK or PSH set — established/data traffic
	lastTimestamp  uint64 // 0 == unset
	iatMean, iatM2 float64
	iatSamples     uint64
}

func (fa *flowAccumulator) observe(m *types.FlowPacketMeta, srcIsLo bool) {
	if fa.packetCount == 0 {
		fa.firstSrcIP = m.SrcIP
		fa.firstDstIP = m.DstIP
		fa.firstSrcPort = m.SrcPort
		fa.firstDstPort = m.DstPort
		fa.protocol = m.Protocol
	}
	fa.packetCount++
	if srcIsLo {
		fa.forwardCount++
	} else {
		fa.reverseCount++
	}

	if m.Protocol == protocolTCP {
		if m.TCPFlags&tcpFlagSYN != 0 {
			fa.synCount++
		}
		if m.TCPFlags&(tcpFlagACK|tcpFlagPSH) != 0 {
			fa.ackPshCount++
		}
	}

	if fa.lastTimestamp != 0 && m.TimestampNS > fa.lastTimestamp {
		iat := float64(m.TimestampNS - fa.lastTimestamp)
		fa.iatSamples++
		delta := iat - fa.iatMean
		fa.iatMean += delta / float64(fa.iatSamples)
		delta2 := iat - fa.iatMean
		fa.iatM2 += delta * delta2
	}
	fa.lastTimestamp = m.TimestampNS
}

func (fa *flowAccumulator) iatStdDevNS() float64 {
	if fa.iatSamples < minIATSamplesForVariance {
		return neutralIATStdDevNS
	}
	variance := fa.iatM2 / float64(fa.iatSamples)
	if variance < 0 {
		return 0
	}
	return math.Sqrt(variance)
}

// portTracker accumulates the distribution of distinct destination ports
// touched by a single source IP within the current window, feeding the
// Shannon entropy feature (port-scan signature: many ports, near-uniform
// distribution -> high entropy; single-service flow: entropy 0).
type portTracker struct {
	counts map[uint16]uint32
	total  uint32
}

func newPortTracker() *portTracker {
	return &portTracker{counts: make(map[uint16]uint32, 8)}
}

func (pt *portTracker) observe(dstPort uint16) {
	pt.total++
	if _, ok := pt.counts[dstPort]; ok {
		pt.counts[dstPort]++
		return
	}
	if len(pt.counts) >= maxPortsPerSrcIP {
		pt.counts[overflowPortKey]++
		return
	}
	pt.counts[dstPort] = 1
}

func (pt *portTracker) entropyBits() float64 {
	if pt.total == 0 {
		return 0
	}
	var h float64
	total := float64(pt.total)
	for _, c := range pt.counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// FlowFeatures is the feature vector handed to the inference engine at the
// close of each 100ms window.
type FlowFeatures struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Protocol         uint8
	PacketCount      uint64 // sample count within kernel's log-rate budget — see package doc
	ForwardCount     uint64
	ReverseCount     uint64
	SynCount         uint64 // TCP SYN packets observed this window (0 for non-TCP flows)
	AckPshCount      uint64 // TCP ACK|PSH packets observed this window (0 for non-TCP flows)
	IATStdDevNS      float64
	RatioFlow        float64 // ForwardCount / max(ReverseCount, 1); see inference.ToFeatureVector for the single-direction SYN/(ACK+PSH) fallback layered on top
	PortEntropyBits  float64 // entropy of dst ports touched by SrcIP this window
	WindowStart      time.Time
	WindowEnd        time.Time
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

type shard struct {
	mu    sync.Mutex
	flows map[FlowKey]*flowAccumulator
}

type portShard struct {
	mu    sync.Mutex
	ports map[uint32]*portTracker // keyed by source IP
}

// Aggregator consumes FlowPacketMeta records and emits FlowFeatures at each
// window boundary. Safe for concurrent Ingest calls; intended usage is one
// ring-buffer reader goroutine calling Ingest and a single internal ticker
// goroutine performing the flush (started by Run).
type Aggregator struct {
	flowShards [numShards]*shard
	portShards [numShards]*portShard

	out chan FlowFeatures

	windowStart time.Time
	winMu       sync.Mutex

	droppedNewFlows uint64 // atomic
	droppedOutput   uint64 // atomic
}

// NewAggregator constructs an aggregator ready for Ingest/Run.
func NewAggregator() *Aggregator {
	a := &Aggregator{
		out:         make(chan FlowFeatures, outputBufferSize),
		windowStart: time.Now(),
	}
	for i := 0; i < numShards; i++ {
		a.flowShards[i] = &shard{flows: make(map[FlowKey]*flowAccumulator, maxFlowsPerShard/4)}
		a.portShards[i] = &portShard{ports: make(map[uint32]*portTracker, 256)}
	}
	return a
}

// Output returns the channel of completed-window flow feature vectors.
func (a *Aggregator) Output() <-chan FlowFeatures {
	return a.out
}

// DroppedNewFlows reports how many previously-unseen 5-tuples were rejected
// this run due to per-shard cardinality caps (observability, not an error).
func (a *Aggregator) DroppedNewFlows() uint64 {
	return atomic.LoadUint64(&a.droppedNewFlows)
}

// DroppedOutput reports how many completed FlowFeatures were discarded
// because the output channel was full (consumer falling behind).
func (a *Aggregator) DroppedOutput() uint64 {
	return atomic.LoadUint64(&a.droppedOutput)
}

// Ingest records one telemetry frame. Non-blocking, allocation-light on the
// hot path (map lookups only; a *flowAccumulator/*portTracker is allocated
// only the first time a given key is seen within a window).
func (a *Aggregator) Ingest(m *types.FlowPacketMeta) {
	key, srcIsLo := canonicalize(m)
	fs := a.flowShards[key.shardIndex()]

	fs.mu.Lock()
	fa, ok := fs.flows[key]
	if !ok {
		if len(fs.flows) >= maxFlowsPerShard {
			fs.mu.Unlock()
			atomic.AddUint64(&a.droppedNewFlows, 1)
			return
		}
		fa = &flowAccumulator{}
		fs.flows[key] = fa
	}
	fa.observe(m, srcIsLo)
	fs.mu.Unlock()

	ps := a.portShards[srcIPShardIndex(m.SrcIP)]
	ps.mu.Lock()
	pt, ok := ps.ports[m.SrcIP]
	if !ok {
		pt = newPortTracker()
		ps.ports[m.SrcIP] = pt
	}
	pt.observe(m.DstPort)
	ps.mu.Unlock()
}

// Run drives the 100ms flush loop until ctx is cancelled, then performs a
// final flush and closes the output channel.
func (a *Aggregator) Run(ctx context.Context) {
	ticker := time.NewTicker(WindowInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-ctx.Done():
			a.flush()
			close(a.out)
			return
		}
	}
}

func (a *Aggregator) flush() {
	windowEnd := time.Now()

	a.winMu.Lock()
	windowStart := a.windowStart
	a.windowStart = windowEnd
	a.winMu.Unlock()

	// Snapshot and reset port trackers first so entropy lookups below see
	// this window's distribution, not the next window's partial data.
	portSnapshot := make(map[uint32]*portTracker, 256)
	for i := 0; i < numShards; i++ {
		ps := a.portShards[i]
		ps.mu.Lock()
		for ip, pt := range ps.ports {
			portSnapshot[ip] = pt
		}
		ps.ports = make(map[uint32]*portTracker, 256)
		ps.mu.Unlock()
	}

	for i := 0; i < numShards; i++ {
		fs := a.flowShards[i]
		fs.mu.Lock()
		flows := fs.flows
		fs.flows = make(map[FlowKey]*flowAccumulator, maxFlowsPerShard/4)
		fs.mu.Unlock()

		for _, fa := range flows {
			var entropy float64
			if pt, ok := portSnapshot[fa.firstSrcIP]; ok {
				entropy = pt.entropyBits()
			}

			ff := FlowFeatures{
				SrcIP:           u32ToIP(fa.firstSrcIP),
				DstIP:           u32ToIP(fa.firstDstIP),
				SrcPort:         fa.firstSrcPort,
				DstPort:         fa.firstDstPort,
				Protocol:        fa.protocol,
				PacketCount:     fa.packetCount,
				ForwardCount:    fa.forwardCount,
				ReverseCount:    fa.reverseCount,
				SynCount:        fa.synCount,
				AckPshCount:     fa.ackPshCount,
				IATStdDevNS:     fa.iatStdDevNS(),
				RatioFlow:       float64(fa.forwardCount) / float64(max64(fa.reverseCount, 1)),
				PortEntropyBits: entropy,
				WindowStart:     windowStart,
				WindowEnd:       windowEnd,
			}

			select {
			case a.out <- ff:
			default:
				atomic.AddUint64(&a.droppedOutput, 1)
			}
		}
	}
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
