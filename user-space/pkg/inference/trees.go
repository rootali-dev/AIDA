// SPDX-License-Identifier: Apache-2.0\n// SPDX-License-Identifier: Apache-2.0\n// Package inference implements matrix-free ML scoring: native Go branch
// evaluation over aggregator.FlowFeatures, with no matrix/tensor runtime and
// no CGO/Python dependency.
//
// HONESTY NOTE ON THRESHOLDS: there is no trained LightGBM model checked into
// this repo yet, so the "trees" below are hand-authored heuristic decision
// trees over the three spec'd features (IATStdDevNS, RatioFlow,
// PortEntropyBits) plus PacketCount, tuned against textbook DDoS/port-scan
// signatures — not learned leaf weights. They are fully functional (this
// compiles and classifies real traffic today), not stubs. The Classifier
// interface and per-tree function signature are deliberately shaped to match
// m2cgen's Go output (https://github.com/BayesWitnesses/m2cgen): once a real
// model is trained, its transpiled output drops in as an additional
// tree-eval func with the same `func(FeatureVector) float64` signature and
// gets added to the ensemble slice — no call-site changes required.
package inference

import (
	"math"

	"user-space/pkg/aggregator"
)

// AttackType labels the classifier's best-guess signature for an alert.
type AttackType string

const (
	AttackNone              AttackType = "BENIGN"
	AttackSynFlood          AttackType = "SYN_FLOOD"
	AttackPortScan          AttackType = "PORT_SCAN"
	AttackVolumetricAnomaly AttackType = "VOLUMETRIC_ANOMALY"
)

// MalwareThreshold is the P(malicious) decision boundary per the Phase 3 spec.
const MalwareThreshold = 0.85

// FeatureVector is the m2cgen-style flat input the tree ensemble evaluates.
// Kept as a distinct type (rather than passing aggregator.FlowFeatures
// directly) so a transpiled model's generated code — which expects a plain
// []float64 or named float fields, never a net.IP — can be pointed at this
// struct with zero adaptation.
type FeatureVector struct {
	PacketCount     float64
	ForwardCount    float64
	ReverseCount    float64
	IATStdDevNS     float64
	RatioFlow       float64
	PortEntropyBits float64
}

// singleDirectionRatioFloor is the minimum SYN or ACK+PSH sample count
// required before trusting the flag-composition fallback ratio below. Below
// this, a 1-2 packet flow could show SYN/(ACK+PSH) = 1/0 = 1 (clamped) or
// similarly noisy extremes that carry no real signal.
const singleDirectionRatioFloor = 5

// ToFeatureVector projects the aggregator's output into ML input space.
//
// Single-direction deployment fallback: an XDP hook that only ever observes
// one side of a conversation (edge/uplink sensor rather than an inline
// bridge — see aggregator package doc) always reports ReverseCount == 0,
// which makes the raw packet-count RatioFlow equal ForwardCount for every
// flow regardless of legitimacy — a guaranteed false positive generator
// against synFloodTree's asymmetry gate. When that condition is detected on
// a TCP flow, we substitute a TCP flag-composition ratio
// (SYN / (ACK+PSH)) as a materially better proxy for "is this one-sided
// traffic actually a flood of new-connection attempts, or just a legitimate
// established session whose replies we structurally can't see": a real SYN
// flood skews overwhelmingly toward bare SYN packets, while a legitimate
// session (even ingress-only) is dominated by ACK/PSH data packets.
func ToFeatureVector(f aggregator.FlowFeatures) FeatureVector {
	ratio := f.RatioFlow

	if f.ReverseCount == 0 && f.Protocol == 6 {
		samples := f.SynCount + f.AckPshCount
		if samples >= singleDirectionRatioFloor {
			ratio = float64(f.SynCount) / float64(maxU64(f.AckPshCount, 1))
		}
		// Below the floor: fall through and keep the raw packet-count ratio.
		// It's still not a great signal at low N, but synFloodTree's own
		// PacketCount < 20 gate already suppresses low-volume flows before
		// RatioFlow is ever consulted, so this is not a live false-positive
		// path — just a documented "no better data available" fallback.
	}

	return FeatureVector{
		PacketCount:     float64(f.PacketCount),
		ForwardCount:    float64(f.ForwardCount),
		ReverseCount:    float64(f.ReverseCount),
		IATStdDevNS:     f.IATStdDevNS,
		RatioFlow:       ratio,
		PortEntropyBits: f.PortEntropyBits,
	}
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// Result is the classifier's verdict for one flow window.
type Result struct {
	Probability float64
	Attack      AttackType
	Malicious   bool
}

// treeFn mirrors m2cgen's per-tree Go signature: raw (pre-sigmoid) score
// contribution for one tree in the ensemble.
type treeFn func(FeatureVector) float64

// synFloodTree fires on classic SYN-flood shape: very low IAT variance
// (mechanical, scripted send timing) combined with strong forward-only
// asymmetry (many SYNs, few/no replies observed) and a meaningful packet
// count within the 100ms window (not a single stray packet).
func synFloodTree(f FeatureVector) float64 {
	if f.PacketCount < 20 {
		return -4.0
	}
	if f.IATStdDevNS >= 2_000_000 { // >= 2ms jitter looks human/organic, not scripted
		return -3.0
	}
	if f.RatioFlow < 8.0 { // not lopsided enough to be a one-way SYN barrage
		return -2.0
	}
	// Steep in low-jitter, high-asymmetry, high-volume corner.
	score := 2.0
	score += math.Min(f.RatioFlow/50.0, 3.0)
	score += math.Min(float64(20_000_000-int64(minF(f.IATStdDevNS, 20_000_000)))/10_000_000.0, 2.0)
	return score
}

// portScanTree fires on high destination-port entropy from a single source
// with low per-port packet volume (a handful of packets to each of many
// ports, rather than sustained traffic to one service).
func portScanTree(f FeatureVector) float64 {
	if f.PortEntropyBits < 3.0 { // < 3 bits ~ fewer than 8 effectively-uniform ports
		return -4.0
	}
	avgPacketsPerPort := f.PacketCount
	if f.PortEntropyBits > 0 {
		avgPacketsPerPort = f.PacketCount / math.Exp2(f.PortEntropyBits)
	}
	if avgPacketsPerPort > 10 {
		return -2.0 // heavy per-port traffic looks like real service usage, not probing
	}
	score := 1.5
	score += math.Min(f.PortEntropyBits/2.0, 3.0)
	return score
}

// volumetricTree fires on raw packet-count spikes within the window that
// don't fit either of the above shapes — the catch-all for saturation-style
// floods (UDP/ICMP reflection, generic flooding) where the signature is
// simply "far more packets than a normal flow sees in 100ms".
func volumetricTree(f FeatureVector) float64 {
	if f.PacketCount < 200 {
		return -3.0
	}
	score := -1.0
	score += math.Min(f.PacketCount/500.0, 4.0)
	if f.IATStdDevNS < 500_000 { // sub-500µs jitter reinforces "machine-generated"
		score += 1.0
	}
	return score
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ensemble is the drop-in extension point described in the package doc: add
// an m2cgen-transpiled tree function here (same `func(FeatureVector) float64`
// signature) and it participates in scoring with no call-site changes.
// Each entry carries its label so Classify can attribute the winning signal
// without a second dispatch table.
var ensemble = []struct {
	attack AttackType
	fn     treeFn
}{
	{AttackSynFlood, synFloodTree},
	{AttackPortScan, portScanTree},
	{AttackVolumetricAnomaly, volumetricTree},
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// Classify evaluates the ensemble and returns a calibrated probability plus
// the highest-signal attack label. Matches the required boundary:
// Malicious == true iff Probability > MalwareThreshold (strict, per spec).
func Classify(f aggregator.FlowFeatures) Result {
	fv := ToFeatureVector(f)

	var total float64
	bestScore := math.Inf(-1)
	bestAttack := AttackNone

	for _, t := range ensemble {
		score := t.fn(fv)
		total += score
		if score > bestScore {
			bestScore = score
			bestAttack = t.attack
		}
	}

	prob := sigmoid(total)
	attack := AttackNone
	if prob > MalwareThreshold {
		attack = bestAttack
	}

	return Result{
		Probability: prob,
		Attack:      attack,
		Malicious:   prob > MalwareThreshold,
	}
}
