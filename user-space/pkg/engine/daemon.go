// SPDX-License-Identifier: Apache-2.0\n// SPDX-License-Identifier: Apache-2.0\npackage engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"

	"user-space/pkg/aggregator"
	"user-space/pkg/inference"
	"user-space/pkg/types"
)

// alertBufferSize bounds the inference->feedback channel. Sized generously
// relative to the kernel's own 10k events/sec ring-buffer cap (see
// aggregator package doc) — even a pathological window producing an alert
// for every tracked flow can't realistically exceed this before the
// feedback goroutine drains it (a single map Put is µs-scale).
const alertBufferSize = 1024

// RunDaemon orchestrates the full Phase 3 closed loop:
//
//	EVENTS ringbuf -> Aggregator (100ms windows) -> inference.Classify
//	                                                     |
//	                                                     v (P > 0.85)
//	                                          FeedbackController -> REPUTATION_MAP
//
// It blocks until ctx is cancelled or a fatal setup error occurs, and
// restores CONFIG_MAP's log level to its pre-daemon value on exit — mirrors
// MonitorEvents' cleanup discipline so `daemon` and `monitor` never fight
// over runtime state.
func RunDaemon(ctx context.Context, mgr *MapManager) error {
	prevLevel, err := mgr.GetLogLevel()
	if err != nil {
		prevLevel = types.LogLevelOff
	}

	// Full telemetry, including clean XDP_PASS packets, is required — the
	// aggregator's baseline features (IATStdDev, PortEntropy) are meaningless
	// if EVENTS only ever carries violations. See aggregator package doc.
	if err := mgr.SetLogLevel(types.LogLevelDebug); err != nil {
		return fmt.Errorf("failed to enable full telemetry (CONFIG_MAP -> debug): %w", err)
	}
	defer func() {
		_ = mgr.SetLogLevel(prevLevel)
	}()

	eventsMap := mgr.GetEventsMap()
	if eventsMap == nil {
		return fmt.Errorf("events ring buffer map is nil")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("failed to open eBPF ring buffer reader: %w", err)
	}
	defer reader.Close()

	daemonCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case sig := <-sigChan:
			fmt.Printf("\n🛑 [AI-IDA] Received signal %v. Draining pipeline and restoring log level...\n", sig)
			reader.Close()
			cancel()
		case <-daemonCtx.Done():
			reader.Close()
		}
	}()

	agg := aggregator.NewAggregator()
	alerts := make(chan ThreatAlert, alertBufferSize)
	feedback := NewFeedbackController(mgr)

	var wg sync.WaitGroup

	// Aggregation window driver.
	wg.Add(1)
	go func() {
		defer wg.Done()
		agg.Run(daemonCtx)
	}()

	// Inference stage: FlowFeatures -> Classify -> ThreatAlert.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(alerts)
		for ff := range agg.Output() {
			result := inference.Classify(ff)
			if !result.Malicious {
				continue
			}
			select {
			case alerts <- ThreatAlert{
				SrcIP:       ff.SrcIP.String(),
				Attack:      result.Attack,
				Probability: result.Probability,
				DetectedAt:  ff.WindowEnd,
			}:
			case <-daemonCtx.Done():
				return
			}
		}
	}()

	// Closed-loop feedback: ThreatAlert -> REPUTATION_MAP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		feedback.Run(daemonCtx, alerts)
	}()

	fmt.Println("================================================================================")
	fmt.Println("🧠 AI-IDA Phase 3 — Autonomous Defense Agent")
	fmt.Println("📡 Telemetry   : /sys/fs/bpf/ai_ida/events (full trace, log-level=debug)")
	fmt.Printf("⏱️  Window      : %s rolling aggregation\n", aggregator.WindowInterval)
	fmt.Printf("🎯 Threshold   : P(malicious) > %.2f\n", inference.MalwareThreshold)
	fmt.Println("⛔ Auto-block  : REPUTATION_MAP (LPM_TRIE), /32 host blocks")
	fmt.Println("🛑 Press Ctrl-C to detach and cleanly restore log level")
	fmt.Println("================================================================================")

	var meta types.FlowPacketMeta
readLoop:
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break readLoop
			}
			select {
			case <-daemonCtx.Done():
				break readLoop
			default:
				fmt.Fprintf(os.Stderr, "⚠️ [AI-IDA] Ring buffer read error: %v\n", err)
				continue
			}
		}

		if err := meta.UnmarshalBinary(record.RawSample); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ [AI-IDA] Failed to unmarshal telemetry frame (%d bytes): %v\n", len(record.RawSample), err)
			continue
		}

		agg.Ingest(&meta)
	}

	cancel()
	wg.Wait()

	dropped := agg.DroppedNewFlows()
	droppedOut := agg.DroppedOutput()
	if dropped > 0 || droppedOut > 0 {
		fmt.Printf("ℹ️  [AI-IDA] Shutdown stats — flows dropped (cardinality cap): %d, features dropped (consumer backpressure): %d\n",
			dropped, droppedOut)
	}

	return nil
}
