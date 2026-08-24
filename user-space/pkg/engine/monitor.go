package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"user-space/pkg/types"

	"github.com/cilium/ebpf/ringbuf"
)

// MonitorEvents starts streaming telemetry from the eBPF ring buffer and demuxes reasons.
func MonitorEvents(ctx context.Context, mgr *MapManager, targetLevel types.LogSeverity) error {
	// 1. Read existing log level to know previous state
	prevLevel, err := mgr.GetLogLevel()
	if err != nil {
		prevLevel = types.LogLevelOff
	}

	// 2. Set active log level in BPF CONFIG_MAP
	if err := mgr.SetLogLevel(targetLevel); err != nil {
		return fmt.Errorf("failed to enable runtime log level in eBPF config map: %w", err)
	}

	// Ensure log level is cleanly restored to OFF on return
	defer func() {
		_ = mgr.SetLogLevel(types.LogLevelOff)
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

	// 3. Set up signal handling for clean teardown on SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	stopChan := make(chan struct{})
	go func() {
		select {
		case sig := <-sigChan:
			fmt.Printf("\n🛑 [AI-IDA] Received signal %v. Restoring log level to OFF and exiting...\n", sig)
			reader.Close()
			close(stopChan)
		case <-ctx.Done():
			reader.Close()
			close(stopChan)
		}
	}()

	fmt.Println("================================================================================")
	fmt.Println("📡 AI-IDA Telemetry & Dynamic Observability Stream")
	fmt.Printf("🎯 Active Log Level : %s (Threshold: %d | Previous: %s)\n", targetLevel.String(), targetLevel, prevLevel.String())
	fmt.Println("🌊 RingBuffer Map   : /sys/fs/bpf/ai_ida/events (1 MB)")
	fmt.Println("🛑 Press Ctrl-C to detach telemetry consumer and cleanly restore log level")
	fmt.Println("================================================================================")
	fmt.Println("TIMESTAMP       SEVERITY ACTION  FLOW                                    PROTOCOL FLAGS     REASON")
	fmt.Println("---------       -------- ------  ----                                    -------- -----     ------")

	var meta types.FlowPacketMeta
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// Reader was closed cleanly
				break
			}
			select {
			case <-stopChan:
				return nil
			default:
				fmt.Fprintf(os.Stderr, "⚠️ [AI-IDA] Ring buffer read error: %v\n", err)
				continue
			}
		}

		if err := meta.UnmarshalBinary(record.RawSample); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ [AI-IDA] Failed to unmarshal telemetry frame (%d bytes): %v\n", len(record.RawSample), err)
			continue
		}

		reason := types.DropReason(meta.DropReason)
		severity := reason.Severity()

		// Out-of-band severity verification against active threshold
		if severity < targetLevel {
			continue
		}

		action := types.Action(meta.Action)
		flowStr := fmt.Sprintf("%s:%d -> %s:%d",
			meta.SrcIPNet().String(), meta.SrcPort,
			meta.DstIPNet().String(), meta.DstPort,
		)

		fmt.Printf("%s %s %s  %-39s %-8s %-9s %s\n",
			meta.FormattedTime(),
			severity.ColoredPrefix(),
			action.ColoredBadge(),
			flowStr,
			meta.ProtocolName(),
			meta.TCPFlagsString(),
			reason.String(),
		)
	}

	return nil
}
