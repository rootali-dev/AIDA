package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"user-space/pkg/inference"
)

// BlockTTL bounds how long a triggered auto-block is trusted as "already
// applied" before the feedback controller is willing to re-push it to
// REPUTATION_MAP. This is a dedup window, not an unblock timer — AI-IDA
// currently has no auto-expiry path; TTL expiry here only means "the next
// alert for this IP will re-issue BlockIP" (idempotent — a repeat Put on an
// already-blocked LPM key is a cheap no-op on the kernel side).
const BlockTTL = 5 * time.Minute

// dedupSweepInterval bounds memory growth of the TTL cache under a sustained
// large-cardinality attack (many distinct offending source IPs).
const dedupSweepInterval = 1 * time.Minute

// ThreatAlert is emitted by the inference stage when P(malicious) crosses
// inference.MalwareThreshold for a completed flow window.
type ThreatAlert struct {
	SrcIP       string // dotted-quad, ready for MapManager.BlockIP as a /32
	Attack      inference.AttackType
	Probability float64
	DetectedAt  time.Time
}

// FeedbackController closes the loop: ML alert -> dedup -> kernel block.
// Per the spec's "under 1ms" latency requirement, the hot path is a single
// mutex-guarded map lookup plus one ebpf.Map.Put — no I/O beyond the BPF
// syscall itself, no allocation beyond the LpmIpv4Key already required by
// MapManager.BlockIP.
type FeedbackController struct {
	mgr *MapManager

	mu      sync.Mutex
	blocked map[string]time.Time // srcIP -> expiry of "already handled" window

	OnBlock func(alert ThreatAlert) // optional hook for logging/metrics; may be nil
}

// NewFeedbackController wires the controller to an already-loaded MapManager
// (see LoadPinnedMaps). mgr must outlive the controller.
func NewFeedbackController(mgr *MapManager) *FeedbackController {
	return &FeedbackController{
		mgr:     mgr,
		blocked: make(map[string]time.Time, 1024),
	}
}

// Run consumes alerts until ctx is cancelled or the alerts channel closes.
// Each alert is deduplicated against the TTL cache, then applied to the
// kernel's REPUTATION_MAP via MapManager.BlockIP as a /32 host route.
func (fc *FeedbackController) Run(ctx context.Context, alerts <-chan ThreatAlert) {
	sweep := time.NewTicker(dedupSweepInterval)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			fc.sweepExpired()
		case alert, ok := <-alerts:
			if !ok {
				return
			}
			fc.handle(alert)
		}
	}
}

func (fc *FeedbackController) handle(alert ThreatAlert) {
	now := time.Now()

	fc.mu.Lock()
	if expiry, seen := fc.blocked[alert.SrcIP]; seen && now.Before(expiry) {
		fc.mu.Unlock()
		return // already blocked within TTL window — skip redundant kernel write
	}
	fc.blocked[alert.SrcIP] = now.Add(BlockTTL)
	fc.mu.Unlock()

	cidr := alert.SrcIP + "/32"
	if err := fc.mgr.BlockIP(cidr); err != nil {
		// Fail visibly rather than silently dropping the mitigation — do not
		// remove the dedup entry, since retry-storming a failing map write
		// is worse than a delayed manual retry.
		fmt.Printf("❌ [AI-IDA] Closed-loop block FAILED for %s (%s, P=%.3f): %v\n",
			alert.SrcIP, alert.Attack, alert.Probability, err)
		return
	}

	if fc.OnBlock != nil {
		fc.OnBlock(alert)
	} else {
		fmt.Printf("⛔ [AI-IDA] Auto-blocked %s — %s (P=%.3f)\n", cidr, alert.Attack, alert.Probability)
	}
}

func (fc *FeedbackController) sweepExpired() {
	now := time.Now()
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for ip, expiry := range fc.blocked {
		if now.After(expiry) {
			delete(fc.blocked, ip)
		}
	}
}
