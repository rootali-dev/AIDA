package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"user-space/pkg/inference"
)

// BlockTTL is the lifetime of a dynamic, ML-triggered auto-block before the
// TTL Janitor calls MapManager.UnblockIP on it. Per TC-08, this is a real
// expiry (the kernel entry is actually removed), not just a dedup window —
// AI-IDA has no other unblock path, so without this every auto-block would
// be a permanent lockout.
const BlockTTL = 300 * time.Second

// janitorInterval is the sweep cadence for both TTL expiry and dedup-cache
// pruning. 30s gives at most a 30s delay past the nominal 300s TTL before an
// IP is actually unblocked — an acceptable resolution for a 5-minute window,
// and cheap even under a large-cardinality attack (a single map iteration +
// only the genuinely-expired subset triggers a kernel call).
const janitorInterval = 30 * time.Second

// ThreatAlert is emitted by the inference stage when P(malicious) crosses
// inference.MalwareThreshold for a completed flow window.
type ThreatAlert struct {
	SrcIP       string // dotted-quad, ready for MapManager.BlockIP as a /32
	Attack      inference.AttackType
	Probability float64
	DetectedAt  time.Time
}

// ---------------------------------------------------------------------------
// STATIC_SAFE_NETWORKS
// ---------------------------------------------------------------------------

// staticSafeNetworks holds CIDRs that are safe on every possible deployment,
// independent of local topology: loopback, the all-hosts broadcast address,
// and the entire multicast range. These never change at runtime.
var staticSafeNetworks = mustParseCIDRs(
	"127.0.0.0/8",        // Loopback
	"255.255.255.255/32", // Limited broadcast
	"224.0.0.0/4",        // Multicast (Class D)
)

// wellKnownPublicDNS covers the common public resolvers explicitly named in
// the spec. This is deliberately a short, explicit allowlist rather than an
// attempt to enumerate "all DNS providers" — anything else legitimate is
// expected to be covered by the dynamic local-resolver discovery below.
var wellKnownPublicDNS = mustParseCIDRs(
	"8.8.8.8/32", "8.8.4.4/32", // Google
	"1.1.1.1/32", "1.0.0.1/32", // Cloudflare
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			// These are compile-time-constant, hand-written CIDRs; a parse
			// failure here is a programming error, not a runtime condition.
			panic(fmt.Sprintf("ai-ida: invalid static safe network %q: %v", c, err))
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// DiscoverSafeNetworks builds the full infrastructure-protection registry:
// the static set above, plus deployment-specific entries resolved at
// startup via netlink and /etc/resolv.conf:
//   - Default gateway (the next-hop for the default route)
//   - Every local interface's assigned subnet
//   - The system's configured DNS resolver(s)
//
// This is the userspace half of TC-07 (infrastructure protection); it is
// defense-in-depth on top of whatever the ML pipeline decides, since a
// naturally very regular polling pattern (e.g. a local Prometheus scraper,
// TC-05) is exactly the shape the SYN/volumetric trees are least equipped to
// distinguish from a slow, deliberate probe.
func DiscoverSafeNetworks() ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, 32)
	nets = append(nets, staticSafeNetworks...)
	nets = append(nets, wellKnownPublicDNS...)

	if gw, err := discoverDefaultGateway(); err == nil && gw != nil {
		nets = append(nets, hostCIDR(gw))
	}

	if subnets, err := discoverLocalSubnets(); err == nil {
		nets = append(nets, subnets...)
	}

	if resolvers, err := discoverLocalResolvers(); err == nil {
		nets = append(nets, resolvers...)
	}

	return nets, nil
}

// hostCIDR wraps a single IP as a /32 (or /128 for IPv6) net.IPNet.
func hostCIDR(ip net.IP) *net.IPNet {
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func discoverDefaultGateway() (net.IP, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("netlink route list failed: %w", err)
	}
	for _, r := range routes {
		if r.Dst == nil && r.Gw != nil {
			return r.Gw, nil
		}
	}
	return nil, fmt.Errorf("no default route found")
}

// discoverLocalSubnets enumerates every non-loopback interface's assigned
// IPv4 subnets. net.IPNet.Contains() checks membership via the mask
// regardless of whether the stored IP is a host address or the network
// address, so using the interface's own address+prefix directly (rather
// than recomputing the network address) is correct.
func discoverLocalSubnets() ([]*net.IPNet, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("netlink link list failed: %w", err)
	}

	var subnets []*net.IPNet
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			continue // best-effort per-interface; one bad link shouldn't abort discovery
		}
		for _, addr := range addrs {
			if addr.IPNet == nil || addr.IP.IsLoopback() {
				continue
			}
			subnets = append(subnets, addr.IPNet)
		}
	}
	return subnets, nil
}

// discoverLocalResolvers parses /etc/resolv.conf for "nameserver" lines.
// Best-effort: a missing or malformed file yields an empty (not error)
// result, since resolv.conf's absence doesn't invalidate the rest of the
// safe-network registry.
func discoverLocalResolvers() ([]*net.IPNet, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var resolvers []*net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil {
				resolvers = append(resolvers, hostCIDR(ip))
			}
		}
	}
	return resolvers, nil
}

// ---------------------------------------------------------------------------
// FeedbackController
// ---------------------------------------------------------------------------

// blockRecord tracks one currently-active dynamic block for the TTL Janitor.
type blockRecord struct {
	expiresAt time.Time
}

// FeedbackController closes the loop: ML alert -> safe-network check ->
// dedup -> kernel block, with a background Janitor that reverses expired
// blocks. Per the spec's "under 1ms" latency requirement, the alert hot path
// is a mutex-guarded map lookup plus one ebpf.Map.Put — no I/O beyond the BPF
// syscall itself.
type FeedbackController struct {
	mgr *MapManager

	safeNetworks   []*net.IPNet
	safeNetworksMu sync.RWMutex

	mu      sync.Mutex
	blocked map[string]blockRecord // srcIP -> active block record

	OnBlock   func(alert ThreatAlert)                 // optional hook for logging/metrics; may be nil
	OnUnblock func(srcIP string)                      // optional hook fired by the Janitor; may be nil
	OnExempt  func(alert ThreatAlert, net *net.IPNet) // optional hook fired on a safe-network exemption; may be nil
}

// NewFeedbackController wires the controller to an already-loaded MapManager
// (see LoadPinnedMaps) and resolves the initial safe-network registry via
// DiscoverSafeNetworks. Discovery failure is non-fatal (falls back to the
// static-only list) since a firewall control plane should degrade gracefully
// rather than refuse to start over a netlink hiccup.
func NewFeedbackController(mgr *MapManager) *FeedbackController {
	fc := &FeedbackController{
		mgr:     mgr,
		blocked: make(map[string]blockRecord, 1024),
	}
	fc.RefreshSafeNetworks()
	return fc
}

// RefreshSafeNetworks re-resolves the dynamic portion of the safe-network
// registry (gateway, local subnets, resolvers may change after DHCP renewal
// or interface reconfiguration). Safe to call at any time, including
// concurrently with alert handling.
func (fc *FeedbackController) RefreshSafeNetworks() {
	nets, _ := DiscoverSafeNetworks() // best-effort; errors already absorbed internally
	fc.safeNetworksMu.Lock()
	fc.safeNetworks = nets
	fc.safeNetworksMu.Unlock()
}

// isSafeNetwork reports whether ip falls inside any registered safe network,
// returning the matching network for logging.
func (fc *FeedbackController) isSafeNetwork(ip net.IP) *net.IPNet {
	fc.safeNetworksMu.RLock()
	defer fc.safeNetworksMu.RUnlock()
	for _, n := range fc.safeNetworks {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}

// Run consumes alerts until ctx is cancelled or the alerts channel closes,
// and drives the TTL Janitor on janitorInterval.
func (fc *FeedbackController) Run(ctx context.Context, alerts <-chan ThreatAlert) {
	janitor := time.NewTicker(janitorInterval)
	defer janitor.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-janitor.C:
			fc.runJanitor()
		case alert, ok := <-alerts:
			if !ok {
				return
			}
			fc.handle(alert)
		}
	}
}

func (fc *FeedbackController) handle(alert ThreatAlert) {
	ip := net.ParseIP(alert.SrcIP)
	if ip == nil {
		fmt.Printf("\u26a0\ufe0f  [AI-IDA] Discarding alert with unparseable SrcIP %q\n", alert.SrcIP)
		return
	}

	// Infrastructure protection (TC-07) takes priority over everything else:
	// never even enter the dedup path for a safe-listed address.
	if sn := fc.isSafeNetwork(ip); sn != nil {
		if fc.OnExempt != nil {
			fc.OnExempt(alert, sn)
		} else {
			fmt.Printf("\U0001f6e1\ufe0f  [AI-IDA] Exempted %s from auto-block (matches safe network %s) \u2014 %s, P=%.3f\n",
				alert.SrcIP, sn.String(), alert.Attack, alert.Probability)
		}
		return
	}

	now := time.Now()

	fc.mu.Lock()
	if rec, seen := fc.blocked[alert.SrcIP]; seen && now.Before(rec.expiresAt) {
		fc.mu.Unlock()
		return // already blocked and not yet expired — skip redundant kernel write
	}
	fc.blocked[alert.SrcIP] = blockRecord{expiresAt: now.Add(BlockTTL)}
	fc.mu.Unlock()

	cidr := alert.SrcIP + "/32"
	if err := fc.mgr.BlockIP(cidr); err != nil {
		// Fail visibly rather than silently dropping the mitigation. Remove
		// the dedup entry we just wrote so a subsequent alert can retry —
		// unlike the old "leave it in the cache" behavior, an entry that
		// failed to actually block anything must not block a real retry.
		fc.mu.Lock()
		delete(fc.blocked, alert.SrcIP)
		fc.mu.Unlock()
		fmt.Printf("\u274c [AI-IDA] Closed-loop block FAILED for %s (%s, P=%.3f): %v\n",
			alert.SrcIP, alert.Attack, alert.Probability, err)
		return
	}

	if fc.OnBlock != nil {
		fc.OnBlock(alert)
	} else {
		fmt.Printf("\u26d4 [AI-IDA] Auto-blocked %s for %s \u2014 %s (P=%.3f)\n", cidr, BlockTTL, alert.Attack, alert.Probability)
	}
}

// runJanitor sweeps the block registry for TTL-expired entries and issues
// the corresponding MapManager.UnblockIP calls (TC-08). This is the only
// path that removes a dynamic block — without it, every auto-block is
// permanent.
func (fc *FeedbackController) runJanitor() {
	now := time.Now()

	fc.mu.Lock()
	var expired []string
	for ip, rec := range fc.blocked {
		if now.After(rec.expiresAt) {
			expired = append(expired, ip)
		}
	}
	fc.mu.Unlock()

	// Deliberately NOT deleted from fc.blocked until UnblockIP actually
	// succeeds: if we removed the tracking entry first and the kernel call
	// then failed, we'd lose all record of an IP that is still blocked in
	// REPUTATION_MAP — silently recreating the exact permanent-lockout risk
	// this Janitor exists to eliminate. A failed unblock simply gets retried
	// on the next sweep.
	for _, ip := range expired {
		if err := fc.mgr.UnblockIP(ip + "/32"); err != nil {
			fmt.Printf("\u26a0\ufe0f  [AI-IDA] TTL Janitor failed to unblock %s (will retry next sweep): %v\n", ip, err)
			continue
		}

		fc.mu.Lock()
		delete(fc.blocked, ip)
		fc.mu.Unlock()

		if fc.OnUnblock != nil {
			fc.OnUnblock(ip)
		} else {
			fmt.Printf("\u2705 [AI-IDA] TTL Janitor auto-unblocked %s (expired after %s)\n", ip, BlockTTL)
		}
	}
}
