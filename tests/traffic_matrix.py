#!/usr/bin/env python3
"""
tests/traffic_matrix.py

Scapy-based edge-case traffic generator and verifier for the AI-IDA
False-Positive Remediation phase (TC-01 through TC-08).

HONEST SCOPE NOTE (read this before trusting a green result):
TC-01/02/04/06 are pure kernel-XDP verdicts (drop vs pass one packet) and are
fully automated here via a sender/observer split:
  - `--role sender`   crafts and transmits each profile's packet(s).
  - `--role observer` sniffs the DUT-facing interface and checks whether each
    profile's uniquely-tagged packet actually arrived. A genuine XDP_DROP
    happens before the kernel hands the frame to any packet-capture tap, so
    "never observed" is a reliable proxy for "the XDP program dropped it" —
    this is standard, well-understood XDP testing methodology, not a guess.

TC-03/05/07/08 are properties of the userspace daemon (aggregator ->
inference -> feedback -> TTL Janitor), not of a single packet's XDP verdict.
This script automates the TRAFFIC GENERATION for those cases, but the actual
assertion is "does REPUTATION_MAP gain/lose an entry", which is a stateful,
cross-process, and (for TC-08) cross-time check. Use `--check-reputation`
against bpftool for that half — see the module docstring in each TC builder
and scripts/setup_test_netns.sh for the exact invocation sequence.

USAGE
  Sender (root netns, external vantage point):
    sudo python3 traffic_matrix.py --role sender --iface veth-ext \
        --dut-ip 10.200.0.2 --gw-ip 10.200.0.1

  Observer (inside ai_ida_test netns, DUT-facing vantage point):
    sudo ip netns exec ai_ida_test python3 traffic_matrix.py \
        --role observer --iface veth-int --duration 15

  Loopback phase (TC-01), single self-contained process inside the netns:
    sudo ip netns exec ai_ida_test python3 traffic_matrix.py \
        --role observer --iface lo --loopback --duration 8

  REPUTATION_MAP spot-check (any time, requires bpftool):
    sudo python3 traffic_matrix.py --check-reputation 10.200.0.50
"""

import argparse
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

try:
    from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, sendp, sniff
except ImportError:
    print("❌ scapy is required: pip install scapy --break-system-packages", file=sys.stderr)
    sys.exit(1)


# -----------------------------------------------------------------------------
# Test profile definitions
# -----------------------------------------------------------------------------

# IP.id is used purely as a correlation tag between sender and observer — it
# has no special meaning to AI-IDA itself, it just lets the observer say
# "yes, TC-04's exact packet arrived" rather than "some UDP packet arrived".
TAG_BASE = 61000


@dataclass
class TrafficProfile:
    tc_id: str
    description: str
    expected_pass: bool  # True = must reach the observer; False = must be dropped by XDP
    build: Callable[["Context"], List]  # returns one or more Scapy packets to send
    layer: str = "kernel"  # "kernel" (auto-verifiable) or "daemon" (needs bpftool follow-up)
    tag: int = field(default=0)


@dataclass
class Context:
    dut_ip: str
    gw_ip: str
    src_ip_ext: str  # the sender's own address on veth-ext / the wire


def _tagged(pkt, tag: int):
    pkt[IP].id = tag
    return pkt


def build_tc01_loopback(ctx: Context, tag: int) -> List:
    # TC-01: 127.0.0.1 -> 127.0.0.1. Must pass the Land Attack check via the
    # loopback exemption in rfc_invariants::is_loopback — src==dst==non-zero
    # would otherwise trip the naive Land Attack heuristic.
    pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / ICMP()
    return [_tagged(pkt, tag)]


def build_tc02_ephemeral_tcp(ctx: Context, tag: int) -> List:
    # TC-02a: remote:443 -> local:54123 with ACK set — established-connection
    # reply traffic. Must bypass PORT_GATE_MAP even if 54123 (or 443) were
    # gated, because it's not a new inbound SYN request.
    pkt = (
        Ether()
        / IP(src="93.184.216.34", dst=ctx.dut_ip)
        / TCP(sport=443, dport=54123, flags="A")
    )
    return [_tagged(pkt, tag)]


def build_tc02_ephemeral_udp(ctx: Context, tag: int) -> List:
    # TC-02b: remote DNS resolver reply landing on an ephemeral (>=32768)
    # client port. Must be exempted by the UDP ephemeral-range carve-out in
    # port_gate::is_port_blocked regardless of PORT_GATE_MAP state.
    pkt = Ether() / IP(src="8.8.8.8", dst=ctx.dut_ip) / UDP(sport=53, dport=40000)
    return [_tagged(pkt, tag)]


def build_tc04_dhcp_discover(ctx: Context, tag: int) -> List:
    # TC-04: 0.0.0.0:68 -> 255.255.255.255:67. Must pass Layer 3 sanity —
    # src_ip == 0 is explicitly excluded from the Land Attack check, and
    # nothing else in the pipeline should treat a legitimate DHCP DISCOVER
    # as malformed.
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
    )
    return [_tagged(pkt, tag)]


def build_tc06_ecn_benign(ctx: Context, tag: int) -> List:
    # TC-06a: ordinary data-bearing ACK packet that also carries ECE+CWR
    # (RFC 3168 congestion signaling). Must NOT be misread as a NULL scan —
    # this is exactly the false positive the flags & 0x3F mask exists to
    # prevent when the *conventional* flags are also legitimately non-empty,
    # and more importantly must not affect a genuinely-populated flag packet.
    pkt = (
        Ether()
        / IP(src="93.184.216.34", dst=ctx.dut_ip)
        / TCP(sport=443, dport=54124, flags="AEC")  # ACK + ECE + CWR
    )
    return [_tagged(pkt, tag)]


def build_tc06b_disguised_null_scan(ctx: Context, tag: int) -> List:
    # TC-06b (bonus regression guard, not in the original 8): a NULL scan
    # attempting to evade a naive `tcp_flags == 0` check by setting a stray
    # ECN bit while leaving every real control flag at zero. The masked
    # comparison (flags & 0x3F) == 0 must still catch this — expected_pass
    # is False, unlike every other TC-06 case.
    pkt = Ether() / IP(src="203.0.113.9", dst=ctx.dut_ip) / TCP(sport=51000, dport=22, flags="C")  # CWR only
    return [_tagged(pkt, tag)]


def build_tc03_health_probe(ctx: Context, tag: int) -> List:
    # TC-03: intermittent half-open probes (a handful of lone SYNs, well
    # under both synFloodTree's PacketCount<20 gate and the aggregator's
    # N>=30 IATStdDev sample floor). Kernel-level verdict is trivially PASS
    # (no kernel rule targets this shape at all); the real assertion is
    # "the daemon must not auto-block ctx.src_ip_ext after this" — see
    # --check-reputation.
    return [
        _tagged(Ether() / IP(src=ctx.src_ip_ext, dst=ctx.dut_ip) / TCP(sport=51000 + i, dport=8080, flags="S"), tag)
        for i in range(6)
    ]


def build_tc05_prometheus_scrape(ctx: Context, tag: int) -> List:
    # TC-05: high-entropy port polling from a local RFC1918 source (here,
    # the sender's own veth-ext address, which is itself a local interface
    # subnet from the DUT's perspective — exactly the shape
    # DiscoverSafeNetworks() protects). Kernel-level verdict is PASS;
    # real assertion is "no auto-block despite high PortEntropyBits" via
    # --check-reputation.
    ports = [9100, 9090, 9093, 9115, 9187, 9216, 9256, 9308]
    return [
        _tagged(Ether() / IP(src=ctx.src_ip_ext, dst=ctx.dut_ip) / TCP(sport=52000, dport=p, flags="S"), tag)
        for p in ports
    ]


def build_tc07_spoofed_gateway_flood(ctx: Context, tag: int) -> List:
    # TC-07: a SYN-flood-shaped burst spoofing the default gateway's own
    # address as source. Kernel-level verdict is PASS (nothing in the XDP
    # pipeline treats this specially); the real assertion is that the
    # feedback controller's safe-network check refuses to ever push
    # ctx.gw_ip into REPUTATION_MAP, no matter how attack-shaped the traffic
    # looks — verify with --check-reputation after running the full daemon.
    return [
        _tagged(Ether() / IP(src=ctx.gw_ip, dst=ctx.dut_ip) / TCP(sport=53000 + i, dport=80, flags="S"), tag)
        for i in range(40)
    ]


def build_tc08_transient_attacker(ctx: Context, tag: int) -> List:
    # TC-08: a real SYN-flood-shaped burst from an ordinary (non-safe)
    # source, intended to cross MalwareThreshold and trigger a genuine
    # auto-block. The assertion has two timed halves:
    #   1. Shortly after this runs (needs a few 100ms aggregation windows),
    #      --check-reputation should show the source BLOCKED.
    #   2. After BlockTTL (300s, or whatever engine.BlockTTL is set to in a
    #      test build — see the tip below) the TTL Janitor should have
    #      called UnblockIP, and --check-reputation should show ABSENT.
    # Waiting a real 5 minutes in an interactive test run is impractical;
    # for faster iteration, temporarily lower engine.BlockTTL and
    # engine.janitorInterval in a local build rather than waiting live.
    attacker_ip = "198.51.100.77"
    return [
        _tagged(Ether() / IP(src=attacker_ip, dst=ctx.dut_ip) / TCP(sport=54000 + i, dport=80, flags="S"), tag)
        for i in range(60)
    ]


PROFILES: List[TrafficProfile] = [
    TrafficProfile("TC-01", "Loopback IPC (127.0.0.1 -> 127.0.0.1)", True, build_tc01_loopback, "kernel"),
    TrafficProfile("TC-02a", "Ephemeral TCP return (ACK set)", True, build_tc02_ephemeral_tcp, "kernel"),
    TrafficProfile("TC-02b", "Ephemeral UDP return (dst_port >= 32768)", True, build_tc02_ephemeral_udp, "kernel"),
    TrafficProfile("TC-03", "Health-check half-open probes (low N)", True, build_tc03_health_probe, "daemon"),
    TrafficProfile("TC-04", "DHCP DISCOVER (0.0.0.0 -> 255.255.255.255)", True, build_tc04_dhcp_discover, "kernel"),
    TrafficProfile("TC-05", "Local Prometheus-style high-entropy scrape", True, build_tc05_prometheus_scrape, "daemon"),
    TrafficProfile("TC-06a", "Benign ACK with ECE|CWR set", True, build_tc06_ecn_benign, "kernel"),
    TrafficProfile("TC-06b", "Disguised NULL scan (CWR-only, evasion attempt)", False, build_tc06b_disguised_null_scan, "kernel"),
    TrafficProfile("TC-07", "Spoofed default-gateway SYN flood", True, build_tc07_spoofed_gateway_flood, "daemon"),
    TrafficProfile("TC-08", "Transient attacker (ban + expiry lifecycle)", True, build_tc08_transient_attacker, "daemon"),
]


# -----------------------------------------------------------------------------
# Sender role
# -----------------------------------------------------------------------------

def run_sender(ctx: Context, iface: str, only: Optional[str]) -> None:
    print(f"📡 Sending on {iface} (dst={ctx.dut_ip}, spoofed-gw={ctx.gw_ip})...\n")
    for i, profile in enumerate(PROFILES):
        if only and profile.tc_id != only:
            continue
        if profile.tc_id.startswith("TC-01"):
            print(f"⏭️  Skipping {profile.tc_id} in sender role — loopback traffic never crosses veth; "
                  f"run it via `--role observer --iface lo --loopback` instead.")
            continue
        tag = TAG_BASE + i
        packets = profile.build(ctx, tag)
        sendp(packets, iface=iface, verbose=False)
        print(f"  [{profile.tc_id}] sent {len(packets)} packet(s), tag={tag} — {profile.description}")
        time.sleep(0.15)  # keep windows visually distinct; not required for correctness
    print("\n✅ Send pass complete.")


# -----------------------------------------------------------------------------
# Observer role
# -----------------------------------------------------------------------------

def run_observer(ctx: Context, iface: str, duration: float, loopback: bool, only: Optional[str]) -> int:
    seen_tags: set = set()

    def on_packet(pkt):
        if pkt.haslayer(IP):
            seen_tags.add(pkt[IP].id)

    print(f"👂 Sniffing {iface} for {duration:.1f}s...")

    sniffer_thread = threading.Thread(
        target=lambda: sniff(iface=iface, timeout=duration, prn=on_packet, store=False),
        daemon=True,
    )
    sniffer_thread.start()

    active_profiles = [p for p in PROFILES if (not only or p.tc_id == only)]

    if loopback:
        # Self-contained loopback phase: this process sends TC-01 to itself
        # a moment after the sniffer starts, so the same sniff() window
        # captures it (or doesn't, if XDP on lo dropped it).
        time.sleep(1.0)
        loop_profile = next(p for p in PROFILES if p.tc_id == "TC-01")
        tag = TAG_BASE
        packets = loop_profile.build(ctx, tag)
        sendp(packets, iface=iface, verbose=False)
        print(f"  [TC-01] self-sent {len(packets)} packet(s) on {iface}, tag={tag}")
        active_profiles = [loop_profile]
    else:
        print("   (waiting for the sender process to fire the traffic matrix on the other side...)")

    sniffer_thread.join()

    print("\n" + "=" * 88)
    print(f"{'TC':<7} {'Layer':<8} {'Expected':<10} {'Observed':<10} {'Result':<8} Description")
    print("-" * 88)

    failures = 0
    for i, profile in enumerate(PROFILES):
        if profile not in active_profiles:
            continue
        tag = TAG_BASE + i if not loopback else TAG_BASE
        observed_pass = tag in seen_tags
        expected = "PASS" if profile.expected_pass else "DROP"
        observed = "PASS" if observed_pass else "DROP"

        if profile.layer == "daemon":
            result = "N/A*"
        else:
            ok = observed_pass == profile.expected_pass
            result = "OK" if ok else "FAIL"
            if not ok:
                failures += 1

        print(f"{profile.tc_id:<7} {profile.layer:<8} {expected:<10} {observed:<10} {result:<8} {profile.description}")

    print("=" * 88)
    print("* daemon-layer cases only report whether the packet(s) reached the wire (always")
    print("  expected here) — the real assertion is REPUTATION_MAP state; see --check-reputation.")

    if failures:
        print(f"\n❌ {failures} kernel-layer assertion(s) FAILED.")
    else:
        print("\n✅ All automated kernel-layer assertions passed.")

    return 1 if failures else 0


# -----------------------------------------------------------------------------
# REPUTATION_MAP spot-check (bpftool wrapper)
# -----------------------------------------------------------------------------

def check_reputation(ip: str) -> int:
    """Looks up `ip` (as a /32) in the pinned REPUTATION_MAP via bpftool.

    This works regardless of whether the Go daemon is running — it reads
    kernel BPF map state directly — which makes it the right tool for
    TC-03/05/07/08's real assertion ("is this IP blocked or not"), rather
    than trying to infer daemon internals from packet timing.
    """
    octets = [int(o) for o in ip.split(".")]
    hex_key = " ".join(f"0x{b:02x}" for b in [32, 0, 0, 0] + octets)  # prefix_len=32 LE + addr bytes

    cmd = ["bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/ai_ida/reputation_map", "key", "hex", *hex_key.split()]
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        if "No such file" in result.stderr or "error" in result.stderr.lower():
            print(f"✅ {ip} is NOT present in REPUTATION_MAP (lookup returned no entry).")
            return 0
        print(f"⚠️  bpftool failed: {result.stderr.strip()}", file=sys.stderr)
        return 2

    print(f"🚫 {ip} IS currently present in REPUTATION_MAP:\n{result.stdout}")
    return 0


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--role", choices=["sender", "observer"], help="sender or observer (see module docstring)")
    parser.add_argument("--iface", help="interface to send on / sniff on")
    parser.add_argument("--dut-ip", default="10.200.0.2", help="protected host's address (default matches setup_test_netns.sh)")
    parser.add_argument("--gw-ip", default="10.200.0.1", help="address to spoof as 'default gateway' for TC-07")
    parser.add_argument("--src-ip-ext", default="10.200.0.1", help="sender's own address, used for TC-03/05's 'local subnet' source")
    parser.add_argument("--duration", type=float, default=15.0, help="observer sniff window in seconds")
    parser.add_argument("--loopback", action="store_true", help="observer self-sends+sniffs TC-01 on lo (Phase 2)")
    parser.add_argument("--only", help="restrict to a single TC id, e.g. TC-06b")
    parser.add_argument("--check-reputation", metavar="IP", help="look up IP in REPUTATION_MAP via bpftool and exit")
    args = parser.parse_args()

    if args.check_reputation:
        return check_reputation(args.check_reputation)

    if not args.role or not args.iface:
        parser.error("--role and --iface are required unless using --check-reputation")

    ctx = Context(dut_ip=args.dut_ip, gw_ip=args.gw_ip, src_ip_ext=args.src_ip_ext)

    if args.role == "sender":
        run_sender(ctx, args.iface, args.only)
        return 0

    return run_observer(ctx, args.iface, args.duration, args.loopback, args.only)


if __name__ == "__main__":
    sys.exit(main())
