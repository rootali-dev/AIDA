#!/usr/bin/env bash
#
# scripts/setup_test_netns.sh
#
# Builds an isolated network-namespace + veth topology for exercising the
# AI-IDA XDP program without touching any real interface, and prints the
# exact follow-up commands to attach the program and run the traffic matrix.
#
# TOPOLOGY
#
#   root netns                         ai_ida_test netns
#   ┌─────────────────┐                ┌─────────────────────┐
#   │  veth-ext        │◄──veth pair──►│  veth-int            │
#   │  10.200.0.1/24   │                │  10.200.0.2/24 (DUT) │
#   │  (attacker /     │                │  lo: 127.0.0.1/8     │
#   │   external side) │                │  (protected host)    │
#   └─────────────────┘                └─────────────────────┘
#
# veth-ext stays in the root namespace and plays the role of "the wire" /
# attacker source. veth-int is moved into ai_ida_test and is the interface
# the XDP program attaches to — it represents the ingress point of the
# protected host. `lo` inside ai_ida_test is brought up separately for the
# loopback (TC-01) test phase, since loopback traffic never crosses veth.
#
# TWO-PHASE ATTACH LIMITATION (read before running TC-01):
# ebpf-loader currently attaches to exactly one interface per invocation and
# pins all five maps to a single fixed bpffs path. Running it twice
# concurrently against two different interfaces (veth-int and lo) would have
# the second invocation's maps silently clobber the first's pins at
# /sys/fs/bpf/ai_ida/. There is no bug being papered over here — it's a
# real constraint of the current loader — so this harness runs in two
# sequential phases instead of one:
#   Phase 1: attach to veth-int, run TC-02/04/05/06/07/08 (anything that
#            crosses the veth pair).
#   Phase 2: attach to lo,       run TC-01 and TC-03 (loopback-local and
#            low-volume probes are most naturally exercised on lo too,
#            though TC-03 works equally well on veth-int).
#
# USAGE
#   sudo ./scripts/setup_test_netns.sh up       # create topology
#   sudo ./scripts/setup_test_netns.sh status   # show current state
#   sudo ./scripts/setup_test_netns.sh down     # tear down
#
set -euo pipefail

NS_NAME="ai_ida_test"
VETH_EXT="veth-ext"
VETH_INT="veth-int"
IP_EXT="10.200.0.1/24"
IP_INT="10.200.0.2/24"
GW_IP="10.200.0.1" # veth-ext plays "default gateway" for TC-07 spoofing tests

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOADER_BIN="${REPO_ROOT}/target/debug/ebpf-loader"

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "❌ This script must be run as root (network namespace + veth + BPF operations)." >&2
        exit 1
    fi
}

teardown() {
    echo "🧹 Tearing down ${NS_NAME} topology (idempotent — ignoring already-absent state)..."
    ip netns del "${NS_NAME}" 2>/dev/null || true
    ip link del "${VETH_EXT}" 2>/dev/null || true
    echo "✅ Teardown complete."
}

setup() {
    teardown # idempotent: always start from a clean slate

    echo "🔧 Creating network namespace '${NS_NAME}'..."
    ip netns add "${NS_NAME}"

    echo "🔧 Creating veth pair ${VETH_EXT} <-> ${VETH_INT}..."
    ip link add "${VETH_EXT}" type veth peer name "${VETH_INT}"

    echo "🔧 Moving ${VETH_INT} into ${NS_NAME}..."
    ip link set "${VETH_INT}" netns "${NS_NAME}"

    echo "🔧 Assigning addresses and bringing links up..."
    ip addr add "${IP_EXT}" dev "${VETH_EXT}"
    ip link set "${VETH_EXT}" up

    ip netns exec "${NS_NAME}" ip addr add "${IP_INT}" dev "${VETH_INT}"
    ip netns exec "${NS_NAME}" ip link set "${VETH_INT}" up
    ip netns exec "${NS_NAME}" ip link set lo up

    # rp_filter is an IP-stack concept applied well after XDP has already
    # run, so it cannot mask a real XDP verdict — but disabling it removes
    # a class of "why didn't my spoofed-source packet even leave veth-ext"
    # confusion when testing TC-04/TC-07 style spoofed-source packets.
    echo "🔧 Disabling rp_filter on both veth ends (does not affect XDP itself)..."
    sysctl -qw net.ipv4.conf."${VETH_EXT}".rp_filter=0 || true
    ip netns exec "${NS_NAME}" sysctl -qw net.ipv4.conf."${VETH_INT}".rp_filter=0 || true

    echo ""
    echo "================================================================================"
    echo "✅ Topology ready."
    echo "================================================================================"
    echo "  Root netns   : ${VETH_EXT} @ ${IP_EXT}  (sender / attacker vantage point)"
    echo "  ${NS_NAME} netns: ${VETH_INT} @ ${IP_INT}  (DUT ingress — XDP attach point)"
    echo "                 lo @ 127.0.0.1/8            (loopback phase only)"
    echo ""
    echo "Build the loader first if you haven't:"
    echo "  cargo build --workspace"
    echo ""
    echo "── Phase 1: veth-based tests (TC-02, TC-04, TC-05, TC-06, TC-07, TC-08) ──"
    echo "  Terminal A (loader, stays running):"
    echo "    sudo ip netns exec ${NS_NAME} ${LOADER_BIN} --iface ${VETH_INT} --skb"
    echo ""
    echo "  Terminal B (observer — run first, sniffs post-XDP traffic on ${VETH_INT}):"
    echo "    sudo ip netns exec ${NS_NAME} python3 ${REPO_ROOT}/tests/traffic_matrix.py \\"
    echo "        --role observer --iface ${VETH_INT} --duration 15"
    echo ""
    echo "  Terminal C (sender — run after observer is listening):"
    echo "    sudo python3 ${REPO_ROOT}/tests/traffic_matrix.py \\"
    echo "        --role sender --iface ${VETH_EXT} --dut-ip ${IP_INT%/*} --gw-ip ${GW_IP}"
    echo ""
    echo "  Ctrl-C the loader in Terminal A when done (auto-cleans /sys/fs/bpf/ai_ida)."
    echo ""
    echo "── Phase 2: loopback test (TC-01) ──"
    echo "  Terminal A (loader, on lo this time):"
    echo "    sudo ip netns exec ${NS_NAME} ${LOADER_BIN} --iface lo"
    echo ""
    echo "  Terminal B (single self-contained process — sends AND sniffs lo):"
    echo "    sudo ip netns exec ${NS_NAME} python3 ${REPO_ROOT}/tests/traffic_matrix.py \\"
    echo "        --role observer --iface lo --loopback --duration 8"
    echo ""
    echo "── Manual REPUTATION_MAP verification (TC-03, TC-05, TC-07, TC-08) ──"
    echo "  These four cases assert an ABSENCE (or, for TC-08, a timed presence-then-"
    echo "  absence) of an auto-block, which is a daemon-level (aggregator -> inference"
    echo "  -> feedback) property, not a single-packet XDP verdict. After running the"
    echo "  daemon (ai-ida-control daemon) alongside the traffic above, inspect state"
    echo "  directly with bpftool (works with or without the Go daemon running):"
    echo "    sudo bpftool map dump pinned /sys/fs/bpf/ai_ida/reputation_map"
    echo "  traffic_matrix.py also offers a --check-reputation <ip> convenience mode"
    echo "  that wraps this same bpftool call — see its --help."
    echo "================================================================================"
}

status() {
    echo "Namespaces:"
    ip netns list | grep -F "${NS_NAME}" || echo "  (${NS_NAME} not present)"
    echo ""
    echo "Root-ns veth:"
    ip -brief link show "${VETH_EXT}" 2>/dev/null || echo "  (${VETH_EXT} not present)"
    echo ""
    if ip netns list | grep -qF "${NS_NAME}"; then
        echo "${NS_NAME} interfaces:"
        ip netns exec "${NS_NAME}" ip -brief addr show
    fi
}

require_root

case "${1:-up}" in
    up) setup ;;
    down) teardown ;;
    status) status ;;
    *)
        echo "Usage: $0 {up|down|status}" >&2
        exit 1
        ;;
esac
