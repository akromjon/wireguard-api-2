#!/bin/bash
# AWG2 side-by-side preflight. Read-only: changes nothing, ever.
#
# Run this on a legacy node BEFORE awg2-sidecar.sh. Every check here exists
# because it silently broke something on 2026-08-09. Exits non-zero if the node
# is not safe to convert, and prints a machine-readable summary line either way.
#
#   ssh <node> 'bash -s' < awg2-preflight.sh
#   ssh <node> 'bash -s' < awg2-preflight.sh -- --port 8081 --iface awg1
set -uo pipefail

NEW_PORT=8081
NEW_IFACE=awg1
while [[ $# -gt 0 ]]; do
	case "$1" in
	--port)
		NEW_PORT=$2
		shift 2
		;;
	--iface)
		NEW_IFACE=$2
		shift 2
		;;
	--) shift ;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

S=""
if [[ $(id -u) -ne 0 ]]; then
	if sudo -n true 2>/dev/null; then
		S="sudo -n"
	else
		echo "FAIL: not root and passwordless sudo unavailable"
		echo "SUMMARY ok=no reason=no-root"
		exit 1
	fi
fi

FAIL=0
WARN=0
pass() { printf '  \033[0;32mPASS\033[0m  %s\n' "$1"; }
fail() {
	printf '  \033[0;31mFAIL\033[0m  %s\n' "$1"
	FAIL=$((FAIL + 1))
}
warn() {
	printf '  \033[0;33mWARN\033[0m  %s\n' "$1"
	WARN=$((WARN + 1))
}

echo "AWG2 preflight — $(hostname) — target ${NEW_IFACE} on UDP ${NEW_PORT}"
echo

# --- 1. Existing interface ------------------------------------------------
CUR_IFACE=$(ip -br link show 2>/dev/null | grep -oE '^(awg|wg)[0-9]+' | head -1)
if [[ -z ${CUR_IFACE} ]]; then
	fail "no existing awg/wg interface found — is this a VPN node?"
else
	pass "existing interface: ${CUR_IFACE}"
fi

CUR_PORT=$(${S} awg show "${CUR_IFACE}" 2>/dev/null | awk '/listening port/ {print $3}')
AWG0_PEERS=$(${S} awg show "${CUR_IFACE}" peers 2>/dev/null | wc -l | tr -d ' ')
if [[ -n ${CUR_PORT} ]]; then
	pass "${CUR_IFACE} listening on ${CUR_PORT}, ${AWG0_PEERS} peers"
else
	fail "could not read ${CUR_IFACE} listening port"
fi

if [[ ${CUR_PORT} == "${NEW_PORT}" ]]; then
	fail "${CUR_IFACE} already uses ${NEW_PORT} — the two interfaces cannot share a port"
fi

if ip -br link show "${NEW_IFACE}" >/dev/null 2>&1; then
	fail "${NEW_IFACE} already exists — this node may already be converted"
else
	pass "${NEW_IFACE} is free"
fi

# --- 2. The NAT redirect trap --------------------------------------------
# A legacy REDIRECT on the port we are about to use sends every AWG2 handshake
# into the legacy interface, which cannot decrypt it. Silent and total.
REDIR=$(${S} iptables -t nat -S PREROUTING 2>/dev/null | grep -c "dport ${NEW_PORT} -j REDIRECT")
if [[ ${REDIR} -gt 0 ]]; then
	fail "NAT REDIRECT exists on ${NEW_PORT} — AWG2 handshakes would be swallowed:"
	${S} iptables -t nat -S PREROUTING | grep "dport ${NEW_PORT} -j REDIRECT" | sed 's/^/          /'
else
	pass "no NAT redirect on ${NEW_PORT}"
fi
ANY_REDIR=$(${S} iptables -t nat -S PREROUTING 2>/dev/null | grep -c 'j REDIRECT')
[[ ${ANY_REDIR} -gt 0 ]] && warn "node has ${ANY_REDIR} other REDIRECT rule(s); review before teardown"

# --- 3. Port actually free -----------------------------------------------
# ss only sees local listeners. It cannot see a provider firewall — that has to
# be probed from off-box, which this script cannot do. Reported, not asserted.
BUSY=$(${S} ss -lun 2>/dev/null | grep -c ":${NEW_PORT} ")
if [[ ${BUSY} -eq 0 ]]; then
	pass "UDP ${NEW_PORT} not bound locally"
else
	fail "UDP ${NEW_PORT} already bound locally"
fi

# --- 4. apt must not be locked -------------------------------------------
# The installer does NOT abort when apt is locked; it proceeds and leaves AWG2
# config running on the old 1.0 kernel module. One node had apt hung for 18 days.
if ${S} fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1; then
	fail "apt is locked — installer would skip the package upgrade and half-convert this node:"
	${S} ps -o pid,etime,cmd -p "$(${S} fuser /var/lib/apt/lists/lock 2>/dev/null | tr -d ' ')" 2>/dev/null | tail -1 | sed 's/^/          /'
else
	pass "apt not locked"
fi

# --- 5. apt sources must be readable -------------------------------------
# A pre-existing amnezia .sources with an inline key plus the installer's .list
# with signed-by = duplicate repo definitions, and apt refuses everything.
# apt-get indextargets parses every sources.list entry without touching the
# network or taking a lock. `--simulate update` is NOT valid and always errors.
APT_ERR=$(${S} apt-get indextargets 2>&1 >/dev/null | grep -E '^E:' | head -3)
if [[ -z ${APT_ERR} ]]; then
	pass "apt sources parse cleanly"
else
	fail "apt cannot read its sources — the package upgrade would fail:"
	echo "${APT_ERR}" | sed 's/^/          /'
	echo "          likely a duplicate amnezia repo: an old .sources with an inline"
	echo "          key alongside the installer's .list with signed-by=. Remove one."
fi

# --- 6. Node API present and healthy -------------------------------------
API_ENV=/etc/wireguard-api/.env
if [[ -r ${API_ENV} ]] || ${S} test -r ${API_ENV}; then
	API_PORT=$(${S} grep -E '^API_PORT=' ${API_ENV} | cut -d= -f2- | tr -d '"')
	API_PORT=${API_PORT:-8080}
	pass "node API env present (TCP ${API_PORT})"
	if [[ ${API_PORT} == "${NEW_PORT}" ]]; then
		warn "node API TCP ${API_PORT} shares a number with the new UDP port (different protocols, but confusing)"
	fi
	SVC=$(systemctl is-active wireguard.service 2>/dev/null)
	if [[ ${SVC} == active ]]; then
		pass "wireguard.service active"
	else
		fail "wireguard.service is ${SVC}"
	fi
else
	fail "cannot read ${API_ENV}"
fi

# --- 7. Disk headroom -----------------------------------------------------
AVAIL=$(df -Pm / | awk 'NR==2 {print $4}')
if [[ ${AVAIL} -ge 500 ]]; then
	pass "disk free: ${AVAIL} MB"
else
	fail "only ${AVAIL} MB free on / — DKMS build needs headroom"
fi

# --- 8. Kernel module -----------------------------------------------------
MOD_LOADED=$(cat /sys/module/amneziawg/version 2>/dev/null || echo none)
echo "  INFO  loaded amneziawg module: ${MOD_LOADED} (must read 3.0.20260805 AFTER install)"

echo
echo "----------------------------------------------------------------------"
if [[ ${FAIL} -gt 0 ]]; then
	echo "PREFLIGHT FAILED — ${FAIL} blocking issue(s), ${WARN} warning(s). Do not install."
	echo "SUMMARY ok=no fails=${FAIL} warns=${WARN} iface=${CUR_IFACE} port=${CUR_PORT} awg0_peers=${AWG0_PEERS}"
	exit 1
fi
echo "PREFLIGHT PASSED — ${WARN} warning(s)."
echo
echo "STILL TO CHECK FROM OFF-BOX (this script cannot):"
echo "  UDP ${NEW_PORT} must be reachable through the provider firewall."
echo "    on this node:  tcpdump -ni any 'udp port ${NEW_PORT}' -c 3"
echo "    from anywhere: printf probe | nc -u -w1 \$(hostname -I | awk '{print \$1}') ${NEW_PORT}"
echo "  IONOS blocks UDP ${NEW_PORT} by default and needs its firewall opened first."
echo
echo "SUMMARY ok=yes fails=0 warns=${WARN} iface=${CUR_IFACE} port=${CUR_PORT} awg0_peers=${AWG0_PEERS} module=${MOD_LOADED}"
