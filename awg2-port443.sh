#!/bin/bash
# Move the AWG2 interface from its side-by-side port onto 443, and retire awg0.
#
# Why: some users' networks pass UDP 443 and drop everything else. Measured
# 2026-08-09 — users who cannot connect had 588 past successes on the legacy
# :443 interface and 9 on :8081, while healthy users were at 19.5% on :8081.
# Same node, same IP, same user; only the port differs. Until awg1 is on 443
# those users cannot connect at all.
#
# This DROPS whoever is still on the old interface. By default it REFUSES to run
# while that interface has any live peer, because this is the one step in the
# whole rollout that can drop a live tunnel. Pass --force to drop them anyway.
#
#   ssh <node> 'bash -s' < awg2-port443.sh            # dry run
#   ssh <node> 'bash -s' < awg2-port443.sh -- --apply
#
# Flags:
#   --iface <n>       interface to move onto 443 (default awg1)
#   --old-iface <n>   interface currently holding 443, to retire (default awg0)
#   --apply           actually do it
#   --force           proceed even though the old interface still has live peers
#   --grace-redirect  keep the old port working by NAT-redirecting it to 443,
#                     for the gap before stored config Endpoints are rewritten
set -uo pipefail

OLD_IFACE=awg0
NEW_IFACE=awg1
TARGET_PORT=443
APPLY=0
GRACE=0
FORCE=0

# A peer is live if it handshook within this window. WireGuard rekeys about
# every 2 minutes, so 180s is one missed rekey. Must match the live-peer gate
# in docs/awg3-conversion-runbook.md — two different windows on the two sides
# of the same decision is how an operator ends up dropping users the runbook
# just told them were not there.
LIVE_WINDOW=180

while [[ $# -gt 0 ]]; do
	case "$1" in
	--apply)
		APPLY=1
		shift
		;;
	--grace-redirect)
		GRACE=1
		shift
		;;
	--force)
		FORCE=1
		shift
		;;
	--iface)
		NEW_IFACE=$2
		shift 2
		;;
	--old-iface)
		OLD_IFACE=$2
		shift 2
		;;
	--) shift ;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

# An unset shell variable in the caller turns `--old-iface "$OLD_IFACE" --apply`
# into `--old-iface --apply`, which would otherwise be accepted as an interface
# named "--apply" and quietly retire nothing.
for iface_arg in "${NEW_IFACE}" "${OLD_IFACE}"; do
	[[ ${iface_arg} =~ ^[a-zA-Z][a-zA-Z0-9_.-]*$ ]] || {
		echo "FAIL: '${iface_arg}' is not a valid interface name — check --iface / --old-iface" >&2
		exit 2
	}
done

AWG_DIR=/etc/amnezia/amneziawg
CONF="${AWG_DIR}/${NEW_IFACE}.conf"
PARAMS="${AWG_DIR}/params.${NEW_IFACE}"
API_ENV=/etc/wireguard-api/.env

FAIL=0
pass() { printf '  \033[0;32mOK   \033[0m %s\n' "$1"; }
bad() {
	printf '  \033[0;31mBAD  \033[0m %s\n' "$1"
	FAIL=$((FAIL + 1))
}
info() { printf '  INFO  %s\n' "$1"; }

[[ $(id -u) -eq 0 ]] || {
	echo "FAIL: must run as root"
	exit 1
}

echo "AWG2 port move — $(hostname) — ${NEW_IFACE} -> UDP ${TARGET_PORT}"
echo

# --- preconditions ---------------------------------------------------------
CUR_PORT=$(awg show "${NEW_IFACE}" 2>/dev/null | awk '/listening port/ {print $3}')
[[ -n ${CUR_PORT} ]] || {
	echo "FAIL: ${NEW_IFACE} not running"
	exit 1
}
if [[ ${CUR_PORT} == "${TARGET_PORT}" ]]; then
	echo "${NEW_IFACE} already on ${TARGET_PORT}; nothing to do."
	echo "SUMMARY ok=yes already=yes port=${TARGET_PORT}"
	exit 0
fi
[[ -f ${CONF} ]] || {
	echo "FAIL: ${CONF} missing"
	exit 1
}

PEERS_BEFORE=$(awg show "${NEW_IFACE}" peers 2>/dev/null | wc -l | tr -d ' ')
OLD_PORT=$(awg show "${OLD_IFACE}" 2>/dev/null | awk '/listening port/ {print $3}')

# Read the peer dump into a variable so the command's OWN exit status is
# checked. Piping straight into awk hides the failure: awk exits 0 on empty
# stdin and prints 0, which is indistinguishable from a genuinely idle
# interface — and "0 live users" is precisely the answer that unlocks dropping
# everyone. Wrong --old-iface, a missing interface or a permission error must
# all be loud.
if OLD_DUMP=$(awg show "${OLD_IFACE}" dump 2>&1); then
	OLD_READABLE=1
	OLD_LIVE=$(printf '%s\n' "${OLD_DUMP}" |
		awk -v n="$(date +%s)" -v w="${LIVE_WINDOW}" 'NR>1 && $5>0 && n-$5<w {c++} END{print c+0}')
else
	OLD_READABLE=0
	OLD_LIVE=0
fi

info "${NEW_IFACE}: port ${CUR_PORT}, ${PEERS_BEFORE} peers"
if ((OLD_READABLE == 1)); then
	info "${OLD_IFACE}: port ${OLD_PORT:-none}, ${OLD_LIVE} live users (handshake < ${LIVE_WINDOW}s) who WILL be dropped"
elif ip -br link show "${OLD_IFACE}" >/dev/null 2>&1; then
	echo "FAIL: ${OLD_IFACE} exists but its peer table could not be read:"
	echo "      ${OLD_DUMP}"
	echo "      Cannot prove it has zero live users, so cannot prove this drops nobody."
	if ((FORCE == 0)); then
		echo "SUMMARY ok=no refused=old_iface_unreadable"
		exit 1
	fi
	echo "      --force given — proceeding blind."
else
	info "${OLD_IFACE}: not present, nothing to drop"
fi

# The zero-live-peer gate. Everything else in this rollout is reversible; this
# is not — a dropped tunnel is a dropped tunnel.
if ((OLD_LIVE > 0 && FORCE == 0)); then
	echo
	echo "REFUSING: ${OLD_IFACE} still has ${OLD_LIVE} live peer(s) (handshake < ${LIVE_WINDOW}s)."
	echo "Taking UDP ${TARGET_PORT} now drops every one of them."
	echo "Wait for the live-peer gate to read zero, or pass --force to drop them deliberately."
	echo "SUMMARY ok=no refused=live_peers old_live=${OLD_LIVE}"
	exit 1
fi
if ((OLD_LIVE > 0)); then
	echo
	echo "WARNING: --force given — ${OLD_LIVE} live peer(s) on ${OLD_IFACE} WILL be dropped."
fi

if [[ -n ${OLD_PORT} && ${OLD_PORT} != "${TARGET_PORT}" ]]; then
	# Something else owns 443; refuse rather than guess.
	if ss -lun 2>/dev/null | grep -q ":${TARGET_PORT} "; then
		echo "FAIL: UDP ${TARGET_PORT} is bound but not by ${OLD_IFACE}. Investigate first."
		exit 1
	fi
fi

if ((APPLY == 0)); then
	echo
	echo "DRY RUN. Would:"
	echo "  1. stop+disable ${OLD_IFACE} (frees ${TARGET_PORT}, drops ${OLD_LIVE} live users)"
	echo "  2. stop ${NEW_IFACE} so its PostDown removes the :${CUR_PORT} firewall rules"
	echo "  3. rewrite ${CUR_PORT} -> ${TARGET_PORT} in ${CONF} ($(grep -c "${CUR_PORT}" "${CONF}" || true) refs), ${PARAMS}, ${API_ENV}"
	echo "  4. start ${NEW_IFACE} (PostUp adds the :${TARGET_PORT} rules) and restart the node API"
	echo "SUMMARY ok=yes applied=no peers=${PEERS_BEFORE} old_live=${OLD_LIVE}"
	exit 0
fi

# --- backup ----------------------------------------------------------------
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/awg-port443-${STAMP}"
mkdir -p "${BACKUP}"
cp -a "${CONF}" "${BACKUP}/" 2>/dev/null
cp -a "${PARAMS}" "${BACKUP}/" 2>/dev/null
cp -a "${API_ENV}" "${BACKUP}/env" 2>/dev/null
info "backup: ${BACKUP}"

rollback() {
	echo
	echo "ROLLING BACK"
	systemctl stop "awg-quick@${NEW_IFACE}" >/dev/null 2>&1
	cp -a "${BACKUP}/$(basename "${CONF}")" "${CONF}" 2>/dev/null
	cp -a "${BACKUP}/$(basename "${PARAMS}")" "${PARAMS}" 2>/dev/null
	cp -a "${BACKUP}/env" "${API_ENV}" 2>/dev/null
	systemctl start "awg-quick@${NEW_IFACE}" >/dev/null 2>&1
	systemctl enable --now "awg-quick@${OLD_IFACE}" >/dev/null 2>&1
	systemctl restart wireguard.service >/dev/null 2>&1
	echo "Restored ${NEW_IFACE} on ${CUR_PORT} and restarted ${OLD_IFACE}."
	echo "SUMMARY ok=no rolledback=yes"
	exit 1
}

# --- 1. retire the old interface, freeing the port -------------------------
systemctl disable --now "awg-quick@${OLD_IFACE}" >/dev/null 2>&1
sleep 1
if ip -br link show "${OLD_IFACE}" >/dev/null 2>&1; then
	awg-quick down "${OLD_IFACE}" >/dev/null 2>&1
fi

# --- 2. stop the new interface BEFORE editing its config -------------------
# PostDown deletes the firewall rules for the CURRENT port. Editing first
# leaves orphaned rules behind — that happened on node 261 on 2026-08-09.
systemctl stop "awg-quick@${NEW_IFACE}" >/dev/null 2>&1
sleep 1

# --- 3. rewrite the port ---------------------------------------------------
sed -i "s/\b${CUR_PORT}\b/${TARGET_PORT}/g" "${CONF}"
[[ -f ${PARAMS} ]] && sed -i "s/^SERVER_PORT=.*/SERVER_PORT=${TARGET_PORT}/" "${PARAMS}"
if [[ -f ${API_ENV} ]]; then
	if grep -q '^AWG_PORT=' "${API_ENV}"; then
		sed -i "s/^AWG_PORT=.*/AWG_PORT=${TARGET_PORT}/" "${API_ENV}"
	else
		echo "AWG_PORT=${TARGET_PORT}" >>"${API_ENV}"
	fi
fi

# --- 4. bring it back up ---------------------------------------------------
systemctl start "awg-quick@${NEW_IFACE}" >/dev/null 2>&1 || rollback
sleep 2
systemctl restart wireguard.service >/dev/null 2>&1
sleep 2

# --- 5. optional grace redirect for stale configs --------------------------
# Clients fetch a config on every connect (every user_sessions row carries its
# own downloaded_at), so they pick up :443 by themselves. This only covers the
# gap between moving the port and rewriting the stored Endpoint, plus anyone
# holding a cached config.
#
# Safe in a way the 2026-08-09 legacy redirect was NOT: that one sent 443 to a
# DIFFERENT interface, so AWG2 handshakes reached a peer that could not decrypt
# them. This forwards the old port to the SAME interface and the same keys.
# Remove it once the stored configs are rewritten and traffic on the old port
# has stopped.
if ((GRACE == 1)); then
	if iptables -t nat -C PREROUTING -p udp --dport "${CUR_PORT}" -j REDIRECT --to-port "${TARGET_PORT}" 2>/dev/null; then
		info "grace redirect ${CUR_PORT} -> ${TARGET_PORT} already present"
	else
		iptables -t nat -A PREROUTING -p udp --dport "${CUR_PORT}" -j REDIRECT --to-port "${TARGET_PORT}"
		iptables -I INPUT -p udp --dport "${CUR_PORT}" -j ACCEPT 2>/dev/null
		info "grace redirect added: udp ${CUR_PORT} -> ${TARGET_PORT} (REMOVE once configs are rewritten)"
	fi
fi

# --- verify ----------------------------------------------------------------
echo
echo "==> Verifying"
NEW_PORT_NOW=$(awg show "${NEW_IFACE}" 2>/dev/null | awk '/listening port/ {print $3}')
[[ ${NEW_PORT_NOW} == "${TARGET_PORT}" ]] && pass "${NEW_IFACE} port = ${NEW_PORT_NOW}" || bad "${NEW_IFACE} port = ${NEW_PORT_NOW:-none} (expected ${TARGET_PORT})"

PEERS_AFTER=$(awg show "${NEW_IFACE}" peers 2>/dev/null | wc -l | tr -d ' ')
((PEERS_AFTER == PEERS_BEFORE)) && pass "peers preserved = ${PEERS_AFTER}" || bad "peers ${PEERS_BEFORE} -> ${PEERS_AFTER}"

[[ $(systemctl is-active "awg-quick@${NEW_IFACE}") == active ]] && pass "${NEW_IFACE} service active" || bad "${NEW_IFACE} service not active"
[[ $(systemctl is-active wireguard.service) == active ]] && pass "node API active" || bad "node API not active"

ss -lun 2>/dev/null | grep -q ":${TARGET_PORT} " && pass "UDP ${TARGET_PORT} bound" || bad "UDP ${TARGET_PORT} not bound"
iptables -S INPUT 2>/dev/null | grep -q "dport ${TARGET_PORT} -j ACCEPT" && pass "firewall accepts ${TARGET_PORT}" || bad "no INPUT ACCEPT for ${TARGET_PORT}"
if iptables -S INPUT 2>/dev/null | grep -q "dport ${CUR_PORT} -j ACCEPT"; then
	info "stale INPUT rule for old port ${CUR_PORT} still present (harmless, nothing listens)"
fi
ip -br link show "${OLD_IFACE}" >/dev/null 2>&1 && bad "${OLD_IFACE} still up" || pass "${OLD_IFACE} retired"

echo
if ((FAIL > 0)); then
	echo "PORT MOVE FAILED — ${FAIL} check(s). Rolling back."
	rollback
fi
echo "PORT MOVE OK — ${NEW_IFACE} now on ${TARGET_PORT}, ${PEERS_AFTER} peers intact."
echo "NEXT: rewrite the stored client configs' Endpoint from :${CUR_PORT} to :${TARGET_PORT}"
echo "      (peer keys are unchanged, so the pool does NOT need regenerating)."
echo "SUMMARY ok=yes applied=yes port=${TARGET_PORT} peers=${PEERS_AFTER} old_dropped=${OLD_LIVE} backup=${BACKUP}"
