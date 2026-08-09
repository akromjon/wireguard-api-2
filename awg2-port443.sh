#!/bin/bash
# Move the AWG2 interface from its side-by-side port onto 443, and retire awg0.
#
# Why: some users' networks pass UDP 443 and drop everything else. Measured
# 2026-08-09 — users who cannot connect had 588 past successes on the legacy
# :443 interface and 9 on :8081, while healthy users were at 19.5% on :8081.
# Same node, same IP, same user; only the port differs. Until awg1 is on 443
# those users cannot connect at all.
#
# This DROPS whoever is still on awg0. They reconnect and land on a config that
# works on restricted networks. Run it when awg0 has drained to a handful.
#
#   ssh <node> 'bash -s' < awg2-port443.sh            # dry run
#   ssh <node> 'bash -s' < awg2-port443.sh -- --apply
set -uo pipefail

OLD_IFACE=awg0
NEW_IFACE=awg1
TARGET_PORT=443
APPLY=0
GRACE=0

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
OLD_LIVE=$(awg show "${OLD_IFACE}" latest-handshakes 2>/dev/null |
	awk -v n="$(date +%s)" '$2>0 && n-$2<300 {c++} END{print c+0}')
OLD_PORT=$(awg show "${OLD_IFACE}" 2>/dev/null | awk '/listening port/ {print $3}')

info "${NEW_IFACE}: port ${CUR_PORT}, ${PEERS_BEFORE} peers"
info "${OLD_IFACE}: port ${OLD_PORT:-none}, ${OLD_LIVE} live users who WILL be dropped"

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
