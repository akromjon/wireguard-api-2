#!/bin/bash
# Install AWG2 alongside an existing legacy interface, without disconnecting
# anyone. The legacy awg0 keeps running and keeps serving every already-issued
# config; the new awg1 serves everything issued from now on.
#
#   scp awg2-preflight.sh awg2-sidecar.sh <node>:/tmp/
#   ssh <node> 'bash /tmp/awg2-sidecar.sh --apply'
#
# Without --apply it runs the preflight and prints the plan, changing nothing.
#
# Afterwards, on the backend:
#   php artisan servers:awg2-cutover --server-id=<id> --configs=<awg0_peers> --apply
#
# The awg0 peer count printed here is the parity target for that command.
set -Eeuo pipefail

NEW_IFACE=awg1
NEW_PORT=8081
NEW_IPV4=10.67.67.1
NEW_IPV6=fd43:43:43::1
APPLY=0
INSTALL_TIMEOUT=900
SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

while [[ $# -gt 0 ]]; do
	case "$1" in
	--apply)
		APPLY=1
		shift
		;;
	--iface)
		NEW_IFACE=$2
		shift 2
		;;
	--port)
		NEW_PORT=$2
		shift 2
		;;
	--ipv4)
		NEW_IPV4=$2
		shift 2
		;;
	--ipv6)
		NEW_IPV6=$2
		shift 2
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

S=""
if [[ $(id -u) -ne 0 ]]; then
	sudo -n true 2>/dev/null || {
		echo "FAIL: need root or passwordless sudo"
		exit 1
	}
	S="sudo -n"
fi

say() { printf '\n\033[0;32m==> %s\033[0m\n' "$1"; }
die() {
	printf '\n\033[0;31mFAIL: %s\033[0m\n' "$1" >&2
	exit 1
}

# --- 1. Preflight ---------------------------------------------------------
say "Preflight"
[[ -r ${SRC_DIR}/awg2-preflight.sh ]] || die "awg2-preflight.sh must sit next to this script"
bash "${SRC_DIR}/awg2-preflight.sh" --port "${NEW_PORT}" --iface "${NEW_IFACE}" ||
	die "preflight refused this node — fix the blocking issues first"

CUR_IFACE=$(ip -br link show | grep -oE '^(awg|wg)[0-9]+' | head -1)
AWG0_PEERS_BEFORE=$(${S} awg show "${CUR_IFACE}" peers | wc -l | tr -d ' ')
PUB_IP=$(${S} grep -E '^SERVER_PUB_IP=' /etc/amnezia/amneziawg/params | cut -d= -f2-)
PUB_NIC=$(${S} grep -E '^SERVER_PUB_NIC=' /etc/amnezia/amneziawg/params | cut -d= -f2-)
[[ -n ${PUB_IP} && -n ${PUB_NIC} ]] || die "could not read SERVER_PUB_IP / SERVER_PUB_NIC from params"
API_PORT_EXISTING=$(${S} grep -E '^API_PORT=' /etc/wireguard-api/.env | cut -d= -f2- | tr -d '"')
API_PORT_EXISTING=${API_PORT_EXISTING:-8080}

cat <<PLAN

Plan for $(hostname):
  keep      ${CUR_IFACE} running with ${AWG0_PEERS_BEFORE} peers (nobody disconnected)
  create    ${NEW_IFACE} on UDP ${NEW_PORT}, tunnel ${NEW_IPV4} / ${NEW_IPV6}
  public    ${PUB_IP} via ${PUB_NIC}
  padding   S3/S4 randomised per node by this script
  after     backend cutover with --configs=${AWG0_PEERS_BEFORE}

PLAN

if [[ ${APPLY} -ne 1 ]]; then
	echo "Dry run — nothing changed. Re-run with --apply to proceed."
	echo "SUMMARY ok=yes applied=no awg0_peers=${AWG0_PEERS_BEFORE}"
	exit 0
fi

# --- 2. Backup ------------------------------------------------------------
say "Backup"
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=/root/awg2-backup-${STAMP}
${S} mkdir -p "${BACKUP}"
${S} cp -a /etc/amnezia/amneziawg "${BACKUP}/"
${S} cp -a /etc/wireguard-api/.env "${BACKUP}/env.bak"
${S} cp -a /usr/local/bin/wireguard "${BACKUP}/wireguard.bin" 2>/dev/null || true
echo "  ${BACKUP}"

# --- 3. Install -----------------------------------------------------------
# Driven entirely by environment variables. Never pipe answers on stdin: the
# defaults do not apply on a non-tty, and the answers are positional so any
# change in prompt count silently desyncs the rest.
say "Installing ${NEW_IFACE} (this takes a few minutes — DKMS build)"
[[ -r ${SRC_DIR}/amneziawg-install.sh ]] || die "amneziawg-install.sh must sit next to this script"

# EVERY prompt must be answered by an exported variable. The installer runs
# with stdin on /dev/null, so any prompt left unset reads EOF, keeps its empty
# value, and spins its until-loop forever at 100% CPU — this hung a node for 21
# minutes on 2026-08-09 because Jc/S1/S2/H1-H4 were left to the installer's own
# randomiser. Generate them here instead: partial coverage is not
# non-interactive.
rand() { shuf -i"$1"-"$2" -n1; }

AWG_JC=$(rand 3 10)
AWG_JMIN=50
AWG_JMAX=1000
AWG_S1=$(rand 15 150)
AWG_S2=$(rand 15 150)
# The kernel module requires S1 + 56 != S2.
while ((AWG_S1 + 56 == AWG_S2)); do AWG_S2=$(rand 15 150); done
AWG_S3=$(rand 8 64)
AWG_S4=$(rand 4 32)

# Four non-overlapping H ranges, each 1000 wide, well separated.
h_base=$(rand 100000000 400000000)
AWG_H1="${h_base}-$((h_base + 1000))"
AWG_H2="$((h_base + 300000000))-$((h_base + 300001000))"
AWG_H3="$((h_base + 600000000))-$((h_base + 600001000))"
AWG_H4="$((h_base + 900000000))-$((h_base + 900001000))"

echo "  Jc=${AWG_JC} S1=${AWG_S1} S2=${AWG_S2} S3=${AWG_S3} S4=${AWG_S4}"
echo "  H1=${AWG_H1}"
echo "  H4=${AWG_H4}"

cd "${SRC_DIR}"
${S} env \
	AWG_PROFILE=awg2 \
	INSTALL_ALONGSIDE=y \
	INSTALL_CONFIRMATION=INSTALL-AWG2 \
	SERVER_PUB_IP="${PUB_IP}" \
	SERVER_PUB_NIC="${PUB_NIC}" \
	SERVER_AWG_NIC="${NEW_IFACE}" \
	SERVER_PORT="${NEW_PORT}" \
	SERVER_AWG_IPV4="${NEW_IPV4}" \
	SERVER_AWG_IPV6="${NEW_IPV6}" \
	CLIENT_DNS_1=1.1.1.1 \
	CLIENT_DNS_2=1.0.0.1 \
	ALLOWED_IPS='0.0.0.0/0,::/0' \
	SERVER_AWG_JC="${AWG_JC}" \
	SERVER_AWG_JMIN="${AWG_JMIN}" \
	SERVER_AWG_JMAX="${AWG_JMAX}" \
	SERVER_AWG_S1="${AWG_S1}" \
	SERVER_AWG_S2="${AWG_S2}" \
	SERVER_AWG_S3="${AWG_S3}" \
	SERVER_AWG_S4="${AWG_S4}" \
	SERVER_AWG_H1="${AWG_H1}" \
	SERVER_AWG_H2="${AWG_H2}" \
	SERVER_AWG_H3="${AWG_H3}" \
	SERVER_AWG_H4="${AWG_H4}" \
	API_PORT="${API_PORT_EXISTING}" \
	SERVER_AWG_I1= SERVER_AWG_I2= SERVER_AWG_I3= SERVER_AWG_I4= SERVER_AWG_I5= \
	timeout "${INSTALL_TIMEOUT}" bash ./amneziawg-install.sh </dev/null && INSTALL_RC=0 || INSTALL_RC=$?
if [[ ${INSTALL_RC} -eq 124 ]]; then
	die "installer exceeded ${INSTALL_TIMEOUT}s and was killed — it was almost certainly spinning on an unanswered prompt. ${CUR_IFACE} is untouched; nothing to roll back."
fi
[[ ${INSTALL_RC} -eq 0 ]] || die "installer exited ${INSTALL_RC}"

# --- 4. Assert ------------------------------------------------------------
say "Verifying"
ERRORS=0
check() {
	if [[ $2 == "$3" ]]; then
		printf '  \033[0;32mOK\033[0m    %s = %s\n' "$1" "$2"
	else
		printf '  \033[0;31mBAD\033[0m   %s = %s (expected %s)\n' "$1" "$2" "$3"
		ERRORS=$((ERRORS + 1))
	fi
}

ENV=/etc/wireguard-api/.env
check "AWG_PROFILE" "$(${S} grep -E '^AWG_PROFILE=' ${ENV} | cut -d= -f2-)" "awg2"
check "WG_CONFIG_FILE" "$(${S} grep -E '^WG_CONFIG_FILE=' ${ENV} | cut -d= -f2-)" "/etc/amnezia/amneziawg/${NEW_IFACE}.conf"
check "WG_PARAMS_FILE" "$(${S} grep -E '^WG_PARAMS_FILE=' ${ENV} | cut -d= -f2-)" "/etc/amnezia/amneziawg/params.${NEW_IFACE}"

# The installer does not abort when apt is locked, so assert the package
# actually upgraded — that is the failure this catches (a node left running
# AWG2 config against packages that never moved).
#
# Assert the ON-DISK module, not the loaded one. During a side-by-side install
# the running legacy interface pins the old module in the kernel, so
# /sys/module/amneziawg/version legitimately lags until awg0 is torn down. The
# loaded module still serves awg1 correctly: verified on 278 Stockholm, where a
# 1.0.20260611 module completed an AWG2 handshake in 100ms and round-tripped
# transport traffic with S4=15 padding intact. Version strings do not track
# capability here — do not assert on them.
DISK_MODULE=$(modinfo amneziawg 2>/dev/null | awk '/^version/ {print $2}')
if [[ ${DISK_MODULE} == 3.* ]]; then
	printf '  \033[0;32mOK\033[0m    on-disk module = %s\n' "${DISK_MODULE}"
else
	printf '  \033[0;31mBAD\033[0m   on-disk module = %s (expected 3.x — did apt actually upgrade?)\n' "${DISK_MODULE:-none}"
	ERRORS=$((ERRORS + 1))
fi
LOADED_MODULE=$(cat /sys/module/amneziawg/version 2>/dev/null)
if [[ ${LOADED_MODULE} != "${DISK_MODULE}" ]]; then
	printf '  \033[0;33mINFO\033[0m  loaded module = %s, pinned by running %s; matches on-disk after teardown\n' \
		"${LOADED_MODULE}" "${CUR_IFACE}"
fi
check "awg tools" "$(awg --version 2>/dev/null | awk '{print $2}' | cut -c1)" "v"
check "${NEW_IFACE} service" "$(systemctl is-active "awg-quick@${NEW_IFACE}")" "active"
check "${CUR_IFACE} service" "$(systemctl is-active "awg-quick@${CUR_IFACE}")" "active"
check "node API" "$(systemctl is-active wireguard.service)" "active"
check "${NEW_IFACE} port" "$(${S} awg show "${NEW_IFACE}" | awk '/listening port/ {print $3}')" "${NEW_PORT}"

# The whole point of side-by-side: the legacy interface must be untouched.
AWG0_PEERS_AFTER=$(${S} awg show "${CUR_IFACE}" peers | wc -l | tr -d ' ')
check "${CUR_IFACE} peers preserved" "${AWG0_PEERS_AFTER}" "${AWG0_PEERS_BEFORE}"

S3=$(${S} awk -F'= *' '/^S3/ {print $2}' "/etc/amnezia/amneziawg/${NEW_IFACE}.conf")
S4=$(${S} awk -F'= *' '/^S4/ {print $2}' "/etc/amnezia/amneziawg/${NEW_IFACE}.conf")
if [[ ${S3:-0} -gt 0 && ${S4:-0} -gt 0 ]]; then
	printf '  \033[0;32mOK\033[0m    padding S3=%s S4=%s\n' "${S3}" "${S4}"
else
	printf '  \033[0;31mBAD\033[0m   padding S3=%s S4=%s (both must be non-zero)\n' "${S3:-unset}" "${S4:-unset}"
	ERRORS=$((ERRORS + 1))
fi

say "Settling for 60s (a bad WG_PARAMS_FILE restart-loops the API)"
sleep 60
check "node API after settle" "$(systemctl is-active wireguard.service)" "active"
RESTARTS=$(systemctl show wireguard.service -p NRestarts --value)
if [[ ${RESTARTS} -le 1 ]]; then
	printf '  \033[0;32mOK\033[0m    node API restarts: %s\n' "${RESTARTS}"
else
	printf '  \033[0;31mBAD\033[0m   node API restarted %s times — check journalctl -u wireguard.service\n' "${RESTARTS}"
	ERRORS=$((ERRORS + 1))
fi

echo
if [[ ${ERRORS} -gt 0 ]]; then
	echo "----------------------------------------------------------------------"
	echo "INSTALL COMPLETED WITH ${ERRORS} FAILED CHECK(S). Do NOT run the backend"
	echo "cutover. Restore from ${BACKUP} if the node is misbehaving:"
	echo "  systemctl stop awg-quick@${NEW_IFACE}"
	echo "  cp -a ${BACKUP}/amneziawg/. /etc/amnezia/amneziawg/"
	echo "  cp -a ${BACKUP}/env.bak /etc/wireguard-api/.env"
	echo "  systemctl restart wireguard.service"
	echo "SUMMARY ok=no applied=yes errors=${ERRORS} awg0_peers=${AWG0_PEERS_BEFORE}"
	exit 1
fi

echo "----------------------------------------------------------------------"
echo "SIDECAR INSTALL OK — ${CUR_IFACE} still serving ${AWG0_PEERS_AFTER} peers, nobody dropped."
echo
echo "NEXT: probe UDP ${NEW_PORT} from OFF-BOX before the cutover — a provider"
echo "firewall is invisible from here:"
echo "  printf probe | nc -u -w1 ${PUB_IP} ${NEW_PORT}"
echo "  (watch here with: tcpdump -ni any 'udp port ${NEW_PORT}' -c 3)"
echo
echo "THEN on the backend:"
echo "  php artisan servers:awg2-cutover --server-id=<id> --configs=${AWG0_PEERS_BEFORE} --apply"
echo
echo "SUMMARY ok=yes applied=yes awg0_peers=${AWG0_PEERS_BEFORE} new_iface=${NEW_IFACE} new_port=${NEW_PORT} s3=${S3} s4=${S4} backup=${BACKUP}"
