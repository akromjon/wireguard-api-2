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

cat <<PLAN

Plan for $(hostname):
  keep      ${CUR_IFACE} running with ${AWG0_PEERS_BEFORE} peers (nobody disconnected)
  create    ${NEW_IFACE} on UDP ${NEW_PORT}, tunnel ${NEW_IPV4} / ${NEW_IPV6}
  public    ${PUB_IP} via ${PUB_NIC}
  padding   S3/S4 randomised per node by the installer
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
	SERVER_AWG_I1= SERVER_AWG_I2= SERVER_AWG_I3= SERVER_AWG_I4= SERVER_AWG_I5= \
	bash ./amneziawg-install.sh </dev/null || die "installer exited non-zero"

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

# The installer does not abort when apt is locked; without this assert a node
# can end up running AWG2 config on the old 1.0 kernel module.
check "kernel module" "$(cat /sys/module/amneziawg/version 2>/dev/null)" "3.0.20260805"
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
