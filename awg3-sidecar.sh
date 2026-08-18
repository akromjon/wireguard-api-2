#!/bin/bash
# Install AWG3 alongside the interface a node is already serving, without
# disconnecting anyone. The incumbent interface keeps running and keeps serving
# every already-issued config; the new awg3 serves everything issued from now on.
#
#   scp awg2-preflight.sh awg3-sidecar.sh amneziawg-install.sh <node>:/tmp/
#   ssh <node> 'bash /tmp/awg3-sidecar.sh --apply'
#
# Without --apply it runs the preflight and prints the plan, changing nothing.
#
# Afterwards, on the backend:
#   php artisan servers:awg3-cutover --server-id=<id> --configs=<peers> --apply
#
# The peer count printed here is the parity target for that command.
#
# NOTE: this shares awg2-preflight.sh, invoked with --awg3. The checks are the
# same node-safety checks; only the kernel-module rule differs.
set -Eeuo pipefail

NEW_IFACE=awg3
NEW_PORT=8443
NEW_IPV4=10.69.66.1
NEW_IPV6=fd45:45:45::1
APPLY=0
INSTALL_TIMEOUT=900
CUR_IFACE=""
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
	--incumbent)
		CUR_IFACE=$2
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
	if [[ -n ${BACKUP:-} ]]; then
		printf 'RECOVERY: restore from %s if the node is misbehaving:\n' "${BACKUP}" >&2
		printf '  systemctl stop awg-quick@%s\n' "${NEW_IFACE}" >&2
		printf '  cp -a %s/amneziawg/. /etc/amnezia/amneziawg/\n' "${BACKUP}" >&2
		printf '  cp -a %s/env.bak /etc/wireguard-api/.env\n' "${BACKUP}" >&2
		printf '  systemctl restart wireguard.service\n' >&2
	fi
	exit 1
}

# --- 1. Preflight ---------------------------------------------------------
say "Preflight"
[[ -r ${SRC_DIR}/awg2-preflight.sh ]] || die "awg2-preflight.sh must sit next to this script"
bash "${SRC_DIR}/awg2-preflight.sh" --awg3 --port "${NEW_PORT}" --iface "${NEW_IFACE}" ||
	die "preflight refused this node — fix the blocking issues first"

if [[ -z ${CUR_IFACE} ]]; then
	# Auto-detect the incumbent interface if not specified.
	mapfile -t IFACES < <(ip -br link show | grep -oE '^(awg|wg)[0-9]+')

	if [[ ${#IFACES[@]} -eq 0 ]]; then
		die "no running AmneziaWG interface found — this script is for co-located installs only"
	elif [[ ${#IFACES[@]} -eq 1 ]]; then
		CUR_IFACE="${IFACES[0]}"
	else
		die "found multiple AmneziaWG interfaces: ${IFACES[*]}. Re-run with --incumbent <iface> to specify which one is the incumbent."
	fi

	# Validate that the detected interface is actually up.
	${S} awg show "${CUR_IFACE}" >/dev/null 2>&1 || die "interface ${CUR_IFACE} is not running"
else
	# Validate that the specified interface is actually up.
	${S} awg show "${CUR_IFACE}" >/dev/null 2>&1 || die "interface ${CUR_IFACE} is not running"
fi
PEERS_BEFORE=$(${S} awg show "${CUR_IFACE}" peers | wc -l | tr -d ' ')
PUB_IP=$(${S} grep -E '^SERVER_PUB_IP=' /etc/amnezia/amneziawg/params | cut -d= -f2-)
PUB_NIC=$(${S} grep -E '^SERVER_PUB_NIC=' /etc/amnezia/amneziawg/params | cut -d= -f2-)
[[ -n ${PUB_IP} && -n ${PUB_NIC} ]] || die "could not read SERVER_PUB_IP / SERVER_PUB_NIC from params"
API_PORT_EXISTING=$(${S} grep -E '^API_PORT=' /etc/wireguard-api/.env | cut -d= -f2- | tr -d '"')
API_PORT_EXISTING=${API_PORT_EXISTING:-8080}

cat <<PLAN

Plan for $(hostname):
  keep      ${CUR_IFACE} running with ${PEERS_BEFORE} peers (nobody disconnected)
  create    ${NEW_IFACE} on UDP ${NEW_PORT}, tunnel ${NEW_IPV4} / ${NEW_IPV6}
  public    ${PUB_IP} via ${PUB_NIC}
  profile   awg3 — header protection ON, S1-S4 all >= 12
  api       reused on TCP ${API_PORT_EXISTING}, repointed to ${NEW_IFACE}
  after     backend cutover with --configs=${PEERS_BEFORE}

WARNING: the shared node API is repointed to AWG3 by this install. The backend
row for this node must already have is_support_awg_third set, or it will hand
AWG3 configs to clients that cannot use them.

PLAN

if [[ ${APPLY} -ne 1 ]]; then
	echo "Dry run — nothing changed. Re-run with --apply to proceed."
	echo "SUMMARY ok=yes applied=no awg2_peers=${PEERS_BEFORE}"
	exit 0
fi

# --- 2. Backup ------------------------------------------------------------
say "Backup"
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=/root/awg3-backup-${STAMP}
${S} mkdir -p "${BACKUP}" || die "failed to create backup directory ${BACKUP}"
${S} cp -a /etc/amnezia/amneziawg "${BACKUP}/" || die "failed to backup /etc/amnezia/amneziawg to ${BACKUP}"
${S} cp -a /etc/wireguard-api/.env "${BACKUP}/env.bak" || die "failed to backup /etc/wireguard-api/.env to ${BACKUP}"
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
# value, and spins its until-loop forever at 100% CPU.
rand() { shuf -i"$1"-"$2" -n1; }

AWG_JC=$(rand 3 10)
AWG_JMIN=50
AWG_JMAX=1000
# All four S values must reach 12: AWG3 header protection reads its ChaCha20
# nonce from the first 12 bytes of the padding prefix. Below 12 it reads into
# the message body, both sides derive different keystreams, and nothing
# connects with no error logged anywhere.
AWG_S1=$(rand 15 150)
AWG_S2=$(rand 15 150)
# The kernel module requires S1 + 56 != S2.
while ((AWG_S1 + 56 == AWG_S2)); do AWG_S2=$(rand 15 150); done
AWG_S3=$(rand 12 64)
AWG_S4=$(rand 12 32)

# Four non-overlapping H ranges, each 1000 wide, well separated.
h_base=$(rand 100000000 400000000)
AWG_H1="${h_base}-$((h_base + 1000))"
AWG_H2="$((h_base + 300000000))-$((h_base + 300001000))"
AWG_H3="$((h_base + 600000000))-$((h_base + 600001000))"
AWG_H4="$((h_base + 900000000))-$((h_base + 900001000))"

echo "  Jc=${AWG_JC} S1=${AWG_S1} S2=${AWG_S2} S3=${AWG_S3} S4=${AWG_S4}"
echo "  H1=${AWG_H1}"
echo "  H4=${AWG_H4}"

# The header protection key and content padding addition are generated by the
# installer when not exported. Leave them to it.
cd "${SRC_DIR}"
${S} env \
	AWG_PROFILE=awg3 \
	INSTALL_ALONGSIDE=y \
	AWG3_COLOCATED_ACK=1 \
	INSTALL_CONFIRMATION=INSTALL-AWG3 \
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
check "AWG_PROFILE" "$(${S} grep -E '^AWG_PROFILE=' ${ENV} | cut -d= -f2-)" "awg3"
check "WG_CONFIG_FILE" "$(${S} grep -E '^WG_CONFIG_FILE=' ${ENV} | cut -d= -f2-)" "/etc/amnezia/amneziawg/${NEW_IFACE}.conf"
check "WG_PARAMS_FILE" "$(${S} grep -E '^WG_PARAMS_FILE=' ${ENV} | cut -d= -f2-)" "/etc/amnezia/amneziawg/params.${NEW_IFACE}"

# Unlike the AWG2 sidecar, assert the LOADED module. AWG3 cannot run against a
# sub-3 module at all, so a stale loaded version here is fatal rather than
# cosmetic.
LOADED_MODULE=$(cat /sys/module/amneziawg/version 2>/dev/null || echo none)
if [[ ${LOADED_MODULE} == 3.* || ${LOADED_MODULE} == 4.* ]]; then
	printf '  \033[0;32mOK\033[0m    loaded module = %s\n' "${LOADED_MODULE}"
else
	printf '  \033[0;31mBAD\033[0m   loaded module = %s (AWG3 needs 3.x — reboot required)\n' "${LOADED_MODULE}"
	ERRORS=$((ERRORS + 1))
fi

check "awg tools" "$(awg --version 2>/dev/null | awk '{print $2}' | cut -c1)" "v"
check "${NEW_IFACE} service" "$(systemctl is-active "awg-quick@${NEW_IFACE}")" "active"
check "${CUR_IFACE} service" "$(systemctl is-active "awg-quick@${CUR_IFACE}")" "active"
check "node API" "$(systemctl is-active wireguard.service)" "active"
check "${NEW_IFACE} port" "$(${S} awg show "${NEW_IFACE}" | awk '/listening port/ {print $3}')" "${NEW_PORT}"

# The whole point of side-by-side: the incumbent interface must be untouched.
PEERS_AFTER=$(${S} awg show "${CUR_IFACE}" peers | wc -l | tr -d ' ')
check "${CUR_IFACE} peers preserved" "${PEERS_AFTER}" "${PEERS_BEFORE}"

CONF="/etc/amnezia/amneziawg/${NEW_IFACE}.conf"
PARAMS="/etc/amnezia/amneziawg/params.${NEW_IFACE}"
if ${S} grep -qE '^HeaderProtectionKey = ' "${CONF}"; then
	printf '  \033[0;32mOK\033[0m    header protection present in %s\n' "${CONF}"
else
	printf '  \033[0;31mBAD\033[0m   no HeaderProtectionKey in %s — this is not an AWG3 interface\n' "${CONF}"
	ERRORS=$((ERRORS + 1))
fi
if ${S} grep -qE '^SERVER_AWG_HEADER_PROTECTION_KEY=' "${PARAMS}"; then
	printf '  \033[0;32mOK\033[0m    header protection key recorded in %s\n' "${PARAMS}"
else
	printf '  \033[0;31mBAD\033[0m   no SERVER_AWG_HEADER_PROTECTION_KEY in %s — issued configs will not carry it\n' "${PARAMS}"
	ERRORS=$((ERRORS + 1))
fi

S3=$(${S} awk -F'= *' '/^S3/ {print $2}' "${CONF}")
S4=$(${S} awk -F'= *' '/^S4/ {print $2}' "${CONF}")
S1=$(${S} awk -F'= *' '/^S1/ {print $2}' "${CONF}")
S2=$(${S} awk -F'= *' '/^S2/ {print $2}' "${CONF}")
PADDING_OK=1
for v in "${S1:-0}" "${S2:-0}" "${S3:-0}" "${S4:-0}"; do
	((v >= 12)) || PADDING_OK=0
done
if ((PADDING_OK == 1)); then
	printf '  \033[0;32mOK\033[0m    padding S1=%s S2=%s S3=%s S4=%s (all >= 12)\n' "${S1}" "${S2}" "${S3}" "${S4}"
else
	printf '  \033[0;31mBAD\033[0m   padding S1=%s S2=%s S3=%s S4=%s — every value must reach 12 or header protection silently fails\n' \
		"${S1:-unset}" "${S2:-unset}" "${S3:-unset}" "${S4:-unset}"
	ERRORS=$((ERRORS + 1))
fi

say "Settling for 60s (a bad WG_PARAMS_FILE restart-loops the API)"
sleep 60
check "node API after settle" "$(systemctl is-active wireguard.service)" "active"
RESTARTS=$(systemctl show wireguard.service -p NRestarts --value 2>/dev/null || echo "unknown")
if [[ ${RESTARTS} =~ ^[0-9]+$ ]]; then
	if [[ ${RESTARTS} -le 1 ]]; then
		printf '  \033[0;32mOK\033[0m    node API restarts: %s\n' "${RESTARTS}"
	else
		printf '  \033[0;31mBAD\033[0m   node API restarted %s times — check journalctl -u wireguard.service\n' "${RESTARTS}"
		ERRORS=$((ERRORS + 1))
	fi
else
	printf '  \033[0;31mBAD\033[0m   could not determine node API restart count (got %s) — check journalctl -u wireguard.service\n' "${RESTARTS}"
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
	echo "SUMMARY ok=no applied=yes errors=${ERRORS} awg2_peers=${PEERS_BEFORE}"
	exit 1
fi

echo "----------------------------------------------------------------------"
echo "AWG3 SIDECAR INSTALL OK — ${CUR_IFACE} still serving ${PEERS_AFTER} peers, nobody dropped."
echo
echo "NEXT: probe UDP ${NEW_PORT} from OFF-BOX before the cutover — a provider"
echo "firewall is invisible from here:"
echo "  printf probe | nc -u -w1 ${PUB_IP} ${NEW_PORT}"
echo "  (watch here with: tcpdump -ni any 'udp port ${NEW_PORT}' -c 3)"
echo
echo "A UDP probe is NOT proof. The only end-to-end proof is a rising handshake"
echo "count after a real client connects:"
echo "  awg show ${NEW_IFACE} latest-handshakes | awk '\$2>0' | wc -l"
echo
echo "THEN on the backend:"
echo "  php artisan servers:awg3-cutover --server-id=<id> --configs=${PEERS_BEFORE} --apply"
echo
echo "SUMMARY ok=yes applied=yes awg2_peers=${PEERS_BEFORE} new_iface=${NEW_IFACE} new_port=${NEW_PORT} s1=${S1} s2=${S2} s3=${S3} s4=${S4} backup=${BACKUP}"
