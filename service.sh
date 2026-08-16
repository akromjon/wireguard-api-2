#!/bin/bash

set -Eeuo pipefail

# github: https://github.com/akromjon/wireguard-api-2
RELEASE_REPO=${RELEASE_REPO:-akromjon/wireguard-api-2}

resolve_release_source() {
	RELEASE_TAG=${WIREGUARD_API_RELEASE_TAG:-}
	if [[ -n ${RELEASE_TAG} ]]; then
		RELEASE_LABEL=${RELEASE_TAG}
		URL_PREFIX="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_TAG}"
	else
		RELEASE_LABEL="latest published release"
		URL_PREFIX="https://github.com/${RELEASE_REPO}/releases/latest/download"
	fi
}

resolve_release_source

AWG_INTERFACE=${AWG_INTERFACE:-awg0}
INSTALL_BINARY=${INSTALL_BINARY:-/usr/local/bin/wireguard}
CONFIG_DIR=${CONFIG_DIR:-/etc/wireguard-api}
SERVICE_NAME=${SERVICE_NAME:-wireguard.service}
API_PORT=${API_PORT:-8080}
WG_CONFIG_FILE=${WG_CONFIG_FILE:-/etc/amnezia/amneziawg/${AWG_INTERFACE}.conf}
WG_PARAMS_FILE=${WG_PARAMS_FILE:-/etc/amnezia/amneziawg/params}
WIREGUARD_CLIENTS=${WIREGUARD_CLIENTS:-/home/wireguard/users}
UPGRADE_EXISTING_SERVICE=${UPGRADE_EXISTING_SERVICE:-false}
UPGRADE_BACKUP_DIR=""
UPGRADE_ROLLBACK_ARMED=0

# Which AmneziaWG profile this node's API generates client configs for. The
# default stays awg2 so running service.sh directly on an existing node keeps
# its behaviour; install3.sh exports awg3.
AWG_PROFILE=${AWG_PROFILE:-awg2}

if [[ ! ${SERVICE_NAME} =~ ^[a-zA-Z0-9_.@-]+\.service$ ]]; then
	echo "Invalid systemd service name: ${SERVICE_NAME}" >&2
	exit 1
fi
if [[ ! ${API_PORT} =~ ^[0-9]+$ ]] || ((API_PORT < 1 || API_PORT > 65535)); then
	echo "Invalid API port: ${API_PORT}" >&2
	exit 1
fi
if [[ ${AWG_PROFILE} != awg2 && ${AWG_PROFILE} != awg3 ]]; then
	echo "Invalid AWG_PROFILE: ${AWG_PROFILE} (expected awg2 or awg3)" >&2
	exit 1
fi

prepare_upgrade_rollback() {
	[[ ${UPGRADE_EXISTING_SERVICE} == true ]] || return 0
	UPGRADE_BACKUP_DIR=$(mktemp -d)
	if [[ -f ${CONFIG_DIR}/.env ]]; then
		cp "${CONFIG_DIR}/.env" "${UPGRADE_BACKUP_DIR}/env"
	fi
	if [[ -f ${INSTALL_BINARY} ]]; then
		cp "${INSTALL_BINARY}" "${UPGRADE_BACKUP_DIR}/binary"
	fi
	if [[ -f /etc/systemd/system/${SERVICE_NAME} ]]; then
		cp "/etc/systemd/system/${SERVICE_NAME}" "${UPGRADE_BACKUP_DIR}/service"
	fi
	UPGRADE_ROLLBACK_ARMED=1
}

rollback_failed_upgrade() {
	local status=$?
	if [[ ${status} -ne 0 && ${UPGRADE_ROLLBACK_ARMED} == 1 && -n ${UPGRADE_BACKUP_DIR} ]]; then
		echo "AWG2 API upgrade failed; restoring the previous ${SERVICE_NAME} binary and environment." >&2
		[[ -f ${UPGRADE_BACKUP_DIR}/env ]] && cp "${UPGRADE_BACKUP_DIR}/env" "${CONFIG_DIR}/.env"
		[[ -f ${UPGRADE_BACKUP_DIR}/binary ]] && install -m 0755 "${UPGRADE_BACKUP_DIR}/binary" "${INSTALL_BINARY}"
		[[ -f ${UPGRADE_BACKUP_DIR}/service ]] && install -m 0644 "${UPGRADE_BACKUP_DIR}/service" "/etc/systemd/system/${SERVICE_NAME}"
		if command -v systemctl >/dev/null 2>&1; then
			systemctl daemon-reload || true
			systemctl restart "${SERVICE_NAME}" || true
		fi
	fi
	[[ -z ${UPGRADE_BACKUP_DIR} ]] || rm -rf "${UPGRADE_BACKUP_DIR}"
}

trap rollback_failed_upgrade EXIT

case "$(uname -sm)" in
"Darwin x86_64") FILENAME="wireguard-darwin-amd64" ;;
"Darwin arm64") FILENAME="wireguard-darwin-arm64" ;;
"Linux x86_64") FILENAME="wireguard-linux-amd64" ;;
"Linux i686") FILENAME="wireguard-linux-386" ;;
"Linux armv7l") FILENAME="wireguard-linux-arm" ;;
"Linux aarch64") FILENAME="wireguard-linux-arm64" ;;
*)
	echo "Unsupported architecture: $(uname -sm)" >&2
	exit 1
	;;
esac

install_binary() (
	local temporary_binary
	temporary_binary=$(mktemp)
	trap 'rm -f "${temporary_binary}"' EXIT

	if [[ -n ${WIREGUARD_API_BINARY:-} ]]; then
		if [[ ! -f ${WIREGUARD_API_BINARY} ]]; then
			echo "WIREGUARD_API_BINARY does not exist: ${WIREGUARD_API_BINARY}" >&2
			exit 1
		fi
		echo "Installing API binary from ${WIREGUARD_API_BINARY}"
		cp "${WIREGUARD_API_BINARY}" "${temporary_binary}"
	else
		echo "Downloading ${FILENAME} from ${RELEASE_REPO} (${RELEASE_LABEL})"
		if ! curl -sSLf "${URL_PREFIX}/${FILENAME}" -o "${temporary_binary}"; then
			echo "Failed to download ${FILENAME} from ${RELEASE_LABEL}; publish a compatible release asset or set WIREGUARD_API_BINARY" >&2
			exit 1
		fi
	fi

	mkdir -p "$(dirname "${INSTALL_BINARY}")"
	install -m 0755 "${temporary_binary}" "${INSTALL_BINARY}"
)

set_env_value() {
	local key=$1
	local value=$2
	local escaped_value=${value//|/\\|}
	if grep -q "^${key}=" "${CONFIG_DIR}/.env"; then
		sed -i.bak "s|^${key}=.*$|${key}=${escaped_value}|" "${CONFIG_DIR}/.env"
		rm -f "${CONFIG_DIR}/.env.bak"
	else
		printf '%s=%s\n' "${key}" "${value}" >>"${CONFIG_DIR}/.env"
	fi
}

prepare_environment() {
	mkdir -p "${CONFIG_DIR}" "${WIREGUARD_CLIENTS}"
	chmod 700 "${CONFIG_DIR}" "${WIREGUARD_CLIENTS}"

	if [[ ! -f ${CONFIG_DIR}/.env ]]; then
		if [[ -f ./.env.example ]]; then
			cp ./.env.example "${CONFIG_DIR}/.env"
		else
			: >"${CONFIG_DIR}/.env"
		fi
	fi
	chmod 600 "${CONFIG_DIR}/.env"

	local current_api_token
	current_api_token=$(grep '^API_TOKEN=' "${CONFIG_DIR}/.env" | cut -d= -f2- || true)
	if [[ -z ${current_api_token} || ${current_api_token} == replace-this-with-your-secure-random-token ]]; then
		if [[ ${UPGRADE_EXISTING_SERVICE} == true ]]; then
			echo "The existing API_TOKEN is missing or still a placeholder; refusing to rotate the legacy service token automatically." >&2
			exit 1
		fi
		current_api_token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
		set_env_value API_TOKEN "${current_api_token}"
	fi

	set_env_value API_PORT "${API_PORT}"
	API_TOKEN=${current_api_token}
	set_env_value AWG_PROFILE "${AWG_PROFILE}"
	set_env_value WG_CONFIG_FILE "${WG_CONFIG_FILE}"
	set_env_value WG_PARAMS_FILE "${WG_PARAMS_FILE}"
	set_env_value WIREGUARD_CLIENTS "${WIREGUARD_CLIENTS}"
}

install_service() (
	local unit_path="/etc/systemd/system/${SERVICE_NAME}"
	local temporary_unit
	temporary_unit=$(mktemp)
	trap 'rm -f "${temporary_unit}"' EXIT

	cat >"${temporary_unit}" <<EOF
[Unit]
Description=WireGuard API V2 for ${AWG_INTERFACE} (AmneziaWG 2.0)
After=network.target awg-quick@${AWG_INTERFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
ExecStart=${INSTALL_BINARY}
EnvironmentFile=${CONFIG_DIR}/.env
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

	install -m 0644 "${temporary_unit}" "${unit_path}"
	systemctl daemon-reload
	systemctl enable "${SERVICE_NAME}"
	if systemctl is-active --quiet "${SERVICE_NAME}"; then
		systemctl restart "${SERVICE_NAME}"
	else
		systemctl start "${SERVICE_NAME}"
	fi

	if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
		echo "Failed to start ${SERVICE_NAME}" >&2
		echo "Check logs with: journalctl -u ${SERVICE_NAME}" >&2
		exit 1
	fi
)

verify_token_context() {
	local api_token=$1
	local expected_interface=$2
	local response attempt
	for ((attempt = 1; attempt <= 10; attempt++)); do
		response=$(curl -fsS --max-time 2 -H "key: ${api_token}" "http://127.0.0.1:${API_PORT}/api/health" || true)
		if [[ ${response} == *'"success":true'* && ${response} == *'"interface":"'"${expected_interface}"'"'* && ${response} == *'"profile":"'"${AWG_PROFILE}"'"'* ]]; then
			echo "Verified ${SERVICE_NAME} serves ${expected_interface} with ${AWG_PROFILE} on TCP ${API_PORT}."
			return 0
		fi
		sleep 1
	done

	echo "API verification failed: ${SERVICE_NAME} did not serve ${expected_interface} with ${AWG_PROFILE} on TCP ${API_PORT}." >&2
	return 1
}

verify_api_instance() {
	verify_token_context "${API_TOKEN}" "${AWG_INTERFACE}"
}

register_with_vipn_master() {
	if [[ ${UPGRADE_EXISTING_SERVICE} == true ]]; then
		echo "Existing VIPN server record remains on ${API_PORT} with its current API token; skipping duplicate registration."
		return
	fi
	read -rp "Register this AWG2 node with VIPN master? [Y/n]: " REGISTER_WITH_MASTER
	REGISTER_WITH_MASTER=${REGISTER_WITH_MASTER:-Y}
	if [[ ! ${REGISTER_WITH_MASTER} =~ ^[Yy]$ ]]; then
		echo "Skipping VIPN master registration. You can still add this server manually."
		return
	fi

	read -rp "Enter VIPN master API URL [https://api.vipn.io]: " MASTER_URL
	MASTER_URL=${MASTER_URL:-https://api.vipn.io}
	MASTER_URL=${MASTER_URL%/}

	read -rsp "Enter VIPN master provisioning token: " MASTER_TOKEN
	echo ""
	if [[ -z ${MASTER_TOKEN} ]]; then
		echo "VIPN master provisioning token is empty. Skipping registration."
		return
	fi

	local api_token public_ip register_payload
	api_token=${API_TOKEN:-$(grep '^API_TOKEN=' "${CONFIG_DIR}/.env" | cut -d= -f2- || true)}
	if [[ -z ${api_token} ]]; then
		echo "API_TOKEN not found in ${CONFIG_DIR}/.env. Skipping registration."
		return
	fi

	public_ip=$(curl -fsS --max-time 5 https://api.ipify.org || true)
	if [[ -z ${public_ip} ]]; then
		public_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
	fi
	if [[ -z ${public_ip} ]]; then
		echo "Could not detect public IP. Skipping registration."
		return
	fi

	register_payload=$(printf '{"ip":"%s","port":%s,"api_key":"%s","vpn_type":"amneziawg"}' "${public_ip}" "${API_PORT}" "${api_token}")
	echo "Registering this AWG2 API instance with VIPN master..."
	if curl -fsS \
		-H "Authorization: Bearer ${MASTER_TOKEN}" \
		-H "Accept: application/json" \
		-H "Content-Type: application/json" \
		-d "${register_payload}" \
		"${MASTER_URL}/master-api/register-node"; then
		echo ""
		echo -e "\033[0;32mVIPN master registration completed.\033[0m"
	else
		echo ""
		echo "VIPN master registration failed. Add this API instance manually using the details below."
	fi
}

# Allow the local validation suite to verify isolated environment generation
# without installing a binary or touching systemd.
if [[ ${WIREGUARD_API_SERVICE_LIB_ONLY:-0} == 1 ]]; then
	trap - EXIT
	return 0 2>/dev/null || exit 0
fi

prepare_upgrade_rollback
prepare_environment
install_binary

if [[ $(uname -s) == Linux ]] && command -v systemctl &>/dev/null; then
	install_service
	verify_api_instance
	UPGRADE_ROLLBACK_ARMED=0
	register_with_vipn_master
fi

API_TOKEN=${API_TOKEN:-$(grep '^API_TOKEN=' "${CONFIG_DIR}/.env" | cut -d= -f2-)}
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
LOCAL_IP=${LOCAL_IP:-localhost}

echo ""
echo -e "\033[0;32mWireGuard API V2 for ${AWG_INTERFACE} installed successfully.\033[0m"
echo "- Service: ${SERVICE_NAME}"
echo "- API: http://${LOCAL_IP}:${API_PORT}"
echo "- Config: ${CONFIG_DIR}/.env"
echo "- VPN config: ${WG_CONFIG_FILE}"
if [[ ${UPGRADE_EXISTING_SERVICE} == true ]]; then
	echo "- Existing API token: preserved"
else
	echo "- API token: ${API_TOKEN}"
fi
