#!/bin/bash

# AmneziaWG server installer
# https://github.com/varckin/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"
AWG_CLIENTS_DIR="/home/wireguard/users"
AWG_H_MIN=5
AWG_H_MAX=2147483647
AWG_H_RANGE_WIDTH=1000

EXISTING_AWG_INTERFACES=()
EXISTING_AWG_PORTS=()
EXISTING_API_PORTS=()
EXISTING_AWG_SUMMARIES=()
LEGACY_AWG_DETECTED=0
AWG2_DETECTED=0

function array_contains() {
	local expected=$1
	shift
	local item
	for item in "$@"; do
		[[ ${item} == "${expected}" ]] && return 0
	done
	return 1
}

function add_existing_interface() {
	local interface=$1
	[[ -n ${interface} ]] || return
	if ((${#EXISTING_AWG_INTERFACES[@]} > 0)) && array_contains "${interface}" "${EXISTING_AWG_INTERFACES[@]}"; then
		return
	fi
	EXISTING_AWG_INTERFACES+=("${interface}")
}

function add_existing_awg_port() {
	local port=$1
	[[ ${port} =~ ^[0-9]+$ ]] || return
	if ((${#EXISTING_AWG_PORTS[@]} > 0)) && array_contains "${port}" "${EXISTING_AWG_PORTS[@]}"; then
		return
	fi
	EXISTING_AWG_PORTS+=("${port}")
}

function add_existing_api_port() {
	local port=$1
	[[ ${port} =~ ^[0-9]+$ ]] || return
	if ((${#EXISTING_API_PORTS[@]} > 0)) && array_contains "${port}" "${EXISTING_API_PORTS[@]}"; then
		return
	fi
	EXISTING_API_PORTS+=("${port}")
}

function detect_existing_awg_installations() {
	local config interface port profile env_file
	local -a config_files env_files live_interfaces

	EXISTING_AWG_INTERFACES=()
	EXISTING_AWG_PORTS=()
	EXISTING_API_PORTS=()
	EXISTING_AWG_SUMMARIES=()
	LEGACY_AWG_DETECTED=0
	AWG2_DETECTED=0

	config_files=("${AMNEZIAWG_DIR}"/*.conf)
	for config in "${config_files[@]}"; do
		[[ -f ${config} ]] || continue
		interface=$(basename "${config}" .conf)
		port=$(awk -F= '/^[[:space:]]*ListenPort[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "${config}")
		profile=legacy
		if grep -Eq '^# CHOP-AWG-PROFILE: awg2$|^[[:space:]]*S3[[:space:]]*=' "${config}"; then
			profile=awg2
			AWG2_DETECTED=1
		else
			LEGACY_AWG_DETECTED=1
		fi
		add_existing_interface "${interface}"
		add_existing_awg_port "${port}"
		EXISTING_AWG_SUMMARIES+=("${interface}|${profile}|${port:-unknown}|${config}")
	done

	if command -v awg >/dev/null 2>&1; then
		read -r -a live_interfaces <<<"$(awg show interfaces 2>/dev/null || true)"
		for interface in "${live_interfaces[@]}"; do
			[[ -n ${interface} ]] || continue
			add_existing_interface "${interface}"
			port=$(awg show "${interface}" listen-port 2>/dev/null || true)
			add_existing_awg_port "${port}"
		done
	fi

	if [[ -f ${AMNEZIAWG_DIR}/params ]] && ((${#EXISTING_AWG_INTERFACES[@]} == 0)); then
		LEGACY_AWG_DETECTED=1
		interface=$(awk -F= '/^SERVER_AWG_NIC=/ {gsub(/["[:space:]]|\047/, "", $2); print $2; exit}' "${AMNEZIAWG_DIR}/params")
		port=$(awk -F= '/^SERVER_PORT=/ {gsub(/["[:space:]]|\047/, "", $2); print $2; exit}' "${AMNEZIAWG_DIR}/params")
		add_existing_interface "${interface:-awg0}"
		add_existing_awg_port "${port}"
		EXISTING_AWG_SUMMARIES+=("${interface:-awg0}|legacy|${port:-unknown}|${AMNEZIAWG_DIR}/params")
	fi

	env_files=(/etc/wireguard-api*/.env)
	for env_file in "${env_files[@]}"; do
		[[ -f ${env_file} ]] || continue
		port=$(awk -F= '/^API_PORT=/ {gsub(/["[:space:]]|\047/, "", $2); print $2; exit}' "${env_file}")
		add_existing_api_port "${port}"
	done
}

function interface_in_use() {
	local interface=$1
	if ((${#EXISTING_AWG_INTERFACES[@]} > 0)) && array_contains "${interface}" "${EXISTING_AWG_INTERFACES[@]}"; then
		return 0
	fi
	[[ -e ${AMNEZIAWG_DIR}/${interface}.conf ]] && return 0
	if command -v ip >/dev/null 2>&1 && ip link show "${interface}" >/dev/null 2>&1; then
		return 0
	fi
	return 1
}

function udp_port_in_use() {
	local port=$1
	if ((${#EXISTING_AWG_PORTS[@]} > 0)) && array_contains "${port}" "${EXISTING_AWG_PORTS[@]}"; then
		return 0
	fi
	if command -v ss >/dev/null 2>&1 && ss -H -lun 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
		return 0
	fi
	return 1
}

function tcp_port_in_use() {
	local port=$1
	if ((${#EXISTING_API_PORTS[@]} > 0)) && array_contains "${port}" "${EXISTING_API_PORTS[@]}"; then
		return 0
	fi
	if command -v ss >/dev/null 2>&1 && ss -H -ltn 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
		return 0
	fi
	return 1
}

function suggest_awg_interface() {
	local index candidate
	for ((index = 0; index < 100; index++)); do
		candidate="awg${index}"
		if ! interface_in_use "${candidate}"; then
			echo "${candidate}"
			return 0
		fi
	done
	return 1
}

function suggest_udp_port() {
	local port attempts
	for ((attempts = 0; attempts < 200; attempts++)); do
		port=$(shuf -i2000-9999 -n1)
		if ! udp_port_in_use "${port}"; then
			echo "${port}"
			return 0
		fi
	done
	return 1
}

function suggest_api_port() {
	local port
	for ((port = 8080; port <= 8199; port++)); do
		if ! tcp_port_in_use "${port}"; then
			echo "${port}"
			return 0
		fi
	done
	return 1
}

function print_existing_awg_summary() {
	local summary interface profile port config
	if ((${#EXISTING_AWG_SUMMARIES[@]} == 0)); then
		return
	fi

	echo -e "${YELLOW}Detected existing AmneziaWG installation(s):${NC}"
	for summary in "${EXISTING_AWG_SUMMARIES[@]}"; do
		IFS='|' read -r interface profile port config <<<"${summary}"
		printf '  - %s: profile=%s, UDP port=%s, source=%s\n' "${interface}" "${profile}" "${port}" "${config}"
	done
	echo "The existing VPN interfaces, listener ports, configs, and peers will not be modified before confirmation."
}

# AWG2 accepts a single H value or an inclusive range. Keep the four H
# ranges valid and non-overlapping so a packet cannot match multiple H rules.
function h_spec_bounds() {
	local spec="$1"
	if [[ ${spec} =~ ^([0-9]+)-([0-9]+)$ ]]; then
		H_SPEC_LOW=${BASH_REMATCH[1]}
		H_SPEC_HIGH=${BASH_REMATCH[2]}
	elif [[ ${spec} =~ ^[0-9]+$ ]]; then
		H_SPEC_LOW=${spec}
		H_SPEC_HIGH=${spec}
	else
		return 1
	fi

	[[ ${H_SPEC_LOW} -ge ${AWG_H_MIN} && ${H_SPEC_HIGH} -le ${AWG_H_MAX} && ${H_SPEC_LOW} -le ${H_SPEC_HIGH} ]]
}

function h_specs_overlap() {
	local specs=("$@")
	local i j low1 high1 low2 high2
	for ((i = 0; i < ${#specs[@]}; i++)); do
		h_spec_bounds "${specs[i]}" || return 0
		low1=${H_SPEC_LOW}
		high1=${H_SPEC_HIGH}
		for ((j = i + 1; j < ${#specs[@]}; j++)); do
			h_spec_bounds "${specs[j]}" || return 0
			low2=${H_SPEC_LOW}
			high2=${H_SPEC_HIGH}
			if (( low1 <= high2 && low2 <= high1 )); then
				return 0
			fi
		done
	done
	return 1
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 20 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]] || [[ ${VERSION_ID} == 8* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 9 or later"
			exit 1
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux or Rocky Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Co-located interfaces must not share generated client files.
	if [ ! -d "${AWG_CLIENTS_DIR}" ]; then
		mkdir -p "${AWG_CLIENTS_DIR}"
		chmod 700 "/home/wireguard"
		chmod 700 "${AWG_CLIENTS_DIR}"
	fi

	HOME_DIR="${AWG_CLIENTS_DIR}"

	echo "$HOME_DIR"
}

function checkPackageAvailability() {
	local PACKAGE_NAME=$1
	if apt-cache show "${PACKAGE_NAME}" &>/dev/null; then
		return 0
	else
		return 1
	fi
}

function installPackagesFromNoble() {
	echo -e "${ORANGE}Packages not available for current Ubuntu version. Attempting to install from Ubuntu 24.04 (noble)...${NC}"
	echo -e "${ORANGE}Warning: This is a workaround and may have compatibility risks.${NC}"
	
	# Add GPG key for the repository (same key as the main PPA)
	# Key ID: 57290828 (full: 4166F2C257290828)
	echo -e "${YELLOW}Adding GPG key for Amnezia PPA...${NC}"
	mkdir -p /etc/apt/keyrings
	
	# Try modern method first (using gpg directly)
	if command -v gpg &>/dev/null; then
		# Download and import the key using modern method
		curl -fsSL https://keyserver.ubuntu.com/pks/lookup?op=get\&search=0x57290828 2>/dev/null | gpg --dearmor -o /etc/apt/keyrings/amnezia-ppa.gpg 2>/dev/null || {
			# Alternative: use gpg --keyserver
			gpg --no-default-keyring --keyring /etc/apt/keyrings/amnezia-ppa.gpg --keyserver keyserver.ubuntu.com --recv-keys 57290828 2>/dev/null || true
		}
	fi
	
	# Fallback to deprecated apt-key method if modern method failed
	if [[ ! -f /etc/apt/keyrings/amnezia-ppa.gpg ]]; then
		if command -v apt-key &>/dev/null; then
			apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828 2>/dev/null || true
		fi
	fi
	
	# Add noble repository with proper GPG key configuration
	NOBLE_SOURCE="/etc/apt/sources.list.d/amneziawg-noble.list"
	if [[ ! -f "${NOBLE_SOURCE}" ]]; then
		# Use signed-by if keyring exists, otherwise unsigned (will need --allow-unauthenticated)
		if [[ -f /etc/apt/keyrings/amnezia-ppa.gpg ]]; then
			echo "deb [signed-by=/etc/apt/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main" > "${NOBLE_SOURCE}"
			echo -e "${GREEN}Added noble repository with GPG key${NC}"
		else
			# Unsigned - we'll use --allow-unauthenticated when installing
			echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main" > "${NOBLE_SOURCE}"
			echo -e "${ORANGE}Added noble repository without GPG key (will use --allow-unauthenticated)${NC}"
		fi
	fi
	
	# Update package lists - force update even if repository is unsigned
	echo -e "${YELLOW}Updating package lists...${NC}"
	local APT_UPDATE_OUTPUT
	local GPG_ISSUE=false
	
	# Try normal update first
	APT_UPDATE_OUTPUT=$(apt update 2>&1)
	echo "${APT_UPDATE_OUTPUT}"
	
	# Check if GPG key issue occurred
	if echo "${APT_UPDATE_OUTPUT}" | grep -q "NO_PUBKEY\|not signed"; then
		GPG_ISSUE=true
		echo -e "${ORANGE}GPG key issue detected. Forcing update with --allow-insecure-repositories...${NC}"
		
		# Force update with insecure repositories flag
		APT_UPDATE_OUTPUT=$(apt update --allow-insecure-repositories 2>&1)
		echo "${APT_UPDATE_OUTPUT}"
		
		# If still failing, try with Acquire::AllowInsecureRepositories
		if echo "${APT_UPDATE_OUTPUT}" | grep -q "not signed\|NO_PUBKEY"; then
			echo -e "${ORANGE}Using apt configuration workaround...${NC}"
			# Create temporary apt config to allow insecure repos
			mkdir -p /etc/apt/apt.conf.d
			echo 'Acquire::AllowInsecureRepositories "true";' > /etc/apt/apt.conf.d/99allow-insecure-temp.conf
			echo 'APT::Get::AllowUnauthenticated "true";' >> /etc/apt/apt.conf.d/99allow-insecure-temp.conf
			APT_UPDATE_OUTPUT=$(apt update 2>&1)
			echo "${APT_UPDATE_OUTPUT}"
			
			# Verify update succeeded (check if we got packages from noble)
			if echo "${APT_UPDATE_OUTPUT}" | grep -q "noble.*InRelease\|Get:.*noble"; then
				echo -e "${GREEN}Successfully updated package lists from noble repository${NC}"
			else
				echo -e "${ORANGE}Warning: Package list update may not have included noble repository${NC}"
			fi
		fi
	fi
	
	# Check what's already installed and what we need from noble
	local NEED_DKMS=false
	local NEED_TOOLS=true
	
	# Check if amneziawg-dkms is already installed
	if dpkg -l | grep -q "^ii.*amneziawg-dkms\|^ii.*amneziawg "; then
		echo -e "${GREEN}amneziawg-dkms or amneziawg is already installed${NC}"
		NEED_DKMS=false
	else
		NEED_DKMS=true
	fi
	
	# Check if amneziawg-tools is already installed
	if command -v awg &>/dev/null; then
		echo -e "${GREEN}amneziawg-tools is already installed${NC}"
		NEED_TOOLS=false
	fi
	
	# Only install dkms if needed
	if [[ "${NEED_DKMS}" == "true" ]]; then
		echo -e "${YELLOW}Installing amneziawg-dkms from noble...${NC}"
		if ! apt install -y --allow-downgrades amneziawg-dkms 2>/dev/null; then
			if ! apt install -y --allow-downgrades amneziawg 2>/dev/null; then
				echo -e "${ORANGE}Could not install amneziawg-dkms from noble, but continuing...${NC}"
			fi
		fi
	fi
	
	# Install amneziawg-tools from noble (this is why we're here)
	if [[ "${NEED_TOOLS}" == "true" ]]; then
		echo -e "${YELLOW}Installing amneziawg-tools from noble...${NC}"
		
		# Check if package is available in noble repository
		echo -e "${YELLOW}Checking package availability...${NC}"
		local PACKAGE_FOUND=false
		if apt-cache madison amneziawg-tools 2>/dev/null | grep -q "noble"; then
			echo -e "${GREEN}Found amneziawg-tools in noble repository${NC}"
			PACKAGE_FOUND=true
		else
			echo -e "${ORANGE}amneziawg-tools not found in noble repository. Checking all sources...${NC}"
			local ALL_SOURCES
			ALL_SOURCES=$(apt-cache madison amneziawg-tools 2>/dev/null)
			if [[ -n "${ALL_SOURCES}" ]]; then
				echo "${ALL_SOURCES}"
				echo -e "${YELLOW}Package found in other repositories, will attempt installation...${NC}"
				PACKAGE_FOUND=true
			else
				echo -e "${RED}Package amneziawg-tools not found in any repository${NC}"
				echo -e "${ORANGE}This may mean the package list wasn't updated properly or the package doesn't exist.${NC}"
			fi
		fi
		
		if [[ "${PACKAGE_FOUND}" == "false" ]]; then
			# Clean up temporary apt config
			rm -f /etc/apt/apt.conf.d/99allow-insecure-temp.conf 2>/dev/null || true
			return 1
		fi
		
		# Try multiple installation methods due to GPG key issues
		local INSTALL_SUCCESS=false
		
		# Method 1: Normal installation
		if apt install -y amneziawg-tools 2>/dev/null; then
			INSTALL_SUCCESS=true
		# Method 2: With allow-downgrades
		elif apt install -y --allow-downgrades amneziawg-tools 2>/dev/null; then
			INSTALL_SUCCESS=true
		# Method 3: With allow-insecure-repositories
		elif [[ "${GPG_ISSUE}" == "true" ]]; then
			if apt install -y --allow-downgrades --allow-insecure-repositories amneziawg-tools 2>/dev/null; then
				INSTALL_SUCCESS=true
			# Method 4: With allow-unauthenticated (last resort)
			elif apt install -y --allow-downgrades --allow-unauthenticated amneziawg-tools 2>/dev/null; then
				INSTALL_SUCCESS=true
			fi
		fi
		
		if [[ "${INSTALL_SUCCESS}" == "false" ]]; then
			echo -e "${RED}Failed to install amneziawg-tools from noble${NC}"
			# Clean up temporary apt config
			rm -f /etc/apt/apt.conf.d/99allow-insecure-temp.conf 2>/dev/null || true
			return 1
		fi
		
		echo -e "${GREEN}Successfully installed amneziawg-tools${NC}"
	fi
	
	# Clean up temporary apt config
	rm -f /etc/apt/apt.conf.d/99allow-insecure-temp.conf 2>/dev/null || true
	
	echo -e "${GREEN}Successfully installed packages from Ubuntu 24.04 (noble)${NC}"
	return 0
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function readJminAndJmax() {
	SERVER_AWG_JMIN=0
	SERVER_AWG_JMAX=0
	until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMIN} >= 1 )) && (( ${SERVER_AWG_JMIN} <= 1280 )); do
		read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 50 SERVER_AWG_JMIN
	done
	until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMAX} >= 1 )) && (( ${SERVER_AWG_JMAX} <= 1280 )); do
		read -rp "Server AmneziaWG Jmax [1-1280]: " -e -i 1000 SERVER_AWG_JMAX
	done
}

function generateS1AndS2() {
	RANDOM_AWG_S1=$(shuf -i15-150 -n1)
	RANDOM_AWG_S2=$(shuf -i15-150 -n1)
}

function readS1AndS2() {
	SERVER_AWG_S1=0
	SERVER_AWG_S2=0
	until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S1} >= 15 )) && (( ${SERVER_AWG_S1} <= 150 )); do
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i ${RANDOM_AWG_S1} SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S2} >= 15 )) && (( ${SERVER_AWG_S2} <= 150 )); do
		read -rp "Server AmneziaWG S2 [15-150]: " -e -i ${RANDOM_AWG_S2} SERVER_AWG_S2
	done
}

function generateH1AndH2AndH3AndH4() {
	local generated_low index
	local -a generated
	while :; do
		generated=()
		for index in 1 2 3 4; do
			generated_low=$(shuf -i "${AWG_H_MIN}-$((AWG_H_MAX - AWG_H_RANGE_WIDTH))" -n1)
			generated+=("${generated_low}-$((generated_low + AWG_H_RANGE_WIDTH))")
		done
		if ! h_specs_overlap "${generated[@]}"; then
			RANDOM_AWG_H1=${generated[0]}
			RANDOM_AWG_H2=${generated[1]}
			RANDOM_AWG_H3=${generated[2]}
			RANDOM_AWG_H4=${generated[3]}
			return
		fi
	done
}

function readH1AndH2AndH3AndH4() {
	until h_spec_bounds "${SERVER_AWG_H1}"; do
		read -rp "Server AmneziaWG H1 [5-2147483647 or range]: " -e -i "${RANDOM_AWG_H1}" SERVER_AWG_H1
	done
	until h_spec_bounds "${SERVER_AWG_H2}"; do
		read -rp "Server AmneziaWG H2 [5-2147483647 or range]: " -e -i "${RANDOM_AWG_H2}" SERVER_AWG_H2
	done
	until h_spec_bounds "${SERVER_AWG_H3}"; do
		read -rp "Server AmneziaWG H3 [5-2147483647 or range]: " -e -i "${RANDOM_AWG_H3}" SERVER_AWG_H3
	done
	until h_spec_bounds "${SERVER_AWG_H4}"; do
		read -rp "Server AmneziaWG H4 [5-2147483647 or range]: " -e -i "${RANDOM_AWG_H4}" SERVER_AWG_H4
	done
}

function readS3AndS4() {
	SERVER_AWG_S3=0
	SERVER_AWG_S4=0
	until [[ ${SERVER_AWG_S3} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S3 <= 64 )); do
		read -rp "Server AmneziaWG S3 padding [0-64, 0 disables]: " -e -i 0 SERVER_AWG_S3
	done
	until [[ ${SERVER_AWG_S4} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S4 <= 32 )); do
		read -rp "Server AmneziaWG S4 padding [0-32, 0 disables]: " -e -i 0 SERVER_AWG_S4
	done
}

function readIParams() {
	echo "AWG2 I1-I5 signatures are optional. Leave them empty unless your deployment has chosen values."
	read -rp "AmneziaWG I1 (optional): " SERVER_AWG_I1
	read -rp "AmneziaWG I2 (optional): " SERVER_AWG_I2
	read -rp "AmneziaWG I3 (optional): " SERVER_AWG_I3
	read -rp "AmneziaWG I4 (optional): " SERVER_AWG_I4
	read -rp "AmneziaWG I5 (optional): " SERVER_AWG_I5
}

function ipv4_tunnel_in_use() {
	local address=$1
	local prefix
	prefix=$(awk -F. '{print $1 "." $2 "."}' <<<"${address}")
	grep -Ehs '^[[:space:]]*Address[[:space:]]*=' "${AMNEZIAWG_DIR}"/*.conf 2>/dev/null | grep -Fq "${prefix}"
}

function ipv6_tunnel_in_use() {
	local address=$1
	local prefix=${address%::*}
	grep -Ehis '^[[:space:]]*Address[[:space:]]*=' "${AMNEZIAWG_DIR}"/*.conf 2>/dev/null | grep -Fiq "${prefix}:"
}

function configure_installation_layout() {
	local interface_index=0 ipv4_octet=66 ipv6_segment=42 summary interface profile port config
	if [[ ${SERVER_AWG_NIC} =~ ^awg([0-9]+)$ ]]; then
		interface_index=${BASH_REMATCH[1]}
	fi
	ipv4_octet=$((66 + interface_index))
	ipv6_segment=$((42 + interface_index))
	((ipv4_octet <= 254)) || ipv4_octet=254

	DEFAULT_AWG_IPV4="10.${ipv4_octet}.66.1"
	DEFAULT_AWG_IPV6="fd42:42:${ipv6_segment}::1"

	if ((${#EXISTING_AWG_INTERFACES[@]} > 0)); then
		SERVER_PARAMS_FILE="${AMNEZIAWG_DIR}/params.${SERVER_AWG_NIC}"
		AWG_CLIENTS_DIR="/home/wireguard/users-${SERVER_AWG_NIC}"
		API_CONFIG_DIR="/etc/wireguard-api"
		API_SERVICE_NAME="wireguard.service"
		API_BINARY_PATH="/usr/local/bin/wireguard"
		LEGACY_WG_PARAMS_FILE="${AMNEZIAWG_DIR}/params"
		for summary in "${EXISTING_AWG_SUMMARIES[@]}"; do
			IFS='|' read -r interface profile port config <<<"${summary}"
			if [[ ${profile} == legacy ]]; then
				LEGACY_WG_CONFIG_FILE="${config}"
				LEGACY_SERVER_PORT="${port}"
				break
			fi
		done
		LEGACY_WG_CONFIG_FILE=${LEGACY_WG_CONFIG_FILE:-${AMNEZIAWG_DIR}/awg0.conf}
		if [[ -f ${API_CONFIG_DIR}/.env ]]; then
			API_PORT=$(awk -F= '/^API_PORT=/ {gsub(/["[:space:]]|\047/, "", $2); print $2; exit}' "${API_CONFIG_DIR}/.env")
		fi
		API_PORT=${API_PORT:-8080}
		REUSE_EXISTING_API=1
	else
		SERVER_PARAMS_FILE="${AMNEZIAWG_DIR}/params"
		AWG_CLIENTS_DIR="/home/wireguard/users"
		API_CONFIG_DIR="/etc/wireguard-api"
		API_SERVICE_NAME="wireguard.service"
		API_BINARY_PATH="/usr/local/bin/wireguard"
		REUSE_EXISTING_API=0
	fi
}

function validate_installation_choices() {
	local config_path="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	if interface_in_use "${SERVER_AWG_NIC}" || [[ -e ${config_path} ]]; then
		echo -e "${RED}Interface ${SERVER_AWG_NIC} or ${config_path} already exists.${NC}" >&2
		return 1
	fi
	if udp_port_in_use "${SERVER_PORT}"; then
		echo -e "${RED}UDP port ${SERVER_PORT} is already assigned or listening.${NC}" >&2
		return 1
	fi
	if [[ ${REUSE_EXISTING_API} != 1 ]] && tcp_port_in_use "${API_PORT}"; then
		echo -e "${RED}TCP API port ${API_PORT} is already assigned or listening.${NC}" >&2
		return 1
	fi
	if ipv4_tunnel_in_use "${SERVER_AWG_IPV4}"; then
		echo -e "${RED}IPv4 tunnel network for ${SERVER_AWG_IPV4}/16 overlaps an existing AmneziaWG config.${NC}" >&2
		return 1
	fi
	if ipv6_tunnel_in_use "${SERVER_AWG_IPV6}"; then
		echo -e "${RED}IPv6 tunnel network for ${SERVER_AWG_IPV6}/64 overlaps an existing AmneziaWG config.${NC}" >&2
		return 1
	fi
	if [[ -e ${SERVER_PARAMS_FILE} ]]; then
		echo -e "${RED}Params file already exists: ${SERVER_PARAMS_FILE}${NC}" >&2
		return 1
	fi
	if [[ ${REUSE_EXISTING_API} != 1 && -e /etc/systemd/system/${API_SERVICE_NAME} ]]; then
		echo -e "${RED}API service already exists: ${API_SERVICE_NAME}${NC}" >&2
		return 1
	fi
	if [[ ${REUSE_EXISTING_API} == 1 && ! -f ${API_CONFIG_DIR}/.env ]]; then
		echo -e "${RED}Existing API environment was not found at ${API_CONFIG_DIR}/.env; refusing to replace the API service blindly.${NC}" >&2
		return 1
	fi
	if [[ ${REUSE_EXISTING_API} == 1 ]]; then
		local existing_api_token
		existing_api_token=$(awk -F= '/^API_TOKEN=/ {print substr($0, index($0, "=") + 1); exit}' "${API_CONFIG_DIR}/.env")
		if [[ -z ${existing_api_token} || ${existing_api_token} == replace-this-with-your-secure-random-token ]]; then
			echo -e "${RED}The existing API token is missing or a placeholder; refusing to rotate it during coexistence setup.${NC}" >&2
			return 1
		fi
		if [[ ! -f ${LEGACY_WG_CONFIG_FILE} || ! -f ${LEGACY_WG_PARAMS_FILE} ]]; then
			echo -e "${RED}Legacy API context files are incomplete: ${LEGACY_WG_CONFIG_FILE}, ${LEGACY_WG_PARAMS_FILE}.${NC}" >&2
			return 1
		fi
	fi
	return 0
}

function installQuestions() {
	echo "AmneziaWG server installer (https://github.com/varckin/amneziawg-install)"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""
	print_existing_awg_summary
	if ((${#EXISTING_AWG_SUMMARIES[@]} > 0)); then
		echo "AWG2 will be installed alongside the detected legacy service."
		echo "A different interface, tunnel network, and UDP listener are required."
		echo "The existing management API will remain on its current TCP port and will be upgraded to generate AWG2 configs."
		echo "Changing only the port does not make a legacy profile compatible with AWG2."
		echo ""
	fi

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	DEFAULT_AWG_NIC=$(suggest_awg_interface)
	until [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_AWG_NIC} -lt 16 ]] && ! interface_in_use "${SERVER_AWG_NIC}"; do
		read -rp "New AWG2 interface name: " -e -i "${DEFAULT_AWG_NIC}" SERVER_AWG_NIC
		if interface_in_use "${SERVER_AWG_NIC}"; then
			echo "Interface ${SERVER_AWG_NIC} is already configured; choose another interface."
		fi
	done
	configure_installation_layout

	until [[ ${SERVER_AWG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "New AWG2 tunnel IPv4: " -e -i "${DEFAULT_AWG_IPV4}" SERVER_AWG_IPV4
		if ipv4_tunnel_in_use "${SERVER_AWG_IPV4}"; then
			echo "That /16 tunnel network overlaps an existing AmneziaWG config."
			SERVER_AWG_IPV4=""
		fi
	done

	until [[ ${SERVER_AWG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "New AWG2 tunnel IPv6: " -e -i "${DEFAULT_AWG_IPV6}" SERVER_AWG_IPV6
		if ipv6_tunnel_in_use "${SERVER_AWG_IPV6}"; then
			echo "That /64 tunnel network overlaps an existing AmneziaWG config."
			SERVER_AWG_IPV6=""
		fi
	done

	# Amnezia's deployment guidance recommends ports up to 9999 because some
	# networks block higher UDP ports. Keep that as the installer default.
	RANDOM_PORT=$(suggest_udp_port)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 9999 ] && ! udp_port_in_use "${SERVER_PORT}"; do
		read -rp "New AWG2 UDP port [1-9999]: " -e -i "${RANDOM_PORT}" SERVER_PORT
		if [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && udp_port_in_use "${SERVER_PORT}"; then
			echo "UDP port ${SERVER_PORT} is used by an existing interface or process. It cannot be reused."
		fi
	done

	if [[ ${REUSE_EXISTING_API} == 1 ]]; then
		echo "Reusing the existing node management API on TCP ${API_PORT}."
	else
		DEFAULT_API_PORT=$(suggest_api_port)
		until [[ ${API_PORT} =~ ^[0-9]+$ ]] && (( API_PORT >= 1 && API_PORT <= 65535 )) && ! tcp_port_in_use "${API_PORT}"; do
			read -rp "AWG2 node API TCP port [1-65535]: " -e -i "${DEFAULT_API_PORT}" API_PORT
			if [[ ${API_PORT} =~ ^[0-9]+$ ]] && tcp_port_in_use "${API_PORT}"; then
				echo "TCP port ${API_PORT} is already assigned or listening. Choose another API port."
			fi
		done
	fi

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nAmneziaWG uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	# Jc
	RANDOM_AWG_JC=$(shuf -i3-10 -n1)
	until [[ ${SERVER_AWG_JC} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JC} >= 1 )) && (( ${SERVER_AWG_JC} <= 128 )); do
		read -rp "Server AmneziaWG Jc [1-128]: " -e -i ${RANDOM_AWG_JC} SERVER_AWG_JC
	done

	# Jmin && Jmax
	readJminAndJmax
	until [ "${SERVER_AWG_JMIN}" -le "${SERVER_AWG_JMAX}" ]; do
		echo "AmneziaWG require Jmin < Jmax"
		readJminAndJmax
	done

	# S1 && S2
	generateS1AndS2
	while (( ${RANDOM_AWG_S1} + 56 == ${RANDOM_AWG_S2} )); do
		generateS1AndS2
	done
	readS1AndS2
	while (( ${SERVER_AWG_S1} + 56 == ${SERVER_AWG_S2} )); do
		echo "AmneziaWG require S1 + 56 <> S2"
		readS1AndS2
	done

	# H1 && H2 && H3 && H4
	generateH1AndH2AndH3AndH4
	readH1AndH2AndH3AndH4
	while h_specs_overlap "${SERVER_AWG_H1}" "${SERVER_AWG_H2}" "${SERVER_AWG_H3}" "${SERVER_AWG_H4}"; do
		echo "AmneziaWG requires H1, H2, H3, and H4 ranges not to overlap"
		readH1AndH2AndH3AndH4
	done

	# AWG2-only additions. I1-I5 are optional; S3/S4 are always persisted,
	# including zero, so generated clients receive an unambiguous AWG2 profile.
	readS3AndS4
	readIParams

	echo ""
	echo "AWG2 installation summary:"
	echo "  Existing interfaces: ${EXISTING_AWG_INTERFACES[*]:-none} (unchanged)"
	echo "  New interface: ${SERVER_AWG_NIC}"
	echo "  New VPN listener: UDP ${SERVER_PORT}"
	echo "  New tunnel addresses: ${SERVER_AWG_IPV4}/16, ${SERVER_AWG_IPV6}/64"
	if [[ ${REUSE_EXISTING_API} == 1 ]]; then
		echo "  Management API: upgrade ${API_SERVICE_NAME} on existing TCP ${API_PORT}"
		echo "    Existing API token and backend server record: preserved"
		echo "    New API target: ${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
		echo "    Legacy ${LEGACY_WG_CONFIG_FILE}: remains running during config rotation"
	else
		echo "  New node API: TCP ${API_PORT} via ${API_SERVICE_NAME}"
	fi
	echo "  New params file: ${SERVER_PARAMS_FILE}"
	echo "  New clients directory: ${AWG_CLIENTS_DIR}"
	echo ""
	validate_installation_choices || exit 1
	read -rp "Type INSTALL-AWG2 to confirm these changes: " INSTALL_CONFIRMATION
	if [[ ${INSTALL_CONFIRMATION} != INSTALL-AWG2 ]]; then
		echo "Installation cancelled; no configuration changes were made."
		exit 0
	fi
}

function installAmneziaWG() {
	# Run setup questions first
	installQuestions

	# Install AmneziaWG tools and module
	if [[ ${OS} == 'ubuntu' ]]; then
		if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
			if ! grep -q "deb-src" /etc/apt/sources.list.d/ubuntu.sources; then
				cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/amneziawg.sources
				sed -i 's/deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources
			fi
		else
			if ! grep -q "^deb-src" /etc/apt/sources.list; then
				cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
				sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		fi
		apt install -y software-properties-common
		add-apt-repository -y ppa:amnezia/ppa
		apt update
		# Install DKMS and build tools if not already installed
		apt install -y dkms build-essential "linux-headers-$(uname -r)"
		
		# Check if packages are available for current Ubuntu version
		PACKAGES_AVAILABLE=true
		if ! checkPackageAvailability "amneziawg-tools"; then
			PACKAGES_AVAILABLE=false
			echo -e "${ORANGE}amneziawg-tools not available for current Ubuntu version${NC}"
		fi
		
		# Try to install packages
		if [[ "${PACKAGES_AVAILABLE}" == "true" ]]; then
			# Try to install amneziawg-dkms if available, otherwise fall back to amneziawg
			if checkPackageAvailability "amneziawg-dkms"; then
				if ! apt install -y amneziawg-dkms amneziawg-tools; then
					echo -e "${ORANGE}Failed to install packages. Trying fallback to Ubuntu 24.04...${NC}"
					PACKAGES_AVAILABLE=false
				fi
			else
				if ! apt install -y amneziawg amneziawg-tools; then
					echo -e "${ORANGE}Failed to install packages. Trying fallback to Ubuntu 24.04...${NC}"
					PACKAGES_AVAILABLE=false
				fi
			fi
		fi
		
		# If packages not available or installation failed, try installing from Ubuntu 24.04 (noble)
		if [[ "${PACKAGES_AVAILABLE}" == "false" ]]; then
			if ! installPackagesFromNoble; then
				echo -e "${RED}Failed to install AmneziaWG packages. Installation cannot continue.${NC}"
				exit 1
			fi
		fi
		
		# Verify installation
		if ! command -v awg &>/dev/null; then
			echo -e "${RED}Error: awg command not found after installation. Installation failed.${NC}"
			exit 1
		fi
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
			sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
		echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		apt update
		# Install DKMS and build tools if not already installed
		apt install -y dkms build-essential "linux-headers-$(uname -r)"
		# Try to install amneziawg-dkms if available, otherwise fall back to amneziawg
		if apt-cache show amneziawg-dkms &>/dev/null; then
			apt install -y amneziawg-dkms amneziawg-tools iptables
		else
			apt install -y amneziawg amneziawg-tools iptables
		fi
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools iptables
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools iptables
	fi

	# Create AmneziaWG directory if it doesn't exist
	mkdir -p "${AMNEZIAWG_DIR}"
	chmod 700 "${AMNEZIAWG_DIR}"

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	SERVER_PRIV_KEY=$(awg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_AWG_NIC=${SERVER_AWG_NIC}
SERVER_AWG_IPV4=${SERVER_AWG_IPV4}
SERVER_AWG_IPV6=${SERVER_AWG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
SERVER_AWG_JC=${SERVER_AWG_JC}
SERVER_AWG_JMIN=${SERVER_AWG_JMIN}
SERVER_AWG_JMAX=${SERVER_AWG_JMAX}
SERVER_AWG_S1=${SERVER_AWG_S1}
SERVER_AWG_S2=${SERVER_AWG_S2}
SERVER_AWG_S3=${SERVER_AWG_S3}
SERVER_AWG_S4=${SERVER_AWG_S4}
SERVER_AWG_H1=${SERVER_AWG_H1}
SERVER_AWG_H2=${SERVER_AWG_H2}
SERVER_AWG_H3=${SERVER_AWG_H3}
SERVER_AWG_H4=${SERVER_AWG_H4}
AWG_PROFILE=awg2" >"${SERVER_PARAMS_FILE}"
	chmod 600 "${SERVER_PARAMS_FILE}"
	printf "SERVER_AWG_I1='%s'\n" "${SERVER_AWG_I1}" >>"${SERVER_PARAMS_FILE}"
	printf "SERVER_AWG_I2='%s'\n" "${SERVER_AWG_I2}" >>"${SERVER_PARAMS_FILE}"
	printf "SERVER_AWG_I3='%s'\n" "${SERVER_AWG_I3}" >>"${SERVER_PARAMS_FILE}"
	printf "SERVER_AWG_I4='%s'\n" "${SERVER_AWG_I4}" >>"${SERVER_PARAMS_FILE}"
	printf "SERVER_AWG_I5='%s'\n" "${SERVER_AWG_I5}" >>"${SERVER_PARAMS_FILE}"

	# Add server interface
	echo "[Interface]
Address = ${SERVER_AWG_IPV4}/16,${SERVER_AWG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
# CHOP-AWG-PROFILE: awg2
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >"${SERVER_AWG_CONF}"

[[ -n ${SERVER_AWG_I1} ]] && echo "I1 = ${SERVER_AWG_I1}" >>"${SERVER_AWG_CONF}"
[[ -n ${SERVER_AWG_I2} ]] && echo "I2 = ${SERVER_AWG_I2}" >>"${SERVER_AWG_CONF}"
[[ -n ${SERVER_AWG_I3} ]] && echo "I3 = ${SERVER_AWG_I3}" >>"${SERVER_AWG_CONF}"
[[ -n ${SERVER_AWG_I4} ]] && echo "I4 = ${SERVER_AWG_I4}" >>"${SERVER_AWG_CONF}"
[[ -n ${SERVER_AWG_I5} ]] && echo "I5 = ${SERVER_AWG_I5}" >>"${SERVER_AWG_CONF}"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-2)".0.0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_AWG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/16 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/16 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"${SERVER_AWG_CONF}"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"${SERVER_AWG_CONF}"
	fi

	# Validate the generated AWG2 directives before touching the live service.
	# This catches an outdated userspace tool early instead of leaving a broken
	# interface behind after installation.
	if ! command -v awg-quick >/dev/null 2>&1; then
		echo -e "${RED}AmneziaWG awg-quick was not installed; cannot validate AWG2 config.${NC}"
		exit 1
	fi
	if ! awg-quick strip "${SERVER_AWG_NIC}" >/dev/null; then
		echo -e "${RED}Installed AmneziaWG tools rejected the AWG2 config.${NC}"
		echo -e "${ORANGE}Upgrade the AmneziaWG userspace tools/kernel package and rerun on a clean VPS.${NC}"
		exit 1
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf

	sysctl --system

	# Try to build and load the AmneziaWG kernel module
	echo -e "${YELLOW}Building and loading AmneziaWG kernel module...${NC}"
	
	# Check if DKMS module exists and build it if needed
	if command -v dkms &>/dev/null; then
		# Check if amneziawg module is registered in DKMS
		if dkms status 2>/dev/null | grep -q amneziawg; then
			echo -e "${YELLOW}Found AmneziaWG DKMS module, building for current kernel...${NC}"
			# Get the module name and version from dkms status
			DKMS_MODULE=$(dkms status 2>/dev/null | grep amneziawg | head -1 | awk '{print $1}' | tr -d ',')
			if [[ -n "$DKMS_MODULE" ]]; then
				# Build and install the module for current kernel
				dkms install "$DKMS_MODULE" --force 2>&1 | grep -v "^$" || true
			fi
		fi
	fi
	
	# Try to load the module
	if modprobe amneziawg 2>/dev/null; then
		echo -e "${GREEN}AmneziaWG kernel module loaded successfully${NC}"
	else
		echo -e "${ORANGE}Warning: Could not load AmneziaWG kernel module.${NC}"
		echo -e "${ORANGE}Attempting to build module manually...${NC}"
		
		# Try to find and build the module source
		MODULE_DIR=$(find /usr/src -maxdepth 1 -type d -name 'amneziawg-*' -print -quit 2>/dev/null)
		if [[ -n "$MODULE_DIR" ]]; then
			if [[ -f "$MODULE_DIR/dkms.conf" ]]; then
				echo -e "${YELLOW}Found module source at $MODULE_DIR${NC}"
				MODULE_NAME=$(grep "^PACKAGE_NAME=" "$MODULE_DIR/dkms.conf" | cut -d'=' -f2)
				MODULE_VERSION=$(grep "^PACKAGE_VERSION=" "$MODULE_DIR/dkms.conf" | cut -d'=' -f2)
				if [[ -n "$MODULE_NAME" ]] && [[ -n "$MODULE_VERSION" ]]; then
					dkms add "$MODULE_NAME/$MODULE_VERSION" 2>&1 | grep -v "^$" || true
					dkms build "$MODULE_NAME/$MODULE_VERSION" 2>&1 | grep -v "^$" || true
					dkms install "$MODULE_NAME/$MODULE_VERSION" --force 2>&1 | grep -v "^$" || true
					modprobe amneziawg 2>/dev/null && echo -e "${GREEN}Module built and loaded successfully${NC}" || true
				fi
			fi
		fi
		
		if ! lsmod | grep -q amneziawg; then
			echo -e "${RED}Failed to load kernel module. You may need to reboot the server.${NC}"
			echo -e "${ORANGE}After reboot, run: sudo modprobe amneziawg${NC}"
		fi
	fi

	systemctl start "awg-quick@${SERVER_AWG_NIC}"
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	echo -e "${GREEN}AmneziaWG is installed. Client configurations will be created by the WireGuard API.${NC}"

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
	AWG_RUNNING=$?

	# AmneziaWG might not work if we updated the kernel. Tell the user to reboot
	if [[ ${AWG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
		
		# Check if kernel module is loaded
		if lsmod | grep -q amneziawg; then
			echo -e "${ORANGE}AmneziaWG kernel module is loaded, but service failed to start.${NC}"
			echo -e "${ORANGE}Check the service logs: journalctl -u awg-quick@${SERVER_AWG_NIC} -n 50${NC}"
		else
			echo -e "${RED}AmneziaWG kernel module is NOT loaded!${NC}"
			echo -e "${YELLOW}Attempting to build and load kernel module...${NC}"
			
			# Try to build DKMS module if available
			if command -v dkms &>/dev/null; then
				if dkms status 2>/dev/null | grep -q amneziawg; then
					DKMS_MODULE=$(dkms status 2>/dev/null | grep amneziawg | head -1 | awk '{print $1}' | tr -d ',')
					if [[ -n "$DKMS_MODULE" ]]; then
						echo -e "${YELLOW}Building DKMS module: $DKMS_MODULE${NC}"
						dkms install "$DKMS_MODULE" --force 2>&1 | grep -v "^$" || true
					fi
				fi
			fi
			
			# Try to load the module
			if modprobe amneziawg 2>/dev/null; then
				echo -e "${GREEN}Kernel module loaded. Retrying service start...${NC}"
				systemctl start "awg-quick@${SERVER_AWG_NIC}"
				sleep 2
				if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
					echo -e "${GREEN}AmneziaWG started successfully after loading kernel module!${NC}"
				else
					echo -e "${RED}Service still failed. Check logs: journalctl -u awg-quick@${SERVER_AWG_NIC} -n 50${NC}"
					echo -e "${ORANGE}You may need to reboot the server.${NC}"
				fi
			else
				echo -e "${RED}Failed to load kernel module.${NC}"
				echo -e "${YELLOW}Troubleshooting steps:${NC}"
				echo -e "  1. Check DKMS status: dkms status | grep amneziawg"
				echo -e "  2. Check if module source exists: ls -la /usr/src/ | grep amneziawg"
				echo -e "  3. Install build tools: sudo apt install -y dkms build-essential linux-headers-$(uname -r)"
				echo -e "  4. Try manual build: sudo dkms install amneziawg/<version> --force"
				echo -e "  5. Reboot the server (DKMS modules often require a reboot)"
			fi
		fi
	else # AmneziaWG is running
		echo -e "\n${GREEN}AmneziaWG is running.${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
	
	# Install the WireGuard API. On a co-located node, upgrade the existing TCP
	# service in place and point it at the new AWG2 interface while preserving
	# the existing API token and backend endpoint.
	echo -e "\n${GREEN}Installing WireGuard API...${NC}"
	if [[ ${REUSE_EXISTING_API} == 1 ]]; then
		if ! AWG_INTERFACE="${SERVER_AWG_NIC}" \
		INSTALL_BINARY="${API_BINARY_PATH}" \
		CONFIG_DIR="${API_CONFIG_DIR}" \
		SERVICE_NAME="${API_SERVICE_NAME}" \
		API_PORT="${API_PORT}" \
		UPGRADE_EXISTING_SERVICE=true \
		WG_CONFIG_FILE="${SERVER_AWG_CONF}" \
		WG_PARAMS_FILE="${SERVER_PARAMS_FILE}" \
		WIREGUARD_CLIENTS="${AWG_CLIENTS_DIR}" \
		bash ./service.sh; then
			echo -e "${RED}WireGuard API installation failed; the AWG2 migration is incomplete.${NC}" >&2
			return 1
		fi
	else
		if ! AWG_INTERFACE="${SERVER_AWG_NIC}" \
		INSTALL_BINARY="${API_BINARY_PATH}" \
		CONFIG_DIR="${API_CONFIG_DIR}" \
		SERVICE_NAME="${API_SERVICE_NAME}" \
		API_PORT="${API_PORT}" \
		WG_CONFIG_FILE="${SERVER_AWG_CONF}" \
		WG_PARAMS_FILE="${SERVER_PARAMS_FILE}" \
		WIREGUARD_CLIENTS="${AWG_CLIENTS_DIR}" \
		bash ./service.sh; then
			echo -e "${RED}WireGuard API installation failed; the AWG2 installation is incomplete.${NC}" >&2
			return 1
		fi
	fi
	
	# Write AmneziaWG port to .env file
	CONFIG_DIR="${API_CONFIG_DIR}"
	if [ -f "$CONFIG_DIR/.env" ]; then
		PORT_ENV_KEY=AWG_PORT
		if [[ ${REUSE_EXISTING_API} == 1 && ${LEGACY_SERVER_PORT:-unknown} =~ ^[0-9]+$ ]]; then
			if grep -q '^LEGACY_AWG_PORT=' "$CONFIG_DIR/.env"; then
				sed -i "s/^LEGACY_AWG_PORT=.*$/LEGACY_AWG_PORT=${LEGACY_SERVER_PORT}/" "$CONFIG_DIR/.env"
			else
				echo "LEGACY_AWG_PORT=${LEGACY_SERVER_PORT}" >>"$CONFIG_DIR/.env"
			fi
		fi
		if grep -q "^${PORT_ENV_KEY}=" "$CONFIG_DIR/.env"; then
			sed -i "s/^${PORT_ENV_KEY}=.*$/${PORT_ENV_KEY}=${SERVER_PORT}/" "$CONFIG_DIR/.env"
		else
			echo "${PORT_ENV_KEY}=${SERVER_PORT}" >> "$CONFIG_DIR/.env"
		fi
		echo -e "${GREEN}${PORT_ENV_KEY} (${SERVER_PORT}) written to $CONFIG_DIR/.env${NC}"
	else
		echo -e "${ORANGE}Warning: .env file not found at $CONFIG_DIR/.env. Cannot write AmneziaWG port.${NC}"
	fi
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"

		# Disable routing
		rm -f /etc/sysctl.d/awg.conf
		sysctl --system

		# Remove config files
		rm -rf "${AMNEZIAWG_DIR:?}"/*

		if [[ ${OS} == 'ubuntu' ]]; then
			apt remove -y amneziawg amneziawg-tools
			add-apt-repository -ry ppa:amnezia/ppa
			if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
				rm -f /etc/apt/sources.list.d/amneziawg.sources
			else
				rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y amneziawg amneziawg-tools
			rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			apt-key del 57290828
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		# Check if AmneziaWG is running
		systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
		AWG_RUNNING=$?

		if [[ ${AWG_RUNNING} -eq 0 ]]; then
			echo "AmneziaWG failed to uninstall properly."
			exit 1
		else
			echo "AmneziaWG uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function loadParams() {
	source "${AMNEZIAWG_DIR}/params"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
}

function manageMenu() {
	echo "AmneziaWG server installer (https://github.com/varckin/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) List all users"
	echo "   2) Revoke existing user"
	echo "   3) Uninstall AmneziaWG"
	echo "   4) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		listClients
		;;
	2)
		revokeClient
		;;
	3)
		uninstallAmneziaWG
		;;
	4)
		exit 0
		;;
	esac
}

# Allow the validation suite to source the pure parameter helpers without
# running package installation or changing the host.
if [[ ${AMNEZIAWG_INSTALLER_LIB_ONLY:-0} == "1" ]]; then
	return 0 2>/dev/null || exit 0
fi

# Check for root, virt, OS...
initialCheck

# Inventory the host before any package or configuration mutation. A legacy
# installation can coexist with AWG2, but an existing AWG2 installation should
# be managed rather than duplicated by rerunning this entry point.
detect_existing_awg_installations
if ((AWG2_DETECTED == 1)); then
	print_existing_awg_summary
	echo "An AWG2 interface is already configured on this host. No changes were made."
	exit 0
fi

if ((LEGACY_AWG_DETECTED == 1)); then
	print_existing_awg_summary
	echo "This installer can add AWG2 alongside the legacy installation using isolated resources."
	read -rp "Continue with a side-by-side AWG2 installation? [y/N]: " INSTALL_ALONGSIDE
	INSTALL_ALONGSIDE=${INSTALL_ALONGSIDE:-N}
	if [[ ! ${INSTALL_ALONGSIDE} =~ ^[Yy]$ ]]; then
		if [[ -e ${AMNEZIAWG_DIR}/params ]]; then
			loadParams
			manageMenu
		fi
		echo "Installation cancelled; no changes were made."
		exit 0
	fi
fi

installAmneziaWG
