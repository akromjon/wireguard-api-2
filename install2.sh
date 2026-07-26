#!/bin/bash

set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

if [[ ${EUID} -ne 0 ]]; then
	printf '%b\n' "${RED}Please run as root${NC}" >&2
	exit 1
fi

REPOSITORY=${WIREGUARD_API_REPOSITORY:-https://github.com/akromjon/wireguard-api-2.git}
REF=${WIREGUARD_API_REF:-main}
TEMP_DIR=$(mktemp -d -t wireguard-api-2.XXXXXX)

cleanup() {
	rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

if ! command -v git >/dev/null 2>&1; then
	printf '%b\n' "${YELLOW}Git is required and was not found.${NC}"
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update
		apt-get install -y git
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y git
	elif command -v yum >/dev/null 2>&1; then
		yum install -y git
	else
		printf '%b\n' "${RED}Install git manually and run this script again.${NC}" >&2
		exit 1
	fi
fi

printf '%b\n' "${GREEN}Installing WireGuard API V2 with AmneziaWG 2.0 on a clean VPS.${NC}"
printf '%b\n' "${YELLOW}Repository: ${REPOSITORY}; ref: ${REF}${NC}"

git clone --depth 1 --branch "${REF}" "${REPOSITORY}" "${TEMP_DIR}/source"
cd "${TEMP_DIR}/source"
chmod +x amneziawg-install.sh service.sh

# This entry point is deliberately AWG2-only. It does not discover or alter
# existing AWG1 interfaces; deploy this repository on a separate VPS/pool.
export AWG_PROFILE=awg2
./amneziawg-install.sh

printf '%b\n' "${GREEN}WireGuard API V2 / AmneziaWG 2.0 installation completed.${NC}"
