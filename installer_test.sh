#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
AMNEZIAWG_INSTALLER_LIB_ONLY=1 source "${SCRIPT_DIR}/amneziawg-install.sh"

fail() {
	echo "installer test failed: $*" >&2
	exit 1
}

if grep -q 'while (( ${RANDOM_AWG_H1}' "${SCRIPT_DIR}/amneziawg-install.sh"; then
	fail "legacy arithmetic comparison must not process H ranges"
fi

# S3/S4 regression guard. 0 is a VALID answer (it disables the padding), so
# seeding the variable with 0 satisfies the until-guard immediately and the
# operator is never prompted — S3/S4 silently forced to 0 with no way to set
# them. Seeding must stay non-numeric.
if grep -qE '^\tSERVER_AWG_S(3|4)=0$' "${SCRIPT_DIR}/amneziawg-install.sh"; then
	fail "readS3AndS4 must not seed S3/S4 with 0 — the prompt would be skipped"
fi

s_padding_in_range "0" 64 || fail "S3=0 must be accepted (disables padding)"
s_padding_in_range "16" 64 || fail "S3=16 must be accepted"
s_padding_in_range "64" 64 || fail "S3 upper bound must be accepted"
s_padding_in_range "8" 32 || fail "S4=8 must be accepted"
s_padding_in_range "32" 32 || fail "S4 upper bound must be accepted"
if s_padding_in_range "65" 64; then
	fail "S3 above 64 must be rejected"
fi
if s_padding_in_range "33" 32; then
	fail "S4 above 32 must be rejected"
fi
if s_padding_in_range "" 64; then
	fail "empty seed must be rejected so the prompt actually runs"
fi
if s_padding_in_range "abc" 64; then
	fail "non-numeric input must be rejected"
fi
if s_padding_in_range "-1" 64; then
	fail "negative padding must be rejected"
fi

# S4 pads every transport packet — it is the data-plane obfuscation AWG2
# exists to provide. Defaulting the prompt to 0 shipped nodes with the feature
# switched off, so the generated defaults must be non-zero and in range.
if grep -qE 'read -rp "Server AmneziaWG S(3|4) padding.*-i 0 ' "${SCRIPT_DIR}/amneziawg-install.sh"; then
	fail "S3/S4 prompts must not default to 0 — padding would ship disabled"
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
	generateS3AndS4
	s_padding_in_range "${RANDOM_AWG_S3}" 64 || fail "generated S3 ${RANDOM_AWG_S3} out of range"
	s_padding_in_range "${RANDOM_AWG_S4}" 32 || fail "generated S4 ${RANDOM_AWG_S4} out of range"
	((RANDOM_AWG_S3 >= 8)) || fail "generated S3 ${RANDOM_AWG_S3} below the useful floor"
	((RANDOM_AWG_S4 >= 4)) || fail "generated S4 ${RANDOM_AWG_S4} below the useful floor"
done

[[ ${AWG3} == 0 ]] || fail "sourcing without AWG_PROFILE must default to awg2"
[[ ${AWG_S_PADDING_MIN} == 0 ]] || fail "awg2 must keep accepting S3=0"
[[ ${INSTALL_TOKEN} == INSTALL-AWG2 ]] || fail "awg2 confirmation token must not change"

# Header protection reads its ChaCha20 nonce out of the first 12 bytes of the
# padding prefix. Below 12 the two sides derive different keystreams and
# nothing connects, with no error anywhere — so the floor is a hard guard.
(
	AWG_S_PADDING_MIN=12
	s_padding_in_range "12" 64 || fail "S3=12 must be accepted under awg3"
	s_padding_in_range "32" 32 || fail "S4=32 must be accepted under awg3"
	if s_padding_in_range "8" 64; then
		fail "S3 below 12 must be rejected under awg3"
	fi
	if s_padding_in_range "0" 32; then
		fail "S4=0 must be rejected under awg3"
	fi
) || exit 1

(
	AWG3=1
	AWG_S_PADDING_MIN=12
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		generateS3AndS4
		((RANDOM_AWG_S3 >= 12)) || fail "awg3 generated S3 ${RANDOM_AWG_S3} below the nonce floor"
		((RANDOM_AWG_S4 >= 12)) || fail "awg3 generated S4 ${RANDOM_AWG_S4} below the nonce floor"
		((RANDOM_AWG_S3 <= 64)) || fail "awg3 generated S3 ${RANDOM_AWG_S3} above the maximum"
		((RANDOM_AWG_S4 <= 32)) || fail "awg3 generated S4 ${RANDOM_AWG_S4} above the maximum"
	done
) || exit 1

h_spec_bounds "5" || fail "single H value should be valid"
h_spec_bounds "5-10" || fail "H range should be valid"
if h_spec_bounds "4"; then
	fail "H values below 5 should be rejected"
fi
if h_spec_bounds "10-5"; then
	fail "reversed H ranges should be rejected"
fi
if h_spec_bounds "5-2147483648"; then
	fail "H values above the documented maximum should be rejected"
fi

if h_specs_overlap "5-10" "11-20"; then
	fail "adjacent H ranges should not overlap"
fi
if ! h_specs_overlap "5-10" "10-20"; then
	fail "shared H boundary should count as overlap"
fi

generateH1AndH2AndH3AndH4
for generated_spec in "${RANDOM_AWG_H1}" "${RANDOM_AWG_H2}" "${RANDOM_AWG_H3}" "${RANDOM_AWG_H4}"; do
	h_spec_bounds "${generated_spec}" || fail "generated H range is invalid: ${generated_spec}"
done
if h_specs_overlap "${RANDOM_AWG_H1}" "${RANDOM_AWG_H2}" "${RANDOM_AWG_H3}" "${RANDOM_AWG_H4}"; then
	fail "generated H ranges overlap"
fi

TEST_AWG_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_AWG_DIR}"' EXIT
AMNEZIAWG_DIR="${TEST_AWG_DIR}"

printf '%s\n' \
	'[Interface]' \
	'Address = 10.66.66.1/16,fd42:42:42::1/64' \
	'ListenPort = 443' \
	'Jc = 5' >"${AMNEZIAWG_DIR}/awg0.conf"

detect_existing_awg_installations
array_contains awg0 "${EXISTING_AWG_INTERFACES[@]}" || fail "existing awg0 interface was not detected"
array_contains 443 "${EXISTING_AWG_PORTS[@]}" || fail "existing AWG UDP port was not detected"
[[ ${LEGACY_AWG_DETECTED} == 1 ]] || fail "config without AWG2 marker should be classified as legacy"
[[ $(suggest_awg_interface) == awg1 ]] || fail "awg1 should be proposed when awg0 exists"
udp_port_in_use 443 || fail "configured legacy UDP port should be reserved"
ipv4_tunnel_in_use 10.66.99.1 || fail "existing IPv4 /16 tunnel should be detected"
ipv6_tunnel_in_use fd42:42:42::99 || fail "existing IPv6 /64 tunnel should be detected"

EXISTING_API_PORTS=(8080)
[[ $(suggest_api_port) == 8081 ]] || fail "next free API port should be proposed"

printf '%s\n' '# CHOP-AWG-PROFILE: awg2' 'S3 = 0' >>"${AMNEZIAWG_DIR}/awg0.conf"
detect_existing_awg_installations
[[ ${AWG2_DETECTED} == 1 ]] || fail "AWG2 marker should be detected"

printf '%s\n' 'HeaderProtectionKey = cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=' >>"${AMNEZIAWG_DIR}/awg0.conf"
detect_existing_awg_installations
[[ ${AWG3_DETECTED} == 1 ]] || fail "an interface with header protection must be detected as awg3"
[[ ${AWG2_DETECTED} == 1 ]] || fail "an awg3 interface must still count as a modern interface"

# Adding a padded AWG2 interface beside an unpadded one: the incumbent is AWG2,
# so nothing matches the legacy profile. It still keeps serving its peers, so
# its real config path and port must be carried into the coexistence context —
# not left empty, and not defaulted to a guessed awg0.conf.
(
	SERVER_AWG_NIC=awg1
	unset LEGACY_WG_CONFIG_FILE LEGACY_SERVER_PORT
	configure_installation_layout
	[[ ${SERVER_PARAMS_FILE} == "${AMNEZIAWG_DIR}/params.awg1" ]] ||
		fail "second AWG2 interface must get its own params file, got ${SERVER_PARAMS_FILE}"
	[[ ${LEGACY_WG_CONFIG_FILE:-} == "${AMNEZIAWG_DIR}/awg0.conf" ]] ||
		fail "incumbent AWG2 config path must be recorded, got ${LEGACY_WG_CONFIG_FILE:-<empty>}"
	[[ ${LEGACY_SERVER_PORT:-} == 443 ]] ||
		fail "incumbent AWG2 port must be recorded, got ${LEGACY_SERVER_PORT:-<empty>}"
	[[ ${REUSE_EXISTING_API} == 1 ]] ||
		fail "coexistence install must reuse the running node API"
) || exit 1

WIREGUARD_API_SERVICE_LIB_ONLY=1
AWG_INTERFACE=awg1
CONFIG_DIR="${TEST_AWG_DIR}/wireguard-api"
API_PORT=8080
UPGRADE_EXISTING_SERVICE=true
WG_CONFIG_FILE="${TEST_AWG_DIR}/awg1.conf"
WG_PARAMS_FILE="${TEST_AWG_DIR}/params.awg1"
WIREGUARD_CLIENTS="${TEST_AWG_DIR}/users-awg1"
mkdir -p "${CONFIG_DIR}"
printf '%s\n' 'API_PORT=8080' 'API_TOKEN=legacy-api-token-1234567890' >"${CONFIG_DIR}/.env"
# shellcheck source=service.sh
source "${SCRIPT_DIR}/service.sh"
[[ ${URL_PREFIX} == "https://github.com/${RELEASE_REPO}/releases/latest/download" ]] || fail "service should download the latest published release by default"
[[ ${RELEASE_LABEL} == "latest published release" ]] || fail "latest release label was not selected"
(
	WIREGUARD_API_RELEASE_TAG=v9.8.7
	resolve_release_source
	[[ ${URL_PREFIX} == "https://github.com/${RELEASE_REPO}/releases/download/v9.8.7" ]]
	[[ ${RELEASE_LABEL} == v9.8.7 ]]
) || fail "explicit release tag override should remain available"
prepare_environment
grep -qx 'API_PORT=8080' "${CONFIG_DIR}/.env" || fail "existing API port should be preserved"
grep -qx 'API_TOKEN=legacy-api-token-1234567890' "${CONFIG_DIR}/.env" || fail "existing API token should be preserved"
grep -qx "WG_CONFIG_FILE=${WG_CONFIG_FILE}" "${CONFIG_DIR}/.env" || fail "API should target the AWG2 config"
grep -qx "WG_PARAMS_FILE=${WG_PARAMS_FILE}" "${CONFIG_DIR}/.env" || fail "API should target the AWG2 params"
grep -qx "WIREGUARD_CLIENTS=${WIREGUARD_CLIENTS}" "${CONFIG_DIR}/.env" || fail "API should target the AWG2 clients directory"

grep -qx 'AWG_PROFILE=awg2' "${CONFIG_DIR}/.env" || fail "service.sh must default the profile to awg2"

# An awg3 install must hand the node API its profile, or the API keeps issuing
# AWG2 configs against a header-protected interface — a node nobody can reach.
(
	AWG_PROFILE=awg3
	CONFIG_DIR="${TEST_AWG_DIR}/wireguard-api-awg3"
	WG_CONFIG_FILE="${TEST_AWG_DIR}/awg1.conf"
	WG_PARAMS_FILE="${TEST_AWG_DIR}/params.awg1"
	WIREGUARD_CLIENTS="${TEST_AWG_DIR}/users-awg1"
	mkdir -p "${CONFIG_DIR}"
	printf '%s\n' 'API_PORT=8080' 'API_TOKEN=legacy-api-token-1234567890' >"${CONFIG_DIR}/.env"
	# shellcheck source=service.sh
	source "${SCRIPT_DIR}/service.sh"
	prepare_environment
	grep -qx 'AWG_PROFILE=awg3' "${CONFIG_DIR}/.env"
) || fail "service.sh must record AWG_PROFILE=awg3 for an awg3 install"

# Written as an if, not `( ... ) && fail`: the subshell is expected to exit
# non-zero, and under `set -e` that would abort the whole test run.
if (
	AWG_PROFILE=awg9
	CONFIG_DIR="${TEST_AWG_DIR}/wireguard-api-bad"
	mkdir -p "${CONFIG_DIR}"
	source "${SCRIPT_DIR}/service.sh" 2>/dev/null
); then
	fail "service.sh must reject an unknown AWG_PROFILE"
fi

echo "installer parameter and coexistence tests passed"
