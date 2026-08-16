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

# The AWG_PROFILE -> switch mapping (AWG3, AWG_S_PADDING_MIN, INSTALL_TOKEN)
# must be exercised by sourcing with AWG_PROFILE actually exported, not by
# hand-setting the derived variables in a subshell. A regression that leaves
# AWG_S_PADDING_MIN=0 under awg3 would produce S3/S4 below the nonce floor —
# a node nobody can connect to, silently — and a test that hand-sets
# AWG_S_PADDING_MIN=12 instead of deriving it would stay green through that
# regression.
(
	AWG_PROFILE=awg3
	AMNEZIAWG_INSTALLER_LIB_ONLY=1 source "${SCRIPT_DIR}/amneziawg-install.sh"
	[[ ${AWG3} == 1 ]] || fail "AWG_PROFILE=awg3 must derive AWG3=1"
	[[ ${AWG_S_PADDING_MIN} == 12 ]] || fail "AWG_PROFILE=awg3 must derive AWG_S_PADDING_MIN=12"
	[[ ${INSTALL_TOKEN} == INSTALL-AWG3 ]] || fail "AWG_PROFILE=awg3 must derive INSTALL_TOKEN=INSTALL-AWG3"
) || exit 1

(
	AWG_PROFILE=awg2
	AMNEZIAWG_INSTALLER_LIB_ONLY=1 source "${SCRIPT_DIR}/amneziawg-install.sh"
	[[ ${AWG3} == 0 ]] || fail "AWG_PROFILE=awg2 must derive AWG3=0"
	[[ ${AWG_S_PADDING_MIN} == 0 ]] || fail "AWG_PROFILE=awg2 must derive AWG_S_PADDING_MIN=0"
	[[ ${INSTALL_TOKEN} == INSTALL-AWG2 ]] || fail "AWG_PROFILE=awg2 must derive INSTALL_TOKEN=INSTALL-AWG2"
) || exit 1

# Written as an if, not `( ... ) && fail` — same style note as above.
if (
	AWG_PROFILE=awg9
	AMNEZIAWG_INSTALLER_LIB_ONLY=1 source "${SCRIPT_DIR}/amneziawg-install.sh" 2>/dev/null
); then
	fail "an unsupported AWG_PROFILE must exit non-zero"
fi

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

(
	AWG3=1
	unset SERVER_AWG_HEADER_PROTECTION_KEY SERVER_AWG_CONTENT_PADDING_ADDITION
	generateHeaderProtectionKey
	# 32 raw bytes base64-encoded is always 44 characters ending in '='.
	[[ ${#SERVER_AWG_HEADER_PROTECTION_KEY} == 44 ]] ||
		fail "header protection key must be 32 bytes of base64, got '${SERVER_AWG_HEADER_PROTECTION_KEY}'"
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
		fail "header protection key is not valid base64: ${SERVER_AWG_HEADER_PROTECTION_KEY}"
	# Arithmetic comparison, not [[ == ]]: BSD wc -c (macOS) right-pads its
	# count with leading spaces, unlike GNU wc, and would fail a string match.
	(($(printf '%s' "${SERVER_AWG_HEADER_PROTECTION_KEY}" | base64 -d | wc -c) == 32)) ||
		fail "header protection key must decode to 32 bytes"

	first=${SERVER_AWG_HEADER_PROTECTION_KEY}
	unset SERVER_AWG_HEADER_PROTECTION_KEY
	generateHeaderProtectionKey
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} != "${first}" ]] ||
		fail "header protection key must be random per node"

	SERVER_AWG_HEADER_PROTECTION_KEY="cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc="
	generateHeaderProtectionKey
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} == "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=" ]] ||
		fail "a well-formed exported header protection key must be honoured"

	# main.go also rejects a malformed key, but only at API startup — after
	# the conf is written and the interface is up. This must fail here,
	# before any disk write.
	if (
		SERVER_AWG_HEADER_PROTECTION_KEY=operator-supplied-key
		generateHeaderProtectionKey
	); then
		fail "a malformed exported header protection key must be rejected before any disk write"
	fi
) || exit 1

(
	AWG3=1
	unset SERVER_AWG_CONTENT_PADDING_ADDITION
	generateContentPaddingAddition
	[[ ${SERVER_AWG_CONTENT_PADDING_ADDITION} =~ ^([0-9]+)-([0-9]+)$ ]] ||
		fail "content padding addition must be a min-max range, got '${SERVER_AWG_CONTENT_PADDING_ADDITION}'"
	low=${BASH_REMATCH[1]}
	high=${BASH_REMATCH[2]}
	((low >= 1)) || fail "content padding minimum must be at least 1"
	((high > low)) || fail "content padding range must be ordered"
	# S4 already pads every transport packet; a large content padding addition
	# on top of it compounds the open MTU question.
	((high <= 64)) || fail "content padding maximum ${high} is too large"
) || exit 1

awg3_module_version_ok "3.0.20260805" || fail "module 3.0 must satisfy the awg3 preflight"
awg3_module_version_ok "4.1.0" || fail "a future major version must satisfy the awg3 preflight"
if awg3_module_version_ok "2.0.20250101"; then
	fail "module 2.0 must fail the awg3 preflight"
fi
if awg3_module_version_ok ""; then
	fail "an unreadable module version must fail the awg3 preflight"
fi

(
	SERVER_AWG_REKEY_AFTER_TIME=100-140
	SERVER_AWG_MAX_HANDSHAKE_ATTEMPTS=18
	unset SERVER_AWG_REKEY_TIMEOUT SERVER_AWG_REJECT_AFTER_TIME SERVER_AWG_KEEPALIVE_TIMEOUT
	directives=$(awg3_timing_directives)
	[[ ${directives} == *"RekeyAfterTime = 100-140"* ]] || fail "exported timing ranges must be emitted"
	[[ ${directives} == *"MaxHandshakeAttempts = 18"* ]] || fail "exported handshake attempts must be emitted"
	[[ ${directives} != *"RekeyTimeout"* ]] || fail "unset timing ranges must be omitted"
	[[ ${directives} != *"KeepaliveTimeout"* ]] || fail "unset timing ranges must be omitted"
) || exit 1

# A stale bash on the node must not turn the preflight into a no-op: the gate
# has to be reachable as a function, not only inline in installAmneziaWG.
declare -F assert_awg3_supported >/dev/null || fail "assert_awg3_supported must be a function"

# The awg2 S3/S4 prompt must keep telling the operator that 0 disables the
# padding; awg3 must not, because 0 is not a valid answer there (S3/S4 must
# reach the nonce floor of 12).
(
	AWG_S_PADDING_MIN=0
	[[ $(s_padding_hint) == ", 0 disables" ]] || fail "awg2 S3/S4 prompt must offer the 0-disables hint"
) || exit 1
(
	AWG_S_PADDING_MIN=12
	[[ -z $(s_padding_hint) ]] || fail "awg3 S3/S4 prompt must not offer the 0-disables hint"
) || exit 1

# A co-located AWG3 install (adding awg3 beside an already-registered API)
# must refuse to proceed without an explicit acknowledgement that the backend
# server record already has is_support_awg_third set — otherwise the
# rewritten .env silently hands unusable configs to pre-12.3.0 clients on the
# same token and port.
awg3_colocated_reuse_acknowledged "1" ||
	fail "AWG3_COLOCATED_ACK=1 must acknowledge the co-located warning"
awg3_colocated_reuse_acknowledged "AWG3-COLOCATED-ACK" ||
	fail "the typed confirmation token must acknowledge the co-located warning"
if awg3_colocated_reuse_acknowledged ""; then
	fail "an empty acknowledgement must not satisfy the co-located gate"
fi
if awg3_colocated_reuse_acknowledged "y"; then
	fail "an unrelated answer must not satisfy the co-located gate"
fi

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

# Written as an if, not `( ... ) && fail`, matching the negative-assertion
# style used elsewhere in this file. (A non-final command in an && list is
# exempt from errexit, so `( ... ) && fail` would not abort the run either —
# this is a style choice, not a safety requirement. See the note near the end
# of this file for the full explanation.)
if (
	AWG_PROFILE=awg9
	CONFIG_DIR="${TEST_AWG_DIR}/wireguard-api-bad"
	mkdir -p "${CONFIG_DIR}"
	source "${SCRIPT_DIR}/service.sh" 2>/dev/null
); then
	fail "service.sh must reject an unknown AWG_PROFILE"
fi

[[ -x ${SCRIPT_DIR}/install3.sh ]] || fail "install3.sh must exist and be executable"
grep -qx 'export AWG_PROFILE=awg3' "${SCRIPT_DIR}/install3.sh" || fail "install3.sh must export the awg3 profile"
grep -qx 'export AWG_PROFILE=awg2' "${SCRIPT_DIR}/install2.sh" || fail "install2.sh must keep exporting awg2"

# The two entry points must stay byte-identical outside four permitted
# regions: the opening banner, the profile comment block, the
# `export AWG_PROFILE=` line, and the closing banner. A regex allowlist of
# "known machinery lines" was tried first (mktemp, git clone, chmod +x, ...)
# and missed real drift: it only asserts that install3.sh contains whatever
# matches the allowlist in install2.sh, so a line absent from the allowlist
# — `set -Eeuo pipefail`, the `cd "${TEMP_DIR}/source"` target, the
# `command -v git` fallback block, the root-check error text — could be
# deleted or edited in install3.sh and the check would still pass. Strip only
# the permitted-different regions from both files and diff what remains:
# anything left over must match exactly, including whitespace.
strip_install_entrypoint_variants() {
	awk 'NR == 1 || $0 !~ /^#/' "$1" |
		grep -Ev 'AmneziaWG [0-9]+\.[0-9]+' |
		grep -v '^export AWG_PROFILE=awg'
}
diff <(strip_install_entrypoint_variants "${SCRIPT_DIR}/install2.sh") \
	<(strip_install_entrypoint_variants "${SCRIPT_DIR}/install3.sh") >/dev/null ||
	fail "install3.sh diverges from install2.sh outside the banner/profile lines"

grep -q 'AmneziaWG 3.0' "${SCRIPT_DIR}/install3.sh" || fail "install3.sh must name the profile it installs"
# Written as an if, not `grep && fail`, matching the negative-assertion style
# used elsewhere in this file. (A non-final command in an `&&` list is
# actually exempt from errexit, so `grep ... && fail ...` would not abort the
# run either — this is a style choice, not a safety requirement.)
if grep -q 'AWG_PROFILE=awg3' "${SCRIPT_DIR}/install2.sh"; then
	fail "install2.sh must not reference awg3"
fi

echo "installer parameter and coexistence tests passed"
