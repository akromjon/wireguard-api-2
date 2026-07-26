#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
AMNEZIAWG_INSTALLER_LIB_ONLY=1 source "${SCRIPT_DIR}/amneziawg-install.sh"

fail() {
	echo "installer test failed: $*" >&2
	exit 1
}

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

echo "installer parameter tests passed"
