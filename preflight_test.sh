#!/bin/bash
# Pure-function tests for awg2-preflight.sh. Runs nothing that touches the host.

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
AWG_PREFLIGHT_LIB_ONLY=1 source "${SCRIPT_DIR}/awg2-preflight.sh"

fail() {
	echo "preflight test failed: $*" >&2
	exit 1
}

# The whole point of the AWG3 gate: a readable module below 3 is a hard stop,
# because the installer will refuse and the node needs a reboot first.
awg_preflight_module_is_awg3 "3.0.20260805" || fail "3.0.20260805 must satisfy AWG3"
awg_preflight_module_is_awg3 "3.0.20260731-04" || fail "3.0.20260731-04 must satisfy AWG3"
awg_preflight_module_is_awg3 "4.1.0" || fail "a future major must satisfy AWG3"

if awg_preflight_module_is_awg3 "1.0.20260611"; then
	fail "1.0.20260611 is the stale-module case and must NOT satisfy AWG3"
fi
if awg_preflight_module_is_awg3 "2.9.9"; then
	fail "2.x must NOT satisfy AWG3"
fi
if awg_preflight_module_is_awg3 "none"; then
	fail "an unreadable module must NOT be reported as satisfying AWG3"
fi
if awg_preflight_module_is_awg3 ""; then
	fail "an empty version must NOT satisfy AWG3"
fi

# The AWG3 gate must be opt-in: a bare AWG2 preflight run must not start
# failing nodes whose loaded module is legitimately old.
grep -q -- '--awg3' "${SCRIPT_DIR}/awg2-preflight.sh" ||
	fail "awg2-preflight.sh must accept --awg3"

echo "preflight tests passed"
