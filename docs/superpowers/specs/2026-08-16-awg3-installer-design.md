# AWG3 support in the node installer and node API — design

**Date:** 2026-08-16
**Status:** Approved, ready for implementation plan
**Repo touched:** `wireguard-api-2` (`install2.sh`, `amneziawg-install.sh`, `service.sh`, `main.go`, tests)

## Problem

`install2.sh` installs an AmneziaWG 2.0 node: server interface plus the node
HTTP API that issues client configs. App 12.3.0 (iOS) and 2.4.2 (Android) speak
AmneziaWG 3.0, and the two hand-built test nodes (`198.251.65.251`,
`146.71.78.67`) prove the wire format works — but every step there was manual,
including injecting `HeaderProtectionKey` into already-issued config rows.

There is no supported way to install an AWG3 node. This design adds one.

## Goals

- `sudo ./install2.sh` produces a working AWG3 node end to end: AWG3 interface,
  AWG3 params file, node API that issues AWG3 client configs.
- `AWG_PROFILE=awg2 ./install2.sh` reproduces today's behaviour exactly.
- An AWG3 install fails before touching disk if the host's AmneziaWG build
  cannot do header protection.

## Non-goals

- No in-place AWG2 → AWG3 upgrade script. Existing nodes are untouched by this
  work. (`awg2-sidecar.sh` / `awg2-preflight.sh` stay AWG2-only.)
- No backend or app change. Which clients are allowed to see an AWG3 node is
  handled by `is_support_awg_third`, specified in
  `backend/docs/superpowers/specs/2026-08-16-awg3-server-gating-design.md`.
- No change to the client config profile marker. It stays the literal `awg2`.

## Profile selection

`install2.sh` exports the profile and rejects anything else:

```bash
export AWG_PROFILE=${AWG_PROFILE:-awg3}
case ${AWG_PROFILE} in
awg2 | awg3) ;;
*) echo "Unsupported AWG_PROFILE: ${AWG_PROFILE}" >&2; exit 1 ;;
esac
```

The banner names the profile being installed. `amneziawg-install.sh` derives one
switch from it, `AWG3=1` when `AWG_PROFILE=awg3`, and every new behaviour below
is gated on that switch only.

**Confirmation token.** The interactive guard becomes `INSTALL-AWG3` under
`AWG3=1` and stays `INSTALL-AWG2` otherwise, so headless callers that export
`INSTALL_CONFIRMATION=INSTALL-AWG2` (`awg2-sidecar.sh`) keep working unchanged.

## Detection of existing interfaces

`detect_existing_awg_installations` currently classifies a conf as `awg2` when it
matches `^# CHOP-AWG-PROFILE: awg2$` or has an `S3 =` line, else `legacy`.

Changes:

- A conf containing `HeaderProtectionKey =` classifies as `awg3` and sets
  `AWG3_DETECTED=1`.
- The marker regex accepts `awg2` or `awg3`.
- `AWG2_DETECTED` keeps its meaning of "a modern (non-legacy) interface exists",
  so the existing side-by-side confirmation path fires for AWG3 nodes too. The
  prompt text prints the detected profile per interface, which
  `EXISTING_AWG_SUMMARIES` already carries.

## Parameters generated for AWG3

| param | source | notes |
|---|---|---|
| `SERVER_AWG_HEADER_PROTECTION_KEY` | `awg genkey` | 32-byte base64, same shape as `PrivateKey`. Honoured if already exported. |
| `SERVER_AWG_CONTENT_PADDING_ADDITION` | random `min-max` | `min` from `shuf -i1-16`, `max = min + shuf -i8-48`. |
| `SERVER_AWG_REKEY_AFTER_TIME`, `..._REKEY_TIMEOUT`, `..._REJECT_AFTER_TIME`, `..._KEEPALIVE_TIMEOUT`, `..._MAX_HANDSHAKE_ATTEMPTS` | operator env only | Never prompted, never generated. Written to params and conf only when exported non-empty. |

The padding addition is kept deliberately small. AWG2's S4 transport padding
already grew every data packet and the MTU / packet-size question raised in the
AWG2 post-migration measurement is still open; a large content padding addition
would compound it.

The timing ranges are left unset so the kernel and client defaults apply.
Randomising them per node would shift rekey and keepalive behaviour, which the
sleep/wake reconnect path depends on. They are reachable by env for a future
experiment without another code change.

### S1–S4 floor

Header protection derives its ChaCha20 nonce from the first 12 bytes of the
random padding prefix. With any of S1–S4 below 12 the nonce reads into the
message body, the two sides derive different keystreams, and nothing connects —
with no error logged anywhere.

Under `AWG3=1`:

- `generateS3AndS4` draws `S3` from 12–64 and `S4` from 12–32.
- `s_padding_in_range` gains a minimum, so the prompt loop re-asks on any value
  below 12 and prints the nonce reason once.
- `S1`/`S2` already have a floor of 15 and are unchanged.

Under `AWG3=0` all four keep today's ranges (`S3` 8–64 seeded, 0–64 accepted;
`S4` 4–32 seeded, 0–32 accepted).

## Preflight version gate

Under `AWG3=1`, after the AmneziaWG packages are installed and `awg` is
confirmed present, and **before** `SERVER_AWG_CONF` or `SERVER_PARAMS_FILE` are
written:

1. If `/sys/module/amneziawg/version` exists and reads `3.` or higher, pass.
2. Otherwise, pass if `awg set --help 2>&1` mentions `header-protection-key`.
3. Otherwise print the required version and the PPA upgrade instruction and
   `exit 1`.

Nothing is written before this point in the AWG3 path, so a failure leaves the
host as it was apart from installed packages.

## Server config and params file

`${SERVER_PARAMS_FILE}` gains, under `AWG3=1`:

```
AWG_PROFILE=awg3
SERVER_AWG_HEADER_PROTECTION_KEY=<base64>
SERVER_AWG_CONTENT_PADDING_ADDITION=<min-max>
```

plus any exported timing values. `AWG_PROFILE=awg2` continues to be written in
the AWG2 path.

`${SERVER_AWG_CONF}` header comment becomes `# CHOP-AWG-PROFILE: awg3`, and two
directives are appended after the `H1`–`H4` block:

```
HeaderProtectionKey = <base64>
ContentPaddingAddition = <min-max>
```

Timing directives (`RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`,
`KeepaliveTimeout`, `MaxHandshakeAttempts`) are appended only when the
corresponding variable is non-empty, the same pattern as `I1`–`I5`.

Keys are inline base64 in a conf file, exactly like `PrivateKey`. The file-path
form applies to the `awg set` CLI, not to conf files.

The existing `awg-quick strip` validation runs afterwards and already fails the
install loudly if the userspace tools reject a directive. It is the second line
of defence behind the preflight gate.

## service.sh

- `AWG_PROFILE=${AWG_PROFILE:-awg2}`, validated against `awg2|awg3`. The default
  stays `awg2` so a direct `bash service.sh` on an existing node behaves as it
  does today.
- `prepare_environment` writes `set_env_value AWG_PROFILE "${AWG_PROFILE}"`
  instead of the hardcoded `awg2`.
- `verify_token_context` asserts `"profile":"${AWG_PROFILE}"` and its success and
  failure messages name the profile.
- Both `service.sh` invocations in `amneziawg-install.sh` pass
  `AWG_PROFILE="${AWG_PROFILE}"` through.

## Node API (`main.go`)

**Profile handling.** `AWG_PROFILE` validation accepts `awg3`. `isAWG2Profile()`
splits into two predicates:

- `isModernProfile()` — `awg2 || awg3`; gates the client-config marker, `S3`/`S4`
  and `I1`–`I5` emission and the existing `validateAWG2Params` call.
- `isAWG3Profile()` — `awg3` only; gates the new directives and the extra
  validation.

**Params.** `WGParams` gains `ServerAWGHeaderProtectionKey`,
`ServerAWGContentPaddingAddition` and the five timing fields, read from the
params file. Under `awg3` the required-params map gains
`SERVER_AWG_HEADER_PROTECTION_KEY`, so a node whose params file lacks it fails
at startup rather than issuing configs that cannot connect.

**Client config emission.** After the `I1`–`I5` block, under `isAWG3Profile()`:

```
HeaderProtectionKey = <base64>
ContentPaddingAddition = <min-max>
```

plus each non-empty timing value as `RekeyAfterTime`, `RekeyTimeout`,
`RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`.

The profile marker line stays the literal `# CHOP-AWG-PROFILE: awg2` for both
modern profiles. `VPNProtocolProfileMarker.detect` on the client accepts only
that literal; emitting `awg3` there makes the iOS app reject the config outright.
The AWG3 keys are additive inside the awg2-marked profile.

**Validation.** Under `awg3`, in addition to today's AWG2 checks:

- `SERVER_AWG_HEADER_PROTECTION_KEY` decodes as base64 to exactly 32 bytes and
  is not all-zero.
- `S1`, `S2`, `S3`, `S4` all parse and are `>= 12`.
- `SERVER_AWG_CONTENT_PADDING_ADDITION`, when present, is a bare number or an
  ordered `min-max` pair.

Failure is fatal at startup, consistent with the current `validateAWG2Params`
call site.

**Health.** `/api/health` already reports `AWG_PROFILE`, so an AWG3 node reports
`"profile":"awg3"` with no further change; `service.sh` verification consumes it.

## Testing

`installer_test.sh` gains AWG3 cases:

- A headless AWG3 run writes the expected params keys and conf directives, and
  the conf marker reads `awg3`.
- `s_padding_in_range` rejects `S3`/`S4` below 12 under `AWG3=1` and accepts 0
  under `AWG3=0`.
- The preflight gate exits non-zero, and writes no conf or params file, when the
  simulated `awg set --help` lacks `header-protection-key`.
- An `AWG_PROFILE=awg2` run produces the same params and conf content as before
  the change.

`main_test.go` gains:

- Client config generation under `awg3` contains the two new directives, the
  timing directives when set, and still carries the `awg2` marker.
- Startup validation rejects a short, malformed or all-zero header key, and
  rejects `S3`/`S4` below 12.
- `awg2` generation output is unchanged.

## Backward compatibility

- `main.go` and `service.sh` both default to `awg2`. Existing nodes, existing
  params files and existing `.env` files behave exactly as today.
- The AWG2 install path is unchanged: same prompts, same ranges, same
  `INSTALL-AWG2` token, same conf and params content.
- Client configs from an AWG3 node keep the `awg2` marker, so pre-12.3.0 apps
  parse them successfully but cannot complete a handshake against a
  header-protected node. That gap is closed by the backend
  `is_support_awg_third` gate, not here: **a node installed with this profile
  must be created with that flag set.**
- An old node binary reading a new AWG3 params file would ignore the unknown
  keys and issue AWG2 configs against an AWG3 interface — a node that accepts
  nobody. The release asset carrying these `main.go` changes must therefore be
  published **before** the first `install2.sh` AWG3 run, since `service.sh`
  downloads the latest release. Note the repo's tag-overwrite release flow: the
  same tag is re-pushed, so confirm the asset timestamp before installing.
- The 20 nodes with a stale `WG_PARAMS_FILE` are unaffected; nothing in this
  design touches an installed node.
