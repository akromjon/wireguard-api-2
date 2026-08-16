# AWG3 Installer + Node API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new `install3.sh` entry point that installs an AmneziaWG 3.0 node end to end — AWG3 server interface, AWG3 params file, and a node API that issues client configs carrying `HeaderProtectionKey`.

**Architecture:** `install2.sh` is never edited. `install3.sh` is a copy that exports `AWG_PROFILE=awg3`; the shared `amneziawg-install.sh` derives one `AWG3=1` switch from that and gates every new behaviour on it. `service.sh` forwards the profile into the node's `.env`, and `main.go` grows an `isAWG3Profile()` predicate that adds the AWG3 directives to generated client configs.

**Tech Stack:** Bash (installer, service, test harness), Go 1.x + Gin (node API, `go test`).

## Global Constraints

- **Client config profile marker stays the literal `# CHOP-AWG-PROFILE: awg2`** for both awg2 and awg3. `VPNProtocolProfileMarker.detect` on iOS accepts only that literal; `awg3` makes the app reject the config outright. Only the *server* conf marker becomes `awg3`.
- **S1, S2, S3, S4 must all be >= 12 under awg3.** Header protection derives its ChaCha20 nonce from the first 12 bytes of the random padding prefix; below 12 the nonce reads into the message body and nothing connects, silently.
- `HeaderProtectionKey` in a **conf file** is inline base64, like `PrivateKey`. The file-path form applies only to the `awg set` CLI.
- Defaults stay `awg2` in `main.go` and `service.sh`. `install2.sh` and the AWG2 install path must come out byte-identical.
- Content padding addition stays small (max total 64): AWG2's S4 transport padding already grew every data packet and the MTU question is still open.
- The five timing ranges (`RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`) are **never generated or prompted** — env passthrough only.
- **Never SSH to a VPN node, never deploy, never publish a release** during this work. Every node serves live users. Verification is local `go test` and `bash installer_test.sh` only.
- Spec: `docs/superpowers/specs/2026-08-16-awg3-installer-design.md`.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `main.go` | modify | Profile predicates, AWG3 params load + validation, AWG3 client-config emission |
| `main_test.go` | modify | Go tests for the above |
| `service.sh` | modify | Forward `AWG_PROFILE` into `.env`, verify it via `/api/health` |
| `amneziawg-install.sh` | modify | `AWG3` switch, awg3 detection, S floors, key/padding generation, preflight gate, params + conf writing |
| `installer_test.sh` | modify | Bash tests for installer and service helpers |
| `install3.sh` | create | AWG3 entry point (copy of `install2.sh`, exports `AWG_PROFILE=awg3`) |
| `README.md` | modify | `install3.sh` one-liner + client version requirement |

Order matters: the node API ships first because a node installed with awg3 against an old binary issues AWG2 configs on an AWG3 interface — a node nobody can reach.

---

### Task 1: Node API — profile predicates, AWG3 params, validation

**Files:**
- Modify: `main.go` (WGParams struct ~line 49-90; `loadWGParams` ~line 318-440; `validateAWG2Params`/`isAWG2Profile` ~line 468-515)
- Test: `main_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `isModernProfile() bool`, `isAWG3Profile() bool`, `validateAWG3Params(params WGParams) error`, `validateAWGRange(value string) error`, and the `WGParams` fields `ServerAWGHeaderProtectionKey`, `ServerAWGContentPaddingAddition`, `ServerAWGRekeyAfterTime`, `ServerAWGRekeyTimeout`, `ServerAWGRejectAfterTime`, `ServerAWGKeepaliveTimeout`, `ServerAWGMaxHandshakeAttempts` (all `string`). Task 2 emits those fields; Task 5 writes the params keys they read.

- [ ] **Step 1: Write the failing tests**

Append to `main_test.go`:

```go
func TestValidateAWG3ParamsAcceptsAWellFormedNode(t *testing.T) {
	params := WGParams{
		ServerAWGS1: "81", ServerAWGS2: "55", ServerAWGS3: "16", ServerAWGS4: "16",
		ServerAWGHeaderProtectionKey:    "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=",
		ServerAWGContentPaddingAddition: "8-40",
	}
	if err := validateAWG3Params(params); err != nil {
		t.Fatalf("expected a valid AWG3 node to pass: %v", err)
	}
}

func TestValidateAWG3ParamsRejectsPaddingBelowTheNonceFloor(t *testing.T) {
	base := WGParams{
		ServerAWGS1: "81", ServerAWGS2: "55", ServerAWGS3: "16", ServerAWGS4: "16",
		ServerAWGHeaderProtectionKey: "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=",
	}
	for _, tc := range []struct {
		name  string
		apply func(*WGParams)
	}{
		{"S1", func(p *WGParams) { p.ServerAWGS1 = "11" }},
		{"S2", func(p *WGParams) { p.ServerAWGS2 = "0" }},
		{"S3", func(p *WGParams) { p.ServerAWGS3 = "8" }},
		{"S4", func(p *WGParams) { p.ServerAWGS4 = "4" }},
	} {
		params := base
		tc.apply(&params)
		err := validateAWG3Params(params)
		if err == nil || !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s below 12 must be rejected, got %v", tc.name, err)
		}
	}
}

func TestValidateAWG3ParamsRejectsBadHeaderProtectionKeys(t *testing.T) {
	base := WGParams{ServerAWGS1: "81", ServerAWGS2: "55", ServerAWGS3: "16", ServerAWGS4: "16"}
	for name, key := range map[string]string{
		"empty":     "",
		"not base64": "!!!!not-base64!!!!",
		"too short": "c2hvcnRrZXk=",
		"all zero":  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		params := base
		params.ServerAWGHeaderProtectionKey = key
		if err := validateAWG3Params(params); err == nil {
			t.Errorf("%s header protection key must be rejected", name)
		}
	}
}

func TestValidateAWGRangeAcceptsEmptyBareAndOrderedRanges(t *testing.T) {
	for _, value := range []string{"", "32", "8-40"} {
		if err := validateAWGRange(value); err != nil {
			t.Errorf("%q must be accepted: %v", value, err)
		}
	}
	for _, value := range []string{"40-8", "abc", "8-abc"} {
		if err := validateAWGRange(value); err == nil {
			t.Errorf("%q must be rejected", value)
		}
	}
}

func TestLoadWGParamsRequiresHeaderProtectionKeyUnderAWG3(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg3"

	paramsPath := filepath.Join(env.dir, "params-awg3")
	writeAWG3ParamsFile(t, paramsPath, "")
	WG_PARAMS_FILE = paramsPath
	paramsFileExplicit = true
	configFileExplicit = true

	err := loadWGParams()
	if err == nil || !strings.Contains(err.Error(), "SERVER_AWG_HEADER_PROTECTION_KEY") {
		t.Fatalf("awg3 node without a header protection key must fail to load, got %v", err)
	}

	writeAWG3ParamsFile(t, paramsPath, "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=")
	if err := loadWGParams(); err != nil {
		t.Fatalf("complete awg3 params must load: %v", err)
	}
	if wgParams.ServerAWGHeaderProtectionKey == "" ||
		wgParams.ServerAWGContentPaddingAddition != "8-40" ||
		wgParams.ServerAWGRekeyAfterTime != "100-140" {
		t.Fatalf("AWG3 params were not read into wgParams: %+v", wgParams)
	}
}

// writeAWG3ParamsFile writes a complete AWG3 params file. An empty
// headerProtectionKey omits the line entirely, which is what an AWG2-era
// params file looks like to an awg3-configured API.
func writeAWG3ParamsFile(t *testing.T, path, headerProtectionKey string) {
	t.Helper()
	body := `SERVER_PUB_IP=203.0.113.10
SERVER_PUB_NIC=eth0
SERVER_AWG_NIC=awg1
SERVER_AWG_IPV4=10.66.66.1
SERVER_AWG_IPV6=fd42:42:42::1
SERVER_PORT=443
SERVER_PRIV_KEY=server-private-key
SERVER_PUB_KEY=server-public-key
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
SERVER_AWG_JC=5
SERVER_AWG_JMIN=50
SERVER_AWG_JMAX=1000
SERVER_AWG_S1=81
SERVER_AWG_S2=55
SERVER_AWG_S3=16
SERVER_AWG_S4=16
SERVER_AWG_H1=100-200
SERVER_AWG_H2=300-400
SERVER_AWG_H3=500-600
SERVER_AWG_H4=700-800
AWG_PROFILE=awg3
SERVER_AWG_CONTENT_PADDING_ADDITION=8-40
SERVER_AWG_REKEY_AFTER_TIME=100-140
`
	if headerProtectionKey != "" {
		body += "SERVER_AWG_HEADER_PROTECTION_KEY=" + headerProtectionKey + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("writing params file: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./... -run 'AWG3|AWGRange' -v`
Expected: FAIL — `undefined: validateAWG3Params`, `undefined: validateAWGRange`.

- [ ] **Step 3: Add the WGParams fields**

In `main.go`, after `ServerAWGI5 string` in the `WGParams` struct:

```go
	// AmneziaWG 3.0 parameters. Only the header protection key and the content
	// padding addition are generated by the installer; the timing ranges are
	// written only when an operator exports them.
	ServerAWGHeaderProtectionKey    string
	ServerAWGContentPaddingAddition string
	ServerAWGRekeyAfterTime         string
	ServerAWGRekeyTimeout           string
	ServerAWGRejectAfterTime        string
	ServerAWGKeepaliveTimeout       string
	ServerAWGMaxHandshakeAttempts   string
```

- [ ] **Step 4: Add the profile predicates**

Replace `isAWG2Profile` in `main.go` (~line 512) with:

```go
// isModernProfile covers every non-legacy AmneziaWG profile: the S3/S4
// paddings, the I1-I5 signatures and the client profile marker are shared by
// awg2 and awg3.
func isModernProfile() bool {
	return backendType == "amneziawg" && (AWG_PROFILE == "awg2" || AWG_PROFILE == "awg3")
}

// isAWG3Profile gates the AmneziaWG 3.0 additions: header protection, the
// content padding addition and the timing ranges.
func isAWG3Profile() bool {
	return backendType == "amneziawg" && AWG_PROFILE == "awg3"
}
```

Then replace every `isAWG2Profile()` call with `isModernProfile()`. Find them with `grep -n 'isAWG2Profile()' main.go` — expect the client-config marker, the S3/S4 block and the I1-I5 block.

- [ ] **Step 5: Accept awg3 in loadWGParams and read the new params**

In `loadWGParams`, replace the profile guard:

```go
	if AWG_PROFILE != "awg2" && AWG_PROFILE != "awg3" && AWG_PROFILE != "legacy" {
		return fmt.Errorf("unsupported AWG_PROFILE %q; use awg2, awg3 or legacy", AWG_PROFILE)
	}
```

Add to the `wgParams = WGParams{...}` literal, after `ServerAWGI5`:

```go
		ServerAWGHeaderProtectionKey:    params["SERVER_AWG_HEADER_PROTECTION_KEY"],
		ServerAWGContentPaddingAddition: params["SERVER_AWG_CONTENT_PADDING_ADDITION"],
		ServerAWGRekeyAfterTime:         params["SERVER_AWG_REKEY_AFTER_TIME"],
		ServerAWGRekeyTimeout:           params["SERVER_AWG_REKEY_TIMEOUT"],
		ServerAWGRejectAfterTime:        params["SERVER_AWG_REJECT_AFTER_TIME"],
		ServerAWGKeepaliveTimeout:       params["SERVER_AWG_KEEPALIVE_TIMEOUT"],
		ServerAWGMaxHandshakeAttempts:   params["SERVER_AWG_MAX_HANDSHAKE_ATTEMPTS"],
```

Replace the required-parameter block guard `if backendType == "amneziawg" && AWG_PROFILE == "awg2" {` with `if isModernProfile() {`, add the AWG3 requirement inside it right after the map literal is built, and chain the AWG3 validation after `validateAWG2Params`:

```go
		if isAWG3Profile() {
			if wgParams.ServerAWGHeaderProtectionKey == "" {
				missing = append(missing, "SERVER_AWG_HEADER_PROTECTION_KEY")
			}
		}
```

(place this immediately before the `if len(missing) > 0 {` check), and:

```go
		if err := validateAWG2Params(wgParams); err != nil {
			return err
		}
		if isAWG3Profile() {
			if err := validateAWG3Params(wgParams); err != nil {
				return err
			}
		}
```

- [ ] **Step 6: Implement the AWG3 validators**

Add to `main.go` next to `validateAWG2Params`:

```go
// Header protection derives its ChaCha20 nonce from the first 12 bytes of the
// random padding prefix. With any of S1-S4 below 12 the nonce reads into the
// message body instead, the two sides derive different keystreams, and nothing
// connects — with no error logged on either side.
const awgHeaderProtectionMinPadding = 12

func validateAWG3Params(params WGParams) error {
	key, err := base64.StdEncoding.DecodeString(params.ServerAWGHeaderProtectionKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("invalid AWG3 SERVER_AWG_HEADER_PROTECTION_KEY: must be 32 bytes of base64")
	}
	if bytes.Equal(key, make([]byte, 32)) {
		return fmt.Errorf("invalid AWG3 SERVER_AWG_HEADER_PROTECTION_KEY: an all-zero key disables header protection")
	}

	for _, padding := range []struct {
		name  string
		value string
	}{
		{name: "S1", value: params.ServerAWGS1},
		{name: "S2", value: params.ServerAWGS2},
		{name: "S3", value: params.ServerAWGS3},
		{name: "S4", value: params.ServerAWGS4},
	} {
		parsed, err := strconv.ParseUint(padding.value, 10, 16)
		if err != nil || parsed < awgHeaderProtectionMinPadding {
			return fmt.Errorf("invalid AWG3 %s value %q: must be at least %d for header protection",
				padding.name, padding.value, awgHeaderProtectionMinPadding)
		}
	}

	if err := validateAWGRange(params.ServerAWGContentPaddingAddition); err != nil {
		return fmt.Errorf("invalid AWG3 SERVER_AWG_CONTENT_PADDING_ADDITION %q: %v",
			params.ServerAWGContentPaddingAddition, err)
	}
	return nil
}

// validateAWGRange accepts an empty value (the directive is then omitted from
// client configs), a bare number, or an ordered "min-max" pair.
func validateAWGRange(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.SplitN(value, "-", 2)
	low, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return fmt.Errorf("must be a number or an ordered min-max range")
	}
	if len(parts) == 1 {
		return nil
	}
	high, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil {
		return fmt.Errorf("must be a number or an ordered min-max range")
	}
	if high < low {
		return fmt.Errorf("range is reversed")
	}
	return nil
}
```

Add `"bytes"` and `"encoding/base64"` to the import block if they are not already there (`grep -n '"bytes"\|"encoding/base64"' main.go`).

- [ ] **Step 7: Run the tests**

Run: `gofmt -l . && go build ./... && go test ./...`
Expected: `gofmt` prints nothing, build succeeds, all tests PASS including the pre-existing `TestAWG2ClientConfigContainsProfileMarkerAndAllParameters` and the `unsupported AWG_PROFILE` test.

- [ ] **Step 8: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(api): load and validate AmneziaWG 3.0 parameters"
```

---

### Task 2: Node API — emit AWG3 directives into client configs

**Files:**
- Modify: `main.go` (client config builder, the `isModernProfile()` I1-I5 block ~line 1419)
- Test: `main_test.go`

**Interfaces:**
- Consumes: `isAWG3Profile()` and the `WGParams` AWG3 fields from Task 1.
- Produces: client configs whose `[Interface]` section carries `HeaderProtectionKey`, `ContentPaddingAddition` and the timing directives.

- [ ] **Step 1: Write the failing test**

Append to `main_test.go`:

```go
func TestAWG3ClientConfigCarriesHeaderProtectionAndKeepsTheAWG2Marker(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg3"
	wgParams.ServerAWGJC = "5"
	wgParams.ServerAWGJMin = "50"
	wgParams.ServerAWGJMax = "1000"
	wgParams.ServerAWGS1 = "81"
	wgParams.ServerAWGS2 = "55"
	wgParams.ServerAWGS3 = "16"
	wgParams.ServerAWGS4 = "16"
	wgParams.ServerAWGH1 = "100-200"
	wgParams.ServerAWGH2 = "300-400"
	wgParams.ServerAWGH3 = "500-600"
	wgParams.ServerAWGH4 = "700-800"
	wgParams.ServerAWGHeaderProtectionKey = "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc="
	wgParams.ServerAWGContentPaddingAddition = "8-40"
	wgParams.ServerAWGRekeyAfterTime = "100-140"
	wgParams.ServerAWGMaxHandshakeAttempts = "18"

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "awg3user"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Success bool   `json:"success"`
		Data    Client `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	for _, expected := range []string{
		// The marker stays awg2: VPNProtocolProfileMarker.detect on iOS accepts
		// only that literal, and the AWG3 keys are additive inside it.
		awg2ConfigMarker,
		"S3 = 16",
		"S4 = 16",
		"HeaderProtectionKey = cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=",
		"ContentPaddingAddition = 8-40",
		"RekeyAfterTime = 100-140",
		"MaxHandshakeAttempts = 18",
	} {
		if !strings.Contains(resp.Data.Config, expected) {
			t.Errorf("AWG3 client config missing %q:\n%s", expected, resp.Data.Config)
		}
	}
	for _, unexpected := range []string{"# CHOP-AWG-PROFILE: awg3", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout"} {
		if strings.Contains(resp.Data.Config, unexpected) {
			t.Errorf("AWG3 client config must not contain %q:\n%s", unexpected, resp.Data.Config)
		}
	}
}

func TestAWG2ClientConfigHasNoAWG3Directives(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg2"
	wgParams.ServerAWGS3 = "16"
	wgParams.ServerAWGS4 = "16"
	wgParams.ServerAWGH1 = "100-200"
	wgParams.ServerAWGH2 = "300-400"
	wgParams.ServerAWGH3 = "500-600"
	wgParams.ServerAWGH4 = "700-800"
	// Set on purpose: an awg2 node must not leak AWG3 keys even if its params
	// file carries them.
	wgParams.ServerAWGHeaderProtectionKey = "cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc="
	wgParams.ServerAWGContentPaddingAddition = "8-40"

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "awg2only"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Success bool   `json:"success"`
		Data    Client `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	for _, unexpected := range []string{"HeaderProtectionKey", "ContentPaddingAddition"} {
		if strings.Contains(resp.Data.Config, unexpected) {
			t.Errorf("awg2 config must not contain %q:\n%s", unexpected, resp.Data.Config)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./... -run 'AWG3ClientConfig|AWG2ClientConfigHasNo' -v`
Expected: FAIL — config missing `HeaderProtectionKey = ...`.

- [ ] **Step 3: Emit the directives**

In `main.go`, immediately after the `isModernProfile()` I1-I5 block and still inside `if backendType == "amneziawg" {`:

```go
		if isAWG3Profile() {
			if wgParams.ServerAWGHeaderProtectionKey != "" {
				interfaceLines = append(interfaceLines,
					fmt.Sprintf("HeaderProtectionKey = %s", wgParams.ServerAWGHeaderProtectionKey))
			}
			for _, field := range []struct {
				name  string
				value string
			}{
				{name: "ContentPaddingAddition", value: wgParams.ServerAWGContentPaddingAddition},
				{name: "RekeyAfterTime", value: wgParams.ServerAWGRekeyAfterTime},
				{name: "RekeyTimeout", value: wgParams.ServerAWGRekeyTimeout},
				{name: "RejectAfterTime", value: wgParams.ServerAWGRejectAfterTime},
				{name: "KeepaliveTimeout", value: wgParams.ServerAWGKeepaliveTimeout},
				{name: "MaxHandshakeAttempts", value: wgParams.ServerAWGMaxHandshakeAttempts},
			} {
				// Unset timing ranges are omitted so the client falls back to
				// its own defaults instead of parsing an empty value.
				if field.value != "" {
					interfaceLines = append(interfaceLines, fmt.Sprintf("%s = %s", field.name, field.value))
				}
			}
		}
```

- [ ] **Step 4: Run the full Go suite**

Run: `gofmt -l . && go test ./...`
Expected: `gofmt` prints nothing, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(api): emit AmneziaWG 3.0 directives in generated client configs"
```

---

### Task 3: service.sh — forward the profile into the node .env

**Files:**
- Modify: `service.sh` (env defaults ~line 21-40, `prepare_environment` ~line 146, `verify_token_context` ~line 192-207)
- Modify: `amneziawg-install.sh` (both `bash ./service.sh` invocations, ~line 1193-1220)
- Test: `installer_test.sh`

**Interfaces:**
- Consumes: `AWG_PROFILE` from the environment (set by `amneziawg-install.sh`, ultimately by `install3.sh`).
- Produces: `AWG_PROFILE=<profile>` in `${CONFIG_DIR}/.env`, consumed by the Go binary from Task 1.

- [ ] **Step 1: Write the failing test**

In `installer_test.sh`, after the existing `prepare_environment` assertions (the `WIREGUARD_CLIENTS=` grep near line 157), add:

```bash
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash installer_test.sh`
Expected: FAIL with `installer test failed: service.sh must default the profile to awg2`.

- [ ] **Step 3: Add the profile variable to service.sh**

After `UPGRADE_EXISTING_SERVICE=${UPGRADE_EXISTING_SERVICE:-false}` (~line 29):

```bash
# Which AmneziaWG profile this node's API generates client configs for. The
# default stays awg2 so running service.sh directly on an existing node keeps
# its behaviour; install3.sh exports awg3.
AWG_PROFILE=${AWG_PROFILE:-awg2}
```

And beside the existing `SERVICE_NAME`/`API_PORT` validation (~line 33-40):

```bash
if [[ ${AWG_PROFILE} != awg2 && ${AWG_PROFILE} != awg3 ]]; then
	echo "Invalid AWG_PROFILE: ${AWG_PROFILE} (expected awg2 or awg3)" >&2
	exit 1
fi
```

- [ ] **Step 4: Write and verify the profile**

In `prepare_environment`, replace `set_env_value AWG_PROFILE awg2` with:

```bash
	set_env_value AWG_PROFILE "${AWG_PROFILE}"
```

In `verify_token_context`, replace the profile assertion and both messages:

```bash
		if [[ ${response} == *'"success":true'* && ${response} == *'"interface":"'"${expected_interface}"'"'* && ${response} == *'"profile":"'"${AWG_PROFILE}"'"'* ]]; then
			echo "Verified ${SERVICE_NAME} serves ${expected_interface} with ${AWG_PROFILE} on TCP ${API_PORT}."
			return 0
		fi
```

```bash
	echo "API verification failed: ${SERVICE_NAME} did not serve ${expected_interface} with ${AWG_PROFILE} on TCP ${API_PORT}." >&2
```

- [ ] **Step 5: Pass the profile through from the installer**

In `amneziawg-install.sh`, add `AWG_PROFILE="${AWG_PROFILE}" \` to **both** `bash ./service.sh` invocations, beside `AWG_INTERFACE="${SERVER_AWG_NIC}" \`.

- [ ] **Step 6: Run the tests**

Run: `bash installer_test.sh`
Expected: PASS, ending with `installer parameter and coexistence tests passed`.

- [ ] **Step 7: Commit**

```bash
git add service.sh amneziawg-install.sh installer_test.sh
git commit -m "feat(service): carry AWG_PROFILE into the node API environment"
```

---

### Task 4: Installer — profile switch, awg3 detection, S padding floor

**Files:**
- Modify: `amneziawg-install.sh` (globals ~line 13-23, `detect_existing_awg_installations` ~line 62-90, `generateS3AndS4`/`s_padding_in_range`/`readS3AndS4` ~line 556-595, `installQuestions` confirmation ~line 878-885)
- Test: `installer_test.sh`

**Interfaces:**
- Consumes: `AWG_PROFILE` exported by the entry point (Task 6); defaults to `awg2`.
- Produces: globals `AWG3` (0/1), `AWG3_DETECTED` (0/1), `AWG_S_PADDING_MIN` (0 or 12), `INSTALL_TOKEN` (`INSTALL-AWG2`/`INSTALL-AWG3`), all used by Task 5.

- [ ] **Step 1: Write the failing tests**

In `installer_test.sh`, after the existing `generateS3AndS4` loop (line ~59), add:

```bash
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
```

And after the existing AWG2-marker detection assertion (line ~112), add:

```bash
printf '%s\n' 'HeaderProtectionKey = cJ0PBHm9nGZbYpXvR1sKfQ2tLdW8uA6yE3iO5rTgVmc=' >>"${AMNEZIAWG_DIR}/awg0.conf"
detect_existing_awg_installations
[[ ${AWG3_DETECTED} == 1 ]] || fail "an interface with header protection must be detected as awg3"
[[ ${AWG2_DETECTED} == 1 ]] || fail "an awg3 interface must still count as a modern interface"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash installer_test.sh`
Expected: FAIL — `AWG3: unbound variable` (or the `sourcing without AWG_PROFILE` message).

- [ ] **Step 3: Add the profile switch**

In `amneziawg-install.sh`, after `AWG_H_RANGE_WIDTH=1000` (~line 16):

```bash
# Which AmneziaWG profile this run installs. install2.sh exports awg2,
# install3.sh exports awg3; everything AWG3-specific below is gated on AWG3=1.
AWG_PROFILE=${AWG_PROFILE:-awg2}
case ${AWG_PROFILE} in
awg2)
	AWG3=0
	AWG_S_PADDING_MIN=0
	INSTALL_TOKEN=INSTALL-AWG2
	;;
awg3)
	AWG3=1
	# Header protection derives its ChaCha20 nonce from the first 12 bytes of
	# the random padding prefix, so every S value must reach 12.
	AWG_S_PADDING_MIN=12
	INSTALL_TOKEN=INSTALL-AWG3
	;;
*)
	echo -e "${RED}Unsupported AWG_PROFILE: ${AWG_PROFILE} (expected awg2 or awg3)${NC}" >&2
	exit 1
	;;
esac
```

Add `AWG3_DETECTED=0` beside the existing `AWG2_DETECTED=0` global (~line 23).

- [ ] **Step 4: Detect an existing AWG3 interface**

In `detect_existing_awg_installations`, add `AWG3_DETECTED=0` to the reset block beside `AWG2_DETECTED=0`, and replace the profile classification with:

```bash
		if grep -Eq '^[[:space:]]*HeaderProtectionKey[[:space:]]*=' "${config}"; then
			profile=awg3
			AWG3_DETECTED=1
			# An awg3 interface is a modern interface: the "manage, don't
			# duplicate" guard below must fire for it too.
			AWG2_DETECTED=1
		elif grep -Eq '^# CHOP-AWG-PROFILE: awg[23]$|^[[:space:]]*S3[[:space:]]*=' "${config}"; then
			profile=awg2
			AWG2_DETECTED=1
		else
			LEGACY_AWG_DETECTED=1
		fi
```

- [ ] **Step 5: Apply the padding floor**

Replace `s_padding_in_range` and `generateS3AndS4`:

```bash
function s_padding_in_range() {
	local value=$1 max=$2
	[[ ${value} =~ ^[0-9]+$ ]] && ((value >= AWG_S_PADDING_MIN)) && ((value <= max))
}
```

```bash
function generateS3AndS4() {
	local s3_floor=8 s4_floor=4
	if ((AWG3 == 1)); then
		s3_floor=${AWG_S_PADDING_MIN}
		s4_floor=${AWG_S_PADDING_MIN}
	fi
	RANDOM_AWG_S3=$(shuf -i"${s3_floor}-64" -n1)
	RANDOM_AWG_S4=$(shuf -i"${s4_floor}-32" -n1)
}
```

In `readS3AndS4`, print the reason once under awg3 and quote the floor in both prompts:

```bash
	if ((AWG3 == 1)); then
		echo "AWG3 header protection reads its nonce from the first 12 bytes of the padding prefix; S3 and S4 must be at least 12."
	fi
	until s_padding_in_range "${SERVER_AWG_S3}" 64; do
		read -rp "Server AmneziaWG S3 padding [${AWG_S_PADDING_MIN}-64]: " -e -i "${RANDOM_AWG_S3}" SERVER_AWG_S3
	done
	until s_padding_in_range "${SERVER_AWG_S4}" 32; do
		read -rp "Server AmneziaWG S4 padding [${AWG_S_PADDING_MIN}-32]: " -e -i "${RANDOM_AWG_S4}" SERVER_AWG_S4
	done
```

Keep the `SERVER_AWG_S3="${SERVER_AWG_S3:-}"` / `SERVER_AWG_S4="${SERVER_AWG_S4:-}"` empty-sentinel lines and their comment exactly as they are — the existing regression test asserts they are not seeded with `0`. The AWG2 prompt text no longer says "0 disables"; that is intentional and the existing `-i 0` guard test still passes.

- [ ] **Step 6: Use the profile in the summary and confirmation**

In `installQuestions`, replace the summary heading and the confirmation guard:

```bash
	echo "${AWG_PROFILE^^} installation summary:"
```

```bash
	if [[ -z ${INSTALL_CONFIRMATION:-} ]]; then
		read -rp "Type ${INSTALL_TOKEN} to confirm these changes: " INSTALL_CONFIRMATION
	fi
	if [[ ${INSTALL_CONFIRMATION} != "${INSTALL_TOKEN}" ]]; then
		echo "Installation cancelled; no configuration changes were made."
		exit 0
	fi
```

- [ ] **Step 7: Run the tests**

Run: `bash installer_test.sh`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add amneziawg-install.sh installer_test.sh
git commit -m "feat(installer): add the awg3 profile switch, detection and padding floor"
```

---

### Task 5: Installer — key generation, preflight gate, params and conf output

**Files:**
- Modify: `amneziawg-install.sh` (new helpers beside `generateS3AndS4`; `installQuestions` ~line 853-860; `installAmneziaWG` params write ~line 990-1015 and conf write ~line 1017-1040)
- Test: `installer_test.sh`

**Interfaces:**
- Consumes: `AWG3`, `AWG_PROFILE` from Task 4.
- Produces: `generateHeaderProtectionKey()`, `generateContentPaddingAddition()`, `awg3_module_version_ok(version)`, `assert_awg3_supported()`, `awg3_timing_directives()`; the params keys `SERVER_AWG_HEADER_PROTECTION_KEY`, `SERVER_AWG_CONTENT_PADDING_ADDITION` and the five optional timing keys read by Task 1.

- [ ] **Step 1: Write the failing tests**

In `installer_test.sh`, after the Task 4 padding assertions, add:

```bash
(
	AWG3=1
	unset SERVER_AWG_HEADER_PROTECTION_KEY SERVER_AWG_CONTENT_PADDING_ADDITION
	generateHeaderProtectionKey
	# 32 raw bytes base64-encoded is always 44 characters ending in '='.
	[[ ${#SERVER_AWG_HEADER_PROTECTION_KEY} == 44 ]] ||
		fail "header protection key must be 32 bytes of base64, got '${SERVER_AWG_HEADER_PROTECTION_KEY}'"
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
		fail "header protection key is not valid base64: ${SERVER_AWG_HEADER_PROTECTION_KEY}"
	[[ $(printf '%s' "${SERVER_AWG_HEADER_PROTECTION_KEY}" | base64 -d | wc -c) == 32 ]] ||
		fail "header protection key must decode to 32 bytes"

	first=${SERVER_AWG_HEADER_PROTECTION_KEY}
	unset SERVER_AWG_HEADER_PROTECTION_KEY
	generateHeaderProtectionKey
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} != "${first}" ]] ||
		fail "header protection key must be random per node"

	SERVER_AWG_HEADER_PROTECTION_KEY=operator-supplied-key
	generateHeaderProtectionKey
	[[ ${SERVER_AWG_HEADER_PROTECTION_KEY} == operator-supplied-key ]] ||
		fail "an exported header protection key must be honoured"
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash installer_test.sh`
Expected: FAIL — `generateHeaderProtectionKey: command not found`.

- [ ] **Step 3: Add the generators**

In `amneziawg-install.sh`, after `generateS3AndS4`:

```bash
# 32 random bytes, base64 — the same shape `awg genkey` produces. Generated
# from /dev/urandom rather than the AmneziaWG tools so it works before the
# packages are installed and stays testable off a node.
function generateHeaderProtectionKey() {
	if [[ -n ${SERVER_AWG_HEADER_PROTECTION_KEY:-} ]]; then
		return
	fi
	SERVER_AWG_HEADER_PROTECTION_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
}

# Extra payload padding on top of S4. Kept small on purpose: S4 already grows
# every transport packet, and the MTU/packet-size question from the AWG2
# migration is still open.
function generateContentPaddingAddition() {
	if [[ -n ${SERVER_AWG_CONTENT_PADDING_ADDITION:-} ]]; then
		return
	fi
	local low
	low=$(shuf -i1-16 -n1)
	SERVER_AWG_CONTENT_PADDING_ADDITION="${low}-$((low + $(shuf -i8-48 -n1)))"
}

# Emits the AWG3 timing directives an operator exported, one per line, and
# nothing at all when none were. These are never generated or prompted for:
# randomising rekey and keepalive timing would shift the reconnect behaviour
# the sleep/wake path depends on.
function awg3_timing_directives() {
	local pair name var
	for pair in \
		"RekeyAfterTime:SERVER_AWG_REKEY_AFTER_TIME" \
		"RekeyTimeout:SERVER_AWG_REKEY_TIMEOUT" \
		"RejectAfterTime:SERVER_AWG_REJECT_AFTER_TIME" \
		"KeepaliveTimeout:SERVER_AWG_KEEPALIVE_TIMEOUT" \
		"MaxHandshakeAttempts:SERVER_AWG_MAX_HANDSHAKE_ATTEMPTS"; do
		name=${pair%%:*}
		var=${pair##*:}
		if [[ -n ${!var:-} ]]; then
			echo "${name} = ${!var}"
		fi
	done
	return 0
}
```

- [ ] **Step 4: Add the preflight gate**

Add beside the generators:

```bash
function awg3_module_version_ok() {
	local version=$1
	[[ ${version} =~ ^([0-9]+) ]] || return 1
	((BASH_REMATCH[1] >= 3))
}

# AWG3 needs a 3.0 module and userspace. Called after the packages are
# installed and before anything is written to disk, so a node that cannot do
# header protection is left exactly as it was.
function assert_awg3_supported() {
	local module_version=""
	if [[ -r /sys/module/amneziawg/version ]]; then
		module_version=$(</sys/module/amneziawg/version)
	fi
	if awg3_module_version_ok "${module_version}"; then
		return 0
	fi
	if awg set --help 2>&1 | grep -q 'header-protection-key'; then
		return 0
	fi
	echo -e "${RED}This host's AmneziaWG build does not support header protection.${NC}" >&2
	echo -e "${ORANGE}Loaded module version: ${module_version:-unknown}; AWG3 needs 3.0 or newer.${NC}" >&2
	echo -e "${ORANGE}Upgrade the Amnezia PPA packages (apt update && apt install --only-upgrade amneziawg-dkms amneziawg-tools), reboot, then rerun install3.sh.${NC}" >&2
	return 1
}
```

Call it in `installAmneziaWG`, immediately before `# Create AmneziaWG directory if it doesn't exist` / `mkdir -p "${AMNEZIAWG_DIR}"`:

```bash
	if ((AWG3 == 1)) && ! assert_awg3_supported; then
		exit 1
	fi
```

- [ ] **Step 5: Generate the AWG3 values during the questions**

In `installQuestions`, after the `readIParams` call:

```bash
	if ((AWG3 == 1)); then
		generateHeaderProtectionKey
		generateContentPaddingAddition
	fi
```

In the summary block, after the clients-directory line:

```bash
	if ((AWG3 == 1)); then
		echo "  Header protection: enabled (per-node key)"
		echo "  Content padding addition: ${SERVER_AWG_CONTENT_PADDING_ADDITION}"
		echo "  Serves iOS 12.3.0+ and Android 2.4.2+ clients only"
	fi
```

- [ ] **Step 6: Write the AWG3 params and conf directives**

In `installAmneziaWG`, change the last line of the params heredoc-style `echo` from `AWG_PROFILE=awg2" >"${SERVER_PARAMS_FILE}"` to:

```bash
AWG_PROFILE=${AWG_PROFILE}" >"${SERVER_PARAMS_FILE}"
```

After the five `SERVER_AWG_I*` `printf` lines:

```bash
	if ((AWG3 == 1)); then
		printf 'SERVER_AWG_HEADER_PROTECTION_KEY=%s\n' "${SERVER_AWG_HEADER_PROTECTION_KEY}" >>"${SERVER_PARAMS_FILE}"
		printf 'SERVER_AWG_CONTENT_PADDING_ADDITION=%s\n' "${SERVER_AWG_CONTENT_PADDING_ADDITION}" >>"${SERVER_PARAMS_FILE}"
		local timing_var
		for timing_var in SERVER_AWG_REKEY_AFTER_TIME SERVER_AWG_REKEY_TIMEOUT \
			SERVER_AWG_REJECT_AFTER_TIME SERVER_AWG_KEEPALIVE_TIMEOUT \
			SERVER_AWG_MAX_HANDSHAKE_ATTEMPTS; do
			if [[ -n ${!timing_var:-} ]]; then
				printf '%s=%s\n' "${timing_var}" "${!timing_var}" >>"${SERVER_PARAMS_FILE}"
			fi
		done
	fi
```

In the server conf `echo` block, change the marker line from `# CHOP-AWG-PROFILE: awg2` to:

```
# CHOP-AWG-PROFILE: ${AWG_PROFILE}
```

After the five `[[ -n ${SERVER_AWG_I*} ]] && echo ...` lines:

```bash
	if ((AWG3 == 1)); then
		# Inline base64, exactly like PrivateKey. The file-path form of this
		# key applies to `awg set`, not to conf files.
		echo "HeaderProtectionKey = ${SERVER_AWG_HEADER_PROTECTION_KEY}" >>"${SERVER_AWG_CONF}"
		[[ -n ${SERVER_AWG_CONTENT_PADDING_ADDITION} ]] &&
			echo "ContentPaddingAddition = ${SERVER_AWG_CONTENT_PADDING_ADDITION}" >>"${SERVER_AWG_CONF}"
		awg3_timing_directives >>"${SERVER_AWG_CONF}"
	fi
```

Update the two `awg-quick strip` failure messages in the same function to say `${AWG_PROFILE}` instead of `AWG2`.

- [ ] **Step 7: Run the tests**

Run: `bash installer_test.sh && bash -n amneziawg-install.sh && bash -n service.sh`
Expected: PASS, no syntax errors.

- [ ] **Step 8: Commit**

```bash
git add amneziawg-install.sh installer_test.sh
git commit -m "feat(installer): generate AWG3 keys, gate on module 3.0, write AWG3 config"
```

---

### Task 6: install3.sh entry point and README

**Files:**
- Create: `install3.sh`
- Modify: `README.md`
- Test: `installer_test.sh`

**Interfaces:**
- Consumes: `AWG_PROFILE` handling from Task 4, the whole installer chain from Tasks 3-5.
- Produces: the published `install3.sh` one-liner.

- [ ] **Step 1: Write the failing test**

Append to `installer_test.sh`, before the final `echo`:

```bash
[[ -x ${SCRIPT_DIR}/install3.sh ]] || fail "install3.sh must exist and be executable"
grep -qx 'export AWG_PROFILE=awg3' "${SCRIPT_DIR}/install3.sh" || fail "install3.sh must export the awg3 profile"
grep -qx 'export AWG_PROFILE=awg2' "${SCRIPT_DIR}/install2.sh" || fail "install2.sh must keep exporting awg2"

# The two entry points must not drift on the machinery that actually installs
# anything. Compared line by line rather than by diff, because the banners and
# comments legitimately differ.
while IFS= read -r shared_line; do
	grep -qxF "${shared_line}" "${SCRIPT_DIR}/install3.sh" ||
		fail "install3.sh is missing install2.sh machinery: ${shared_line}"
done < <(grep -E 'REPOSITORY|WIREGUARD_API_REF|mktemp|rm -rf|trap cleanup|git clone|chmod \+x|EUID|apt-get install -y git|\./amneziawg-install\.sh' "${SCRIPT_DIR}/install2.sh")

grep -q 'AmneziaWG 3.0' "${SCRIPT_DIR}/install3.sh" || fail "install3.sh must name the profile it installs"
# Written as an if, not `grep && fail`: under `set -e` a failing grep on the
# left of && would abort the whole test run.
if grep -q 'AWG_PROFILE=awg3' "${SCRIPT_DIR}/install2.sh"; then
	fail "install2.sh must not reference awg3"
fi
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash installer_test.sh`
Expected: FAIL with `installer test failed: install3.sh must exist and be executable`.

- [ ] **Step 3: Create install3.sh**

Copy `install2.sh` and change only the banner and the profile block:

```bash
cp install2.sh install3.sh
chmod +x install3.sh
```

Then edit `install3.sh` so those two places read:

```bash
printf '%b\n' "${GREEN}Preparing WireGuard API V2 with AmneziaWG 3.0.${NC}"
```

```bash
# This entry point is AWG3-only: the installed interface enables header
# protection, so it serves iOS 12.3.0+ and Android 2.4.2+ clients only. Mark
# the resulting server with is_support_awg_third in the admin panel. Use
# install2.sh for an AWG2 node.
export AWG_PROFILE=awg3
./amneziawg-install.sh
```

and the closing line:

```bash
printf '%b\n' "${GREEN}WireGuard API V2 / AmneziaWG 3.0 installation completed.${NC}"
```

Leave every other line — root check, `REPOSITORY`/`REF`, temp dir, cleanup trap, git bootstrap, `git clone`, `chmod +x` — byte-identical.

- [ ] **Step 4: Document it**

In `README.md`, beside the existing `install2.sh` one-liner, add:

````markdown
### AmneziaWG 3.0 node

```bash
curl -sSL https://raw.githubusercontent.com/akromjon/wireguard-api-2/main/install3.sh -o install3.sh
chmod +x install3.sh
sudo ./install3.sh
```

An AWG3 node enables header protection, so only iOS 12.3.0+ and Android 2.4.2+
clients can connect to it. Set `is_support_awg_third` on the server record when
you register it, or older clients will be handed a config they cannot use.
Requires an AmneziaWG 3.0 module; the installer checks and refuses to continue
otherwise. `install2.sh` still installs an AWG2 node and is unchanged.
````

- [ ] **Step 5: Run everything**

Run: `bash installer_test.sh && bash -n install3.sh && go test ./...`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add install3.sh README.md installer_test.sh
git commit -m "feat: add install3.sh, the AmneziaWG 3.0 entry point"
```

---

## After the plan

Not part of this plan, and not to be done by the implementing agent:

1. Publish a release whose binary contains Tasks 1-2. `service.sh` downloads the latest release, so an `install3.sh` run before that publishes a node whose API issues AWG2 configs on an AWG3 interface — a node nobody can reach. Note the repo's tag-overwrite release flow: confirm the asset timestamp, not just the tag.
2. Install a node with `install3.sh` and register it with `is_support_awg_third = true` (backend spec `2026-08-16-awg3-server-gating-design.md`).
3. Verify with `AWG_LIVE_CONF=<client.conf> cargo test -p awg-core --test kernel_live -- --ignored --nocapture` from the iOS repo.
