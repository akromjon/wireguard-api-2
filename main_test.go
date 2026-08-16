package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

// fakeWGScript emulates wg/awg and wg-quick/awg-quick so tests run without
// WireGuard installed. Every invocation is appended to invocations.log next to
// the script; creating a sync_fail file makes syncconf exit non-zero.
const fakeWGScript = `#!/bin/bash
dir="$(dirname "$0")"
echo "$1" >> "$dir/invocations.log"
case "$1" in
  show)
    if [ -f "$dir/status_fail" ]; then
      echo "fake show failure" >&2
      exit 1
    fi
    ;;
  genkey) echo "priv$RANDOM$RANDOM$RANDOM" ;;
  pubkey) echo "pub-$(cat)" ;;
  genpsk) echo "psk$RANDOM$RANDOM$RANDOM" ;;
  strip) exit 0 ;;
  syncconf)
    cat > /dev/null
    if [ -f "$dir/sync_fail" ]; then
      echo "fake syncconf failure" >&2
      exit 1
    fi
    ;;
esac
exit 0
`

type testEnv struct {
	dir        string
	configFile string
	clientsDir string
	router     *gin.Engine
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "wg0.conf")
	clientsDir := filepath.Join(dir, "clients")
	script := filepath.Join(dir, "wg")

	initialConfig := `[Interface]
Address = 10.66.0.1/16
ListenPort = 51820
PrivateKey = server-private-key
`
	if err := os.WriteFile(configFile, []byte(initialConfig), 0600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if err := os.MkdirAll(clientsDir, 0700); err != nil {
		t.Fatalf("creating clients dir: %v", err)
	}
	if err := os.WriteFile(script, []byte(fakeWGScript), 0755); err != nil {
		t.Fatalf("writing fake wg script: %v", err)
	}

	oldConfigFile, oldClientsDir := WG_CONFIG_FILE, WIREGUARD_CLIENTS
	oldWGCmd, oldWGQuickCmd := wgCmd, wgQuickCmd
	oldParams, oldToken := wgParams, API_TOKEN
	oldParamsFile, oldBackendType := WG_PARAMS_FILE, backendType
	oldAWGProfile := AWG_PROFILE
	oldUseUDP443Endpoint := USE_UDP_443_ENDPOINT
	oldConfigFileExplicit, oldParamsFileExplicit := configFileExplicit, paramsFileExplicit

	WG_CONFIG_FILE = configFile
	WG_PARAMS_FILE = filepath.Join(dir, "params")
	WIREGUARD_CLIENTS = clientsDir
	wgCmd = script
	wgQuickCmd = script
	API_TOKEN = "test-token"
	USE_UDP_443_ENDPOINT = false
	AWG_PROFILE = "awg2"
	configFileExplicit = false
	paramsFileExplicit = false
	wgParams = WGParams{
		ServerPubIP:   "203.0.113.10",
		ServerWGNIC:   "wg0",
		ServerWGIPv4:  "10.66.0.1",
		ServerPort:    "51820",
		ServerPrivKey: "server-private-key",
		ServerPubKey:  "server-public-key",
		ClientDNS1:    "1.1.1.1",
		ClientDNS2:    "1.0.0.1",
		AllowedIPs:    "0.0.0.0/0",
	}
	backendType = "wireguard"

	t.Cleanup(func() {
		WG_CONFIG_FILE, WIREGUARD_CLIENTS = oldConfigFile, oldClientsDir
		WG_PARAMS_FILE, backendType = oldParamsFile, oldBackendType
		wgCmd, wgQuickCmd = oldWGCmd, oldWGQuickCmd
		wgParams, API_TOKEN = oldParams, oldToken
		AWG_PROFILE = oldAWGProfile
		USE_UDP_443_ENDPOINT = oldUseUDP443Endpoint
		configFileExplicit, paramsFileExplicit = oldConfigFileExplicit, oldParamsFileExplicit
	})

	// Use the production router so tests exercise the exact routing + middleware
	return &testEnv{dir: dir, configFile: configFile, clientsDir: clientsDir, router: newRouter()}
}

func (e *testEnv) request(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("key", token)
	}

	recorder := httptest.NewRecorder()
	e.router.ServeHTTP(recorder, req)

	return recorder
}

func (e *testEnv) authedRequest(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(t, method, path, body, "test-token")
}

func (e *testEnv) syncconfCalls(t *testing.T) int {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(e.dir, "invocations.log"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("reading invocations log: %v", err)
	}

	return strings.Count(string(content), "syncconf")
}

func (e *testEnv) configContent(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(e.configFile)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	return string(content)
}

type bulkResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Created int              `json:"created"`
		Failed  int              `json:"failed"`
		Results []BulkUserResult `json:"results"`
	} `json:"data"`
}

func decodeBulkResponse(t *testing.T, recorder *httptest.ResponseRecorder) bulkResponse {
	t.Helper()

	var resp bulkResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response %q: %v", recorder.Body.String(), err)
	}

	return resp
}

func bulkNames(count int) []string {
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("user%d", i)
	}
	return names
}

func appendToFile(t *testing.T, path, content string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("opening %s for append: %v", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("appending to %s: %v", path, err)
	}
}

func TestClientNameRegex(t *testing.T) {
	valid := []string{"a", "abc", "ABC123", "a_b-c", strings.Repeat("x", 15)}
	for _, name := range valid {
		if !clientNameRegex.MatchString(name) {
			t.Errorf("expected %q to be a valid client name", name)
		}
	}

	invalid := []string{"", strings.Repeat("x", 16), "has space", "ünïcode", "semi;colon", "slash/name", "dot.name"}
	for _, name := range invalid {
		if clientNameRegex.MatchString(name) {
			t.Errorf("expected %q to be rejected as a client name", name)
		}
	}
}

func TestAuthMiddleware(t *testing.T) {
	env := setupTestEnv(t)

	if got := env.request(t, http.MethodGet, "/api/users", nil, "").Code; got != http.StatusNotFound {
		t.Errorf("missing token: got status %d, want 404", got)
	}
	if got := env.request(t, http.MethodGet, "/api/users", nil, "wrong-token").Code; got != http.StatusNotFound {
		t.Errorf("wrong token: got status %d, want 404", got)
	}
	if got := env.authedRequest(t, http.MethodGet, "/api/users", nil).Code; got != http.StatusOK {
		t.Errorf("valid token: got status %d, want 200", got)
	}
}

func TestHealthEndpointReturnsRunningStateAndContextIdentity(t *testing.T) {
	env := setupTestEnv(t)

	recorder := env.authedRequest(t, http.MethodGet, "/api/health", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Running   bool   `json:"running"`
			Interface string `json:"interface"`
			Profile   string `json:"profile"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !resp.Success || !resp.Data.Running || resp.Data.Interface != "wg0" || resp.Data.Profile != "awg2" {
		t.Fatalf("unexpected health response: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "peers") || strings.Contains(recorder.Body.String(), "status_output") {
		t.Fatalf("health response contains detailed status data: %s", recorder.Body.String())
	}
	if calls := env.syncconfCalls(t); calls != 0 {
		t.Errorf("health endpoint must not synchronize config: got %d syncconf calls", calls)
	}
}

func TestStatsEndpointReturnsCountersWithoutDumpingPeers(t *testing.T) {
	env := setupTestEnv(t)

	recorder := env.authedRequest(t, http.MethodGet, "/api/stats", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()

	// The whole point of this endpoint is that it stays small and cheap no
	// matter how many peers the node holds, so it must never grow per-peer
	// fields the way /api/status does.
	for _, forbidden := range []string{"public_key", "preshared_key", "transfer_rx", "status_output", "system_load"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("stats response leaked per-peer/detail field %q: %s", forbidden, body)
		}
	}

	if calls := env.syncconfCalls(t); calls != 0 {
		t.Errorf("stats endpoint must not synchronize config: got %d syncconf calls", calls)
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Interface string `json:"interface"`
			Profile   string `json:"profile"`
			RxBytes   uint64 `json:"rx_bytes"`
			TxBytes   uint64 `json:"tx_bytes"`
			Peers     int    `json:"peers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	// A test host has no wg0, so counters are unreadable and the handler
	// reports failure rather than inventing zeroes. Either way it must answer
	// quickly and never expose peer detail, which is asserted above.
	if resp.Success && (resp.Data.Interface != wgParams.ServerWGNIC || resp.Data.Profile != AWG_PROFILE) {
		t.Fatalf("unexpected identity in stats response: %s", body)
	}
}

func TestHealthEndpointReportsStoppedInterfaceWithoutDetails(t *testing.T) {
	env := setupTestEnv(t)
	if err := os.WriteFile(filepath.Join(env.dir, "status_fail"), nil, 0600); err != nil {
		t.Fatalf("creating status failure marker: %v", err)
	}

	recorder := env.authedRequest(t, http.MethodGet, "/api/health", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Running bool `json:"running"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !resp.Success || resp.Data.Running {
		t.Fatalf("unexpected stopped health response: %s", recorder.Body.String())
	}
	if calls := env.syncconfCalls(t); calls != 0 {
		t.Errorf("health endpoint must not synchronize config: got %d syncconf calls", calls)
	}
}

func TestSingleAddUser(t *testing.T) {
	env := setupTestEnv(t)

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "alice"})
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
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.Data.IPV4 != "10.66.0.2" {
		t.Errorf("got ipv4 %q, want 10.66.0.2 (first free after server .1)", resp.Data.IPV4)
	}
	if !strings.Contains(resp.Data.Config, "PersistentKeepalive = 25") {
		t.Error("client config missing PersistentKeepalive")
	}
	if !strings.Contains(resp.Data.Config, "Endpoint = 203.0.113.10:51820") {
		t.Error("default client endpoint should use SERVER_PORT")
	}

	if !strings.Contains(env.configContent(t), "### Client alice") {
		t.Error("server config missing peer entry for alice")
	}
	clientFile := filepath.Join(env.clientsDir, "wg0-client-alice.conf")
	if _, err := os.Stat(clientFile); err != nil {
		t.Errorf("client config file not written: %v", err)
	}
	if calls := env.syncconfCalls(t); calls != 1 {
		t.Errorf("got %d syncconf calls, want 1", calls)
	}

	// The same name again must be rejected without touching the config
	dup := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "alice"})
	if dup.Code != http.StatusConflict {
		t.Errorf("duplicate add: got status %d, want 409", dup.Code)
	}
	if calls := env.syncconfCalls(t); calls != 1 {
		t.Errorf("duplicate add must not sync again: got %d syncconf calls, want 1", calls)
	}
}

func TestAWG2ClientConfigContainsProfileMarkerAndAllParameters(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg2"
	wgParams.ServerAWGJC = "5"
	wgParams.ServerAWGJMin = "50"
	wgParams.ServerAWGJMax = "1000"
	wgParams.ServerAWGS1 = "20"
	wgParams.ServerAWGS2 = "90"
	wgParams.ServerAWGS3 = "0"
	wgParams.ServerAWGS4 = "32"
	wgParams.ServerAWGH1 = "100-200"
	wgParams.ServerAWGH2 = "300-400"
	wgParams.ServerAWGH3 = "500-600"
	wgParams.ServerAWGH4 = "700-800"
	wgParams.ServerAWGI1 = "<b 0x1234> <r 2>"
	wgParams.ServerAWGI2 = "<rd 3>"
	wgParams.ServerAWGI3 = "<rc 4>"
	wgParams.ServerAWGI4 = "<t>"
	wgParams.ServerAWGI5 = "<b 0xabcd>"

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "awg2user"})
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
	if !resp.Success {
		t.Fatalf("expected successful AWG2 add: %s", recorder.Body.String())
	}

	for _, expected := range []string{
		awg2ConfigMarker,
		"Jc = 5",
		"Jmin = 50",
		"Jmax = 1000",
		"S1 = 20",
		"S2 = 90",
		"S3 = 0",
		"S4 = 32",
		"H1 = 100-200",
		"H2 = 300-400",
		"H3 = 500-600",
		"H4 = 700-800",
		"I1 = <b 0x1234> <r 2>",
		"I2 = <rd 3>",
		"I3 = <rc 4>",
		"I4 = <t>",
		"I5 = <b 0xabcd>",
	} {
		if !strings.Contains(resp.Data.Config, expected) {
			t.Errorf("AWG2 client config missing %q:\n%s", expected, resp.Data.Config)
		}
	}

	// The public API envelope and Client fields remain unchanged while the
	// config carries the additional AWG2 information.
	if resp.Data.Name != "awg2user" || resp.Data.IPV4 == "" || resp.Data.Config == "" {
		t.Errorf("unexpected compatible client response: %+v", resp.Data)
	}
}

func TestLegacyAWGProfileDoesNotEmitAWG2OnlyFields(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "legacy"
	wgParams.ServerAWGJC = "5"
	wgParams.ServerAWGS1 = "20"
	wgParams.ServerAWGS2 = "90"
	wgParams.ServerAWGH1 = "100"
	wgParams.ServerAWGH2 = "200"
	wgParams.ServerAWGH3 = "300"
	wgParams.ServerAWGH4 = "400"
	wgParams.ServerAWGS3 = "0"
	wgParams.ServerAWGS4 = "32"
	wgParams.ServerAWGI1 = "<t>"

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "legacyuser"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	var resp struct {
		Data Client `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if strings.Contains(resp.Data.Config, awg2ConfigMarker) ||
		strings.Contains(resp.Data.Config, "S3 =") ||
		strings.Contains(resp.Data.Config, "S4 =") ||
		strings.Contains(resp.Data.Config, "I1 =") {
		t.Errorf("legacy profile unexpectedly emitted AWG2-only fields:\n%s", resp.Data.Config)
	}
	if !strings.Contains(resp.Data.Config, "Jc = 5") || !strings.Contains(resp.Data.Config, "H1 = 100") {
		t.Errorf("legacy AWG fields disappeared from legacy config:\n%s", resp.Data.Config)
	}
}

func TestAWG2OmitsEmptyOptionalSignatureFields(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg2"
	wgParams.ServerAWGS3 = "0"
	wgParams.ServerAWGS4 = "0"
	wgParams.ServerAWGH1 = "100-200"
	wgParams.ServerAWGH2 = "300-400"
	wgParams.ServerAWGH3 = "500-600"
	wgParams.ServerAWGH4 = "700-800"

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "no-signatures"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data Client `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !strings.Contains(resp.Data.Config, "S3 = 0") || !strings.Contains(resp.Data.Config, "S4 = 0") {
		t.Errorf("zero S3/S4 values must remain explicit:\n%s", resp.Data.Config)
	}
	for _, field := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if strings.Contains(resp.Data.Config, field+" =") {
			t.Errorf("empty optional %s must be omitted:\n%s", field, resp.Data.Config)
		}
	}
}

func TestLoadAWG2Params(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg2"
	paramsPath := filepath.Join(env.dir, "awg2-params")
	explicitConfigPath := filepath.Join(env.dir, "awg1-custom.conf")
	t.Setenv("WG_CONFIG_FILE", explicitConfigPath)
	params := `SERVER_PUB_IP=203.0.113.10
SERVER_PUB_NIC=eth0
SERVER_AWG_NIC=awg0
SERVER_AWG_IPV4=10.66.66.1
SERVER_AWG_IPV6=fd42:42:42::1
SERVER_PORT=443
SERVER_PRIV_KEY=server-private
SERVER_PUB_KEY=server-public
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=1.0.0.1
ALLOWED_IPS=0.0.0.0/0,::/0
SERVER_AWG_JC=5
SERVER_AWG_JMIN=50
SERVER_AWG_JMAX=1000
SERVER_AWG_S1=20
SERVER_AWG_S2=90
SERVER_AWG_S3=0
SERVER_AWG_S4=32
SERVER_AWG_H1=100-200
SERVER_AWG_H2=300-400
SERVER_AWG_H3=500-600
SERVER_AWG_H4=700-800
SERVER_AWG_I1='<b 0x1234>'
SERVER_AWG_I2='<r 2>'
SERVER_AWG_I3='<rd 3>'
SERVER_AWG_I4='<rc 4>'
SERVER_AWG_I5='<t>'
`
	if err := os.WriteFile(paramsPath, []byte(params), 0600); err != nil {
		t.Fatalf("writing params: %v", err)
	}
	WG_PARAMS_FILE = paramsPath

	if err := loadWGParams(); err != nil {
		t.Fatalf("loadWGParams: %v", err)
	}
	if wgParams.ServerAWGS3 != "0" || wgParams.ServerAWGS4 != "32" {
		t.Errorf("S3/S4 not loaded: S3=%q S4=%q", wgParams.ServerAWGS3, wgParams.ServerAWGS4)
	}
	if wgParams.ServerAWGH1 != "100-200" || wgParams.ServerAWGH4 != "700-800" {
		t.Errorf("H ranges not preserved: H1=%q H4=%q", wgParams.ServerAWGH1, wgParams.ServerAWGH4)
	}
	if wgParams.ServerAWGI1 != "<b 0x1234>" || wgParams.ServerAWGI5 != "<t>" {
		t.Errorf("I fields not loaded: I1=%q I5=%q", wgParams.ServerAWGI1, wgParams.ServerAWGI5)
	}
	if WG_CONFIG_FILE != explicitConfigPath {
		t.Errorf("explicit config path was replaced: got %q want %q", WG_CONFIG_FILE, explicitConfigPath)
	}
}

func TestDetectBackendUsesExplicitAmneziaParams(t *testing.T) {
	dir := t.TempDir()
	paramsPath := filepath.Join(dir, "params.awg1")
	configPath := filepath.Join(dir, "custom-awg1.conf")
	awgPath := filepath.Join(dir, "awg")
	if err := os.WriteFile(paramsPath, []byte("SERVER_AWG_NIC=awg1\n"), 0600); err != nil {
		t.Fatalf("writing params: %v", err)
	}
	if err := os.WriteFile(awgPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("writing fake awg: %v", err)
	}

	t.Setenv("PATH", dir)
	t.Setenv("WG_PARAMS_FILE", paramsPath)
	oldBackendType, oldParamsFile, oldConfigFile := backendType, WG_PARAMS_FILE, WG_CONFIG_FILE
	oldWGCmd, oldWGQuickCmd := wgCmd, wgQuickCmd
	oldParamsFileExplicit, oldConfigFileExplicit := paramsFileExplicit, configFileExplicit
	WG_CONFIG_FILE = configPath
	configFileExplicit = true
	paramsFileExplicit = false
	t.Cleanup(func() {
		backendType, WG_PARAMS_FILE, WG_CONFIG_FILE = oldBackendType, oldParamsFile, oldConfigFile
		wgCmd, wgQuickCmd = oldWGCmd, oldWGQuickCmd
		paramsFileExplicit, configFileExplicit = oldParamsFileExplicit, oldConfigFileExplicit
	})

	detectBackend()
	if backendType != "amneziawg" {
		t.Fatalf("explicit AWG params should select amneziawg backend, got %q", backendType)
	}
	if WG_PARAMS_FILE != paramsPath {
		t.Fatalf("got params path %q want %q", WG_PARAMS_FILE, paramsPath)
	}
	if WG_CONFIG_FILE != configPath {
		t.Fatalf("explicit config path was replaced: got %q want %q", WG_CONFIG_FILE, configPath)
	}
}

func TestLoadAWG2ParamsRejectsMissingRequiredField(t *testing.T) {
	env := setupTestEnv(t)
	backendType = "amneziawg"
	AWG_PROFILE = "awg2"
	paramsPath := filepath.Join(env.dir, "incomplete-params")
	params := `SERVER_PUB_IP=203.0.113.10
SERVER_AWG_NIC=awg0
SERVER_AWG_IPV4=10.66.66.1
SERVER_PORT=443
SERVER_PUB_KEY=server-public
SERVER_AWG_S3=0
SERVER_AWG_S4=32
SERVER_AWG_H1=100-200
SERVER_AWG_H2=300-400
SERVER_AWG_H3=500-600
`
	if err := os.WriteFile(paramsPath, []byte(params), 0600); err != nil {
		t.Fatalf("writing params: %v", err)
	}
	WG_PARAMS_FILE = paramsPath

	err := loadWGParams()
	if err == nil || !strings.Contains(err.Error(), "required AWG2 parameters missing") {
		t.Fatalf("expected missing AWG2 parameter error, got %v", err)
	}
	if !strings.Contains(err.Error(), "SERVER_AWG_H4") {
		t.Errorf("error should identify missing H4, got %v", err)
	}
}

func TestLoadAWG2ParamsRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name       string
		overrides  string
		wantErrors []string
	}{
		{name: "S3 exceeds documented range", overrides: "SERVER_AWG_S3=65", wantErrors: []string{"S3", "0-64"}},
		{name: "S4 exceeds documented range", overrides: "SERVER_AWG_S4=33", wantErrors: []string{"S4", "0-32"}},
		{name: "H below minimum", overrides: "SERVER_AWG_H1=4", wantErrors: []string{"H1", "bounds"}},
		{name: "H ranges overlap", overrides: "SERVER_AWG_H1=100-300", wantErrors: []string{"H1 and H2", "overlap"}},
		{name: "H range has too many bounds", overrides: "SERVER_AWG_H1=100-200-300", wantErrors: []string{"H1", "number or min-max"}},
	}

	baseParams := `SERVER_PUB_IP=203.0.113.10
SERVER_AWG_NIC=awg0
SERVER_AWG_IPV4=10.66.66.1
SERVER_PORT=443
SERVER_PUB_KEY=server-public
SERVER_AWG_S3=0
SERVER_AWG_S4=32
SERVER_AWG_H1=100-200
SERVER_AWG_H2=300-400
SERVER_AWG_H3=500-600
SERVER_AWG_H4=700-800
`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			backendType = "amneziawg"
			AWG_PROFILE = "awg2"
			paramsPath := filepath.Join(env.dir, "params")
			key := tc.overrides[:strings.Index(tc.overrides, "=")]
			original := map[string]string{
				"SERVER_AWG_S3": "0",
				"SERVER_AWG_H1": "100-200",
			}[key]
			content := strings.Replace(baseParams, key+"="+original, tc.overrides, 1)
			if err := os.WriteFile(paramsPath, []byte(content), 0600); err != nil {
				t.Fatalf("writing params: %v", err)
			}
			WG_PARAMS_FILE = paramsPath

			err := loadWGParams()
			if err == nil {
				t.Fatal("expected malformed AWG2 params to be rejected")
			}
			for _, fragment := range tc.wantErrors {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("error %q does not contain %q", err, fragment)
				}
			}
		})
	}
}

func TestLoadWGParamsRejectsUnknownAWGProfile(t *testing.T) {
	setupTestEnv(t)
	AWG_PROFILE = "not-a-profile"
	if err := loadWGParams(); err == nil || !strings.Contains(err.Error(), "unsupported AWG_PROFILE") {
		t.Fatalf("expected unsupported profile error, got %v", err)
	}
}

func TestSingleAddUserUsesUDP443WhenEnabled(t *testing.T) {
	env := setupTestEnv(t)
	USE_UDP_443_ENDPOINT = true

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "udp443"})
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
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if !strings.Contains(resp.Data.Config, "Endpoint = 203.0.113.10:443") {
		t.Error("enabled UDP 443 mode should generate a 443 client endpoint")
	}
	if strings.Contains(resp.Data.Config, "Endpoint = 203.0.113.10:51820") {
		t.Error("enabled UDP 443 mode must not generate SERVER_PORT as the client endpoint")
	}
	if !strings.Contains(env.configContent(t), "ListenPort = 51820") {
		t.Error("enabling UDP 443 endpoint mode must not change the WireGuard listener")
	}
}

func TestSingleAddUserInvalidName(t *testing.T) {
	env := setupTestEnv(t)

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "bad name!"})
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", recorder.Code)
	}
}

func TestBulkAddValidation(t *testing.T) {
	cases := []struct {
		label string
		body  any
	}{
		{"empty names", AddUsersBulkRequest{Names: []string{}}},
		{"missing names", map[string]any{}},
		{"too many names", AddUsersBulkRequest{Names: bulkNames(maxBulkUsers + 1)}},
		{"invalid name", AddUsersBulkRequest{Names: []string{"ok1", "not ok"}}},
		{"duplicate names", AddUsersBulkRequest{Names: []string{"twin", "other", "twin"}}},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			env := setupTestEnv(t)
			before := env.configContent(t)

			recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", tc.body)
			if recorder.Code != http.StatusBadRequest {
				t.Errorf("got status %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
			}
			if env.configContent(t) != before {
				t.Error("rejected request must not modify the server config")
			}
			if calls := env.syncconfCalls(t); calls != 0 {
				t.Errorf("rejected request must not sync: got %d syncconf calls", calls)
			}
		})
	}
}

func TestBulkAddHappyPath(t *testing.T) {
	env := setupTestEnv(t)
	names := bulkNames(25)

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: names})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if !resp.Success {
		t.Fatalf("expected success=true, message %q", resp.Message)
	}
	if resp.Data.Created != len(names) || resp.Data.Failed != 0 {
		t.Fatalf("got created=%d failed=%d, want %d/0", resp.Data.Created, resp.Data.Failed, len(names))
	}
	if len(resp.Data.Results) != len(names) {
		t.Fatalf("got %d results, want %d", len(resp.Data.Results), len(names))
	}

	seenIPs := make(map[string]bool)
	for i, result := range resp.Data.Results {
		if result.Name != names[i] {
			t.Errorf("result %d: got name %q, want %q (order must match request)", i, result.Name, names[i])
		}
		if !result.Success {
			t.Errorf("result %d (%s): unexpected failure %q", i, result.Name, result.Message)
		}
		if result.IPV4 == "" || seenIPs[result.IPV4] {
			t.Errorf("result %d (%s): missing or duplicate ipv4 %q", i, result.Name, result.IPV4)
		}
		seenIPs[result.IPV4] = true
	}

	config := env.configContent(t)
	if got := strings.Count(config, "### Client "); got != len(names) {
		t.Errorf("server config has %d peer entries, want %d", got, len(names))
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(env.clientsDir, "wg0-client-"+name+".conf")); err != nil {
			t.Errorf("client file for %s not written: %v", name, err)
		}
	}

	// The whole point of the endpoint: one config apply for the entire batch
	if calls := env.syncconfCalls(t); calls != 1 {
		t.Errorf("got %d syncconf calls, want exactly 1", calls)
	}
}

func TestBulkAddFullBatchOf500(t *testing.T) {
	env := setupTestEnv(t)
	names := bulkNames(maxBulkUsers)

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: names})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if resp.Data.Created != maxBulkUsers {
		t.Fatalf("got created=%d, want %d", resp.Data.Created, maxBulkUsers)
	}

	seenIPs := make(map[string]bool)
	for _, result := range resp.Data.Results {
		if seenIPs[result.IPV4] {
			t.Fatalf("duplicate ipv4 %q allocated in one batch", result.IPV4)
		}
		seenIPs[result.IPV4] = true
	}

	if calls := env.syncconfCalls(t); calls != 1 {
		t.Errorf("got %d syncconf calls, want exactly 1", calls)
	}
}

func TestBulkAddSkipsExistingName(t *testing.T) {
	env := setupTestEnv(t)

	if code := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "existing"}).Code; code != http.StatusOK {
		t.Fatalf("seeding existing user failed with status %d", code)
	}

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: []string{"existing", "fresh"}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if resp.Data.Created != 1 || resp.Data.Failed != 1 {
		t.Fatalf("got created=%d failed=%d, want 1/1", resp.Data.Created, resp.Data.Failed)
	}
	if resp.Data.Results[0].Success || !strings.Contains(resp.Data.Results[0].Message, "already exists") {
		t.Errorf("existing name should fail with already-exists, got %+v", resp.Data.Results[0])
	}
	if !resp.Data.Results[1].Success {
		t.Errorf("fresh name should succeed, got %+v", resp.Data.Results[1])
	}
}

func TestBulkAddSyncFailure(t *testing.T) {
	env := setupTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.dir, "sync_fail"), nil, 0600); err != nil {
		t.Fatalf("creating sync_fail flag: %v", err)
	}

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: bulkNames(3)})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500 (body %s)", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if resp.Success {
		t.Error("expected success=false when config apply fails")
	}
	// The caller must still learn what was written so a follow-up sync can reconcile
	if resp.Data.Created != 3 {
		t.Errorf("got created=%d, want 3 (clients were written before the failed apply)", resp.Data.Created)
	}
	if !strings.Contains(resp.Message, "failed to apply config") {
		t.Errorf("message should explain the apply failure, got %q", resp.Message)
	}
}

func TestBulkAddAllNamesExistingIsFailure(t *testing.T) {
	env := setupTestEnv(t)

	for _, name := range []string{"one", "two"} {
		if code := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: name}).Code; code != http.StatusOK {
			t.Fatalf("seeding %s failed with status %d", name, code)
		}
	}

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: []string{"one", "two"}})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("a batch that created nothing must not report success: got status %d, body %s", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if resp.Success {
		t.Error("expected success=false when created=0")
	}
	if resp.Data.Created != 0 || resp.Data.Failed != 2 {
		t.Errorf("got created=%d failed=%d, want 0/2", resp.Data.Created, resp.Data.Failed)
	}
	if !strings.Contains(resp.Message, "no clients were created") {
		t.Errorf("message should say nothing was created, got %q", resp.Message)
	}
}

func TestBulkAddAbortsWhenConfigUnreadable(t *testing.T) {
	env := setupTestEnv(t)

	if err := os.Remove(env.configFile); err != nil {
		t.Fatalf("removing config file: %v", err)
	}

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: bulkNames(3)})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500 (body %s)", recorder.Code, recorder.Body.String())
	}

	resp := decodeBulkResponse(t, recorder)
	if resp.Data.Created != 0 {
		t.Errorf("got created=%d, want 0", resp.Data.Created)
	}
	// Systemic failure: every name must be reported, none silently dropped
	if len(resp.Data.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(resp.Data.Results))
	}
	for _, result := range resp.Data.Results {
		if result.Success {
			t.Errorf("%s reported success with an unreadable config", result.Name)
		}
	}
}

func TestBulkAddRetryAppliesPreviouslyUnappliedPeers(t *testing.T) {
	env := setupTestEnv(t)

	// First batch: peers get written but the apply fails
	syncFail := filepath.Join(env.dir, "sync_fail")
	if err := os.WriteFile(syncFail, nil, 0600); err != nil {
		t.Fatalf("creating sync_fail flag: %v", err)
	}
	if code := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: bulkNames(2)}).Code; code != http.StatusInternalServerError {
		t.Fatalf("expected first batch to fail apply, got status %d", code)
	}

	// Retry with the same names: everything already exists, created=0, but
	// the sync must still run so the previously written peers get applied
	if err := os.Remove(syncFail); err != nil {
		t.Fatalf("removing sync_fail flag: %v", err)
	}
	before := env.syncconfCalls(t)

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: bulkNames(2)})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("retry with all-existing names: got status %d, want 500 (created=0)", recorder.Code)
	}
	if env.syncconfCalls(t) != before+1 {
		t.Error("retry must run syncconf to self-heal peers a failed batch left unapplied")
	}
}

func TestSingleAddConcurrentSameName(t *testing.T) {
	env := setupTestEnv(t)

	const attempts = 4
	codes := make(chan int, attempts)
	var wg sync.WaitGroup

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "contended"}).Code
		}()
	}
	wg.Wait()
	close(codes)

	okCount, conflictCount := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Errorf("unexpected status %d for concurrent same-name add", code)
		}
	}
	if okCount != 1 || conflictCount != attempts-1 {
		t.Errorf("got %d OK / %d conflict, want exactly 1 OK / %d conflict", okCount, conflictCount, attempts-1)
	}

	if got := strings.Count(env.configContent(t), "### Client contended"); got != 1 {
		t.Errorf("config has %d peer entries for the contended name, want 1", got)
	}
}

func TestClientExistsMatchesConfigEntryWithoutClientFile(t *testing.T) {
	env := setupTestEnv(t)

	// Peer present in the server config but its client file is gone
	// (out-of-band cleanup) — the name must still count as taken
	appendToFile(t, env.configFile, "\n### Client ghost\n[Peer]\nPublicKey = x\nAllowedIPs = 10.66.0.9/32\n")

	exists, err := clientExists("ghost")
	if err != nil {
		t.Fatalf("clientExists: %v", err)
	}
	if !exists {
		t.Error("peer in server config without a client file must count as existing")
	}

	// A name that is a suffix of an existing one must NOT match
	exists, err = clientExists("host")
	if err != nil {
		t.Fatalf("clientExists: %v", err)
	}
	if exists {
		t.Error("suffix of an existing name must not count as existing")
	}
}

func TestSingleAddCleansUpClientFileWhenConfigAppendFails(t *testing.T) {
	env := setupTestEnv(t)

	// Make the server config unappendable AFTER validation reads it: read
	// works (0400) but O_WRONLY open for the peer append fails
	if err := os.Chmod(env.configFile, 0400); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	t.Cleanup(func() { os.Chmod(env.configFile, 0600) })

	recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "orphan"})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500", recorder.Code)
	}

	// The half-written client file must be removed, otherwise the name is
	// permanently blocked even though no peer exists
	if _, err := os.Stat(filepath.Join(env.clientsDir, "wg0-client-orphan.conf")); !os.IsNotExist(err) {
		t.Error("client file left behind after failed config append")
	}

	// And the name must be addable again once the config is writable
	if err := os.Chmod(env.configFile, 0600); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	if code := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "orphan"}).Code; code != http.StatusOK {
		t.Errorf("retry after failed append: got status %d, want 200", code)
	}
}

func TestConcurrentAddsAllocateUniqueIPs(t *testing.T) {
	env := setupTestEnv(t)

	const singles = 10
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		recorder := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", AddUsersBulkRequest{Names: bulkNames(30)})
		if recorder.Code != http.StatusOK {
			t.Errorf("bulk add failed with status %d", recorder.Code)
		}
	}()

	for i := 0; i < singles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recorder := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: fmt.Sprintf("single%d", i)})
			if recorder.Code != http.StatusOK {
				t.Errorf("single add %d failed with status %d", i, recorder.Code)
			}
		}(i)
	}

	wg.Wait()

	allowedIPs := regexp.MustCompile(`AllowedIPs = (10\.66\.\d+\.\d+)/32`).FindAllStringSubmatch(env.configContent(t), -1)
	if len(allowedIPs) != 30+singles {
		t.Fatalf("got %d peers in config, want %d", len(allowedIPs), 30+singles)
	}

	seen := make(map[string]bool)
	for _, match := range allowedIPs {
		if seen[match[1]] {
			t.Fatalf("duplicate ip %s allocated under concurrency", match[1])
		}
		seen[match[1]] = true
	}
}

func TestGetNextAvailableIPv4FillsGaps(t *testing.T) {
	env := setupTestEnv(t)

	extra := `
### Client a
[Peer]
AllowedIPs = 10.66.0.2/32

### Client b
[Peer]
AllowedIPs = 10.66.0.4/32
`
	appendToFile(t, env.configFile, extra)

	ip, err := getNextAvailableIPv4()
	if err != nil {
		t.Fatalf("getNextAvailableIPv4: %v", err)
	}
	if ip != "10.66.0.3" {
		t.Errorf("got %s, want 10.66.0.3 (lowest gap)", ip)
	}
}

func TestAllocateClientIPsRespectsProvidedValues(t *testing.T) {
	setupTestEnv(t)

	ipv4, ipv6, err := allocateClientIPsLocked("10.66.9.9", "")
	if err != nil {
		t.Fatalf("allocateClientIPsLocked: %v", err)
	}
	if ipv4 != "10.66.9.9" {
		t.Errorf("provided ipv4 must be kept, got %s", ipv4)
	}
	if ipv6 != "" {
		t.Errorf("ipv6 disabled on server, got %q", ipv6)
	}
}

func TestAllocateClientIPv6(t *testing.T) {
	env := setupTestEnv(t)
	wgParams.ServerWGIPv6 = "fd42:42:42::1"

	extra := "\n### Client v6\n[Peer]\nAllowedIPs = 10.66.0.2/32,fd42:42:42::2/128\n"
	appendToFile(t, env.configFile, extra)

	_, ipv6, err := allocateClientIPsLocked("10.66.0.3", "")
	if err != nil {
		t.Fatalf("allocateClientIPsLocked: %v", err)
	}
	if ipv6 != "fd42:42:42::3" {
		t.Errorf("got ipv6 %s, want fd42:42:42::3 (::1 server, ::2 taken)", ipv6)
	}
}

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
		"empty":      "",
		"not base64": "!!!!not-base64!!!!",
		"too short":  "c2hvcnRrZXk=",
		"all zero":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
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
