package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type claimResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Claimed  int           `json:"claimed"`
		Created  int           `json:"created"`
		Existing int           `json:"existing"`
		Failed   int           `json:"failed"`
		Results  []ClaimResult `json:"results"`
	} `json:"data"`
}

func (e *testEnv) claim(t *testing.T, names ...string) (int, claimResp) {
	t.Helper()
	rec := e.authedRequest(t, http.MethodPost, "/api/users/claim", AddUsersBulkRequest{Names: names})
	var resp claimResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad claim response %q: %v", rec.Body.String(), err)
	}
	return rec.Code, resp
}

// peerKeyLines returns the PublicKey lines of a config, in order.
func peerKeyLines(conf string) []string {
	var out []string
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "PublicKey = ") {
			out = append(out, l)
		}
	}
	return out
}

func TestClaimServesFromStockWithoutSyncconf(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 5)
	env.addUser(t, "seed")

	before := env.configContent(t)
	spares := spareBlocksLocked([]byte(before))
	if len(spares) != 5 {
		t.Fatalf("got %d spares, want 5", len(spares))
	}
	keysBefore := peerKeyLines(before)
	calls := env.syncconfCalls(t)

	code, resp := env.claim(t, "a1", "a2", "a3")
	if code != http.StatusOK || !resp.Success {
		t.Fatalf("status %d, resp %+v", code, resp)
	}
	if resp.Data.Claimed != 3 || resp.Data.Created != 0 || resp.Data.Existing != 0 || resp.Data.Failed != 0 || len(resp.Data.Results) != 3 {
		t.Fatalf("bad counts: %+v", resp.Data)
	}
	for _, r := range resp.Data.Results {
		if r.Status != "claimed" || !r.Success || r.Config == "" || r.IPV4 == "" {
			t.Errorf("bad result %+v", r)
		}
		if !strings.Contains(r.Config, "PrivateKey = ") {
			t.Errorf("config of %s has no private key", r.Name)
		}
	}
	if got := env.syncconfCalls(t); got != calls {
		t.Fatalf("claim from stock ran syncconf: %d -> %d", calls, got)
	}

	after := env.configContent(t)
	for _, n := range []string{"a1", "a2", "a3"} {
		if !strings.Contains(after, "### Client "+n+"\n") {
			t.Errorf("conf lacks client %s", n)
		}
		path := filepath.Join(env.clientsDir, "wg0-client-"+n+".conf")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("client file %s: %v", n, err)
		}
	}
	if got := strings.Count(after, "### Spare "); got != 2 {
		t.Fatalf("got %d spares left, want 2", got)
	}
	if got := len(env.spareFiles(t)); got != 2 {
		t.Fatalf("got %d spare files left, want 2", got)
	}
	// The first three spares became a1..a3 in order; keys and addresses stay.
	if strings.Join(peerKeyLines(after), "|") != strings.Join(keysBefore, "|") {
		t.Fatalf("PublicKey lines changed")
	}
	for i, r := range resp.Data.Results {
		want := fmt.Sprintf("### Client %s\n[Peer]\nPublicKey = %s\n", r.Name, spares[i].PublicKey)
		if !strings.Contains(after, want) {
			t.Errorf("block of %s is not the former spare %s", r.Name, spares[i].Name)
		}
		if !strings.Contains(after, "AllowedIPs = "+r.IPV4+"/32") {
			t.Errorf("ipv4 %s of %s not in conf", r.IPV4, r.Name)
		}
	}
}

func TestClaimRetryReturnsExisting(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	env.addUser(t, "seed")

	_, first := env.claim(t, "a1")
	code, second := env.claim(t, "a1")
	if code != http.StatusOK || second.Data.Existing != 1 || second.Data.Claimed != 0 {
		t.Fatalf("status %d, %+v", code, second.Data)
	}
	r := second.Data.Results[0]
	if r.Status != "existing" || !r.Success || r.Config == "" || r.Config != first.Data.Results[0].Config {
		t.Fatalf("bad retry result %+v", r)
	}
	if got := strings.Count(env.configContent(t), "### Spare "); got != 2 {
		t.Fatalf("retry consumed a spare: %d left", got)
	}
}

func TestClaimFallsBackToCreateWhenStockEmpty(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 2)
	env.addUser(t, "seed")
	calls := env.syncconfCalls(t)

	code, resp := env.claim(t, "b1", "b2", "b3", "b4")
	if code != http.StatusOK || !resp.Success {
		t.Fatalf("status %d, %+v", code, resp)
	}
	if resp.Data.Claimed != 2 || resp.Data.Created != 2 || resp.Data.Failed != 0 {
		t.Fatalf("bad counts: %+v", resp.Data)
	}
	for i, want := range []string{"claimed", "claimed", "created", "created"} {
		r := resp.Data.Results[i]
		if r.Status != want || !r.Success || r.Config == "" || r.IPV4 == "" {
			t.Errorf("result %d: %+v, want status %s", i, r, want)
		}
	}
	if got := env.syncconfCalls(t); got != calls+1 {
		t.Fatalf("got %d syncconf calls, want exactly 1", got-calls)
	}
	conf := env.configContent(t)
	if got := strings.Count(conf, "### Spare "); got != 2 {
		t.Fatalf("stock not refilled in the same apply: %d spares", got)
	}
	for _, n := range []string{"b1", "b2", "b3", "b4"} {
		if got := strings.Count(conf, "### Client "+n+"\n"); got != 1 {
			t.Errorf("client %s appears %d times", n, got)
		}
	}
	// No address handed out twice.
	seen := map[string]bool{}
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "AllowedIPs = ") {
			if seen[l] {
				t.Errorf("duplicate %s", l)
			}
			seen[l] = true
		}
	}
}

func TestClaimAppliesFirstWhenLastApplyFailed(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	syncFail := filepath.Join(env.dir, "sync_fail")

	// A failed apply leaves spares in the file that are not in the kernel.
	if err := os.WriteFile(syncFail, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if rec := env.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: "seed"}); rec.Code != http.StatusInternalServerError {
		t.Fatalf("add with failing apply: status %d", rec.Code)
	}
	if got := strings.Count(env.configContent(t), "### Spare "); got != 3 {
		t.Fatalf("got %d spares, want 3", got)
	}

	// Still failing: refuse, and hand nothing out.
	conf := env.configContent(t)
	code, _ := env.claim(t, "a1")
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", code)
	}
	after := env.configContent(t)
	if strings.Contains(after, "### Client a1") {
		t.Fatalf("a1 was relabelled although the apply failed")
	}
	if after != conf {
		t.Fatalf("conf changed by a refused claim")
	}
	if _, err := os.Stat(filepath.Join(env.clientsDir, "wg0-client-a1.conf")); err == nil {
		t.Fatalf("client file written by a refused claim")
	}

	// Healthy again: one syncconf before serving.
	if err := os.Remove(syncFail); err != nil {
		t.Fatal(err)
	}
	calls := env.syncconfCalls(t)
	code, resp := env.claim(t, "a1")
	if code != http.StatusOK || resp.Data.Claimed != 1 || resp.Data.Results[0].Status != "claimed" {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if got := env.syncconfCalls(t); got != calls+1 {
		t.Fatalf("got %d syncconf calls before serving, want 1", got-calls)
	}
}

func TestClaimLeftoverApplyFailure(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 1)
	env.addUser(t, "seed")
	if err := os.WriteFile(filepath.Join(env.dir, "sync_fail"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	// One name from stock, one leftover whose apply fails: 200, leftover failed.
	code, resp := env.claim(t, "c1", "c2")
	if code != http.StatusOK || resp.Data.Claimed != 1 || resp.Data.Failed != 1 || resp.Data.Created != 0 {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if r := resp.Data.Results[1]; r.Success || r.Status != "error" {
		t.Fatalf("leftover result %+v", r)
	}

	// Nothing served from stock and the leftovers' apply fails: 500.
	code, _ = env.claim(t, "c3")
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", code)
	}
}

func TestClaimValidation(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	env.addUser(t, "seed")
	before := env.configContent(t)
	calls := env.syncconfCalls(t)

	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	cases := map[string][]string{
		"empty":     {},
		"too many":  many,
		"bad name":  {"ok", "bad name!"},
		"duplicate": {"x", "y", "x"},
	}
	for label, names := range cases {
		code, _ := env.claim(t, names...)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", label, code)
		}
	}
	if env.configContent(t) != before {
		t.Fatalf("conf changed by rejected requests")
	}
	if env.syncconfCalls(t) != calls {
		t.Fatalf("syncconf ran for rejected requests")
	}
}

func TestClaimLeftoverApplyFailsAndNothingSucceededAnswers500(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 0)
	env.addUser(t, "seed") // successful apply: lastApplyOK is true
	if err := os.WriteFile(filepath.Join(env.dir, "sync_fail"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	code, resp := env.claim(t, "d1")
	if code != http.StatusInternalServerError || resp.Success {
		t.Fatalf("status %d, %+v", code, resp)
	}
	if resp.Data.Failed != 1 || resp.Data.Created != 0 || resp.Data.Claimed != 0 {
		t.Fatalf("bad counts: %+v", resp.Data)
	}
	if strings.Contains(resp.Message, "before claiming") || !strings.Contains(resp.Message, "created 1 clients but failed to apply config") {
		t.Fatalf("wrong 500 reason: %q", resp.Message)
	}
	if r := resp.Data.Results[0]; r.Success || r.Status != "error" {
		t.Fatalf("result %+v", r)
	}
}

func TestClaimedConfigUsesCurrentSettings(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 2)
	env.addUser(t, "seed")

	before := env.configContent(t)
	spare := spareBlocksLocked([]byte(before))[0]
	calls := env.syncconfCalls(t)

	oldPort := wgParams.ServerPort
	wgParams.ServerPort = "60999"
	t.Cleanup(func() { wgParams.ServerPort = oldPort })

	code, resp := env.claim(t, "f1")
	if code != http.StatusOK || resp.Data.Claimed != 1 {
		t.Fatalf("status %d, %+v", code, resp)
	}
	r := resp.Data.Results[0]
	file, err := os.ReadFile(filepath.Join(env.clientsDir, "wg0-client-f1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for label, text := range map[string]string{"response": r.Config, "file": string(file)} {
		if !strings.Contains(text, ":60999\n") || strings.Contains(text, ":"+oldPort+"\n") {
			t.Errorf("%s config has a stale endpoint:\n%s", label, text)
		}
		if !strings.Contains(text, "Address = "+r.IPV4+"/32") {
			t.Errorf("%s config lost the spare address", label)
		}
	}
	if r.Config != string(file) {
		t.Errorf("response and client file differ")
	}

	after := env.configContent(t)
	want := fmt.Sprintf("### Client f1\n[Peer]\nPublicKey = %s\n", spare.PublicKey)
	if !strings.Contains(after, want) {
		t.Fatalf("peer block of f1 is not the former spare")
	}
	if strings.Join(peerKeyLines(after), "|") != strings.Join(peerKeyLines(before), "|") ||
		strings.Count(after, "PresharedKey = ") != strings.Count(before, "PresharedKey = ") ||
		strings.Count(after, "AllowedIPs = ") != strings.Count(before, "AllowedIPs = ") {
		t.Fatalf("peer key material or addresses changed")
	}
	for _, l := range strings.Split(before, "\n") {
		if (strings.HasPrefix(l, "PresharedKey = ") || strings.HasPrefix(l, "AllowedIPs = ")) && !strings.Contains(after, l+"\n") {
			t.Errorf("line %q vanished from the conf", l)
		}
	}
	if got := env.syncconfCalls(t); got != calls {
		t.Fatalf("claim ran syncconf")
	}
}
