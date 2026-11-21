package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setSparePool(t *testing.T, n int) {
	t.Helper()
	old := SPARE_POOL
	SPARE_POOL = n
	t.Cleanup(func() { SPARE_POOL = old })
}

func (e *testEnv) addUser(t *testing.T, name string) {
	t.Helper()
	rec := e.authedRequest(t, http.MethodPost, "/api/users/add", AddUserRequest{Name: name})
	if rec.Code != http.StatusOK {
		t.Fatalf("adding %s: status %d, body %s", name, rec.Code, rec.Body.String())
	}
}

func (e *testEnv) spareFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(e.clientsDir, "spare"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading spare dir: %v", err)
	}
	var names []string
	for _, f := range entries {
		names = append(names, f.Name())
	}
	return names
}

func TestSparePoolZeroChangesNothing(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 0)

	env.addUser(t, "alice")

	conf := env.configContent(t)
	if strings.Contains(conf, "### Spare") {
		t.Fatalf("spare block with SPARE_POOL=0:\n%s", conf)
	}
	if _, err := os.Stat(filepath.Join(env.clientsDir, "spare")); !os.IsNotExist(err) {
		t.Fatalf("spare dir exists with SPARE_POOL=0 (err=%v)", err)
	}
	if !strings.Contains(conf, "### Client alice") {
		t.Fatalf("client block missing:\n%s", conf)
	}
}

func TestTopUpWithPoolZeroDoesNotWriteConf(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 0)
	before, _ := os.Stat(env.configFile)

	created, trimmed, err := topUpSparesLocked()
	if err != nil || created != 0 || trimmed != 0 {
		t.Fatalf("got %d, %d, %v", created, trimmed, err)
	}
	after, _ := os.Stat(env.configFile)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("conf was rewritten")
	}
}

func TestTopUpFillsToTargetInOneApply(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 5)

	env.addUser(t, "alice")

	conf := env.configContent(t)
	if got := strings.Count(conf, "### Spare sp"); got != 5 {
		t.Fatalf("got %d spare blocks, want 5:\n%s", got, conf)
	}
	files := env.spareFiles(t)
	if len(files) != 5 {
		t.Fatalf("got %d spare files, want 5: %v", len(files), files)
	}
	for _, name := range files {
		if !strings.HasPrefix(name, "wg0-client-sp") {
			t.Errorf("unexpected spare file name %q", name)
		}
	}
	if calls := env.syncconfCalls(t); calls != 1 {
		t.Fatalf("got %d syncconf calls, want 1", calls)
	}
	for _, sp := range spareBlocksLocked([]byte(conf)) {
		if len(sp.Name) != 14 || sp.PublicKey == "" {
			t.Errorf("bad spare %+v", sp)
		}
	}
}

func TestTopUpCapsAt500PerApply(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 600)

	env.addUser(t, "alice")
	if got := strings.Count(env.configContent(t), "### Spare "); got != 500 {
		t.Fatalf("got %d spares after first apply, want 500", got)
	}
	env.addUser(t, "bob")
	if got := strings.Count(env.configContent(t), "### Spare "); got != 600 {
		t.Fatalf("got %d spares after second apply, want 600", got)
	}
}

func TestTopUpTrimsWhenTargetLowered(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 5)
	env.addUser(t, "alice")
	first := spareBlocksLocked([]byte(env.configContent(t)))

	setSparePool(t, 2)
	env.addUser(t, "bob")

	conf := env.configContent(t)
	left := spareBlocksLocked([]byte(conf))
	if len(left) != 2 {
		t.Fatalf("got %d spare blocks, want 2:\n%s", len(left), conf)
	}
	// Trimming takes from the end: the first two survive.
	if left[0] != first[0] || left[1] != first[1] {
		t.Fatalf("wrong spares kept: %v vs %v", left, first)
	}
	if got := len(env.spareFiles(t)); got != 2 {
		t.Fatalf("got %d spare files, want 2", got)
	}
	if !strings.Contains(conf, "### Client alice") || !strings.Contains(conf, "### Client bob") {
		t.Fatalf("clients lost:\n%s", conf)
	}
}

func TestSparesHiddenFromListUsers(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	env.addUser(t, "alice")

	rec := env.authedRequest(t, http.MethodGet, "/api/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sp") && strings.Contains(rec.Body.String(), "client-sp") {
		t.Fatalf("spare listed: %s", rec.Body.String())
	}
	var resp struct {
		Data []Client `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "alice" {
		t.Fatalf("want only alice, got %s", rec.Body.String())
	}
}

func TestSparesExcludedFromStatsPeers(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 5)
	env.addUser(t, "alice")
	env.addUser(t, "bob")

	// Point the counters at a fixture so the handler reaches the peer count.
	sys := filepath.Join(env.dir, "sys")
	stats := filepath.Join(sys, "wg0", "statistics")
	if err := os.MkdirAll(stats, 0700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"rx_bytes", "tx_bytes"} {
		if err := os.WriteFile(filepath.Join(stats, c), []byte("10\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldSys := sysClassNetDir
	sysClassNetDir = sys
	t.Cleanup(func() { sysClassNetDir = oldSys })

	keys := "k1\nk2\nk3\nk4\nk5\nk6\nk7\n"
	if err := os.WriteFile(filepath.Join(env.dir, "show_output"), []byte(keys), 0600); err != nil {
		t.Fatal(err)
	}

	rec := env.authedRequest(t, http.MethodGet, "/api/stats", nil)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Peers int `json:"peers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.Success {
		t.Fatalf("bad response %s (%v)", rec.Body.String(), err)
	}
	if resp.Data.Peers != 2 {
		t.Fatalf("peers = %d, want 2", resp.Data.Peers)
	}
}

func TestSparesExcludedFromStatus(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 2)
	env.addUser(t, "alice")

	blocks := spareBlocksLocked([]byte(env.configContent(t)))
	var aliceKey string
	conf := env.configContent(t)
	i := strings.Index(conf, "### Client alice")
	for _, line := range strings.Split(conf[i:], "\n") {
		if strings.HasPrefix(line, "PublicKey = ") {
			aliceKey = strings.TrimPrefix(line, "PublicKey = ")
			break
		}
	}
	dump := "serverpriv\tserverpub\t51820\toff\n" +
		blocks[0].PublicKey + "\t(none)\t(none)\t10.66.0.9/32\t0\t0\t0\toff\n" +
		aliceKey + "\t(none)\t(none)\t10.66.0.2/32\t0\t0\t0\toff\n"
	if err := os.WriteFile(filepath.Join(env.dir, "show_output"), []byte(dump), 0600); err != nil {
		t.Fatal(err)
	}

	rec := env.authedRequest(t, http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Peers []struct {
				PublicKey  string `json:"public_key"`
				ClientName string `json:"client_name"`
			} `json:"peers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(resp.Data.Peers) != 1 || resp.Data.Peers[0].PublicKey != aliceKey || resp.Data.Peers[0].ClientName != "alice" {
		t.Fatalf("want only alice in peers, got %+v", resp.Data.Peers)
	}
}

func TestHealthReportsSpareCountAndTarget(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 5)
	env.addUser(t, "alice")
	calls := env.syncconfCalls(t)

	rec := env.authedRequest(t, http.MethodGet, "/api/health", nil)
	var resp struct {
		Data struct {
			SpareCount  int `json:"spare_count"`
			SpareTarget int `json:"spare_target"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Data.SpareCount != 5 || resp.Data.SpareTarget != 5 {
		t.Fatalf("got %+v: %s", resp.Data, rec.Body.String())
	}
	if env.syncconfCalls(t) != calls {
		t.Fatal("health must not apply the config")
	}
}

func TestDeleteAllKeepsSpares(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	env.addUser(t, "alice")
	env.addUser(t, "bob")
	before := spareBlocksLocked([]byte(env.configContent(t)))
	if len(before) != 3 {
		t.Fatalf("setup: %d spares", len(before))
	}

	rec := env.authedRequest(t, http.MethodPost, "/api/users/delete-all", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	conf := env.configContent(t)
	if strings.Contains(conf, "### Client") {
		t.Fatalf("client left:\n%s", conf)
	}
	after := spareBlocksLocked([]byte(conf))
	if len(after) != 3 {
		t.Fatalf("got %d spare blocks, want 3:\n%s", len(after), conf)
	}
	for i := range after {
		if after[i] != before[i] {
			t.Fatalf("spare %d changed", i)
		}
	}
	if got := len(env.spareFiles(t)); got != 3 {
		t.Fatalf("got %d spare files, want 3", got)
	}
	if !strings.Contains(conf, "PrivateKey = server-private-key") {
		t.Fatalf("server section lost:\n%s", conf)
	}
}

func TestDeleteAllKeepsSparesPlacedBeforeClients(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 2)
	env.addUser(t, "alice")
	// Delete alice, then add bob: bob's block lands after the spares.
	if rec := env.authedRequest(t, http.MethodPost, "/api/users/delete", DeleteUserRequest{Name: "alice"}); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	env.addUser(t, "bob")
	conf := env.configContent(t)
	if strings.Index(conf, "### Spare ") > strings.Index(conf, "### Client bob") {
		t.Fatalf("expected spares before bob:\n%s", conf)
	}

	if rec := env.authedRequest(t, http.MethodPost, "/api/users/delete-all", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete-all: %d %s", rec.Code, rec.Body.String())
	}
	conf = env.configContent(t)
	if strings.Count(conf, "### Spare ") != 2 || strings.Contains(conf, "### Client") {
		t.Fatalf("unexpected conf:\n%s", conf)
	}
}

func TestRemoveAllClientsWithoutSparesUnchanged(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 0)
	env.addUser(t, "alice")
	env.addUser(t, "bob")
	original := "[Interface]\nAddress = 10.66.0.1/16\nListenPort = 51820\nPrivateKey = server-private-key\n"

	if err := removeAllClientsFromConfig(); err != nil {
		t.Fatal(err)
	}
	got := env.configContent(t)
	// Previous behaviour: everything before the first client marker.
	if got != original+"\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSyncDeletedClientsIgnoresSpares(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	env.addUser(t, "alice")
	before := env.configContent(t)

	rec := env.authedRequest(t, http.MethodGet, "/api/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if err := syncDeletedClientsWithConfig(); err != nil {
		t.Fatal(err)
	}
	if after := env.configContent(t); after != before {
		t.Fatalf("conf changed:\n%s\n---\n%s", before, after)
	}
}

func TestApplyRecordsLastApplyResult(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 0)

	wgConfigMutex.Lock()
	err := applyConfigLocked()
	ok1, at1 := lastApplyOK, lastApplyAt
	wgConfigMutex.Unlock()
	if err != nil || !ok1 || at1.IsZero() {
		t.Fatalf("after success: err=%v ok=%v at=%v", err, ok1, at1)
	}

	if err := os.WriteFile(filepath.Join(env.dir, "sync_fail"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	wgConfigMutex.Lock()
	err = applyConfigLocked()
	ok2 := lastApplyOK
	wgConfigMutex.Unlock()
	if err == nil || ok2 {
		t.Fatalf("after failure: err=%v ok=%v", err, ok2)
	}
}

func TestParseSparePool(t *testing.T) {
	for raw, want := range map[string]int{"": 0, "0": 0, "7": 7, " 12 ": 12, "-3": 0, "abc": 0, "1.5": 0} {
		if got := parseSparePool(raw); got != want {
			t.Errorf("parseSparePool(%q) = %d, want %d", raw, got, want)
		}
	}
}
