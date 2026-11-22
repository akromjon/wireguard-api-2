package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func setSparePoolAuto(t *testing.T) {
	t.Helper()
	oldN, oldA := SPARE_POOL, sparePoolAuto
	SPARE_POOL, sparePoolAuto = 0, true
	t.Cleanup(func() { SPARE_POOL, sparePoolAuto = oldN, oldA })
}

func (e *testEnv) healthSpares(t *testing.T) (count, target int) {
	t.Helper()
	rec := e.authedRequest(t, http.MethodGet, "/api/health", nil)
	var resp struct {
		Data struct {
			SpareCount  int `json:"spare_count"`
			SpareTarget int `json:"spare_target"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding health: %v (%s)", err, rec.Body.String())
	}
	return resp.Data.SpareCount, resp.Data.SpareTarget
}

func TestParseSparePoolSetting(t *testing.T) {
	cases := map[string]struct {
		n    int
		auto bool
	}{
		"auto": {0, true}, "AUTO": {0, true}, " auto ": {0, true},
		"500": {500, false}, "": {0, false}, "x": {0, false}, "-1": {0, false},
	}
	for raw, want := range cases {
		n, auto := parseSparePoolSetting(raw)
		if n != want.n || auto != want.auto {
			t.Errorf("parseSparePoolSetting(%q) = (%d, %v), want (%d, %v)", raw, n, auto, want.n, want.auto)
		}
	}
}

func TestAutoStockFollowsClientCount(t *testing.T) {
	env := setupTestEnv(t)
	setSparePoolAuto(t)

	for _, n := range []string{"a1", "a2", "a3"} {
		env.addUser(t, n)
	}
	if c, tg := env.healthSpares(t); c != 3 || tg != 3 {
		t.Fatalf("after 3 clients: spares %d target %d, want 3/3", c, tg)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", map[string]any{"names": []string{"b1", "b2"}}); w.Code != http.StatusOK {
		t.Fatalf("add-bulk: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 5 || tg != 5 {
		t.Fatalf("after 5 clients: spares %d target %d, want 5/5", c, tg)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/delete", map[string]any{"name": "a1"}); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 4 || tg != 4 {
		t.Fatalf("after deleting one client: spares %d target %d, want 4/4", c, tg)
	}
}

func TestReconcileAutoFillsToClientCount(t *testing.T) {
	env := setupTestEnv(t)
	resetReconcileState(t)
	conf := "[Interface]\nAddress = 10.66.0.1/16\nListenPort = 51820\nPrivateKey = server-private-key\n" +
		"\n### Client c1\n[Peer]\nPublicKey = p1\nAllowedIPs = 10.66.0.2/32\n" +
		"\n### Client c2\n[Peer]\nPublicKey = p2\nAllowedIPs = 10.66.0.3/32\n"
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	setSparePoolAuto(t)

	ran, err := reconcileSpares(time.Now(), true)
	if err != nil || !ran {
		t.Fatalf("reconcile: ran=%v err=%v", ran, err)
	}
	if c, tg := env.healthSpares(t); c != 2 || tg != 2 {
		t.Fatalf("after reconcile: spares %d target %d, want 2/2", c, tg)
	}
	ran, err = reconcileSpares(time.Now(), true)
	if err != nil || ran {
		t.Fatalf("second reconcile must be a no-op: ran=%v err=%v", ran, err)
	}
}

func TestAutoStockClaimRaisesTargetAndBulkDeleteRefills(t *testing.T) {
	env := setupTestEnv(t)
	setSparePoolAuto(t)
	for _, n := range []string{"a1", "a2", "a3"} {
		env.addUser(t, n)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/claim", map[string]any{"names": []string{"n1", "n2"}}); w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 1 || tg != 5 {
		t.Fatalf("after claiming 2: spares %d target %d, want 1/5", c, tg)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/delete-bulk", map[string]any{"names": []string{"a1", "a2"}}); w.Code != http.StatusOK {
		t.Fatalf("delete-bulk: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 3 || tg != 3 {
		t.Fatalf("after burning the 2 old clients: spares %d target %d, want 3/3", c, tg)
	}
}

// With no clients there is nothing to back up: delete-all empties the stock and
// re-adding clients grows it back in the same applies.
func TestAutoStockDeleteAllThenRegrow(t *testing.T) {
	env := setupTestEnv(t)
	setSparePoolAuto(t)
	for _, n := range []string{"a1", "a2", "a3"} {
		env.addUser(t, n)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/delete-all", nil); w.Code != http.StatusOK {
		t.Fatalf("delete-all: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 0 || tg != 0 {
		t.Fatalf("after delete-all: spares %d target %d, want 0/0", c, tg)
	}

	if w := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", map[string]any{"names": []string{"r1", "r2"}}); w.Code != http.StatusOK {
		t.Fatalf("add-bulk: %d %s", w.Code, w.Body.String())
	}
	if c, tg := env.healthSpares(t); c != 2 || tg != 2 {
		t.Fatalf("after re-adding 2: spares %d target %d, want 2/2", c, tg)
	}
}
