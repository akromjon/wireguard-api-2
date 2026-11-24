package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type dumpPeer struct {
	key, allowed string
	rx, tx       uint64
}

func dumpText(peers ...dumpPeer) string {
	var b strings.Builder
	b.WriteString("srvpriv\tsrvpub\t51820\toff\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "%s\t(none)\t203.0.113.7:4000\t%s\t1700000000\t%d\t%d\toff\n", p.key, p.allowed, p.rx, p.tx)
	}
	return b.String()
}

func setupUsage(t *testing.T) *testEnv {
	t.Helper()
	env := setupTestEnv(t)
	oldURL, oldState := USAGE_PUSH_URL, USAGE_STATE_FILE
	USAGE_PUSH_URL = "https://master.example/node-usage"
	USAGE_STATE_FILE = filepath.Join(env.dir, "state.json")
	resetUsageMemory()
	t.Cleanup(func() {
		USAGE_PUSH_URL, USAGE_STATE_FILE = oldURL, oldState
		resetUsageMemory()
	})
	return env
}

func resetUsageMemory() {
	usageMu.Lock()
	defer usageMu.Unlock()
	usageSt = newUsageState()
	usageLoaded = false
	lastPeers = nil
}

func (e *testEnv) setDump(t *testing.T, peers ...dumpPeer) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "show_output"), []byte(dumpText(peers...)), 0600); err != nil {
		t.Fatal(err)
	}
}

func mustCollect(t *testing.T) {
	t.Helper()
	if err := collectUsage(); err != nil {
		t.Fatalf("collectUsage: %v", err)
	}
}

func snapshot() usageState {
	usageMu.Lock()
	defer usageMu.Unlock()
	return usageSt
}

func TestFirstCollectWithoutStatePrimesBaseline(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	st := snapshot()
	if len(st.Open) != 0 {
		t.Fatalf("Open = %v, want empty", st.Open)
	}
	if st.Last["pubA"] != (peerCounter{5000, 9000}) || !st.Primed {
		t.Fatalf("state = %+v", st)
	}
}

func TestDeltaSinceLastCollect(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6500, 9100})
	mustCollect(t)
	got := snapshot().Open["pubA"]
	want := usageEntry{PublicKey: "pubA", AllowedIP: "10.66.0.61", RX: 1500, TX: 100}
	if got != want {
		t.Fatalf("Open[pubA] = %+v, want %+v", got, want)
	}
}

func TestDeltaAccumulatesAcrossCollects(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 100, 100})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 200, 150})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 260, 150})
	mustCollect(t)
	got := snapshot().Open["pubA"]
	if got.RX != 160 || got.TX != 50 {
		t.Fatalf("Open[pubA] = %+v, want rx 160 tx 50", got)
	}
}

func TestCounterDropCountsNewValue(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 300, 40})
	mustCollect(t)
	got := snapshot().Open["pubA"]
	if got.RX != 300 || got.TX != 40 {
		t.Fatalf("Open[pubA] = %+v", got)
	}
}

func TestNewPeerAfterPrimeCountsFullCounter(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t,
		dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000},
		dumpPeer{"pubB", "10.66.0.62/32", 700, 800})
	mustCollect(t)
	st := snapshot()
	if got := st.Open["pubB"]; got.RX != 700 || got.TX != 800 {
		t.Fatalf("Open[pubB] = %+v", got)
	}
	if _, ok := st.Open["pubA"]; ok {
		t.Fatalf("pubA should have no delta")
	}
}

func TestRemovedPeerDroppedFromLast(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t,
		dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000},
		dumpPeer{"pubB", "10.66.0.62/32", 100, 100})
	mustCollect(t)
	env.setDump(t,
		dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000},
		dumpPeer{"pubB", "10.66.0.62/32", 400, 100})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	st := snapshot()
	if _, ok := st.Last["pubB"]; ok {
		t.Fatalf("pubB still in Last")
	}
	if got := st.Open["pubB"]; got.RX != 300 {
		t.Fatalf("Open[pubB] = %+v, earlier delta must stay", got)
	}
}

func TestZeroDeltaNotInOpen(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	mustCollect(t)
	if _, ok := snapshot().Open["pubA"]; ok {
		t.Fatalf("zero delta peer in Open")
	}
}

func TestAllowedIPTakesFirstIPv4(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "fd42:42:42::3d/128,10.66.0.61/32", 1, 1})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "fd42:42:42::3d/128,10.66.0.61/32", 2, 2})
	mustCollect(t)
	if got := snapshot().Open["pubA"].AllowedIP; got != "10.66.0.61" {
		t.Fatalf("AllowedIP = %q", got)
	}
}

func TestPeerWithoutIPv4NotSent(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "fd42:42:42::3d/128", 0, 0})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "fd42:42:42::3d/128", 500, 500})
	mustCollect(t)
	st := snapshot()
	if len(st.Open) != 0 {
		t.Fatalf("Open = %v", st.Open)
	}
	if _, ok := st.Last["pubA"]; !ok {
		t.Fatalf("peer without IPv4 must stay in Last")
	}
}

func TestParseDump(t *testing.T) {
	out := dumpText(
		dumpPeer{"pubA", "10.66.0.61/32,fd42:42:42::3d/128", 5, 6},
		dumpPeer{"pubB", "(none)", 7, 8})
	// dumpText already writes (none) for psk; allowed-ips "(none)" is the field under test.
	got := parseDump(out)
	if len(got) != 2 {
		t.Fatalf("got %d peers", len(got))
	}
	if strings.Join(got[0].AllowedIPs, "|") != "10.66.0.61|fd42:42:42::3d" || got[0].RX != 5 || got[0].TX != 6 {
		t.Fatalf("peer 0 = %+v", got[0])
	}
	if len(got[1].AllowedIPs) != 0 {
		t.Fatalf("peer 1 = %+v", got[1])
	}
}

func TestApplyCollectsBeforeSyncconf(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.addUser(t, "alice")
	env.addUser(t, "bob")
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6000, 9000})
	_ = os.Remove(filepath.Join(env.dir, "invocations.log"))

	rec := env.authedRequest(t, http.MethodPost, "/api/users/delete", DeleteUserRequest{Name: "alice"})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if got := snapshot().Open["pubA"].RX; got != 1000 {
		t.Fatalf("Open[pubA].RX = %d, want 1000", got)
	}
	log, _ := os.ReadFile(filepath.Join(env.dir, "invocations.log"))
	lines := strings.Fields(string(log))
	showAt, syncAt := -1, -1
	for i, l := range lines {
		if l == "show" && showAt < 0 {
			showAt = i
		}
		if l == "syncconf" && syncAt < 0 {
			syncAt = i
		}
	}
	if showAt < 0 || syncAt < 0 || showAt > syncAt {
		t.Fatalf("invocations = %v, want show before syncconf", lines)
	}
}

func TestDisabledMeterDoesNothing(t *testing.T) {
	env := setupUsage(t)
	USAGE_PUSH_URL = ""
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	if err := collectUsage(); err != nil {
		t.Fatalf("collectUsage: %v", err)
	}
	if _, err := os.Stat(USAGE_STATE_FILE); !os.IsNotExist(err) {
		t.Fatalf("state file exists (err=%v)", err)
	}
	if log, _ := os.ReadFile(filepath.Join(env.dir, "invocations.log")); strings.Contains(string(log), "show") {
		t.Fatalf("meter ran show: %s", log)
	}
}

func TestStateSurvivesReload(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6500, 9100})
	mustCollect(t)
	before := snapshot()

	resetUsageMemory()
	usageMu.Lock()
	err := loadUsageState()
	usageMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	if !after.Primed || after.Last["pubA"] != before.Last["pubA"] || after.Open["pubA"] != before.Open["pubA"] {
		t.Fatalf("after = %+v, before = %+v", after, before)
	}
	info, err := os.Stat(USAGE_STATE_FILE)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state file mode: %v %v", info, err)
	}
}

func TestShowFailureReturnsErrorAndKeepsState(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	if err := os.WriteFile(filepath.Join(env.dir, "status_fail"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := collectUsage(); err == nil {
		t.Fatal("want error when show fails")
	}
	if snapshot().Last["pubA"] != (peerCounter{5000, 9000}) {
		t.Fatal("Last changed on failure")
	}
}

func TestLastPeersUpdatedOnCollect(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 1, 2})
	mustCollect(t)
	usageMu.Lock()
	defer usageMu.Unlock()
	if len(lastPeers) != 1 || lastPeers[0].PublicKey != "pubA" {
		t.Fatalf("lastPeers = %+v", lastPeers)
	}
}
