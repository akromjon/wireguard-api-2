package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type dumpPeer struct {
	key, allowed string
	rx, tx       uint64
}

func dumpText(peers ...dumpPeer) string {
	return dumpTextIface("srvpub", peers...)
}

// dumpTextIface is dumpText with a chosen interface public key.
func dumpTextIface(ifacePub string, peers ...dumpPeer) string {
	var b strings.Builder
	b.WriteString("srvpriv\t" + ifacePub + "\t51820\toff\n")
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
	usageGen, usageSavedGen, usageSaveFailed = 0, 0, false
	lastPeers = nil
}

func mustSave(t *testing.T) {
	t.Helper()
	if err := saveUsageState(); err != nil {
		t.Fatalf("saveUsageState: %v", err)
	}
}

func (e *testEnv) setDump(t *testing.T, peers ...dumpPeer) {
	t.Helper()
	e.setDumpIface(t, "srvpub", peers...)
}

func (e *testEnv) setDumpIface(t *testing.T, ifacePub string, peers ...dumpPeer) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "show_output"), []byte(dumpTextIface(ifacePub, peers...)), 0600); err != nil {
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
	pub, got := parseDump(out)
	if pub != "srvpub" {
		t.Fatalf("interface key = %q", pub)
	}
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

// setCollectedAt moves the time of the last reading.
func setCollectedAt(at time.Time) {
	usageMu.Lock()
	defer usageMu.Unlock()
	usageSt.CollectedAt = at
}

func TestInterfaceKeyChangeTakesNewBaseline(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6000, 9000})
	mustCollect(t)
	// Same peer key, interface re-created with another key: its counters
	// are not comparable with the old ones.
	env.setDumpIface(t, "otherpub", dumpPeer{"pubA", "10.66.0.61/32", 90000, 90000})
	mustCollect(t)
	st := snapshot()
	if got := st.Open["pubA"]; got.RX != 1000 || got.TX != 0 {
		t.Fatalf("Open[pubA] = %+v, want only the earlier 1000 rx", got)
	}
	if st.Last["pubA"] != (peerCounter{90000, 90000}) || st.Iface != "wg0 otherpub" {
		t.Fatalf("state = %+v", st)
	}
	env.setDumpIface(t, "otherpub", dumpPeer{"pubA", "10.66.0.61/32", 90500, 90000})
	mustCollect(t)
	if got := snapshot().Open["pubA"].RX; got != 1500 {
		t.Fatalf("Open[pubA].RX = %d, want 1500 after the new baseline", got)
	}
}

func TestLongGapTakesNewBaseline(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6000, 9000})
	mustCollect(t)
	setCollectedAt(time.Now().Add(-31 * time.Minute))
	env.setDump(t,
		dumpPeer{"pubA", "10.66.0.61/32", 50 << 30, 9000},
		dumpPeer{"pubB", "10.66.0.62/32", 30 << 30, 0})
	mustCollect(t)
	st := snapshot()
	if got := st.Open["pubA"]; got.RX != 1000 {
		t.Fatalf("Open[pubA] = %+v, want only the earlier 1000 rx", got)
	}
	if _, ok := st.Open["pubB"]; ok {
		t.Fatalf("peer first seen after the gap was counted: %+v", st.Open["pubB"])
	}
	if st.Last["pubB"] != (peerCounter{30 << 30, 0}) {
		t.Fatalf("Last = %+v", st.Last)
	}
	if time.Since(st.CollectedAt) > time.Minute {
		t.Fatalf("CollectedAt not updated: %v", st.CollectedAt)
	}
}

func TestShortGapCountsDeltas(t *testing.T) {
	env := setupUsage(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	setCollectedAt(time.Now().Add(-29 * time.Minute))
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6000, 9500})
	mustCollect(t)
	if got := snapshot().Open["pubA"]; got.RX != 1000 || got.TX != 500 {
		t.Fatalf("Open[pubA] = %+v", got)
	}
}

func TestStaleStateFileNotCounted(t *testing.T) {
	env := setupUsage(t)
	// State left behind weeks ago (feature off, or the API down).
	old := usageState{Primed: true, Iface: "wg0 srvpub", CollectedAt: time.Now().Add(-21 * 24 * time.Hour),
		Last: map[string]peerCounter{"pubA": {RX: 1 << 30}}, Open: map[string]usageEntry{}}
	data, _ := json.Marshal(old)
	if err := os.WriteFile(USAGE_STATE_FILE, data, 0600); err != nil {
		t.Fatal(err)
	}
	env.setDump(t,
		dumpPeer{"pubA", "10.66.0.61/32", 50 << 30, 0},
		dumpPeer{"pubB", "10.66.0.62/32", 30 << 30, 0})
	mustCollect(t)
	if st := snapshot(); len(st.Open) != 0 {
		t.Fatalf("Open = %+v, want nothing from a stale state", st.Open)
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
	mustSave(t)
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

// fakeMaster answers with the scripted statuses in order (last one repeats).
type fakeMaster struct {
	srv      *httptest.Server
	mu       sync.Mutex
	statuses []int
	body     string
	keys     []string
	bodies   []usageBatch
	raw      []string
}

func newFakeMaster(t *testing.T, body string, statuses ...int) *fakeMaster {
	t.Helper()
	m := &fakeMaster{statuses: statuses, body: body}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b usageBatch
		_ = json.Unmarshal(raw, &b)
		m.mu.Lock()
		i := len(m.bodies)
		m.keys = append(m.keys, r.Header.Get("key"))
		m.bodies = append(m.bodies, b)
		m.raw = append(m.raw, string(raw))
		st := m.statuses[len(m.statuses)-1]
		if i < len(m.statuses) {
			st = m.statuses[i]
		}
		m.mu.Unlock()
		w.WriteHeader(st)
		if st == 200 {
			io.WriteString(w, m.body)
		}
	}))
	old := USAGE_PUSH_URL
	USAGE_PUSH_URL = m.srv.URL + "/node-usage"
	t.Cleanup(func() { m.srv.Close(); USAGE_PUSH_URL = old })
	return m
}

func (m *fakeMaster) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

func seedPending(n int) []string {
	usageMu.Lock()
	defer usageMu.Unlock()
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		ids = append(ids, id)
		usageSt.Pending = append(usageSt.Pending, usageBatch{BatchID: id, SentAt: time.Now().UTC(),
			Peers: []usageEntry{{PublicKey: "pubA", AllowedIP: "10.66.0.61", RX: 1, TX: 1}}})
	}
	return ids
}

func pendingIDs() []string {
	usageMu.Lock()
	defer usageMu.Unlock()
	var ids []string
	for _, b := range usageSt.Pending {
		ids = append(ids, b.BatchID)
	}
	return ids
}

func TestTickSendsDeltaWithKeyHeader(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 200)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6500, 9000})
	usageTick(time.Now())
	if m.count() != 1 {
		t.Fatalf("requests = %d, want 1", m.count())
	}
	if m.keys[0] != "test-token" {
		t.Fatalf("key header = %q", m.keys[0])
	}
	b := m.bodies[0]
	want := []usageEntry{{PublicKey: "pubA", AllowedIP: "10.66.0.61", RX: 1500, TX: 0}}
	if len(b.Peers) != 1 || b.Peers[0] != want[0] {
		t.Fatalf("peers = %+v", b.Peers)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(b.BatchID) {
		t.Fatalf("batch_id = %q", b.BatchID)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal([]byte(m.raw[0]), &generic); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, generic["sent_at"].(string)); err != nil {
		t.Fatalf("sent_at: %v", err)
	}
	if !strings.HasSuffix(generic["sent_at"].(string), "Z") {
		t.Fatalf("sent_at not UTC: %v", generic["sent_at"])
	}
	if got := pendingIDs(); len(got) != 0 {
		t.Fatalf("Pending = %v", got)
	}
}

func TestHeartbeatWhenNothingToSend(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 200)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	usageTick(time.Now())
	if m.count() != 1 {
		t.Fatalf("requests = %d, want 1", m.count())
	}
	if !strings.Contains(m.raw[0], `"peers":[]`) {
		t.Fatalf("body = %s", m.raw[0])
	}
	if got := pendingIDs(); len(got) != 0 {
		t.Fatalf("Pending = %v", got)
	}
}

func TestRetrySendsSameBatchID(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 503, 200)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6500, 9000})
	usageTick(time.Now())
	if got := pendingIDs(); len(got) != 1 {
		t.Fatalf("after 503 Pending = %v", got)
	}
	usageTick(time.Now())
	if m.count() != 2 || m.bodies[0].BatchID != m.bodies[1].BatchID {
		t.Fatalf("count=%d ids=%v", m.count(), m.bodies)
	}
	if got := pendingIDs(); len(got) != 0 {
		t.Fatalf("Pending = %v", got)
	}
}

func TestOrderOldestFirstStopsAtFailure(t *testing.T) {
	setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 200, 500)
	ids := seedPending(3)
	pushPending(time.Now())
	if m.count() != 2 {
		t.Fatalf("requests = %d, want 2", m.count())
	}
	if m.bodies[0].BatchID != ids[0] || m.bodies[1].BatchID != ids[1] {
		t.Fatalf("order wrong: %v", m.bodies)
	}
	got := pendingIDs()
	if len(got) != 2 || got[0] != ids[1] || got[1] != ids[2] {
		t.Fatalf("Pending = %v", got)
	}
}

func TestOther4xxDropsBatch(t *testing.T) {
	setupUsage(t)
	newFakeMaster(t, "", 422)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	seedPending(1)
	_, ok := pushPending(time.Now())
	if ok {
		t.Fatal("ok = true on 422")
	}
	if got := pendingIDs(); len(got) != 0 {
		t.Fatalf("Pending = %v", got)
	}
	if !strings.Contains(buf.String(), "dropped") {
		t.Fatalf("log = %q", buf.String())
	}
}

func Test404KeepsBatch(t *testing.T) {
	setupUsage(t)
	newFakeMaster(t, "", 404)
	seedPending(1)
	pushPending(time.Now())
	if got := pendingIDs(); len(got) != 1 {
		t.Fatalf("Pending = %v", got)
	}
}

func TestLimitsFromLastAnswer(t *testing.T) {
	setupUsage(t)
	newFakeMaster(t, `{"ok":true,"limits":[{"allowed_ip":"10.66.0.61","rate_kbps":256}]}`, 200)
	seedPending(2)
	limits, ok := pushPending(time.Now())
	if !ok || len(limits) != 1 || limits[0].AllowedIP != "10.66.0.61" || limits[0].RateKbps != 256 {
		t.Fatalf("limits=%v ok=%v", limits, ok)
	}
}

func TestUndecodable200AcknowledgesButNotOK(t *testing.T) {
	setupUsage(t)
	newFakeMaster(t, `not json`, 200)
	seedPending(1)
	_, ok := pushPending(time.Now())
	if ok {
		t.Fatal("ok = true for undecodable body")
	}
	if got := pendingIDs(); len(got) != 0 {
		t.Fatalf("Pending = %v", got)
	}
}

func TestPendingCappedAt2000(t *testing.T) {
	setupUsage(t)
	for i := 0; i <= 2000; i++ {
		usageMu.Lock()
		usageSt.Open = map[string]usageEntry{"pubA": {PublicKey: "pubA", AllowedIP: "10.66.0.61", RX: uint64(i + 1)}}
		usageMu.Unlock()
		sealOpenBatch(time.Now())
	}
	st := snapshot()
	if len(st.Pending) != 2000 {
		t.Fatalf("len = %d", len(st.Pending))
	}
	if st.Pending[0].Peers[0].RX != 2 {
		t.Fatalf("oldest RX = %d, want 2 (first dropped)", st.Pending[0].Peers[0].RX)
	}
	if len(st.Open) != 0 {
		t.Fatalf("Open not cleared")
	}
}

func TestCollectAndSealDoNotWriteState(t *testing.T) {
	env := setupUsage(t)
	env.addUser(t, "alice")
	env.addUser(t, "bob")
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6000, 9000})
	// The apply path (under wgConfigMutex) collects too.
	if rec := env.authedRequest(t, http.MethodPost, "/api/users/delete", DeleteUserRequest{Name: "alice"}); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	sealOpenBatch(time.Now())
	if _, err := os.Stat(USAGE_STATE_FILE); !os.IsNotExist(err) {
		t.Fatalf("state file written outside the push loop (err=%v)", err)
	}
	if len(pendingIDs()) != 1 {
		t.Fatalf("Pending = %v", pendingIDs())
	}
	mustSave(t)
	if _, err := os.Stat(USAGE_STATE_FILE); err != nil {
		t.Fatalf("state file after save: %v", err)
	}
}

// lockDir makes dir unwritable; it skips the test when that has no effect
// (running as root).
func lockDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0600); err == nil {
		os.Remove(probe)
		t.Skip("directory permissions are not enforced (root?)")
	}
}

func sentRX(m *fakeMaster) (total uint64, dataPosts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.bodies {
		if len(b.Peers) > 0 {
			dataPosts++
		}
		for _, p := range b.Peers {
			total += p.RX
		}
	}
	return total, dataPosts
}

func TestUnsavedStateSendsOnlyHeartbeat(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 200)
	sub := filepath.Join(env.dir, "st")
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatal(err)
	}
	USAGE_STATE_FILE = filepath.Join(sub, "state.json")
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 1000, 0})
	usageTick(time.Now()) // baseline, saved, heartbeat

	lockDir(t, sub)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 0})
	usageTick(time.Now())
	if m.count() != 2 || len(m.bodies[1].Peers) != 0 {
		t.Fatalf("with an unwritable state dir: requests=%d bodies=%+v, want a heartbeat only", m.count(), m.bodies)
	}
	if len(pendingIDs()) != 1 {
		t.Fatalf("outbox must stay in memory: %v", pendingIDs())
	}

	os.Chmod(sub, 0700)
	usageTick(time.Now())
	usageTick(time.Now())
	total, posts := sentRX(m)
	if total != 4000 || posts != 1 {
		t.Fatalf("master got rx %d in %d data posts, want 4000 in 1", total, posts)
	}
	if len(pendingIDs()) != 0 {
		t.Fatalf("Pending = %v", pendingIDs())
	}
}

func TestSaveFailureThenRestartCountsOnce(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, `{"ok":true,"limits":[]}`, 200)
	sub := filepath.Join(env.dir, "st")
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatal(err)
	}
	USAGE_STATE_FILE = filepath.Join(sub, "state.json")
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 1000, 0})
	usageTick(time.Now()) // on disk: Last = 1000

	lockDir(t, sub)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 0})
	usageTick(time.Now()) // cannot save: nothing but a heartbeat goes out

	os.Chmod(sub, 0700)
	resetUsageMemory() // API restart
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5100, 0})
	usageTick(time.Now())
	if total, _ := sentRX(m); total != 4100 {
		t.Fatalf("real traffic 4100, master got %d", total)
	}
}

func TestCorruptStateFileMovedAside(t *testing.T) {
	env := setupUsage(t)
	if err := os.WriteFile(USAGE_STATE_FILE, []byte("{garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	st := snapshot()
	if !st.Primed || len(st.Open) != 0 || st.Last["pubA"] != (peerCounter{5000, 9000}) {
		t.Fatalf("state = %+v, want a fresh baseline", st)
	}
	aside, _ := filepath.Glob(USAGE_STATE_FILE + ".corrupt-*")
	if len(aside) != 1 {
		t.Fatalf("moved-aside files = %v", aside)
	}
	if data, _ := os.ReadFile(aside[0]); string(data) != "{garbage" {
		t.Fatalf("moved-aside content = %q", data)
	}
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5500, 9000})
	mustCollect(t)
	if got := snapshot().Open["pubA"].RX; got != 500 {
		t.Fatalf("Open[pubA].RX = %d, want 500", got)
	}
	mustSave(t)
	resetUsageMemory()
	usageMu.Lock()
	err := loadUsageState()
	usageMu.Unlock()
	if err != nil || snapshot().Open["pubA"].RX != 500 {
		t.Fatalf("reload after heal: err=%v state=%+v", err, snapshot())
	}
}

func TestStaleTempFilesRemovedOnLoad(t *testing.T) {
	env := setupUsage(t)
	dir := filepath.Dir(USAGE_STATE_FILE)
	for _, name := range []string{".usage-state-123456", ".usage-state-notdigits", ".usage-state-", "keep.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, ".usage-state-999"), 0700); err != nil {
		t.Fatal(err)
	}
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 1, 1})
	mustCollect(t)
	if _, err := os.Stat(filepath.Join(dir, ".usage-state-123456")); !os.IsNotExist(err) {
		t.Fatalf("leftover temp file still there (err=%v)", err)
	}
	for _, name := range []string{".usage-state-notdigits", ".usage-state-", "keep.json", ".usage-state-999"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s removed: %v", name, err)
		}
	}
}

func TestRedirect301KeepsBatchAndSendsNoGET(t *testing.T) {
	setupUsage(t)
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		io.WriteString(w, `{"ok":true,"limits":[]}`)
	}))
	defer srv.Close()
	USAGE_PUSH_URL = srv.URL + "/old"
	ids := seedPending(1)
	if _, ok := pushPending(time.Now()); ok {
		t.Fatal("ok = true on a 301")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "POST /old" {
		t.Fatalf("requests = %v, want only POST /old", seen)
	}
	if got := pendingIDs(); len(got) != 1 || got[0] != ids[0] {
		t.Fatalf("Pending = %v, want the batch kept", got)
	}
}

func TestRedirect307ToOtherHostNotFollowed(t *testing.T) {
	setupUsage(t)
	var mu sync.Mutex
	var otherSaw []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		otherSaw = append(otherSaw, r.Method+" key="+r.Header.Get("key"))
		mu.Unlock()
		io.WriteString(w, `{"ok":true,"limits":[]}`)
	}))
	defer other.Close()
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL+"/x", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	USAGE_PUSH_URL = first.URL + "/node-usage"
	ids := seedPending(1)
	pushPending(time.Now())
	mu.Lock()
	defer mu.Unlock()
	if len(otherSaw) != 0 {
		t.Fatalf("other host got %v", otherSaw)
	}
	if got := pendingIDs(); len(got) != 1 || got[0] != ids[0] {
		t.Fatalf("Pending = %v, want the batch kept", got)
	}
}

func TestUsageURLWarning(t *testing.T) {
	setupUsage(t)
	USAGE_PUSH_URL = "https://master.example/node-usage"
	if w := usageURLWarning(); w != "" {
		t.Fatalf("https warned: %q", w)
	}
	USAGE_PUSH_URL = "http://master.example/node-usage"
	if w := usageURLWarning(); !strings.Contains(w, "not https") {
		t.Fatalf("http not warned: %q", w)
	}
}

func TestPendingSurvivesRestart(t *testing.T) {
	env := setupUsage(t)
	m := newFakeMaster(t, "", 503)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 5000, 9000})
	mustCollect(t)
	env.setDump(t, dumpPeer{"pubA", "10.66.0.61/32", 6500, 9000})
	usageTick(time.Now())
	want := pendingIDs()
	if len(want) != 1 || m.count() != 1 {
		t.Fatalf("want=%v count=%d", want, m.count())
	}
	resetUsageMemory()
	usageMu.Lock()
	err := loadUsageState()
	usageMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := pendingIDs(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("after restart = %v, want %v", got, want)
	}
}
