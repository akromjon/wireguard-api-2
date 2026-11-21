package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLargeConf appends the given number of client and spare blocks to the
// test config, with their client files, the way the node writes them. No apply
// runs. It returns the client names in file order. Keys are placeholders.
func writeLargeConf(t *testing.T, env *testEnv, clients, spares int) []string {
	t.Helper()
	if err := os.MkdirAll(spareDir(), 0700); err != nil {
		t.Fatal(err)
	}
	var conf strings.Builder
	conf.WriteString(env.configContent(t))
	host := 1 // 10.66.0.1 is the server
	nextIP := func() string {
		host++
		return fmt.Sprintf("10.66.%d.%d", (host-1)/254, (host-1)%254+1)
	}
	names := make([]string, clients)
	for i := 0; i < clients+spares; i++ {
		keys := clientKeys{
			privateKey:   fmt.Sprintf("test-private-%05d", i),
			publicKey:    fmt.Sprintf("test-public-%05d", i),
			preSharedKey: fmt.Sprintf("test-psk-%05d", i),
		}
		ipv4 := nextIP()
		marker, name, path := clientMarker, fmt.Sprintf("c%04d", i), ""
		if i < clients {
			names[i] = name
			path = clientFilePath(name)
		} else {
			marker, name = spareMarker, fmt.Sprintf("sp%012x", i)
			path = sparePath(name)
		}
		if err := os.WriteFile(path, []byte(buildClientConfigText(ipv4, "", keys)), 0600); err != nil {
			t.Fatal(err)
		}
		conf.WriteString(buildPeerBlock(marker, name, ipv4, "", keys))
	}
	if err := os.WriteFile(env.configFile, []byte(conf.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return names
}

// A claim or delete-bulk of 200 names on a node holding 1,600 clients and
// 1,600 spares must not scan the whole config once per name under the lock.
func TestClaimAndDeleteBulkOfManyNamesOnALargeConf(t *testing.T) {
	const clients, spares, batch = 1600, 1600, 200
	const bound = 2 * time.Second

	env := setupTestEnv(t)
	resetReconcileState(t)
	setSparePool(t, spares)
	old := writeLargeConf(t, env, clients, spares)
	wgConfigMutex.Lock()
	lastApplyOK = true
	wgConfigMutex.Unlock()

	newNames := make([]string, batch)
	for i := range newNames {
		newNames[i] = fmt.Sprintf("n%03d", i)
	}

	start := time.Now()
	code, claimed := env.claim(t, newNames...)
	claimTook := time.Since(start)
	if code != http.StatusOK || claimed.Data.Claimed != batch {
		t.Fatalf("claim: status %d, claimed %d of %d (%s)", code, claimed.Data.Claimed, batch, claimed.Message)
	}

	start = time.Now()
	code, deleted := env.deleteBulk(t, old[:batch]...)
	deleteTook := time.Since(start)
	if code != http.StatusOK || deleted.Data.Deleted != batch {
		t.Fatalf("delete-bulk: status %d, deleted %d of %d (%s)", code, deleted.Data.Deleted, batch, deleted.Message)
	}

	t.Logf("%d clients + %d spares, %d names: claim %v, delete-bulk %v", clients, spares, batch, claimTook, deleteTook)
	if claimTook > bound {
		t.Errorf("claim of %d names took %v, want under %v", batch, claimTook, bound)
	}
	if deleteTook > bound {
		t.Errorf("delete-bulk of %d names took %v, want under %v", batch, deleteTook, bound)
	}

	conf := env.configContent(t)
	if got := strings.Count(conf, "\n"+clientMarker); got != clients {
		t.Fatalf("got %d client blocks, want %d", got, clients)
	}
	if got := strings.Count(conf, "\n"+spareMarker); got != spares {
		t.Fatalf("got %d spare blocks after the refill, want %d", got, spares)
	}
}

// markerLines returns the client and spare marker lines of a config in order.
func markerLines(conf string) []string {
	var out []string
	for _, l := range strings.Split(conf, "\n") {
		if isMarkerLine(strings.TrimRight(l, "\r")) {
			out = append(out, l)
		}
	}
	return out
}

// delete-bulk reads the config once, but must pick the same blocks as running
// single delete's removeClientFromConfig name by name.
func TestDeleteBulkPicksTheBlocksSingleDeleteWould(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 1) // keep the one spare through the apply
	keys := clientKeys{privateKey: "k", publicKey: "p", preSharedKey: "s"}
	conf := env.configContent(t)
	blocks := []struct{ marker, name string }{
		{clientMarker, "a"}, {clientMarker, "wg0-client-a"}, {clientMarker, "awg0-client-b"},
		{clientMarker, "c"}, {spareMarker, "d"}, {clientMarker, "c"}, {clientMarker, "e"},
		{clientMarker, "wg0-client-x"},
	}
	for i, b := range blocks {
		conf += buildPeerBlock(b.marker, b.name, fmt.Sprintf("10.66.0.%d", i+2), "", keys)
	}
	if err := os.WriteFile(env.configFile, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	// "a" takes only its own block, not "wg0-client-a"; "b" falls through to
	// its awg0 form; both "c" blocks go; a spare is never matched; "x" finds
	// its wg0 form already taken by the name before it.
	names := []string{"a", "b", "c", "d", "wg0-client-x", "x", "zz"}

	want := []byte(conf)
	wantStatus := make([]string, len(names))
	for i, n := range names {
		var removed bool
		want, removed = removeClientFromConfig(want, n)
		wantStatus[i] = deleteStatusNotFound
		if removed {
			wantStatus[i] = deleteStatusDeleted
		}
	}

	code, resp := env.deleteBulk(t, names...)
	if code != http.StatusOK {
		t.Fatalf("status %d: %+v", code, resp)
	}
	for i, r := range resp.Data.Results {
		if r.Name != names[i] || r.Status != wantStatus[i] {
			t.Errorf("result %d = %s %s, want %s %s", i, r.Name, r.Status, names[i], wantStatus[i])
		}
	}
	got, wantMarkers := markerLines(env.configContent(t)), markerLines(string(want))
	if strings.Join(got, "|") != strings.Join(wantMarkers, "|") {
		t.Fatalf("blocks left %q, want %q", got, wantMarkers)
	}
	if strings.Join(got, "|") != "### Client wg0-client-a|### Spare d|### Client e" {
		t.Fatalf("unexpected blocks left %q", got)
	}
}

// claim reads the config once, but must call a name taken exactly when
// clientExists would.
func TestClientTakenAnswersLikeClientExists(t *testing.T) {
	env := setupTestEnv(t)
	keys := clientKeys{privateKey: "k", publicKey: "p", preSharedKey: "s"}
	conf := env.configContent(t)
	for i, m := range []string{clientMarker + "a", clientMarker + "wg0-client-b", clientMarker + "awg0-client-c", spareMarker + "d"} {
		conf += buildPeerBlock(m, "", fmt.Sprintf("10.66.0.%d", i+2), "", keys)
	}
	conf += "\n" + clientMarker + "e\r\n[Peer]\nPublicKey = p\n"
	if err := os.WriteFile(env.configFile, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"f.conf", "awg0-client-g.conf", "wg0-client-h.conf"} {
		if err := os.WriteFile(filepath.Join(env.clientsDir, f), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	markers := clientMarkerNames(conf)
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "wg0-client-b", "client-b"} {
		want, err := clientExists(n)
		if err != nil {
			t.Fatal(err)
		}
		if got := clientTaken(markers, n); got != want {
			t.Errorf("%s: clientTaken %v, clientExists %v", n, got, want)
		}
	}
}
