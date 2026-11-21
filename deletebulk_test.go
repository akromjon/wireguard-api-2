package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type deleteBulkResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Deleted  int                `json:"deleted"`
		NotFound int                `json:"not_found"`
		Failed   int                `json:"failed"`
		Results  []DeleteBulkResult `json:"results"`
	} `json:"data"`
}

func (e *testEnv) deleteBulk(t *testing.T, names ...string) (int, deleteBulkResp) {
	t.Helper()
	rec := e.authedRequest(t, http.MethodPost, "/api/users/delete-bulk", AddUsersBulkRequest{Names: names})
	var resp deleteBulkResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad delete-bulk response %q: %v", rec.Body.String(), err)
	}
	return rec.Code, resp
}

func (e *testEnv) clientFile(name string) string {
	return filepath.Join(e.clientsDir, "wg0-client-"+name+".conf")
}

func TestDeleteBulkMixedFoundAndNotFound(t *testing.T) {
	env := setupTestEnv(t)
	for _, n := range []string{"c1", "c2", "c3"} {
		env.addUser(t, n)
	}

	code, resp := env.deleteBulk(t, "c1", "c2", "zz")
	if code != http.StatusOK || !resp.Success {
		t.Fatalf("status %d, resp %+v", code, resp)
	}
	if resp.Data.Deleted != 2 || resp.Data.NotFound != 1 || resp.Data.Failed != 0 || len(resp.Data.Results) != 3 {
		t.Fatalf("bad counts: %+v", resp.Data)
	}
	want := []DeleteBulkResult{
		{Name: "c1", Success: true, Status: "deleted"},
		{Name: "c2", Success: true, Status: "deleted"},
		{Name: "zz", Success: true, Status: "not_found"},
	}
	for i, w := range want {
		if resp.Data.Results[i] != w {
			t.Errorf("result %d = %+v, want %+v", i, resp.Data.Results[i], w)
		}
	}

	conf := env.configContent(t)
	for _, n := range []string{"c1", "c2"} {
		if strings.Contains(conf, "### Client "+n+"\n") {
			t.Errorf("block of %s still in config", n)
		}
		if _, err := os.Stat(env.clientFile(n)); err == nil {
			t.Errorf("client file of %s still exists", n)
		}
	}
	if !strings.Contains(conf, "### Client c3\n") {
		t.Errorf("c3 block was removed")
	}
	if _, err := os.Stat(env.clientFile("c3")); err != nil {
		t.Errorf("c3 client file was removed: %v", err)
	}
}

func TestDeleteBulkFileWithoutBlockCountsAsDeleted(t *testing.T) {
	env := setupTestEnv(t)
	env.addUser(t, "c1")
	// Rename the block by hand: only the client file is left for c1.
	conf := strings.Replace(env.configContent(t), "### Client c1\n", "### Client other\n", 1)
	if err := os.WriteFile(env.configFile, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}

	code, resp := env.deleteBulk(t, "c1")
	if code != http.StatusOK || resp.Data.Deleted != 1 {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if _, err := os.Stat(env.clientFile("c1")); err == nil {
		t.Errorf("client file still exists")
	}
}

func TestDeleteBulkOneSyncconfWithRefill(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 3)
	for _, n := range []string{"c1", "c2", "c3"} {
		env.addUser(t, n)
	}
	if got := len(spareBlocksLocked([]byte(env.configContent(t)))); got != 3 {
		t.Fatalf("got %d spares before, want 3", got)
	}
	calls := env.syncconfCalls(t)

	code, resp := env.deleteBulk(t, "c1", "c2")
	if code != http.StatusOK || resp.Data.Deleted != 2 {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if got := env.syncconfCalls(t); got != calls+1 {
		t.Fatalf("got %d syncconf calls, want exactly 1", got-calls)
	}
	if got := len(spareBlocksLocked([]byte(env.configContent(t)))); got != 3 {
		t.Fatalf("got %d spares after, want 3", got)
	}
	if got := len(env.spareFiles(t)); got != 3 {
		t.Fatalf("got %d spare files, want 3", got)
	}
}

func TestDeleteBulkAllNotFoundStillOneApply(t *testing.T) {
	env := setupTestEnv(t)
	env.addUser(t, "c1")
	calls := env.syncconfCalls(t)

	code, resp := env.deleteBulk(t, "x1", "x2")
	if code != http.StatusOK || resp.Data.NotFound != 2 || resp.Data.Deleted != 0 {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if got := env.syncconfCalls(t); got != calls+1 {
		t.Fatalf("got %d syncconf calls, want 1", got-calls)
	}
}

func TestDeleteBulkNeverMatchesSpares(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 2)
	env.addUser(t, "seed")
	spares := spareBlocksLocked([]byte(env.configContent(t)))
	if len(spares) != 2 {
		t.Fatalf("got %d spares, want 2", len(spares))
	}
	name := spares[0].Name
	if !clientNameRegex.MatchString(name) {
		t.Fatalf("spare name %q is not a valid client name; test would not reach the handler", name)
	}

	code, resp := env.deleteBulk(t, name)
	if code != http.StatusOK || resp.Data.NotFound != 1 || resp.Data.Deleted != 0 {
		t.Fatalf("status %d, %+v", code, resp.Data)
	}
	if got := env.configContent(t); !strings.Contains(got, spareMarker+name+"\n") {
		t.Fatalf("spare block %s was removed", name)
	}
	if _, err := os.Stat(sparePath(name)); err != nil {
		t.Fatalf("spare client file was removed: %v", err)
	}
}

func TestDeleteBulkValidation(t *testing.T) {
	env := setupTestEnv(t)
	env.addUser(t, "c1")
	before := env.configContent(t)
	calls := env.syncconfCalls(t)

	tooMany := make([]string, 501)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("n%d", i)
	}
	cases := map[string][]string{
		"empty":     {},
		"too many":  tooMany,
		"invalid":   {"c1", "bad name!"},
		"duplicate": {"c1", "c1"},
	}
	for label, names := range cases {
		code, resp := env.deleteBulk(t, names...)
		if code != http.StatusBadRequest || resp.Success {
			t.Errorf("%s: status %d, resp %+v", label, code, resp)
		}
	}
	if env.configContent(t) != before {
		t.Errorf("config changed by rejected requests")
	}
	if _, err := os.Stat(env.clientFile("c1")); err != nil {
		t.Errorf("c1 client file removed by rejected request: %v", err)
	}
	if got := env.syncconfCalls(t); got != calls {
		t.Errorf("rejected requests ran syncconf")
	}
}

func TestDeleteBulkApplyFailureReportsNoneDeleted(t *testing.T) {
	env := setupTestEnv(t)
	env.addUser(t, "c1")
	env.addUser(t, "c2")
	syncFail := filepath.Join(env.dir, "sync_fail")
	if err := os.WriteFile(syncFail, nil, 0600); err != nil {
		t.Fatal(err)
	}

	code, resp := env.deleteBulk(t, "c1", "c2", "zz")
	if code != http.StatusInternalServerError || resp.Success {
		t.Fatalf("status %d, resp %+v", code, resp)
	}
	if resp.Data.Deleted != 0 || resp.Data.Failed != 2 || resp.Data.NotFound != 1 {
		t.Fatalf("bad counts: %+v", resp.Data)
	}
	for _, r := range resp.Data.Results[:2] {
		if r.Success || r.Status != "error" || r.Message == "" {
			t.Errorf("result %+v, want error", r)
		}
	}
	if r := resp.Data.Results[2]; r.Status != "not_found" {
		t.Errorf("zz result %+v", r)
	}
	if strings.Contains(env.configContent(t), "### Client c1\n") {
		t.Errorf("block stayed in the file")
	}

	if err := os.Remove(syncFail); err != nil {
		t.Fatal(err)
	}
	code, resp = env.deleteBulk(t, "c1", "c2")
	if code != http.StatusOK || resp.Data.NotFound != 2 || resp.Data.Deleted != 0 {
		t.Fatalf("retry: status %d, %+v", code, resp.Data)
	}
}

func TestClaimConcurrentWithDeleteBulkLosesNoPeer(t *testing.T) {
	env := setupTestEnv(t)
	setSparePool(t, 6)
	const n = 10
	var pre, claimed []string
	for i := 0; i < 3*n; i++ {
		name := fmt.Sprintf("old%d", i)
		env.addUser(t, name)
		pre = append(pre, name)
	}
	// client name -> PublicKey of each client block
	clientKeys := func(conf string) map[string]string {
		out := map[string]string{}
		_, blocks := splitBlocks(conf)
		for _, b := range blocks {
			m := strings.TrimRight(blockMarker(b), "\r")
			if strings.HasPrefix(m, clientMarker) {
				out[strings.TrimPrefix(m, clientMarker)] = blockValue(b, "PublicKey")
			}
		}
		return out
	}
	before := clientKeys(env.configContent(t))

	deleted := map[string]bool{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	fail := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		t.Errorf(format, a...)
	}
	for i := 0; i < n; i++ {
		d1, d2 := pre[2*i], pre[2*i+1]
		c1, c2 := fmt.Sprintf("new%da", i), fmt.Sprintf("new%db", i)
		deleted[d1], deleted[d2] = true, true
		claimed = append(claimed, c1, c2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			rec := env.authedRequest(t, http.MethodPost, "/api/users/delete-bulk", AddUsersBulkRequest{Names: []string{d1, d2}})
			if rec.Code != http.StatusOK {
				fail("delete-bulk status %d: %s", rec.Code, rec.Body.String())
			}
		}()
		go func() {
			defer wg.Done()
			rec := env.authedRequest(t, http.MethodPost, "/api/users/claim", AddUsersBulkRequest{Names: []string{c1, c2}})
			if rec.Code != http.StatusOK {
				fail("claim status %d: %s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()

	conf := env.configContent(t)
	after := clientKeys(conf)
	if got := strings.Count(conf, "### Client "); got != len(after) {
		t.Fatalf("%d client blocks but %d distinct names: a block is duplicated", got, len(after))
	}
	for _, name := range claimed {
		if after[name] == "" {
			t.Errorf("claimed %s has no client block", name)
		}
		if _, err := os.Stat(env.clientFile(name)); err != nil {
			t.Errorf("claimed %s has no client file: %v", name, err)
		}
	}
	for _, name := range pre {
		if deleted[name] {
			if _, ok := after[name]; ok {
				t.Errorf("deleted %s still has a block", name)
			}
			if _, err := os.Stat(env.clientFile(name)); err == nil {
				t.Errorf("deleted %s still has a client file", name)
			}
		} else if after[name] != before[name] {
			t.Errorf("peer %s lost or changed", name)
		}
	}
	// The untouched third of the pre-existing clients stays, plus the claimed.
	if len(after) != len(claimed)+n {
		t.Errorf("got %d client blocks, want %d", len(after), len(claimed))
	}

	allKeys := peerKeyLines(conf)
	seen := map[string]bool{}
	for _, k := range allKeys {
		if seen[k] {
			t.Fatalf("a PublicKey appears twice: a peer is duplicated")
		}
		seen[k] = true
	}
	spareBlocks := len(spareBlocksLocked([]byte(conf)))
	if len(allKeys) != len(after)+spareBlocks {
		t.Errorf("%d peers in file, want %d clients + %d spares", len(allKeys), len(after), spareBlocks)
	}
	if got := len(env.spareFiles(t)); got != spareBlocks {
		t.Errorf("%d spare files for %d spare blocks", got, spareBlocks)
	}
}
