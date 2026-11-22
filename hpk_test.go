package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeaderProtectionKeyOfParsesVariants(t *testing.T) {
	for _, in := range []string{
		"HeaderProtectionKey = abc\n",
		"HeaderProtectionKey=abc\r\n",
		"  headerprotectionkey   =   abc  \n",
	} {
		if v, ok := headerProtectionKeyOf([]byte(in)); !ok || v != "abc" {
			t.Errorf("headerProtectionKeyOf(%q) = (%q, %v), want (abc, true)", in, v, ok)
		}
	}
	if v, ok := headerProtectionKeyOf([]byte("Jc = 4\n")); ok || v != "" {
		t.Errorf("no key: got (%q, %v), want (\"\", false)", v, ok)
	}
}

func TestDropHeaderProtectionKeyRemovesOnlyThatLine(t *testing.T) {
	in := "[Interface]\nJc = 4\nHeaderProtectionKey = abc\nH1 = 5\n"
	want := "[Interface]\nJc = 4\nH1 = 5\n"
	if got := string(dropHeaderProtectionKey([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func syncWithKeys(t *testing.T, fileConf, liveConf string, showconfFail bool) *testEnv {
	t.Helper()
	env := setupTestEnv(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(env.dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(fileConf), 0600); err != nil {
		t.Fatal(err)
	}
	write("showconf_output", liveConf)
	if showconfFail {
		write("showconf_fail", "")
	}
	if err := syncWireGuardConf(); err != nil {
		t.Fatalf("syncWireGuardConf: %v", err)
	}
	return env
}

func TestSyncDropsKeyWhenLiveKeyMatches(t *testing.T) {
	env := syncWithKeys(t, "[Interface]\nJc = 4\nHeaderProtectionKey = abc\n", "[Interface]\nHeaderProtectionKey = abc\n", false)
	got := env.lastSyncconfStdin(t)
	if strings.Contains(got, "HeaderProtectionKey") {
		t.Errorf("key should be dropped, got %q", got)
	}
	if !strings.Contains(got, "Jc = 4") {
		t.Errorf("other lines must stay, got %q", got)
	}
}

func TestSyncKeepsKeyWhenLiveKeyDiffers(t *testing.T) {
	env := syncWithKeys(t, "[Interface]\nHeaderProtectionKey = abc\n", "[Interface]\nHeaderProtectionKey = xyz\n", false)
	if got := env.lastSyncconfStdin(t); !strings.Contains(got, "HeaderProtectionKey = abc") {
		t.Errorf("key should be kept, got %q", got)
	}
}

func TestSyncKeepsKeyWhenLiveHasNoKey(t *testing.T) {
	env := syncWithKeys(t, "[Interface]\nHeaderProtectionKey = abc\n", "[Interface]\nJc = 4\n", false)
	if got := env.lastSyncconfStdin(t); !strings.Contains(got, "HeaderProtectionKey = abc") {
		t.Errorf("key should be kept, got %q", got)
	}
}

func TestSyncKeepsKeyWhenShowconfFails(t *testing.T) {
	env := syncWithKeys(t, "[Interface]\nHeaderProtectionKey = abc\n", "", true)
	if got := env.lastSyncconfStdin(t); !strings.Contains(got, "HeaderProtectionKey = abc") {
		t.Errorf("key should be kept, got %q", got)
	}
	if calls := env.syncconfCalls(t); calls != 1 {
		t.Errorf("syncconf calls = %d, want 1", calls)
	}
}
