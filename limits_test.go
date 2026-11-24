package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fakeNftScript = `#!/bin/bash
dir="$(dirname "$0")"
n=$(ls "$dir"/nft_in_* 2>/dev/null | wc -l)
cat > "$dir/nft_in_$((n+1))"
if [ -f "$dir/nft_fail" ]; then echo "fake nft failure" >&2; exit 1; fi
if [ -f "$dir/nft_hang" ]; then exec sleep 30; fi
`

// setupNft points nftCmd at a fake and resets the applied state.
func setupNft(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "nft")
	if err := os.WriteFile(script, []byte(fakeNftScript), 0755); err != nil {
		t.Fatal(err)
	}
	old := nftCmd
	nftCmd = script
	resetLimitsMemory()
	t.Cleanup(func() { nftCmd = old; resetLimitsMemory() })
	return dir
}

func resetLimitsMemory() {
	limitsMu.Lock()
	defer limitsMu.Unlock()
	appliedScript, appliedOnce, lastLimitErr = "", false, ""
}

func nftScripts(t *testing.T, dir string) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "nft_in_*"))
	var out []string
	for i := range files {
		data, err := os.ReadFile(filepath.Join(dir, "nft_in_"+strconv.Itoa(i+1)))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(data))
	}
	return out
}

const oneLimitScript = `table inet chop_fairuse
delete table inet chop_fairuse
table inet chop_fairuse {
  chain forward {
    type filter hook forward priority -5; policy accept;
    ip daddr 10.66.0.61 limit rate over 32000 bytes/second burst 64000 bytes drop
    ip saddr 10.66.0.61 limit rate over 32000 bytes/second burst 64000 bytes drop
  }
}
`

func TestLimitScriptForOnePeer(t *testing.T) {
	got := buildLimitScript([]nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}},
		[]peerReading{{PublicKey: "pubA", AllowedIPs: []string{"10.66.0.61"}}})
	if got != oneLimitScript {
		t.Fatalf("script:\n%s", got)
	}
}

func TestLimitCoversPeerIPv6(t *testing.T) {
	got := buildLimitScript([]nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}},
		[]peerReading{{PublicKey: "pubA", AllowedIPs: []string{"10.66.0.61", "fd42:42:42::3d"}}})
	for _, want := range []string{
		"    ip6 daddr fd42:42:42::3d limit rate over 32000 bytes/second burst 64000 bytes drop\n",
		"    ip6 saddr fd42:42:42::3d limit rate over 32000 bytes/second burst 64000 bytes drop\n",
		"    ip daddr 10.66.0.61 limit",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestLimitScriptWritesMappedAsIPv4(t *testing.T) {
	got := buildLimitScript([]nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}, {AllowedIP: "::ffff:10.66.0.9", RateKbps: 256}},
		[]peerReading{{PublicKey: "pubA", AllowedIPs: []string{"::ffff:10.66.0.61", "fd42:42:42::3d"}}})
	if strings.Contains(got, "::ffff") {
		t.Fatalf("mapped address in script:\n%s", got)
	}
	for _, want := range []string{
		"    ip daddr 10.66.0.61 limit rate over 32000 bytes/second burst 64000 bytes drop\n",
		"    ip saddr 10.66.0.61 limit rate over 32000 bytes/second burst 64000 bytes drop\n",
		"    ip6 daddr fd42:42:42::3d limit",
		"    ip daddr 10.66.0.9 limit",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestLimitUnknownPeerAndZeroRate(t *testing.T) {
	got := buildLimitScript([]nodeLimit{{AllowedIP: "10.66.0.9", RateKbps: 0}}, nil)
	if !strings.Contains(got, "ip daddr 10.66.0.9 limit rate over 32000 bytes/second burst 64000 bytes drop") {
		t.Fatalf("script:\n%s", got)
	}
}

func TestEmptyLimitsRemovesTable(t *testing.T) {
	if got := buildLimitScript([]nodeLimit{}, nil); got != "table inet chop_fairuse\ndelete table inet chop_fairuse\n" {
		t.Fatalf("script: %q", got)
	}
}

func TestEmptyLimitsFirstCallStillRuns(t *testing.T) {
	dir := setupNft(t)
	if err := applyLimits(nil); err != nil {
		t.Fatal(err)
	}
	if err := applyLimits([]nodeLimit{}); err != nil {
		t.Fatal(err)
	}
	if s := nftScripts(t, dir); len(s) != 1 || s[0] != limitRemoveScript() {
		t.Fatalf("scripts: %q", s)
	}
}

func TestSameLimitsNotReapplied(t *testing.T) {
	dir := setupNft(t)
	x := []nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}}
	for i := 0; i < 2; i++ {
		if err := applyLimits(x); err != nil {
			t.Fatal(err)
		}
	}
	if s := nftScripts(t, dir); len(s) != 1 || s[0] != oneLimitScript {
		t.Fatalf("scripts: %q", s)
	}
}

func TestFailedSendKeepsLimits(t *testing.T) {
	dir := setupNft(t)
	setupUsage(t)
	x := []nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}}
	newFakeMaster(t, `{"ok":true,"limits":[{"allowed_ip":"10.66.0.61","rate_kbps":256}]}`, 200, 503)
	usageTick(time.Now())
	usageTick(time.Now())
	if s := nftScripts(t, dir); len(s) != 1 {
		t.Fatalf("nft calls = %d", len(s))
	}
	limitsMu.Lock()
	same := appliedScript == buildLimitScript(x, nil)
	limitsMu.Unlock()
	if !same {
		t.Fatal("applied set changed")
	}
}

func TestNftFailureRetriedNextTick(t *testing.T) {
	dir := setupNft(t)
	x := []nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}}
	os.WriteFile(filepath.Join(dir, "nft_fail"), nil, 0600)
	if err := applyLimits(x); err == nil {
		t.Fatal("expected error")
	}
	os.Remove(filepath.Join(dir, "nft_fail"))
	if err := applyLimits(x); err != nil {
		t.Fatal(err)
	}
	if s := nftScripts(t, dir); len(s) != 2 {
		t.Fatalf("nft calls = %d", len(s))
	}
	if err := applyLimits(x); err != nil {
		t.Fatal(err)
	}
	if s := nftScripts(t, dir); len(s) != 2 {
		t.Fatalf("nft calls after success = %d", len(s))
	}
}

func TestHungNftIsKilled(t *testing.T) {
	dir := setupNft(t)
	old := nftTimeout
	nftTimeout = 300 * time.Millisecond
	t.Cleanup(func() { nftTimeout = old })
	os.WriteFile(filepath.Join(dir, "nft_hang"), nil, 0600)
	start := time.Now()
	err := applyLimits([]nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}})
	if err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("applyLimits took %v", d)
	}
	limitsMu.Lock()
	applied := appliedOnce
	limitsMu.Unlock()
	if applied {
		t.Fatal("a killed nft run counted as applied")
	}
}

func TestOnlyOwnTableTouched(t *testing.T) {
	dir := setupNft(t)
	applyLimits([]nodeLimit{{AllowedIP: "10.66.0.61", RateKbps: 256}})
	applyLimits([]nodeLimit{{AllowedIP: "10.66.0.62", RateKbps: 512}})
	applyLimits(nil)
	scripts := nftScripts(t, dir)
	if len(scripts) != 3 {
		t.Fatalf("nft calls = %d", len(scripts))
	}
	for _, s := range scripts {
		if strings.Contains(s, "flush") {
			t.Fatalf("flush in script:\n%s", s)
		}
		for _, line := range strings.Split(s, "\n") {
			if (strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "delete table ")) && !strings.Contains(line, "inet chop_fairuse") {
				t.Fatalf("other table: %q", line)
			}
		}
	}
}
