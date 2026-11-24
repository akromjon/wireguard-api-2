package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Speed limits: the master's push answer lists peers to slow down. They are
// enforced with nftables in one table of our own, `inet chop_fairuse`. The
// node API never touches any other table or the saved ruleset; limits live in
// memory and come back with the next push answer.

const limitTable = "inet chop_fairuse"

var (
	// nftCmd is the nft binary; tests point it at a fake.
	nftCmd = "nft"
	// nftTimeout bounds one nft run, so a hung nft cannot stop the push loop.
	nftTimeout = 15 * time.Second

	limitsMu      sync.Mutex // guards the three vars below, never held with usageMu
	appliedScript string
	appliedOnce   bool
	lastLimitErr  string
)

func limitRemoveScript() string {
	return "table " + limitTable + "\ndelete table " + limitTable + "\n"
}

// buildLimitScript renders the whole table. Each limited IPv4 is mapped to its
// peer and every allowed-ip of that peer is limited; a limit that matches no
// peer is applied for that IPv4 alone. IPv4-mapped IPv6 addresses are written
// as plain IPv4 (an `ip` rule never gets a mapped address). Output is
// deterministic.
func buildLimitScript(limits []nodeLimit, peers []peerReading) string {
	if len(limits) == 0 {
		return limitRemoveScript()
	}
	sorted := append([]nodeLimit(nil), limits...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].AllowedIP < sorted[j].AllowedIP })

	var b strings.Builder
	b.WriteString(limitRemoveScript())
	b.WriteString("table " + limitTable + " {\n  chain forward {\n    type filter hook forward priority -5; policy accept;\n")
	for _, l := range sorted {
		rate := l.RateKbps
		if rate <= 0 {
			rate = 256
		}
		bps := rate * 1000 / 8
		want, _ := normIP(l.AllowedIP)
		if want == "" {
			continue
		}
		addrs := []string{l.AllowedIP}
		for _, p := range peers {
			found := false
			for _, a := range p.AllowedIPs {
				if n, _ := normIP(a); n == want {
					found = true
					break
				}
			}
			if found {
				addrs = p.AllowedIPs
				break
			}
		}
		seen := map[string]bool{}
		for _, a := range addrs {
			addr, v4 := normIP(a)
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			fam := "ip6"
			if v4 {
				fam = "ip"
			}
			for _, dir := range []string{"daddr", "saddr"} {
				fmt.Fprintf(&b, "    %s %s %s limit rate over %d bytes/second burst %d bytes drop\n", fam, dir, addr, bps, 2*bps)
			}
		}
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// applyLimits makes the kernel match the wanted limits. It does nothing when
// the wanted set equals what this process applied last. It never holds
// usageMu while running nft (syncWireGuardConf waits on usageMu under
// wgConfigMutex).
func applyLimits(limits []nodeLimit) error {
	usageMu.Lock()
	peers := append([]peerReading(nil), lastPeers...)
	usageMu.Unlock()

	script := buildLimitScript(limits, peers)

	limitsMu.Lock()
	defer limitsMu.Unlock()
	if appliedOnce && script == appliedScript {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nftCmd, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("no answer in %s, killed", nftTimeout)
		}
		msg := fmt.Sprintf("nft failed: %v", err)
		if o := strings.TrimSpace(out.String()); o != "" {
			msg += ": " + o
		}
		if msg != lastLimitErr {
			lastLimitErr = msg
			log.Printf("usage push: %s", msg)
		}
		return fmt.Errorf("%s", msg)
	}
	appliedScript, appliedOnce, lastLimitErr = script, true, ""
	return nil
}
