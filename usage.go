package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Usage meter: reads per-peer byte counters from the kernel and keeps the
// deltas since the last read. Counters live in the kernel and vanish when a
// peer is removed, so the meter must run right before every apply.
// Lock order: wgConfigMutex -> usageMu, never the other way.

var (
	// USAGE_PUSH_URL turns the feature on; empty means off.
	USAGE_PUSH_URL      string
	USAGE_PUSH_INTERVAL = 120 * time.Second
	USAGE_STATE_FILE    = "/var/lib/wireguard-api/usage-state.json"

	usageMu     sync.Mutex
	usageSt     usageState
	usageLoaded bool
	// lastPeers is the peer list of the latest successful collect.
	lastPeers []peerReading
)

type usageEntry struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	RX        uint64 `json:"rx_bytes"`
	TX        uint64 `json:"tx_bytes"`
}

type usageBatch struct {
	BatchID string       `json:"batch_id"`
	SentAt  time.Time    `json:"sent_at"`
	Peers   []usageEntry `json:"peers"`
}

type peerCounter struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

type usageState struct {
	Primed  bool                   `json:"primed"`
	Last    map[string]peerCounter `json:"last"`
	Open    map[string]usageEntry  `json:"open"`
	Pending []usageBatch           `json:"pending"`
}

type peerReading struct {
	PublicKey  string
	AllowedIPs []string // without prefix length
	RX, TX     uint64
}

func usageEnabled() bool { return USAGE_PUSH_URL != "" }

func newUsageState() usageState {
	return usageState{Last: map[string]peerCounter{}, Open: map[string]usageEntry{}}
}

// parseDump parses `<wg|awg> show <nic> dump`. The first line is the
// interface; peer lines are tab separated:
// pubkey psk endpoint allowed-ips handshake rx tx keepalive
func parseDump(out string) []peerReading {
	var peers []peerReading
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 8 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[5], 10, 64)
		tx, err2 := strconv.ParseUint(f[6], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		p := peerReading{PublicKey: f[0], RX: rx, TX: tx}
		if f[3] != "(none)" && f[3] != "" {
			for _, cidr := range strings.Split(f[3], ",") {
				cidr = strings.TrimSpace(cidr)
				if cidr == "" {
					continue
				}
				if idx := strings.Index(cidr, "/"); idx >= 0 {
					cidr = cidr[:idx]
				}
				p.AllowedIPs = append(p.AllowedIPs, cidr)
			}
		}
		peers = append(peers, p)
	}
	return peers
}

func firstIPv4(ips []string) string {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return s
		}
	}
	return ""
}

func counterDelta(cur, last uint64) uint64 {
	if cur >= last {
		return cur - last
	}
	return cur
}

// loadUsageState reads the state file. A missing file is a fresh, unprimed
// state; an unreadable one is an error. Caller holds usageMu (or is a test).
func loadUsageState() error {
	st := newUsageState()
	data, err := os.ReadFile(USAGE_STATE_FILE)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading usage state: %v", err)
	}
	if err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("parsing usage state: %v", err)
		}
		if st.Last == nil {
			st.Last = map[string]peerCounter{}
		}
		if st.Open == nil {
			st.Open = map[string]usageEntry{}
		}
	}
	usageSt = st
	usageLoaded = true
	return nil
}

// saveUsageState writes the state atomically (temp file + rename).
func saveUsageState() error {
	data, err := json.Marshal(usageSt)
	if err != nil {
		return err
	}
	dir := filepath.Dir(USAGE_STATE_FILE)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".usage-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, USAGE_STATE_FILE); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// collectUsage folds the kernel counters into the open deltas and saves the
// state. It takes usageMu only, never wgConfigMutex. No-op when disabled.
func collectUsage() error {
	if !usageEnabled() {
		return nil
	}
	usageMu.Lock()
	defer usageMu.Unlock()

	if !usageLoaded {
		if err := loadUsageState(); err != nil {
			return err
		}
	}

	success, out := executeCommand(wgCmd, "show", wgParams.ServerWGNIC, "dump")
	if success != "success" {
		return fmt.Errorf("%s show dump failed: %s", wgCmd, out)
	}
	peers := parseDump(out)

	last := make(map[string]peerCounter, len(peers))
	for _, p := range peers {
		last[p.PublicKey] = peerCounter{RX: p.RX, TX: p.TX}
		if !usageSt.Primed {
			continue
		}
		prev, known := usageSt.Last[p.PublicKey]
		var drx, dtx uint64
		if known {
			drx, dtx = counterDelta(p.RX, prev.RX), counterDelta(p.TX, prev.TX)
		} else {
			drx, dtx = p.RX, p.TX
		}
		if drx == 0 && dtx == 0 {
			continue
		}
		ip := firstIPv4(p.AllowedIPs)
		if ip == "" {
			continue
		}
		e := usageSt.Open[p.PublicKey]
		e.PublicKey = p.PublicKey
		e.AllowedIP = ip
		e.RX += drx
		e.TX += dtx
		usageSt.Open[p.PublicKey] = e
	}
	usageSt.Last = last
	usageSt.Primed = true
	lastPeers = peers

	return saveUsageState()
}

// collectUsageLogged is for call sites that must never be blocked by the meter.
func collectUsageLogged() {
	if err := collectUsage(); err != nil {
		log.Printf("usage meter: %v", err)
	}
}
