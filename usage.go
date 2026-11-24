package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	Primed bool `json:"primed"`
	// Iface is the interface name and its public key at the last reading.
	// Counters read on another interface (or a re-created one) are not
	// comparable with Last.
	Iface string `json:"iface"`
	// CollectedAt is the time of the last successful reading.
	CollectedAt time.Time              `json:"collected_at"`
	Last        map[string]peerCounter `json:"last"`
	Open        map[string]usageEntry  `json:"open"`
	Pending     []usageBatch           `json:"pending"`
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
// interface (private key, public key, port, ...); it returns that public key.
// Peer lines are tab separated:
// pubkey psk endpoint allowed-ips handshake rx tx keepalive
func parseDump(out string) (ifacePub string, peers []peerReading) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		if i == 0 {
			if f := strings.Split(strings.TrimRight(line, "\r"), "\t"); len(f) >= 2 {
				ifacePub = f[1]
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
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
	return ifacePub, peers
}

func firstIPv4(ips []string) string {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return s
		}
	}
	return ""
}

// usageStaleAfter is how old the last reading may be before the next one is
// taken as a new baseline instead of a delta: a longer gap means the API was
// down or the feature was off, and the counters moved by an unknown amount
// that may not belong to the current holders. Two intervals at least, so a
// long USAGE_PUSH_INTERVAL_SECONDS does not re-baseline every tick.
func usageStaleAfter() time.Duration {
	d := 30 * time.Minute
	if 2*USAGE_PUSH_INTERVAL > d {
		d = 2 * USAGE_PUSH_INTERVAL
	}
	return d
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
	ifacePub, peers := parseDump(out)
	iface := wgParams.ServerWGNIC + " " + ifacePub
	now := time.Now()

	// count is false when this reading only sets the baseline. Open and
	// Pending stay: they hold deltas that were measured correctly.
	count := usageSt.Primed
	if count {
		if usageSt.Iface != iface {
			log.Printf("usage meter: interface %s is not the one of the last reading, taking a new baseline", wgParams.ServerWGNIC)
			count = false
		} else if gap := now.Sub(usageSt.CollectedAt); gap > usageStaleAfter() {
			log.Printf("usage meter: last reading is %s old, taking a new baseline", gap.Round(time.Second))
			count = false
		}
	}

	last := make(map[string]peerCounter, len(peers))
	for _, p := range peers {
		last[p.PublicKey] = peerCounter{RX: p.RX, TX: p.TX}
		if !count {
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
	usageSt.Iface = iface
	usageSt.CollectedAt = now
	lastPeers = peers

	return saveUsageState()
}

// collectUsageLogged is for call sites that must never be blocked by the meter.
func collectUsageLogged() {
	if err := collectUsage(); err != nil {
		log.Printf("usage meter: %v", err)
	}
}

const maxPendingBatches = 2000

// usageHTTPClient sends the batches; tests swap it.
var usageHTTPClient = &http.Client{Timeout: 10 * time.Second}

// nodeLimit is one per-peer rate limit the master asks for.
type nodeLimit struct {
	AllowedIP string `json:"allowed_ip"`
	RateKbps  int    `json:"rate_kbps"`
}

type usageAnswer struct {
	OK     bool        `json:"ok"`
	Limits []nodeLimit `json:"limits"`
}

func newBatchID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable in any useful way.
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// sealOpenBatch moves the open deltas into a new pending batch and saves.
// Does nothing when there is nothing open.
func sealOpenBatch(now time.Time) {
	usageMu.Lock()
	defer usageMu.Unlock()
	if len(usageSt.Open) == 0 {
		return
	}
	peers := make([]usageEntry, 0, len(usageSt.Open))
	for _, e := range usageSt.Open {
		peers = append(peers, e)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	usageSt.Pending = append(usageSt.Pending, usageBatch{
		BatchID: newBatchID(),
		SentAt:  now.UTC().Truncate(time.Second),
		Peers:   peers,
	})
	usageSt.Open = map[string]usageEntry{}
	if over := len(usageSt.Pending) - maxPendingBatches; over > 0 {
		usageSt.Pending = append([]usageBatch(nil), usageSt.Pending[over:]...)
		log.Printf("usage push: outbox full, dropped %d oldest batches", over)
	}
	if err := saveUsageState(); err != nil {
		log.Printf("usage push: saving state: %v", err)
	}
}

func usageURLHost() string {
	if u, err := url.Parse(USAGE_PUSH_URL); err == nil {
		return u.Host
	}
	return "?"
}

// sendBatch posts one batch. It returns the HTTP status (0 on a transport
// error) and the decoded answer (nil unless a 200 body decoded).
func sendBatch(b usageBatch) (int, *usageAnswer) {
	if b.Peers == nil {
		b.Peers = []usageEntry{}
	}
	body, err := json.Marshal(b)
	if err != nil {
		log.Printf("usage push: encoding batch: %v", err)
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, USAGE_PUSH_URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("usage push: bad request for host %s", usageURLHost())
		return 0, nil
	}
	req.Header.Set("key", API_TOKEN)
	req.Header.Set("Content-Type", "application/json")
	resp, err := usageHTTPClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the url.Error text repeats the full URL
		}
		log.Printf("usage push to %s failed: %v", usageURLHost(), err)
		return 0, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var ans usageAnswer
	if err := json.Unmarshal(data, &ans); err != nil || !ans.OK {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, &ans
}

// pushPending sends the outbox oldest-first, one request per batch. It never
// holds usageMu during HTTP. limits/ok come from the last 200 answer that
// decoded; ok=false leaves the limits unchanged.
func pushPending(now time.Time) (limits []nodeLimit, ok bool) {
	usageMu.Lock()
	batches := append([]usageBatch(nil), usageSt.Pending...)
	usageMu.Unlock()

	stored := true
	if len(batches) == 0 {
		// Heartbeat: lets the master see the node alive and answer limits.
		batches = []usageBatch{{BatchID: newBatchID(), SentAt: now.UTC().Truncate(time.Second), Peers: []usageEntry{}}}
		stored = false
	}

	done := map[string]bool{}
	for _, b := range batches {
		status, ans := sendBatch(b)
		if status == http.StatusOK {
			done[b.BatchID] = true
			if ans != nil {
				limits, ok = ans.Limits, true
			}
			continue
		}
		if status >= 400 && status < 500 && status != 404 && status != 429 {
			log.Printf("usage push: master answered %d, dropped batch %s", status, b.BatchID)
			done[b.BatchID] = true
			continue
		}
		if status != 0 {
			log.Printf("usage push: master answered %d, keeping outbox", status)
		}
		break
	}

	if stored && len(done) > 0 {
		usageMu.Lock()
		kept := usageSt.Pending[:0:0]
		for _, b := range usageSt.Pending {
			if !done[b.BatchID] {
				kept = append(kept, b)
			}
		}
		usageSt.Pending = kept
		if err := saveUsageState(); err != nil {
			log.Printf("usage push: saving state: %v", err)
		}
		usageMu.Unlock()
	}
	return limits, ok
}

// usageTick is one push cycle.
func usageTick(now time.Time) {
	collectUsageLogged()
	sealOpenBatch(now)
	limits, ok := pushPending(now)
	if ok {
		if err := applyLimits(limits); err != nil {
			log.Printf("usage push: applying limits: %v", err)
		}
	}
}

// startUsageLoop ticks right away, then every tick until ctx is done.
func startUsageLoop(ctx context.Context, tick time.Duration) {
	usageTick(time.Now())
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			usageTick(time.Now())
		}
	}
}
