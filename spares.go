package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Spare stock: an optional pool of pre-loaded peers. Each spare is a real
// [Peer] block in the server config (marker "### Spare <name>"), applied to the
// kernel like any client, whose private key is written to a file under
// spareDir() that nobody holds until the spare is claimed. With SPARE_POOL=0
// (default) none of this runs; SPARE_POOL=auto keeps one spare per client.

const (
	clientMarker      = "### Client "
	spareMarker       = "### Spare "
	maxSparesPerApply = 500
)

// SPARE_POOL is the target number of spare peers kept in the server config.
var SPARE_POOL int

// sparePoolAuto (SPARE_POOL=auto) makes the target follow the current client
// count: one ready spare per client, recomputed on every apply.
var sparePoolAuto bool

var clientMarkerRegex = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(clientMarker))

// Result of the most recent syncWireGuardConf; guarded by wgConfigMutex.
var (
	lastApplyOK bool
	lastApplyAt time.Time
)

// Time of the last background reconcile attempt, successful or not; guarded
// by wgConfigMutex.
var lastReconcileAttempt time.Time

// reconcileInterval is the least time between background reconciles.
const reconcileInterval = 10 * time.Minute

type spare struct{ Name, PublicKey string }

// parseSparePool reads the SPARE_POOL setting. Anything that is not a
// non-negative integer becomes 0 with one log line.
func parseSparePool(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Printf("invalid SPARE_POOL value, using 0")
		return 0
	}
	return n
}

// parseSparePoolSetting reads SPARE_POOL: "auto" (any case) turns on the
// client-count target, anything else goes through parseSparePool.
func parseSparePoolSetting(raw string) (int, bool) {
	if strings.EqualFold(strings.TrimSpace(raw), "auto") {
		return 0, true
	}
	return parseSparePool(raw), false
}

// spareTargetFor returns the wanted stock size for conf.
func spareTargetFor(conf []byte) int {
	if sparePoolAuto {
		return len(clientMarkerRegex.FindAllIndex(conf, -1))
	}
	return SPARE_POOL
}

func spareDir() string {
	return filepath.Join(WIREGUARD_CLIENTS, "spare")
}

func sparePath(name string) string {
	return filepath.Join(spareDir(), wgParams.ServerWGNIC+"-client-"+name+".conf")
}

// syncWireGuardConf applies the whole server config to the kernel and records
// whether that worked. Callers hold wgConfigMutex.
func syncWireGuardConf() error {
	err := syncWireGuardConfRun()
	lastApplyOK = err == nil
	if err == nil {
		lastApplyAt = time.Now()
	}
	return err
}

// applyConfigLocked tops the spare stock up (or trims it) and then applies the
// config. A top-up failure is logged and never stops the apply. Caller holds
// wgConfigMutex.
func applyConfigLocked() error {
	if _, _, err := topUpSparesLocked(); err != nil {
		log.Printf("spare top-up failed: %v", err)
	}
	return syncWireGuardConf()
}

// buildClientConfigText returns the client-side config text for a peer.
func buildClientConfigText(ipv4, ipv6 string, keys clientKeys) string {
	endpoint := wgParams.ServerPubIP

	// If IPv6, add brackets if missing
	if strings.Contains(endpoint, ":") && !strings.Contains(endpoint, "[") {
		endpoint = "[" + endpoint + "]"
	}

	endpointPort := wgParams.ServerPort
	if USE_UDP_443_ENDPOINT {
		endpointPort = "443"
	}
	endpoint = endpoint + ":" + endpointPort

	// Format Address line based on provided IP addresses
	var addressParts []string
	if ipv4 != "" {
		addressParts = append(addressParts, ipv4+"/32")
	}
	if ipv6 != "" {
		addressParts = append(addressParts, ipv6+"/128")
	}
	addressLine := fmt.Sprintf("Address = %s", strings.Join(addressParts, ","))

	// Build client config - include AmneziaWG parameters if backend is AmneziaWG.
	// The marker is a comment so legacy parsers continue to accept the config,
	// while clients that support profile selection can identify AWG2 explicitly.
	var interfaceLines []string
	if isModernProfile() {
		interfaceLines = append(interfaceLines, awg2ConfigMarker)
	}
	interfaceLines = append(interfaceLines, fmt.Sprintf("PrivateKey = %s", keys.privateKey))
	interfaceLines = append(interfaceLines, addressLine)
	interfaceLines = append(interfaceLines, fmt.Sprintf("DNS = %s,%s", wgParams.ClientDNS1, wgParams.ClientDNS2))

	// Add AmneziaWG specific parameters if backend is AmneziaWG
	if backendType == "amneziawg" {
		if wgParams.ServerAWGJC != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("Jc = %s", wgParams.ServerAWGJC))
		}
		if wgParams.ServerAWGJMin != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("Jmin = %s", wgParams.ServerAWGJMin))
		}
		if wgParams.ServerAWGJMax != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("Jmax = %s", wgParams.ServerAWGJMax))
		}
		if wgParams.ServerAWGS1 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("S1 = %s", wgParams.ServerAWGS1))
		}
		if wgParams.ServerAWGS2 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("S2 = %s", wgParams.ServerAWGS2))
		}
		if isModernProfile() {
			if wgParams.ServerAWGS3 != "" {
				interfaceLines = append(interfaceLines, fmt.Sprintf("S3 = %s", wgParams.ServerAWGS3))
			}
			if wgParams.ServerAWGS4 != "" {
				interfaceLines = append(interfaceLines, fmt.Sprintf("S4 = %s", wgParams.ServerAWGS4))
			}
		}
		if wgParams.ServerAWGH1 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("H1 = %s", wgParams.ServerAWGH1))
		}
		if wgParams.ServerAWGH2 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("H2 = %s", wgParams.ServerAWGH2))
		}
		if wgParams.ServerAWGH3 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("H3 = %s", wgParams.ServerAWGH3))
		}
		if wgParams.ServerAWGH4 != "" {
			interfaceLines = append(interfaceLines, fmt.Sprintf("H4 = %s", wgParams.ServerAWGH4))
		}
		if isModernProfile() {
			for _, field := range []struct {
				name  string
				value string
			}{
				{name: "I1", value: wgParams.ServerAWGI1},
				{name: "I2", value: wgParams.ServerAWGI2},
				{name: "I3", value: wgParams.ServerAWGI3},
				{name: "I4", value: wgParams.ServerAWGI4},
				{name: "I5", value: wgParams.ServerAWGI5},
			} {
				// Empty I fields are omitted deliberately. This is valid for
				// optional signatures and avoids old tools parsing an empty value.
				if field.value != "" {
					interfaceLines = append(interfaceLines, fmt.Sprintf("%s = %s", field.name, field.value))
				}
			}
		}

		if isAWG3Profile() {
			if wgParams.ServerAWGHeaderProtectionKey != "" {
				interfaceLines = append(interfaceLines,
					fmt.Sprintf("HeaderProtectionKey = %s", wgParams.ServerAWGHeaderProtectionKey))
			}
			for _, field := range []struct {
				name  string
				value string
			}{
				{name: "ContentPaddingAddition", value: wgParams.ServerAWGContentPaddingAddition},
				{name: "RekeyAfterTime", value: wgParams.ServerAWGRekeyAfterTime},
				{name: "RekeyTimeout", value: wgParams.ServerAWGRekeyTimeout},
				{name: "RejectAfterTime", value: wgParams.ServerAWGRejectAfterTime},
				{name: "KeepaliveTimeout", value: wgParams.ServerAWGKeepaliveTimeout},
				{name: "MaxHandshakeAttempts", value: wgParams.ServerAWGMaxHandshakeAttempts},
			} {
				// Unset timing ranges are omitted so the client falls back to
				// its own defaults instead of parsing an empty value.
				if field.value != "" {
					interfaceLines = append(interfaceLines, fmt.Sprintf("%s = %s", field.name, field.value))
				}
			}
		}
	}

	// PersistentKeepalive keeps the client's NAT mapping alive while the
	// phone is locked and idle; without it recovery after unlock is slow.
	return fmt.Sprintf(`[Interface]
%s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, strings.Join(interfaceLines, "\n"),
		wgParams.ServerPubKey, keys.preSharedKey, endpoint, wgParams.AllowedIPs)
}

// buildPeerBlock returns the server-config text for one peer, introduced by
// the given marker ("### Client " or "### Spare ").
func buildPeerBlock(marker, name, ipv4, ipv6 string, keys clientKeys) string {
	var allowedIPsParts []string
	if ipv4 != "" {
		allowedIPsParts = append(allowedIPsParts, ipv4+"/32")
	}
	if ipv6 != "" {
		allowedIPsParts = append(allowedIPsParts, ipv6+"/128")
	}
	allowedIPs := strings.Join(allowedIPsParts, ",")

	return fmt.Sprintf(`
%s%s
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, marker, name, keys.publicKey, keys.preSharedKey, allowedIPs)
}

// isMarkerLine reports whether line starts a client or spare block.
func isMarkerLine(line string) bool {
	return strings.HasPrefix(line, clientMarker) || strings.HasPrefix(line, spareMarker)
}

// spareBlocksLocked lists the spare blocks of a config in file order.
func spareBlocksLocked(conf []byte) []spare {
	var out []spare
	cur := -1
	for _, line := range strings.Split(string(conf), "\n") {
		line = strings.TrimRight(line, "\r")
		if isMarkerLine(line) {
			cur = -1
			if strings.HasPrefix(line, spareMarker) {
				out = append(out, spare{Name: strings.TrimPrefix(line, spareMarker)})
				cur = len(out) - 1
			}
			continue
		}
		if cur >= 0 && out[cur].PublicKey == "" {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "PublicKey" {
				out[cur].PublicKey = strings.TrimSpace(v)
			}
		}
	}
	return out
}

func spareCountLocked() (int, error) {
	conf, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return 0, fmt.Errorf("failed to read WireGuard config: %v", err)
	}
	return len(spareBlocksLocked(conf)), nil
}

// splitBlocks cuts a config into the text before the first marker and one
// chunk per marker block. Blank lines that precede a marker belong to that
// block, so concatenating the pieces gives back the original text.
func splitBlocks(conf string) (header string, blocks []string) {
	lines := strings.SplitAfter(conf, "\n")
	start := -1
	for i, l := range lines {
		if !isMarkerLine(strings.TrimRight(l, "\r\n")) {
			continue
		}
		cut := i
		for cut > 0 && strings.TrimSpace(lines[cut-1]) == "" && cut-1 > start {
			cut--
		}
		if start >= 0 {
			blocks = append(blocks, strings.Join(lines[start:cut], ""))
		} else {
			header = strings.Join(lines[:cut], "")
		}
		start = cut
	}
	if start < 0 {
		return conf, nil
	}
	blocks = append(blocks, strings.Join(lines[start:], ""))
	return header, blocks
}

func blockMarker(block string) string {
	for _, l := range strings.Split(block, "\n") {
		l = strings.TrimRight(l, "\r")
		if isMarkerLine(l) {
			return l
		}
	}
	return ""
}

// removeClientBlocksKeepSpares returns conf without any "### Client " block;
// spare blocks and everything before the first block stay as they are. ok is
// false when there was no client block.
func removeClientBlocksKeepSpares(conf string) (string, bool) {
	header, blocks := splitBlocks(conf)
	found := false
	var spares []string
	for _, b := range blocks {
		if strings.HasPrefix(blockMarker(b), clientMarker) {
			found = true
		} else {
			spares = append(spares, b)
		}
	}
	if !found {
		return conf, false
	}
	// The blank line in front of the first block stays with the header when
	// that block is a client, so a config without spares comes out byte for
	// byte as before.
	if strings.HasPrefix(blockMarker(blocks[0]), clientMarker) {
		header += blocks[0][:len(blocks[0])-len(strings.TrimLeft(blocks[0], "\r\n"))]
	}
	if !strings.HasSuffix(header, "\n") {
		header += "\n"
	}
	var out strings.Builder
	out.WriteString(header)
	for _, b := range spares {
		if !strings.HasSuffix(out.String(), "\n\n") {
			out.WriteString("\n")
		}
		out.WriteString(strings.TrimLeft(b, "\r\n"))
	}
	return out.String(), true
}

func newSpareName(taken map[string]bool) (string, error) {
	for try := 0; try < 20; try++ {
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("failed to generate spare name: %v", err)
		}
		name := "sp" + hex.EncodeToString(raw)
		if taken[name] || fileExists(sparePath(name)) {
			continue
		}
		taken[name] = true
		return name, nil
	}
	return "", fmt.Errorf("could not find a free spare name")
}

var markerNameRegex = regexp.MustCompile(`(?m)^### (?:Client|Spare) (.+?)\r?$`)

// topUpSparesLocked brings the stock of spare peers to SPARE_POOL: it adds at
// most maxSparesPerApply new ones, or trims surplus ones from the end of the
// config. The config is written at most once and is NOT applied; the caller
// applies it. Caller holds wgConfigMutex.
func topUpSparesLocked() (created, trimmed int, err error) {
	conf, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read WireGuard config: %v", err)
	}
	have := spareBlocksLocked(conf)
	target := spareTargetFor(conf)
	if target < 0 {
		target = 0
	}

	switch {
	case len(have) > target:
		return 0, trimSparesLocked(string(conf), len(have)-target), nil
	case len(have) == target:
		return 0, 0, nil
	}

	need := target - len(have)
	if need > maxSparesPerApply {
		need = maxSparesPerApply
	}

	alloc, err := newIPAllocatorLocked()
	if err != nil {
		return 0, 0, err
	}
	taken := make(map[string]bool)
	for _, m := range markerNameRegex.FindAllSubmatch(conf, -1) {
		taken[string(m[1])] = true
	}
	if err := os.MkdirAll(spareDir(), 0700); err != nil {
		return 0, 0, fmt.Errorf("failed to create spare directory: %v", err)
	}

	var blocks bytes.Buffer
	var files []string
	var buildErr error
	for created < need {
		name, err := newSpareName(taken)
		if err != nil {
			buildErr = err
			break
		}
		keys, err := generateClientKeysNative()
		if err != nil {
			buildErr = err
			break
		}
		ipv4, ipv6, err := alloc.next()
		if err != nil {
			buildErr = err
			break
		}
		path := sparePath(name)
		if err := os.WriteFile(path, []byte(buildClientConfigText(ipv4, ipv6, keys)), 0600); err != nil {
			buildErr = fmt.Errorf("failed to write spare client config: %v", err)
			break
		}
		files = append(files, path)
		blocks.WriteString(buildPeerBlock(spareMarker, name, ipv4, ipv6, keys))
		created++
	}

	if created > 0 {
		if err := appendToConf(blocks.Bytes()); err != nil {
			for _, p := range files {
				os.Remove(p)
			}
			return 0, 0, err
		}
	}
	return created, 0, buildErr
}

func appendToConf(data []byte) error {
	f, err := os.OpenFile(WG_CONFIG_FILE, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open server config: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to update server config: %v", err)
	}
	return nil
}

// trimSparesLocked removes the last n spare blocks and their files. It returns
// how many were removed.
func trimSparesLocked(conf string, n int) int {
	header, blocks := splitBlocks(conf)
	var names []string
	kept := make([]string, len(blocks))
	copy(kept, blocks)
	for i := len(kept) - 1; i >= 0 && len(names) < n; i-- {
		m := blockMarker(kept[i])
		if !strings.HasPrefix(m, spareMarker) {
			continue
		}
		names = append(names, strings.TrimPrefix(m, spareMarker))
		kept[i] = ""
	}
	if len(names) == 0 {
		return 0
	}
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(header+strings.Join(kept, "")), 0600); err != nil {
		log.Printf("failed to trim spares from server config: %v", err)
		return 0
	}
	for _, name := range names {
		if err := os.Remove(sparePath(name)); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to remove spare client file: %v", err)
		}
	}
	return len(names)
}

// reconcileSparesOnce brings the spare stock to SPARE_POOL when no write has
// done so. It runs only when the stock differs from the target, the last
// successful apply is at least reconcileInterval old (or there was none since
// start) and the last attempt is at least reconcileInterval old.
func reconcileSparesOnce(now time.Time) (ran bool, err error) {
	return reconcileSpares(now, false)
}

func reconcileSpares(now time.Time, startup bool) (bool, error) {
	// Look without the lock first so an idle node never contends for it.
	conf, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return false, fmt.Errorf("failed to read WireGuard config: %v", err)
	}
	if len(spareBlocksLocked(conf)) == spareTargetFor(conf) {
		return false, nil
	}

	wgConfigMutex.Lock()
	defer wgConfigMutex.Unlock()

	// Another write may have fixed the stock meanwhile.
	conf, err = os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return false, fmt.Errorf("failed to read WireGuard config: %v", err)
	}
	if len(spareBlocksLocked(conf)) == spareTargetFor(conf) {
		return false, nil
	}
	if !startup {
		if !lastApplyAt.IsZero() && now.Sub(lastApplyAt) < reconcileInterval {
			return false, nil
		}
		if !lastReconcileAttempt.IsZero() && now.Sub(lastReconcileAttempt) < reconcileInterval {
			return false, nil
		}
	}
	lastReconcileAttempt = now
	return true, applyConfigLocked()
}

// startSpareLoop reconciles once right away (service start, also the path that
// trims stock after SPARE_POOL is lowered), then every tick until ctx is done.
// Errors are logged; it never exits the process. With SPARE_POOL=0 a failure
// (e.g. an unreadable config) is logged once until a run succeeds again, not
// every tick: with the feature off this loop has nothing to report each minute.
func startSpareLoop(ctx context.Context, tick time.Duration) {
	reported := false
	run := func(startup bool) {
		_, err := reconcileSpares(time.Now(), startup)
		switch {
		case err == nil:
			reported = false
		case SPARE_POOL == 0 && !sparePoolAuto && reported:
			// Already reported once; stay quiet until a run succeeds.
		default:
			log.Printf("spare reconcile failed: %v", err)
			reported = true
		}
	}
	run(true)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run(false)
		}
	}
}
