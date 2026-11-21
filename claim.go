package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// ClaimResult is the outcome of one requested name in POST /api/users/claim.
type ClaimResult struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Status  string `json:"status"` // claimed, created, existing, error
	Message string `json:"message,omitempty"`
	IPV4    string `json:"ipv4,omitempty"`
	IPV6    string `json:"ipv6,omitempty"`
	Config  string `json:"config,omitempty"`
}

const (
	claimStatusClaimed  = "claimed"
	claimStatusCreated  = "created"
	claimStatusExisting = "existing"
	claimStatusError    = "error"
)

func clientFilePath(name string) string {
	return filepath.Join(WIREGUARD_CLIENTS, wgParams.ServerWGNIC+"-client-"+name+".conf")
}

// existingClientConfig reads the client file of a name clientExists reported
// as taken, trying the same file name patterns clientExists checks.
func existingClientConfig(name string) (string, error) {
	paths := []string{
		clientFilePath(name),
		filepath.Join(WIREGUARD_CLIENTS, "wg0-client-"+name+".conf"),
		filepath.Join(WIREGUARD_CLIENTS, "awg0-client-"+name+".conf"),
		filepath.Join(WIREGUARD_CLIENTS, name+".conf"),
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("client exists but its config file cannot be read")
}

// blockAddresses returns the IPv4 and IPv6 address (without prefix length) of
// a peer block's AllowedIPs line.
func blockAddresses(block string) (ipv4, ipv6 string) {
	for _, line := range strings.Split(block, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok || strings.TrimSpace(k) != "AllowedIPs" {
			continue
		}
		for _, part := range strings.Split(v, ",") {
			addr, _, _ := strings.Cut(strings.TrimSpace(part), "/")
			switch {
			case addr == "":
			case strings.Contains(addr, ":"):
				ipv6 = addr
			default:
				ipv4 = addr
			}
		}
	}
	return ipv4, ipv6
}

// claimUsersHandlerGin hands out client configs for a list of names, using
// spare peers that are already loaded in the kernel when it can. A claimed
// spare only has its comment line changed, so serving from stock needs no
// syncconf. Names the stock cannot cover are created like add-bulk does, with
// one apply for all of them (which also refills the stock).
func claimUsersHandlerGin(c *gin.Context) {
	var req AddUsersBulkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request payload"})
		return
	}
	if msg := validateBulkNames(req.Names); msg != "" {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Message: msg})
		return
	}

	results, status, errMsg := claimLocked(req.Names)
	counts := map[string]int{}
	for _, r := range results {
		if r.Success {
			counts[r.Status]++
		} else {
			counts[claimStatusError]++
		}
	}
	data := gin.H{
		"claimed":  counts[claimStatusClaimed],
		"created":  counts[claimStatusCreated],
		"existing": counts[claimStatusExisting],
		"failed":   counts[claimStatusError],
		"results":  results,
	}
	if status != http.StatusOK {
		c.JSON(status, APIResponse{Success: false, Message: errMsg, Data: data})
		return
	}
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Claimed %d, created %d, existing %d, failed %d of %d clients",
			counts[claimStatusClaimed], counts[claimStatusCreated], counts[claimStatusExisting],
			counts[claimStatusError], len(req.Names)),
		Data: data,
	})
}

// claimLocked does the work of one claim request under a single
// wgConfigMutex hold. It returns the per-name results and the HTTP status to
// answer with (with a message when that is not 200).
func claimLocked(names []string) ([]ClaimResult, int, string) {
	wgConfigMutex.Lock()
	defer wgConfigMutex.Unlock()

	// A spare written by an apply that failed (or never ran since start) may
	// not be in the kernel; it must never be handed out.
	if !lastApplyOK {
		if err := applyConfigLocked(); err != nil {
			log.Printf("claim: config apply before serving failed: %v", err)
			return nil, http.StatusInternalServerError, fmt.Sprintf("failed to apply config before claiming: %v", err)
		}
	}

	confBytes, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Sprintf("failed to read WireGuard config: %v", err)
	}
	header, blocks := splitBlocks(string(confBytes))
	var spareIdx []int // indexes into blocks, file order
	for i, b := range blocks {
		if strings.HasPrefix(blockMarker(b), spareMarker) {
			spareIdx = append(spareIdx, i)
		}
	}

	if err := os.MkdirAll(WIREGUARD_CLIENTS, 0700); err != nil {
		return nil, http.StatusInternalServerError, fmt.Sprintf("failed to create clients directory: %v", err)
	}

	results := make([]ClaimResult, len(names))
	type move struct {
		from, to string
		old      []byte
	}
	var moves []move
	var leftovers []int // indexes into names
	relabelled := false

	rollback := func() {
		for _, m := range moves {
			if err := os.WriteFile(m.from, m.old, 0600); err != nil {
				log.Printf("claim: rollback of a client file move failed: %v", err)
			}
			os.Remove(m.to)
		}
	}

	for i, name := range names {
		exists, err := clientExists(name)
		if err != nil {
			for j := i; j < len(names); j++ {
				results[j] = ClaimResult{Name: names[j], Status: claimStatusError, Message: err.Error()}
			}
			break
		}
		if exists {
			cfg, err := existingClientConfig(name)
			if err != nil {
				results[i] = ClaimResult{Name: name, Status: claimStatusError, Message: err.Error()}
				continue
			}
			results[i] = ClaimResult{Name: name, Success: true, Status: claimStatusExisting, Config: cfg}
			continue
		}

		claimed := false
		for len(spareIdx) > 0 && !claimed {
			idx := spareIdx[0]
			spareIdx = spareIdx[1:]
			spareName := strings.TrimPrefix(strings.TrimRight(blockMarker(blocks[idx]), "\r"), spareMarker)
			from, to := sparePath(spareName), clientFilePath(name)
			oldBytes, err := os.ReadFile(from)
			if err != nil {
				// A spare without its file cannot be handed out; leave it.
				log.Printf("claim: skipping a spare whose client file cannot be read: %v", err)
				continue
			}
			// Rebuild the client text from the current settings, so a claimed
			// config is as fresh as a created one. The key material is the
			// spare's own.
			keys := clientKeys{
				privateKey:   interfacePrivateKey(string(oldBytes)),
				publicKey:    blockValue(blocks[idx], "PublicKey"),
				preSharedKey: blockValue(blocks[idx], "PresharedKey"),
			}
			if keys.privateKey == "" || keys.publicKey == "" || keys.preSharedKey == "" {
				log.Printf("claim: skipping a spare with incomplete key material")
				continue
			}
			ipv4, ipv6 := blockAddresses(blocks[idx])
			cfgBytes := []byte(buildClientConfigText(ipv4, ipv6, keys))
			if err := os.WriteFile(to, cfgBytes, 0600); err != nil {
				log.Printf("claim: skipping a spare whose client file cannot be written: %v", err)
				continue
			}
			if err := os.Remove(from); err != nil {
				os.Remove(to)
				log.Printf("claim: skipping a spare whose client file cannot be removed: %v", err)
				continue
			}
			moves = append(moves, move{from: from, to: to, old: oldBytes})
			blocks[idx] = strings.Replace(blocks[idx], spareMarker+spareName, clientMarker+name, 1)
			relabelled = true
			claimed = true
			results[i] = ClaimResult{
				Name: name, Success: true, Status: claimStatusClaimed,
				IPV4: ipv4, IPV6: ipv6, Config: string(cfgBytes),
			}
		}
		if !claimed {
			leftovers = append(leftovers, i)
		}
	}

	if relabelled {
		if err := os.WriteFile(WG_CONFIG_FILE, []byte(header+strings.Join(blocks, "")), 0600); err != nil {
			rollback()
			return nil, http.StatusInternalServerError, fmt.Sprintf("failed to update server config: %v", err)
		}
	}

	if len(leftovers) > 0 {
		var createdIdx []int
		alloc, err := newIPAllocatorLocked()
		for _, i := range leftovers {
			name := names[i]
			if err != nil {
				results[i] = ClaimResult{Name: name, Status: claimStatusError, Message: err.Error()}
				continue
			}
			keys, kerr := generateClientKeysNative()
			if kerr != nil {
				results[i] = ClaimResult{Name: name, Status: claimStatusError, Message: kerr.Error()}
				continue
			}
			ipv4, ipv6, aerr := alloc.next()
			if aerr != nil {
				// Pool exhausted: the rest would fail the same way.
				err = aerr
				results[i] = ClaimResult{Name: name, Status: claimStatusError, Message: aerr.Error()}
				continue
			}
			cfg, cerr := createWireGuardClientLocked(name, ipv4, ipv6, keys)
			if cerr != nil {
				results[i] = ClaimResult{Name: name, Status: claimStatusError, Message: cerr.Error()}
				continue
			}
			results[i] = ClaimResult{Name: name, Success: true, Status: claimStatusCreated, IPV4: ipv4, IPV6: ipv6, Config: cfg}
			createdIdx = append(createdIdx, i)
		}

		if len(createdIdx) > 0 {
			if applyErr := applyConfigLocked(); applyErr != nil {
				log.Printf("claim: created %d clients but failed to apply config: %v", len(createdIdx), applyErr)
				ok := 0
				for _, r := range results {
					if r.Success {
						ok++
					}
				}
				for _, i := range createdIdx {
					results[i] = ClaimResult{
						Name: names[i], Status: claimStatusError,
						Message: fmt.Sprintf("failed to apply config: %v", applyErr),
					}
				}
				if ok == len(createdIdx) {
					return results, http.StatusInternalServerError,
						fmt.Sprintf("created %d clients but failed to apply config: %v", len(createdIdx), applyErr)
				}
			}
		}
	}

	return results, http.StatusOK, ""
}

// blockValue returns the value of the first "<key> = value" line of a block.
func blockValue(block, key string) string {
	for _, line := range strings.Split(block, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// interfacePrivateKey returns the PrivateKey line of a client config.
func interfacePrivateKey(conf string) string {
	return blockValue(conf, "PrivateKey")
}
