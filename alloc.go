package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ipAllocator hands out IPv4/IPv6 pairs for a whole batch of new peers while
// reading WG_CONFIG_FILE only once. It follows the same rules as
// getNextAvailableIPv4 / getNextAvailableIPv6 (lowest free address first, /16
// base, host 1..254 per block, IPv6 parts 2..0xfffe, IPv6 skipped when the
// server has no IPv6 address). Like those functions it reads the live config,
// so it MUST be built with wgConfigMutex held and used until that lock is
// released.
type ipAllocator struct {
	v4Base string
	v4Used map[string]bool
	v4Next int // next candidate index into the /16 host space (c*254 + h-1)

	v6Enabled bool
	v6Base    string
	v6Used    map[int]bool
	v6Next    int
}

func newIPAllocatorLocked() (*ipAllocator, error) {
	parts := strings.Split(wgParams.ServerWGIPv4, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid server IPv4 address format")
	}
	a := &ipAllocator{
		v4Base: fmt.Sprintf("%s.%s", parts[0], parts[1]),
		v4Used: make(map[string]bool),
	}

	var v6Parts []string
	if wgParams.ServerWGIPv6 != "" {
		v6Parts = strings.Split(wgParams.ServerWGIPv6, "::")
		if len(v6Parts) != 2 {
			return nil, fmt.Errorf("invalid server IPv6 address format")
		}
		a.v6Enabled = true
		a.v6Base = v6Parts[0]
		a.v6Used = make(map[int]bool)
		a.v6Next = 2
	}

	content, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		return nil, fmt.Errorf("failed to read WireGuard config: %v", err)
	}

	ipv4Regex := regexp.MustCompile(regexp.QuoteMeta(a.v4Base) + `\.\d{1,3}\.\d{1,3}`)
	for _, ip := range ipv4Regex.FindAllString(string(content), -1) {
		a.v4Used[ip] = true
	}
	a.v4Used[wgParams.ServerWGIPv4] = true

	if a.v6Enabled {
		ipv6Regex := regexp.MustCompile(regexp.QuoteMeta(a.v6Base) + `::([\da-fA-F]+)`)
		for _, match := range ipv6Regex.FindAllStringSubmatch(string(content), -1) {
			if len(match) == 2 {
				var part int
				fmt.Sscanf(match[1], "%x", &part)
				a.v6Used[part] = true
			}
		}
	}
	return a, nil
}

// next returns the lowest free address pair and marks it used. ipv6 is empty
// when the server has no IPv6 address.
func (a *ipAllocator) next() (ipv4, ipv6 string, err error) {
	const perBlock = 254
	for ; a.v4Next < 256*perBlock; a.v4Next++ {
		ip := fmt.Sprintf("%s.%d.%d", a.v4Base, a.v4Next/perBlock, a.v4Next%perBlock+1)
		if !a.v4Used[ip] {
			ipv4 = ip
			break
		}
	}
	if ipv4 == "" {
		return "", "", fmt.Errorf("no available IPv4 addresses in the subnet")
	}

	if a.v6Enabled {
		for ; a.v6Next <= 0xfffe; a.v6Next++ {
			if !a.v6Used[a.v6Next] {
				ipv6 = fmt.Sprintf("%s::%x", a.v6Base, a.v6Next)
				break
			}
		}
		if ipv6 == "" {
			return "", "", fmt.Errorf("no available IPv6 addresses in the subnet")
		}
	}

	// Commit only once both families succeeded.
	a.v4Used[ipv4] = true
	if a.v6Enabled {
		a.v6Used[a.v6Next] = true
	}
	return ipv4, ipv6, nil
}

// generateClientKeysNative produces the same key material as
// generateClientKeys without spawning wg/awg: X25519 private/public pair and a
// 32-byte pre-shared key, all base64 (std encoding).
func generateClientKeysNative() (clientKeys, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return clientKeys{}, fmt.Errorf("failed to generate private key: %v", err)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return clientKeys{}, fmt.Errorf("failed to generate preshared key: %v", err)
	}
	enc := base64.StdEncoding
	return clientKeys{
		privateKey:   enc.EncodeToString(priv.Bytes()),
		publicKey:    enc.EncodeToString(priv.PublicKey().Bytes()),
		preSharedKey: enc.EncodeToString(psk),
	}, nil
}
