package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

const allocFixture = `[Interface]
Address = 10.66.0.1/16
ListenPort = 51820
PrivateKey = server-private-key

### Client a
[Peer]
PublicKey = pub-a
AllowedIPs = 10.66.0.2/32

### Client b
[Peer]
PublicKey = pub-b
AllowedIPs = 10.66.0.4/32

### Client c
[Peer]
PublicKey = pub-c
AllowedIPs = 10.66.0.5/32
`

func TestIPAllocatorMatchesSingleAllocator(t *testing.T) {
	setupTestEnv(t)
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(allocFixture), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := newIPAllocatorLocked()
	if err != nil {
		t.Fatalf("newIPAllocatorLocked: %v", err)
	}
	var got []string
	for i := 0; i < 3; i++ {
		v4, v6, err := a.next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if v6 != "" {
			t.Fatalf("unexpected ipv6 %q with IPv6 disabled", v6)
		}
		got = append(got, v4)
	}

	// Reference: three rounds of the single allocator, appending each result.
	var want []string
	for i := 0; i < 3; i++ {
		ip, err := getNextAvailableIPv4()
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, ip)
		f, err := os.OpenFile(WG_CONFIG_FILE, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(f, "\n[Peer]\nAllowedIPs = %s/32\n", ip)
		f.Close()
	}

	expected := []string{"10.66.0.3", "10.66.0.6", "10.66.0.7"}
	for i := range expected {
		if want[i] != expected[i] || got[i] != expected[i] {
			t.Fatalf("allocation %d: batch=%s single=%s expected=%s", i, got[i], want[i], expected[i])
		}
	}
}

func TestIPAllocatorSkipsBlockEdges(t *testing.T) {
	setupTestEnv(t)
	cfg := "[Interface]\nAddress = 10.66.0.1/16\n"
	for h := 2; h <= 254; h++ {
		cfg += fmt.Sprintf("AllowedIPs = 10.66.0.%d/32\n", h)
	}
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := newIPAllocatorLocked()
	if err != nil {
		t.Fatal(err)
	}
	v4, _, err := a.next()
	if err != nil || v4 != "10.66.1.1" {
		t.Fatalf("got %q, %v; want 10.66.1.1 (skips .255 and .0)", v4, err)
	}
}

func TestIPAllocatorIPv6(t *testing.T) {
	setupTestEnv(t)
	old := wgParams.ServerWGIPv6
	wgParams.ServerWGIPv6 = "fd42:42:42::1"
	t.Cleanup(func() { wgParams.ServerWGIPv6 = old })

	cfg := allocFixture + "\n[Peer]\nAllowedIPs = 10.66.0.9/32, fd42:42:42::2/128, fd42:42:42::4/128\n"
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := newIPAllocatorLocked()
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{
		{"10.66.0.3", "fd42:42:42::3"},
		{"10.66.0.6", "fd42:42:42::5"},
		{"10.66.0.7", "fd42:42:42::6"},
	}
	for i, w := range want {
		v4, v6, err := a.next()
		if err != nil {
			t.Fatal(err)
		}
		if v4 != w[0] || v6 != w[1] {
			t.Fatalf("allocation %d: got %s %s, want %s %s", i, v4, v6, w[0], w[1])
		}
	}

	// Single allocator agrees on the first free v6 part for the same file.
	single, err := getNextAvailableIPv6()
	if err != nil || single != "fd42:42:42::3" {
		t.Fatalf("single allocator got %q, %v", single, err)
	}
}

func TestIPAllocatorReadsConfigOnce(t *testing.T) {
	setupTestEnv(t)
	if err := os.WriteFile(WG_CONFIG_FILE, []byte(allocFixture), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := newIPAllocatorLocked()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WG_CONFIG_FILE, []byte("garbage \x00 not a config"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := a.next(); err != nil {
			t.Fatalf("next after config replaced: %v", err)
		}
	}
}

func TestNativeKeysAreValidX25519(t *testing.T) {
	k1, err := generateClientKeysNative()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(k1.privateKey)
	if err != nil {
		t.Fatalf("private key not base64: %v", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("private key not X25519: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()); got != k1.publicKey {
		t.Fatal("public key does not match private key")
	}
	psk, err := base64.StdEncoding.DecodeString(k1.preSharedKey)
	if err != nil || len(psk) != 32 {
		t.Fatalf("preshared key must be 32 base64 bytes, got len %d err %v", len(psk), err)
	}

	k2, err := generateClientKeysNative()
	if err != nil {
		t.Fatal(err)
	}
	if k1.privateKey == k2.privateKey || k1.publicKey == k2.publicKey || k1.preSharedKey == k2.preSharedKey {
		t.Fatal("two calls returned overlapping key material")
	}
}

// Private keys come out clamped, byte for byte like `wg genkey`.
func TestNativePrivateKeysAreClamped(t *testing.T) {
	for i := 0; i < 64; i++ {
		k, err := generateClientKeysNative()
		if err != nil {
			t.Fatal(err)
		}
		priv, err := base64.StdEncoding.DecodeString(k.privateKey)
		if err != nil || len(priv) != 32 {
			t.Fatalf("private key must be 32 base64 bytes, got len %d err %v", len(priv), err)
		}
		if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
			t.Fatalf("private key %d is not clamped: first byte %08b, last byte %08b", i, priv[0], priv[31])
		}
		key, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if got := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()); got != k.publicKey {
			t.Fatal("public key does not match the clamped private key")
		}
	}
}
