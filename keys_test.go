package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestAddPathsGenerateKeysInProcess(t *testing.T) {
	env := setupTestEnv(t)

	if w := env.authedRequest(t, http.MethodPost, "/api/users/add-bulk", map[string]any{"names": []string{"kb1", "kb2", "kb3"}}); w.Code != http.StatusOK {
		t.Fatalf("add-bulk: %d %s", w.Code, w.Body.String())
	}
	if w := env.authedRequest(t, http.MethodPost, "/api/users/add", map[string]any{"name": "ks1"}); w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}

	for _, l := range invocationLines(t, env) {
		if l == "genkey" || l == "pubkey" || l == "genpsk" {
			t.Fatalf("key generation must not spawn %q; invocations: %v", l, invocationLines(t, env))
		}
	}

	conf := env.configContent(t)
	n := 0
	for _, line := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "PublicKey" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil || len(raw) != 32 {
			t.Errorf("peer public key %q is not 32 base64 bytes (err %v)", strings.TrimSpace(v), err)
		}
		n++
	}
	if n != 4 {
		t.Errorf("want 4 peers with public keys, got %d", n)
	}
}
