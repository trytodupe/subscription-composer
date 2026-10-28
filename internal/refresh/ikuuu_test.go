package refresh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
	"github.com/ttd/subscription-composer/internal/model"
)

func TestIkUUUAuthorizedSourceAndRevocationFallback(t *testing.T) {
	var revoked atomic.Bool
	var profiles, refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer test-app-token" {
			t.Error("app source did not use stored bearer credential")
		}
		if r.URL.Path == "/api/v2/client-auth/refresh-app-token" {
			refreshes.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"code":"TOKEN_INVALID"}`))
			return
		}
		if r.URL.Path != "/api/v2/nodes/profile" {
			t.Error("app source fetched the API base instead of profile endpoint")
			http.NotFound(w, r)
			return
		}
		profiles.Add(1)
		if revoked.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"code":"TOKEN_INVALID"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "SUCCESS", "data": map[string]any{
			"user_id": "test-user",
			"profile": "proxies:\n  - {name: JP One, type: ss, server: jp.entry.test, port: 8388, cipher: aes-256-gcm, password: test-only}\nx-client-custom:\n  nameserver-policy:\n    '+.entry.test': ['https://provider-dns.test/dns-query', 'tcp://provider-dns.test:54#cost-bias=+100ms']\n",
		}})
	}))
	defer server.Close()
	base := server.URL + "/api/v2"
	cfg := testConfig(t.TempDir(), model.Source{ID: "account", Type: "ikuuu", URL: base, Format: "clash"})
	manager := newManager(t, cfg)
	store, err := authstate.New(filepath.Join(cfg.SnapshotDir, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save("account", authstate.Session{AppToken: "test-app-token", APIBaseURL: base, ExpiresAt: time.Now().Add(48 * time.Hour).Unix(), DeviceID: "test-device", DeviceName: "Test"}); err != nil {
		t.Fatal(err)
	}
	refreshOK(t, manager, true)
	if profiles.Load() != 1 || refreshes.Load() != 0 {
		t.Fatal("fresh credential unexpectedly refreshed or failed to fetch profile")
	}
	initial := manager.Status().Revision
	body, _ := manager.Profile("first")
	if !strings.Contains(string(body), "account / JP One") || !strings.Contains(string(body), "provider-dns.test") || !strings.Contains(string(body), `"domain_resolver":"node-dns-`) {
		t.Fatal("official YAML profile or its node DNS policy was not converted")
	}
	revoked.Store(true)
	if err := manager.Refresh(context.Background(), true); err != nil {
		t.Fatal("last valid nodes should survive revoked authorization", err)
	}
	status := manager.Status()
	if status.Revision != initial || !status.Sources[0].Stale || !strings.Contains(status.Sources[0].Error, "login required") {
		t.Fatal("revoked authorization did not retain previous config with actionable status")
	}
	if refreshes.Load() != 1 {
		t.Fatal("authorization failure did not use exactly one refresh attempt")
	}
}
