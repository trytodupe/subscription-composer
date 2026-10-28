package refresh

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestSourceDNSUpdateAndSnapshotFallback(t *testing.T) {
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resolver := "https://first-dns.example/dns-query"
		switch mode.Load() {
		case 1:
			resolver = "https://second-dns.example/dns-query"
		case 2:
			resolver = "http://private-invalid.example/dns-query"
		}
		_, _ = fmt.Fprintf(w, `proxies:
  - {name: JP One, type: ss, server: gateway.entry.example, port: 8388, cipher: aes-256-gcm, password: test-only}
x-client-custom:
  nameserver-policy:
    '+.entry.example': [%q]
`, resolver)
	}))
	defer server.Close()
	cfg := testConfig(t.TempDir(), model.Source{ID: "airport", URL: server.URL, Format: "clash"})
	manager := newManager(t, cfg)
	refreshOK(t, manager, true)
	first, _ := manager.Profile("first")
	firstRevision := manager.Status().Revision
	if !strings.Contains(string(first), "first-dns.example") || !strings.Contains(string(first), `"domain_resolver":"node-dns-`) {
		t.Fatal("source DNS policy did not reach the published profile")
	}
	mode.Store(1)
	refreshOK(t, manager, true)
	second, _ := manager.Profile("first")
	if manager.Status().Revision == firstRevision || !strings.Contains(string(second), "second-dns.example") || strings.Contains(string(second), "first-dns.example") {
		t.Fatal("source DNS update did not replace the old resolver atomically")
	}
	if !strings.Contains(string(second), "airport / JP One") || !strings.Contains(string(second), "gateway.entry.example") {
		t.Fatal("DNS rotation changed node identity or hostname")
	}
	mode.Store(2)
	refreshOK(t, manager, true)
	fallback, _ := manager.Profile("first")
	status := manager.Status()
	if !bytes.Equal(fallback, second) || !status.Sources[0].Stale || strings.Contains(status.Sources[0].Error, "private-invalid.example") {
		t.Fatal("invalid DNS policy did not retain the last valid source safely")
	}
	restarted := newManager(t, cfg)
	refreshOK(t, restarted, true)
	restored, _ := restarted.Profile("first")
	if !bytes.Equal(restored, second) || !restarted.Status().Sources[0].Stale {
		t.Fatal("snapshot fallback lost the source DNS policy after restart")
	}
}
