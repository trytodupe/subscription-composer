package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/refresh"
)

const testToken = "a-device-specific-token-at-least-24-bytes"

func testService(t *testing.T, sourceURL string) http.Handler {
	t.Helper()
	cfg := model.Config{SnapshotDir: t.TempDir(), Debounce: "1h", RefreshTimeout: "2s", Sources: []model.Source{{ID: "airport", URL: sourceURL}}, Devices: []model.Device{{ID: "phone", Platform: "android", Token: testToken, Base: json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}]}`)}}}
	m, err := refresh.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return New(m, cfg.Devices)
}

func request(h http.Handler, method, path string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if auth {
		r.SetBasicAuth("phone", testToken)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthenticatedProfileRefreshAndForce(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"type":"shadowsocks","tag":"JP One","server":"198.51.100.1","server_port":8388,"method":"aes-256-gcm","password":"secret"}`))
	}))
	defer up.Close()
	h := testService(t, up.URL)
	if got := request(h, "GET", "/profiles/phone.json", false).Code; got != 401 {
		t.Fatalf("unauthenticated status=%d", got)
	}
	if hits.Load() != 0 {
		t.Fatal("unauthenticated request reached upstream")
	}
	first := request(h, "GET", "/profiles/phone.json", true)
	if first.Code != 200 || first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("X-Config-Revision") == "" {
		t.Fatalf("initial request failed: %d %s", first.Code, first.Body.String())
	}
	if got := request(h, "GET", "/profiles/phone.json", true).Code; got != 200 {
		t.Fatalf("debounced request=%d", got)
	}
	if hits.Load() != 1 {
		t.Fatal("debounce did not reuse upstream check")
	}
	if got := request(h, "POST", "/profiles/phone/refresh", true).Code; got != 200 {
		t.Fatalf("forced request=%d", got)
	}
	if hits.Load() != 2 {
		t.Fatal("force did not refetch upstream")
	}
	wrong := httptest.NewRequest("GET", "/profiles/phone.json", nil)
	wrong.SetBasicAuth("other", testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wrong)
	if w.Code != 401 {
		t.Fatal("basic username was not bound to device")
	}
	bearer := httptest.NewRequest("GET", "/profiles/phone/status", nil)
	bearer.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, bearer)
	if w.Code != 200 || strings.Contains(w.Body.String(), testToken) || strings.Contains(w.Body.String(), "198.51.100.1") {
		t.Fatal("status failed or exposed node credentials")
	}
}

func TestUnavailableProfileIsExplicit(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "private-upstream-body", 502) }))
	defer up.Close()
	h := testService(t, up.URL)
	w := request(h, "GET", "/profiles/phone.json", true)
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-upstream-body") {
		t.Fatalf("unavailable profile status=%d", w.Code)
	}
	if got := request(h, "GET", "/profiles/phone/refresh", true); got.Code != 405 || got.Header().Get("Allow") != "POST" {
		t.Fatal("force endpoint should require POST")
	}
}
