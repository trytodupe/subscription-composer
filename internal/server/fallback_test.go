package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProfileFallsBackWithExplicitStaleHeaders(t *testing.T) {
	var offline atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() {
			http.Error(w, "upstream failure", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"type":"shadowsocks","tag":"JP One","server":"198.51.100.1","server_port":8388,"method":"aes-256-gcm","password":"secret"}`))
	}))
	defer up.Close()
	h := testService(t, up.URL)
	first := request(h, "GET", "/profiles/phone.json", true)
	if first.Code != http.StatusOK || first.Header().Get("X-Config-Stale") != "false" {
		t.Fatal("first profile did not publish fresh data")
	}
	offline.Store(true)
	fallback := request(h, "GET", "/profiles/phone.json?refresh=force", true)
	if fallback.Code != http.StatusOK || fallback.Header().Get("X-Config-Stale") != "true" {
		t.Fatal("failed upstream did not return an explicit stale snapshot")
	}
	if fallback.Body.String() != first.Body.String() || fallback.Header().Get("X-Config-Revision") != first.Header().Get("X-Config-Revision") {
		t.Fatal("fallback changed the last valid configuration")
	}
}
