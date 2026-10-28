package rulesets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func entry(url, format string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"type": "remote", "tag": "cn", "url": url, "format": format, "download_detour": "client-direct"})
	return b
}

func TestSourceConditionalFallbackAndRestart(t *testing.T) {
	body := `{"version":3,"rules":[{"domain_suffix":["example.cn"]}]}`
	fail := false
	var conditional bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "private upstream failure", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("If-None-Match") == `"abc"` {
			conditional = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		w.Write([]byte(body))
	}))
	defer server.Close()
	entries := []json.RawMessage{json.RawMessage(`{"type":"inline","tag":"keep","rules":[{"domain":["local.test"]}]}`), entry(server.URL, "source"), json.RawMessage(`{"type":"local","tag":"disk","path":"test.json"}`)}
	resolved, cache, statuses, err := Resolve(context.Background(), entries, nil, "")
	if err != nil || len(statuses) != 1 || len(resolved) != 3 || string(resolved[0]) != string(entries[0]) || string(resolved[2]) != string(entries[2]) || !strings.Contains(string(resolved[1]), `"type":"inline"`) || !strings.Contains(string(resolved[1]), "example.cn") {
		t.Fatalf("initial resolve: %s, %+v, %v", resolved, statuses, err)
	}
	first := cache["cn"]
	if first.Fingerprint == "" || string(first.Body) != body || first.Status.ChangedAt == "" || first.Status.SucceededAt == "" || first.Status.CheckedAt == "" {
		t.Fatalf("invalid initial cache: %+v", first.Status)
	}
	encoded, _ := json.Marshal(cache)
	var restored map[string]Cache
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	_, updated, statuses, err := Resolve(context.Background(), entries, restored, "")
	if err != nil || !conditional || statuses[0].Stale || statuses[0].ChangedAt != first.Status.ChangedAt || updated["cn"].Status.SucceededAt == "" {
		t.Fatalf("304: %+v, %v", statuses, err)
	}
	fail = true
	resolved, stale, statuses, err := Resolve(context.Background(), entries, updated, "")
	if err != nil || !statuses[0].Stale || statuses[0].Error == "" || strings.Contains(statuses[0].Error, "private") || string(stale["cn"].Rules) != string(first.Rules) || !strings.Contains(string(resolved[1]), "example.cn") {
		t.Fatalf("fallback: %+v, %v", statuses, err)
	}
	changed := []json.RawMessage{entry(server.URL+"?changed=1", "source")}
	resolved, _, _, err = Resolve(context.Background(), changed, stale, "")
	if err == nil || resolved != nil {
		t.Fatal("changed fingerprint used stale rules")
	}
}

func TestMalformedSourceNeverPublished(t *testing.T) {
	malformed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if malformed {
			w.Write([]byte(`{"version":3,"rules":["invalid"]}`))
			return
		}
		w.Write([]byte(`{"version":3,"rules":[{"domain":["valid.test"]}]}`))
	}))
	defer server.Close()
	entries := []json.RawMessage{entry(server.URL, "source")}
	_, cache, _, err := Resolve(context.Background(), entries, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	malformed = true
	resolved, stale, statuses, err := Resolve(context.Background(), entries, cache, "")
	if err != nil || !statuses[0].Stale || !strings.Contains(string(resolved[0]), "valid.test") || string(stale["cn"].Body) != string(cache["cn"].Body) {
		t.Fatalf("malformed source fallback: %s, %+v, %v", resolved, statuses, err)
	}
	resolved, _, _, err = Resolve(context.Background(), entries, nil, "")
	if err == nil || resolved != nil {
		t.Fatalf("malformed source published: %s", resolved)
	}
}

func TestHTTPClientConfigurationRejected(t *testing.T) {
	resolved, _, _, err := Resolve(context.Background(), []json.RawMessage{json.RawMessage(`{"type":"remote","tag":"cn","url":"https://example.com/set.json","format":"source","http_client":{"detour":"proxy"}}`)}, nil, "")
	if err == nil || resolved != nil || !strings.Contains(err.Error(), "http_client") {
		t.Fatalf("unexpected result: %s, %v", resolved, err)
	}
}

func TestBinaryDecompile(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("SUBCOMPOSE_SING_BOX is not set")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "fixture.json")
	compiled := filepath.Join(dir, "fixture.srs")
	if err := os.WriteFile(source, []byte(`{"version":3,"rules":[{"domain_suffix":["example.cn"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "rule-set", "compile", "--output", compiled, source).CombinedOutput(); err != nil {
		t.Fatalf("fixture compilation failed: %s: %v", output, err)
	}
	body, err := os.ReadFile(compiled)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer server.Close()
	resolved, cache, _, err := Resolve(context.Background(), []json.RawMessage{entry(server.URL, "binary")}, nil, binary)
	if err != nil || !strings.Contains(string(resolved[0]), "example.cn") || string(cache["cn"].Body) != string(body) {
		t.Fatalf("binary resolve: %s, %v", resolved, err)
	}
}
