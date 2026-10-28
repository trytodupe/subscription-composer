package refresh

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestInlineRuleSetsPersistAndFallbackAcrossRestart(t *testing.T) {
	var unavailable atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes" {
			_, _ = w.Write([]byte(linkA))
			return
		}
		if unavailable.Load() {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.cn"]}]}`))
	}))
	defer srv.Close()
	cfg := testConfig(t.TempDir(), model.Source{ID: "airport", URL: srv.URL + "/nodes"})
	asset, _ := json.Marshal(map[string]any{"type": "remote", "tag": "cn", "format": "source", "url": srv.URL + "/rules.json"})
	cfg.Policy.RuleSets = []json.RawMessage{asset}
	cfg.Policy.DirectRuleSets = []string{"cn"}
	m := newManager(t, cfg)
	refreshOK(t, m, true)
	profile, _ := m.Profile("first")
	if bytes.Contains(profile, []byte(srv.URL)) || !bytes.Contains(profile, []byte(`"type":"inline"`)) {
		t.Fatal("published config still depends on remote assets")
	}
	revision := m.Status().Revision
	unavailable.Store(true)
	restarted := newManager(t, cfg)
	refreshOK(t, restarted, true)
	if restarted.Status().Revision != revision {
		t.Fatal("asset outage changed published content")
	}
	found := false
	for _, status := range restarted.Status().Sources {
		if status.ID == "ruleset:cn" {
			found = true
			if !status.Stale {
				t.Fatal("asset fallback not marked stale")
			}
		}
	}
	if !found {
		t.Fatal("rule-set status missing")
	}
}

func TestMissingRuleSetPreventsInitialPublication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes" {
			_, _ = w.Write([]byte(linkA))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	cfg := testConfig(t.TempDir(), model.Source{ID: "airport", URL: srv.URL + "/nodes"})
	asset, _ := json.Marshal(map[string]any{"type": "remote", "tag": "cn", "format": "source", "url": srv.URL + "/missing.json"})
	cfg.Policy.RuleSets = []json.RawMessage{asset}
	m := newManager(t, cfg)
	if err := m.Refresh(context.Background(), true); err == nil {
		t.Fatal("missing initial rule set was published")
	}
	if _, ok := m.Profile("first"); ok {
		t.Fatal("partial generation was published")
	}
}
