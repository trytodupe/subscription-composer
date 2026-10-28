package rulesets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExplicitRuleSetIntervalReusesFreshValidatedAsset(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.cn"]}]}`))
	}))
	defer server.Close()
	entry, _ := json.Marshal(map[string]any{"type": "remote", "tag": "cn", "url": server.URL, "format": "source", "update_interval": "24h"})
	_, cache, first, err := Resolve(context.Background(), []json.RawMessage{entry}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, second, err := Resolve(context.Background(), []json.RawMessage{entry}, cache, "")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || first[0].CheckedAt != second[0].CheckedAt {
		t.Fatal("fresh static asset was re-fetched or falsely marked as newly checked")
	}
	asset := cache["cn"]
	asset.Status.SucceededAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano)
	cache["cn"] = asset
	if _, _, _, err := Resolve(context.Background(), []json.RawMessage{entry}, cache, ""); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatal("expired asset was not checked upstream")
	}
}

func TestRuleSetIntervalDaysAndInvalidDurations(t *testing.T) {
	if d, err := updateInterval("1d"); err != nil || d != 24*time.Hour {
		t.Fatal("native day duration was not accepted")
	}
	for _, value := range []string{"NaNd", "+Infd", "1e100d", "invalid", "0d"} {
		if d, err := updateInterval(value); err == nil && d > 0 {
			t.Fatalf("invalid interval accepted: %s", value)
		}
	}
}
