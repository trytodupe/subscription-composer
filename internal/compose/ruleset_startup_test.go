package compose

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/rulesets"
)

// Live startup complements schema checks: remote assets must actually exist.
func TestNativeExampleRuleSetDownloads(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" || os.Getenv("SUBCOMPOSE_NETWORK_TEST") != "1" {
		t.Skip("set SUBCOMPOSE_SING_BOX and SUBCOMPOSE_NETWORK_TEST=1 for live rule-set startup")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var service model.Config
	if err := json.Unmarshal(data, &service); err != nil {
		t.Fatal(err)
	}
	assetCtx, assetCancel := context.WithTimeout(context.Background(), 20*time.Second)
	resolved, _, statuses, err := rulesets.Resolve(assetCtx, service.Policy.RuleSets, nil, binary)
	assetCancel()
	if err != nil {
		t.Fatalf("live rule-set preparation failed: %v", err)
	}
	if len(statuses) != len(service.Policy.RuleSets) {
		t.Fatalf("expected %d checked rule sets, got %d", len(service.Policy.RuleSets), len(statuses))
	}
	for _, status := range statuses {
		if status.Stale {
			t.Fatal("live test unexpectedly used cached rule sets")
		}
	}
	service.Policy.RuleSets = resolved
	device := service.Devices[0]
	base := decode(t, device.Base)
	base["inbounds"] = []any{}
	delete(base, "endpoints")
	dns := base["dns"].(map[string]any)
	var servers []any
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		if server["type"] != "tailscale" {
			servers = append(servers, server)
		}
	}
	dns["servers"] = servers
	for _, owner := range []map[string]any{dns, base["route"].(map[string]any)} {
		var rules []any
		for _, raw := range owner["rules"].([]any) {
			rule := raw.(map[string]any)
			if _, isTailnet := rule["preferred_by"]; !isTailnet {
				rules = append(rules, rule)
			}
		}
		owner["rules"] = rules
	}
	base["log"] = map[string]any{"level": "info"}
	device.Base, err = json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	content, err := Build(device, service.Policy, []model.Node{{
		Tag: "test / JP Demo", Country: "JP",
		Outbound: map[string]any{"type": "shadowsocks", "server": "198.51.100.10", "server_port": 8388, "method": "aes-256-gcm", "password": "test-only"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	cmd.Dir = dir
	output, _ := cmd.CombinedOutput()
	logs := string(output)
	if strings.Contains(logs, "outbound connection to raw.githubusercontent.com") {
		t.Fatal("client still downloads rule sets at startup")
	}
	for _, expected := range []string{"sing-box started"} {
		if !strings.Contains(logs, expected) {
			t.Fatalf("live example startup missing %q: %s", expected, logs)
		}
	}
}
