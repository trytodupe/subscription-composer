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
)

// This opt-in test starts DNS transports without TUN, endpoints or live proxies.
// Native check alone does not initialize detour dialers and misses this failure.
func TestNativeExampleDNSStartup(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var service model.Config
	if err := json.Unmarshal(data, &service); err != nil {
		t.Fatal(err)
	}
	base := decode(t, service.Devices[0].Base)
	dns := base["dns"].(map[string]any)
	var servers []any
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		if server["type"] != "tailscale" {
			servers = append(servers, server)
		}
	}
	dns["servers"] = servers
	delete(dns, "rules")
	config := map[string]any{
		"dns":   dns,
		"route": map[string]any{"default_domain_resolver": "bootstrap"},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "selector", "tag": "main", "outbounds": []string{"direct"}},
		},
		"log": map[string]any{"level": "info"},
	}
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(ctx, binary, "run", "-c", path).CombinedOutput()
	if !strings.Contains(string(output), "sing-box started") {
		t.Fatalf("example DNS transports did not start: %s", output)
	}
}
