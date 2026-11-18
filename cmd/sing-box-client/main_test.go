package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/clientupdate"
)

func TestStatusAndArgumentValidation(t *testing.T) {
	root := t.TempDir()
	cfg := clientupdate.Config{
		SubscriptionURL: "https://example.test/profile", Username: "linux", TokenFile: filepath.Join(root, "token"),
		StateDir: filepath.Join(root, "state"), ConfigDir: filepath.Join(root, "config"),
		LocalFile: filepath.Join(root, "config", "10-local.json"), SubscriptionFile: filepath.Join(root, "config", "20-subscription.json"),
		WorkDir: filepath.Join(root, "work"), SingBoxBinary: "/usr/bin/sing-box", RCServiceBinary: "/sbin/rc-service",
		ServiceName: "sing-box", HealthAddress: "127.0.0.1:9090",
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "client.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"status", "--config", path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"phase":"pending"`) || strings.Contains(out.String(), "example.test") {
		t.Fatalf("unexpected status: %s", out.String())
	}
	for _, args := range [][]string{
		nil, {"unknown"}, {"fetch", "--jitter", "bad"}, {"apply", "--jitter", "5m"}, {"status", "trailing"},
	} {
		if err := run(args, &out); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	// Positive fetch jitter must parse, before loading the deliberately missing config.
	err = run([]string{"fetch", "--config", filepath.Join(root, "missing"), "--jitter", "5m"}, &out)
	if err == nil || err.Error() != "cannot read private client configuration" {
		t.Fatalf("fetch jitter did not parse: %v", err)
	}
}
