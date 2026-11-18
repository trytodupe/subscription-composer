package compose

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ttd/subscription-composer/internal/config"
)

func TestExampleDeviceProfiles(t *testing.T) {
	t.Setenv("SUBCOMPOSE_MACOS_TOKEN", "macos-example-token-at-least-24-bytes")
	t.Setenv("SUBCOMPOSE_ANDROID_TOKEN", "android-example-token-at-least-24-bytes")
	t.Setenv("SUBCOMPOSE_LAPTOP_TOKEN", "laptop-example-token-at-least-24-bytes")
	t.Setenv("SUBCOMPOSE_LINUX_TOKEN", "linux-example-token-at-least-24-bytes")
	for _, device := range []string{"MACOS", "LINUX", "LAPTOP"} {
		t.Setenv("SUBCOMPOSE_"+device+"_API_SECRET", device+"-api-secret-at-least-24-bytes")
	}
	cfg, err := config.Load(filepath.Join("..", "..", "examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Devices) != 4 {
		t.Fatalf("expected four device profiles, got %d", len(cfg.Devices))
	}
	_, _, nodes := fixture()
	for _, device := range cfg.Devices {
		t.Run(device.ID, func(t *testing.T) {
			data, err := Build(device, cfg.Policy, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Contains(data, []byte("tailscale")); got != (device.Platform == "android") {
				t.Fatal("only the Android profile should contain Tailscale configuration")
			}
			profile := decode(t, data)
			if device.Platform == "android" {
				if _, exists := profile["services"]; exists {
					t.Fatal("Android must not expose a remote control service by default")
				}
			} else {
				services := profile["services"].([]any)
				if len(services) != 1 || services[0].(map[string]any)["type"] != "api" || services[0].(map[string]any)["secret"] != device.RemoteControl.Secret {
					t.Fatal("desktop profile must include its remote control service")
				}
			}
			cache := profile["experimental"].(map[string]any)["cache_file"].(map[string]any)
			if cache["cache_id"] != device.ID {
				t.Fatal("device cache identity was not preserved")
			}
			tun := profile["inbounds"].([]any)[0].(map[string]any)
			if tun["strict_route"] != false {
				t.Fatal("strict routing must be disabled on every platform")
			}
			addresses := tun["address"].([]any)
			if len(addresses) != 2 || addresses[1] != "fdfe:dcba:9876::1/126" {
				t.Fatal("every platform must configure an IPv6 TUN address")
			}
			if device.ID == "laptop" && addresses[0] != "172.31.255.1/30" {
				t.Fatal("Laptop must use its dedicated IPv4 TUN address")
			}
			if device.Platform == "linux" {
				if tun["type"] != "tun" || tun["interface_name"] != "sb-tun" || tun["auto_route"] != true {
					t.Fatal("Linux profile must configure TUN routing")
				}
			}
			listen := "127.0.0.1"
			if device.LocalProxy.Exposed() {
				listen = "::"
			}
			for _, raw := range profile["inbounds"].([]any)[1:] {
				if inbound := raw.(map[string]any); inbound["type"] == "mixed" && inbound["listen"] != listen {
					t.Fatalf("unexpected local proxy listener %v", inbound)
				}
			}
			first := profile["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			if guarded := first["action"] == "reject"; guarded != device.LocalProxy.Exposed() {
				t.Fatal("only exposed local proxies must start with the source guard")
			}
			if binary := os.Getenv("SUBCOMPOSE_SING_BOX"); binary != "" {
				if err := Check(context.Background(), binary, data); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
