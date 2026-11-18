package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func loadRemoteControlDevices(t *testing.T, devices ...map[string]any) (model.Config, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"sources": []any{map[string]any{"id": "demo", "file": "nodes.json"}},
		"devices": devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func remoteControlDevice(platform string, options map[string]any) map[string]any {
	device := map[string]any{
		"id": platform, "platform": platform,
		"token": "subscription-token-for-" + platform,
		"base":  map[string]any{},
	}
	if options != nil {
		device["remote_control"] = options
	}
	return device
}

func TestRemoteControlDefaultsAndOverrides(t *testing.T) {
	for _, platform := range []string{"macos", "linux", "android"} {
		t.Run(platform, func(t *testing.T) {
			t.Setenv("TEST_REMOTE_API_SECRET", "independent-api-secret-at-least-24-bytes")
			options := map[string]any{"secret": "env:TEST_REMOTE_API_SECRET"}
			cfg, err := loadRemoteControlDevices(t, remoteControlDevice(platform, options))
			if err != nil {
				t.Fatal(err)
			}
			r := cfg.Devices[0].RemoteControl
			if r.IsEnabled(platform) != (platform != "android") {
				t.Fatal("incorrect platform default")
			}
			if platform != "android" && (r.Listen != "127.0.0.1" || r.ListenPort != 9090 || r.Secret != os.Getenv("TEST_REMOTE_API_SECRET")) {
				t.Fatal("API defaults or secret resolution were lost")
			}
			options["enabled"] = platform == "android"
			options["listen"] = "::1"
			options["listen_port"] = 9191
			cfg, err = loadRemoteControlDevices(t, remoteControlDevice(platform, options))
			if err != nil {
				t.Fatal(err)
			}
			r = cfg.Devices[0].RemoteControl
			if r.IsEnabled(platform) != (platform == "android") {
				t.Fatal("explicit API override was lost")
			}
			if platform == "android" && (r.Listen != "::1" || r.ListenPort != 9191) {
				t.Fatal("custom listener was lost")
			}
		})
	}
	if _, err := loadRemoteControlDevices(t, remoteControlDevice("android", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRemoteControlDevices(t, remoteControlDevice("linux", map[string]any{"enabled": false, "secret": "env:UNUSED_REMOTE_API_SECRET"})); err != nil {
		t.Fatal("disabled API must not require a secret")
	}
}

func TestRemoteControlRejectsInvalidSettingsWithoutLeakingSecrets(t *testing.T) {
	secret := "private-api-secret-at-least-24-bytes"
	cases := []struct {
		name    string
		options map[string]any
	}{
		{"missing secret", nil},
		{"short secret", map[string]any{"secret": "private-api-secret"}},
		{"missing env", map[string]any{"secret": "env:UNSET_REMOTE_API_SECRET"}},
		{"unresolved env", map[string]any{"secret": "env:TEST_INDIRECT_API_SECRET"}},
		{"line break", map[string]any{"secret": secret + "\ninvalid"}},
		{"leading space", map[string]any{"secret": " " + secret}},
		{"invalid address", map[string]any{"secret": secret, "listen": "not-an-address"}},
		{"zone", map[string]any{"secret": secret, "listen": "fe80::1%en0"}},
		{"negative port", map[string]any{"secret": secret, "listen_port": -1}},
		{"oversized port", map[string]any{"secret": secret, "listen_port": 65536}},
		{"proxy port", map[string]any{"secret": secret, "listen_port": 7890}},
		{"direct port", map[string]any{"secret": secret, "listen_port": 7891}},
		{"unknown field", map[string]any{"secret": secret, "port": 9090}},
		{"invalid enabled", map[string]any{"secret": secret, "enabled": "true"}},
	}
	t.Setenv("TEST_INDIRECT_API_SECRET", "env:unresolved-secret-value-at-least-24-bytes")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadRemoteControlDevices(t, remoteControlDevice("linux", tc.options))
			if err == nil {
				t.Fatal("invalid remote control settings accepted")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "private-api-secret") {
				t.Fatal("remote control error exposed a secret")
			}
		})
	}
}

func TestRemoteControlSecretsMustBeIndependent(t *testing.T) {
	secret := "independent-api-secret-at-least-24-bytes"
	linux := remoteControlDevice("linux", map[string]any{"secret": secret})
	macos := remoteControlDevice("macos", map[string]any{"secret": secret})
	if _, err := loadRemoteControlDevices(t, linux, macos); err == nil {
		t.Fatal("shared API secrets accepted")
	}
	macos["remote_control"] = map[string]any{"secret": strings.Repeat("a", 32)}
	macos["token"] = secret
	if _, err := loadRemoteControlDevices(t, linux, macos); err == nil {
		t.Fatal("API secret matching another device subscription token accepted")
	}
	linux["token"] = secret
	if _, err := loadRemoteControlDevices(t, linux); err == nil {
		t.Fatal("API secret matching its subscription token accepted")
	}
}
