package compose

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestRemoteControlPlatformDefaultsAndOverrides(t *testing.T) {
	for _, platform := range []string{"macos", "linux", "android"} {
		for _, override := range []*bool{nil, boolPointer(true), boolPointer(false)} {
			name := platform + "/default"
			if override != nil {
				name = platform + "/disabled"
				if *override {
					name = platform + "/enabled"
				}
			}
			t.Run(name, func(t *testing.T) {
				device, policy, nodes := fixture()
				device.Platform = platform
				device.RemoteControl = model.RemoteControl{Enabled: override, Secret: strings.Repeat("a", 32)}
				original := append([]byte(nil), device.Base...)
				data, err := Build(device, policy, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(original, device.Base) || device.RemoteControl.Listen != "" || device.RemoteControl.ListenPort != 0 || device.RemoteControl.Enabled != override {
					t.Fatal("composition mutated device settings")
				}
				items, exists := decode(t, data)["services"]
				if !device.RemoteControl.IsEnabled(platform) {
					if exists {
						t.Fatal("disabled remote control generated a service")
					}
					return
				}
				services := items.([]any)
				want := map[string]any{"type": "api", "tag": "remote-api", "listen": "127.0.0.1", "listen_port": float64(9090), "secret": strings.Repeat("a", 32)}
				if len(services) != 1 || !reflect.DeepEqual(services[0], want) {
					t.Fatal("incorrect generated API service")
				}
				next, err := Build(device, policy, nodes)
				if err != nil || !bytes.Equal(data, next) {
					t.Fatal("repeated composition changed the API configuration")
				}
			})
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func TestRemoteControlPreservesOtherServicesAndCustomListener(t *testing.T) {
	device, policy, nodes := fixture()
	device.Platform = "linux"
	device.RemoteControl = model.RemoteControl{Secret: strings.Repeat("a", 32), Listen: "::1", ListenPort: 9191}
	device.Base = json.RawMessage(`{"services":[{"type":"derp","tag":"existing","listen":"127.0.0.1","listen_port":8443}]}`)
	data, err := Build(device, policy, nodes)
	if err != nil {
		t.Fatal(err)
	}
	services := decode(t, data)["services"].([]any)
	if len(services) != 2 || services[0].(map[string]any)["tag"] != "existing" {
		t.Fatal("base services were not preserved")
	}
	api := services[1].(map[string]any)
	if api["listen"] != "::1" || api["listen_port"] != float64(9191) {
		t.Fatal("custom remote control listener was lost")
	}
	device.RemoteControl.Enabled = boolPointer(false)
	data, err = Build(device, policy, nodes)
	if err != nil || len(decode(t, data)["services"].([]any)) != 1 {
		t.Fatal("disabling API removed another service")
	}
}

func TestRemoteControlRejectsConflicts(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		disabled bool
	}{
		{"native API", `{"services":[{"type":"api","tag":"custom"}]}`, false},
		{"native API while disabled", `{"services":[{"type":"api","tag":"custom"}]}`, true},
		{"reserved tag", `{"services":[{"type":"derp","tag":"remote-api"}]}`, false},
		{"reserved tag while disabled", `{"services":[{"type":"derp","tag":"remote-api"}]}`, true},
		{"duplicate service tag", `{"services":[{"type":"derp","tag":"duplicate"},{"type":"derp","tag":"duplicate"}]}`, false},
		{"invalid service", `{"services":[null]}`, false},
		{"missing service type", `{"services":[{"tag":"custom"}]}`, false},
		{"invalid services array", `{"services":{}}`, false},
		{"inbound port", `{"inbounds":[{"type":"mixed","tag":"custom","listen_port":9090}]}`, false},
		{"service port", `{"services":[{"type":"derp","tag":"custom","listen_port":9090}]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device, policy, nodes := fixture()
			device.Platform = "linux"
			device.RemoteControl = model.RemoteControl{Enabled: boolPointer(!tc.disabled), Secret: strings.Repeat("a", 32)}
			device.Base = json.RawMessage(tc.base)
			if _, err := Build(device, policy, nodes); err == nil {
				t.Fatal("remote control conflict accepted")
			}
		})
	}
	for _, options := range []model.RemoteControl{
		{},
		{Secret: "env:UNRESOLVED_API_SECRET"},
		{Secret: strings.Repeat("a", 32), ListenPort: 7890},
		{Secret: strings.Repeat("a", 32), ListenPort: 7891},
		{Secret: strings.Repeat("a", 32), Listen: "localhost"},
	} {
		device, policy, nodes := fixture()
		device.Platform, device.RemoteControl = "linux", options
		if _, err := Build(device, policy, nodes); err == nil {
			t.Fatal("unvalidated remote control settings accepted by Build")
		}
	}
}
