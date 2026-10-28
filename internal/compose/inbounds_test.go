package compose

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestBuildAddsLocalProxyInboundsForEveryDevice(t *testing.T) {
	for _, platform := range []string{"macos", "android"} {
		t.Run(platform, func(t *testing.T) {
			device, policy, nodes := fixture()
			device.Platform = platform
			data, err := Build(device, policy, nodes)
			if err != nil {
				t.Fatal(err)
			}
			config := decode(t, data)
			inbounds := config["inbounds"].([]any)
			if len(inbounds) != 3 || inbounds[0].(map[string]any)["tag"] != "tun-in" {
				t.Fatalf("base inbound not preserved: %v", inbounds)
			}
			for i, tag := range []string{"mixed-rules", "mixed-direct"} {
				want := map[string]any{
					"type": "mixed", "tag": tag,
					"listen": "127.0.0.1", "listen_port": float64(7890 + i),
				}
				if !reflect.DeepEqual(inbounds[i+1], want) {
					t.Fatalf("unexpected listener: %v", inbounds[i+1])
				}
			}
			for _, raw := range config["route"].(map[string]any)["rules"].([]any) {
				if reflect.DeepEqual(raw.(map[string]any)["inbound"], []any{"mixed-rules"}) {
					t.Fatal("policy listener must use normal routing")
				}
			}
		})
	}
}

func TestNativeLocalProxyConfiguration(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	device, _, nodes := fixture()
	device.Base = json.RawMessage(`{}`)
	data, err := Build(device, model.Policy{}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), binary, data); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAddsDirectOutboundWhenMissing(t *testing.T) {
	device, _, nodes := fixture()
	device.Base = json.RawMessage(`{}`)
	data, err := Build(device, model.Policy{}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range decode(t, data)["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "direct" && outbound["type"] == "direct" {
			return
		}
	}
	t.Fatal("generated direct route has no direct outbound")
}
