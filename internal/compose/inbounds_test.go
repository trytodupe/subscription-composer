package compose

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestBuildAddsLoopbackProxyInboundsByDefault(t *testing.T) {
	for _, platform := range []string{"macos", "android", "linux"} {
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
			rules := config["route"].(map[string]any)["rules"].([]any)
			want := map[string]any{"inbound": []any{"mixed-direct"}, "action": "route", "outbound": "direct"}
			if !reflect.DeepEqual(rules[0], want) {
				t.Fatalf("loopback listeners must not add a source guard: %v", rules[0])
			}
			for _, raw := range rules {
				if reflect.DeepEqual(raw.(map[string]any)["inbound"], []any{"mixed-rules"}) {
					t.Fatal("policy listener must use normal routing")
				}
			}
		})
	}
}

func TestBuildExposedProxyInboundsAreGuarded(t *testing.T) {
	cases := []struct {
		name     string
		settings model.LocalProxy
		want     []any
	}{
		{"tailscale", model.LocalProxy{AllowTailscale: true}, []any{"127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48"}},
		{"cidrs", model.LocalProxy{AllowCIDRs: []string{"192.168.1.7/24", "192.168.1.0/24", "2001:db8::1/64"}}, []any{"127.0.0.0/8", "::1/128", "192.168.1.0/24", "2001:db8::/64"}},
		{"both", model.LocalProxy{AllowTailscale: true, AllowCIDRs: []string{"100.64.0.0/10", "127.0.0.1/32", "192.168.1.0/24"}}, []any{"127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "127.0.0.1/32", "192.168.1.0/24"}},
	}
	for _, tc := range cases {
		for _, platform := range []string{"macos", "android", "linux"} {
			t.Run(tc.name+"/"+platform, func(t *testing.T) {
				device, policy, nodes := fixture()
				device.Platform = platform
				device.LocalProxy = tc.settings
				original := append([]string(nil), tc.settings.AllowCIDRs...)
				data, err := Build(device, policy, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(device.LocalProxy.AllowCIDRs, original) {
					t.Fatal("composition mutated device settings")
				}
				config := decode(t, data)
				inbounds := config["inbounds"].([]any)
				var wantInbounds []map[string]any
				wantDirectTags := []any{"mixed-direct"}
				if platform == "macos" {
					wantInbounds = []map[string]any{
						{"type": "mixed", "tag": "mixed-rules", "listen": "::", "listen_port": float64(7890)},
						{"type": "mixed", "tag": "mixed-rules-loopback", "listen": "127.0.0.1", "listen_port": float64(7890)},
						{"type": "mixed", "tag": "mixed-direct", "listen": "::", "listen_port": float64(7891)},
						{"type": "mixed", "tag": "mixed-direct-loopback", "listen": "127.0.0.1", "listen_port": float64(7891)},
					}
					wantDirectTags = []any{"mixed-direct", "mixed-direct-loopback"}
				} else {
					wantInbounds = []map[string]any{
						{"type": "mixed", "tag": "mixed-rules", "listen": "::", "listen_port": float64(7890)},
						{"type": "mixed", "tag": "mixed-direct", "listen": "::", "listen_port": float64(7891)},
					}
				}
				if len(inbounds) != 1+len(wantInbounds) {
					t.Fatalf("unexpected inbound count: %v", inbounds)
				}
				for i, want := range wantInbounds {
					if !reflect.DeepEqual(inbounds[i+1], want) {
						t.Fatalf("unexpected inbound[%d]: got %v, want %v", i+1, inbounds[i+1], want)
					}
				}
				rules := config["route"].(map[string]any)["rules"].([]any)
				guard := map[string]any{
					"type": "logical", "mode": "and",
					"rules": []any{
						map[string]any{"inbound": []any{"mixed-rules", "mixed-direct"}},
						map[string]any{"source_ip_cidr": tc.want, "invert": true},
					},
					"action": "reject",
				}
				if !reflect.DeepEqual(rules[0], guard) {
					t.Fatalf("unexpected source guard: %v", rules[0])
				}
				direct := map[string]any{"inbound": wantDirectTags, "action": "route", "outbound": "direct"}
				if !reflect.DeepEqual(rules[1], direct) {
					t.Fatalf("source guard must precede the direct listener route: %v", rules[1])
				}
			})
		}
	}
}

func TestBuildRejectsInvalidLocalProxyCIDRs(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "192.168.1.0", "not-a-prefix", "192.168.1.0/33", "::ffff:192.168.1.0/120", "fe80::/64%eth0"} {
		t.Run(cidr, func(t *testing.T) {
			device, policy, nodes := fixture()
			device.LocalProxy = model.LocalProxy{AllowCIDRs: []string{cidr}}
			if _, err := Build(device, policy, nodes); err == nil || !strings.Contains(err.Error(), "local_proxy") {
				t.Fatalf("expected local_proxy validation error, got %v", err)
			}
		})
	}
}

func TestNativeLocalProxyConfiguration(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	for _, platform := range []string{"macos", "android", "linux"} {
		for _, settings := range []model.LocalProxy{{}, {AllowTailscale: true, AllowCIDRs: []string{"192.0.2.0/24"}}} {
			device, _, nodes := fixture()
			device.Platform = platform
			device.Base = json.RawMessage(`{}`)
			device.LocalProxy = settings
			data, err := Build(device, model.Policy{}, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), binary, data); err != nil {
				t.Fatal(err)
			}
		}
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

func TestCheckScrubsChildEnvironment(t *testing.T) {
	t.Setenv("SUBCOMPOSE_SECRET_LEAK_PROBE", "sensitive-token")
	script := t.TempDir() + "/fake-sing-box"
	writeShellScript(t, script, "if [ -n \"$SUBCOMPOSE_SECRET_LEAK_PROBE\" ] || [ \"$HOME\" != \"/var/empty\" ]; then exit 1; fi\nexit 0\n")
	if err := Check(context.Background(), script, []byte(`{}`)); err != nil {
		t.Fatalf("child environment was not scrubbed: %v", err)
	}
}
