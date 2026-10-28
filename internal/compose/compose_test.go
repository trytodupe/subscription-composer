package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func fixture() (model.Device, model.Policy, []model.Node) {
	device := model.Device{ID: "desktop", Base: json.RawMessage(`{
		"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"tun0"}],
		"outbounds":[{"type":"direct","tag":"direct"}],
		"endpoints":[{"type":"tailscale","tag":"ts"}],
		"dns":{"servers":[{"type":"local","tag":"local"}],"final":"local"},
		"route":{"rules":[{"preferred_by":["ts"],"action":"route","endpoint":"ts"}]},
		"experimental":{"cache_file":{"path":"state.db"}},"log":{"level":"warn"}
	}`)}
	policy := model.Policy{
		Rules:           []json.RawMessage{json.RawMessage(`{"domain":["example.org"],"action":"route","outbound":"regional"}`)},
		DirectDomains:   []string{"lan"},
		DirectCIDRs:     []string{"192.168.0.0/16"},
		RegionalDomains: []string{"example.net"},
		RuleSets:        []json.RawMessage{json.RawMessage(`{"type":"local","tag":"local-set","format":"binary","path":"local.srs"}`)},
		DirectRuleSets:  []string{"local-set"},
	}
	nodes := []model.Node{
		{Tag: "node-jp", Country: "JP", Outbound: map[string]any{"type": "socks", "server": "secret.example", "server_port": 1080}},
		{Tag: "node-other", Outbound: map[string]any{"type": "socks", "server": "private.example", "server_port": 1080}},
	}
	return device, policy, nodes
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestBuildPreservesInfrastructureAndOrdersPolicies(t *testing.T) {
	device, policy, nodes := fixture()
	base := append([]byte(nil), device.Base...)
	original := nodes[0].Outbound["server"]
	data, err := Build(device, policy, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base, device.Base) || nodes[0].Outbound["server"] != original {
		t.Fatal("inputs mutated")
	}
	config := decode(t, data)
	route := config["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 7 {
		t.Fatalf("unexpected rule count %d", len(rules))
	}
	if !reflect.DeepEqual(rules[0].(map[string]any)["inbound"], []any{"mixed-direct"}) || rules[0].(map[string]any)["outbound"] != "direct" {
		t.Fatalf("explicit direct route must precede base routes: %v", rules[0])
	}
	if rules[1].(map[string]any)["endpoint"] != "ts" || rules[2].(map[string]any)["outbound"] != "regional" || rules[3].(map[string]any)["domain_suffix"].([]any)[0] != "lan" || rules[6].(map[string]any)["rule_set"].([]any)[0] != "local-set" {
		t.Fatalf("incorrect route precedence: %v", rules)
	}
	if route["final"] != "main" || config["log"].(map[string]any)["level"] != "warn" || config["endpoints"].([]any)[0].(map[string]any)["tag"] != "ts" {
		t.Fatal("base fields or final route lost")
	}
	if config["dns"].(map[string]any)["final"] != "local" || config["inbounds"].([]any)[0].(map[string]any)["tag"] != "tun-in" {
		t.Fatal("base network settings lost")
	}
	cache := config["experimental"].(map[string]any)["cache_file"].(map[string]any)
	if cache["path"] != "state.db" || cache["enabled"] != true || cache["cache_id"] != "desktop" {
		t.Fatalf("unexpected cache: %v", cache)
	}
	outbounds := config["outbounds"].([]any)
	byTag := map[string]map[string]any{}
	for _, raw := range outbounds {
		entry := raw.(map[string]any)
		byTag[entry["tag"].(string)] = entry
	}
	if len(byTag) != 10 || byTag["direct"]["type"] != "direct" {
		t.Fatalf("unexpected outbounds %v", byTag)
	}
	if !reflect.DeepEqual(byTag["main"]["outbounds"], []any{"auto", "country-JP", "country-OTHER"}) || !reflect.DeepEqual(byTag["regional"]["outbounds"], []any{"main", "country-JP", "country-OTHER"}) {
		t.Fatal("incorrect shared selectors")
	}
	if !reflect.DeepEqual(byTag["country-JP"]["outbounds"], []any{"country-JP-auto", "node-jp"}) || byTag["country-JP"]["interrupt_exist_connections"] != true {
		t.Fatal("incorrect country selector")
	}
	if byTag["auto"]["url"] != "https://www.google.com/generate_204" || byTag["auto"]["interval"] != "5m" || byTag["auto"]["tolerance"] != float64(50) {
		t.Fatal("incorrect URL test defaults")
	}
	if byTag["auto"]["interrupt_exist_connections"] != false || byTag["country-JP-auto"]["interrupt_exist_connections"] != false {
		t.Fatal("automatic groups should not interrupt sessions")
	}
}

func TestDeterminismAndExplicitCache(t *testing.T) {
	device, policy, nodes := fixture()
	device.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"cache_file":{"enabled":false,"cache_id":"own"}}}`)
	first, err := Build(device, policy, nodes)
	if err != nil {
		t.Fatal(err)
	}
	nodes[0], nodes[1] = nodes[1], nodes[0]
	second, err := Build(device, policy, nodes)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("unstable output: %v", err)
	}
	cache := decode(t, first)["experimental"].(map[string]any)["cache_file"].(map[string]any)
	if cache["enabled"] != false || cache["cache_id"] != "own" {
		t.Fatalf("explicit cache settings changed: %v", cache)
	}
}

func TestRejectInvalidReferencesAndTags(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*model.Device, *model.Policy, *[]model.Node)
	}{
		{"no nodes", func(_ *model.Device, _ *model.Policy, n *[]model.Node) { *n = nil }},
		{"reserved tag", func(_ *model.Device, _ *model.Policy, n *[]model.Node) { (*n)[0].Tag = "main" }},
		{"duplicate node", func(_ *model.Device, _ *model.Policy, n *[]model.Node) { (*n)[0].Tag = (*n)[1].Tag }},
		{"generated country collision", func(_ *model.Device, _ *model.Policy, n *[]model.Node) { (*n)[0].Tag = "country-JP" }},
		{"invalid selector default", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"manual","outbounds":["direct"],"default":"missing"}]}`)
		}},
		{"base collision", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"auto"}]}`)
		}},
		{"bad route", func(_ *model.Device, p *model.Policy, _ *[]model.Node) {
			p.Rules = []json.RawMessage{json.RawMessage(`{"action":"route","outbound":"missing"}`)}
		}},
		{"missing inbound", func(_ *model.Device, p *model.Policy, _ *[]model.Node) {
			p.Rules = []json.RawMessage{json.RawMessage(`{"inbound":["missing"],"action":"route","outbound":"main"}`)}
		}},
		{"bad nested route", func(_ *model.Device, p *model.Policy, _ *[]model.Node) {
			p.Rules = []json.RawMessage{json.RawMessage(`{"type":"logical","mode":"or","rules":[{"outbound":"missing"}],"action":"route","outbound":"main"}`)}
		}},
		{"bad endpoint", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"route":{"rules":[{"action":"route","endpoint":"absent"}]}}`)
		}},
		{"bad DNS detour", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"dns":{"servers":[{"type":"https","tag":"dns","detour":"absent"}]}}`)
		}},
		{"bad rule set", func(_ *model.Device, p *model.Policy, _ *[]model.Node) { p.DirectRuleSets = []string{"unknown"} }},
		{"duplicate rule set", func(_ *model.Device, p *model.Policy, _ *[]model.Node) {
			p.RuleSets = append(p.RuleSets, p.RuleSets[0])
		}},
		{"invalid rule", func(_ *model.Device, p *model.Policy, _ *[]model.Node) {
			p.Rules = []json.RawMessage{json.RawMessage(`[]`)}
		}},
		{"legacy DNS server", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"dns":{"servers":[{"tag":"dns","address":"https://dns.example/dns-query"}]}}`)
		}},
		{"legacy inbound", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"inbounds":[{"type":"mixed","tag":"proxy","sniff":true}]}`)
		}},
		{"legacy outbound", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"outbounds":[{"type":"block","tag":"blocked"}]}`)
		}},
		{"reserved inbound tag", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"inbounds":[{"type":"mixed","tag":"mixed-direct","listen_port":9000}]}`)
		}},
		{"reserved policy port", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"inbounds":[{"type":"http","tag":"custom","listen_port":7890}]}`)
		}},
		{"reserved direct port", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"inbounds":[{"type":"socks","tag":"custom","listen_port":7891}]}`)
		}},
		{"incorrect direct outbound", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"outbounds":[{"type":"socks","tag":"direct","server":"example.com","server_port":1080}]}`)
		}},
		{"invalid base rules", func(d *model.Device, _ *model.Policy, _ *[]model.Node) {
			d.Base = json.RawMessage(`{"route":{"rules":{}}}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, policy, nodes := fixture()
			tc.edit(&device, &policy, &nodes)
			if _, err := Build(device, policy, nodes); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBaseRuleSetsAreMerged(t *testing.T) {
	device, policy, nodes := fixture()
	device.Base = json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[{"type":"local","tag":"base-set","format":"binary","path":"base.srs"}],"rules":[{"rule_set":["base-set"],"action":"route","outbound":"direct"}]}}`)
	data, err := Build(device, policy, nodes)
	if err != nil {
		t.Fatal(err)
	}
	route := decode(t, data)["route"].(map[string]any)
	sets := route["rule_set"].([]any)
	if len(sets) != 2 || sets[0].(map[string]any)["tag"] != "base-set" || sets[1].(map[string]any)["tag"] != "local-set" {
		t.Fatalf("incorrect rule set merge: %v", sets)
	}
}

func TestCheckAcceptsSuccessfulValidator(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "fake-check")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$1\" = check ] && [ \"$2\" = -c ] && [ -f \"$3\" ]\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), binary, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRedactsCredentialsAndCleansTempfile(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-check")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat \"$3\" >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	secret := []byte(`{"password":"secret-password"}`)
	err := Check(context.Background(), binary, secret)
	if err == nil || strings.Contains(err.Error(), "secret-password") || strings.Contains(err.Error(), dir) {
		t.Fatalf("unsafe check error: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary file left behind: %v %v", files, err)
	}
}
