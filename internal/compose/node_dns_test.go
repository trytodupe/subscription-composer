package compose

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestNodeDNSIsScopedAndPreservesDevicePolicy(t *testing.T) {
	device := model.Device{ID: "desktop", Base: json.RawMessage(`{
		"outbounds":[{"type":"direct","tag":"direct"}],
		"dns":{"servers":[
			{"type":"udp","tag":"bootstrap","server":"192.0.2.53"},
			{"type":"https","tag":"site-dns","server":"dns.example","domain_resolver":"bootstrap","detour":"main"}
		],"rules":[{"domain_suffix":["campus.example"],"action":"route","server":"bootstrap"}],"final":"site-dns"},
		"route":{"default_domain_resolver":"bootstrap"}
	}`)}
	resolver := &model.DNSServer{Type: "https", Server: "provider-dns.example", Path: "/dns-query"}
	nodes := []model.Node{
		{Provider: "airport", Tag: "first", Outbound: map[string]any{"type": "shadowsocks", "server": "one.entry.example", "server_port": 8388, "method": "aes-256-gcm", "password": "test-only"}, DNSResolver: resolver},
		{Provider: "airport", Tag: "second", Outbound: map[string]any{"type": "vmess", "server": "two.entry.example", "server_port": 8388, "uuid": "00000000-0000-0000-0000-000000000001", "security": "auto"}, DNSResolver: resolver},
		{Provider: "other", Tag: "unmatched", Outbound: map[string]any{"type": "socks", "server": "other.example", "server_port": 1080}},
	}
	before, _ := json.Marshal(nodes)
	data, err := Build(device, model.Policy{}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(nodes)
	if !bytes.Equal(before, after) {
		t.Fatal("composition mutated source nodes")
	}
	result := decode(t, data)
	dns := result["dns"].(map[string]any)
	baseDNS := decode(t, device.Base)["dns"].(map[string]any)
	if dns["final"] != baseDNS["final"] || !reflect.DeepEqual(dns["rules"], baseDNS["rules"]) {
		t.Fatal("node DNS changed application DNS policy")
	}
	servers := dns["servers"].([]any)
	if len(servers) != 3 || !reflect.DeepEqual(servers[:2], baseDNS["servers"]) {
		t.Fatal("base DNS was changed or identical node resolvers were not deduplicated")
	}
	generated := servers[2].(map[string]any)
	if generated["type"] != "https" || generated["server"] != resolver.Server || generated["domain_resolver"] != "bootstrap" || generated["detour"] != nil {
		t.Fatal("provider DNS did not use direct bootstrap")
	}
	for _, raw := range result["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		switch outbound["tag"] {
		case "first", "second":
			if outbound["domain_resolver"] != generated["tag"] || outbound["server"] == "192.0.2.53" {
				t.Fatal("matching node did not retain its hostname with the provider resolver")
			}
		case "unmatched":
			if outbound["domain_resolver"] != nil {
				t.Fatal("source DNS leaked into an unrelated node")
			}
		}
	}
	nodes[0], nodes[1] = nodes[1], nodes[0]
	reordered, err := Build(device, model.Policy{}, nodes)
	if err != nil || !bytes.Equal(data, reordered) {
		t.Fatalf("node ordering changed generated DNS: %v", err)
	}
}

func TestNodeDNSBootstrapAndConflicts(t *testing.T) {
	for _, test := range []struct {
		name      string
		base      string
		wantError bool
	}{
		{"local default", `{}`, false},
		{"explicit options", `{"dns":{"servers":[{"type":"local","tag":"bootstrap"}]},"route":{"default_domain_resolver":{"server":"bootstrap","timeout":"3s"}}}`, false},
		{"proxied bootstrap", `{"dns":{"servers":[{"type":"https","tag":"bootstrap","server":"dns.example","detour":"main"}]},"route":{"default_domain_resolver":"bootstrap"}}`, true},
		{"cyclic bootstrap", `{"dns":{"servers":[{"type":"https","tag":"bootstrap","server":"dns.example","domain_resolver":"bootstrap"}]},"route":{"default_domain_resolver":"bootstrap"}}`, true},
		{"implicit recursion", `{"dns":{"servers":[{"type":"https","tag":"bootstrap","server":"dns.example"}]},"route":{"default_domain_resolver":"bootstrap"}}`, true},
		{"missing bootstrap", `{"route":{"default_domain_resolver":"absent"}}`, true},
		{"local tag collision", `{"dns":{"servers":[{"type":"local","tag":"node-dns-bootstrap"}]}}`, true},
		{"fake IP bootstrap", `{"dns":{"servers":[{"type":"fakeip","tag":"bootstrap"}]},"route":{"default_domain_resolver":"bootstrap"}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := model.Node{Provider: "airport", Tag: "node", Outbound: map[string]any{"type": "socks", "server": "entry.example", "server_port": 1080}, DNSResolver: &model.DNSServer{Type: "https", Server: "provider.example", Path: "/dns-query"}}
			data, err := Build(model.Device{Base: json.RawMessage(test.base)}, model.Policy{}, []model.Node{node})
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected build result: %v", err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "provider.example") {
					t.Fatal("build error exposed resolver address")
				}
				return
			}
			config := decode(t, data)
			servers := config["dns"].(map[string]any)["servers"].([]any)
			if len(servers) != 2 || servers[1].(map[string]any)["domain_resolver"] == nil {
				t.Fatal("hostname DNS server has no bootstrap")
			}
		})
	}
	device, policy, nodes := fixture()
	nodes[0].DNSResolver = &model.DNSServer{Type: "tcp", Server: "127.0.0.1", ServerPort: 54}
	data, err := Build(device, policy, nodes)
	if err != nil {
		t.Fatal(err)
	}
	servers := decode(t, data)["dns"].(map[string]any)["servers"].([]any)
	if len(servers) != 2 || servers[1].(map[string]any)["domain_resolver"] != nil {
		t.Fatal("IP DNS endpoint unnecessarily bootstraps")
	}
	nodes[0].Outbound["domain_resolver"] = "local"
	if _, err := Build(device, policy, nodes); err == nil {
		t.Fatal("node DNS overwrote an explicit resolver")
	}
}

func TestDNSDialerResolverReferenceIsValidated(t *testing.T) {
	device, policy, nodes := fixture()
	device.Base = json.RawMessage(`{"dns":{"servers":[{"type":"https","tag":"dns","server":"dns.example","domain_resolver":"missing"}]}}`)
	if _, err := Build(device, policy, nodes); err == nil {
		t.Fatal("DNS server accepted a dangling domain_resolver reference")
	}
}
