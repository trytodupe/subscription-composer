package nodes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
	"gopkg.in/yaml.v3"
)

func dnsPolicyFields(t *testing.T, body string) map[string]*yaml.Node {
	t.Helper()
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	return clashMap(document.Content[0])
}

func dnsEntries(hosts ...string) []entry {
	result := make([]entry, len(hosts))
	for i, host := range hosts {
		result[i] = entry{outbound: map[string]any{"server": host, "type": "shadowsocks"}}
	}
	return result
}

func TestClashNodeResolversScopeAndSpecificity(t *testing.T) {
	fields := dnsPolicyFields(t, `dns: {nameserver: [https://global.invalid/dns-query]}
x-client-custom:
  nameserver-policy:
    '+.Example.': https://suffix.example/dns-query
    '*.Deeper.Example': tls://wild.example
    'DEEPER.EXAMPLE': udp://exact.example
    '+.deeper.example': tcp://inclusive.example:54
    'host.deeper.example.': https://host.example/special%2Fpath
`)
	entries := dnsEntries("EXAMPLE.", "a.example", "otherexample", "deeper.example", "child.DEEPER.example.", "host.deeper.example.", "suffixexample", "192.0.2.8", "[::1]")
	original := make([]map[string]any, len(entries))
	for i := range entries {
		original[i] = map[string]any{"server": entries[i].outbound["server"], "type": "shadowsocks"}
	}
	if err := clashNodeResolvers(fields, entries); err != nil {
		t.Fatal(err)
	}
	want := []*model.DNSServer{
		{Type: "https", Server: "suffix.example", Path: "/dns-query"},
		{Type: "https", Server: "suffix.example", Path: "/dns-query"},
		nil,
		{Type: "udp", Server: "exact.example"},
		{Type: "tls", Server: "wild.example"},
		{Type: "https", Server: "host.example", Path: "/special%2Fpath"},
		nil, nil, nil,
	}
	for i := range entries {
		if !reflect.DeepEqual(entries[i].resolver, want[i]) {
			t.Errorf("entry %d resolver: got %+v, want %+v", i, entries[i].resolver, want[i])
		}
		if !reflect.DeepEqual(entries[i].outbound, original[i]) {
			t.Errorf("entry %d outbound changed", i)
		}
	}
}

func TestClashNodeResolversPreferTCPAndReuse(t *testing.T) {
	fields := dnsPolicyFields(t, `x-client-custom:
  nameserver-policy:
    '+.v51124-4.qpon':
      - https://provider.example/dns-query
      - tcp://provider.example:54#cost-bias=+100ms
`)
	entries := dnsEntries("v51124-4.qpon", "A.v51124-4.qpon", "b.v51124-4.qpon")
	if err := clashNodeResolvers(fields, entries); err != nil {
		t.Fatal(err)
	}
	want := &model.DNSServer{Type: "tcp", Server: "provider.example", ServerPort: 54}
	for i := range entries {
		if !reflect.DeepEqual(entries[i].resolver, want) {
			t.Errorf("entry %d: got %+v, want %+v", i, entries[i].resolver, want)
		}
	}
}

func TestClashNodeResolversAbsentPolicy(t *testing.T) {
	entries := dnsEntries("node.example")
	for _, body := range []string{
		`dns: {nameserver: [https://global.example/dns-query]}`,
		`x-client-custom: {other-option: true}`,
	} {
		if err := clashNodeResolvers(dnsPolicyFields(t, body), entries); err != nil {
			t.Fatal(err)
		}
		if entries[0].resolver != nil {
			t.Fatal("unrelated DNS settings were imported")
		}
	}
}

func TestClashParseScopedDNS(t *testing.T) {
	body := `proxies:
  - {name: first, type: ss, server: proxy.example, port: 8388, cipher: aes-256-gcm, password: sample-secret}
  - {name: second, type: ss, server: unrelated.example, port: 8388, cipher: aes-256-gcm, password: sample-secret}
dns: {nameserver: [https://global.example/dns-query]}
x-client-custom:
  nameserver-policy:
    '+.proxy.example': [https://provider.example/dns-query, 'tcp://provider.example:54#cost-bias=+100ms']
`
	nodes, err := Parse(model.Source{ID: "test-source", Format: "clash"}, []byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || !reflect.DeepEqual(nodes[0].DNSResolver, &model.DNSServer{Type: "tcp", Server: "provider.example", ServerPort: 54}) || nodes[1].DNSResolver != nil {
		t.Fatalf("unexpected node DNS resolvers: %+v", nodes)
	}
	if nodes[0].Outbound["server"] != "proxy.example" {
		t.Fatal("proxy hostname changed")
	}
}

func TestClashDNSEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     model.DNSServer
	}{
		{"https://provider.example", model.DNSServer{Type: "https", Server: "provider.example", Path: "/dns-query"}},
		{"https://provider.example:443/a%2Fb#cost-bias=+100ms", model.DNSServer{Type: "https", Server: "provider.example", Path: "/a%2Fb"}},
		{"tls://provider.example:853", model.DNSServer{Type: "tls", Server: "provider.example"}},
		{"tcp://provider.example:54#cost-bias=-25ms", model.DNSServer{Type: "tcp", Server: "provider.example", ServerPort: 54}},
		{"udp://192.0.2.53:53", model.DNSServer{Type: "udp", Server: "192.0.2.53"}},
		{"https://[2001:db8::1]:4443/resolve", model.DNSServer{Type: "https", Server: "2001:db8::1", ServerPort: 4443, Path: "/resolve"}},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			got, ok := clashDNSEndpoint(tc.endpoint)
			if !ok || !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "server_port") && got.ServerPort == 0 {
				t.Fatal("default port should be omitted")
			}
		})
	}
}

func TestClashNodeResolversRejectMalformedWithoutLeakingValues(t *testing.T) {
	cases := []string{
		`x-client-custom: null`,
		`x-client-custom: {nameserver-policy: null}`,
		`x-client-custom: {nameserver-policy: {}}`,
		`x-client-custom: {nameserver-policy: [secret-domain.example]}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: []}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: [https://secret-host.example, 5]}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: [""]}}`,
		`x-client-custom: {nameserver-policy: {'+.secret-domain.example': http://secret-host.example/dns-query}}`,
		`x-client-custom: {nameserver-policy: {'*.secret-domain.example': https://secret-user:secret-pass@secret-host.example/dns-query}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: 'https://secret-host.example/dns-query?secret-token=1'}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: https://secret-host.example/dns-query#secret-token}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: https://secret-host.example/dns-query#cost-bias=secret-token}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: https://secret-host.example:0}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: 'https://secret-host.example:'}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: 'https://[secret-host.example]'}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: https://secret-host.example:65536}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: tls://secret-host.example/dns-query}}`,
		`x-client-custom: {nameserver-policy: {secret-domain.example: https://secret-host..example/dns-query}}`,
		`x-client-custom: {nameserver-policy: {'+.secret-domain..example': https://secret-host.example}}`,
		`x-client-custom: {nameserver-policy: {'*.192.0.2.1': https://secret-host.example}}`,
		`x-client-custom: {nameserver-policy: {'geosite:secret-domain.example': https://secret-host.example}}`,
		`x-client-custom: {nameserver-policy: {'regexp:secret-domain.example': https://secret-host.example}}`,
		`x-client-custom: {nameserver-policy: {'secret-domain.example/24': https://secret-host.example}}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			entries := dnsEntries("secret-domain.example")
			err := clashNodeResolvers(dnsPolicyFields(t, body), entries)
			if err == nil {
				t.Fatal("expected invalid custom DNS policy")
			}
			for _, secret := range []string{"secret-domain", "secret-host", "secret-user", "secret-pass", "secret-token"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("error exposed policy value")
				}
			}
			if entries[0].resolver != nil {
				t.Fatal("invalid policy changed entry")
			}
		})
	}
}
