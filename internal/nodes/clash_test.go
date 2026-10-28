package nodes

import (
	"reflect"
	"strings"
	"testing"
)

func TestClashProxies(t *testing.T) {
	inline := `proxies:
  - {name: "JP SS", type: ss, server: ss.example, port: 8388, cipher: aes-256-gcm, password: "sample-secret", udp: false, client-fingerprint: chrome, group: "Asia"}
  - {name: "US VMess", type: vmess, server: vm.example, port: "443", uuid: "sample-uuid", alterId: 0, cipher: auto, network: ws, tls: true, sni: tls.example, skip-cert-verify: false, ws-opts: {path: /ws, headers: {Host: front.example}}, alpn: [h2, http/1.1], client-fingerprint: chrome, udp: true}
proxy-groups:
  - {name: group, type: select, proxies: ["JP SS", "US VMess"]}
dns: {enable: true, nameserver: ["1.1.1.1"]}
`
	multiline := `proxies:
  - name: JP SS
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-256-gcm
    password: sample-secret
    udp: false
    client-fingerprint: chrome
    group: Asia
  - name: US VMess
    type: vmess
    server: vm.example
    port: "443"
    uuid: sample-uuid
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    sni: tls.example
    skip-cert-verify: false
    ws-opts:
      path: /ws
      headers:
        Host: front.example
    alpn:
      - h2
      - http/1.1
    client-fingerprint: chrome
    udp: true
proxy-groups:
  - name: group
    type: select
    proxies: [JP SS, US VMess]
`
	first, err := parseClash([]byte(inline))
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseClash([]byte(multiline))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("inline and multiline YAML differ")
	}
	if len(first) != 2 || first[0].name != "JP SS" || first[1].name != "US VMess" {
		t.Fatal("only proxies should be imported")
	}
	ss := first[0].outbound
	if ss["type"] != "shadowsocks" || ss["method"] != "aes-256-gcm" || ss["password"] != "sample-secret" || ss["server_port"] != 8388 || !reflect.DeepEqual(ss["network"], []string{"tcp"}) {
		t.Fatal("SS mapping differs")
	}
	vm := first[1].outbound
	if vm["type"] != "vmess" || vm["alter_id"] != 0 || vm["security"] != "auto" || vm["server_port"] != 443 || vm["uuid"] != "sample-uuid" {
		t.Fatal("VMess fields differ")
	}
	tls := vm["tls"].(map[string]any)
	if tls["insecure"] != false || tls["server_name"] != "tls.example" || !reflect.DeepEqual(tls["alpn"], []string{"h2", "http/1.1"}) || tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
		t.Fatal("VMess TLS mapping differs")
	}
	transport := vm["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/ws" || transport["headers"].(map[string]any)["Host"] != "front.example" {
		t.Fatal("VMess WS mapping differs")
	}
	if _, ok := vm["network"]; ok {
		t.Fatal("enabled UDP should use native default")
	}
}

func TestClashGRPCAndTLSValidation(t *testing.T) {
	body := `proxies:
  - {name: node, type: vmess, server: vm.example, port: 443, uuid: id, network: grpc, grpc-opts: {grpc-service-name: svc}, tls: true, servername: front.example, skip-cert-verify: true}
`
	entries, err := parseClash([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	vm := entries[0].outbound
	if vm["transport"].(map[string]any)["service_name"] != "svc" || vm["tls"].(map[string]any)["insecure"] != true || vm["tls"].(map[string]any)["server_name"] != "front.example" {
		t.Fatal("GRPC and TLS mapping differs")
	}
}

func TestClashRejectsUnsupportedAndAmbiguousFields(t *testing.T) {
	cases := []struct{ name, proxy, want string }{
		{"unknown protocol", `{name: secret-name, type: trojan, server: secret-host, port: 443}`, "unsupported Clash proxy protocol"},
		{"SS plugin", `{name: secret-name, type: ss, server: secret-host, port: 443, cipher: aes-256-gcm, password: secret-value, plugin: obfs-local}`, "plugins are unsupported"},
		{"connection field", `{name: secret-name, type: ss, server: secret-host, port: 443, cipher: aes-256-gcm, password: secret-value, tfo: true}`, "unsupported Clash proxy connection field"},
		{"unknown transport", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, network: h2}`, "unsupported transport"},
		{"unknown WS option", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, network: ws, ws-opts: {early-data-header-name: secret-value}}`, "unsupported Clash proxy connection field"},
		{"unsupported WS header", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, network: ws, ws-opts: {headers: {Authorization: secret-value}}}`, "only one Host header"},
		{"false TLS with server name", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, tls: false, sni: secret-value}`, "TLS options require tls mode"},
		{"false TLS with skip verify", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, tls: false, skip-cert-verify: true}`, "TLS options require tls mode"},
		{"bad bool", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, tls: "false"}`, "must be a boolean"},
		{"duplicate proxy key", `{name: secret-name, type: ss, server: secret-host, server: other-secret, port: 443, cipher: aes-256-gcm, password: secret-value}`, "duplicate Clash YAML field"},
		{"duplicate nested key", `{name: secret-name, type: vmess, server: secret-host, port: 443, uuid: secret-value, network: ws, ws-opts: {headers: {Host: one, Host: two}}}`, "duplicate Clash YAML field"},
		{"alias", `{name: secret-name, type: ss, server: &host secret-host, port: 443, cipher: aes-256-gcm, password: secret-value}`, "aliases and anchors"},
		{"alias reference", `{name: secret-name, type: ss, server: secret-host, port: 443, cipher: aes-256-gcm, password: secret-value, group: &label safe, label: *label}`, "aliases and anchors"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseClash([]byte("proxies:\n  - " + tc.proxy + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s, got %v", tc.want, err)
			}
			for _, secret := range []string{"secret-name", "secret-host", "secret-value", "other-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("error leaked proxy value")
				}
			}
		})
	}
	for _, body := range []string{"proxies: []", "proxies: []\n---\nproxies: []\n", "proxies: [invalid"} {
		if _, err := parseClash([]byte(body)); err == nil {
			t.Fatal("expected invalid or empty YAML rejection")
		}
	}
}
