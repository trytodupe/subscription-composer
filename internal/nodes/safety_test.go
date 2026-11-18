package nodes

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

// Secret markers used by the tests below; errors must never echo them.
var safetySecrets = []string{"secret-host", "secret-pass", "secret-uuid", "secret-name", "secretValue"}

func assertRejected(t *testing.T, body, want string) {
	t.Helper()
	_, err := Parse(model.Source{ID: "provider"}, []byte(body), nil)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
	for _, secret := range safetySecrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %v", secret, err)
		}
	}
}

func nativeVLESS(t *testing.T, mutate func(o map[string]any)) string {
	t.Helper()
	o := map[string]any{
		"type": "vless", "tag": "secret-name", "server": "secret-host.example", "server_port": 443, "uuid": "secret-uuid",
		"tls":       map[string]any{"enabled": true, "server_name": "secret-host.example"},
		"transport": map[string]any{"type": "ws", "path": "/ws"},
		"multiplex": map[string]any{"enabled": true, "protocol": "h2mux"},
	}
	mutate(o)
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestNativeRejectsForbiddenOptions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(o map[string]any)
		want   string
	}{
		{"detour", func(o map[string]any) { o["detour"] = "other" }, "unsupported option detour"},
		{"domain_resolver", func(o map[string]any) { o["domain_resolver"] = "local" }, "unsupported option domain_resolver"},
		{"bind_interface", func(o map[string]any) { o["bind_interface"] = "eth0" }, "unsupported option bind_interface"},
		{"inet4_bind_address", func(o map[string]any) { o["inet4_bind_address"] = "10.0.0.1" }, "unsupported option inet4_bind_address"},
		{"inet6_bind_address", func(o map[string]any) { o["inet6_bind_address"] = "::1" }, "unsupported option inet6_bind_address"},
		{"routing_mark", func(o map[string]any) { o["routing_mark"] = 1 }, "unsupported option routing_mark"},
		{"netns", func(o map[string]any) { o["netns"] = "/run/netns/x" }, "unsupported option netns"},
		{"reuse_addr", func(o map[string]any) { o["reuse_addr"] = true }, "unsupported option reuse_addr"},
		{"tcp_fast_open", func(o map[string]any) { o["tcp_fast_open"] = true }, "unsupported option tcp_fast_open"},
		{"plugin", func(o map[string]any) { o["plugin"] = "obfs-local" }, "unsupported option plugin"},
		{"unknown key not echoed", func(o map[string]any) { o["secretValue"] = "x" }, "unsupported option in provider node"},
		{"tls certificate_path", func(o map[string]any) { o["tls"].(map[string]any)["certificate_path"] = "/etc/ssl/x" }, "unsupported option tls.certificate_path"},
		{"tls certificate", func(o map[string]any) { o["tls"].(map[string]any)["certificate"] = []any{"pem"} }, "unsupported option tls.certificate"},
		{"tls key_path", func(o map[string]any) { o["tls"].(map[string]any)["key_path"] = "/etc/ssl/key" }, "unsupported option tls.key_path"},
		{"tls client_certificate_path", func(o map[string]any) { o["tls"].(map[string]any)["client_certificate_path"] = "/x" }, "unsupported option tls.client_certificate_path"},
		{"tls client_key_path", func(o map[string]any) { o["tls"].(map[string]any)["client_key_path"] = "/x" }, "unsupported option tls.client_key_path"},
		{"tls ech config_path", func(o map[string]any) {
			o["tls"].(map[string]any)["ech"] = map[string]any{"enabled": true, "config_path": "/x"}
		}, "unsupported option tls.ech.config_path"},
		{"tls utls nested", func(o map[string]any) {
			o["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "detour": "x"}
		}, "unsupported option tls.utls.detour"},
		{"tls as scalar", func(o map[string]any) { o["tls"] = true }, "option tls must be an object"},
		{"leaf as object", func(o map[string]any) { o["server_port"] = map[string]any{"detour": "x"} }, "option server_port must not be an object"},
		{"leaf array of objects", func(o map[string]any) {
			o["tls"].(map[string]any)["alpn"] = []any{map[string]any{"certificate_path": "/x"}}
		}, "option tls.alpn must be a scalar"},
		{"transport detour", func(o map[string]any) { o["transport"].(map[string]any)["detour"] = "x" }, "unsupported option transport.detour"},
		{"ws transport grpc field", func(o map[string]any) { o["transport"].(map[string]any)["service_name"] = "x" }, "unsupported option transport.service_name"},
		{"ws header object", func(o map[string]any) {
			o["transport"].(map[string]any)["headers"] = map[string]any{"Host": map[string]any{"x": "y"}}
		}, "option transport.headers values"},
		{"multiplex brutal nested", func(o map[string]any) {
			o["multiplex"].(map[string]any)["brutal"] = map[string]any{"enabled": true, "bind_interface": "eth0"}
		}, "unsupported option multiplex.brutal.bind_interface"},
		{"multiplex unknown", func(o map[string]any) { o["multiplex"].(map[string]any)["detour"] = "x" }, "unsupported option multiplex.detour"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, nativeVLESS(t, tc.mutate), tc.want)
		})
	}
	// Per-type allowlists: options valid for one protocol are rejected for another.
	assertRejected(t, `{"type":"trojan","tag":"n","server":"a.example","server_port":443,"password":"secret-pass","uuid":"secret-uuid"}`, "unsupported option uuid")
	assertRejected(t, `{"type":"tuic","tag":"n","server":"a.example","server_port":443,"uuid":"u","password":"secret-pass","multiplex":{"enabled":true}}`, "unsupported option multiplex")
	assertRejected(t, `{"type":"hysteria2","tag":"n","server":"a.example","server_port":443,"password":"secret-pass","obfs":{"type":"salamander","password":"p","detour":"x"}}`, "unsupported option obfs.detour")
}

func TestNativeAcceptsAllowlistedOptions(t *testing.T) {
	body := nativeVLESS(t, func(o map[string]any) {
		o["flow"] = "xtls-rprx-vision"
		o["packet_encoding"] = "xudp"
		o["network"] = "tcp"
		o["transport"] = map[string]any{"type": "ws", "path": "/ws", "headers": map[string]any{"Host": "front.example", "X-Multi": []any{"a", "b"}}, "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}
		o["tls"] = map[string]any{
			"enabled": true, "server_name": "front.example", "insecure": false, "alpn": []any{"h2"},
			"min_version": "1.2", "max_version": "1.3", "cipher_suites": []any{"TLS_AES_128_GCM_SHA256"},
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": "pk", "short_id": "ab"},
			"ech":     map[string]any{"enabled": true, "config": []any{"-----BEGIN ECH CONFIGS-----"}},
		}
		o["multiplex"] = map[string]any{"enabled": true, "protocol": "smux", "max_connections": 4, "min_streams": 4, "max_streams": 0, "padding": true, "brutal": map[string]any{"enabled": false, "up_mbps": 10, "down_mbps": 50}}
	})
	if _, err := Parse(model.Source{ID: "provider"}, []byte(body), nil); err != nil {
		t.Fatal(err)
	}
	accepted := []string{
		`{"type":"shadowsocks","tag":"ss","server":"a.example","server_port":8388,"method":"aes-256-gcm","password":"p","network":"tcp","udp_over_tcp":true,"multiplex":{"enabled":true}}`,
		`{"type":"shadowsocks","tag":"ss2","server":"a.example","server_port":8388,"method":"aes-256-gcm","password":"p","udp_over_tcp":{"enabled":true,"version":2}}`,
		`{"type":"vmess","tag":"vm","server":"a.example","server_port":443,"uuid":"u","security":"auto","alter_id":0,"global_padding":true,"authenticated_length":true,"packet_encoding":"packetaddr","transport":{"type":"grpc","service_name":"svc","idle_timeout":"15s","ping_timeout":"15s","permit_without_stream":false}}`,
		`{"type":"tuic","tag":"tu","server":"a.example","server_port":443,"uuid":"u","password":"p","congestion_control":"bbr","udp_relay_mode":"quic","udp_over_stream":false,"zero_rtt_handshake":false,"heartbeat":"10s","tls":{"enabled":true,"alpn":["h3"]}}`,
	}
	for _, body := range accepted {
		if _, err := Parse(model.Source{ID: "provider"}, []byte(body), nil); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	}
}

func TestInsecureTLSRejectedInAllFormats(t *testing.T) {
	vmessLink := func(verify any) string {
		payload, _ := json.Marshal(map[string]any{
			"v": "2", "ps": "secret-name", "add": "secret-host.example", "port": "443", "id": "secret-uuid",
			"net": "tcp", "tls": "tls", "verify_cert": verify,
		})
		return "vmess://" + base64.StdEncoding.EncodeToString(payload)
	}
	rejected := []struct{ name, body string }{
		{"native insecure", nativeVLESS(t, func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = true })},
		{"clash skip-cert-verify", "proxies:\n  - {name: secret-name, type: vmess, server: secret-host.example, port: 443, uuid: secret-uuid, tls: true, skip-cert-verify: true}\n"},
		{"hysteria2 insecure=1", "hy2://secret-pass@secret-host.example:443?insecure=1#node"},
		{"hysteria2 insecure=true", "hysteria2://secret-pass@secret-host.example:443?insecure=true#node"},
		{"vmess verify_cert false", vmessLink(false)},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, tc.body, "certificate verification must stay enabled")
		})
	}
	assertRejected(t, nativeVLESS(t, func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = "true" }), "insecure must be a boolean")

	accepted := []string{
		nativeVLESS(t, func(o map[string]any) { o["tls"].(map[string]any)["insecure"] = false }),
		"proxies:\n  - {name: n, type: vmess, server: a.example, port: 443, uuid: u, tls: true, skip-cert-verify: false}\n",
		"hy2://pass@a.example:443?insecure=0#node",
		"hy2://pass@a.example:443?insecure=false#node",
		vmessLink(true),
	}
	for _, body := range accepted {
		nodes, err := Parse(model.Source{ID: "provider"}, []byte(body), nil)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if tls := nodes[0].Outbound["tls"].(map[string]any); tls["insecure"] != false {
			t.Fatalf("%s: insecure false must be preserved: %v", body, tls)
		}
	}
}

func TestServerAddressPolicy(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "::1", "[::1]", "0.0.0.0", "0.1.2.3", "::",
		"10.0.0.1", "172.16.5.4", "192.168.1.1", "fc00::1", "fd12:3456::1",
		"169.254.169.254", "fe80::1", "fe80::1%eth0",
		"100.64.0.1", "100.100.100.200", "100.127.255.255",
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff01::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:100.100.100.200", "::ffff:10.1.1.1",
		"::127.0.0.1", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1",
		"198.18.0.1", "255.255.255.255", "127.0.0.1.",
		"localhost", "LOCALHOST.", "api.localhost",
		"127.1", "2130706433", "0x7f.1", "0x7f000001",
	}
	for _, server := range blocked {
		t.Run("blocked "+server, func(t *testing.T) {
			if err := validateServerAddress(server); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.32.0.1", "192.0.2.8",
		"2606:4700:4700::1111", "[2606:4700:4700::1111]", "::ffff:1.1.1.1", "64:ff9b::808:808",
		"example.com", "node-1.provider.example", "a1.b2", "localhost.example.com",
	}
	for _, server := range allowed {
		t.Run("allowed "+server, func(t *testing.T) {
			if err := validateServerAddress(server); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := validateServerAddress("a.example com"); err == nil {
		t.Fatal("whitespace in server must be rejected")
	}
}

func TestPrivateServerRejectedInAllFormats(t *testing.T) {
	vmessPayload, _ := json.Marshal(map[string]any{"v": "2", "ps": "secret-name", "add": "100.100.100.200", "port": "80", "id": "secret-uuid"})
	cases := []struct{ name, body string }{
		{"native loopback", nativeVLESS(t, func(o map[string]any) { o["server"] = "127.0.0.1" })},
		{"native mapped IMDS", nativeVLESS(t, func(o map[string]any) { o["server"] = "::ffff:100.100.100.200" })},
		{"clash private", "proxies:\n  - {name: secret-name, type: ss, server: 192.168.1.1, port: 8388, cipher: aes-256-gcm, password: secret-pass}\n"},
		{"ss link link-local", "ss://" + encode("aes-256-gcm:secret-pass") + "@169.254.169.254:8388#node"},
		{"vmess link IMDS", "vmess://" + base64.StdEncoding.EncodeToString(vmessPayload)},
		{"vless link IPv6 loopback", "vless://secret-uuid@[::1]:443#node"},
		{"trojan link CGNAT", "trojan://secret-pass@100.64.1.1:443#node"},
		{"hysteria2 link unspecified", "hy2://secret-pass@0.0.0.0:443#node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRejected(t, tc.body, "public address or hostname")
		})
	}
	for _, body := range []string{
		nativeVLESS(t, func(o map[string]any) { o["server"] = "203.0.113.10" }),
		"trojan://pass@1.1.1.1:443#node",
		"vless://uuid@[2606:4700:4700::1111]:443#node",
		"ss://" + encode("aes-256-gcm:pass") + "@ss.example:8388#node",
	} {
		if _, err := Parse(model.Source{ID: "provider"}, []byte(body), nil); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	}
}
