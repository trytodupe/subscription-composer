package nodes

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func encode(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }

func TestLinks(t *testing.T) {
	vmess := `{"v":"2","ps":"Tokyo","add":"vm.example","port":"443","id":"uuid","aid":"0","scy":"auto","net":"ws","host":"front.example","path":"/ws","tls":"tls","sni":"tls.example"}`
	cases := []struct {
		name, link, typ, country string
		check                    func(t *testing.T, outbound map[string]any)
	}{
		{"SIP002 SS subscription", encode("ss://" + encode("aes-256-gcm:password") + "@ss.example:8388#US%20Node"), "shadowsocks", "US", func(t *testing.T, o map[string]any) {
			if o["method"] != "aes-256-gcm" || o["password"] != "password" {
				t.Fatal(o)
			}
		}},
		{"VMess TLS WS", "vmess://" + encode(vmess), "vmess", "JP", func(t *testing.T, o map[string]any) {
			if o["tls"].(map[string]any)["server_name"] != "tls.example" || o["transport"].(map[string]any)["headers"].(map[string]any)["Host"] != "front.example" {
				t.Fatal(o)
			}
		}},
		{"VLESS Reality Vision", "vless://uuid@vl.example:443?security=reality&sni=target.example&fp=chrome&pbk=public&sid=1a&flow=xtls-rprx-vision&type=tcp#JP%20Reality", "vless", "JP", func(t *testing.T, o map[string]any) {
			tls := o["tls"].(map[string]any)
			if o["flow"] != "xtls-rprx-vision" || tls["reality"].(map[string]any)["public_key"] != "public" || tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
				t.Fatal(o)
			}
		}},
		{"Trojan TLS", "trojan://password@tr.example:443?sni=front.example#Singapore", "trojan", "SG", func(t *testing.T, o map[string]any) {
			if o["tls"].(map[string]any)["enabled"] != true {
				t.Fatal(o)
			}
		}},
		{"Hysteria2 TLS obfs bandwidth", "hy2://user:" + "pass" + "@hy.example:443?sni=front.example&insecure=1&obfs=salamander&obfs-password=" + "obfuscation" + "&upmbps=100&downmbps=250#DE%20Node", "hysteria2", "DE", func(t *testing.T, o map[string]any) {
			if o["password"] != "user:pass" || o["up_mbps"] != 100 || o["down_mbps"] != 250 || o["obfs"].(map[string]any)["password"] != "obfuscation" || o["tls"].(map[string]any)["insecure"] != true {
				t.Fatal(o)
			}
		}},
		{"Hysteria2 alias", "hysteria2://pass@hy.example:8443?sni=front.example&insecure=false#HK%20Node", "hysteria2", "HK", func(t *testing.T, o map[string]any) {
			if o["password"] != "pass" || o["tls"].(map[string]any)["insecure"] != false {
				t.Fatal(o)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := Parse(model.Source{ID: "provider"}, []byte(tc.link), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes) != 1 || nodes[0].Outbound["type"] != tc.typ || nodes[0].Country != tc.country || nodes[0].Tag != "provider / "+nodes[0].Name || nodes[0].Tag != nodes[0].Outbound["tag"] || nodes[0].Provider != "provider" {
				t.Fatal(nodes)
			}
			tc.check(t, nodes[0].Outbound)
		})
	}
}

func TestNativeFullConfig(t *testing.T) {
	body := `{"dns":{"servers":[{"tag":"unused"}]},"route":{"rules":[{"outbound":"gone"}]},"outbounds":[{"type":"selector","tag":"group","outbounds":["JP"]},{"type":"direct","tag":"direct"},{"type":"vless","tag":"JP","server":"example.com","server_port":443,"uuid":"id","tls":{"enabled":true,"server_name":"front"},"transport":{"type":"ws","path":"/stream"},"packet_encoding":"xudp"}]}`
	nodes, err := Parse(model.Source{ID: "native", Format: "sing-box"}, []byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "JP" || nodes[0].Country != "JP" {
		t.Fatal(nodes)
	}
	out := nodes[0].Outbound
	if out["packet_encoding"] != "xudp" || out["tls"].(map[string]any)["server_name"] != "front" || out["tag"] != nodes[0].Tag {
		t.Fatal(out)
	}
	if _, ok := out["route"]; ok {
		t.Fatal(out)
	}
	if _, ok := out["dns"]; ok {
		t.Fatal(out)
	}
	for _, input := range []string{`[{"type":"trojan","tag":"one","server":"x","server_port":443,"password":"p"}]`, `{"type":"trojan","tag":"one","server":"x","server_port":443,"password":"p"}`} {
		if got, err := Parse(model.Source{ID: "native"}, []byte(input), nil); err != nil || len(got) != 1 {
			t.Fatalf("single/array: %v, %v", got, err)
		}
	}
}

func TestUnsupportedAndEmpty(t *testing.T) {
	cases := []struct{ name, body, message string }{
		{"empty", "  ", "empty subscription"},
		{"only groups", `{"outbounds":[{"type":"selector","tag":"group"}]}`, "no supported nodes"},
		{"incomplete YAML proxy", "proxies:\n  - name: JP", "Clash type is required"},
		{"unknown protocol", "tuic://secret@example.com:443#node", "unsupported link protocol"},
		{"SS plugin", "ss://" + encode("aes-128-gcm:secret") + "@a.example:443?plugin=obfs-local#node", "SS plugin"},
		{"VLESS transport", "vless://id@a.example:443?type=quic#node", "unsupported transport"},
		{"unknown query", "vless://id@a.example:443?secretField=secretValue#node", "unsupported or repeated"},
		{"unknown VMess field", "vmess://" + encode(`{"ps":"node","add":"a.example","port":443,"id":"id","net":"tcp","obfs":"secretValue"}`), "unsupported VMess"},
		{"native detour", `{"type":"vless","tag":"node","server":"example.com","server_port":443,"uuid":"id","detour":"other"}`, "detour"},
		{"native transport", `{"type":"vless","tag":"node","server":"example.com","server_port":443,"uuid":"id","transport":{"type":"http"}}`, "unsupported transport"},
		{"native unsupported type", `{"type":"hysteria","tag":"node","server":"example.com","server_port":443}`, "unsupported native protocol"},
		{"native missing credentials", `{"type":"vless","tag":"node","server":"example.com","server_port":443}`, "uuid is required"},
		{"native Hysteria2 missing password", `{"type":"hysteria2","tag":"node","server":"example.com","server_port":443}`, "password is required"},
		{"native TUIC missing password", `{"type":"tuic","tag":"node","server":"example.com","server_port":443,"uuid":"id"}`, "password is required"},
		{"native TUIC missing UUID", `{"type":"tuic","tag":"node","server":"example.com","server_port":443,"password":"password"}`, "uuid is required"},
		{"native Hysteria2 bad port range", `{"type":"hysteria2","tag":"node","server":"example.com","server_ports":["500:100"],"password":"password"}`, "increasing ranges"},
		{"Hysteria2 missing obfs password", "hy2://pw@hy.example:443?obfs=salamander#node", "obfs requires"},
		{"Hysteria2 unsupported option", "hy2://pw@hy.example:443?skip-cert-verify=1#node", "unsupported or repeated"},
		{"Hysteria2 invalid bandwidth", "hy2://pw@hy.example:443?upmbps=10.5#node", "positive integer"},
		{"Hysteria2 invalid port", "hy2://pw@hy.example:65536#node", "node port"},
		{"Hysteria2 invalid insecure", "hy2://pw@hy.example:443?insecure=maybe#node", "insecure option"},
		{"malformed options", "vless://id@a.example:443?security=tls&%ZZ=x#node", "malformed proxy link query"},
		{"invalid reality", "vless://id@a.example:443?security=reality#node", "public key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(model.Source{ID: "provider"}, []byte(tc.body), nil)
			if err == nil || !strings.Contains(err.Error(), tc.message) || strings.Contains(err.Error(), "secretValue") || strings.Contains(err.Error(), "secretField") {
				t.Fatalf("error: %v", err)
			}
		})
	}
}

func TestStableTagsAndOverrides(t *testing.T) {
	input := func(server, password string) []byte {
		body, _ := json.Marshal(map[string]any{"type": "trojan", "tag": "🇯🇵 Tokyo", "server": server, "server_port": 443, "password": password})
		return body
	}
	source := model.Source{ID: "provider"}
	first, err := Parse(source, input("old.example", "oldsecret"), map[string]string{"🇯🇵 Tokyo": "us", "provider/🇯🇵 Tokyo": "kr"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(source, input("new.example", "newsecret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Tag != "provider / 🇯🇵 Tokyo" || first[0].Tag != second[0].Tag || first[0].Outbound["tag"] != first[0].Tag || first[0].Country != "KR" || second[0].Country != "JP" {
		t.Fatal(first, second)
	}
	other, err := Parse(model.Source{ID: "another"}, input("old.example", "oldsecret"), nil)
	if err != nil || other[0].Tag == first[0].Tag {
		t.Fatal(other, err)
	}
	_, err = Parse(source, []byte("ss://"+encode("aes-256-gcm:pass")+"@a.example:443#same\nss://"+encode("aes-256-gcm:other")+"@b.example:443#same"), nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate name error, got %v", err)
	}
	unknown, err := Parse(source, input("old.example", "oldsecret"), map[string]string{"🇯🇵 Tokyo": "other"})
	if err != nil || unknown[0].Country != "OTHER" {
		t.Fatal(unknown, err)
	}
	firstOrder := "trojan://one@a.example:443#HK%20One\ntrojan://two@b.example:443#US%20Two"
	reversed := "trojan://changed@c.example:443#US%20Two\ntrojan://rotated@d.example:443#HK%20One"
	a, err := Parse(source, []byte(firstOrder), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(source, []byte(reversed), nil)
	if err != nil || a[0].Tag != b[1].Tag || a[1].Tag != b[0].Tag {
		t.Fatal(a, b, err)
	}
}

func TestNativeQUICOutbounds(t *testing.T) {
	config := `{"outbounds":[{"type":"selector","tag":"group"},{"type":"hysteria2","tag":"🇸🇬 Fast","server":"hy.example","server_port":443,"password":"auth","up_mbps":120,"down_mbps":240,"obfs":{"type":"salamander","password":"obfs-secret"},"tls":{"enabled":true,"server_name":"front.example"}},{"type":"tuic","tag":"🇭🇰 Backup","server":"tuic.example","server_port":8443,"uuid":"client-id","password":"auth","congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":true,"server_name":"tuic.example"}}]}`
	nodes, err := Parse(model.Source{ID: "provider"}, []byte(config), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].Tag != "provider / 🇸🇬 Fast" || nodes[1].Tag != "provider / 🇭🇰 Backup" || nodes[0].Country != "SG" || nodes[1].Country != "HK" {
		t.Fatal(nodes)
	}
	hy, tuic := nodes[0].Outbound, nodes[1].Outbound
	if hy["up_mbps"] != float64(120) || hy["obfs"].(map[string]any)["password"] != "obfs-secret" || hy["tls"].(map[string]any)["server_name"] != "front.example" || hy["tag"] != nodes[0].Tag {
		t.Fatal(hy)
	}
	if tuic["uuid"] != "client-id" || tuic["password"] != "auth" || tuic["congestion_control"] != "bbr" || tuic["udp_relay_mode"] != "native" || tuic["tag"] != nodes[1].Tag {
		t.Fatal(tuic)
	}
	ranged := `{"type":"hysteria2","tag":"Ranged","server":"range.example","server_ports":["2080:3000","443"],"hop_interval":"30s","password":"auth","tls":{"enabled":true}}`
	got, err := Parse(model.Source{ID: "provider"}, []byte(ranged), nil)
	if err != nil || len(got) != 1 || got[0].Outbound["server_ports"].([]any)[0] != "2080:3000" || got[0].Outbound["hop_interval"] != "30s" {
		t.Fatal(got, err)
	}
}
