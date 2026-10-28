package nodes

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ttd/subscription-composer/internal/model"
)

func TestSSPanelVMessMetadataAndCertificateVerification(t *testing.T) {
	for _, verify := range []bool{true, false} {
		payload, err := json.Marshal(map[string]any{
			"v": "2", "ps": "JP Panel", "add": "node.example.com", "port": "443",
			"id": "11111111-1111-1111-1111-111111111111", "aid": "0",
			"net": "ws", "type": "none", "host": "node.example.com", "path": "/ws",
			"tls": "tls", "class": 1, "verify_cert": verify,
		})
		if err != nil {
			t.Fatal(err)
		}
		link := "vmess://" + base64.StdEncoding.EncodeToString(payload)
		parsed, err := Parse(model.Source{ID: "panel"}, []byte(link), nil)
		if err != nil {
			t.Fatal(err)
		}
		tls, ok := parsed[0].Outbound["tls"].(map[string]any)
		if !ok || tls["insecure"] != !verify {
			t.Fatal("certificate verification semantics were lost")
		}
		if _, ok := parsed[0].Outbound["class"]; ok {
			t.Fatal("provider presentation metadata leaked into native config")
		}
	}
}

func TestSSPanelVMessRejectsAmbiguousCertificatePolicy(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"v": "2", "ps": "JP Panel", "add": "node.example.com", "port": "443",
		"id": "11111111-1111-1111-1111-111111111111", "net": "tcp", "tls": "tls",
		"verify_cert": "false",
	})
	_, err := Parse(model.Source{ID: "panel"}, []byte("vmess://"+base64.StdEncoding.EncodeToString(payload)), nil)
	if err == nil {
		t.Fatal("ambiguous string certificate policy was accepted")
	}
}
