package compose

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/nodes"
)

// Exercise the full import-to-dial path without external DNS, TUN or credentials.
func TestNativeProviderDNSResolution(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	dnsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsListener.Close()
	queries := make(chan string, 32)
	go func() {
		for {
			conn, err := dnsListener.Accept()
			if err != nil {
				return
			}
			go serveNodeDNS(conn, queries)
		}
	}()
	endpoint, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	connected := make(chan struct{})
	go func() {
		conn, err := endpoint.Accept()
		if err == nil {
			conn.Close()
			close(connected)
		}
	}()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	input := fmt.Sprintf(`proxies:
  - {name: JP Probe, type: ss, server: gateway.entry.test, port: %d, cipher: aes-256-gcm, password: test-only}
x-client-custom:
  nameserver-policy:
    "+.entry.test": ["https://127.0.0.1:1/dns-query", "tcp://127.0.0.1:%d#cost-bias=+100ms"]
`, endpoint.Addr().(*net.TCPAddr).Port, dnsListener.Addr().(*net.TCPAddr).Port)
	imported, err := nodes.Parse(model.Source{ID: "airport", Format: "clash"}, []byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "http", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"dns": map[string]any{"servers": []any{map[string]any{
			"type": "hosts", "tag": "bootstrap", "predefined": map[string][]string{"unrelated.test": {"192.0.2.1"}},
		}}},
		"route": map[string]any{"default_domain_resolver": "bootstrap"},
	})
	config, err := Build(model.Device{ID: "probe", Base: base}, model.Policy{}, imported)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Check(ctx, binary, config); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	var proxy net.Conn
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		proxy, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("native proxy did not start")
	}
	defer proxy.Close()
	if _, err := io.WriteString(proxy, "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-queries:
		if name != "gateway.entry.test" {
			t.Fatal("provider DNS was queried for an unrelated domain")
		}
	case <-ctx.Done():
		t.Fatal("native proxy did not query the imported provider DNS")
	}
	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("native proxy did not dial the address returned by provider DNS")
	}
}

func serveNodeDNS(conn net.Conn, queries chan<- string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length < 17 || length > 4096 {
			return
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		offset := 12
		var labels []string
		for offset < len(query) && query[offset] != 0 {
			length := int(query[offset])
			offset++
			if length > 63 || offset+length >= len(query) {
				return
			}
			labels = append(labels, string(query[offset:offset+length]))
			offset += length
		}
		if offset+5 > len(query) {
			return
		}
		kind := binary.BigEndian.Uint16(query[offset+1 : offset+3])
		response := append([]byte(nil), query[:offset+5]...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[6:8], 0)
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		if kind == 1 {
			binary.BigEndian.PutUint16(response[6:8], 1)
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
		}
		select {
		case queries <- strings.Join(labels, "."):
		default:
		}
		binary.BigEndian.PutUint16(size[:], uint16(len(response)))
		if _, err := conn.Write(append(size[:], response...)); err != nil {
			return
		}
	}
}
