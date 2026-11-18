package compose

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
)

// TestNativeLocalProxySourceGuard runs sing-box to establish runtime behavior
// that a schema check cannot: IPv4 clients on a dual-stack listener are matched
// by plain IPv4 prefixes, disallowed sources are rejected on both generated
// listeners, and traffic from other inbounds is never caught by the guard.
func TestNativeLocalProxySourceGuard(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reachable")
	}))
	defer target.Close()

	cases := []struct {
		name string
		// sources replaces the generated allowlist; nil keeps it unchanged.
		sources                  []string
		ipv4Allowed, ipv6Allowed bool
		// naive replaces the logical guard with a plain inverted default rule.
		naive        bool
		otherAllowed bool
	}{
		{"generated allowlist", nil, true, true, false, true},
		{"loopback excluded", []string{"192.168.1.0/24", "100.64.0.0/10"}, false, false, false, true},
		{"only IPv6 loopback", []string{"::1/128"}, false, true, false, true},
		{"only IPv4 loopback", []string{"127.0.0.0/8"}, true, false, false, true},
		// A mapped prefix never matches because sing-box unmaps client addresses.
		{"only mapped IPv4 loopback", []string{"::ffff:127.0.0.0/104"}, false, false, false, true},
		// Negative control: invert negates the inbound match too, so a plain
		// rule would reject every other inbound, including TUN.
		{"naive inverted rule", nil, true, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ports := reservePorts(t, 3)
			device := model.Device{
				ID: "guard-test", Platform: "linux",
				RemoteControl: model.RemoteControl{Enabled: boolPointer(false)},
				LocalProxy:    model.LocalProxy{AllowTailscale: true, AllowCIDRs: []string{"192.168.1.0/24"}},
				Base: json.RawMessage(fmt.Sprintf(`{
					"log":{"level":"warn"},
					"inbounds":[{"type":"mixed","tag":"other-in","listen":"::","listen_port":%d}],
					"route":{"rules":[{"inbound":["other-in"],"action":"route","outbound":"direct"}]}
				}`, ports[2])),
			}
			_, _, nodes := fixture()
			content, err := Build(device, model.Policy{}, nodes)
			if err != nil {
				t.Fatal(err)
			}
			profile := decode(t, content)
			for _, raw := range profile["inbounds"].([]any) {
				inbound := raw.(map[string]any)
				switch inbound["tag"] {
				case "mixed-rules":
					inbound["listen_port"] = ports[0]
				case "mixed-direct":
					inbound["listen_port"] = ports[1]
				}
			}
			rules := profile["route"].(map[string]any)["rules"].([]any)
			// The direct route lets mixed-rules reach the target without real nodes.
			rules = append([]any{rules[0], map[string]any{"inbound": []any{"mixed-rules"}, "action": "route", "outbound": "direct"}}, rules[1:]...)
			profile["route"].(map[string]any)["rules"] = rules
			guard := rules[0].(map[string]any)["rules"].([]any)[1].(map[string]any)
			if tc.sources != nil {
				guard["source_ip_cidr"] = tc.sources
			}
			if tc.naive {
				rules[0] = map[string]any{
					"inbound":        []any{"mixed-rules", "mixed-direct"},
					"source_ip_cidr": guard["source_ip_cidr"],
					"invert":         true, "action": "reject",
				}
			}
			content, err = json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), binary, content); err != nil {
				t.Fatal(err)
			}
			startSingBox(t, binary, content, ports)
			for _, listener := range []struct {
				tag     string
				port    int
				guarded bool
			}{
				{"mixed-rules", ports[0], true},
				{"mixed-direct", ports[1], true},
				{"other-in", ports[2], false},
			} {
				for _, client := range []struct {
					host    string
					allowed bool
				}{
					{"127.0.0.1", tc.ipv4Allowed},
					{"::1", tc.ipv6Allowed},
				} {
					want := client.allowed
					if !listener.guarded {
						want = tc.otherAllowed
					}
					proxy := net.JoinHostPort(client.host, strconv.Itoa(listener.port))
					if got := httpProxyReaches(proxy, target.URL); got != want {
						t.Errorf("HTTP via %s from %s: reachable=%v, want %v", listener.tag, client.host, got, want)
					}
					if got := socksProxyReaches(proxy, target.Listener.Addr().String()); got != want {
						t.Errorf("SOCKS5 via %s from %s: reachable=%v, want %v", listener.tag, client.host, got, want)
					}
				}
			}
		})
	}
}

// TestNativeDarwinDualLocalProxyListeners verifies that macOS profiles can bind
// wildcard :: and companion 127.0.0.1 listeners on the same ports under Darwin,
// and that mixed-direct-loopback bypasses policy rules alongside mixed-direct.
func TestNativeDarwinDualLocalProxyListeners(t *testing.T) {
	binary := os.Getenv("SUBCOMPOSE_SING_BOX")
	if binary == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("macOS dual wildcard and loopback listeners require Darwin socket semantics")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reachable")
	}))
	defer target.Close()

	for _, tc := range []struct {
		name        string
		rejectRules bool
		rulesWant   bool
	}{
		{"policy and direct listeners reachable", false, true},
		{"direct loopback bypasses policy reject", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ports := reservePorts(t, 2)
			device := model.Device{
				ID:            "macos-dual-test",
				Platform:      "macos",
				RemoteControl: model.RemoteControl{Enabled: boolPointer(false)},
				LocalProxy:    model.LocalProxy{AllowTailscale: true, AllowCIDRs: []string{"192.0.2.0/24"}},
				Base:          json.RawMessage(`{"log":{"level":"warn"}}`),
			}
			var policy model.Policy
			if tc.rejectRules {
				policy.Rules = []json.RawMessage{
					json.RawMessage(`{"ip_cidr":["127.0.0.0/8","::1/128"],"action":"reject"}`),
				}
			}
			_, _, nodes := fixture()
			content, err := Build(device, policy, nodes)
			if err != nil {
				t.Fatal(err)
			}
			profile := decode(t, content)
			for _, raw := range profile["inbounds"].([]any) {
				inbound := raw.(map[string]any)
				switch inbound["tag"] {
				case "mixed-rules", "mixed-rules-loopback":
					inbound["listen_port"] = ports[0]
				case "mixed-direct", "mixed-direct-loopback":
					inbound["listen_port"] = ports[1]
				}
			}
			if !tc.rejectRules {
				rules := profile["route"].(map[string]any)["rules"].([]any)
				rules = append(rules[:2], append([]any{
					map[string]any{"inbound": []any{"mixed-rules", "mixed-rules-loopback"}, "action": "route", "outbound": "direct"},
				}, rules[2:]...)...)
				profile["route"].(map[string]any)["rules"] = rules
			}
			content, err = json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), binary, content); err != nil {
				t.Fatal(err)
			}
			startSingBox(t, binary, content, ports)
			for _, listener := range []struct {
				name string
				port int
				want bool
			}{
				{"rules", ports[0], tc.rulesWant},
				{"direct", ports[1], true},
			} {
				for _, host := range []string{"127.0.0.1", "::1"} {
					proxy := net.JoinHostPort(host, strconv.Itoa(listener.port))
					if got := httpProxyReaches(proxy, target.URL); got != listener.want {
						t.Errorf("HTTP via %s (%s): reachable=%v, want %v", listener.name, host, got, listener.want)
					}
					if got := socksProxyReaches(proxy, target.Listener.Addr().String()); got != listener.want {
						t.Errorf("SOCKS5 via %s (%s): reachable=%v, want %v", listener.name, host, got, listener.want)
					}
				}
			}
		})
	}
}

func reservePorts(t *testing.T, count int) []int {
	t.Helper()
	ports := make([]int, 0, count)
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	for range count {
		listener, err := net.Listen("tcp", "[::]:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func startSingBox(t *testing.T, binary string, content []byte, ports []int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "run", "-D", dir, "-c", path)
	cmd.Env = []string{"HOME=/var/empty"}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal("could not start native proxy test instance")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); <-done })
	for _, port := range ports {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			select {
			case <-done:
				t.Fatal("native proxy test instance exited")
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("listener on port %d did not become reachable: %v", port, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func httpProxyReaches(proxy, target string) bool {
	proxyURL := &url.URL{Scheme: "http", Host: proxy}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	return err == nil && response.StatusCode == http.StatusOK && string(body) == "reachable"
}

// socksProxyReaches performs a minimal SOCKS5 CONNECT followed by an HTTP request.
func socksProxyReaches(proxy, target string) bool {
	conn, err := net.DialTimeout("tcp", proxy, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return false
	}
	address := net.ParseIP(host).To4()
	if address == nil {
		return false
	}
	if err := socksConnect(conn, address, uint16(port)); err != nil {
		return false
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n"); err != nil {
		return false
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	return err == nil && response.StatusCode == http.StatusOK && string(body) == "reachable"
}

func socksConnect(conn net.Conn, address net.IP, port uint16) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil || greeting[0] != 5 || greeting[1] != 0 {
		return errors.New("SOCKS5 greeting failed")
	}
	request := append([]byte{5, 1, 0, 1}, address...)
	request = binary.BigEndian.AppendUint16(request, port)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		return errors.New("SOCKS5 connect failed")
	}
	return nil
}
