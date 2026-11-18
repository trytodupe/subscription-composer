package netsafe

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var (
	testRootsOnce sync.Once
	testRoots     *x509.CertPool
)

// httptest TLS servers all share one certificate (valid for 127.0.0.1, ::1
// and example.com), so one pool trusts every test server.
func roots(t *testing.T) *x509.CertPool {
	t.Helper()
	testRootsOnce.Do(func() {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		testRoots = x509.NewCertPool()
		testRoots.AddCert(server.Certificate())
		server.Close()
	})
	return testRoots
}

func strictClient(t *testing.T) *http.Client {
	return NewClient(Policy{RootCAs: roots(t)})
}

func relaxedClient(t *testing.T) *http.Client {
	return NewClient(Policy{AllowLoopback: true, RootCAs: roots(t)})
}

func get(t *testing.T, client *http.Client, target string, header http.Header) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

func TestCheckBlocksNonPublicAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "0.1.2.3", "::",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1", "fc00::1",
		"100.64.0.1", "100.100.100.200", "100.127.255.255",
		"169.254.169.254", "fe80::1", "fe80::1%en0",
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff01::1", "ff0e::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:100.100.100.200", "::ffff:10.0.0.1",
		"64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "64:ff9b:1::1",
		"::127.0.0.1", "::ffff:0:a9fe:a9fe", "2002:7f00:1::1", "2001::1", "2001:db8::1", "fec0::1", "100::1",
		"255.255.255.255", "240.0.0.1", "198.18.0.1", "192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
	} {
		addr := netip.MustParseAddr(raw)
		if err := (Policy{}).Check(addr); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: expected blocked, got %v", raw, err)
		}
	}
	if err := (Policy{}).Check(netip.Addr{}); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("zero address: expected blocked, got %v", err)
	}
}

func TestCheckAllowsPublicAddresses(t *testing.T) {
	for _, raw := range []string{
		"1.1.1.1", "8.8.8.8", "140.82.112.3", "185.199.108.133", "104.16.0.1",
		"100.63.255.255", "100.128.0.0", "172.32.0.1", "11.0.0.1",
		"2606:4700:4700::1111", "2a00:1450:4001::1", "::ffff:8.8.8.8", "64:ff9b::808:808",
	} {
		if err := (Policy{}).Check(netip.MustParseAddr(raw)); err != nil {
			t.Errorf("%s: expected allowed, got %v", raw, err)
		}
	}
}

func TestAllowLoopbackRelaxesOnlyLoopback(t *testing.T) {
	relaxed := Policy{AllowLoopback: true}
	for _, raw := range []string{"127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"} {
		if err := relaxed.Check(netip.MustParseAddr(raw)); err != nil {
			t.Errorf("%s: expected allowed by test policy, got %v", raw, err)
		}
	}
	for _, raw := range []string{"169.254.169.254", "100.100.100.200", "10.0.0.1", "fd00::1", "0.0.0.0", "64:ff9b::7f00:1"} {
		if err := relaxed.Check(netip.MustParseAddr(raw)); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: expected still blocked, got %v", raw, err)
		}
	}
}

func TestControlRejectsNonTCPAndBadAddresses(t *testing.T) {
	if err := (Policy{}).control("udp4", "8.8.8.8:53", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("udp accepted: %v", err)
	}
	if err := (Policy{}).control("tcp4", "example.com:443", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("unresolved address accepted: %v", err)
	}
	if err := (Policy{}).control("tcp6", "[fe80::1%en0]:443", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("zoned link-local accepted: %v", err)
	}
	if err := (Policy{}).control("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public address rejected: %v", err)
	}
}

func TestDialRejectsLoopbackAfterResolution(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	for _, target := range []string{server.URL, "https://localhost:" + port + "/"} {
		if _, err := get(t, strictClient(t), target, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: expected blocked dial, got %v", target, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("blocked destination received a request")
	}
	if resp, err := get(t, relaxedClient(t), server.URL, nil); err != nil || resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("test policy could not reach loopback: %v", err)
	}
}

func TestNewTransportHonorsEnvironmentProxy(t *testing.T) {
	if NewTransport(Policy{}).Proxy == nil {
		t.Fatal("operator proxy environment is ignored")
	}
}

func TestRedirectSameOriginKeepsHeaders(t *testing.T) {
	var got http.Header
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		got = r.Header.Clone()
	}))
	defer server.Close()
	header := http.Header{"Authorization": {"Bearer secret"}, "X-Subscription-Token": {"secret"}}
	if _, err := get(t, relaxedClient(t), server.URL+"/start?token=secret", header); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer secret" || got.Get("X-Subscription-Token") != "secret" {
		t.Fatalf("same-origin redirect lost headers: %v", got)
	}
	if got.Get("Referer") != "" {
		t.Fatal("redirect sent a Referer carrying the source URL")
	}
}

func TestRedirectCrossOriginStripsCredentials(t *testing.T) {
	var got http.Header
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer destination.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/asset", http.StatusFound)
	}))
	defer origin.Close()
	header := http.Header{
		"Authorization":        {"Bearer secret"},
		"Cookie":               {"session=secret"},
		"X-Subscription-Token": {"secret"},
		"If-None-Match":        {`"etag"`},
		"User-Agent":           {"subcompose-test"},
	}
	if _, err := get(t, relaxedClient(t), origin.URL+"/sub?token=secret", header); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("cross-origin redirect was not followed")
	}
	for name, values := range got {
		for _, value := range values {
			if strings.Contains(value, "secret") || strings.Contains(value, "etag") {
				t.Errorf("cross-origin redirect leaked %s: %q", name, value)
			}
		}
	}
	if got.Get("User-Agent") != "subcompose-test" {
		t.Errorf("allowlisted header dropped: %v", got)
	}
}

func TestRedirectDowngradeRejected(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer plain.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/asset", http.StatusFound)
	}))
	defer origin.Close()
	if _, err := get(t, relaxedClient(t), origin.URL, nil); !errors.Is(err, ErrRedirectBlocked) || hits.Load() != 0 {
		t.Fatalf("https to http redirect followed: %v", err)
	}
}

func TestRedirectLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remaining, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if remaining > 0 {
			http.Redirect(w, r, fmt.Sprintf("/%d", remaining-1), http.StatusFound)
		}
	}))
	defer server.Close()
	if resp, err := get(t, relaxedClient(t), fmt.Sprintf("%s/%d", server.URL, MaxRedirects), nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%d redirects rejected: %v", MaxRedirects, err)
	}
	if _, err := get(t, relaxedClient(t), fmt.Sprintf("%s/%d", server.URL, MaxRedirects+1), nil); !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("%d redirects followed: %v", MaxRedirects+1, err)
	}
}

func TestCheckRedirectUnit(t *testing.T) {
	origin, _ := http.NewRequest(http.MethodGet, "https://Sub.Example:443/a", nil)
	sameOriginNext, _ := http.NewRequest(http.MethodGet, "https://sub.example/b", nil)
	sameOriginNext.Header.Set("Authorization", "Bearer secret")
	sameOriginNext.Header.Set("Referer", "https://sub.example/a?token=secret")
	if err := CheckRedirect(sameOriginNext, []*http.Request{origin}); err != nil || sameOriginNext.Header.Get("Authorization") == "" || sameOriginNext.Header.Get("Referer") != "" {
		t.Fatalf("same origin with default port: %v, %v", err, sameOriginNext.Header)
	}
	otherPort, _ := http.NewRequest(http.MethodGet, "https://sub.example:8443/b", nil)
	otherPort.Header.Set("Authorization", "Bearer secret")
	otherPort.Header.Set("Accept", "*/*")
	if err := CheckRedirect(otherPort, []*http.Request{origin}); err != nil || otherPort.Header.Get("Authorization") != "" || otherPort.Header.Get("Accept") != "*/*" {
		t.Fatalf("different port must be a different origin: %v, %v", err, otherPort.Header)
	}
	downgrade, _ := http.NewRequest(http.MethodGet, "http://sub.example/b", nil)
	if err := CheckRedirect(downgrade, []*http.Request{origin}); !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("downgrade accepted: %v", err)
	}
}

func TestProxyAddrParsing(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"127.0.0.1:7890", "127.0.0.1:7890"},
		{"http://Proxy.Local", "proxy.local:80"},
		{"https://proxy.example:8443", "proxy.example:8443"},
		{"socks5://[::1]", "[::1]:1080"},
		{"http://user:pass@10.0.0.2:3128/", "10.0.0.2:3128"},
	} {
		if got, ok := proxyAddr(tc.value); !ok || got != tc.want {
			t.Errorf("%s: got %q, %v", tc.value, got, ok)
		}
	}
	if _, ok := proxyAddr(""); ok {
		t.Error("empty proxy parsed")
	}
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "127.0.0.1:7890")
	t.Setenv("HTTP_PROXY", "http://[::1]:8080")
	t.Setenv("http_proxy", "")
	addrs := proxyAddrsFromEnv()
	if len(addrs) != 2 || !addrs["127.0.0.1:7890"] || !addrs["[::1]:8080"] {
		t.Fatalf("environment proxies: %v", addrs)
	}
	t.Setenv("REQUEST_METHOD", "GET")
	addrs = proxyAddrsFromEnv()
	if len(addrs) != 1 || !addrs["127.0.0.1:7890"] {
		t.Fatalf("CGI HTTP_PROXY was not ignored: %v", addrs)
	}
}

func TestSetTestDefaultPolicyRestoresAfterSubtest(t *testing.T) {
	if DefaultPolicy().relaxed() {
		t.Fatal("default policy started relaxed")
	}
	t.Run("relaxed", func(t *testing.T) {
		SetTestDefaultPolicy(t, Policy{AllowLoopback: true, RootCAs: roots(t)})
		if !DefaultPolicy().AllowLoopback {
			t.Fatal("test policy not installed")
		}
	})
	if DefaultPolicy().relaxed() {
		t.Fatal("test policy leaked past subtest cleanup")
	}
}

// connectProxy is a minimal CONNECT proxy that tunnels every request to
// upstream, recording the requested authority.
func connectProxy(t *testing.T, upstream string, authority *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		authority.Store(r.Host)
		backend, err := net.Dial("tcp", upstream)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			backend.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(backend, bufio.NewReader(buffered))
			close(done)
		}()
		_, _ = io.Copy(client, backend)
		client.Close()
		backend.Close()
		<-done
	}))
}

func TestLoopbackProxyIsExemptButOnlyWhenConfigured(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	var authority atomic.Value
	proxy := connectProxy(t, target.Listener.Addr().String(), &authority)
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	strict := Policy{RootCAs: roots(t)}

	configured := &http.Client{Transport: newTransport(strict, http.ProxyURL(proxyURL), map[string]bool{canonicalURLAddr(proxyURL): true}), CheckRedirect: CheckRedirect}
	resp, err := get(t, configured, "https://example.com/", nil)
	if err != nil || resp.StatusCode != http.StatusOK || hits.Load() != 1 || authority.Load() != "example.com:443" {
		t.Fatalf("configured loopback proxy unusable: %v, authority=%v", err, authority.Load())
	}

	unlisted := &http.Client{Transport: newTransport(strict, http.ProxyURL(proxyURL), map[string]bool{}), CheckRedirect: CheckRedirect}
	if _, err := get(t, unlisted, "https://example.com/", nil); !errors.Is(err, ErrBlockedAddress) || hits.Load() != 1 {
		t.Fatalf("unlisted loopback proxy was dialed: %v", err)
	}
}

func TestDirectRequestToProxyEndpointRejected(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	direct := func(*http.Request) (*url.URL, error) { return nil, nil }
	client := &http.Client{Transport: newTransport(Policy{RootCAs: roots(t)}, direct, map[string]bool{canonicalURLAddr(serverURL): true}), CheckRedirect: CheckRedirect}
	if _, err := get(t, client, server.URL, nil); !errors.Is(err, ErrDirectToProxy) || hits.Load() != 0 {
		t.Fatalf("direct request rode the proxy exemption: %v", err)
	}
}
