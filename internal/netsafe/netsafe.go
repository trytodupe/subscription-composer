// Package netsafe builds the outbound HTTP clients the server uses to fetch
// operator-configured URLs: subscription sources, remote rule sets and the
// ikuuu API.
//
// The server runs on a cloud VM whose instance metadata service (Aliyun ECS
// serves it at 100.100.100.200) and private network must never be reachable
// through a configured or redirected URL. Destinations are therefore checked
// at the socket level, after DNS resolution, against the exact IP being
// dialed, so a DNS answer that changes between validation and use (DNS
// rebinding) cannot smuggle in an internal address.
//
// Proxies: the server honors the operator's own HTTPS_PROXY / HTTP_PROXY /
// NO_PROXY environment (net/http semantics). The exact proxy host:port taken
// from that environment when a transport is built is the only destination
// exempt from the address check, so a proxy listening on loopback keeps
// working. For requests sent through such a proxy, the proxy resolves and
// connects to the target, so destination filtering for proxied requests is
// delegated to the proxy; requests excluded by NO_PROXY are dialed directly
// and fully checked.
package netsafe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// MaxRedirects is the number of redirects a client follows before failing.
const MaxRedirects = 5

var (
	// ErrBlockedAddress reports a dial to an address that is not publicly routable.
	ErrBlockedAddress = errors.New("netsafe: destination address is not publicly routable")
	// ErrRedirectBlocked reports a redirect rejected by CheckRedirect.
	ErrRedirectBlocked = errors.New("netsafe: redirect rejected")
	// ErrDirectToProxy reports a request whose target is the configured proxy
	// itself; the proxy exemption only covers proxy connections.
	ErrDirectToProxy = errors.New("netsafe: request targets the configured proxy directly")
)

// Policy relaxes the production destination rules. The zero value is the
// production policy, and production code must always use it: every
// relaxation is honored only inside a test binary and panics elsewhere.
type Policy struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1 so tests can reach httptest
	// servers. Every other blocked range stays blocked.
	AllowLoopback bool
	// RootCAs replaces the system trust store, for httptest TLS servers.
	RootCAs *x509.CertPool
}

func (p Policy) relaxed() bool {
	return p.AllowLoopback || p.RootCAs != nil
}

var (
	testDefaultPolicy atomic.Pointer[Policy]
	prodClient        = sync.OnceValue(func() *http.Client { return NewClient(Policy{}) })
)

// SetTestDefaultPolicy overrides DefaultPolicy and DefaultClient for the
// duration of tb so tests using httptest TLS servers on loopback can opt in
// without adding test parameters to production APIs. It panics outside a test
// binary.
func SetTestDefaultPolicy(tb testing.TB, p Policy) {
	if tb == nil || !testing.Testing() {
		panic("netsafe: SetTestDefaultPolicy outside a test binary")
	}
	prev := testDefaultPolicy.Swap(&p)
	tb.Cleanup(func() { testDefaultPolicy.Store(prev) })
}

// DefaultPolicy returns Policy{}, or the policy installed by
// SetTestDefaultPolicy for the running test.
func DefaultPolicy() Policy {
	if tp := testDefaultPolicy.Load(); tp != nil {
		if !testing.Testing() {
			panic("netsafe: relaxed policy outside a test binary")
		}
		return *tp
	}
	return Policy{}
}

// DefaultClient returns a shared production client, or a client built from
// DefaultPolicy inside a test binary.
func DefaultClient() *http.Client {
	if testing.Testing() {
		return NewClient(DefaultPolicy())
	}
	return prodClient()
}

// Additional ranges not covered by the netip.Addr classification methods.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT; includes Aliyun metadata 100.100.100.200
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes limited broadcast
	netip.MustParsePrefix("::/96"),           // deprecated IPv4-compatible IPv6
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated (SIIT)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4 (deprecated, can embed private IPv4)
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
}

// The well-known NAT64 prefix embeds an IPv4 destination, which is checked
// instead of the prefix itself so IPv6-only networks still reach public IPv4.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// Check reports whether addr may be dialed under p.
func (p Policy) Check(addr netip.Addr) error {
	addr = addr.WithZone("").Unmap()
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrBlockedAddress)
	}
	if p.AllowLoopback && addr.IsLoopback() {
		return nil
	}
	if nat64Prefix.Contains(addr) {
		raw := addr.As16()
		embedded := netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
		if err := (Policy{}).Check(embedded); err != nil {
			return fmt.Errorf("%w: %s embeds %s", ErrBlockedAddress, addr, embedded)
		}
		return nil
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
		}
	}
	return nil
}

// control runs after DNS resolution for every connection attempt, including
// each Happy Eyeballs fallback, so it sees the address actually dialed.
func (p Policy) control(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("%w: unsupported network %q", ErrBlockedAddress, network)
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address", ErrBlockedAddress)
	}
	return p.Check(addrPort.Addr())
}

// NewClient returns a client that dials only public addresses (or the
// operator's proxy) and follows redirects under CheckRedirect. Callers that
// must not follow redirects may copy the client and replace CheckRedirect.
func NewClient(p Policy) *http.Client {
	return &http.Client{Transport: NewTransport(p), CheckRedirect: CheckRedirect}
}

// NewTransport returns a transport that dials only public addresses, except
// the operator proxy configured in the environment at construction time.
func NewTransport(p Policy) *http.Transport {
	return newTransport(p, http.ProxyFromEnvironment, proxyAddrsFromEnv())
}

func newTransport(p Policy, proxy func(*http.Request) (*url.URL, error), proxyAddrs map[string]bool) *http.Transport {
	if p.relaxed() && !testing.Testing() {
		panic("netsafe: relaxed policy outside a test binary")
	}
	checked := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: p.control}
	// Used only for the exact operator proxy endpoints.
	unchecked := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			proxyURL, err := proxy(req)
			if err != nil || proxyURL != nil {
				return proxyURL, err
			}
			// A direct request to the proxy endpoint would otherwise ride on
			// the proxy exemption, e.g. a loopback proxy that NO_PROXY or the
			// built-in loopback bypass sends direct.
			if proxyAddrs[canonicalURLAddr(req.URL)] {
				return nil, ErrDirectToProxy
			}
			return nil, nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if proxyAddrs[canonicalAddr(address)] {
				return unchecked.DialContext(ctx, network, address)
			}
			return checked.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxIdleConns:           16,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// proxyAddrsFromEnv mirrors the proxy variables net/http reads. Only the
// endpoints are needed here; NO_PROXY matching stays with net/http.
func proxyAddrsFromEnv() map[string]bool {
	addrs := make(map[string]bool)
	for _, spec := range []struct {
		upper, lower string
		ignoreInCGI  bool
	}{
		{"HTTPS_PROXY", "https_proxy", false},
		{"HTTP_PROXY", "http_proxy", true},
	} {
		if spec.ignoreInCGI && os.Getenv("REQUEST_METHOD") != "" {
			continue
		}
		value := os.Getenv(spec.upper)
		if value == "" {
			value = os.Getenv(spec.lower)
		}
		if addr, ok := proxyAddr(value); ok {
			addrs[addr] = true
		}
	}
	return addrs
}

// proxyAddr parses a proxy setting the way net/http does: a value without a
// scheme is an http proxy.
func proxyAddr(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if u, err = url.Parse("http://" + value); err != nil {
			return "", false
		}
	}
	if u.Hostname() == "" {
		return "", false
	}
	return canonicalURLAddr(u), true
}

var defaultPorts = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}

func canonicalURLAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = defaultPorts[strings.ToLower(u.Scheme)]
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func canonicalAddr(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

// Headers forwarded on a cross-origin redirect. Everything else, including
// Authorization, Cookie, conditional validators and any custom source
// header, may carry credentials or state bound to the original origin.
var crossOriginHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Encoding": true,
	"Accept-Language": true,
	"User-Agent":      true,
}

// CheckRedirect follows at most MaxRedirects redirects, only to https URLs.
// Cross-origin redirects are followed (rule-set hosts such as github.com and
// cdn.jsdelivr.net legitimately redirect to other hosts), but only the
// headers in an allowlist survive them: net/http copies every original
// header to each hop and only strips Authorization and Cookie itself, so
// custom secret headers would otherwise leak. Referer is never sent, because
// subscription URLs often carry tokens in the path or query.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrRedirectBlocked, MaxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%w: redirect to a non-https URL", ErrRedirectBlocked)
	}
	req.Header.Del("Referer")
	// net/http rebuilds each hop's headers from the original request, so
	// comparing against the original origin is sufficient.
	if len(via) > 0 && !sameOrigin(req.URL, via[0].URL) {
		for name := range req.Header {
			if !crossOriginHeaders[http.CanonicalHeaderKey(name)] {
				delete(req.Header, name)
			}
		}
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && canonicalURLAddr(a) == canonicalURLAddr(b)
}
