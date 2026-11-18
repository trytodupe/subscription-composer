// Package netsafetest provides the relaxed netsafe policy used by tests that
// talk to httptest TLS servers on loopback. Only _test.go files may import
// it; netsafe panics if the relaxed policy is used outside a test binary.
package netsafetest

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ttd/subscription-composer/internal/netsafe"
)

var (
	rootsOnce sync.Once
	roots     *x509.CertPool
)

// RootCAs trusts the certificate shared by every httptest TLS server.
func RootCAs() *x509.CertPool {
	rootsOnce.Do(func() {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		roots = x509.NewCertPool()
		roots.AddCert(server.Certificate())
		server.Close()
	})
	return roots
}

// Policy allows loopback destinations and trusts httptest TLS servers.
func Policy() netsafe.Policy {
	return netsafe.Policy{AllowLoopback: true, RootCAs: RootCAs()}
}

// Use installs Policy as netsafe's default policy for the duration of tb.
func Use(tb testing.TB) {
	tb.Helper()
	netsafe.SetTestDefaultPolicy(tb, Policy())
}

// NewServer starts an httptest TLS server and installs Policy for tb.
func NewServer(tb testing.TB, handler http.Handler) *httptest.Server {
	tb.Helper()
	Use(tb)
	return httptest.NewTLSServer(handler)
}
