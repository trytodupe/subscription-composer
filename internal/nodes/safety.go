package nodes

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	errInsecureTLS = errors.New("TLS certificate verification must stay enabled; " +
		"remove insecure / skip-cert-verify or set verify_cert to true")
	errInvalidTLSInsecure = errors.New("TLS insecure must be a boolean")
	errBlockedServer      = errors.New("node server must be a public address or hostname; " +
		"loopback, private, link-local, CGNAT, multicast and reserved addresses are rejected")
	errInvalidServer   = errors.New("node server contains whitespace or control characters")
	errNumericHostname = errors.New("node server looks like a non-canonical IP literal")
	errInvalidTLS      = errors.New("node tls must be an object")
)

// blockedPrefixes complements the netip.Addr predicates with ranges that are
// not globally routable but are not covered by them.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, includes Aliyun IMDS 100.100.100.200
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking, sing-box fake-ip default range
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, includes limited broadcast
	netip.MustParsePrefix("::/96"),         // deprecated IPv4-compatible IPv6
}

var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// validateNodeSafety is applied to every imported node regardless of input
// format, after the format-specific parser produced a sing-box outbound.
// Errors never include the server, credentials or node name.
func validateNodeSafety(e entry) error {
	if raw, ok := e.outbound["tls"]; ok {
		tls, ok := raw.(map[string]any)
		if !ok {
			return errInvalidTLS
		}
		if value, ok := tls["insecure"]; ok {
			insecure, ok := value.(bool)
			if !ok {
				return errInvalidTLSInsecure
			}
			if insecure {
				return errInsecureTLS
			}
		}
	}
	server, _ := e.outbound["server"].(string)
	// Node-scoped DNS resolvers (Clash nameserver-policy) are intentionally not
	// checked here: they only carry DNS queries and integration tests point them
	// at loopback listeners.
	return validateServerAddress(server)
}

// validateServerAddress rejects IP literals that would make the proxy client
// connect to the local host, the local network or cloud metadata services.
// Hostnames are accepted; their resolution is outside the importer's control.
func validateServerAddress(server string) error {
	for _, c := range server {
		if c <= ' ' || c == 0x7f {
			return errInvalidServer
		}
	}
	host := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(server, "["), "]"), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedAddr(addr) {
			return errBlockedServer
		}
		return nil
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return errBlockedServer
	}
	// A real top-level domain is never numeric. Forms such as 127.1, 2130706433
	// or 0x7f.1 are not parsed by netip but may still be interpreted as IPv4 by
	// a system resolver, so they are rejected instead of treated as hostnames.
	label := lower[strings.LastIndexByte(lower, '.')+1:]
	if label != "" && (isDigits(label) || strings.HasPrefix(label, "0x")) {
		return errNumericHostname
	}
	return nil
}

func isBlockedAddr(addr netip.Addr) bool {
	addr = addr.WithZone("")
	if nat64Prefix.Contains(addr) {
		embedded := addr.As16()
		return isBlockedAddr(netip.AddrFrom4([4]byte(embedded[12:16])))
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isDigits(text string) bool {
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return text != ""
}
