package model

import (
	"errors"
	"fmt"
	"net/netip"
)

// Tailscale assigns node addresses from these ranges.
var tailscaleCIDRs = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}

// loopbackCIDRs are always allowed so local applications keep working when
// the generated proxy listeners are exposed beyond loopback.
var loopbackCIDRs = []string{"127.0.0.0/8", "::1/128"}

// Exposed reports whether the generated proxy listeners accept non-loopback clients.
func (p LocalProxy) Exposed() bool {
	return p.AllowTailscale || len(p.AllowCIDRs) > 0
}

// Resolved validates and canonicalizes the allowlist without changing the input.
func (p LocalProxy) Resolved() (LocalProxy, error) {
	resolved := LocalProxy{AllowTailscale: p.AllowTailscale}
	seen := make(map[string]bool, len(p.AllowCIDRs))
	for _, value := range p.AllowCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" {
			return LocalProxy{}, fmt.Errorf("allow_cidrs entry %q must be a CIDR prefix without a zone", value)
		}
		if prefix.Bits() == 0 {
			return LocalProxy{}, errors.New("allow_cidrs must not contain a default route such as 0.0.0.0/0 or ::/0")
		}
		// sing-box matches unmapped client addresses, so mapped prefixes would never match.
		if prefix.Addr().Is4In6() {
			return LocalProxy{}, fmt.Errorf("allow_cidrs entry %q must use plain IPv4 notation instead of an IPv4-mapped IPv6 prefix", value)
		}
		canonical := prefix.Masked().String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		resolved.AllowCIDRs = append(resolved.AllowCIDRs, canonical)
	}
	return resolved, nil
}

// SourceCIDRs returns the deduplicated client source allowlist for exposed listeners.
// It returns nil when the listeners stay on loopback.
func (p LocalProxy) SourceCIDRs() ([]string, error) {
	resolved, err := p.Resolved()
	if err != nil || !resolved.Exposed() {
		return nil, err
	}
	candidates := append([]string(nil), loopbackCIDRs...)
	if resolved.AllowTailscale {
		candidates = append(candidates, tailscaleCIDRs...)
	}
	candidates = append(candidates, resolved.AllowCIDRs...)
	seen := make(map[string]bool, len(candidates))
	cidrs := make([]string, 0, len(candidates))
	for _, cidr := range candidates {
		if !seen[cidr] {
			seen[cidr] = true
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs, nil
}
