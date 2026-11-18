package clientupdate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// The native TCP listener uses dual stack for ::; 0.0.0.0 accepts only IPv4.
func (c *Client) checkHealthEndpoint(ctx context.Context, api map[string]any) error {
	mismatch := errors.New("API listener does not match health_address")
	listen, ok := api["listen"].(string)
	if !ok {
		return mismatch
	}
	bound, err := netip.ParseAddr(listen)
	if err != nil {
		return mismatch
	}
	bound = bound.Unmap()
	port, ok := api["listen_port"].(json.Number)
	if !ok {
		return mismatch
	}
	n, err := strconv.Atoi(string(port))
	host, healthPort, splitErr := net.SplitHostPort(c.cfg.HealthAddress)
	healthN, portErr := strconv.Atoi(healthPort)
	if err != nil || splitErr != nil || portErr != nil || n != healthN || n < 1 || n > 65535 {
		return mismatch
	}
	var addresses []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{addr}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, c.healthTimeout)
		defer cancel()
		addresses, err = net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
		if err != nil {
			return mismatch
		}
	}
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsUnspecified() {
			return errors.New("health_address must not use a wildcard host")
		}
	}
	for _, address := range addresses {
		address = address.Unmap()
		if bound.IsUnspecified() {
			if bound.Is6() || address.Is4() {
				return nil
			}
		} else if bound.WithZone("") == address.WithZone("") && (bound.Zone() == "" || bound.Zone() == address.Zone()) {
			return nil
		}
	}
	return mismatch
}
