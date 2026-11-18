package compose

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ttd/subscription-composer/internal/model"
)

var (
	localProxyTags         = []string{"mixed-rules", "mixed-direct"}
	loopbackCompanionTags  = []string{"mixed-rules-loopback", "mixed-direct-loopback"}
	reservedLocalProxyTags = map[string]bool{
		"mixed-rules":           true,
		"mixed-direct":          true,
		"mixed-rules-loopback":  true,
		"mixed-direct-loopback": true,
	}
)

// addLocalProxyInbounds binds the generated proxies to loopback by default.
// An exposed device listens on every address and relies on the source
// allowlist rule returned by localProxyGuard. On macOS, NetworkExtension
// scopes wildcard listeners inside NEPacketTunnelProvider to the primary
// physical interface, which breaks local IPv4 loopback handshakes unless an
// explicit 127.0.0.1 companion listener is also bound on the same port.
func addLocalProxyInbounds(base map[string]json.RawMessage, platform string, settings model.LocalProxy) error {
	inbounds, err := array(base, "inbounds")
	if err != nil {
		return err
	}
	for _, raw := range inbounds {
		inbound, err := object(raw)
		if err != nil {
			return errors.New("inbound must be an object")
		}
		var tag string
		_ = json.Unmarshal(inbound["tag"], &tag)
		if reservedLocalProxyTags[tag] {
			return fmt.Errorf("base inbound conflicts with generated tag %s", tag)
		}
		var port int
		_ = json.Unmarshal(inbound["listen_port"], &port)
		if port == 7890 || port == 7891 {
			return fmt.Errorf("base inbound conflicts with generated port %d", port)
		}
	}
	listen := "127.0.0.1"
	if settings.Exposed() {
		listen = "::"
	}
	for i, tag := range localProxyTags {
		port := 7890 + i
		inbounds, err = appendJSON(inbounds, map[string]any{
			"type": "mixed", "tag": tag,
			"listen": listen, "listen_port": port,
		})
		if err != nil {
			return err
		}
		if settings.Exposed() && platform == "macos" {
			inbounds, err = appendJSON(inbounds, map[string]any{
				"type": "mixed", "tag": loopbackCompanionTags[i],
				"listen": "127.0.0.1", "listen_port": port,
			})
			if err != nil {
				return err
			}
		}
	}
	base["inbounds"], err = json.Marshal(inbounds)
	return err
}

func directProxyTags(platform string, settings model.LocalProxy) []string {
	if settings.Exposed() && platform == "macos" {
		return []string{"mixed-direct", "mixed-direct-loopback"}
	}
	return []string{"mixed-direct"}
}

// localProxyGuard returns the route rule that rejects proxy clients outside
// the allowlist, or nil when the listeners stay on loopback. A logical rule is
// required because invert on a default rule would negate the inbound match too
// and reject traffic from every other inbound.
func localProxyGuard(settings model.LocalProxy) (json.RawMessage, error) {
	cidrs, err := settings.SourceCIDRs()
	if err != nil || cidrs == nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"type": "logical", "mode": "and",
		"rules": []any{
			map[string]any{"inbound": localProxyTags},
			map[string]any{"source_ip_cidr": cidrs, "invert": true},
		},
		"action": "reject",
	})
}
