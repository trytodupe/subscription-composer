package compose

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ttd/subscription-composer/internal/model"
)

var localProxyTags = []string{"mixed-rules", "mixed-direct"}

// addLocalProxyInbounds binds the generated proxies to loopback by default.
// An exposed device listens on every address and relies on the source
// allowlist rule returned by localProxyGuard.
func addLocalProxyInbounds(base map[string]json.RawMessage, settings model.LocalProxy) error {
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
		if tag == "mixed-rules" || tag == "mixed-direct" {
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
		inbounds, err = appendJSON(inbounds, map[string]any{
			"type": "mixed", "tag": tag,
			"listen": listen, "listen_port": 7890 + i,
		})
		if err != nil {
			return err
		}
	}
	base["inbounds"], err = json.Marshal(inbounds)
	return err
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
