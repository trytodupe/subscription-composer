package compose

import (
	"encoding/json"
	"errors"
	"fmt"
)

// addLocalProxyInbounds reserves loopback listeners for policy and direct traffic.
func addLocalProxyInbounds(base map[string]json.RawMessage) error {
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
	for _, listener := range []struct {
		tag  string
		port int
	}{
		{"mixed-rules", 7890},
		{"mixed-direct", 7891},
	} {
		inbounds, err = appendJSON(inbounds, map[string]any{
			"type": "mixed", "tag": listener.tag,
			"listen": "127.0.0.1", "listen_port": listener.port,
		})
		if err != nil {
			return err
		}
	}
	base["inbounds"], err = json.Marshal(inbounds)
	return err
}
