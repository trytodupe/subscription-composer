package nodes

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var supportedTypes = map[string]bool{"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "hysteria2": true, "tuic": true}
var groupTypes = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

func parseNative(body []byte) ([]entry, error) {
	var raw []json.RawMessage
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("invalid sing-box outbound array")
		}
	} else {
		root, err := decodeJSONMap(body)
		if err != nil {
			return nil, err
		}
		if outbounds, ok := root["outbounds"]; ok {
			encoded, _ := json.Marshal(outbounds)
			if err := json.Unmarshal(encoded, &raw); err != nil {
				return nil, errors.New("sing-box outbounds must be an array")
			}
		} else if _, ok := root["type"]; ok {
			raw = []json.RawMessage{json.RawMessage(body)}
		} else {
			return nil, errors.New("expected sing-box outbounds or one outbound object; use format clash for Clash input")
		}
	}
	var entries []entry
	for i, item := range raw {
		outbound, err := decodeJSONMap(item)
		if err != nil {
			return nil, fmt.Errorf("outbound %d: %w", i+1, err)
		}
		typ, err := requireString(outbound, "type")
		if err != nil {
			return nil, fmt.Errorf("outbound %d: %w", i+1, err)
		}
		if groupTypes[typ] {
			continue
		}
		if !supportedTypes[typ] {
			return nil, fmt.Errorf("outbound %d: unsupported native protocol; supported: shadowsocks, vmess, vless, trojan, hysteria2, tuic", i+1)
		}
		if hasUnsupportedTopology(outbound) {
			return nil, fmt.Errorf("outbound %d: detour or domain_resolver references are unsupported in provider nodes", i+1)
		}
		name, err := requireString(outbound, "tag")
		if err != nil {
			return nil, fmt.Errorf("outbound %d: %w", i+1, err)
		}
		if _, err = requireString(outbound, "server"); err != nil {
			return nil, fmt.Errorf("outbound %d: %w", i+1, err)
		}
		if typ == "hysteria2" && outbound["server_ports"] != nil {
			if err := validateServerPorts(outbound["server_ports"]); err != nil {
				return nil, fmt.Errorf("outbound %d: %w", i+1, err)
			}
		}
		if outbound["server_port"] != nil || typ != "hysteria2" || outbound["server_ports"] == nil {
			port, err := mapPort(outbound["server_port"])
			if err != nil {
				return nil, fmt.Errorf("outbound %d: %w", i+1, err)
			}
			outbound["server_port"] = port
		}
		credential := "uuid"
		switch typ {
		case "shadowsocks":
			credential = "password"
			method, err := requireString(outbound, "method")
			if err != nil {
				return nil, fmt.Errorf("outbound %d: %w", i+1, err)
			}
			if !ssMethods[method] {
				return nil, fmt.Errorf("outbound %d: unsupported SS method", i+1)
			}
		case "trojan", "hysteria2":
			credential = "password"
		case "tuic":
			if _, err := requireString(outbound, "uuid"); err != nil {
				return nil, fmt.Errorf("outbound %d: %w", i+1, err)
			}
			credential = "password"
		}
		if _, err := requireString(outbound, credential); err != nil {
			return nil, fmt.Errorf("outbound %d: %w", i+1, err)
		}
		if transport, ok := outbound["transport"]; ok {
			if typ == "hysteria2" || typ == "tuic" {
				return nil, fmt.Errorf("outbound %d: transport is unsupported for QUIC outbounds", i+1)
			}
			obj, ok := transport.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("outbound %d: transport must be an object", i+1)
			}
			t, ok := obj["type"].(string)
			if !ok || (t != "ws" && t != "grpc") {
				return nil, fmt.Errorf("outbound %d: unsupported transport; supported: tcp, ws, grpc", i+1)
			}
		}
		entries = append(entries, entry{name: name, outbound: outbound})
	}
	return entries, nil
}

func hasUnsupportedTopology(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "detour" || key == "domain_resolver" {
				return true
			}
			if hasUnsupportedTopology(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if hasUnsupportedTopology(child) {
				return true
			}
		}
	}
	return false
}

func validateServerPorts(value any) error {
	ports, ok := value.([]any)
	if !ok || len(ports) == 0 {
		return errors.New("Hysteria2 server_ports must be a nonempty array of ports or ranges")
	}
	for _, item := range ports {
		portRange, ok := item.(string)
		if !ok {
			return errors.New("Hysteria2 server_ports must contain numeric ports or port ranges")
		}
		first, last, rangePresent := strings.Cut(portRange, ":")
		start, err := portNumber(first)
		if err != nil {
			return errors.New("Hysteria2 server_ports must contain ports from 1 to 65535")
		}
		if rangePresent {
			end, err := portNumber(last)
			if err != nil || end < start {
				return errors.New("Hysteria2 server_ports must contain increasing ranges from 1 to 65535")
			}
		}
	}
	return nil
}
