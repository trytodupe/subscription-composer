// Package nodes imports supported sing-box outbounds and subscription links.
package nodes

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ttd/subscription-composer/internal/model"
)

// Parse imports nodes and explicitly scoped node-hostname DNS policies.
// General subscription routing and DNS configuration are not imported.
// Tags depend only on the source ID and original node name. Repeated names are
// rejected because endpoint-based disambiguation would break rotation stability.
func Parse(source model.Source, body []byte, overrides map[string]string) ([]model.Node, error) {
	if strings.TrimSpace(source.ID) == "" {
		return nil, errors.New("source ID is required")
	}
	input := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if input == "" {
		return nil, errors.New("empty subscription; keeping existing nodes is recommended")
	}
	format := strings.ToLower(strings.TrimSpace(source.Format))
	if format == "" || format == "auto" {
		if looksLikeClash(input) {
			format = "clash"
		} else if strings.HasPrefix(input, "{") || strings.HasPrefix(input, "[") {
			format = "sing-box"
		} else {
			format = "links"
		}
	}
	var entries []entry
	var err error
	switch format {
	case "sing-box":
		entries, err = parseNative([]byte(input))
	case "links":
		entries, err = parseLinks(input)
	case "clash":
		entries, err = parseClash([]byte(input))
	default:
		return nil, errors.New("unsupported source format; use auto, sing-box, links, or clash")
	}
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("subscription contains no supported nodes")
	}
	nodes := make([]model.Node, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		name := e.name
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("node name is required for stable identity")
		}
		if seen[name] {
			return nil, errors.New("duplicate node names in one source; assign unique names for stable tags")
		}
		seen[name] = true
		country, err := countryFor(source.ID, name, overrides)
		if err != nil {
			return nil, err
		}
		tag := source.ID + " / " + name
		e.outbound["tag"] = tag
		nodes = append(nodes, model.Node{Provider: source.ID, Name: name, Tag: tag, Country: country, Outbound: e.outbound, DNSResolver: e.resolver})
	}
	return nodes, nil
}

var clashProxies = regexp.MustCompile(`(?m)^proxies\s*:`)

func looksLikeClash(input string) bool {
	if clashProxies.MatchString(input) {
		return true
	}
	if strings.HasPrefix(input, "{") {
		var root map[string]json.RawMessage
		if json.Unmarshal([]byte(input), &root) == nil {
			_, ok := root["proxies"]
			return ok
		}
	}
	return false
}

type entry struct {
	name     string
	outbound map[string]any
	resolver *model.DNSServer
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.Join(strings.Fields(value), "")
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 subscription or link payload")
}

func decodeJSONMap(data []byte) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil || value == nil {
		return nil, errors.New("invalid JSON object in subscription")
	}
	return value, nil
}

func portNumber(text string) (int, error) {
	var port int
	if text == "" {
		return 0, errors.New("node port is required")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, errors.New("node port must be a number from 1 to 65535")
		}
		port = port*10 + int(c-'0')
		if port > 65535 {
			return 0, errors.New("node port must be a number from 1 to 65535")
		}
	}
	if port == 0 {
		return 0, errors.New("node port must be a number from 1 to 65535")
	}
	return port, nil
}

func mapPort(value any) (int, error) {
	switch v := value.(type) {
	case float64:
		if v >= 1 && v <= 65535 && float64(int(v)) == v {
			return int(v), nil
		}
	case string:
		return portNumber(v)
	}
	return 0, errors.New("node port must be a number from 1 to 65535")
}

func requireString(obj map[string]any, key string) (string, error) {
	value, ok := obj[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("node %s is required", key)
	}
	return value, nil
}
