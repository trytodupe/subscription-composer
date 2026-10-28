package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/ttd/subscription-composer/internal/model"
)

// addNodeDNS keeps provider resolution local to each imported outbound. DNS
// rules for application traffic never inherit subscription policy.
func addNodeDNS(base map[string]json.RawMessage, nodes []model.Node) (map[string]string, error) {
	needed := false
	for _, node := range nodes {
		needed = needed || node.DNSResolver != nil
	}
	if !needed {
		return nil, nil
	}
	dns, err := nested(base, "dns")
	if err != nil {
		return nil, err
	}
	servers, err := array(dns, "servers")
	if err != nil {
		return nil, err
	}
	byTag := make(map[string]map[string]json.RawMessage)
	for _, raw := range servers {
		server, err := object(raw)
		if err != nil {
			return nil, errors.New("invalid base DNS server")
		}
		if _, exists := server["tag"]; !exists {
			continue
		}
		tag, err := requiredTag(server)
		if err != nil || byTag[tag] != nil {
			return nil, errors.New("invalid or duplicate base DNS tag")
		}
		byTag[tag] = server
	}
	var bootstrap any
	bootstrapReady := false
	ensureBootstrap := func() error {
		if bootstrapReady {
			return nil
		}
		route, err := nested(base, "route")
		if err != nil {
			return err
		}
		if raw, exists := route["default_domain_resolver"]; exists {
			tag, err := dnsResolverTag(raw)
			if err != nil || !directDNSBootstrap(tag, byTag, make(map[string]bool)) {
				return errors.New("node DNS requires a direct, nonrecursive bootstrap resolver")
			}
			if err := json.Unmarshal(raw, &bootstrap); err != nil {
				return errors.New("invalid node DNS bootstrap resolver")
			}
		} else {
			const tag = "node-dns-bootstrap"
			if byTag[tag] != nil {
				return errors.New("generated node DNS tag conflicts with base DNS")
			}
			server := map[string]any{"type": "local", "tag": tag}
			servers, err = appendJSON(servers, server)
			if err != nil {
				return err
			}
			byTag[tag] = map[string]json.RawMessage{"type": json.RawMessage(`"local"`)}
			bootstrap = tag
		}
		bootstrapReady = true
		return nil
	}
	resolvers := make(map[string]string)
	generated := make(map[string]string)
	for _, node := range nodes {
		if node.DNSResolver == nil {
			continue
		}
		if _, exists := node.Outbound["domain_resolver"]; exists {
			return nil, errors.New("node has conflicting domain resolver settings")
		}
		identity, err := json.Marshal(struct {
			Provider string
			Server   *model.DNSServer
		}{node.Provider, node.DNSResolver})
		if err != nil {
			return nil, errors.New("invalid node DNS resolver")
		}
		key := string(identity)
		tag, exists := generated[key]
		if !exists {
			digest := sha256.Sum256(identity)
			tag = "node-dns-" + hex.EncodeToString(digest[:12])
			if byTag[tag] != nil {
				return nil, errors.New("generated node DNS tag conflicts with base DNS")
			}
			encoded, _ := json.Marshal(node.DNSResolver)
			var server map[string]any
			_ = json.Unmarshal(encoded, &server)
			server["tag"] = tag
			if _, err := netip.ParseAddr(node.DNSResolver.Server); err != nil {
				if err := ensureBootstrap(); err != nil {
					return nil, err
				}
				server["domain_resolver"] = bootstrap
			}
			servers, err = appendJSON(servers, server)
			if err != nil {
				return nil, errors.New("invalid generated node DNS server")
			}
			byTag[tag] = make(map[string]json.RawMessage)
			generated[key] = tag
		}
		resolvers[node.Tag] = tag
	}
	dns["servers"], _ = json.Marshal(servers)
	base["dns"], _ = json.Marshal(dns)
	return resolvers, nil
}

func dnsResolverTag(raw json.RawMessage) (string, error) {
	var tag string
	if json.Unmarshal(raw, &tag) == nil && tag != "" {
		return tag, nil
	}
	options, err := object(raw)
	if err != nil || json.Unmarshal(options["server"], &tag) != nil || tag == "" {
		return "", errors.New("invalid DNS resolver reference")
	}
	return tag, nil
}

func directDNSBootstrap(tag string, servers map[string]map[string]json.RawMessage, visiting map[string]bool) bool {
	server := servers[tag]
	if server == nil || visiting[tag] {
		return false
	}
	visiting[tag] = true
	defer delete(visiting, tag)
	var kind, detour string
	if json.Unmarshal(server["type"], &kind) != nil || kind == "fakeip" || kind == "tailscale" {
		return false
	}
	if raw, exists := server["detour"]; exists && (json.Unmarshal(raw, &detour) != nil || detour != "") {
		return false
	}
	if raw, exists := server["domain_resolver"]; exists {
		next, err := dnsResolverTag(raw)
		return err == nil && directDNSBootstrap(next, servers, visiting)
	}
	if kind == "local" || kind == "hosts" || kind == "dhcp" || kind == "resolved" {
		return true
	}
	var address string
	if json.Unmarshal(server["server"], &address) != nil {
		return false
	}
	_, err := netip.ParseAddr(address)
	return err == nil
}
