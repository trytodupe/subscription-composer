package nodes

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
	"gopkg.in/yaml.v3"
)

var errClashDNSPolicy = errors.New("invalid Clash custom nameserver policy")

type clashDNSRule struct {
	domain   string
	kind     int // 0: inclusive suffix, 1: subdomains only, 2: exact
	resolver *model.DNSServer
}

// clashNodeResolvers imports only x-client-custom.nameserver-policy. Prefer an
// advertised TCP endpoint because provider DoH can be reset on restricted
// networks. Otherwise use the first endpoint; this is not adaptive failover.
func clashNodeResolvers(fields map[string]*yaml.Node, entries []entry) error {
	custom := fields["x-client-custom"]
	if custom == nil {
		return nil
	}
	if custom.Kind != yaml.MappingNode {
		return errClashDNSPolicy
	}
	policy := clashMap(custom)["nameserver-policy"]
	if policy == nil {
		return nil
	}
	if policy.Kind != yaml.MappingNode || len(policy.Content) == 0 {
		return errClashDNSPolicy
	}
	rules := make([]clashDNSRule, 0, len(policy.Content)/2)
	for i := 0; i < len(policy.Content); i += 2 {
		key, value := policy.Content[i], policy.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return errClashDNSPolicy
		}
		domain, kind, ok := clashDNSSelector(key.Value)
		if !ok {
			return errClashDNSPolicy
		}
		var endpoints []string
		switch value.Kind {
		case yaml.ScalarNode:
			if value.Tag != "!!str" {
				return errClashDNSPolicy
			}
			endpoints = []string{value.Value}
		case yaml.SequenceNode:
			if len(value.Content) == 0 {
				return errClashDNSPolicy
			}
			for _, item := range value.Content {
				if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || item.Value == "" {
					return errClashDNSPolicy
				}
				endpoints = append(endpoints, item.Value)
			}
		default:
			return errClashDNSPolicy
		}
		var resolver *model.DNSServer
		for _, endpoint := range endpoints {
			candidate, ok := clashDNSEndpoint(endpoint)
			if !ok {
				return errClashDNSPolicy
			}
			if resolver == nil || resolver.Type != "tcp" && candidate.Type == "tcp" {
				resolver = candidate
			}
		}
		rules = append(rules, clashDNSRule{domain: domain, kind: kind, resolver: resolver})
	}
	// Validate the full policy before changing any entries.
	for i := range entries {
		host, ok := entries[i].outbound["server"].(string)
		if !ok || net.ParseIP(host) != nil {
			continue
		}
		host, ok = clashDNSName(host)
		if !ok {
			continue
		}
		var best *clashDNSRule
		for j := range rules {
			rule := &rules[j]
			if !rule.matches(host) {
				continue
			}
			if best == nil || len(rule.domain) > len(best.domain) || len(rule.domain) == len(best.domain) && rule.kind > best.kind {
				best = rule
			}
		}
		if best != nil {
			entries[i].resolver = best.resolver
		}
	}
	return nil
}

func (r clashDNSRule) matches(host string) bool {
	if host == r.domain {
		return r.kind != 1
	}
	return r.kind != 2 && strings.HasSuffix(host, "."+r.domain)
}

func clashDNSSelector(raw string) (string, int, bool) {
	kind := 2
	switch {
	case strings.HasPrefix(raw, "+."):
		kind, raw = 0, raw[2:]
	case strings.HasPrefix(raw, "*."):
		kind, raw = 1, raw[2:]
	}
	domain, ok := clashDNSName(raw)
	return domain, kind, ok && net.ParseIP(domain) == nil
}

func clashDNSName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false
			}
		}
	}
	return name, true
}

func clashDNSEndpoint(raw string) (*model.DNSServer, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery {
		return nil, false
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		if !strings.HasPrefix(u.Fragment, "cost-bias=") || strings.Count(raw, "#") != 1 {
			return nil, false
		}
		if _, err := time.ParseDuration(strings.TrimPrefix(u.Fragment, "cost-bias=")); err != nil {
			return nil, false
		}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
		bracketed := strings.HasPrefix(u.Host, "[")
		if (ip.To4() == nil) != bracketed {
			return nil, false
		}
	} else {
		if strings.HasPrefix(u.Host, "[") {
			return nil, false
		}
		var ok bool
		host, ok = clashDNSName(host)
		if !ok {
			return nil, false
		}
	}
	portText := u.Port()
	if u.Host != u.Hostname() && portText == "" && !strings.HasSuffix(u.Host, "]") {
		return nil, false
	}
	defaults := map[string]uint16{"https": 443, "tls": 853, "tcp": 53, "udp": 53}
	defaultPort, ok := defaults[u.Scheme]
	if !ok {
		return nil, false
	}
	resolver := &model.DNSServer{Type: u.Scheme, Server: host}
	if portText != "" {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, false
		}
		if uint16(port) != defaultPort {
			resolver.ServerPort = uint16(port)
		}
	}
	if u.Scheme == "https" {
		resolver.Path = u.EscapedPath()
		if resolver.Path == "" {
			resolver.Path = "/dns-query"
		}
	} else if u.Path != "" || u.RawPath != "" {
		return nil, false
	}
	return resolver, true
}
