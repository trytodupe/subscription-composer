// Package compose assembles a native sing-box configuration from a device base and policy.
package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ttd/subscription-composer/internal/model"
)

// Build merges native infrastructure with generated outbounds and policy routes.
// Regional and main selectors share their country selectors; changing one selection
// affects both paths. Infrastructure route rules always precede policy rules.
func Build(device model.Device, policy model.Policy, nodes []model.Node) ([]byte, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no nodes available")
	}
	base, err := object(device.Base)
	if err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	if err := addLocalProxyInbounds(base); err != nil {
		return nil, err
	}
	outbounds, err := array(base, "outbounds")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool)
	for _, entry := range outbounds {
		obj, err := object(entry)
		if err != nil {
			return nil, errors.New("invalid base outbound")
		}
		tag, err := requiredTag(obj)
		if err != nil || tags[tag] {
			return nil, errors.New("missing or duplicate base outbound tag")
		}
		if tag == "direct" {
			var kind string
			_ = json.Unmarshal(obj["type"], &kind)
			if kind != "direct" {
				return nil, errors.New("reserved outbound tag direct must have type direct")
			}
		}
		tags[tag] = true
	}
	if !tags["direct"] {
		outbounds, err = appendJSON(outbounds, map[string]any{"type": "direct", "tag": "direct"})
		if err != nil {
			return nil, err
		}
		tags["direct"] = true
	}
	countryNodes := make(map[string][]string)
	sorted := append([]model.Node(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Tag < sorted[j].Tag })
	nodeResolvers, err := addNodeDNS(base, sorted)
	if err != nil {
		return nil, err
	}
	for _, node := range sorted {
		if node.Tag == "" || node.Outbound == nil || tags[node.Tag] {
			return nil, errors.New("missing, duplicate, or conflicting node tag")
		}
		tags[node.Tag] = true
		country := strings.ToUpper(strings.TrimSpace(node.Country))
		if country == "" {
			country = "OTHER"
		}
		countryNodes[country] = append(countryNodes[country], node.Tag)
		if rawTag, ok := node.Outbound["tag"]; ok {
			if tag, valid := rawTag.(string); !valid || tag != node.Tag {
				return nil, errors.New("node outbound tag mismatch")
			}
		}
		copyOutbound := make(map[string]any, len(node.Outbound)+1)
		for key, value := range node.Outbound {
			copyOutbound[key] = value
		}
		copyOutbound["tag"] = node.Tag
		if resolver, exists := nodeResolvers[node.Tag]; exists {
			copyOutbound["domain_resolver"] = resolver
		}
		outbounds, err = appendJSON(outbounds, copyOutbound)
		if err != nil {
			return nil, errors.New("invalid node outbound")
		}
	}
	countries := make([]string, 0, len(countryNodes))
	for country := range countryNodes {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	url := policy.TestURL
	if url == "" {
		url = "https://www.google.com/generate_204"
	}
	interval := policy.TestInterval
	if interval == "" {
		interval = "5m"
	}
	add := func(tag string, value any) error {
		if tags[tag] {
			return errors.New("generated outbound tag collision")
		}
		tags[tag] = true
		var err error
		outbounds, err = appendJSON(outbounds, value)
		return err
	}
	urltest := func(tag string, choices []string) map[string]any {
		return map[string]any{"type": "urltest", "tag": tag, "outbounds": choices, "url": url, "interval": interval, "tolerance": 50, "interrupt_exist_connections": false}
	}
	selector := func(tag string, choices []string, selected string) map[string]any {
		return map[string]any{"type": "selector", "tag": tag, "outbounds": choices, "default": selected, "interrupt_exist_connections": true}
	}
	all := make([]string, 0, len(sorted))
	for _, node := range sorted {
		all = append(all, node.Tag)
	}
	mainChoices := []string{"auto"}
	for _, country := range countries {
		mainChoices = append(mainChoices, "country-"+country)
	}
	groupsStart := len(outbounds)
	if err := add("main", selector("main", mainChoices, "auto")); err != nil {
		return nil, err
	}
	if err := add("regional", selector("regional", append([]string{"main"}, mainChoices[1:]...), "main")); err != nil {
		return nil, err
	}
	// Keep the primary groups first in clients that follow outbound order.
	outbounds = append(outbounds[groupsStart:], outbounds[:groupsStart]...)
	if err := add("auto", urltest("auto", all)); err != nil {
		return nil, err
	}
	for _, country := range countries {
		countryTag := "country-" + country
		countryAuto := countryTag + "-auto"
		choices := append([]string{countryAuto}, countryNodes[country]...)
		if err := add(countryAuto, urltest(countryAuto, countryNodes[country])); err != nil {
			return nil, err
		}
		if err := add(countryTag, selector(countryTag, choices, countryAuto)); err != nil {
			return nil, err
		}
	}
	base["outbounds"], _ = json.Marshal(outbounds)

	route, err := nested(base, "route")
	if err != nil {
		return nil, err
	}
	rules, err := array(route, "rules")
	if err != nil {
		return nil, err
	}
	// Explicit direct requests must bypass both infrastructure and policy routes.
	rules = append([]json.RawMessage{json.RawMessage(`{"inbound":["mixed-direct"],"action":"route","outbound":"direct"}`)}, rules...)
	for _, rule := range policy.Rules {
		if _, err := object(rule); err != nil {
			return nil, errors.New("policy rule must be an object")
		}
		rules = append(rules, rule)
	}
	for _, item := range []struct {
		values []string
		field  string
		target string
	}{
		{policy.DirectDomains, "domain_suffix", "direct"},
		{policy.DirectCIDRs, "ip_cidr", "direct"},
		{policy.RegionalDomains, "domain_suffix", "regional"},
		{policy.DirectRuleSets, "rule_set", "direct"},
	} {
		if len(item.values) == 0 {
			continue
		}
		rule, _ := json.Marshal(map[string]any{item.field: item.values, "action": "route", "outbound": item.target})
		rules = append(rules, rule)
	}
	route["rules"], _ = json.Marshal(rules)
	ruleSets, err := array(route, "rule_set")
	if err != nil {
		return nil, err
	}
	setTags := make(map[string]bool)
	for _, entry := range append(append([]json.RawMessage(nil), ruleSets...), policy.RuleSets...) {
		obj, err := object(entry)
		if err != nil {
			return nil, errors.New("rule set must be an object")
		}
		tag, err := requiredTag(obj)
		if err != nil || setTags[tag] {
			return nil, errors.New("missing or duplicate rule set tag")
		}
		setTags[tag] = true
	}
	ruleSets = append(ruleSets, policy.RuleSets...)
	if len(ruleSets) > 0 {
		route["rule_set"], _ = json.Marshal(ruleSets)
	}
	route["final"] = json.RawMessage(`"main"`)
	base["route"], _ = json.Marshal(route)

	experimental, err := nested(base, "experimental")
	if err != nil {
		return nil, err
	}
	cache, err := nested(experimental, "cache_file")
	if err != nil {
		return nil, err
	}
	if _, ok := cache["enabled"]; !ok {
		cache["enabled"] = json.RawMessage("true")
	}
	if _, ok := cache["cache_id"]; !ok && device.ID != "" {
		cache["cache_id"], _ = json.Marshal(device.ID)
	}
	experimental["cache_file"], _ = json.Marshal(cache)
	base["experimental"], _ = json.Marshal(experimental)
	result, err := json.Marshal(base)
	if err != nil {
		return nil, errors.New("invalid native configuration")
	}
	if err := validate(result); err != nil {
		return nil, err
	}
	return result, nil
}

func object(data json.RawMessage) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, errors.New("expected JSON object")
	}
	return obj, nil
}

func nested(parent map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	if data, ok := parent[key]; ok {
		obj, err := object(data)
		if err != nil {
			return nil, fmt.Errorf("%s must be an object", key)
		}
		return obj, nil
	}
	return make(map[string]json.RawMessage), nil
}

func array(parent map[string]json.RawMessage, key string) ([]json.RawMessage, error) {
	if data, ok := parent[key]; ok {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil || items == nil {
			return nil, fmt.Errorf("%s must be an array", key)
		}
		return items, nil
	}
	return []json.RawMessage{}, nil
}

func appendJSON(items []json.RawMessage, value any) ([]json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(items, data), nil
}

func requiredTag(obj map[string]json.RawMessage) (string, error) {
	var tag string
	if err := json.Unmarshal(obj["tag"], &tag); err != nil || tag == "" {
		return "", errors.New("missing tag")
	}
	return tag, nil
}

// Check runs sing-box's native validator. Its output and configuration paths
// are deliberately withheld because they can contain subscription credentials.
func Check(ctx context.Context, binary string, config []byte) error {
	if binary == "" {
		return errors.New("check binary is empty")
	}
	file, err := os.CreateTemp("", "compose-check-*.json")
	if err != nil {
		return errors.New("cannot create temporary configuration")
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return errors.New("cannot protect temporary configuration")
	}
	if _, err := file.Write(config); err != nil {
		return errors.New("cannot write temporary configuration")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close temporary configuration")
	}
	cmd := exec.CommandContext(ctx, binary, "check", "-c", file.Name())
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return errors.New("sing-box configuration check failed")
	}
	return nil
}
