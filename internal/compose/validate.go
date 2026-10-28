package compose

import (
	"encoding/json"
	"errors"
	"fmt"
)

// validate checks the shape and local references we create or depend on.
// Native schema and protocol-specific constraints belong to sing-box check.
func validate(data []byte) error {
	base, _ := object(data)
	outbounds, err := array(base, "outbounds")
	if err != nil {
		return err
	}
	tags := map[string]bool{}
	emptyDirect := map[string]bool{}
	for _, raw := range outbounds {
		obj, err := object(raw)
		if err != nil {
			return errors.New("outbound must be an object")
		}
		if err := nativeType(obj, "outbound"); err != nil {
			return err
		}
		var kind string
		_ = json.Unmarshal(obj["type"], &kind)
		if kind == "block" || kind == "dns" || kind == "wireguard" {
			return errors.New("removed outbound type")
		}
		if kind == "direct" && (obj["override_address"] != nil || obj["override_port"] != nil) {
			return errors.New("removed direct outbound override")
		}
		tag, err := requiredTag(obj)
		if err != nil || tags[tag] {
			return errors.New("invalid or duplicate outbound tag")
		}
		tags[tag] = true
		if kind == "direct" && len(obj) == 2 {
			emptyDirect[tag] = true
		}
	}
	endpoints := map[string]bool{}
	endpointItems, err := array(base, "endpoints")
	if err != nil {
		return err
	}
	for _, raw := range endpointItems {
		obj, err := object(raw)
		if err != nil {
			return errors.New("endpoint must be an object")
		}
		tag, err := requiredTag(obj)
		if err != nil || endpoints[tag] || tags[tag] {
			return errors.New("invalid or duplicate endpoint tag")
		}
		endpoints[tag] = true
	}
	// Endpoints can be routed to directly, and may be used as dial detours.
	dialTags := make(map[string]bool, len(tags)+len(endpoints))
	for tag := range tags {
		dialTags[tag] = true
	}
	for tag := range endpoints {
		dialTags[tag] = true
	}
	for _, raw := range append(outbounds, endpointItems...) {
		obj, _ := object(raw)
		if err := reference(obj, "detour", dialTags); err != nil {
			return err
		}
		if err := reference(obj, "download_detour", tags); err != nil {
			return err
		}
		if _, exists := obj["outbounds"]; exists {
			choices, err := references(obj, "outbounds", dialTags)
			if err != nil || len(choices) == 0 {
				return errors.New("invalid outbound choices")
			}
			if _, hasDefault := obj["default"]; hasDefault {
				var selected string
				if err := json.Unmarshal(obj["default"], &selected); err != nil || selected == "" {
					return errors.New("invalid selector default")
				}
				found := false
				for _, choice := range choices {
					found = found || choice == selected
				}
				if !found {
					return errors.New("selector default is not a choice")
				}
			}
		}
	}
	inbounds, err := array(base, "inbounds")
	if err != nil {
		return err
	}
	inboundTags := map[string]bool{}
	for _, raw := range inbounds {
		obj, err := object(raw)
		if err != nil {
			return errors.New("inbound must be an object")
		}
		if err := nativeType(obj, "inbound"); err != nil {
			return err
		}
		if obj["tag"] != nil {
			tag, err := requiredTag(obj)
			if err != nil || inboundTags[tag] {
				return errors.New("invalid or duplicate inbound tag")
			}
			inboundTags[tag] = true
		}
		if obj["sniff"] != nil || obj["sniff_override_destination"] != nil {
			return errors.New("removed inbound sniff fields")
		}
		if err := reference(obj, "detour", dialTags); err != nil {
			return err
		}
	}
	route, err := nested(base, "route")
	if err != nil {
		return err
	}
	sets := map[string]bool{}
	ruleSets, err := array(route, "rule_set")
	if err != nil {
		return err
	}
	for _, raw := range ruleSets {
		obj, _ := object(raw) // Checked during merging.
		tag, _ := requiredTag(obj)
		sets[tag] = true
		if err := reference(obj, "download_detour", tags); err != nil {
			return err
		}
	}
	rules, err := array(route, "rules")
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := validateRule(rule, dialTags, endpoints, inboundTags, sets); err != nil {
			return err
		}
	}
	if err := reference(route, "final", dialTags); err != nil {
		return err
	}
	dns, err := nested(base, "dns")
	if err != nil {
		return err
	}
	servers, err := array(dns, "servers")
	if err != nil {
		return err
	}
	serverTags := map[string]bool{}
	for _, raw := range servers {
		obj, err := object(raw)
		if err != nil {
			return errors.New("DNS server must be an object")
		}
		if err := nativeType(obj, "DNS server"); err != nil {
			return err
		}
		if obj["address"] != nil {
			return errors.New("removed legacy DNS server address")
		}
		if err := reference(obj, "detour", dialTags); err != nil {
			return err
		}
		var detour string
		_ = json.Unmarshal(obj["detour"], &detour)
		if emptyDirect[detour] {
			return errors.New("DNS detour targets an empty direct outbound; omit detour for direct DNS connections")
		}
		if tagRaw, exists := obj["tag"]; exists {
			tag, err := requiredTag(obj)
			if err != nil || serverTags[tag] || len(tagRaw) == 0 {
				return errors.New("invalid or duplicate DNS server tag")
			}
			serverTags[tag] = true
		}
	}
	for _, raw := range servers {
		obj, _ := object(raw)
		if err := reference(obj, "address_resolver", serverTags); err != nil {
			return err
		}
		if err := resolver(obj, "domain_resolver", serverTags); err != nil {
			return err
		}
	}
	if err := reference(dns, "final", serverTags); err != nil {
		return err
	}
	dnsRules, err := array(dns, "rules")
	if err != nil {
		return err
	}
	for _, raw := range dnsRules {
		obj, err := object(raw)
		if err != nil {
			return errors.New("DNS rule must be an object")
		}
		if err := reference(obj, "server", serverTags); err != nil {
			return err
		}
		if _, err := references(obj, "inbound", inboundTags); err != nil {
			return err
		}
		if _, err := references(obj, "rule_set", sets); err != nil {
			return err
		}
	}
	if err := resolver(route, "default_domain_resolver", serverTags); err != nil {
		return err
	}
	for _, raw := range append(outbounds, endpointItems...) {
		obj, _ := object(raw)
		if err := resolver(obj, "domain_resolver", serverTags); err != nil {
			return err
		}
	}
	return nil
}

func nativeType(obj map[string]json.RawMessage, kind string) error {
	var name string
	if err := json.Unmarshal(obj["type"], &name); err != nil || name == "" {
		return fmt.Errorf("invalid %s type", kind)
	}
	return nil
}

func validateRule(raw json.RawMessage, outbounds, endpoints, inbounds, sets map[string]bool) error {
	obj, err := object(raw)
	if err != nil {
		return errors.New("route rule must be an object")
	}
	for _, field := range []string{"outbound", "preferred_by"} {
		if field == "preferred_by" {
			if _, err := references(obj, field, outbounds); err != nil {
				return err
			}
		} else if err := reference(obj, field, outbounds); err != nil {
			return err
		}
	}
	if err := reference(obj, "endpoint", endpoints); err != nil {
		return err
	}
	if _, err := references(obj, "inbound", inbounds); err != nil {
		return err
	}
	if _, err := references(obj, "rule_set", sets); err != nil {
		return err
	}
	if rawChildren, exists := obj["rules"]; exists {
		var children []json.RawMessage
		if err := json.Unmarshal(rawChildren, &children); err != nil || children == nil {
			return errors.New("logical rules must be an array")
		}
		for _, child := range children {
			if err := validateRule(child, outbounds, endpoints, inbounds, sets); err != nil {
				return err
			}
		}
	}
	return nil
}

func reference(obj map[string]json.RawMessage, field string, available map[string]bool) error {
	if raw, ok := obj[field]; ok {
		var tag string
		if err := json.Unmarshal(raw, &tag); err != nil || tag == "" || !available[tag] {
			return fmt.Errorf("invalid or unknown %s reference", field)
		}
	}
	return nil
}

func references(obj map[string]json.RawMessage, field string, available map[string]bool) ([]string, error) {
	raw, ok := obj[field]
	if !ok {
		return nil, nil
	}
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil {
		var tag string
		if err := json.Unmarshal(raw, &tag); err != nil {
			return nil, fmt.Errorf("invalid %s references", field)
		}
		tags = []string{tag}
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("empty %s references", field)
	}
	for _, tag := range tags {
		if tag == "" || !available[tag] {
			return nil, fmt.Errorf("unknown %s reference", field)
		}
	}
	return tags, nil
}

func resolver(obj map[string]json.RawMessage, field string, servers map[string]bool) error {
	raw, exists := obj[field]
	if !exists {
		return nil
	}
	if len(raw) > 0 && raw[0] == '{' {
		options, err := object(raw)
		if err != nil {
			return fmt.Errorf("invalid %s", field)
		}
		return reference(options, "server", servers)
	}
	return reference(obj, field, servers)
}
