package nodes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var clashMetadata = map[string]bool{
	"group": true, "groups": true, "label": true, "labels": true, "class": true,
}

func parseClash(body []byte) ([]entry, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, errors.New("invalid Clash YAML")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("Clash YAML must contain one document")
	}
	// Inspect the syntax tree before mapping values: aliases, anchors and repeated
	// keys can otherwise change what a proxy connects to or expand unpredictably.
	stack := []*yaml.Node{&root}
	for count := 0; len(stack) > 0; count++ {
		if count >= 100000 {
			return nil, errors.New("Clash YAML has too many nodes")
		}
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.Kind == yaml.AliasNode || node.Anchor != "" {
			return nil, errors.New("Clash YAML aliases and anchors are unsupported")
		}
		if node.Kind == yaml.MappingNode {
			seen := make(map[string]bool, len(node.Content)/2)
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					return nil, errors.New("Clash YAML mapping keys must be strings")
				}
				if seen[key.Value] {
					return nil, errors.New("duplicate Clash YAML field")
				}
				seen[key.Value] = true
			}
		}
		stack = append(stack, node.Content...)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("Clash YAML must be a mapping")
	}
	fields := clashMap(root.Content[0])
	proxies := fields["proxies"]
	if proxies == nil || proxies.Kind != yaml.SequenceNode || len(proxies.Content) == 0 {
		return nil, errors.New("Clash YAML proxies must be a nonempty list")
	}
	entries := make([]entry, 0, len(proxies.Content))
	for i, proxy := range proxies.Content {
		if proxy.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("proxy %d: expected a mapping", i+1)
		}
		fields := clashMap(proxy)
		typ, err := clashRequired(fields, "type")
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", i+1, err)
		}
		var e entry
		switch typ {
		case "ss":
			e, err = clashSS(fields)
		case "vmess":
			e, err = clashVMess(fields)
		default:
			err = errors.New("unsupported Clash proxy protocol; supported: ss, vmess")
		}
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", i+1, err)
		}
		entries = append(entries, e)
	}
	if err := clashNodeResolvers(fields, entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func clashMap(node *yaml.Node) map[string]*yaml.Node {
	fields := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		fields[node.Content[i].Value] = node.Content[i+1]
	}
	return fields
}

func clashAllowed(fields map[string]*yaml.Node, allowMetadata bool, names ...string) error {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for key := range fields {
		if key == "plugin" || key == "plugin-opts" {
			return errors.New("Clash proxy plugins are unsupported")
		}
		if !allowed[key] && !(allowMetadata && clashMetadata[key]) {
			return errors.New("unsupported Clash proxy connection field")
		}
	}
	return nil
}

func clashString(fields map[string]*yaml.Node, key string) (string, error) {
	node := fields[key]
	if node == nil {
		return "", nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("Clash %s must be a string", key)
	}
	return node.Value, nil
}

func clashRequired(fields map[string]*yaml.Node, key string) (string, error) {
	value, err := clashString(fields, key)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("Clash %s is required", key)
	}
	return value, nil
}

func clashPort(fields map[string]*yaml.Node) (int, error) {
	node := fields["port"]
	if node == nil || node.Kind != yaml.ScalarNode || (node.Tag != "!!str" && node.Tag != "!!int") {
		return 0, errors.New("node port must be a number from 1 to 65535")
	}
	return portNumber(node.Value)
}

func clashBool(fields map[string]*yaml.Node, key string) (bool, error) {
	node := fields[key]
	if node == nil {
		return false, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return false, fmt.Errorf("Clash %s must be a boolean", key)
	}
	value, err := strconv.ParseBool(node.Value)
	if err != nil {
		return false, fmt.Errorf("Clash %s must be a boolean", key)
	}
	return value, nil
}

func clashUDP(fields map[string]*yaml.Node, out map[string]any) error {
	if fields["udp"] == nil {
		return nil
	}
	udp, err := clashBool(fields, "udp")
	if err != nil {
		return err
	}
	if !udp {
		out["network"] = []string{"tcp"}
	}
	return nil
}

func clashSS(fields map[string]*yaml.Node) (entry, error) {
	if err := clashAllowed(fields, true, "name", "type", "server", "port", "cipher", "password", "udp", "client-fingerprint"); err != nil {
		return entry{}, err
	}
	name, err := clashRequired(fields, "name")
	if err != nil {
		return entry{}, err
	}
	server, err := clashRequired(fields, "server")
	if err != nil {
		return entry{}, err
	}
	port, err := clashPort(fields)
	if err != nil {
		return entry{}, err
	}
	cipher, err := clashRequired(fields, "cipher")
	if err != nil {
		return entry{}, err
	}
	if !ssMethods[cipher] {
		return entry{}, errors.New("unsupported Clash SS cipher")
	}
	password, err := clashRequired(fields, "password")
	if err != nil {
		return entry{}, err
	}
	// SS has no TLS handshake, so a client fingerprint cannot affect this outbound.
	if _, err := clashString(fields, "client-fingerprint"); err != nil {
		return entry{}, err
	}
	out := map[string]any{"type": "shadowsocks", "server": server, "server_port": port, "method": cipher, "password": password}
	if err := clashUDP(fields, out); err != nil {
		return entry{}, err
	}
	return entry{name: name, outbound: out}, nil
}

func clashVMess(fields map[string]*yaml.Node) (entry, error) {
	if err := clashAllowed(fields, true, "name", "type", "server", "port", "uuid", "alterId", "cipher", "network", "tls", "servername", "sni", "skip-cert-verify", "ws-opts", "grpc-opts", "alpn", "client-fingerprint", "udp"); err != nil {
		return entry{}, err
	}
	name, err := clashRequired(fields, "name")
	if err != nil {
		return entry{}, err
	}
	server, err := clashRequired(fields, "server")
	if err != nil {
		return entry{}, err
	}
	port, err := clashPort(fields)
	if err != nil {
		return entry{}, err
	}
	uuid, err := clashRequired(fields, "uuid")
	if err != nil {
		return entry{}, err
	}
	aid := 0
	if node := fields["alterId"]; node != nil {
		if node.Kind != yaml.ScalarNode || (node.Tag != "!!int" && node.Tag != "!!str") {
			return entry{}, errors.New("Clash alterId must be a nonnegative integer")
		}
		aid, err = strconv.Atoi(node.Value)
		if err != nil || aid < 0 {
			return entry{}, errors.New("Clash alterId must be a nonnegative integer")
		}
	}
	cipher, err := clashString(fields, "cipher")
	if err != nil {
		return entry{}, err
	}
	if cipher == "" {
		cipher = "auto"
	}
	if !map[string]bool{"auto": true, "none": true, "zero": true, "aes-128-gcm": true, "chacha20-poly1305": true}[cipher] {
		return entry{}, errors.New("unsupported Clash VMess cipher")
	}
	network, err := clashString(fields, "network")
	if err != nil {
		return entry{}, err
	}
	serverName, err := clashString(fields, "servername")
	if err != nil {
		return entry{}, err
	}
	sni, err := clashString(fields, "sni")
	if err != nil {
		return entry{}, err
	}
	if serverName != "" && sni != "" && serverName != sni {
		return entry{}, errors.New("Clash servername and sni conflict")
	}
	if serverName == "" {
		serverName = sni
	}
	fingerprint, err := clashString(fields, "client-fingerprint")
	if err != nil {
		return entry{}, err
	}
	alpn, err := clashALPN(fields["alpn"])
	if err != nil {
		return entry{}, err
	}
	tlsEnabled, err := clashBool(fields, "tls")
	if err != nil {
		return entry{}, err
	}
	skipVerify, err := clashBool(fields, "skip-cert-verify")
	if err != nil {
		return entry{}, err
	}
	out := map[string]any{"type": "vmess", "server": server, "server_port": port, "uuid": uuid, "alter_id": aid, "security": cipher}
	if tlsEnabled {
		tls, err := makeTLS("tls", serverName, alpn, fingerprint, "", "")
		if err != nil {
			return entry{}, err
		}
		if fields["skip-cert-verify"] != nil {
			tls["insecure"] = skipVerify
		}
		out["tls"] = tls
	} else if serverName != "" || alpn != "" || fingerprint != "" || skipVerify {
		return entry{}, errors.New("Clash TLS options require tls mode")
	}
	var host, path, serviceName string
	if fields["ws-opts"] != nil {
		if network != "ws" {
			return entry{}, errors.New("Clash ws-opts require ws transport")
		}
		host, path, err = clashWS(fields["ws-opts"])
		if err != nil {
			return entry{}, err
		}
	}
	if fields["grpc-opts"] != nil {
		if network != "grpc" {
			return entry{}, errors.New("Clash grpc-opts require grpc transport")
		}
		serviceName, err = clashGRPC(fields["grpc-opts"])
		if err != nil {
			return entry{}, err
		}
	}
	transport, err := makeTransport(network, host, path, serviceName)
	if err != nil {
		return entry{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	if err := clashUDP(fields, out); err != nil {
		return entry{}, err
	}
	return entry{name: name, outbound: out}, nil
}

func clashALPN(node *yaml.Node) (string, error) {
	if node == nil {
		return "", nil
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		return node.Value, nil
	}
	if node.Kind != yaml.SequenceNode || len(node.Content) == 0 {
		return "", errors.New("Clash alpn must be a nonempty list of strings")
	}
	parts := make([]string, 0, len(node.Content))
	for _, part := range node.Content {
		if part.Kind != yaml.ScalarNode || part.Tag != "!!str" || strings.TrimSpace(part.Value) == "" || strings.Contains(part.Value, ",") {
			return "", errors.New("Clash alpn must contain nonempty protocol names")
		}
		parts = append(parts, part.Value)
	}
	return strings.Join(parts, ","), nil
}

func clashWS(node *yaml.Node) (string, string, error) {
	if node.Kind != yaml.MappingNode {
		return "", "", errors.New("Clash ws-opts must be a mapping")
	}
	fields := clashMap(node)
	if err := clashAllowed(fields, false, "path", "headers"); err != nil {
		return "", "", err
	}
	path, err := clashString(fields, "path")
	if err != nil {
		return "", "", err
	}
	var host string
	if headers := fields["headers"]; headers != nil {
		if headers.Kind != yaml.MappingNode {
			return "", "", errors.New("Clash ws-opts headers must be a mapping")
		}
		for key, value := range clashMap(headers) {
			if !strings.EqualFold(key, "Host") || host != "" || value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
				return "", "", errors.New("Clash ws-opts supports only one Host header")
			}
			host = value.Value
		}
	}
	return host, path, nil
}

func clashGRPC(node *yaml.Node) (string, error) {
	if node.Kind != yaml.MappingNode {
		return "", errors.New("Clash grpc-opts must be a mapping")
	}
	fields := clashMap(node)
	if err := clashAllowed(fields, false, "grpc-service-name"); err != nil {
		return "", err
	}
	return clashString(fields, "grpc-service-name")
}
