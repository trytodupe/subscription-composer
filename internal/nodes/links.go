package nodes

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func parseLinks(input string) ([]entry, error) {
	if !strings.Contains(input, "://") {
		decoded, err := decodeBase64(input)
		if err != nil {
			return nil, errors.New("expected ss://, vmess://, vless://, trojan://, hy2://, or hysteria2:// links; use format clash for YAML")
		}
		input = strings.TrimSpace(string(decoded))
	}
	var entries []entry
	for lineNumber, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e entry
		var err error
		switch {
		case strings.HasPrefix(line, "ss://"):
			e, err = parseSS(line)
		case strings.HasPrefix(line, "vmess://"):
			e, err = parseVMess(line)
		case strings.HasPrefix(line, "vless://"):
			e, err = parseProxyURL(line, "vless")
		case strings.HasPrefix(line, "trojan://"):
			e, err = parseProxyURL(line, "trojan")
		case strings.HasPrefix(line, "hy2://"), strings.HasPrefix(line, "hysteria2://"):
			e, err = parseHysteria2(line)
		default:
			return nil, fmt.Errorf("line %d: unsupported link protocol; use ss, vmess, vless, trojan, hy2, or hysteria2 (use format clash for YAML)", lineNumber+1)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func parseSS(link string) (entry, error) {
	// Legacy SS subscriptions encode method:password@host:port as one unit.
	payload := strings.TrimPrefix(link, "ss://")
	if before, _, _ := strings.Cut(payload, "#"); !strings.Contains(before, "@") {
		encoded, suffix, _ := strings.Cut(payload, "#")
		decoded, err := decodeBase64(encoded)
		if err != nil {
			return entry{}, errors.New("invalid SS credentials encoding")
		}
		link = "ss://" + string(decoded) + "#" + suffix
	}
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return entry{}, errors.New("invalid SS link; expected credentials@server:port#name")
	}
	if u.RawQuery != "" {
		return entry{}, errors.New("SS plugin or query options are unsupported; use an unmodified SIP002 link")
	}
	userinfo := u.User.String()
	if strings.Contains(userinfo, ":") {
		// Percent-encoded credentials are already decoded by url.Userinfo.
		password, ok := u.User.Password()
		if !ok {
			return entry{}, errors.New("SS password is required")
		}
		userinfo = u.User.Username() + ":" + password
	} else {
		decoded, err := decodeBase64(u.User.Username())
		if err != nil {
			return entry{}, errors.New("invalid SIP002 SS credentials")
		}
		userinfo = string(decoded)
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || password == "" {
		return entry{}, errors.New("SS method and password are required")
	}
	if !ssMethods[method] {
		return entry{}, errors.New("unsupported SS method; use a sing-box supported AES or ChaCha20 method")
	}
	port, err := portNumber(u.Port())
	if err != nil {
		return entry{}, err
	}
	return entry{name: u.Fragment, outbound: map[string]any{"type": "shadowsocks", "server": u.Hostname(), "server_port": port, "method": method, "password": password}}, nil
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"chacha20-ietf": true, "rc4-md5": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
}

func parseVMess(link string) (entry, error) {
	decoded, err := decodeBase64(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return entry{}, errors.New("invalid VMess v2rayN base64 payload")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(decoded, &fields) != nil || fields == nil {
		return entry{}, errors.New("VMess link must contain v2rayN JSON")
	}
	allowed := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true, "verify_cert": true, "class": true}
	for key := range fields {
		if !allowed[key] {
			return entry{}, errors.New("unsupported VMess v2rayN field; supported: ps, add, port, id, aid, scy, net, type, host, path, tls, sni, alpn, fp")
		}
	}
	get := func(key string) (string, error) {
		var value string
		if len(fields[key]) == 0 {
			return "", nil
		}
		if err := json.Unmarshal(fields[key], &value); err == nil {
			return value, nil
		}
		var number json.Number
		if err := json.Unmarshal(fields[key], &number); err == nil {
			return number.String(), nil
		}
		return "", errors.New("VMess v2rayN fields must be strings or numbers")
	}
	// Some SSPanel subscriptions attach presentation metadata and certificate
	// verification as a boolean outside the usual v2rayN string fields.
	var verifyCert *bool
	if raw, ok := fields["verify_cert"]; ok {
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil || string(raw) == "null" {
			return entry{}, errors.New("VMess verify_cert must be a boolean")
		}
		verifyCert = &value
	}
	values := make(map[string]string, len(fields))
	for key := range fields {
		if key == "class" || key == "verify_cert" {
			continue
		}
		values[key], err = get(key)
		if err != nil {
			return entry{}, err
		}
	}
	if values["v"] != "" && values["v"] != "2" {
		return entry{}, errors.New("unsupported VMess v2rayN version; use version 2")
	}
	if values["ps"] == "" || values["add"] == "" || values["id"] == "" {
		return entry{}, errors.New("VMess name, server, and UUID are required")
	}
	port, err := portNumber(values["port"])
	if err != nil {
		return entry{}, err
	}
	aid := 0
	if values["aid"] != "" {
		aid, err = strconv.Atoi(values["aid"])
		if err != nil || aid < 0 {
			return entry{}, errors.New("VMess alter ID must be a nonnegative integer")
		}
	}
	scy := values["scy"]
	if scy == "" {
		scy = "auto"
	}
	if !map[string]bool{"auto": true, "none": true, "zero": true, "aes-128-gcm": true, "chacha20-poly1305": true}[scy] {
		return entry{}, errors.New("unsupported VMess security cipher")
	}
	if values["type"] != "" && values["type"] != "none" {
		return entry{}, errors.New("unsupported VMess header type; only none is supported")
	}
	out := map[string]any{"type": "vmess", "server": values["add"], "server_port": port, "uuid": values["id"], "alter_id": aid, "security": scy}
	tlsMode := values["tls"]
	if tlsMode != "" && tlsMode != "none" && tlsMode != "tls" {
		return entry{}, errors.New("unsupported VMess TLS mode")
	}
	if tlsMode == "tls" {
		tls, err := makeTLS("tls", values["sni"], values["alpn"], values["fp"], "", "")
		if err != nil {
			return entry{}, err
		}
		if verifyCert != nil {
			tls["insecure"] = !*verifyCert
		}
		out["tls"] = tls
	} else if values["sni"] != "" || values["alpn"] != "" || values["fp"] != "" {
		return entry{}, errors.New("VMess TLS options require tls mode")
	}
	transport, err := makeTransport(values["net"], values["host"], values["path"], "")
	if err != nil {
		return entry{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	return entry{name: values["ps"], outbound: out}, nil
}

func parseProxyURL(link, protocol string) (entry, error) {
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return entry{}, errors.New("invalid proxy link; expected credentials@server:port#name")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return entry{}, errors.New("unexpected password separator in proxy credentials")
	}
	credential := u.User.Username()
	if credential == "" {
		return entry{}, errors.New("proxy credentials are required")
	}
	port, err := portNumber(u.Port())
	if err != nil {
		return entry{}, err
	}
	allowed := map[string]bool{
		"type": true, "security": true, "sni": true, "alpn": true, "fp": true,
		"host": true, "path": true, "serviceName": true, "headerType": true,
	}
	if protocol == "vless" {
		allowed["encryption"] = true
		allowed["flow"] = true
		allowed["pbk"] = true
		allowed["sid"] = true
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return entry{}, errors.New("malformed proxy link query options")
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			return entry{}, errors.New("unsupported or repeated proxy link option; supported: type, security, sni, alpn, fp, host, path, serviceName, headerType, and VLESS encryption, flow, pbk, sid")
		}
	}
	if q.Get("headerType") != "" && q.Get("headerType") != "none" {
		return entry{}, errors.New("unsupported TCP header; only none is supported")
	}
	security := q.Get("security")
	if security == "" && protocol == "trojan" {
		security = "tls"
	}
	if protocol == "trojan" && security != "tls" {
		return entry{}, errors.New("Trojan links require TLS")
	}
	if protocol == "vless" && security != "" && security != "none" && security != "tls" && security != "reality" {
		return entry{}, errors.New("unsupported VLESS security; use none, tls, or reality")
	}
	out := map[string]any{"type": protocol, "server": u.Hostname(), "server_port": port}
	if protocol == "vless" {
		out["uuid"] = credential
		if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
			return entry{}, errors.New("unsupported VLESS encryption; use none")
		}
		if flow := q.Get("flow"); flow != "" {
			if flow != "xtls-rprx-vision" || (security != "tls" && security != "reality") || (q.Get("type") != "" && q.Get("type") != "tcp") {
				return entry{}, errors.New("VLESS flow supports only xtls-rprx-vision over TCP with TLS or Reality")
			}
			out["flow"] = flow
		}
	} else {
		out["password"] = credential
	}
	if security == "tls" || security == "reality" {
		tls, err := makeTLS(security, q.Get("sni"), q.Get("alpn"), q.Get("fp"), q.Get("pbk"), q.Get("sid"))
		if err != nil {
			return entry{}, err
		}
		out["tls"] = tls
	} else if q.Get("sni") != "" || q.Get("alpn") != "" || q.Get("fp") != "" || q.Get("pbk") != "" || q.Get("sid") != "" {
		return entry{}, errors.New("TLS and Reality options require matching security mode")
	}
	transport, err := makeTransport(q.Get("type"), q.Get("host"), q.Get("path"), q.Get("serviceName"))
	if err != nil {
		return entry{}, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	return entry{name: u.Fragment, outbound: out}, nil
}

func makeTLS(mode, serverName, alpn, fingerprint, publicKey, shortID string) (map[string]any, error) {
	tls := map[string]any{"enabled": true}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if alpn != "" {
		var protocols []string
		for _, part := range strings.Split(alpn, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return nil, errors.New("TLS ALPN must contain nonempty protocol names")
			}
			protocols = append(protocols, part)
		}
		tls["alpn"] = protocols
	}
	if fingerprint != "" {
		if !map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "edge": true, "random": true, "randomized": true}[fingerprint] {
			return nil, errors.New("unsupported uTLS fingerprint")
		}
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if mode == "reality" {
		if publicKey == "" {
			return nil, errors.New("Reality public key (pbk) is required")
		}
		tls["reality"] = map[string]any{"enabled": true, "public_key": publicKey, "short_id": shortID}
	} else if publicKey != "" || shortID != "" {
		return nil, errors.New("Reality options require reality security")
	}
	return tls, nil
}

func makeTransport(network, host, path, serviceName string) (map[string]any, error) {
	switch network {
	case "", "tcp":
		if host != "" || path != "" || serviceName != "" {
			return nil, errors.New("host, path, and serviceName require the matching ws or grpc transport")
		}
		return nil, nil
	case "ws":
		if serviceName != "" {
			return nil, errors.New("serviceName requires grpc transport")
		}
		transport := map[string]any{"type": "ws"}
		if path != "" {
			transport["path"] = path
		}
		if host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		return transport, nil
	case "grpc":
		if host != "" || path != "" {
			return nil, errors.New("host and path require ws transport")
		}
		return map[string]any{"type": "grpc", "service_name": serviceName}, nil
	default:
		return nil, errors.New("unsupported transport; use tcp, ws, or grpc")
	}
}
