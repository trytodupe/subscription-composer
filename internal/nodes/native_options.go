package nodes

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

// optionSpec describes which JSON values a provider may set for one sing-box
// outbound option. Provider-supplied native outbounds are untrusted: sing-box
// dial, TLS and plugin options can read local files (certificate_path,
// key_path, ech.config_path), bind local interfaces or network namespaces,
// set routing marks, or chain into other outbounds (detour). Only options
// that describe how to reach and authenticate to the remote node are allowed;
// everything else rejects the node.
type optionSpec struct {
	// fields lists the allowed keys when the value is an object.
	fields map[string]*optionSpec
	// anyKeys accepts an object with arbitrary keys whose values are scalars or
	// arrays of scalars (HTTP headers).
	anyKeys bool
	// scalar accepts a non-object value (string, number, bool, null) or an
	// array of such values.
	scalar bool
}

var leafOption = &optionSpec{scalar: true}

func objectOption(keys ...string) *optionSpec {
	spec := &optionSpec{fields: make(map[string]*optionSpec, len(keys))}
	for _, key := range keys {
		spec.fields[key] = leafOption
	}
	return spec
}

func (s *optionSpec) with(key string, child *optionSpec) *optionSpec {
	s.fields[key] = child
	return s
}

// nativeTLSOption deliberately omits every certificate, client key and file
// path option: a provider must not pin a custom trust anchor, present a local
// client identity, or make sing-box read local files. ECH is limited to an
// inline config. insecure is accepted here only so that an explicit false
// keeps working; validateNodeSafety rejects true for every input format.
var nativeTLSOption = objectOption(
	"enabled", "server_name", "insecure", "alpn",
	"min_version", "max_version", "cipher_suites",
).
	with("utls", objectOption("enabled", "fingerprint")).
	with("reality", objectOption("enabled", "public_key", "short_id")).
	with("ech", objectOption("enabled", "config"))

var nativeMultiplexOption = objectOption(
	"enabled", "protocol", "max_connections", "min_streams", "max_streams", "padding",
).
	with("brutal", objectOption("enabled", "up_mbps", "down_mbps"))

// udp_over_tcp is either a boolean or an object.
var nativeUDPOverTCPOption = func() *optionSpec {
	spec := objectOption("enabled", "version")
	spec.scalar = true
	return spec
}()

var nativeHeadersOption = &optionSpec{anyKeys: true}

// nativeTransportOptions is keyed by transport type. Only the transports the
// other import formats can express are accepted.
var nativeTransportOptions = map[string]*optionSpec{
	"ws": objectOption("type", "path", "max_early_data", "early_data_header_name").
		with("headers", nativeHeadersOption),
	"grpc": objectOption("type", "service_name", "idle_timeout", "ping_timeout", "permit_without_stream"),
}

// nativeOutboundOptions is keyed by outbound type. transport is validated
// separately because its allowed fields depend on the transport type.
// Shadowsocks plugin and plugin_opts are intentionally absent: sing-box's
// v2ray-plugin maps plugin_opts "cert" to a local certificate path and
// "certRaw" to a custom trust anchor, and the link and Clash importers already
// reject SS plugins.
var nativeOutboundOptions = map[string]*optionSpec{
	"shadowsocks": objectOption("type", "tag", "server", "server_port", "method", "password", "network").
		with("udp_over_tcp", nativeUDPOverTCPOption).
		with("multiplex", nativeMultiplexOption),
	"vmess": objectOption("type", "tag", "server", "server_port", "uuid", "security", "alter_id",
		"global_padding", "authenticated_length", "network", "packet_encoding").
		with("tls", nativeTLSOption).
		with("multiplex", nativeMultiplexOption),
	"vless": objectOption("type", "tag", "server", "server_port", "uuid", "flow", "network", "packet_encoding").
		with("tls", nativeTLSOption).
		with("multiplex", nativeMultiplexOption),
	"trojan": objectOption("type", "tag", "server", "server_port", "password", "network").
		with("tls", nativeTLSOption).
		with("multiplex", nativeMultiplexOption),
	"hysteria2": objectOption("type", "tag", "server", "server_port", "server_ports", "hop_interval",
		"up_mbps", "down_mbps", "password", "network").
		with("obfs", objectOption("type", "password")).
		with("tls", nativeTLSOption),
	"tuic": objectOption("type", "tag", "server", "server_port", "uuid", "password", "congestion_control",
		"udp_relay_mode", "udp_over_stream", "zero_rtt_handshake", "heartbeat", "network").
		with("tls", nativeTLSOption),
}

func validateNativeOptions(typ string, outbound map[string]any) error {
	spec := nativeOutboundOptions[typ]
	if spec == nil {
		return errors.New("unsupported native protocol; supported: shadowsocks, vmess, vless, trojan, hysteria2, tuic")
	}
	for _, key := range slices.Sorted(maps.Keys(outbound)) {
		if key == "transport" {
			if err := validateNativeTransport(typ, outbound[key]); err != nil {
				return err
			}
			continue
		}
		child := spec.fields[key]
		if child == nil {
			return unsupportedOption("", key)
		}
		if err := validateOption(key, outbound[key], child); err != nil {
			return err
		}
	}
	return nil
}

func validateNativeTransport(typ string, value any) error {
	if typ == "hysteria2" || typ == "tuic" {
		return errors.New("transport is unsupported for QUIC outbounds")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return errors.New("transport must be an object")
	}
	t, _ := obj["type"].(string)
	spec := nativeTransportOptions[t]
	if spec == nil {
		return errors.New("unsupported transport; supported: tcp, ws, grpc")
	}
	return validateOption("transport", obj, spec)
}

func validateOption(path string, value any, spec *optionSpec) error {
	switch v := value.(type) {
	case map[string]any:
		if spec.anyKeys {
			for _, key := range slices.Sorted(maps.Keys(v)) {
				if !isScalarOrScalarArray(v[key]) {
					return fmt.Errorf("option %s values must be strings or string arrays", path)
				}
			}
			return nil
		}
		if spec.fields == nil {
			return fmt.Errorf("option %s must not be an object", path)
		}
		for _, key := range slices.Sorted(maps.Keys(v)) {
			child := spec.fields[key]
			if child == nil {
				return unsupportedOption(path, key)
			}
			if err := validateOption(path+"."+key, v[key], child); err != nil {
				return err
			}
		}
		return nil
	default:
		if !spec.scalar {
			return fmt.Errorf("option %s must be an object", path)
		}
		if !isScalarOrScalarArray(v) {
			return fmt.Errorf("option %s must be a scalar or an array of scalars", path)
		}
		return nil
	}
}

func isScalarOrScalarArray(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		return false
	case []any:
		for _, item := range v {
			switch item.(type) {
			case map[string]any, []any:
				return false
			}
		}
	}
	return true
}

// optionName matches sing-box option keys. Only such keys are echoed in errors
// so that arbitrary provider content (possibly credentials) never is.
var optionName = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

func unsupportedOption(path, key string) error {
	location := ""
	if path != "" {
		location = " under " + path
	}
	if !optionName.MatchString(key) {
		return fmt.Errorf("unsupported option%s in provider node", location)
	}
	if path != "" {
		key = path + "." + key
	}
	return fmt.Errorf("unsupported option %s in provider node", key)
}
