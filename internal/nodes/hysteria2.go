package nodes

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

func parseHysteria2(link string) (entry, error) {
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" || u.User.Username() == "" {
		return entry{}, errors.New("invalid Hysteria2 link; expected password@server:port#name")
	}
	port, err := portNumber(u.Port())
	if err != nil {
		return entry{}, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return entry{}, errors.New("malformed Hysteria2 link query options")
	}
	allowed := map[string]bool{
		"sni": true, "insecure": true, "alpn": true, "obfs": true,
		"obfs-password": true, "upmbps": true, "downmbps": true,
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			return entry{}, errors.New("unsupported or repeated Hysteria2 option; supported: sni, insecure, alpn, obfs, obfs-password, upmbps, downmbps")
		}
	}
	password := u.User.Username()
	if suffix, ok := u.User.Password(); ok {
		if suffix == "" {
			return entry{}, errors.New("Hysteria2 userpass password is required")
		}
		password += ":" + suffix
	}
	tls, err := makeTLS("tls", q.Get("sni"), q.Get("alpn"), "", "", "")
	if err != nil {
		return entry{}, err
	}
	if values, ok := q["insecure"]; ok {
		switch values[0] {
		case "1", "true":
			tls["insecure"] = true
		case "0", "false":
			tls["insecure"] = false
		default:
			return entry{}, errors.New("Hysteria2 insecure option must be 0, 1, true, or false")
		}
	}
	out := map[string]any{"type": "hysteria2", "server": u.Hostname(), "server_port": port, "password": password, "tls": tls}
	if obfs, hasObfs := q["obfs"]; hasObfs {
		if obfs[0] != "salamander" || q.Get("obfs-password") == "" {
			return entry{}, errors.New("Hysteria2 obfs requires salamander and obfs-password")
		}
		out["obfs"] = map[string]any{"type": "salamander", "password": q.Get("obfs-password")}
	} else if _, hasPassword := q["obfs-password"]; hasPassword {
		return entry{}, errors.New("Hysteria2 obfs-password requires obfs=salamander")
	}
	for _, option := range []struct{ query, field string }{{"upmbps", "up_mbps"}, {"downmbps", "down_mbps"}} {
		if values, ok := q[option.query]; ok {
			// sing-box uses integer Mbps values; empty or zero does not set a limit.
			if strings.TrimSpace(values[0]) != values[0] || values[0] == "" {
				return entry{}, errors.New("Hysteria2 bandwidth must be a positive integer in Mbps")
			}
			mbps, err := strconv.Atoi(values[0])
			if err != nil || mbps <= 0 {
				return entry{}, errors.New("Hysteria2 bandwidth must be a positive integer in Mbps")
			}
			out[option.field] = mbps
		}
	}
	return entry{name: u.Fragment, outbound: out}, nil
}
