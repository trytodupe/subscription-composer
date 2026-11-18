package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// Load resolves file paths relative to the config and explicit env: secret references.
func Load(path string) (model.Config, error) {
	var cfg model.Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 4<<20 {
		return cfg, errors.New("service configuration exceeds 4 MiB or cannot be inspected")
	}
	dec := json.NewDecoder(io.LimitReader(f, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid service configuration JSON or unknown service field")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("configuration must contain one JSON object")
	}
	root, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return cfg, errors.New("listen must be a host:port address")
	}
	if cfg.SnapshotDir == "" {
		cfg.SnapshotDir = "state"
	}
	if !filepath.IsAbs(cfg.SnapshotDir) {
		cfg.SnapshotDir = filepath.Join(root, cfg.SnapshotDir)
	}
	for _, item := range []struct{ name, value string }{{"refresh_timeout", cfg.RefreshTimeout}, {"debounce", cfg.Debounce}} {
		if item.value != "" {
			d, err := time.ParseDuration(item.value)
			if err != nil || d < 0 || (item.name == "refresh_timeout" && (d == 0 || d > 2*time.Minute)) {
				return cfg, fmt.Errorf("invalid %s duration", item.name)
			}
		}
	}
	if cfg.RefreshTimeout == "" {
		cfg.RefreshTimeout = "20s"
	}
	if cfg.Debounce == "" {
		cfg.Debounce = "2s"
	}
	if len(cfg.Sources) == 0 || len(cfg.Devices) == 0 {
		return cfg, errors.New("at least one source and device are required")
	}
	sources := map[string]bool{}
	for i := range cfg.Sources {
		s := &cfg.Sources[i]
		if !identifier.MatchString(s.ID) || sources[s.ID] {
			return cfg, errors.New("source IDs must be unique identifiers")
		}
		sources[s.ID] = true
		switch s.Type {
		case "", "subscription", "ikuuu":
		default:
			return cfg, fmt.Errorf("source %s type must be subscription or ikuuu", s.ID)
		}
		if s.Type == "ikuuu" && (s.File != "" || len(s.Headers) != 0) {
			return cfg, fmt.Errorf("source %s ikuuu input requires an API URL and manages its own authentication", s.ID)
		}
		if (s.URL == "") == (s.File == "") {
			return cfg, fmt.Errorf("source %s requires exactly one of url or file", s.ID)
		}
		if s.URL != "" {
			if s.URL, err = secret(s.URL); err != nil {
				return cfg, fmt.Errorf("source %s URL: %w", s.ID, err)
			}
			u, e := url.Parse(s.URL)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Fragment != "" {
				return cfg, fmt.Errorf("source %s requires an HTTPS URL without a fragment", s.ID)
			}
			if s.Type == "ikuuu" {
				if u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Trim(u.Path, "/") == "" {
					return cfg, fmt.Errorf("source %s requires a secure API base URL without credentials or query", s.ID)
				}
			}
		}
		if s.File != "" && !filepath.IsAbs(s.File) {
			s.File = filepath.Join(root, s.File)
		}
		for k, v := range s.Headers {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
				return cfg, fmt.Errorf("source %s has an invalid header", s.ID)
			}
			resolved, e := secret(v)
			if e != nil || strings.ContainsAny(resolved, "\r\n") {
				return cfg, fmt.Errorf("source %s header secret is missing or invalid", s.ID)
			}
			s.Headers[k] = resolved
		}
		switch s.Format {
		case "", "auto", "sing-box", "links", "clash":
		default:
			return cfg, fmt.Errorf("source %s format must be auto, sing-box, links or clash", s.ID)
		}
	}
	devices, tokens := map[string]bool{}, map[string]bool{}
	apiSecrets := map[string]bool{}
	for i := range cfg.Devices {
		d := &cfg.Devices[i]
		if !identifier.MatchString(d.ID) || devices[d.ID] {
			return cfg, errors.New("device IDs must be unique identifiers")
		}
		devices[d.ID] = true
		if d.Platform != "macos" && d.Platform != "android" && d.Platform != "linux" {
			return cfg, fmt.Errorf("device %s platform must be macos, android or linux", d.ID)
		}
		if d.Token, err = secret(d.Token); err != nil {
			return cfg, fmt.Errorf("device %s token: %w", d.ID, err)
		}
		if len(d.Token) < 24 || tokens[d.Token] {
			return cfg, errors.New("device tokens must be unique and at least 24 bytes")
		}
		tokens[d.Token] = true
		if d.RemoteControl.IsEnabled(d.Platform) {
			resolved, e := secret(d.RemoteControl.Secret)
			if e != nil {
				return cfg, fmt.Errorf("device %s remote control secret: %w", d.ID, e)
			}
			d.RemoteControl.Secret = resolved
		}
		if d.RemoteControl, err = d.RemoteControl.Resolved(d.Platform); err != nil {
			return cfg, fmt.Errorf("device %s: %w", d.ID, err)
		}
		if d.RemoteControl.IsEnabled(d.Platform) {
			if apiSecrets[d.RemoteControl.Secret] {
				return cfg, errors.New("remote control secrets must be unique per device")
			}
			apiSecrets[d.RemoteControl.Secret] = true
		}
		if d.LocalProxy, err = d.LocalProxy.Resolved(); err != nil {
			return cfg, fmt.Errorf("device %s local_proxy: %w", d.ID, err)
		}
		var base map[string]json.RawMessage
		if json.Unmarshal(d.Base, &base) != nil || base == nil {
			return cfg, fmt.Errorf("device %s base must be a native sing-box object", d.ID)
		}
	}
	for value := range apiSecrets {
		if tokens[value] {
			return cfg, errors.New("remote control secrets must differ from subscription tokens")
		}
	}
	return cfg, nil
}

func secret(value string) (string, error) {
	if !strings.HasPrefix(value, "env:") {
		return value, nil
	}
	name := strings.TrimPrefix(value, "env:")
	if name == "" {
		return "", errors.New("empty environment variable reference")
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", errors.New("referenced environment variable is unset or empty")
	}
	return v, nil
}
