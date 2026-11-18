package model

import (
	"errors"
	"net/netip"
	"strings"
)

// IsEnabled applies platform defaults only when the device has no override.
func (r RemoteControl) IsEnabled(platform string) bool {
	if r.Enabled != nil {
		return *r.Enabled
	}
	return platform == "macos" || platform == "linux"
}

// Resolved returns stable, validated settings without reading secrets or changing inputs.
func (r RemoteControl) Resolved(platform string) (RemoteControl, error) {
	enabled := r.IsEnabled(platform)
	r.Enabled = &enabled
	if !enabled {
		return RemoteControl{Enabled: &enabled}, nil
	}
	if r.Listen == "" {
		r.Listen = "127.0.0.1"
	}
	address, err := netip.ParseAddr(r.Listen)
	if err != nil || address.Zone() != "" {
		return RemoteControl{}, errors.New("remote control listen must be an IP address without a zone")
	}
	r.Listen = address.Unmap().String()
	if r.ListenPort == 0 {
		r.ListenPort = 9090
	}
	if r.ListenPort == 7890 || r.ListenPort == 7891 {
		return RemoteControl{}, errors.New("remote control port conflicts with a generated proxy inbound")
	}
	if len(r.Secret) < 24 || strings.TrimSpace(r.Secret) != r.Secret || strings.ContainsAny(r.Secret, "\r\n") || strings.HasPrefix(r.Secret, "env:") {
		return RemoteControl{}, errors.New("remote control requires a resolved secret of at least 24 bytes without surrounding whitespace or line breaks")
	}
	return r, nil
}
