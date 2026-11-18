package compose

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ttd/subscription-composer/internal/model"
)

func addRemoteControl(base map[string]json.RawMessage, device model.Device) error {
	settings, err := device.RemoteControl.Resolved(device.Platform)
	if err != nil {
		return err
	}
	items, err := array(base, "services")
	if err != nil {
		return err
	}
	tags := make(map[string]bool)
	for _, raw := range items {
		service, err := object(raw)
		if err != nil {
			return errors.New("base service must be an object")
		}
		if err := nativeType(service, "service"); err != nil {
			return err
		}
		var kind string
		_ = json.Unmarshal(service["type"], &kind)
		if kind == "api" {
			return errors.New("configure API services through remote_control instead of base.services")
		}
		if service["tag"] != nil {
			tag, err := requiredTag(service)
			if err != nil || tags[tag] || tag == "remote-api" || tag == "remote-api-loopback" {
				return errors.New("invalid, duplicate or reserved base service tag")
			}
			tags[tag] = true
		}
	}
	if !settings.IsEnabled(device.Platform) {
		return nil
	}
	if settings.Secret == device.Token {
		return errors.New("remote control secret must differ from subscription token")
	}
	// Reject port reuse before publication instead of waiting for a client bind failure.
	for _, key := range []string{"inbounds", "services"} {
		listeners, err := array(base, key)
		if err != nil {
			return err
		}
		for _, raw := range listeners {
			listener, err := object(raw)
			if err != nil {
				return fmt.Errorf("base %s entry must be an object", key)
			}
			var port uint16
			if value, exists := listener["listen_port"]; exists {
				if err := json.Unmarshal(value, &port); err != nil {
					return fmt.Errorf("base %s listen_port must be a valid port", key)
				}
				if port == settings.ListenPort {
					return errors.New("remote control port conflicts with a base listener")
				}
			}
		}
	}
	items, err = appendJSON(items, map[string]any{
		"type": "api", "tag": "remote-api",
		"listen": settings.Listen, "listen_port": settings.ListenPort,
		"secret": settings.Secret,
	})
	if err != nil {
		return errors.New("cannot encode remote control service")
	}
	if device.Platform == "macos" && (settings.Listen == "::" || settings.Listen == "0.0.0.0") {
		items, err = appendJSON(items, map[string]any{
			"type": "api", "tag": "remote-api-loopback",
			"listen": "127.0.0.1", "listen_port": settings.ListenPort,
			"secret": settings.Secret,
		})
		if err != nil {
			return errors.New("cannot encode remote control service")
		}
	}
	base["services"], err = json.Marshal(items)
	return err
}
