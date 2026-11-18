package clientupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

func object(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value map[string]any
	if err := dec.Decode(&value); err != nil || value == nil {
		return nil, errors.New("configuration must be a JSON object")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("configuration must contain one JSON object")
	}
	return value, nil
}

func services(obj map[string]any) ([]any, error) {
	value, exists := obj["services"]
	if !exists {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New("services must be an array")
	}
	for _, item := range items {
		service, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("service must be an object")
		}
		kind, ok := service["type"].(string)
		if !ok || kind == "" {
			return nil, errors.New("service requires a type")
		}
	}
	return items, nil
}

func localObject(data []byte) (map[string]any, error) {
	local, err := object(data)
	if err != nil {
		return nil, err
	}
	for key := range local {
		if key != "services" && key != "log" {
			return nil, errors.New("local configuration allows only services and log")
		}
	}
	items, err := services(local)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.(map[string]any)["type"] != "api" {
			return nil, errors.New("local configuration allows only API services")
		}
	}
	return local, nil
}

// projectLocal removes a single legacy API only when its replacement is supplied
// by the subscription. Validation still rejects duplicates within either input.
func projectLocal(local, subscription []byte) ([]byte, error) {
	l, err := localObject(local)
	if err != nil {
		return nil, err
	}
	s, err := object(subscription)
	if err != nil {
		return nil, err
	}
	remote, err := services(s)
	if err != nil {
		return nil, err
	}
	localServices, _ := services(l)
	apis := 0
	for _, item := range remote {
		if item.(map[string]any)["type"] == "api" {
			apis++
		}
	}
	if len(localServices) != 1 || apis != 1 {
		return local, nil
	}
	// Validate the legacy service before removing it, including its stable tag.
	if _, err := pairDigest(local, []byte(`{}`)); err != nil {
		return nil, err
	}
	delete(l, "services")
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, errors.New("cannot project local configuration")
	}
	return append(data, '\n'), nil
}

func pairObjects(local, subscription []byte) (map[string]any, map[string]any, map[string]any, error) {
	l, err := localObject(local)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := object(subscription)
	if err != nil {
		return nil, nil, nil, err
	}
	localServices, _ := services(l)
	remoteServices, err := services(s)
	if err != nil {
		return nil, nil, nil, err
	}
	tags := make(map[string]bool)
	var api map[string]any
	apis := 0
	for _, items := range [][]any{localServices, remoteServices} {
		for _, item := range items {
			service := item.(map[string]any)
			value, exists := service["tag"]
			tag, ok := value.(string)
			if exists {
				if !ok || tag == "" || tags[tag] {
					return nil, nil, nil, errors.New("invalid or conflicting service tag")
				}
				tags[tag] = true
			}
			if service["type"] == "api" {
				if tag == "" {
					return nil, nil, nil, errors.New("API service requires a stable tag")
				}
				apis++
				api = service
			}
		}
	}
	if apis != 1 {
		return nil, nil, nil, errors.New("configuration pair must contain exactly one API service")
	}
	return l, s, api, nil
}

// pairDigest preserves array order and JSON number precision. The pair describes
// the exact explicit inputs to native validation; it does not emulate native merge.
func pairDigest(local, subscription []byte) (string, error) {
	l, s, _, err := pairObjects(local, subscription)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal([]any{l, s})
	if err != nil {
		return "", errors.New("cannot canonicalize configuration")
	}
	return contentHash(canonical), nil
}

func contentHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func equivalent(a, b []byte) bool {
	left, err := object(a)
	if err != nil {
		return false
	}
	right, err := object(b)
	if err != nil {
		return false
	}
	x, _ := json.Marshal(left)
	y, _ := json.Marshal(right)
	return bytes.Equal(x, y)
}
