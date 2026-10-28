package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIkUUUSourceConfigurationValidation(t *testing.T) {
	base := `{"sources":[{"id":"official","type":"ikuuu","url":"https://api.example/api/v2","format":"clash"}],"devices":[{"id":"mac","platform":"macos","token":"a-valid-device-token-for-test-use","base":{}}]}`
	cases := []struct {
		name, body string
		valid      bool
	}{
		{"secure API", base, true},
		{"loopback development", strings.Replace(base, "https://api.example", "http://127.0.0.1:8081", 1), true},
		{"insecure public API", strings.Replace(base, "https://api.example", "http://api.example", 1), false},
		{"credentials in API URL", strings.Replace(base, "https://api.example", "https://user:private-value@api.example", 1), false},
		{"query on API base", strings.Replace(base, "/api/v2\"", "/api/v2?token=private-value\"", 1), false},
		{"file for app source", strings.Replace(base, `"url":"https://api.example/api/v2"`, `"file":"nodes.json"`, 1), false},
		{"custom auth headers", strings.Replace(base, `"format":"clash"`, `"format":"clash","headers":{"Authorization":"Bearer private-value"}`, 1), false},
		{"unknown type", strings.Replace(base, `"type":"ikuuu"`, `"type":"unknown"`, 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("configuration error exposed a credential")
			}
		})
	}
}
