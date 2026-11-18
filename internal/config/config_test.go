package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadResolvesPathsAndSecretReferences(t *testing.T) {
	t.Setenv("TEST_SUBCOMPOSE_TOKEN", "test-token-with-at-least-24-bytes")
	dir := t.TempDir()
	body := `{"sources":[{"id":"airport","file":"nodes.json"}],"devices":[{"id":"phone","platform":"android","token":"env:TEST_SUBCOMPOSE_TOKEN","base":{}}]}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[0].File != filepath.Join(dir, "nodes.json") || cfg.SnapshotDir != filepath.Join(dir, "state") {
		t.Fatal("relative paths were not resolved against config directory")
	}
	if cfg.Devices[0].Token != os.Getenv("TEST_SUBCOMPOSE_TOKEN") {
		t.Fatal("secret reference was not resolved")
	}
}

func TestLoadRejectsInvalidConfigurationWithoutExposingSecrets(t *testing.T) {
	valid := `{"sources":[{"id":"airport","url":"https://secret-user:secret-password@example.com/sub"}],"devices":[{"id":"phone","platform":"android","token":"a-long-enough-device-token-for-tests","base":{}}]}`
	cases := []string{
		strings.Replace(valid, `"sources":`, `"unknown":true,"sources":`, 1),
		valid + ` {}`,
		strings.Replace(valid, `"url":`, `"file":"nodes.json","url":`, 1),
		strings.Replace(valid, `"android"`, `"windows"`, 1),
		strings.Replace(valid, `a-long-enough-device-token-for-tests`, `env:SUBCOMPOSE_MISSING_ENV`, 1),
		strings.Replace(valid, `"sources":`, `"refresh_timeout":"0s","sources":`, 1),
		strings.Replace(valid, `https://`, `http://`, 1),
		strings.Replace(valid, `https://secret-user:secret-password@example.com`, `http://127.0.0.1`, 1),
		strings.Replace(valid, `"base":{}`, `"local_proxy":{"allow_cidrs":["0.0.0.0/0"]},"base":{}`, 1),
		strings.Replace(valid, `"base":{}`, `"local_proxy":{"allow_cidrs":["::/0"]},"base":{}`, 1),
		strings.Replace(valid, `"base":{}`, `"local_proxy":{"allow_cidrs":["172.16.20.1"]},"base":{}`, 1),
	}
	for i, body := range cases {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
		if strings.Contains(err.Error(), "secret-password") || strings.Contains(err.Error(), "a-long-enough-device-token-for-tests") {
			t.Fatalf("case %d exposed a secret", i)
		}
	}
}

func TestLoadCanonicalizesLocalProxyCIDRs(t *testing.T) {
	body := `{"sources":[{"id":"airport","file":"nodes.json"}],"devices":[{"id":"phone","platform":"android","token":"a-long-enough-device-token-for-tests","local_proxy":{"allow_tailscale":true,"allow_cidrs":["172.16.20.9/24","172.16.20.0/24"]},"base":{}}]}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	lp := cfg.Devices[0].LocalProxy
	if !lp.AllowTailscale || len(lp.AllowCIDRs) != 1 || lp.AllowCIDRs[0] != "172.16.20.0/24" {
		t.Fatalf("unexpected local_proxy: %+v", lp)
	}
}
