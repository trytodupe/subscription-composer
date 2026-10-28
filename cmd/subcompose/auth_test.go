package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
	"github.com/ttd/subscription-composer/internal/model"
)

func TestAuthImportVerifiesAndPersistsRotation(t *testing.T) {
	expires := time.Now().Add(30 * 24 * time.Hour).Unix()
	metadata := func(token string) map[string]any {
		return map[string]any{"site_code": "ikuuu", "user_id": "test-user", "token_type": "app", "is_active": true, "expires_at": expires, "app_token": token}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer original-test-token" {
			t.Error("wrong bootstrap credential")
		}
		var token string
		switch r.URL.Path {
		case "/api/v2/client-auth/token-info":
			token = "original-test-token"
		case "/api/v2/client-auth/refresh-app-token":
			var body map[string]string
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || body["device_id"] == "" || body["device_name"] == "" {
				t.Error("missing device binding")
			}
			token = "rotated-test-token"
		default:
			t.Error("unexpected authentication endpoint")
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "code": "SUCCESS", "data": metadata(token)})
	}))
	defer server.Close()
	root := t.TempDir()
	base := server.URL + "/api/v2"
	data, _ := json.Marshal(authstate.Session{AppToken: "original-test-token", APIBaseURL: base, ExpiresAt: expires, TokenType: "Bearer"})
	input := filepath.Join(root, "bootstrap.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := model.Config{SnapshotDir: filepath.Join(root, "state"), Sources: []model.Source{{ID: "account", Type: "ikuuu", URL: base}}}
	if err := runAuth(context.Background(), cfg, authOptions{Import: "account", File: input}); err != nil {
		t.Fatal(err)
	}
	store, err := authstate.New(filepath.Join(cfg.SnapshotDir, "auth"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Load("account")
	if err != nil || session.AppToken != "rotated-test-token" || session.DeviceID == "" {
		t.Fatal("verified rotated session not persisted")
	}
}

func TestReadAuthorizationRequiresPrivateRegularFile(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "callback.txt")
	if err := os.WriteFile(input, []byte("private-callback"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorization(input); err == nil {
		t.Fatal("publicly readable credential was accepted")
	}
	if err := os.Chmod(input, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorization(input); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(input, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorization(link); err == nil {
		t.Fatal("symlink credential was accepted")
	}
	if err := os.WriteFile(input, []byte(strings.Repeat("x", (64<<10)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorization(input); err == nil {
		t.Fatal("oversized credential was accepted")
	}
}
