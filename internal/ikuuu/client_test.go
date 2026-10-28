package ikuuu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
)

func clientStore(t *testing.T) *authstate.Store {
	t.Helper()
	store, err := authstate.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func clientSession(base, token string) authstate.Session {
	return authstate.Session{APIBaseURL: base, AppToken: token, ExpiresAt: time.Now().Add(48 * time.Hour).Unix(), TokenType: "Bearer"}
}

func tokenResponse(token string) string {
	return responseEnvelope(fmt.Sprintf(`{"site_code":"site","user_id":"user","token_type":"app","expires_at":%d,"is_active":true,"created_at":1,"last_used_at":null,"app_token":%q}`, time.Now().Add(48*time.Hour).Unix(), token))
}

func TestImportVerifiesPersistsAndRotates(t *testing.T) {
	store := clientStore(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer old-secret" || r.URL.RawQuery != "" {
			t.Error("incorrect token authentication or query")
		}
		switch r.URL.Path {
		case "/api/v2/client-auth/token-info":
			if r.Method != http.MethodGet {
				t.Error("token info must use GET")
			}
			fmt.Fprint(w, tokenResponse("old-secret"))
		case "/api/v2/client-auth/refresh-app-token":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Error("incorrect refresh request")
			}
			var fields map[string]string
			if err := json.NewDecoder(r.Body).Decode(&fields); err != nil || len(fields) != 2 || fields["device_name"] != "Subscription Composer" || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(fields["device_id"]) {
				t.Error("incorrect device request")
			}
			initial, err := store.Load("source_1")
			if err != nil || initial.AppToken != "old-secret" || initial.DeviceID != fields["device_id"] {
				t.Errorf("initial credential not durable before refresh: %v", err)
			}
			fmt.Fprint(w, tokenResponse("new-secret"))
		default:
			t.Error("unexpected endpoint")
		}
	}))
	defer server.Close()
	client := &Client{Store: store}
	imported, err := client.Import(context.Background(), "source_1", clientSession(server.URL+"/api/v2/", "old-secret"))
	if err != nil || imported.AppToken != "new-secret" || imported.TokenType != "Bearer" {
		t.Fatalf("import: %v, %+v", err, imported)
	}
	stored, err := store.Load("source_1")
	if err != nil || stored != imported {
		t.Fatalf("rotation not durable: %v, %+v", err, stored)
	}
}

func TestFetchConcurrentRefreshAndRestart(t *testing.T) {
	store := clientStore(t)
	var refreshes atomic.Int32
	var profiles atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/client-auth/refresh-app-token":
			refreshes.Add(1)
			if r.Header.Get("Authorization") != "Bearer old-secret" {
				t.Error("refresh used stale or invalid token")
			}
			fmt.Fprint(w, tokenResponse("new-secret"))
		case "/api/v2/nodes/profile":
			profiles.Add(1)
			if r.Header.Get("Authorization") != "Bearer new-secret" {
				t.Error("profile did not use rotated token")
			}
			fmt.Fprint(w, responseEnvelope(`{"user_id":"user","profile":"proxies:\n  - name: demo\n"}`))
		default:
			t.Error("unexpected endpoint")
		}
	}))
	defer server.Close()
	session := clientSession(server.URL+"/api/v2", "old-secret")
	session.ExpiresAt = time.Now().Add(time.Hour).Unix()
	if err := store.Save("source_1", session); err != nil {
		t.Fatal(err)
	}
	client := &Client{Store: store}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := client.Fetch(context.Background(), "source_1", server.URL+"/api/v2/")
			if err != nil || string(data) != "proxies:\n  - name: demo\n" {
				t.Errorf("fetch: %v, %q", err, data)
			}
		}()
	}
	wg.Wait()
	if refreshes.Load() != 1 || profiles.Load() != 2 {
		t.Fatalf("unexpected request counts: refresh=%d profile=%d", refreshes.Load(), profiles.Load())
	}
	restarted := &Client{Store: store}
	if _, err := restarted.Fetch(context.Background(), "source_1", server.URL+"/api/v2"); err != nil || refreshes.Load() != 1 {
		t.Fatalf("restart lost credential: %v", err)
	}
}

func TestFetchProfile401RotatesOnceAndPersistsOnFailure(t *testing.T) {
	store := clientStore(t)
	var refreshes atomic.Int32
	var profiles atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/nodes/profile":
			profiles.Add(1)
			if r.Header.Get("Authorization") == "Bearer old-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"success":false,"code":"TOKEN_INVALID","msg":"server-private-secret"}`)
				return
			}
			stored, err := store.Load("source_1")
			if err != nil || stored.AppToken != "new-secret" {
				t.Error("profile reached before rotated token was saved")
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"success":false,"code":"PRIVATE_MESSAGE","msg":"server-private-secret"}`)
		case "/api/v2/client-auth/refresh-app-token":
			refreshes.Add(1)
			if r.Header.Get("Authorization") != "Bearer old-secret" {
				t.Error("unexpected refresh bearer")
			}
			fmt.Fprint(w, tokenResponse("new-secret"))
		default:
			t.Error("unexpected endpoint")
		}
	}))
	defer server.Close()
	initial := clientSession(server.URL+"/api/v2", "old-secret")
	initial.DeviceID, initial.DeviceName = "persistent-id", "Persistent name"
	if err := store.Save("source_1", initial); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{Store: store}).Fetch(context.Background(), "source_1", server.URL+"/api/v2")
	if err == nil || strings.Contains(err.Error(), "server-private-secret") || strings.Contains(err.Error(), "PRIVATE_MESSAGE") || refreshes.Load() != 1 || profiles.Load() != 2 {
		t.Fatalf("failed profile behavior: %v; requests %d/%d", err, refreshes.Load(), profiles.Load())
	}
	stored, err := store.Load("source_1")
	if err != nil || stored.AppToken != "new-secret" || stored.DeviceID != initial.DeviceID || stored.DeviceName != initial.DeviceName {
		t.Fatalf("rotation lost after profile error: %v, %+v", err, stored)
	}
}

func TestFetchRejectsWrongBaseAndMissingSession(t *testing.T) {
	store := clientStore(t)
	client := &Client{Store: store}
	if _, err := client.Fetch(context.Background(), "source_1", "https://example.org/api/v2"); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("missing session: %v", err)
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer server.Close()
	if err := store.Save("source_1", clientSession(server.URL+"/api/v2", "secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Fetch(context.Background(), "source_1", server.URL+"/other"); err == nil || received.Load() != 0 {
		t.Fatalf("wrong base sent credential: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Fetch(ctx, "source_1", server.URL+"/api/v2"); !errors.Is(err, context.Canceled) || received.Load() != 0 {
		t.Fatalf("canceled fetch reached network: %v", err)
	}
}

func TestRefreshFailureKeepsLastKnownToken(t *testing.T) {
	store := clientStore(t)
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/client-auth/refresh-app-token" {
			t.Error("unexpected endpoint")
		}
		refreshes.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"code":"TOKEN_INVALID","msg":"private"}`)
	}))
	defer server.Close()
	session := clientSession(server.URL+"/api/v2", "old-secret")
	session.ExpiresAt = time.Now().Add(time.Hour).Unix()
	if err := store.Save("source_1", session); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{Store: store}).Fetch(context.Background(), "source_1", server.URL+"/api/v2")
	if !errors.Is(err, ErrLoginRequired) || refreshes.Load() != 1 {
		t.Fatalf("invalid refresh: %v", err)
	}
	stored, err := store.Load("source_1")
	if err != nil || stored.AppToken != "old-secret" || stored.DeviceID == "" {
		t.Fatalf("last known token or identity lost: %v, %+v", err, stored)
	}
}

func TestImportPreservesDeviceAndDoesNotRetryAmbiguousPOST(t *testing.T) {
	store := clientStore(t)
	var posts atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/client-auth/token-info" {
			fmt.Fprint(w, tokenResponse("old-secret"))
			return
		}
		posts.Add(1)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"device_id":"provided-id","device_name":"Provided name"}` {
			t.Errorf("device was changed: %s", body)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"success":false,"code":"PRIVATE_MESSAGE","msg":"hidden-secret"}`)
	}))
	defer server.Close()
	session := clientSession(server.URL+"/api/v2", "old-secret")
	session.DeviceID, session.DeviceName = "provided-id", "Provided name"
	_, err := (&Client{Store: store}).Import(context.Background(), "source_1", session)
	if err == nil || strings.Contains(err.Error(), "hidden-secret") || posts.Load() != 1 {
		t.Fatalf("failed import: %v", err)
	}
	stored, err := store.Load("source_1")
	if err != nil || stored.DeviceID != "provided-id" || stored.AppToken != "old-secret" {
		t.Fatalf("initial credential lost: %v, %+v", err, stored)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	store := clientStore(t)
	var received atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer dest.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	session := clientSession(server.URL+"/api/v2", "secret")
	if err := store.Save("source_1", session); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{Store: store, HTTPClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}}).Fetch(context.Background(), "source_1", server.URL+"/api/v2")
	if err == nil || received.Load() != 0 {
		t.Fatalf("redirect followed: %v", err)
	}
}
func TestAmbiguousRefreshTransportFailure(t *testing.T) {
	store := clientStore(t)
	session := clientSession("https://example.org/api/v2", "old-secret")
	session.DeviceID, session.DeviceName = "persistent-id", "Persistent name"
	session.ExpiresAt = time.Now().Add(time.Hour).Unix()
	if err := store.Save("source_1", session); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	client := &Client{Store: store, HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Error("unexpected request")
		}
		posts.Add(1)
		return nil, errors.New("server rotated token secret-in-transport")
	})}}
	_, err := client.Fetch(context.Background(), "source_1", session.APIBaseURL)
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") || strings.Contains(err.Error(), "secret-in-transport") || posts.Load() != 1 {
		t.Fatalf("ambiguous refresh: %v, requests=%d", err, posts.Load())
	}
	stored, err := store.Load("source_1")
	if err != nil || stored != session {
		t.Fatalf("last known credential lost: %v, %+v", err, stored)
	}
}

func TestProfileResponseBoundAndNoSecretInErrors(t *testing.T) {
	store := clientStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("s", maxClientResponseBytes+1))
	}))
	defer server.Close()
	if err := store.Save("source_1", clientSession(server.URL+"/api/v2", "secret")); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{Store: store}).Fetch(context.Background(), "source_1", server.URL+"/api/v2")
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("large response accepted or leaked: %v", err)
	}
}

func TestImportRejectsRevokedTokenWithoutSaving(t *testing.T) {
	store := clientStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"code":"TOKEN_INVALID","msg":"private-secret"}`)
	}))
	defer server.Close()
	_, err := (&Client{Store: store}).Import(context.Background(), "source_1", clientSession(server.URL+"/api/v2", "old-secret"))
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("revoked token: %v", err)
	}
	if _, err := store.Load("source_1"); !errors.Is(err, authstate.ErrNotFound) {
		t.Fatalf("revoked credential was saved: %v", err)
	}
}

func TestProfile401AfterRefreshRequiresLoginWithoutLoop(t *testing.T) {
	store := clientStore(t)
	var refreshes atomic.Int32
	var profiles atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/client-auth/refresh-app-token" {
			refreshes.Add(1)
			fmt.Fprint(w, tokenResponse("new-secret"))
			return
		}
		profiles.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"code":"TOKEN_INVALID","msg":"private-secret"}`)
	}))
	defer server.Close()
	session := clientSession(server.URL+"/api/v2", "old-secret")
	session.DeviceID, session.DeviceName = "persistent-id", "Persistent name"
	if err := store.Save("source_1", session); err != nil {
		t.Fatal(err)
	}
	_, err := (&Client{Store: store}).Fetch(context.Background(), "source_1", session.APIBaseURL)
	if !errors.Is(err, ErrLoginRequired) || refreshes.Load() != 1 || profiles.Load() != 2 {
		t.Fatalf("401 retry behavior: %v; refresh=%d profile=%d", err, refreshes.Load(), profiles.Load())
	}
	stored, err := store.Load("source_1")
	if err != nil || stored.AppToken != "new-secret" {
		t.Fatalf("rotated credential missing: %v, %+v", err, stored)
	}
}
