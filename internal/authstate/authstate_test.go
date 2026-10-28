package authstate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validSession() Session {
	return Session{AppToken: "secret-app-token", APIBaseURL: "https://example.com/api/v2", ExpiresAt: 0}
}

func TestRoundTripAndRotation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "auth")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory permissions: %v, %v", info, err)
	}
	if _, err := store.Load("airport"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session: %v", err)
	}
	if err := store.Save("airport", validSession()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "airport.json")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions: %v, %v", info, err)
	}
	loaded, err := store.Load("airport")
	if err != nil || loaded.TokenType != "Bearer" || loaded.AppToken != validSession().AppToken {
		t.Fatalf("saved session mismatch: %v", err)
	}
	rotated := validSession()
	rotated.AppToken = "rotated-token"
	rotated.ExpiresAt = 123456789
	if err := store.Save("airport", rotated); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = reopened.Load("airport")
	if err != nil || loaded.AppToken != rotated.AppToken || loaded.ExpiresAt != rotated.ExpiresAt {
		t.Fatalf("rotated session mismatch: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("credential directory entries: %v, %v", entries, err)
	}
}

func TestRejectUnsafePathsAndSymlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "auth")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"", "../other", "a/b", ".hidden", "a.b", strings.Repeat("a", 65)} {
		if err := store.Save(account, validSession()); err == nil {
			t.Errorf("accepted account %q", account)
		}
		if _, err := store.Load(account); err == nil {
			t.Errorf("loaded account %q", account)
		}
		if err := store.WithLock(context.Background(), account, func() error { return nil }); err == nil {
			t.Errorf("locked account %q", account)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".json", ".lock"} {
		path := filepath.Join(root, "airport"+suffix)
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		if suffix == ".json" {
			if _, err := store.Load("airport"); err == nil || errors.Is(err, ErrNotFound) {
				t.Fatalf("symlink read: %v", err)
			}
			if err := store.Save("airport", validSession()); err == nil {
				t.Fatal("saved over symlink")
			}
		} else if err := store.WithLock(context.Background(), "airport", func() error { return nil }); err == nil {
			t.Fatal("opened symlink lock")
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "untouched" {
		t.Fatalf("changed symlink target: %q, %v", data, err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(root, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := New(linked); err == nil {
		t.Fatal("accepted symlink root")
	}
	if err := os.Rename(root, root+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root+"-moved", root); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("airport"); err == nil {
		t.Fatal("accepted replaced symlink root")
	}
}

func TestMalformedAndSecretErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "auth")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "airport.json")
	secret := "sensitive-token"
	for _, data := range []string{
		`{"app_token":"sensitive-token","api_base_url":"https://example.com/api/v2","expires_at":0} true`,
		`{"app_token":"sensitive-token","api_base_url":"https://example.com/api/v2","expires_at":0,"unexpected":1}`,
		`{"app_token":"sensitive-token","api_base_url":"https://example.com/api/v2","expires_at":-1}`,
		`{"app_token":"sensitive-token","api_base_url":"https://example.com/api/v2","expires_at":0,"token_type":"Bad\nType"}`,
		strings.Repeat(" ", maxSessionBytes+1),
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := store.Load("airport")
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "example.com") {
			t.Fatalf("unsafe load error: %v", err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("airport"); err == nil {
		t.Fatal("accepted readable-by-others session")
	}

	invalid := validSession()
	invalid.AppToken = secret
	invalid.APIBaseURL = "https://user:password@example.com/api/v2?secret=sensitive-token"
	if err := store.Save("airport", invalid); err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "example.com") {
		t.Fatalf("unsafe save error: %v", err)
	}
}

func TestSessionValidation(t *testing.T) {
	for _, bad := range []Session{
		{APIBaseURL: "https://example.com/api/v2"},
		{AppToken: "token\r\n", APIBaseURL: "https://example.com/api/v2"},
		{AppToken: "token", APIBaseURL: "http://example.com"},
		{AppToken: "token", APIBaseURL: "ftp://example.com/api/v2"},
		{AppToken: "token", APIBaseURL: "https://example.com/api/v2#"},
		{AppToken: "token", APIBaseURL: "https://example.com/api/v2?"},
		{AppToken: "token", APIBaseURL: "https://example.com/api/v2", ExpiresAt: -1},
	} {
		if err := bad.Validate(); err == nil {
			t.Error("accepted invalid session")
		}
	}
	local := validSession()
	local.APIBaseURL = "http://127.0.0.1:8080/custom/api"
	if err := local.Validate(); err != nil {
		t.Fatalf("rejected loopback HTTP: %v", err)
	}
}

// This test runs only as a child process, holding the lock until stdin closes.
func TestLockHelper(t *testing.T) {
	root := os.Getenv("AUTHSTATE_LOCK_TEST_ROOT")
	if root == "" {
		return
	}
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WithLock(context.Background(), "airport", func() error {
		if _, err := os.Stdout.WriteString("ready\n"); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, os.Stdin)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCrossProcessLockAndCancellation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "auth")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelper$")
	cmd.Env = append(os.Environ(), "AUTHSTATE_LOCK_TEST_ROOT="+root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("lock helper: %v: %s", err, stderr.String())
		}
	}()
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("lock helper did not acquire lock: %q, %v: %s", ready, err, stderr.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	called := false
	err = store.WithLock(ctx, "airport", func() error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("lock was not held across processes: called=%v, err=%v", called, err)
	}
	if err := store.WithLock(context.Background(), "other", func() error { return nil }); err != nil {
		t.Fatalf("independent account lock: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	acquireCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := store.WithLock(acquireCtx, "airport", func() error {
		return store.Save("airport", validSession())
	}); err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
}
