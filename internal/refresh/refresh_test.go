package refresh

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
)

const linkA = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=none#US-node"
const linkB = "vless://12345678-1234-1234-1234-123456789abc@example.net:443?security=none#US-node"

func testConfig(dir string, sources ...model.Source) model.Config {
	return model.Config{SnapshotDir: dir, Debounce: "1h", RefreshTimeout: "3s", Sources: sources,
		Devices: []model.Device{
			{ID: "first", Base: json.RawMessage(`{"outbounds":[{"tag":"direct","type":"direct"}]}`)},
			{ID: "second", Base: json.RawMessage(`{"outbounds":[{"tag":"direct","type":"direct"}]}`)},
		},
	}
}

func newManager(t *testing.T, cfg model.Config) *Manager {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func refreshOK(t *testing.T, m *Manager, force bool) {
	t.Helper()
	if err := m.Refresh(context.Background(), force); err != nil {
		t.Fatal(err)
	}
}

func TestCoalescingCancellationAndDebounce(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			close(started)
			<-release
		}
		_, _ = w.Write([]byte(linkA))
	}))
	defer srv.Close()
	m := newManager(t, testConfig(t.TempDir(), model.Source{ID: "a", URL: srv.URL}))
	caller, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- m.Refresh(caller, false) }()
	<-started
	cancel()
	if err := <-first; err != context.Canceled {
		t.Fatalf("first caller: %v", err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(release)
	}()
	if err := m.Refresh(context.Background(), true); err != nil {
		t.Fatalf("shared refresh: %v", err)
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("expected one fetch, got %d", got)
	}
	refreshOK(t, m, false)
	if got := count.Load(); got != 1 {
		t.Fatalf("debounced request fetched again: %d", got)
	}
	refreshOK(t, m, true)
	if got := count.Load(); got != 2 {
		t.Fatalf("forced request did not fetch: %d", got)
	}
}

func TestValidatorsFallbackAndTimestamps(t *testing.T) {
	var mode atomic.Int32
	var conditional atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("auth header missing")
		}
		if r.Header.Get("If-None-Match") == `"a"` && r.Header.Get("If-Modified-Since") == "Mon, 02 Jan 2006 15:04:05 GMT" {
			conditional.Store(true)
		}
		switch mode.Load() {
		case 1:
			w.WriteHeader(http.StatusNotModified)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.Header().Set("ETag", `"a"`)
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
			_, _ = w.Write([]byte(linkA))
		}
	}))
	defer srv.Close()
	m := newManager(t, testConfig(t.TempDir(), model.Source{ID: "a", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer secret"}}))
	refreshOK(t, m, false)
	initial := m.Status()
	profile, _ := m.Profile("first")
	time.Sleep(time.Millisecond)
	mode.Store(1)
	refreshOK(t, m, true)
	second := m.Status()
	if !conditional.Load() || second.Sources[0].ChangedAt != initial.Sources[0].ChangedAt || second.Sources[0].SucceededAt == initial.Sources[0].SucceededAt || second.PublishedAt != initial.PublishedAt || second.Revision != initial.Revision {
		t.Fatalf("304 changed revision or content timestamp: %+v -> %+v", initial, second)
	}
	time.Sleep(time.Millisecond)
	mode.Store(2)
	refreshOK(t, m, true)
	failed := m.Status()
	if !failed.Sources[0].Stale || failed.Sources[0].Error == "" || failed.Sources[0].SucceededAt != second.Sources[0].SucceededAt || failed.Sources[0].CheckedAt == second.Sources[0].CheckedAt || failed.LastError != "" {
		t.Fatalf("fallback not visible: %+v", failed)
	}
	p, _ := m.Profile("first")
	if !bytes.Equal(p, profile) {
		t.Fatal("fallback changed published profile")
	}
	p[0] ^= 0xff
	p2, _ := m.Profile("first")
	if !bytes.Equal(p2, profile) {
		t.Fatal("profile was returned by reference")
	}
}

func TestInitialMissingSourceNeverPublishes(t *testing.T) {
	good := filepath.Join(t.TempDir(), "good.txt")
	if err := os.WriteFile(good, []byte(linkA), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t.TempDir(), model.Source{ID: "good", File: good}, model.Source{ID: "missing", File: filepath.Join(t.TempDir(), "absent")})
	m := newManager(t, cfg)
	if err := m.Refresh(context.Background(), false); err == nil {
		t.Fatal("missing source was silently omitted")
	}
	if _, ok := m.Profile("first"); ok {
		t.Fatal("partial generation published")
	}
	if !m.Status().Sources[1].Stale {
		t.Fatal("missing source status not stale")
	}
}

func TestRestartBindingAndOfflineProfiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "nodes.txt")
	if err := os.WriteFile(file, []byte(linkA), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(dir, model.Source{ID: "provider", File: file})
	m := newManager(t, cfg)
	refreshOK(t, m, false)
	old, _ := m.Profile("first")
	original := m.Status()
	info, err := os.Stat(filepath.Join(dir, snapshotFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: %v %v", info, err)
	}
	info, _ = os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("directory permissions are not private")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	cfg.Devices = cfg.Devices[:1]
	restarted := newManager(t, cfg)
	if p, ok := restarted.Profile("first"); !ok || !bytes.Equal(p, old) {
		t.Fatal("offline profile was not restored")
	}
	if _, ok := restarted.Profile("second"); ok {
		t.Fatal("removed device was exposed")
	}
	refreshOK(t, restarted, false) // Debounce must not persist across restarts.
	if !restarted.Status().Sources[0].Stale || restarted.Status().Revision == original.Revision {
		t.Fatal("fallback or current device list was not applied")
	}
	other := filepath.Join(t.TempDir(), "other.txt")
	changed := cfg
	changed.Sources = []model.Source{{ID: "provider", File: other}}
	bound := newManager(t, changed)
	if err := bound.Refresh(context.Background(), false); err == nil {
		t.Fatal("cache from old file used for changed source")
	}
	if bound.Status().Sources[0].SucceededAt != "" {
		t.Fatal("changed source inherited success")
	}
}

func TestAtomicGenerationAndRecovery(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.txt")
	if err := os.WriteFile(file, []byte(linkA), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t.TempDir(), model.Source{ID: "a", File: file})
	m := newManager(t, cfg)
	refreshOK(t, m, false)
	old, _ := m.Profile("first")
	previous := m.Status()
	// A valid first device and invalid second device must not publish either.
	m.cfg.Devices[1].Base = json.RawMessage(`{"outbounds":[{"tag":"main","type":"direct"}]}`)
	if err := os.WriteFile(file, []byte(linkB), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background(), true); err == nil {
		t.Fatal("expected second device build failure")
	}
	current, _ := m.Profile("first")
	if !bytes.Equal(old, current) || m.Status().Revision != previous.Revision || m.Status().LastError == "" {
		t.Fatal("failed generation modified published state")
	}
	restored := newManager(t, cfg)
	p, _ := restored.Profile("first")
	if !bytes.Equal(old, p) {
		t.Fatal("failed generation persisted")
	}
	m.cfg.Devices[1].Base = cfg.Devices[1].Base
	refreshOK(t, m, true)
	if m.Status().Revision == previous.Revision || m.Status().Sources[0].ChangedAt == previous.Sources[0].ChangedAt {
		t.Fatal("updated source did not publish")
	}
}

func TestNoSecretInError(t *testing.T) {
	secret := "secret-password-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(secret))
	}))
	defer srv.Close()
	cfg := testConfig(t.TempDir(), model.Source{ID: "provider", URL: srv.URL + "/" + secret, Headers: map[string]string{"Authorization": secret}})
	m := newManager(t, cfg)
	err := m.Refresh(context.Background(), false)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(m.Status().Sources[0].Error, secret) {
		t.Fatal("source error exposed credentials")
	}
}

func TestParallelBoundedFetch(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if n <= old || maxInFlight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		_, _ = w.Write([]byte(linkA))
	}))
	defer srv.Close()
	var sources []model.Source
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		sources = append(sources, model.Source{ID: id, URL: srv.URL})
	}
	m := newManager(t, testConfig(t.TempDir(), sources...))
	refreshOK(t, m, false)
	if got := maxInFlight.Load(); got <= 1 || got > 4 {
		t.Fatalf("parallelism outside 2..4: %d", got)
	}
}

func TestConcurrentStatusCopies(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.txt")
	if err := os.WriteFile(file, []byte(linkA), 0600); err != nil {
		t.Fatal(err)
	}
	m := newManager(t, testConfig(t.TempDir(), model.Source{ID: "a", File: file}))
	refreshOK(t, m, false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Status().Sources[0].Error = "modified"
			m.Profile("first")
		}()
	}
	wg.Wait()
	if m.Status().Sources[0].Error != "" {
		t.Fatal("status slice returned by reference")
	}
}

func TestIndependentFallbackAndNativeCheck(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.txt")
	b := filepath.Join(t.TempDir(), "b.txt")
	if err := os.WriteFile(a, []byte(linkA), 0600); err != nil {
		t.Fatal(err)
	}
	secondLink := strings.Replace(linkA, "US-node", "JP-node", 1)
	if err := os.WriteFile(b, []byte(secondLink), 0600); err != nil {
		t.Fatal(err)
	}
	m := newManager(t, testConfig(t.TempDir(), model.Source{ID: "a", File: a}, model.Source{ID: "b", File: b}))
	refreshOK(t, m, false)
	prior := m.Status()
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(strings.Replace(secondLink, "example.com", "example.net", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	refreshOK(t, m, true)
	current := m.Status()
	if !current.Sources[0].Stale || current.Sources[1].Stale || current.Sources[0].ChangedAt != prior.Sources[0].ChangedAt || current.Revision == prior.Revision {
		t.Fatal("sources were not updated independently")
	}
	profile, _ := m.Profile("first")
	m.cfg.CheckBinary = filepath.Join(t.TempDir(), "missing-binary")
	if err := m.Refresh(context.Background(), true); err == nil {
		t.Fatal("expected native check failure")
	}
	after, _ := m.Profile("first")
	if !bytes.Equal(profile, after) || m.Status().Revision != current.Revision {
		t.Fatal("native check failure published an incomplete generation")
	}
}

func TestRejectInvalidSnapshotAndOversizeSource(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.txt")
	if err := os.WriteFile(file, bytes.Repeat([]byte("x"), maxSourceBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t.TempDir(), model.Source{ID: "a", File: file})
	m := newManager(t, cfg)
	if err := m.Refresh(context.Background(), false); err == nil {
		t.Fatal("oversized source was accepted")
	}
	if err := os.WriteFile(filepath.Join(cfg.SnapshotDir, snapshotFile), []byte(`{"version":1,"sources":null,"profiles":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid snapshot was accepted")
	}
}
