package clientupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const localConfig = `{"log":{"level":"info"},"services":[{"type":"api","tag":"remote-api","listen":"127.0.0.1","listen_port":9090,"secret":"private-api-secret"}]}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) *Client {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	stateDir := filepath.Join(root, "state")
	for _, dir := range []string{configDir, stateDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		SubscriptionURL: "https://example.test/profile?token=private-url-secret", Username: "linux",
		TokenFile: filepath.Join(root, "token"), ConfigDir: configDir, StateDir: stateDir,
		LocalFile: filepath.Join(configDir, "10-local.json"), SubscriptionFile: filepath.Join(configDir, "20-subscription.json"),
		WorkDir: filepath.Join(root, "work"), SingBoxBinary: "/usr/bin/sing-box", RCServiceBinary: "/sbin/rc-service",
		ServiceName: "sing-box", HealthAddress: "127.0.0.1:9090",
	}
	writeFile(t, cfg.TokenFile, "private-subscription-token\n")
	writeFile(t, cfg.LocalFile, localConfig)
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.run = func(context.Context, string, ...string) error { return nil }
	client.probe = func(context.Context, string) error { return nil }
	client.healthInterval = time.Millisecond
	client.healthTimeout = 100 * time.Millisecond
	return client
}

func stateOf(t *testing.T, c *Client) State {
	t.Helper()
	state, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func backupPath(t *testing.T, c *Client, name string) string {
	t.Helper()
	state := stateOf(t, c)
	dir, err := c.backupDir(&state)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func TestPairDigest(t *testing.T) {
	a := []byte(`{"number":9007199254740993,"items":["a","b"],"services":[{"type":"other","tag":"other"}]}`)
	b := []byte(`{ "services": [{"tag":"other","type":"other"}], "items":["a","b"], "number":9007199254740993 }`)
	first, err := pairDigest([]byte(localConfig), a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pairDigest([]byte(localConfig), b)
	if err != nil || first != second {
		t.Fatalf("object order or whitespace changed digest: %v", err)
	}
	for _, changed := range []string{
		strings.Replace(string(a), "9007199254740993", "9007199254740992", 1),
		strings.Replace(string(a), `["a","b"]`, `["b","a"]`, 1),
	} {
		next, err := pairDigest([]byte(localConfig), []byte(changed))
		if err != nil || next == first {
			t.Fatalf("meaningful change was lost: %v", err)
		}
	}
	changedLocal := strings.Replace(localConfig, "private-api-secret", "new-secret", 1)
	next, err := pairDigest([]byte(changedLocal), a)
	if err != nil || next == first {
		t.Fatalf("local change was lost: %v", err)
	}
	for _, invalid := range []string{
		`{"services":[{"type":"api","tag":"other"}]}`,
		`{"services":[{"type":"other","tag":"remote-api"}]}`,
		`{"services":[{"type":"other","tag":"x"},{"type":"other","tag":"x"}]}`,
		`{"services":null}`, `[]`, `{} {}`, `{"services":[null]}`,
	} {
		if _, err := pairDigest([]byte(localConfig), []byte(invalid)); err == nil {
			t.Fatalf("accepted invalid subscription: %s", invalid)
		}
	}
	for _, invalid := range []string{`{}`, `{"services":[]}`, `{"services":[{"type":"api"}]}`, strings.Replace(localConfig, `"log":`, `"route":`, 1)} {
		if _, err := pairDigest([]byte(invalid), a); err == nil {
			t.Fatal("accepted invalid local configuration")
		}
	}
}

func TestConfigValidation(t *testing.T) {
	c := fixture(t)
	for name, change := range map[string]func(*Config){
		"plaintext remote": func(c *Config) { c.SubscriptionURL = "http://example.test/profile" },
		"URL credentials":  func(c *Config) { c.SubscriptionURL = "https://linux@example.test/profile" },
		"relative path":    func(c *Config) { c.TokenFile = "token" },
		"same file":        func(c *Config) { c.SubscriptionFile = c.LocalFile },
		"nested file":      func(c *Config) { c.LocalFile = filepath.Join(c.ConfigDir, "nested", "local.json") },
		"state in config":  func(c *Config) { c.StateDir = filepath.Join(c.ConfigDir, "state") },
		"non-json input":   func(c *Config) { c.LocalFile += ".example" },
		"invalid health":   func(c *Config) { c.HealthAddress = "http://127.0.0.1:9090/" },
		"wildcard IPv4":    func(c *Config) { c.HealthAddress = "0.0.0.0:9090" },
		"wildcard IPv6":    func(c *Config) { c.HealthAddress = "[::]:9090" },
		"service option":   func(c *Config) { c.ServiceName = "--help" },
		"input order":      func(c *Config) { c.LocalFile = filepath.Join(c.ConfigDir, "99-local.json") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := c.cfg
			change(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	cfg := c.cfg
	cfg.SubscriptionURL = "http://[::1]:8080/profile"
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	writeFile(t, path, string(data))
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted public config file")
	}
	writeFile(t, path, strings.TrimSuffix(string(data), "}")+`,"unknown":true}`)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("accepted unknown config field")
	}
}

func TestFetchAuthenticationAndNativeInputs(t *testing.T) {
	c := fixture(t)
	body := `{"outbounds":[],"services":[{"type":"other","tag":"subscription-service"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, secret, ok := r.BasicAuth()
		if !ok || user != "linux" || secret != "private-subscription-token" {
			t.Error("incorrect Basic authentication")
		}
		io.WriteString(w, body)
	}))
	defer server.Close()
	c.cfg.SubscriptionURL = server.URL
	checks := 0
	c.run = func(_ context.Context, binary string, args ...string) error {
		checks++
		if binary != c.cfg.SingBoxBinary || len(args) != 7 || !reflect.DeepEqual(args[:6], []string{"check", "-D", c.cfg.WorkDir, "-c", c.cfg.LocalFile, "-c"}) {
			t.Fatalf("unexpected validation command: %s %v", binary, args)
		}
		data, err := os.ReadFile(args[6])
		if err != nil || string(data) != body {
			t.Fatal("native validation did not receive the subscription")
		}
		return nil
	}
	if err := c.Fetch(context.Background(), time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if checks != 1 {
		t.Fatal("expected one native check and no restart")
	}
	data, err := os.ReadFile(c.path("candidate.json"))
	if err != nil || string(data) != body {
		t.Fatal("candidate not saved")
	}
	if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fetch changed deployed subscription")
	}
	if state := stateOf(t, c); state.Phase != "pending" || state.CandidateDigest == "" || state.AppliedDigest != "" {
		t.Fatalf("incorrect state: %+v", state)
	}
	for _, path := range []string{c.path("candidate.json"), c.path("status.json")} {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("state file is not private")
		}
	}
}

func TestFetchRejectsFailuresWithoutReplacingCandidate(t *testing.T) {
	for _, test := range []string{"redirect", "large declared", "large streamed", "invalid JSON", "native failure", "timeout", "extra config"} {
		t.Run(test, func(t *testing.T) {
			c := fixture(t)
			writeFile(t, c.path("candidate.json"), `{"old":true}`)
			followed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/secret-target" {
					followed = true
				}
				switch test {
				case "redirect":
					http.Redirect(w, r, "/secret-target", http.StatusFound)
				case "large declared":
					w.Header().Set("Content-Length", "16777217")
					w.WriteHeader(http.StatusOK)
				case "large streamed":
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					_, _ = io.Copy(w, io.LimitReader(zeroReader{}, maxSubscriptionSize+1))
				case "invalid JSON":
					io.WriteString(w, "invalid private-response-secret")
				default:
					io.WriteString(w, `{}`)
				}
			}))
			defer server.Close()
			c.cfg.SubscriptionURL = server.URL + "?secret=private-url-secret"
			if test == "native failure" {
				c.run = func(context.Context, string, ...string) error { return errors.New("private-native-secret") }
			}
			if test == "extra config" {
				writeFile(t, filepath.Join(c.cfg.ConfigDir, "unexpected.json"), `{}`)
			}
			ctx := context.Background()
			if test == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := c.Fetch(ctx, 0)
			if err == nil {
				t.Fatal("expected fetch failure")
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("error leaked secret")
			}
			if followed {
				t.Fatal("followed an authenticated redirect")
			}
			data, _ := os.ReadFile(c.path("candidate.json"))
			if string(data) != `{"old":true}` {
				t.Fatal("failed fetch replaced candidate")
			}
			state := stateOf(t, c)
			if state.Phase != "failed" || strings.Contains(state.LastError, "private-") {
				t.Fatalf("bad failure status: %+v", state)
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestApplyNoChangeAndDiskDrift(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.path("candidate.json"), `{"n":9007199254740993,"items":[1,2]}`)
	restarts := 0
	c.run = func(_ context.Context, binary string, args ...string) error {
		if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
			restarts++
		}
		return nil
	}
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := stateOf(t, c)
	if first.Transaction || first.Phase != "applied" || first.AppliedDigest == "" || first.PreviousPresent {
		t.Fatalf("bad first apply: %+v", first)
	}
	writeFile(t, c.path("candidate.json"), `{ "items": [1, 2], "n": 9007199254740993 }`)
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 {
		t.Fatal("no-change apply restarted service")
	}
	// A matching stored digest must not mask a modified deployed file.
	writeFile(t, c.cfg.SubscriptionFile, `{"drift":true}`)
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarts != 2 {
		t.Fatal("disk drift was ignored")
	}
	previous, _ := os.ReadFile(backupPath(t, c, "previous.json"))
	if string(previous) != `{"drift":true}` {
		t.Fatal("incorrect restore point")
	}
	writeFile(t, c.cfg.LocalFile, strings.Replace(localConfig, "info", "warn", 1))
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarts != 3 || stateOf(t, c).AppliedDigest == first.AppliedDigest {
		t.Fatal("local change was ignored")
	}
}

func TestApplyFailureRestoresPrevious(t *testing.T) {
	for _, prior := range []bool{false, true} {
		for _, healthFailure := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "initial", true: "existing"}[prior], map[bool]string{false: "restart", true: "health"}[healthFailure]}, "/"), func(t *testing.T) {
				c := fixture(t)
				if prior {
					writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
				}
				writeFile(t, c.path("candidate.json"), `{"new":true}`)
				restarts := 0
				c.run = func(_ context.Context, binary string, args ...string) error {
					if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
						restarts++
						if restarts == 1 && !healthFailure {
							return errors.New("private-restart-secret")
						}
					}
					return nil
				}
				c.probe = func(context.Context, string) error {
					if restarts == 1 && healthFailure {
						return errors.New("listener unavailable")
					}
					return nil
				}
				err := c.Apply(context.Background())
				if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
					t.Fatalf("unexpected outcome: %v", err)
				}
				if restarts != 2 {
					t.Fatalf("expected application and recovery restarts, got %d", restarts)
				}
				data, readErr := os.ReadFile(c.cfg.SubscriptionFile)
				if prior && (readErr != nil || string(data) != `{"old":true}`) {
					t.Fatal("previous subscription not restored")
				}
				if !prior && !errors.Is(readErr, os.ErrNotExist) {
					t.Fatal("initial apply did not restore API-only deployment")
				}
				state := stateOf(t, c)
				if state.Transaction || state.Phase != "failed" || strings.Contains(state.LastError, "private-") {
					t.Fatalf("incorrect recovery state: %+v", state)
				}
				if prior {
					saved, _ := os.ReadFile(backupPath(t, c, "previous.json"))
					if string(saved) != `{"old":true}` || state.AppliedDigest == "" {
						t.Fatal("restore point not retained")
					}
				} else if state.AppliedDigest != "" {
					t.Fatal("claimed an applied subscription after initial failure")
				}
			})
		}
	}
}

func TestFailedRollbackBlocksUpdatesUntilRecovery(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
	writeFile(t, c.path("candidate.json"), `{"new":true}`)
	c.run = func(_ context.Context, binary string, args ...string) error {
		if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
			return errors.New("failed")
		}
		return nil
	}
	if err := c.Apply(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	state := stateOf(t, c)
	if !state.Transaction || state.Phase != "failed" {
		t.Fatalf("lost recovery transaction: %+v", state)
	}
	for _, action := range []func() error{
		func() error { return c.Apply(context.Background()) },
		func() error { return c.Fetch(context.Background(), 0) },
	} {
		if err := action(); err == nil || !strings.Contains(err.Error(), "unfinished application") {
			t.Fatalf("update allowed during recovery: %v", err)
		}
	}
	c.run = func(context.Context, string, ...string) error { return nil }
	if err := c.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	state = stateOf(t, c)
	if state.Transaction || state.Phase != "applied" || state.AppliedDigest == "" {
		t.Fatalf("rollback not confirmed: %+v", state)
	}
}

func TestInterruptedTransactionRecovery(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		c := fixture(t)
		writeFile(t, c.path("previous.json"), `{"old":true}`)
		writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
		if replaced {
			writeFile(t, c.cfg.SubscriptionFile, `{"new":true}`)
		}
		state := State{Phase: "applying", Transaction: true, RestoreAvailable: true, PreviousPresent: true}
		if err := c.save(&state); err != nil {
			t.Fatal(err)
		}
		if err := c.Apply(context.Background()); err == nil {
			t.Fatal("accepted interrupted application")
		}
		if err := c.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(c.cfg.SubscriptionFile)
		if string(data) != `{"old":true}` || stateOf(t, c).Transaction {
			t.Fatal("interrupted transaction not recovered")
		}
	}
}

func TestApplyPreflightNeverOverwritesPrevious(t *testing.T) {
	for _, mode := range []string{"missing", "native", "extra"} {
		c := fixture(t)
		writeFile(t, c.path("previous.json"), `{"preserved":true}`)
		writeFile(t, c.cfg.SubscriptionFile, `{"deployed":true}`)
		if mode != "missing" {
			writeFile(t, c.path("candidate.json"), `{}`)
		}
		if mode == "native" {
			c.run = func(context.Context, string, ...string) error { return errors.New("invalid") }
		}
		if mode == "extra" {
			writeFile(t, filepath.Join(c.cfg.ConfigDir, "extra.json"), `{}`)
		}
		if err := c.Apply(context.Background()); err == nil {
			t.Fatal("expected preflight failure")
		}
		previous, _ := os.ReadFile(c.path("previous.json"))
		deployed, _ := os.ReadFile(c.cfg.SubscriptionFile)
		if string(previous) != `{"preserved":true}` || string(deployed) != `{"deployed":true}` {
			t.Fatal("preflight changed deployment or restore point")
		}
	}
}

func TestLockAndHealthStability(t *testing.T) {
	c := fixture(t)
	release, err := acquireLock(c.path("lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("lock not enforced: %v", err)
	}
	release()
	calls := 0
	c.probe = func(context.Context, string) error {
		calls++
		if calls == 2 {
			return errors.New("transient failure")
		}
		return nil
	}
	if err := c.healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("did not require three consecutive checks: %d", calls)
	}
}

func TestAtomicWriteReplacesSymlinkWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	target, link := filepath.Join(root, "target"), filepath.Join(root, "link")
	writeFile(t, target, "preserved")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(target)
	updated, _ := os.ReadFile(link)
	if !bytes.Equal(original, []byte("preserved")) || !bytes.Equal(updated, []byte("new")) {
		t.Fatal("atomic write followed symlink")
	}
}

func TestUnchangedFetchRemainsApplied(t *testing.T) {
	c := fixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{ "number": 9007199254740993 }`) }))
	defer server.Close()
	c.cfg.SubscriptionURL = server.URL
	writeFile(t, c.path("candidate.json"), `{"number":9007199254740993}`)
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if state := stateOf(t, c); state.Phase != "applied" {
		t.Fatalf("unchanged fetch suggests pending application: %+v", state)
	}
	writeFile(t, c.cfg.SubscriptionFile, `{"drift":true}`)
	if err := c.Fetch(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if state := stateOf(t, c); state.Phase != "pending" {
		t.Fatalf("fetch ignored deployed drift: %+v", state)
	}
}

func TestCancellationStillAttemptsRecovery(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
	writeFile(t, c.path("candidate.json"), `{"new":true}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restarts := 0
	c.run = func(ctx context.Context, binary string, args ...string) error {
		if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
			restarts++
			if restarts == 1 {
				cancel()
				return ctx.Err()
			}
			if ctx.Err() != nil {
				t.Fatal("recovery inherited cancellation")
			}
		}
		return nil
	}
	if err := c.Apply(ctx); err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatalf("canceled apply was not recovered: %v", err)
	}
	if restarts != 2 || stateOf(t, c).Transaction {
		t.Fatal("recovery not completed")
	}
}

func TestInitialInterruptedTransactionAndRollbackValidation(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.cfg.SubscriptionFile, `{"new":true}`)
	state := State{Phase: "applying", Transaction: true, RestoreAvailable: true, PreviousPresent: false}
	if err := c.save(&state); err != nil {
		t.Fatal(err)
	}
	if err := c.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("initial transaction failed to restore API-only configuration")
	}
	state = stateOf(t, c)
	if state.Transaction || state.AppliedDigest != "" {
		t.Fatalf("unexpected restored state: %+v", state)
	}

	// A restore point introducing a second API must fail before changing disk.
	state.RestoreAvailable, state.PreviousPresent = true, true
	if err := c.save(&state); err != nil {
		t.Fatal(err)
	}
	writeFile(t, c.path("previous.json"), `{"services":[{"type":"api","tag":"conflict"}]}`)
	if err := c.Rollback(context.Background()); err == nil {
		t.Fatal("accepted invalid rollback input")
	}
	if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid rollback changed deployed inputs")
	}
}
