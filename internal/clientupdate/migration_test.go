package clientupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const apiSubscription = `{"services":[{"type":"api","tag":"remote-api","listen":"::","listen_port":9090,"secret":"private-remote-api-secret"}],"outbounds":[]}`

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := readRegular(path)
	if err != nil || string(data) != want {
		t.Fatalf("unexpected file content at %s: %v", path, err)
	}
}

func assertProjectedLocal(t *testing.T, data []byte) {
	t.Helper()
	if !equivalent(data, []byte(`{"log":{"level":"info"}}`)) {
		t.Fatal("migration must remove only the local API and preserve log")
	}
}

func TestPairLayouts(t *testing.T) {
	for _, local := range []string{`{}`, `{"services":[]}`, `{"log":{"level":"warn"}}`} {
		if _, err := pairDigest([]byte(local), []byte(apiSubscription)); err != nil {
			t.Fatalf("rejected subscription-owned API: %v", err)
		}
	}
	for _, test := range []struct{ local, subscription string }{
		{`{}`, `{}`},
		{localConfig, apiSubscription},
		{`{"services":[{"type":"api","tag":"one"},{"type":"api","tag":"two"}]}`, `{}`},
		{`{}`, `{"services":[{"type":"api","tag":"one"},{"type":"api","tag":"two"}]}`},
		{`{}`, `{"services":[{"type":"api","tag":"same"},{"type":"other","tag":"same"}]}`},
		{`{}`, `{"services":[{"type":"api"}]}`},
		{`{}`, `{"services":[{"tag":"missing-type"}]}`},
		{`{}`, `{"services":[{"type":42}]}`},
		{`{}`, `{"services":[{"type":"api","tag":42}]}`},
		{`{}`, `{"services":{}}`},
		{`{"services":[{"type":"other","tag":"other"}]}`, apiSubscription},
		{`{"route":{}}`, apiSubscription},
		{`{"services":null}`, apiSubscription},
	} {
		if _, err := pairDigest([]byte(test.local), []byte(test.subscription)); err == nil {
			t.Fatal("accepted invalid configuration pair")
		}
	}
}

func TestFetchMigrationDoesNotMutateDeployment(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "existing"}[present], func(t *testing.T) {
			c := fixture(t)
			if present {
				writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, apiSubscription)
			}))
			defer server.Close()
			c.cfg.SubscriptionURL = server.URL
			var temporaryPaths []string
			c.run = func(_ context.Context, binary string, args ...string) error {
				if binary != c.cfg.SingBoxBinary || len(args) != 7 {
					t.Fatal("fetch should only validate the actual pair")
				}
				localPath := args[4]
				if localPath == c.cfg.LocalFile || filepath.Dir(localPath) != c.cfg.StateDir || filepath.Dir(args[6]) != c.cfg.StateDir {
					t.Fatal("migration check inputs must be outside config_dir")
				}
				projected, err := readRegular(localPath)
				if err != nil {
					t.Fatal(err)
				}
				assertProjectedLocal(t, projected)
				assertFile(t, args[6], apiSubscription)
				assertFile(t, c.cfg.LocalFile, localConfig)
				temporaryPaths = append(temporaryPaths, localPath, args[6])
				return nil
			}
			if err := c.Fetch(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			assertFile(t, c.cfg.LocalFile, localConfig)
			if present {
				assertFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
			} else if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fetch installed a subscription")
			}
			assertFile(t, c.path("candidate.json"), apiSubscription)
			for _, path := range temporaryPaths {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("temporary validation input was not removed")
				}
			}
			if state := stateOf(t, c); state.Phase != "pending" || state.PairBackup || state.RestoreAvailable {
				t.Fatalf("fetch changed restore state: %+v", state)
			}
		})
	}
}

func TestApplyMigrationAndExactPairRollback(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "existing"}[present], func(t *testing.T) {
			c := fixture(t)
			// Whitespace and formatting of the restore point must survive exactly.
			original := " \n" + localConfig + "\n"
			writeFile(t, c.cfg.LocalFile, original)
			if present {
				writeFile(t, c.cfg.SubscriptionFile, "{ \"old\": true }\n")
			}
			writeFile(t, c.path("candidate.json"), apiSubscription)
			restarts := 0
			c.run = func(_ context.Context, binary string, args ...string) error {
				if binary == c.cfg.SingBoxBinary {
					local, err := readRegular(args[4])
					if err != nil {
						t.Fatal(err)
					}
					subscription := []byte(`{}`)
					if len(args) == 7 {
						subscription, err = readRegular(args[6])
						if err != nil {
							t.Fatal(err)
						}
					}
					if _, err := pairDigest(local, subscription); err != nil {
						t.Fatal("native validation received an invalid pair")
					}
				}
				if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
					restarts++
					state := stateOf(t, c)
					if !state.Transaction || !state.PairBackup || !state.RestoreAvailable {
						t.Fatal("pair transaction must be durable before restarting")
					}
				}
				return nil
			}
			if err := c.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			local, _ := readRegular(c.cfg.LocalFile)
			assertProjectedLocal(t, local)
			assertFile(t, c.cfg.SubscriptionFile, apiSubscription)
			assertFile(t, backupPath(t, c, "previous-local.json"), original)
			state := stateOf(t, c)
			if state.Transaction || !state.PairBackup || state.PreviousLocalHash != contentHash([]byte(original)) || state.PreviousPresent != present {
				t.Fatalf("incorrect pair state: %+v", state)
			}
			status, _ := readRegular(c.path("status.json"))
			if bytes.Contains(status, []byte("private-")) {
				t.Fatal("state leaked API secret")
			}
			if err := c.Apply(context.Background()); err != nil || restarts != 1 {
				t.Fatalf("unchanged migration restarted: %v", err)
			}
			// Subsequent manual changes must not replace the original restore point.
			writeFile(t, c.cfg.LocalFile, `{"log":{"level":"error"}}`)
			if err := c.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertFile(t, c.cfg.LocalFile, original)
			if present {
				assertFile(t, c.cfg.SubscriptionFile, "{ \"old\": true }\n")
			} else if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("first install rollback retained subscription")
			}
			if restarts != 2 || stateOf(t, c).Transaction {
				t.Fatal("rollback did not finish")
			}
		})
	}
}

func TestMigrationFailureRestoresBothInputs(t *testing.T) {
	for _, present := range []bool{false, true} {
		for _, healthFailure := range []bool{false, true} {
			c := fixture(t)
			if present {
				writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
			}
			writeFile(t, c.path("candidate.json"), apiSubscription)
			restarts := 0
			c.run = func(_ context.Context, binary string, args ...string) error {
				if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
					restarts++
					if restarts == 1 {
						local, _ := readRegular(c.cfg.LocalFile)
						assertProjectedLocal(t, local)
						if !healthFailure {
							return errors.New("private-restart-secret")
						}
					} else {
						assertFile(t, c.cfg.LocalFile, localConfig)
					}
				}
				return nil
			}
			c.probe = func(context.Context, string) error {
				if restarts == 1 && healthFailure {
					return errors.New("unhealthy")
				}
				return nil
			}
			if err := c.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
				t.Fatalf("unexpected application outcome: %v", err)
			}
			assertFile(t, c.cfg.LocalFile, localConfig)
			if present {
				assertFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
			} else if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("first failure did not remove subscription")
			}
			if restarts != 2 || stateOf(t, c).Transaction {
				t.Fatal("pair recovery did not finish")
			}
		}
	}
}

func savePairTransaction(t *testing.T, c *Client, present bool) {
	t.Helper()
	writeFile(t, c.path("previous-local.json"), localConfig)
	state := State{
		Phase: "applying", Transaction: true, RestoreAvailable: true, PreviousPresent: present,
		PairBackup: true, PreviousLocalHash: contentHash([]byte(localConfig)),
	}
	if present {
		writeFile(t, c.path("previous.json"), `{"old":true}`)
		state.PreviousSubscriptionHash = contentHash([]byte(`{"old":true}`))
	}
	if err := c.save(&state); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedPairWriteRecovery(t *testing.T) {
	for _, present := range []bool{false, true} {
		for _, stage := range []string{"before writes", "local written", "both written", "local restored"} {
			t.Run(map[bool]string{false: "initial/", true: "existing/"}[present]+stage, func(t *testing.T) {
				c := fixture(t)
				savePairTransaction(t, c, present)
				if present {
					writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
				}
				if stage == "local written" || stage == "both written" {
					writeFile(t, c.cfg.LocalFile, `{"log":{"level":"info"}}`)
				}
				if stage == "both written" || stage == "local restored" {
					writeFile(t, c.cfg.SubscriptionFile, apiSubscription)
				}
				if err := c.Apply(context.Background()); err == nil {
					t.Fatal("updates must be blocked during pair recovery")
				}
				if err := c.Rollback(context.Background()); err != nil {
					t.Fatal(err)
				}
				assertFile(t, c.cfg.LocalFile, localConfig)
				if present {
					assertFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
				} else if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("interrupted initial migration retained subscription")
				}
				if stateOf(t, c).Transaction {
					t.Fatal("recovery transaction not cleared")
				}
			})
		}
	}
}

func TestPairBackupRejectionBeforeMutation(t *testing.T) {
	for _, mode := range []string{"missing local", "corrupt local", "missing subscription", "corrupt subscription", "native rejection", "invalid pair"} {
		t.Run(mode, func(t *testing.T) {
			c := fixture(t)
			writeFile(t, c.cfg.SubscriptionFile, `{"old":true}`)
			writeFile(t, c.path("candidate.json"), apiSubscription)
			if err := c.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			state := stateOf(t, c)
			state.Transaction = true
			if err := c.save(&state); err != nil {
				t.Fatal(err)
			}
			writeFile(t, c.cfg.LocalFile, `{"log":{"level":"warn"}}`)
			writeFile(t, c.cfg.SubscriptionFile, apiSubscription)
			switch mode {
			case "missing local":
				if err := os.Remove(backupPath(t, c, "previous-local.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt local":
				// Valid JSON is still corrupt when it does not match the snapshot.
				writeFile(t, backupPath(t, c, "previous-local.json"), strings.Replace(localConfig, "info", "error", 1))
			case "missing subscription":
				if err := os.Remove(backupPath(t, c, "previous.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt subscription":
				writeFile(t, backupPath(t, c, "previous.json"), `{"different":true}`)
			case "native rejection":
				c.run = func(context.Context, string, ...string) error { return errors.New("private-native-secret") }
			case "invalid pair":
				writeFile(t, backupPath(t, c, "previous.json"), apiSubscription)
				state := stateOf(t, c)
				state.PreviousSubscriptionHash = contentHash([]byte(apiSubscription))
				if err := c.save(&state); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Rollback(context.Background()); err == nil || strings.Contains(err.Error(), "private-") {
				t.Fatalf("unexpected rollback outcome: %v", err)
			}
			assertFile(t, c.cfg.LocalFile, `{"log":{"level":"warn"}}`)
			assertFile(t, c.cfg.SubscriptionFile, apiSubscription)
			if !stateOf(t, c).Transaction {
				t.Fatal("failed rollback lost recovery transaction")
			}
		})
	}
}

func TestLegacyRollbackDoesNotProjectOrAssumePairBackup(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.path("previous.json"), `{"old":true}`)
	// A stale file must never be mistaken for a backup belonging to legacy state.
	writeFile(t, c.path("previous-local.json"), localConfig)
	writeFile(t, c.cfg.LocalFile, `{}`)
	writeFile(t, c.cfg.SubscriptionFile, apiSubscription)
	state := State{Phase: "failed", Transaction: true, RestoreAvailable: true, PreviousPresent: true}
	if err := c.save(&state); err != nil {
		t.Fatal(err)
	}
	if err := c.Rollback(context.Background()); err == nil {
		t.Fatal("legacy recovery accepted previous subscription with stripped local")
	}
	assertFile(t, c.cfg.LocalFile, `{}`)
	assertFile(t, c.cfg.SubscriptionFile, apiSubscription)
}

func TestHealthEndpointCompatibility(t *testing.T) {
	for _, test := range []struct {
		listen, health string
		valid          bool
	}{
		{"::", "127.0.0.1:9090", true},
		{"::", "[::1]:9090", true},
		{"0.0.0.0", "127.0.0.1:9090", true},
		{"0.0.0.0", "[::1]:9090", false},
		{"127.0.0.1", "127.0.0.1:9090", true},
		{"127.0.0.1", "127.0.0.2:9090", false},
		{"127.0.0.1", "[::1]:9090", false},
		{"::1", "[::1]:9090", true},
		{"::1", "127.0.0.1:9090", false},
		{"::", "127.0.0.1:9091", false},
		{"::", "0.0.0.0:9090", false},
		{"::", "[::]:9090", false},
		{"::", "[::ffff:0.0.0.0]:9090", false},
		{"invalid", "127.0.0.1:9090", false},
	} {
		t.Run(test.listen+"/"+test.health, func(t *testing.T) {
			c := fixture(t)
			// Bypass New here to exercise pair preflight's own wildcard rejection.
			c.cfg.HealthAddress = test.health
			writeFile(t, c.path("candidate.json"), strings.Replace(apiSubscription, `"listen":"::"`, `"listen":"`+test.listen+`"`, 1))
			if test.valid {
				// The old local must also match health_address to provide a valid restore point.
				writeFile(t, c.cfg.LocalFile, strings.Replace(localConfig, "127.0.0.1", test.listen, 1))
			}
			err := c.Apply(context.Background())
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "private-") {
					t.Fatalf("unexpected preflight result: %v", err)
				}
				assertFile(t, c.cfg.LocalFile, localConfig)
				if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("health mismatch modified deployment")
				}
			}
		})
	}
}

func TestMigrationRejectsDuplicateAPIAndMissingLocal(t *testing.T) {
	for _, mode := range []string{"duplicate remote", "duplicate local", "missing local", "nonregular local"} {
		t.Run(mode, func(t *testing.T) {
			c := fixture(t)
			writeFile(t, c.path("candidate.json"), apiSubscription)
			switch mode {
			case "duplicate remote":
				writeFile(t, c.path("candidate.json"), `{"services":[{"type":"api","tag":"a"},{"type":"api","tag":"b"}]}`)
			case "duplicate local":
				writeFile(t, c.cfg.LocalFile, `{"services":[{"type":"api","tag":"a"},{"type":"api","tag":"b"}]}`)
			case "missing local", "nonregular local":
				if err := os.Remove(c.cfg.LocalFile); err != nil {
					t.Fatal(err)
				}
				if mode == "nonregular local" {
					if err := os.Mkdir(c.cfg.LocalFile, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := c.Apply(context.Background()); err == nil {
				t.Fatal("accepted invalid migration input")
			}
			if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input changed deployment")
			}
		})
	}
}

func TestApplyWithSubscriptionOwnedAPI(t *testing.T) {
	for _, local := range []string{`{}`, `{"log":{"level":"info"}}`} {
		for _, fail := range []bool{false, true} {
			c := fixture(t)
			writeFile(t, c.cfg.LocalFile, local)
			writeFile(t, c.cfg.SubscriptionFile, apiSubscription)
			candidate := strings.Replace(apiSubscription, `"outbounds":[]`, `"outbounds":[],"route":{}`, 1)
			writeFile(t, c.path("candidate.json"), candidate)
			restarts := 0
			c.run = func(_ context.Context, binary string, args ...string) error {
				if binary == c.cfg.RCServiceBinary && args[1] == "restart" {
					restarts++
					if fail && restarts == 1 {
						return errors.New("restart failed")
					}
				}
				return nil
			}
			err := c.Apply(context.Background())
			if fail {
				if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
					t.Fatalf("unexpected failure result: %v", err)
				}
				assertFile(t, c.cfg.SubscriptionFile, apiSubscription)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertFile(t, c.cfg.SubscriptionFile, candidate)
			}
			assertFile(t, c.cfg.LocalFile, local)
			assertFile(t, backupPath(t, c, "previous-local.json"), local)
			if !stateOf(t, c).PairBackup || stateOf(t, c).Transaction {
				t.Fatal("invalid final pair state")
			}
		}
	}
}

func TestApplyRequiresValidatedRestorePair(t *testing.T) {
	c := fixture(t)
	writeFile(t, c.cfg.LocalFile, `{}`)
	writeFile(t, c.path("candidate.json"), apiSubscription)
	if err := c.Apply(context.Background()); err == nil {
		t.Fatal("accepted an initial deployment with no API restore point")
	}
	assertFile(t, c.cfg.LocalFile, `{}`)
	if _, err := os.Stat(c.cfg.SubscriptionFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid restore point changed deployment")
	}
	if stateOf(t, c).Transaction {
		t.Fatal("invalid restore point started a transaction")
	}
}

func TestPairBackupMetadataRequired(t *testing.T) {
	for _, state := range []State{
		{Phase: "applying", Transaction: true, RestoreAvailable: true, PairBackup: true},
		{Phase: "applying", Transaction: true, RestoreAvailable: true, PreviousLocalHash: strings.Repeat("a", 64)},
		{Phase: "applied", PairBackup: true, PreviousLocalHash: strings.Repeat("a", 64)},
	} {
		c := fixture(t)
		if err := c.save(&state); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Status(); err == nil {
			t.Fatal("accepted incomplete or unmarked pair backup metadata")
		}
		if err := c.Rollback(context.Background()); err == nil {
			t.Fatal("rollback accepted invalid backup metadata")
		}
		assertFile(t, c.cfg.LocalFile, localConfig)
	}
}
