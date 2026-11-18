package clientupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const originalSubscription = "{ \"old\": true }\n"

func appliedGeneration(t *testing.T) (*Client, State) {
	t.Helper()
	c := fixture(t)
	writeFile(t, c.cfg.SubscriptionFile, originalSubscription)
	writeFile(t, c.path("candidate.json"), apiSubscription)
	if err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, c)
	if !validBackupGeneration(state.BackupGeneration) {
		t.Fatal("apply did not publish a backup generation")
	}
	for _, path := range []string{c.path(state.BackupGeneration), backupPath(t, c, "previous-local.json"), backupPath(t, c, "previous.json")} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("backup generation and files must be private")
		}
	}
	return c, state
}

func TestRejectedRestoreGenerationPreservesPriorBackup(t *testing.T) {
	c, before := appliedGeneration(t)
	oldLocalPath := backupPath(t, c, "previous-local.json")
	oldSubscriptionPath := backupPath(t, c, "previous.json")
	deployedLocal, err := readRegular(c.cfg.LocalFile)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, c.path("candidate.json"), strings.Replace(apiSubscription, `"outbounds":[]`, `"outbounds":[],"route":{}`, 1))
	var rejectedDir string
	c.run = func(_ context.Context, binary string, args ...string) error {
		if binary == c.cfg.SingBoxBinary && filepath.Base(args[4]) == "previous-local.json" && filepath.Dir(args[4]) != c.path(before.BackupGeneration) {
			rejectedDir = filepath.Dir(args[4])
			return errors.New("reject new restore pair")
		}
		return nil
	}
	if err := c.Apply(context.Background()); err == nil {
		t.Fatal("expected new restore pair rejection")
	}
	if rejectedDir == "" {
		t.Fatal("new restore generation was not validated")
	}
	if _, err := os.Stat(rejectedDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unpublished rejected generation was not removed")
	}
	after := stateOf(t, c)
	// Failure reporting may change; every field identifying the restore point stays.
	after.Phase, after.LastError, after.UpdatedAt = before.Phase, before.LastError, before.UpdatedAt
	if after != before {
		t.Fatal("failed preflight changed the prior rollback state")
	}
	assertFile(t, oldLocalPath, localConfig)
	assertFile(t, oldSubscriptionPath, originalSubscription)
	assertFile(t, c.cfg.LocalFile, string(deployedLocal))
	assertFile(t, c.cfg.SubscriptionFile, apiSubscription)
	if err := c.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFile(t, c.cfg.LocalFile, localConfig)
	assertFile(t, c.cfg.SubscriptionFile, originalSubscription)
}

func TestUnpublishedGenerationInterruptionPreservesRollback(t *testing.T) {
	c, before := appliedGeneration(t)
	status, err := readRegular(c.path("status.json"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := readRegular(c.cfg.LocalFile)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := readRegular(c.cfg.SubscriptionFile)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := c.stageBackup(local, subscription, true)
	if err != nil {
		t.Fatal(err)
	}
	if generation == before.BackupGeneration {
		t.Fatal("staging reused the published backup directory")
	}
	next := before
	next.BackupGeneration = generation
	next.PreviousLocalHash = contentHash(local)
	next.PreviousSubscriptionHash = contentHash(subscription)
	if _, err := c.restoreInput(context.Background(), &next); err != nil {
		t.Fatal(err)
	}
	// Simulate process exit with a complete staged pair, before publishing next.
	assertFile(t, c.path("status.json"), string(status))
	assertFile(t, backupPath(t, c, "previous-local.json"), localConfig)
	assertFile(t, backupPath(t, c, "previous.json"), originalSubscription)
	if err := c.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFile(t, c.cfg.LocalFile, localConfig)
	assertFile(t, c.cfg.SubscriptionFile, originalSubscription)
	assertFile(t, filepath.Join(c.path(generation), "previous-local.json"), string(local))
	assertFile(t, filepath.Join(c.path(generation), "previous.json"), string(subscription))
	if state := stateOf(t, c); state.BackupGeneration != before.BackupGeneration || state.Transaction {
		t.Fatal("rollback did not retain the published generation")
	}
}

func TestBackupGenerationValidation(t *testing.T) {
	for _, name := range []string{".", "..", "../backup-123", "backup-../other", "/backup-123", "backup-", "backup-a\\b", "backup-a/b", "backup-a.json", "backup-a\n"} {
		t.Run(name, func(t *testing.T) {
			c := fixture(t)
			state := State{Phase: "applied", RestoreAvailable: true, PairBackup: true, PreviousLocalHash: strings.Repeat("a", 64), BackupGeneration: name}
			if err := c.save(&state); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Status(); err == nil {
				t.Fatal("state accepted an invalid generation name")
			}
			if _, err := c.backupDir(&state); err == nil {
				t.Fatal("resolver accepted an invalid generation name")
			}
		})
	}
	c := fixture(t)
	state := State{Phase: "pending", BackupGeneration: "backup-123"}
	if err := c.save(&state); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(); err == nil {
		t.Fatal("generation requires a pair backup marker")
	}
	if err := os.Symlink(t.TempDir(), c.path("backup-link")); err != nil {
		t.Fatal(err)
	}
	state.PairBackup, state.BackupGeneration = true, "backup-link"
	if _, err := c.backupDir(&state); err == nil {
		t.Fatal("resolver accepted a symlink generation")
	}
}
