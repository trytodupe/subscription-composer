package clientupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Apply rebuilds the candidate digest with the current local configuration.
// Once a transaction is recorded, any uncertain outcome requires recovery.
func (c *Client) Apply(ctx context.Context) error {
	return c.mutate(false, func(state *State) error {
		candidate, err := readRegular(c.path("candidate.json"))
		if err != nil {
			return errors.New("no readable candidate subscription; fetch first")
		}
		input, err := c.preflight(ctx, c.path("candidate.json"), candidate)
		if err != nil {
			return err
		}
		digest := input.digest
		deployed, err := readRegular(c.cfg.SubscriptionFile)
		present := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot read deployed subscription")
		}
		if state.AppliedDigest == digest && present && equivalent(deployed, candidate) && bytes.Equal(input.originalLocal, input.local) {
			state.Phase, state.CandidateDigest, state.LastError = "applied", digest, ""
			return c.save(state)
		}
		generation, err := c.stageBackup(input.originalLocal, deployed, present)
		if err != nil {
			return err
		}
		unpublished := true
		defer func() {
			if unpublished {
				_ = os.RemoveAll(c.path(generation))
			}
		}()
		next := *state
		next.Phase, next.LastError = "applying", ""
		next.CandidateDigest = digest
		next.Transaction, next.RestoreAvailable, next.PreviousPresent = true, true, present
		next.PairBackup, next.PreviousLocalHash = true, contentHash(input.originalLocal)
		next.BackupGeneration = generation
		next.PreviousSubscriptionHash = ""
		if present {
			next.PreviousSubscriptionHash = contentHash(deployed)
		}
		// Read and validate the persisted backup pair before changing either input.
		if _, err := c.restoreInput(ctx, &next); err != nil {
			return err
		}
		// A failed directory sync can follow a successful state rename. Retain the
		// generation once publication is attempted, even if save reports an error.
		unpublished = false
		if err := c.save(&next); err != nil {
			return err
		}
		*state = next
		if !bytes.Equal(input.originalLocal, input.local) {
			if err := atomicWrite(c.cfg.LocalFile, input.local); err != nil {
				return c.failedApply(ctx, state)
			}
		}
		if err := atomicWrite(c.cfg.SubscriptionFile, candidate); err != nil {
			return c.failedApply(ctx, state)
		}
		if err := c.restart(ctx); err != nil {
			return c.failedApply(ctx, state)
		}
		if err := c.healthy(ctx); err != nil {
			return c.failedApply(ctx, state)
		}
		state.Phase, state.AppliedDigest, state.LastError = "applied", digest, ""
		state.Transaction = false
		return c.save(state)
	})
}

func (c *Client) failedApply(ctx context.Context, state *State) error {
	// Cancellation must not prevent an attempt to restore the previous service.
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 120*time.Second)
	defer cancel()
	if err := c.restore(recoveryCtx, state); err != nil {
		return errors.New("application failed and rollback failed; recovery requires rollback")
	}
	return errors.New("application failed; previous configuration restored")
}

// Rollback also recovers a transaction interrupted by process or machine failure.
// The restore point is retained, including when restarting the old service fails.
func (c *Client) Rollback(ctx context.Context) error {
	return c.mutate(true, func(state *State) error {
		if !state.RestoreAvailable {
			return errors.New("no previous configuration is available")
		}
		// Verify the restore point before recording a new rollback transaction.
		if _, err := c.restoreInput(ctx, state); err != nil {
			return err
		}
		state.Transaction, state.Phase, state.LastError = true, "applying", ""
		if err := c.save(state); err != nil {
			return err
		}
		if err := c.restore(ctx, state); err != nil {
			return err
		}
		state.Phase, state.LastError = "applied", ""
		return c.save(state)
	})
}

type restorePoint struct {
	local        []byte
	subscription []byte
	digest       string
}

func (c *Client) restoreInput(ctx context.Context, state *State) (restorePoint, error) {
	var point restorePoint
	if err := c.checkDirectory(); err != nil {
		return point, err
	}
	backupDir, err := c.backupDir(state)
	if err != nil {
		return point, err
	}
	localPath := c.cfg.LocalFile
	if state.PairBackup {
		localPath = filepath.Join(backupDir, "previous-local.json")
		local, err := readPrivate(localPath)
		if err != nil || contentHash(local) != state.PreviousLocalHash {
			return point, errors.New("missing or corrupt previous local configuration")
		}
		point.local = local
	} else {
		// Pre-migration states backed up only the subscription. They deliberately
		// use current local, and must validate that exact pair without projection.
		local, err := readRegular(localPath)
		if err != nil {
			return point, errors.New("cannot read local configuration for legacy rollback")
		}
		point.local = local
	}
	subscription, subscriptionPath := []byte(`{}`), ""
	if state.PreviousPresent {
		subscriptionPath = filepath.Join(backupDir, "previous.json")
		previous, err := readRegular(subscriptionPath)
		if err != nil {
			return point, errors.New("cannot read previous subscription")
		}
		if state.PairBackup && contentHash(previous) != state.PreviousSubscriptionHash {
			return point, errors.New("corrupt previous subscription")
		}
		subscription, point.subscription = previous, previous
	}
	digest, err := c.validatePair(ctx, localPath, point.local, subscriptionPath, subscription)
	if err != nil {
		return point, err
	}
	if state.PreviousPresent {
		point.digest = digest
	}
	return point, nil
}

func (c *Client) restore(ctx context.Context, state *State) error {
	point, err := c.restoreInput(ctx, state)
	if err != nil {
		return err
	}
	if state.PairBackup {
		if err := atomicWrite(c.cfg.LocalFile, point.local); err != nil {
			return errors.New("cannot restore previous local configuration")
		}
	}
	if state.PreviousPresent {
		err = atomicWrite(c.cfg.SubscriptionFile, point.subscription)
	} else {
		err = removeDurable(c.cfg.SubscriptionFile)
	}
	if err != nil {
		return errors.New("cannot restore previous subscription")
	}
	if err := c.restart(ctx); err != nil {
		return err
	}
	if err := c.healthy(ctx); err != nil {
		return err
	}
	state.AppliedDigest, state.Transaction = point.digest, false
	return nil
}
