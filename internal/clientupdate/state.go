package clientupdate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// State contains digests and operation outcomes only, never configuration or credentials.
// A transaction remains set until the running service has been confirmed healthy.
type State struct {
	Phase                    string    `json:"phase"`
	AppliedDigest            string    `json:"applied_digest,omitempty"`
	CandidateDigest          string    `json:"candidate_digest,omitempty"`
	Transaction              bool      `json:"transaction"`
	RestoreAvailable         bool      `json:"restore_available"`
	PreviousPresent          bool      `json:"previous_present"`
	PairBackup               bool      `json:"pair_backup,omitempty"`
	BackupGeneration         string    `json:"backup_generation,omitempty"`
	PreviousLocalHash        string    `json:"previous_local_hash,omitempty"`
	PreviousSubscriptionHash string    `json:"previous_subscription_hash,omitempty"`
	LastError                string    `json:"last_error,omitempty"`
	UpdatedAt                time.Time `json:"updated_at"`
}

func (c *Client) Status() (State, error) {
	data, err := readPrivate(c.path("status.json"))
	if errors.Is(err, os.ErrNotExist) {
		return State{Phase: "pending"}, nil
	}
	if err != nil {
		return State{}, errors.New("cannot read updater state")
	}
	var state State
	if json.Unmarshal(data, &state) != nil {
		return State{}, errors.New("invalid updater state")
	}
	switch state.Phase {
	case "pending", "applying", "applied", "failed":
	default:
		return State{}, errors.New("invalid updater state phase")
	}
	if state.Transaction && !state.RestoreAvailable {
		return State{}, errors.New("invalid updater recovery state")
	}
	if state.BackupGeneration != "" && (!state.PairBackup || !validBackupGeneration(state.BackupGeneration)) {
		return State{}, errors.New("invalid updater backup generation")
	}
	if state.PairBackup {
		if !state.RestoreAvailable || len(state.PreviousLocalHash) != 64 ||
			(state.PreviousPresent && len(state.PreviousSubscriptionHash) != 64) ||
			(!state.PreviousPresent && state.PreviousSubscriptionHash != "") {
			return State{}, errors.New("invalid updater pair backup state")
		}
	} else if state.PreviousLocalHash != "" || state.PreviousSubscriptionHash != "" {
		return State{}, errors.New("pair backup metadata requires a pair backup marker")
	}
	return state, nil
}

func (c *Client) save(state *State) error {
	state.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("cannot encode updater state")
	}
	if err := atomicWrite(c.path("status.json"), append(data, '\n')); err != nil {
		return errors.New("cannot persist updater state")
	}
	return nil
}

// Generation names cannot select paths outside the private state directory.
func validBackupGeneration(name string) bool {
	suffix, ok := strings.CutPrefix(name, "backup-")
	if !ok || suffix == "" {
		return false
	}
	for _, char := range suffix {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func (c *Client) backupDir(state *State) (string, error) {
	if state.BackupGeneration == "" {
		// Both subscription-only and early pair backups used these fixed paths.
		return c.cfg.StateDir, nil
	}
	if !state.PairBackup || !validBackupGeneration(state.BackupGeneration) {
		return "", errors.New("invalid updater backup generation")
	}
	dir := c.path(state.BackupGeneration)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("backup generation must be a private real directory")
	}
	return dir, nil
}

// stageBackup never changes files referenced by an existing state.
func (c *Client) stageBackup(local, subscription []byte, present bool) (string, error) {
	dir, err := os.MkdirTemp(c.cfg.StateDir, "backup-*")
	if err != nil {
		return "", errors.New("cannot create backup generation")
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := atomicWrite(filepath.Join(dir, "previous-local.json"), local); err != nil {
		return "", errors.New("cannot save previous local configuration")
	}
	if present {
		if err := atomicWrite(filepath.Join(dir, "previous.json"), subscription); err != nil {
			return "", errors.New("cannot save previous subscription")
		}
	}
	if err := syncDir(c.cfg.StateDir); err != nil {
		return "", errors.New("cannot persist backup generation")
	}
	complete = true
	return filepath.Base(dir), nil
}

func (c *Client) path(name string) string { return filepath.Join(c.cfg.StateDir, name) }

// atomicWrite makes both file content and the rename durable on the same filesystem.
func atomicWrite(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sing-box-client-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeDurable(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}
