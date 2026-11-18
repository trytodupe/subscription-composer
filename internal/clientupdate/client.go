package clientupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxSubscriptionSize = 16 << 20

type Client struct {
	cfg            Config
	run            func(context.Context, string, ...string) error
	probe          func(context.Context, string) error
	healthTimeout  time.Duration
	healthInterval time.Duration
}

func New(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg,
		run: func(ctx context.Context, binary string, args ...string) error {
			// Native output may contain subscription credentials or API secrets.
			return exec.CommandContext(ctx, binary, args...).Run()
		},
		probe: func(ctx context.Context, address string) error {
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
			if err != nil {
				return err
			}
			return conn.Close()
		},
		healthTimeout:  20 * time.Second,
		healthInterval: time.Second,
	}, nil
}

func (c *Client) mutate(allowRecovery bool, action func(*State) error) error {
	if err := os.MkdirAll(c.cfg.StateDir, 0700); err != nil {
		return errors.New("cannot create updater state directory")
	}
	info, err := os.Lstat(c.cfg.StateDir)
	if err != nil || !info.IsDir() {
		return errors.New("state_dir must be a real directory")
	}
	if err := os.Chmod(c.cfg.StateDir, 0700); err != nil {
		return errors.New("cannot restrict updater state directory")
	}
	unlock, err := acquireLock(c.path("lock"))
	if err != nil {
		return err
	}
	defer unlock()
	state, err := c.Status()
	if err != nil {
		return err
	}
	if state.Transaction && !allowRecovery {
		return errors.New("unfinished application requires rollback before further updates")
	}
	if err := action(&state); err != nil {
		state.Phase, state.LastError = "failed", err.Error()
		if saveErr := c.save(&state); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		return err
	}
	return nil
}

// Fetch validates and stages a subscription without changing the running service.
func (c *Client) Fetch(ctx context.Context, jitter time.Duration) error {
	if jitter < 0 {
		return errors.New("jitter must not be negative")
	}
	if jitter > 0 {
		delay, err := rand.Int(rand.Reader, big.NewInt(int64(jitter)))
		if err != nil {
			return errors.New("cannot choose fetch delay")
		}
		if err := wait(ctx, time.Duration(delay.Int64())); err != nil {
			return errors.New("fetch delay canceled")
		}
	}
	return c.mutate(false, func(state *State) error {
		data, err := c.download(ctx)
		if err != nil {
			return err
		}
		// The check input lives outside config_dir so the daemon cannot load it.
		file, err := os.CreateTemp(c.cfg.StateDir, ".candidate-*")
		if err != nil {
			return errors.New("cannot create candidate validation file")
		}
		name := file.Name()
		defer os.Remove(name)
		if _, err := file.Write(data); err != nil {
			file.Close()
			return errors.New("cannot write candidate validation file")
		}
		if err := file.Close(); err != nil {
			return errors.New("cannot close candidate validation file")
		}
		input, err := c.preflight(ctx, name, data)
		if err != nil {
			return err
		}
		digest := input.digest
		if err := atomicWrite(c.path("candidate.json"), data); err != nil {
			return errors.New("cannot persist candidate subscription")
		}
		state.Phase, state.CandidateDigest, state.LastError = "pending", digest, ""
		if state.AppliedDigest == digest && bytes.Equal(input.originalLocal, input.local) {
			deployed, err := readRegular(c.cfg.SubscriptionFile)
			if err == nil && equivalent(deployed, data) {
				state.Phase = "applied"
			}
		}
		return c.save(state)
	})
}

func (c *Client) download(ctx context.Context) ([]byte, error) {
	token, err := readPrivate(c.cfg.TokenFile)
	if err != nil {
		return nil, errors.New("cannot read private subscription token")
	}
	secret := strings.TrimSpace(string(token))
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return nil, errors.New("invalid subscription token")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.SubscriptionURL, nil)
	if err != nil {
		return nil, errors.New("cannot prepare subscription request")
	}
	req.SetBasicAuth(c.cfg.Username, secret)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("subscription request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("subscription server returned a non-200 response")
	}
	if res.ContentLength > maxSubscriptionSize {
		return nil, errors.New("subscription exceeds 16 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxSubscriptionSize+1))
	if err != nil {
		return nil, errors.New("cannot read subscription response")
	}
	if len(data) > maxSubscriptionSize {
		return nil, errors.New("subscription exceeds 16 MiB limit")
	}
	return data, nil
}

func (c *Client) checkDirectory() error {
	entries, err := os.ReadDir(c.cfg.ConfigDir)
	if err != nil {
		return errors.New("cannot inspect sing-box configuration directory")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(c.cfg.ConfigDir, entry.Name())
		if path != c.cfg.LocalFile && path != c.cfg.SubscriptionFile {
			return errors.New("config_dir contains an unmanaged .json entry")
		}
		if !entry.Type().IsRegular() {
			return errors.New("managed configuration entries must be regular files")
		}
	}
	return nil
}

type validatedInput struct {
	originalLocal []byte
	local         []byte
	digest        string
}

func (c *Client) preflight(ctx context.Context, path string, data []byte) (validatedInput, error) {
	var input validatedInput
	if err := c.checkDirectory(); err != nil {
		return input, err
	}
	local, err := readRegular(c.cfg.LocalFile)
	if err != nil {
		return input, errors.New("cannot read local configuration")
	}
	projected, err := projectLocal(local, data)
	if err != nil {
		return input, err
	}
	localPath := c.cfg.LocalFile
	if !bytes.Equal(local, projected) {
		file, err := os.CreateTemp(c.cfg.StateDir, ".local-*")
		if err != nil {
			return input, errors.New("cannot create local validation file")
		}
		localPath = file.Name()
		defer os.Remove(localPath)
		_, writeErr := file.Write(projected)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return input, errors.New("cannot write local validation file")
		}
	}
	digest, err := c.validatePair(ctx, localPath, projected, path, data)
	if err != nil {
		return input, err
	}
	return validatedInput{originalLocal: local, local: projected, digest: digest}, nil
}

func (c *Client) validatePair(ctx context.Context, localPath string, local []byte, subscriptionPath string, subscription []byte) (string, error) {
	digest, err := pairDigest(local, subscription)
	if err != nil {
		return "", err
	}
	_, _, api, _ := pairObjects(local, subscription)
	if err := c.checkHealthEndpoint(ctx, api); err != nil {
		return "", err
	}
	inputs := []string{"-c", localPath}
	if subscriptionPath != "" {
		inputs = append(inputs, "-c", subscriptionPath)
	}
	if err := c.nativeCheck(ctx, inputs...); err != nil {
		return "", err
	}
	return digest, nil
}

func (c *Client) nativeCheck(ctx context.Context, inputs ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := append([]string{"check", "-D", c.cfg.WorkDir}, inputs...)
	if err := c.run(ctx, c.cfg.SingBoxBinary, args...); err != nil {
		return errors.New("native sing-box validation failed")
	}
	return nil
}

func (c *Client) restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.run(ctx, c.cfg.RCServiceBinary, c.cfg.ServiceName, "restart") != nil {
		return errors.New("OpenRC restart failed")
	}
	return nil
}

// healthy checks process status and listener availability over a stability window.
// It does not establish API authentication, configuration identity, or connectivity.
func (c *Client) healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.healthTimeout)
	defer cancel()
	consecutive := 0
	for {
		probeCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		err := c.run(probeCtx, c.cfg.RCServiceBinary, c.cfg.ServiceName, "status")
		if err == nil {
			err = c.probe(probeCtx, c.cfg.HealthAddress)
		}
		stop()
		if err == nil {
			consecutive++
		} else {
			consecutive = 0
		}
		if consecutive == 3 {
			return nil
		}
		if wait(ctx, c.healthInterval) != nil {
			return errors.New("service or TCP listener health check failed")
		}
	}
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
