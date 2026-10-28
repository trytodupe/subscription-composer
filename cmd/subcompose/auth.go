package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
	"github.com/ttd/subscription-composer/internal/ikuuu"
	"github.com/ttd/subscription-composer/internal/model"
)

type authOptions struct{ Login, Import, Status, File, LoginURL, Helper string }

type authSummary struct {
	Source      string `json:"source"`
	Authorized  bool   `json:"authorized"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	DeviceBound bool   `json:"device_bound"`
}

func runAuth(ctx context.Context, cfg model.Config, opts authOptions) error {
	id := opts.Login
	if opts.Import != "" {
		id = opts.Import
	}
	if opts.Status != "" {
		id = opts.Status
	}
	var source model.Source
	for _, s := range cfg.Sources {
		if s.ID == id {
			source = s
			break
		}
	}
	if source.ID == "" || source.Type != "ikuuu" {
		return errors.New("authorization requires a configured source with type ikuuu")
	}
	store, err := authstate.New(filepath.Join(cfg.SnapshotDir, "auth"))
	if err != nil {
		return err
	}
	if opts.Status != "" {
		s, err := store.Load(id)
		if errors.Is(err, authstate.ErrNotFound) {
			return json.NewEncoder(os.Stdout).Encode(authSummary{Source: id})
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(authSummary{Source: id, Authorized: s.ExpiresAt == 0 || s.ExpiresAt > time.Now().Unix(), ExpiresAt: s.ExpiresAt, DeviceBound: s.DeviceID != ""})
	}
	input := opts.File
	if opts.Login != "" {
		u, err := url.Parse(opts.LoginURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return errors.New("web login requires an HTTPS URL without credentials")
		}
		helper := opts.Helper
		if helper == "" {
			executable, err := os.Executable()
			if err != nil {
				return errors.New("cannot locate login helper")
			}
			helper = filepath.Join(filepath.Dir(executable), "ikuuu-login")
		}
		if _, err := os.Stat(helper); err != nil {
			return errors.New("native login helper unavailable; build it on macOS or import a callback captured on another machine")
		}
		dir, err := os.MkdirTemp(cfg.SnapshotDir, ".auth-bootstrap-")
		if err != nil {
			return errors.New("cannot create private login directory")
		}
		defer os.RemoveAll(dir)
		input = filepath.Join(dir, "callback.txt")
		loginCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		fmt.Fprintln(os.Stdout, "Complete official web sign-in in the native login window.")
		command := exec.CommandContext(loginCtx, helper, "--url", opts.LoginURL, "--output", input)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return errors.New("web login canceled or callback capture failed")
		}
	}
	if input == "" {
		return errors.New("ikuuu-import requires auth-file")
	}
	data, err := readAuthorization(input)
	if err != nil {
		return err
	}
	var session authstate.Session
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if dec.Decode(&session) != nil || dec.Decode(new(any)) != io.EOF {
			return errors.New("invalid authorization session JSON")
		}
		if session.APIBaseURL == "" {
			session.APIBaseURL = source.URL
		}
		if strings.TrimRight(session.APIBaseURL, "/") != strings.TrimRight(source.URL, "/") {
			return errors.New("authorization API URL does not match configured source")
		}
	} else {
		session, err = ikuuu.ParseCallback(strings.TrimSpace(string(data)), source.URL)
		if err != nil {
			return err
		}
	}
	client := ikuuu.Client{Store: store}
	requestCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	session, err = client.Import(requestCtx, id, session)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(authSummary{Source: id, Authorized: true, ExpiresAt: session.ExpiresAt, DeviceBound: session.DeviceID != ""})
}

func readAuthorization(path string) ([]byte, error) {
	var reader io.Reader = os.Stdin
	if path != "-" {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, errors.New("cannot open authorization input")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("authorization input must be a private regular file")
		}
		reader = f
	}
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return nil, errors.New("authorization input is empty, unreadable or exceeds 64 KiB")
	}
	return data, nil
}
