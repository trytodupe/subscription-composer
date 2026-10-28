// Package authstate persists account credentials independently of published snapshots.
package authstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const maxSessionBytes = 64 << 10

var (
	ErrNotFound = errors.New("auth session not found")
	accountID   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
)

type Session struct {
	AppToken   string `json:"app_token"`
	APIBaseURL string `json:"api_base_url"`
	ExpiresAt  int64  `json:"expires_at"`
	TokenType  string `json:"token_type,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
}

// Validate checks the stored session without disclosing its contents in errors.
func (s Session) Validate() error {
	if strings.TrimSpace(s.AppToken) == "" || strings.IndexFunc(s.AppToken, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("invalid app token")
	}
	u, err := url.Parse(s.APIBaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(s.APIBaseURL, "#") {
		return errors.New("invalid API base URL")
	}
	if (s.DeviceID == "") != (s.DeviceName == "") {
		return errors.New("incomplete auth device identity")
	}
	for _, value := range []string{s.DeviceID, s.DeviceName} {
		if len(value) > 256 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return errors.New("invalid auth device identity")
		}
	}
	if s.ExpiresAt < 0 {
		return errors.New("invalid session expiry")
	}
	if s.TokenType != "" {
		for _, r := range s.TokenType {
			if r <= ' ' || r >= 0x7f {
				return errors.New("invalid token type")
			}
		}
	}
	return nil
}

type Store struct {
	root string
}

// New creates a private directory for credentials and lock files.
func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("invalid auth directory")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("invalid auth directory")
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, errors.New("cannot create auth directory")
	}
	s := &Store{root: absolute}
	if err := s.checkRoot(); err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0700); err != nil {
		return nil, errors.New("cannot secure auth directory")
	}
	return s, nil
}

func (s *Store) checkRoot() error {
	info, err := os.Lstat(s.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid auth directory")
	}
	return nil
}

func (s *Store) path(account, suffix string) (string, error) {
	if !accountID.MatchString(account) {
		return "", errors.New("invalid auth account")
	}
	if err := s.checkRoot(); err != nil {
		return "", err
	}
	return filepath.Join(s.root, account+suffix), nil
}

// Load reads one session. Callers can use it inside WithLock to coordinate updates.
func (s *Store) Load(account string) (Session, error) {
	var session Session
	path, err := s.path(account, ".json")
	if err != nil {
		return session, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return session, ErrNotFound
	}
	if err != nil {
		return session, errors.New("cannot open auth session")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxSessionBytes {
		return session, errors.New("invalid auth session file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSessionBytes+1))
	if err != nil || len(data) > maxSessionBytes {
		return session, errors.New("invalid auth session file")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&session) != nil || dec.Decode(new(any)) != io.EOF || session.Validate() != nil {
		return Session{}, errors.New("invalid auth session")
	}
	return session, nil
}

// Save atomically replaces a credential even when downstream snapshot publishing fails.
// It does not acquire the account lock; callers coordinating a read-modify-write
// sequence should use WithLock.
func (s *Store) Save(account string, session Session) error {
	path, err := s.path(account, ".json")
	if err != nil {
		return err
	}
	if session.TokenType == "" {
		session.TokenType = "Bearer"
	}
	if err := session.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil || len(data) > maxSessionBytes {
		return errors.New("invalid auth session size")
	}
	if err := checkDestination(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.root, ".auth-*")
	if err != nil {
		return errors.New("cannot create auth session")
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot secure auth session")
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot write auth session")
	}
	if err := s.checkRoot(); err != nil {
		return err
	}
	if err := checkDestination(path); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("cannot replace auth session")
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return errors.New("cannot sync auth directory")
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot sync auth directory")
	}
	return nil
}

func checkDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("invalid auth session file")
	}
	return nil
}

// WithLock serializes work on an account across processes. Load and Save do not
// lock themselves, so both can be called by fn without deadlocking.
func (s *Store) WithLock(ctx context.Context, account string, fn func() error) error {
	path, err := s.path(account, ".lock")
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errors.New("cannot open auth lock")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("invalid auth lock file")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			if err := ctx.Err(); err != nil {
				return err
			}
			return fn()
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return errors.New("cannot acquire auth lock")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
