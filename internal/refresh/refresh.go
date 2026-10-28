package refresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
	"github.com/ttd/subscription-composer/internal/compose"
	"github.com/ttd/subscription-composer/internal/ikuuu"
	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/nodes"
	"github.com/ttd/subscription-composer/internal/rulesets"
)

const (
	maxSourceBytes   = 8 << 20
	maxSnapshotBytes = 128 << 20
	snapshotVersion  = 1
	snapshotFile     = "snapshot.json"
)

type sourceCache struct {
	Fingerprint string             `json:"fingerprint"`
	Body        []byte             `json:"body"`
	ETag        string             `json:"etag,omitempty"`
	Modified    string             `json:"modified,omitempty"`
	Status      model.SourceStatus `json:"status"`
}

type snapshot struct {
	Version  int                       `json:"version"`
	Sources  map[string]sourceCache    `json:"sources"`
	Profiles map[string][]byte         `json:"profiles"`
	RuleSets map[string]rulesets.Cache `json:"rule_sets,omitempty"`
	Status   model.Status              `json:"status"`
}

type attempt struct {
	done chan struct{}
	err  error
}

// Manager keeps published profiles immutable until an entire generation is ready.
type Manager struct {
	cfg          model.Config
	client       *http.Client
	appClient    *ikuuu.Client
	timeout      time.Duration
	debounce     time.Duration
	fingerprints map[string]string

	mu          sync.RWMutex
	flight      *attempt
	lastAttempt time.Time
	lastResult  error
	cache       map[string]sourceCache
	ruleSets    map[string]rulesets.Cache
	profiles    map[string][]byte
	status      model.Status
}

// New opens the last published generation without fetching sources.
func New(cfg model.Config) (*Manager, error) {
	if cfg.SnapshotDir == "" || len(cfg.Sources) == 0 || len(cfg.Devices) == 0 {
		return nil, errors.New("snapshot directory, sources, and devices are required")
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("invalid configuration")
	}
	var isolated model.Config
	if err := json.Unmarshal(encoded, &isolated); err != nil {
		return nil, errors.New("invalid configuration")
	}
	cfg = isolated
	timeout, err := duration(cfg.RefreshTimeout, 20*time.Second)
	if err != nil || timeout == 0 {
		return nil, errors.New("invalid refresh timeout")
	}
	debounce, err := duration(cfg.Debounce, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid debounce: %w", err)
	}
	m := &Manager{
		cfg: cfg, client: &http.Client{}, timeout: timeout, debounce: debounce,
		fingerprints: make(map[string]string), cache: make(map[string]sourceCache),
		profiles: make(map[string][]byte), ruleSets: make(map[string]rulesets.Cache),
	}
	for _, s := range cfg.Sources {
		if s.Type != "" && s.Type != "subscription" && s.Type != "ikuuu" {
			return nil, errors.New("unsupported source type")
		}
		if s.Type == "ikuuu" && (s.URL == "" || s.File != "" || len(s.Headers) != 0) {
			return nil, errors.New("ikuuu source requires an API URL and manages its own authentication")
		}
		if s.ID == "" || m.fingerprints[s.ID] != "" || (s.URL == "") == (s.File == "") {
			return nil, errors.New("invalid or duplicate source")
		}
		if s.URL != "" {
			u, err := url.Parse(s.URL)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return nil, errors.New("invalid source URL")
			}
		}
		b, err := json.Marshal(s)
		if err != nil {
			return nil, errors.New("invalid source")
		}
		h := sha256.Sum256(b)
		m.fingerprints[s.ID] = hex.EncodeToString(h[:])
		m.status.Sources = append(m.status.Sources, model.SourceStatus{ID: s.ID})
	}
	seen := make(map[string]bool)
	for _, d := range cfg.Devices {
		if d.ID == "" || seen[d.ID] {
			return nil, errors.New("invalid or duplicate device")
		}
		seen[d.ID] = true
	}
	if err := secureDir(cfg.SnapshotDir); err != nil {
		return nil, errors.New("cannot secure snapshot directory")
	}
	for _, s := range cfg.Sources {
		if s.Type == "ikuuu" {
			store, err := authstate.New(filepath.Join(cfg.SnapshotDir, "auth"))
			if err != nil {
				return nil, err
			}
			m.appClient = &ikuuu.Client{Store: store, HTTPClient: m.client}
			break
		}
	}
	if err := m.load(seen); err != nil {
		return nil, err
	}
	return m, nil
}

func duration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, errors.New("expected a nonnegative duration")
	}
	return d, nil
}

func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid directory")
	}
	return os.Chmod(dir, 0700)
}

func (m *Manager) load(devices map[string]bool) error {
	path := filepath.Join(m.cfg.SnapshotDir, snapshotFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSnapshotBytes || info.Mode().Perm()&0077 != 0 {
		return errors.New("invalid snapshot file")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read snapshot")
	}
	defer f.Close()
	var snap snapshot
	dec := json.NewDecoder(io.LimitReader(f, maxSnapshotBytes+1))
	if err := dec.Decode(&snap); err != nil {
		return errors.New("invalid snapshot")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF || snap.Version != snapshotVersion || snap.Sources == nil || snap.Profiles == nil || len(snap.Profiles) == 0 || snap.Status.Revision != hashProfiles(snap.Profiles) || snap.Status.PublishedAt == "" {
		return errors.New("invalid snapshot version or content")
	}
	for id, profile := range snap.Profiles {
		if devices[id] && len(profile) > 0 {
			m.profiles[id] = append([]byte(nil), profile...)
		}
	}
	for i, s := range m.cfg.Sources {
		cached, ok := snap.Sources[s.ID]
		if !ok || cached.Fingerprint != m.fingerprints[s.ID] || cached.Status.ID != s.ID || len(cached.Body) == 0 || len(cached.Body) > maxSourceBytes || cached.Status.SucceededAt == "" {
			continue
		}
		m.cache[s.ID] = cached
		m.status.Sources[i] = cached.Status
	}
	for tag, cached := range snap.RuleSets {
		if cached.Status.ID == "ruleset:"+tag && cached.Fingerprint != "" && len(cached.Body) > 0 && json.Valid(cached.Rules) {
			m.ruleSets[tag] = cached
			m.status.Sources = append(m.status.Sources, cached.Status)
		}
	}
	if len(m.profiles) > 0 {
		m.status.Revision = snap.Status.Revision
		m.status.PublishedAt = snap.Status.PublishedAt
	}
	m.status.CheckedAt = snap.Status.CheckedAt
	m.status.LastError = snap.Status.LastError
	return nil
}

// Refresh joins an in-progress attempt. A caller's cancellation stops its wait,
// while the attempt runs under its own timeout for other callers.
func (m *Manager) Refresh(ctx context.Context, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	a := m.flight
	if a == nil {
		if !force && !m.lastAttempt.IsZero() && time.Since(m.lastAttempt) < m.debounce {
			err := m.lastResult
			m.mu.Unlock()
			return err
		}
		a = &attempt{done: make(chan struct{})}
		m.flight = a
		m.lastAttempt = time.Now()
		go m.run(a)
	}
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.done:
		return a.err
	}
}

func (m *Manager) run(a *attempt) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	err := m.refresh(ctx)
	m.mu.Lock()
	a.err = err
	m.lastResult = err
	m.flight = nil
	close(a.done)
	m.mu.Unlock()
}

// Profile returns an independent copy of a published device configuration.
func (m *Manager) Profile(deviceID string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.profiles[deviceID]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

// Status returns an independent copy of the current status.
func (m *Manager) Status() model.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.Sources = append([]model.SourceStatus(nil), s.Sources...)
	return s
}

type sourceResult struct {
	cache sourceCache
	nodes []model.Node
	err   error
}

func (m *Manager) refresh(ctx context.Context) error {
	m.mu.RLock()
	prior := make(map[string]sourceCache, len(m.cache))
	for k, v := range m.cache {
		prior[k] = v
	}
	availableRules := make(map[string]rulesets.Cache, len(m.ruleSets))
	for k, v := range m.ruleSets {
		availableRules[k] = v
	}
	m.mu.RUnlock()

	results := make([]sourceResult, len(m.cfg.Sources))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, source := range m.cfg.Sources {
		wg.Add(1)
		go func(i int, source model.Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				results[i] = m.updateSource(ctx, source, prior[source.ID])
			case <-ctx.Done():
				results[i] = m.fallback(source, prior[source.ID], "refresh timed out")
			}
		}(i, source)
	}
	wg.Wait()

	checked := time.Now().UTC().Format(time.RFC3339Nano)
	caches := make(map[string]sourceCache, len(results))
	statuses := make([]model.SourceStatus, len(results))
	var all []model.Node
	var missing bool
	for i, r := range results {
		id := m.cfg.Sources[i].ID
		statuses[i] = r.cache.Status
		if r.err != nil {
			missing = true
		}
		if r.cache.Status.SucceededAt != "" {
			caches[id] = r.cache
		}
		all = append(all, r.nodes...)
	}
	fail := func(err error) error {
		m.mu.Lock()
		m.status.CheckedAt = checked
		m.status.Sources = statuses
		m.status.LastError = err.Error()
		m.mu.Unlock()
		return err
	}
	if missing || len(all) == 0 {
		return fail(errors.New("no usable data for every configured source"))
	}
	if err := ctx.Err(); err != nil {
		return fail(errors.New("refresh timed out"))
	}
	profiles := make(map[string][]byte, len(m.cfg.Devices))
	usedRules := make(map[string]rulesets.Cache)
	ruleStatuses := make(map[string]model.SourceStatus)
	for _, d := range m.cfg.Devices {
		config, err := compose.Build(d, m.cfg.Policy, all)
		if err != nil {
			return fail(fmt.Errorf("config build failed: %w", err))
		}
		if len(config) == 0 {
			return fail(errors.New("config build returned empty output"))
		}
		resolved, assets, assetStatus, err := inlineRuleSets(ctx, config, availableRules, m.cfg.CheckBinary)
		for _, status := range assetStatus {
			ruleStatuses[status.ID] = status
		}
		if err != nil {
			for _, status := range assetStatus {
				statuses = append(statuses, status)
			}
			return fail(fmt.Errorf("rule-set preparation failed: %w", err))
		}
		for tag, asset := range assets {
			availableRules[tag] = asset
			usedRules[tag] = asset
		}
		config = resolved
		if m.cfg.CheckBinary != "" {
			if err := compose.Check(ctx, m.cfg.CheckBinary, config); err != nil {
				return fail(errors.New("config check failed"))
			}
		}
		profiles[d.ID] = config
	}
	if err := ctx.Err(); err != nil {
		return fail(errors.New("refresh timed out"))
	}
	statusIDs := make([]string, 0, len(ruleStatuses))
	for id := range ruleStatuses {
		statusIDs = append(statusIDs, id)
	}
	sort.Strings(statusIDs)
	for _, id := range statusIDs {
		statuses = append(statuses, ruleStatuses[id])
	}
	revision := hashProfiles(profiles)
	m.mu.RLock()
	publishedAt := m.status.PublishedAt
	previousRevision := m.status.Revision
	m.mu.RUnlock()
	if revision != previousRevision || publishedAt == "" {
		publishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	status := model.Status{CheckedAt: checked, PublishedAt: publishedAt, Revision: revision, Sources: statuses}
	if err := m.save(snapshot{Version: snapshotVersion, Sources: caches, RuleSets: usedRules, Profiles: profiles, Status: status}); err != nil {
		return fail(errors.New("snapshot write failed"))
	}
	m.mu.Lock()
	m.cache = caches
	m.ruleSets = usedRules
	m.profiles = profiles
	m.status = status
	m.mu.Unlock()
	return nil
}

func hashProfiles(profiles map[string][]byte) string {
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(h, "%d:%s:%d:", len(id), id, len(profiles[id]))
		h.Write(profiles[id])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) save(s snapshot) error {
	b, err := json.Marshal(s)
	if err != nil || len(b) > maxSnapshotBytes {
		return errors.New("snapshot exceeds limit")
	}
	f, err := os.CreateTemp(m.cfg.SnapshotDir, ".snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(m.cfg.SnapshotDir, snapshotFile)); err != nil {
		return err
	}
	dir, err := os.Open(m.cfg.SnapshotDir)
	if err == nil {
		// Rename commits the generation; a directory sync failure cannot undo it.
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (m *Manager) updateSource(ctx context.Context, s model.Source, old sourceCache) sourceResult {
	body, etag, modified, err := m.fetch(ctx, s, old)
	if err != nil {
		if s.Type == "ikuuu" {
			if errors.Is(err, ikuuu.ErrLoginRequired) {
				return m.fallback(s, old, "ikuuu login required; run the authorization command")
			}
			return m.fallback(s, old, "ikuuu profile fetch failed")
		}
		return m.fallback(s, old, "source fetch failed")
	}
	n, err := nodes.Parse(s, body, m.cfg.Policy.CountryOverrides)
	if err != nil {
		return m.fallback(s, old, "source parse failed: "+err.Error())
	}
	if len(n) == 0 {
		return m.fallback(s, old, "source returned no nodes")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := old.Status
	status.ID = s.ID
	status.CheckedAt = now
	status.SucceededAt = now
	status.Stale = false
	status.Error = ""
	status.NodeCount = len(n)
	if status.ChangedAt == "" || !bytes.Equal(body, old.Body) {
		status.ChangedAt = now
	}
	return sourceResult{cache: sourceCache{
		Fingerprint: m.fingerprints[s.ID], Body: body, ETag: etag, Modified: modified, Status: status,
	}, nodes: n}
}

func (m *Manager) fallback(s model.Source, old sourceCache, reason string) sourceResult {
	status := old.Status
	status.ID = s.ID
	status.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	status.Stale = true
	status.Error = reason
	old.Status = status
	old.Fingerprint = m.fingerprints[s.ID]
	if status.SucceededAt == "" || len(old.Body) == 0 {
		return sourceResult{cache: old, err: errors.New(reason)}
	}
	n, err := nodes.Parse(s, old.Body, m.cfg.Policy.CountryOverrides)
	if err != nil || len(n) == 0 {
		status.NodeCount = 0
		old.Status = status
		return sourceResult{cache: old, err: errors.New(reason)}
	}
	old.Status.NodeCount = len(n)
	return sourceResult{cache: old, nodes: n}
}

func (m *Manager) fetch(ctx context.Context, s model.Source, old sourceCache) ([]byte, string, string, error) {
	if s.Type == "ikuuu" {
		if m.appClient == nil {
			return nil, "", "", ikuuu.ErrLoginRequired
		}
		body, err := m.appClient.Fetch(ctx, s.ID, s.URL)
		return body, "", "", err
	}
	if s.File != "" {
		f, err := os.Open(s.File)
		if err != nil {
			return nil, "", "", err
		}
		defer f.Close()
		body, err := readLimited(f)
		return body, "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, "", "", err
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	if old.Status.SucceededAt != "" {
		if old.ETag != "" {
			req.Header.Set("If-None-Match", old.ETag)
		}
		if old.Modified != "" {
			req.Header.Set("If-Modified-Since", old.Modified)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && old.Status.SucceededAt != "" {
		return old.Body, old.ETag, old.Modified, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", "", errors.New("unexpected HTTP response")
	}
	body, err := readLimited(resp.Body)
	return body, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), err
}

func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSourceBytes {
		return nil, errors.New("source exceeds size limit")
	}
	return body, nil
}
