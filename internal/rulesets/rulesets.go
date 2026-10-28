// Package rulesets resolves native remote rule sets on the server before profiles are published.
// Downloads use the server's default HTTP transport (including HTTP_PROXY); a remote
// download_detour belongs to the client and does not affect these requests.
package rulesets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
)

const maxAssetBytes = 20 << 20

// Cache persists the last successfully decoded asset and its HTTP validators.
type Cache struct {
	Fingerprint string             `json:"fingerprint"`
	Body        []byte             `json:"body"`
	Rules       json.RawMessage    `json:"rules"`
	ETag        string             `json:"etag,omitempty"`
	Modified    string             `json:"modified,omitempty"`
	Status      model.SourceStatus `json:"status"`
}

type remote struct {
	Type           string          `json:"type"`
	Tag            string          `json:"tag"`
	URL            string          `json:"url"`
	Format         string          `json:"format"`
	HTTPClient     json.RawMessage `json:"http_client"`
	UpdateInterval string          `json:"update_interval"`
}

// Resolve replaces remote entries with native inline rules and returns a cache keyed
// by raw remote tag, plus statuses whose IDs use the "ruleset:" prefix. The caller
// must publish resolved only when err is nil. A matching last-good cache is used
// when fetching or decoding fails.
func Resolve(ctx context.Context, entries []json.RawMessage, prior map[string]Cache, binary string) (resolved []json.RawMessage, next map[string]Cache, statuses []model.SourceStatus, err error) {
	resolved = make([]json.RawMessage, 0, len(entries))
	next = make(map[string]Cache)
	seen := make(map[string]bool)
	for _, entry := range entries {
		var r remote
		if json.Unmarshal(entry, &r) != nil {
			return nil, next, statuses, errors.New("invalid rule set entry")
		}
		if r.Type != "remote" {
			resolved = append(resolved, entry)
			continue
		}
		if r.Tag == "" || seen[r.Tag] {
			return nil, next, statuses, errors.New("invalid or duplicate remote rule set tag")
		}
		seen[r.Tag] = true
		id := "ruleset:" + r.Tag
		hash := sha256.Sum256(entry)
		fingerprint := hex.EncodeToString(hash[:])
		old, valid := prior[r.Tag]
		valid = valid && old.Fingerprint == fingerprint && old.Status.ID == id && old.Status.SucceededAt != "" && len(old.Body) > 0 && len(old.Body) <= maxAssetBytes && validateRules(old.Rules) == nil
		if !valid {
			old = Cache{}
		}
		if r.UpdateInterval != "" {
			interval, parseErr := updateInterval(r.UpdateInterval)
			if parseErr != nil || interval <= 0 {
				return nil, next, statuses, errors.New("server rule set update_interval must be a positive duration, for example 24h")
			}
			if valid {
				lastSuccess, parseErr := time.Parse(time.RFC3339Nano, old.Status.SucceededAt)
				age := time.Since(lastSuccess)
				if parseErr == nil && age >= 0 && age < interval {
					next[r.Tag] = old
					statuses = append(statuses, old.Status)
					inline, marshalErr := json.Marshal(struct {
						Type  string          `json:"type"`
						Tag   string          `json:"tag"`
						Rules json.RawMessage `json:"rules"`
					}{"inline", r.Tag, old.Rules})
					if marshalErr != nil {
						return nil, next, statuses, errors.New("cannot encode inline rule set")
					}
					resolved = append(resolved, inline)
					continue
				}
			}
		}
		current, failure := resolveOne(ctx, r, fingerprint, id, old, valid, binary)
		statuses = append(statuses, current.Status)
		if failure != nil {
			return nil, next, statuses, failure
		}
		next[r.Tag] = current
		inline, marshalErr := json.Marshal(struct {
			Type  string          `json:"type"`
			Tag   string          `json:"tag"`
			Rules json.RawMessage `json:"rules"`
		}{Type: "inline", Tag: r.Tag, Rules: current.Rules})
		if marshalErr != nil {
			return nil, next, statuses, errors.New("cannot encode inline rule set")
		}
		resolved = append(resolved, inline)
	}
	return resolved, next, statuses, nil
}

func updateInterval(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(value, "d"), 64)
		if err != nil || math.IsNaN(days) || math.IsInf(days, 0) || days <= 0 || days >= float64(math.MaxInt64)/float64(24*time.Hour) {
			return 0, errors.New("invalid update interval")
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(value)
}

func resolveOne(ctx context.Context, r remote, fingerprint, id string, old Cache, valid bool, binary string) (Cache, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := old.Status
	status.ID = id
	status.CheckedAt = now
	fail := func(reason string) (Cache, error) {
		status.Stale = true
		status.Error = reason
		old.Status = status
		if valid && ctx.Err() == nil {
			return old, nil
		}
		return old, errors.New(reason)
	}
	reject := func(reason string) (Cache, error) {
		cached, _ := fail(reason)
		return cached, errors.New(reason)
	}
	parsedURL, urlErr := url.Parse(r.URL)
	if urlErr != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return reject("invalid remote rule set URL")
	}
	if len(r.HTTPClient) != 0 && string(bytes.TrimSpace(r.HTTPClient)) != "null" && string(bytes.TrimSpace(r.HTTPClient)) != "{}" {
		return reject("remote rule set http_client is unsupported")
	}
	format := r.Format
	if format == "" {
		format = "binary"
	}
	if format != "binary" && format != "source" {
		return reject("unsupported remote rule set format")
	}
	if format == "binary" && binary == "" {
		return reject("binary rule set requires a sing-box binary")
	}
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if requestErr != nil {
		return fail("invalid remote rule set request")
	}
	if valid {
		if old.ETag != "" {
			request.Header.Set("If-None-Match", old.ETag)
		}
		if old.Modified != "" {
			request.Header.Set("If-Modified-Since", old.Modified)
		}
	}
	response, fetchErr := (&http.Client{Transport: http.DefaultTransport}).Do(request)
	if fetchErr != nil {
		return fail("remote rule set fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if !valid {
			return fail("remote rule set returned 304 without cache")
		}
		status.SucceededAt = now
		status.Stale = false
		status.Error = ""
		old.Status = status
		return old, nil
	}
	if response.StatusCode != http.StatusOK {
		return fail("remote rule set fetch failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxAssetBytes+1))
	if readErr != nil || len(body) > maxAssetBytes {
		return fail("remote rule set exceeds limit or could not be read")
	}
	var rules json.RawMessage
	var decodeErr error
	if format == "source" {
		rules, decodeErr = decodeSource(body)
	} else {
		rules, decodeErr = decodeBinary(ctx, binary, body)
	}
	if decodeErr != nil {
		return fail("remote rule set decode failed")
	}
	status.SucceededAt = now
	status.Stale = false
	status.Error = ""
	status.NodeCount = 0
	if status.ChangedAt == "" || !bytes.Equal(body, old.Body) {
		status.ChangedAt = now
	}
	return Cache{Fingerprint: fingerprint, Body: body, Rules: rules, ETag: response.Header.Get("ETag"), Modified: response.Header.Get("Last-Modified"), Status: status}, nil
}

func decodeSource(body []byte) (json.RawMessage, error) {
	var source struct {
		Version json.RawMessage `json:"version"`
		Rules   json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(body, &source) != nil || len(source.Version) == 0 || source.Version[0] < '0' || source.Version[0] > '9' || validateRules(source.Rules) != nil {
		return nil, errors.New("invalid source rule set")
	}
	return source.Rules, nil
}

func validateRules(raw json.RawMessage) error {
	var rules []json.RawMessage
	if json.Unmarshal(raw, &rules) != nil || len(rules) == 0 || bytes.TrimSpace(raw)[0] != '[' {
		return errors.New("invalid rules array")
	}
	for _, rule := range rules {
		var object map[string]json.RawMessage
		if json.Unmarshal(rule, &object) != nil || object == nil {
			return errors.New("invalid rule")
		}
	}
	return nil
}

func decodeBinary(ctx context.Context, binary string, body []byte) (json.RawMessage, error) {
	dir, err := os.MkdirTemp("", "ruleset-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "input.srs")
	output := filepath.Join(dir, "output.json")
	if err := os.WriteFile(input, body, 0600); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, binary, "rule-set", "decompile", "--output", output, input)
	command.Dir = dir
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("rule set decompile failed")
	}
	file, err := os.Open(output)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAssetBytes {
		return nil, errors.New("decompiled rule set exceeds limit")
	}
	decoded, err := io.ReadAll(io.LimitReader(file, maxAssetBytes+1))
	if err != nil || len(decoded) > maxAssetBytes {
		return nil, errors.New("decompiled rule set exceeds limit")
	}
	return decodeSource(decoded)
}
