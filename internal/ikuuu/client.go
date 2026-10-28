package ikuuu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
)

const (
	maxClientResponseBytes = 8 << 20
	defaultRefreshBefore   = 24 * time.Hour
)

var ErrLoginRequired = errors.New("ikuuu login required")

type Client struct {
	Store         *authstate.Store
	HTTPClient    *http.Client
	RefreshBefore time.Duration
}

type authAPIError struct {
	status int
	code   string
}

func (e *authAPIError) Error() string {
	return fmt.Sprintf("ikuuu API: %s (HTTP %d)", e.code, e.status)
}

func clientBaseURL(raw string) (string, error) {
	u, err := qrBaseURL(raw)
	if err != nil || u.EscapedPath() != u.Path || strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") || strings.Contains(u.Path, "/./") || strings.HasSuffix(u.Path, "/.") || hasControls(raw) {
		return "", errors.New("invalid ikuuu API base URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func (c *Client) validate() error {
	if c == nil || c.Store == nil {
		return errors.New("invalid ikuuu client")
	}
	return nil
}

// Import verifies the callback token and saves a device identity before
// rotating it. Both writes are durable while the account lock is held.
func (c *Client) Import(ctx context.Context, account string, session authstate.Session) (authstate.Session, error) {
	if err := c.validate(); err != nil {
		return authstate.Session{}, err
	}
	if ctx == nil {
		return authstate.Session{}, errors.New("invalid ikuuu context")
	}
	base, err := clientBaseURL(session.APIBaseURL)
	if err != nil || session.Validate() != nil || (session.TokenType != "" && session.TokenType != "Bearer") {
		return authstate.Session{}, errors.New("invalid ikuuu session")
	}
	session.APIBaseURL = base
	session.TokenType = "Bearer"
	var imported authstate.Session
	err = c.Store.WithLock(ctx, account, func() error {
		info, err := c.tokenInfo(ctx, session)
		if err != nil {
			return err
		}
		if info.AppToken != session.AppToken {
			return errors.New("ikuuu token verification failed")
		}
		session.ExpiresAt = info.ExpiresAt
		if session.DeviceID == "" {
			session.DeviceID, err = newDeviceID()
			if err != nil {
				return err
			}
			session.DeviceName = "Subscription Composer"
		}
		if err := c.Store.Save(account, session); err != nil {
			return err
		}
		imported, err = c.refresh(ctx, account, session)
		return err
	})
	return imported, err
}

// Fetch uses the stored credential for this API and returns the profile YAML.
func (c *Client) Fetch(ctx context.Context, account string, apiBaseURL string) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("invalid ikuuu context")
	}
	base, err := clientBaseURL(apiBaseURL)
	if err != nil {
		return nil, err
	}
	var profile []byte
	err = c.Store.WithLock(ctx, account, func() error {
		session, err := c.Store.Load(account)
		if errors.Is(err, authstate.ErrNotFound) {
			return ErrLoginRequired
		}
		if err != nil {
			return err
		}
		storedBase, err := clientBaseURL(session.APIBaseURL)
		if err != nil || storedBase != base {
			return errors.New("ikuuu API base URL mismatch")
		}
		session.APIBaseURL = base
		refreshed := false
		before := c.RefreshBefore
		if before == 0 {
			before = defaultRefreshBefore
		}
		if session.DeviceID == "" || session.ExpiresAt <= time.Now().Add(before).Unix() {
			session, err = c.prepareAndRefresh(ctx, account, session)
			if err != nil {
				return err
			}
			refreshed = true
		}
		profile, err = c.profile(ctx, session)
		if isUnauthorized(err) && !refreshed {
			session, err = c.prepareAndRefresh(ctx, account, session)
			if err != nil {
				return err
			}
			profile, err = c.profile(ctx, session)
		}
		if isUnauthorized(err) {
			return ErrLoginRequired
		}
		return err
	})
	return profile, err
}

func (c *Client) prepareAndRefresh(ctx context.Context, account string, session authstate.Session) (authstate.Session, error) {
	if session.DeviceID == "" {
		id, err := newDeviceID()
		if err != nil {
			return authstate.Session{}, err
		}
		session.DeviceID = id
		session.DeviceName = "Subscription Composer"
		if err := c.Store.Save(account, session); err != nil {
			return authstate.Session{}, err
		}
	}
	return c.refresh(ctx, account, session)
}

func (c *Client) refresh(ctx context.Context, account string, session authstate.Session) (authstate.Session, error) {
	body, err := json.Marshal(struct {
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
	}{session.DeviceID, session.DeviceName})
	if err != nil {
		return authstate.Session{}, errors.New("invalid ikuuu device")
	}
	data, err := c.request(ctx, session, http.MethodPost, "/client-auth/refresh-app-token", body)
	if isUnauthorized(err) {
		return authstate.Session{}, ErrLoginRequired
	}
	if err != nil {
		return authstate.Session{}, err
	}
	var token appTokenData
	if json.Unmarshal(data, &token) != nil || !token.valid() || token.AppToken == session.AppToken {
		return authstate.Session{}, errors.New("invalid ikuuu refresh response")
	}
	session.AppToken = token.AppToken
	session.ExpiresAt = token.ExpiresAt
	if err := c.Store.Save(account, session); err != nil {
		return authstate.Session{}, err
	}
	return session, nil
}

func (c *Client) tokenInfo(ctx context.Context, session authstate.Session) (appTokenData, error) {
	var token appTokenData
	data, err := c.request(ctx, session, http.MethodGet, "/client-auth/token-info", nil)
	if isUnauthorized(err) {
		return token, ErrLoginRequired
	}
	if err != nil {
		return token, err
	}
	if json.Unmarshal(data, &token) != nil || !token.valid() {
		return appTokenData{}, ErrLoginRequired
	}
	return token, nil
}

func (c *Client) profile(ctx context.Context, session authstate.Session) ([]byte, error) {
	data, err := c.request(ctx, session, http.MethodGet, "/nodes/profile", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		UserID  string `json:"user_id"`
		Profile string `json:"profile"`
	}
	if json.Unmarshal(data, &result) != nil || result.UserID == "" || result.Profile == "" {
		return nil, errors.New("invalid ikuuu profile response")
	}
	return []byte(result.Profile), nil
}

func isUnauthorized(err error) bool {
	var apiErr *authAPIError
	return errors.As(err, &apiErr) && (apiErr.status == http.StatusUnauthorized || apiErr.code == "TOKEN_INVALID" || apiErr.code == "TOKEN_EXPIRED")
}

func (c *Client) request(ctx context.Context, session authstate.Session, method, endpoint string, body []byte) (json.RawMessage, error) {
	base, err := url.Parse(session.APIBaseURL)
	if err != nil {
		return nil, errors.New("invalid ikuuu API base URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + endpoint
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid ikuuu request")
	}
	req.Header.Set("Authorization", "Bearer "+session.AppToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.Client{}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			if method == http.MethodPost {
				return nil, fmt.Errorf("ikuuu refresh outcome unknown; stored credential unchanged: %w", ctx.Err())
			}
			return nil, ctx.Err()
		}
		if method == http.MethodPost {
			return nil, errors.New("ikuuu refresh outcome unknown; stored credential unchanged")
		}
		return nil, errors.New("ikuuu request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &authAPIError{resp.StatusCode, "TOKEN_INVALID"}
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxClientResponseBytes+1))
	if err != nil || len(payload) > maxClientResponseBytes {
		return nil, errors.New("invalid ikuuu API response")
	}
	var envelope struct {
		Success *bool           `json:"success"`
		Code    string          `json:"code"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(payload, &envelope) != nil || envelope.Success == nil || envelope.Code == "" {
		return nil, &authAPIError{resp.StatusCode, "INVALID_RESPONSE"}
	}
	code := "HTTP_ERROR"
	if envelope.Code == "TOKEN_INVALID" || envelope.Code == "TOKEN_EXPIRED" {
		code = envelope.Code
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !*envelope.Success || envelope.Code != "SUCCESS" {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && code == "HTTP_ERROR" {
			code = "API_ERROR"
		}
		return nil, &authAPIError{resp.StatusCode, code}
	}
	data := bytes.TrimSpace(envelope.Data)
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return nil, &authAPIError{resp.StatusCode, "INVALID_RESPONSE"}
	}
	return envelope.Data, nil
}

func newDeviceID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errors.New("cannot create ikuuu device identity")
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	var encoded [36]byte
	hex.Encode(encoded[0:8], id[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], id[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], id[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], id[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], id[10:16])
	return string(encoded[:]), nil
}
