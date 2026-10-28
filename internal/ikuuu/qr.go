package ikuuu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxQRResponseBytes = 1 << 20

var safeAPICode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// QRClient calls the unauthenticated QR login endpoints.
type QRClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

type QRSession struct {
	ID        string `json:"qr_session_id"`
	PollToken string `json:"poll_token"`
	CodeText  string `json:"qr_code_text"`
	ExpiresAt int64  `json:"expires_at"`
}

// APIError exposes only the response status and a safe API code.
type APIError struct {
	Code   string
	Status int

	operation string
}

func (e *APIError) Error() string {
	if e == nil {
		return "ikuuu QR API error"
	}
	operation := e.operation
	if operation != "create" && operation != "poll" {
		operation = "request"
	}
	code := sanitizedCode(e.Code)
	return fmt.Sprintf("ikuuu QR %s: %s (HTTP %d)", operation, code, e.Status)
}

func sanitizedCode(code string) string {
	if !safeAPICode.MatchString(code) {
		return "INVALID_RESPONSE"
	}
	return code
}

func (c QRClient) Create(ctx context.Context) (QRSession, error) {
	var session QRSession
	data, status, err := c.request(ctx, "create", http.MethodPost, "/qr-auth/create-session", nil, []byte(`{"target":"app"}`))
	if err != nil {
		return session, err
	}
	if err := json.Unmarshal(data, &session); err != nil || !session.validCreate() {
		return QRSession{}, &APIError{Code: "INVALID_RESPONSE", Status: status, operation: "create"}
	}
	return session, nil
}

func (c QRClient) Poll(ctx context.Context, session QRSession) (json.RawMessage, error) {
	if !session.validPoll() {
		return nil, errors.New("invalid or expired QR session")
	}
	query := url.Values{"poll_token": {session.PollToken}}
	data, _, err := c.request(ctx, "poll", http.MethodGet, "/qr-auth/poll", query, nil)
	return data, err
}

func (s QRSession) validPoll() bool {
	return s.ID != "" && s.PollToken != "" && !hasControls(s.ID) && !hasControls(s.PollToken) && s.ExpiresAt > time.Now().Unix()
}

func (s QRSession) validCreate() bool {
	if !s.validPoll() || s.CodeText == "" {
		return false
	}
	code, err := url.Parse(s.CodeText)
	if err != nil || code.Scheme != "ikuuu" || code.Host != "qr-login" || code.User != nil || code.Opaque != "" || code.Path != "" || code.Fragment != "" || strings.Contains(s.CodeText, "#") || code.ForceQuery {
		return false
	}
	values, err := url.ParseQuery(code.RawQuery)
	return err == nil && len(values) == 1 && len(values["sid"]) == 1 && values.Get("sid") == s.ID
}

func hasControls(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func (c QRClient) request(ctx context.Context, operation, method, endpoint string, query url.Values, body []byte) (json.RawMessage, int, error) {
	if ctx == nil {
		return nil, 0, errors.New("invalid QR request")
	}
	base, err := qrBaseURL(c.BaseURL)
	if err != nil {
		return nil, 0, err
	}
	base.Path = strings.TrimRight(base.Path, "/") + endpoint
	base.RawPath = ""
	base.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("invalid QR request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.Client{Timeout: 15 * time.Second}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, errors.New("ikuuu QR request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, &APIError{Code: "HTTP_ERROR", Status: resp.StatusCode, operation: operation}
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxQRResponseBytes+1))
	if err != nil || len(payload) > maxQRResponseBytes {
		return nil, resp.StatusCode, &APIError{Code: "INVALID_RESPONSE", Status: resp.StatusCode, operation: operation}
	}
	var envelope struct {
		Success *bool           `json:"success"`
		Code    string          `json:"code"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(payload, &envelope) != nil || envelope.Success == nil || envelope.Code == "" {
		return nil, resp.StatusCode, &APIError{Code: "INVALID_RESPONSE", Status: resp.StatusCode, operation: operation}
	}
	if !*envelope.Success || envelope.Code != "SUCCESS" {
		return nil, resp.StatusCode, &APIError{Code: sanitizedCode(envelope.Code), Status: resp.StatusCode, operation: operation}
	}
	data := bytes.TrimSpace(envelope.Data)
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return nil, resp.StatusCode, &APIError{Code: "INVALID_RESPONSE", Status: resp.StatusCode, operation: operation}
	}
	return envelope.Data, resp.StatusCode, nil
}

func qrBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "?") || u.Fragment != "" || strings.Contains(raw, "#") || u.RawPath != "" {
		return nil, errors.New("invalid QR base URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (!strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("invalid QR base URL")
		}
	}
	return u, nil
}
