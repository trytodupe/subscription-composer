package ikuuu

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ttd/subscription-composer/internal/authstate"
)

const maxCallbackBytes = 64 << 10

// ParseCallback extracts an app credential from the login callback. The API
// address comes from the caller, never from the callback payload.
func ParseCallback(raw string, apiBaseURL string) (authstate.Session, error) {
	invalid := errors.New("invalid login callback")
	if len(raw) > maxCallbackBytes || len(raw) == 0 {
		return authstate.Session{}, invalid
	}
	base, err := clientBaseURL(apiBaseURL)
	if err != nil {
		return authstate.Session{}, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ikuuu" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Path != "/login" || u.RawPath != "" || u.Fragment != "" || strings.Contains(raw, "#") || u.ForceQuery {
		return authstate.Session{}, invalid
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) != 1 || len(query["token"]) != 1 || query.Get("token") == "" {
		return authstate.Session{}, invalid
	}
	encoded := query.Get("token")
	var payload []byte
	if strings.HasPrefix(encoded, "{") {
		payload = []byte(encoded)
	} else {
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			payload, err = encoding.DecodeString(encoded)
			if err == nil {
				break
			}
		}
		if err != nil {
			return authstate.Session{}, invalid
		}
	}
	if len(payload) > maxCallbackBytes || len(bytes.TrimSpace(payload)) == 0 {
		return authstate.Session{}, invalid
	}
	var token appTokenData
	if json.Unmarshal(payload, &token) != nil || !token.valid() {
		return authstate.Session{}, invalid
	}
	session := authstate.Session{AppToken: token.AppToken, APIBaseURL: base, ExpiresAt: token.ExpiresAt, TokenType: "Bearer"}
	if session.Validate() != nil {
		return authstate.Session{}, invalid
	}
	return session, nil
}

type appTokenData struct {
	SiteCode  string `json:"site_code"`
	UserID    string `json:"user_id"`
	TokenType string `json:"token_type"`
	ExpiresAt int64  `json:"expires_at"`
	IsActive  bool   `json:"is_active"`
	AppToken  string `json:"app_token"`
}

func (t appTokenData) valid() bool {
	return t.TokenType == "app" && t.IsActive && t.ExpiresAt > time.Now().Unix() &&
		strings.TrimSpace(t.AppToken) != "" && !hasControls(t.AppToken) &&
		strings.TrimSpace(t.SiteCode) != "" && strings.TrimSpace(t.UserID) != ""
}
