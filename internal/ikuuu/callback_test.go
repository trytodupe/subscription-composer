package ikuuu

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func callbackToken() string {
	return `{"site_code":"site","user_id":"user","token_type":"app","expires_at":` +
		formatExpiry(time.Now().Add(48*time.Hour).Unix()) +
		`,"is_active":true,"created_at":1,"last_used_at":null,"app_token":"callback-secret"}`
}

func formatExpiry(expiry int64) string {
	data, _ := json.Marshal(expiry)
	return string(data)
}

func TestParseCallbackFormatsAndBoundaries(t *testing.T) {
	base := "https://authcode.iku-client-comm-1.win/api/v2/"
	payload := callbackToken()
	for len(payload)%3 == 0 {
		payload += " "
	}
	for _, token := range []string{payload, base64.RawURLEncoding.EncodeToString([]byte(payload)), base64.URLEncoding.EncodeToString([]byte(payload)), base64.RawStdEncoding.EncodeToString([]byte(payload)), base64.StdEncoding.EncodeToString([]byte(payload))} {
		session, err := ParseCallback("ikuuu:///login?token="+url.QueryEscape(token), base)
		if err != nil || session.AppToken != "callback-secret" || session.TokenType != "Bearer" || session.APIBaseURL != strings.TrimSuffix(base, "/") {
			t.Fatalf("valid callback rejected: %v, %+v", err, session)
		}
	}
	for _, raw := range []string{
		"ikuuu://login?token=" + url.QueryEscape(payload),
		"ikuuu://user@host/login?token=" + url.QueryEscape(payload),
		"ikuuu:///other?token=" + url.QueryEscape(payload),
		"ikuuu:///login?token=a&token=b",
		"ikuuu:///login?token=" + url.QueryEscape(payload) + "#fragment",
		"ikuuu:///login?token=" + url.QueryEscape(strings.Replace(payload, `"is_active":true`, `"is_active":false`, 1)),
		"ikuuu:///login?token=" + url.QueryEscape(strings.Replace(payload, `"token_type":"app"`, `"token_type":"web"`, 1)),
		"ikuuu:///login?token=" + url.QueryEscape(strings.Replace(payload, `"expires_at":`+formatExpiry(time.Now().Add(48*time.Hour).Unix()), `"expires_at":1`, 1)),
		"ikuuu:///login?token=" + url.QueryEscape(strings.Replace(payload, `"app_token":"callback-secret"`, `"app_token":""`, 1)),
		strings.Repeat("x", maxCallbackBytes+1),
	} {
		_, err := ParseCallback(raw, base)
		if err == nil || strings.Contains(err.Error(), "callback-secret") || strings.Contains(err.Error(), "authcode.") {
			t.Fatalf("invalid callback accepted or leaked: %v", err)
		}
	}
	if _, err := ParseCallback("ikuuu:///login?token="+url.QueryEscape(payload), "http://example.org/api/v2"); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
}
