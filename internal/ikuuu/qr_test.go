package ikuuu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testQRSession() QRSession {
	return QRSession{ID: "session-1", PollToken: "secret +&?/#=token", CodeText: "ikuuu://qr-login?sid=session-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func responseEnvelope(data string) string {
	return `{"success":true,"code":"SUCCESS","msg":"Success","data":` + data + `}`
}

func TestCreateAndPoll(t *testing.T) {
	session := testQRSession()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected authentication")
		}
		switch r.URL.Path {
		case "/api/v2/qr-auth/create-session":
			if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("incorrect create request: method=%s content-type=%s", r.Method, r.Header.Get("Content-Type"))
			}
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || string(body["target"]) != `"app"` {
				t.Error("incorrect create body")
			}
			data, _ := json.Marshal(session)
			fmt.Fprint(w, responseEnvelope(string(data)))
		case "/api/v2/qr-auth/poll":
			if r.Method != http.MethodGet || len(r.URL.Query()) != 1 || r.URL.Query().Get("poll_token") != session.PollToken || r.URL.RawQuery != "poll_token="+url.QueryEscape(session.PollToken) {
				t.Error("incorrect poll request")
			}
			fmt.Fprint(w, responseEnvelope(`{"status":"pending"}`))
		default:
			t.Error("unexpected route")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := QRClient{BaseURL: server.URL + "/api/v2/"}
	created, err := client.Create(context.Background())
	if err != nil || created != session {
		t.Fatalf("create failed: %v", err)
	}
	data, err := client.Poll(context.Background(), created)
	if err != nil || string(data) != `{"status":"pending"}` {
		t.Fatalf("poll failed: %v, %s", err, data)
	}
}

func TestPollKeepsCompletedDataOpaque(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, responseEnvelope(`{"status":"complete","unknown":{"future":true}}`))
	}))
	defer server.Close()
	data, err := (QRClient{BaseURL: server.URL}).Poll(context.Background(), testQRSession())
	if err != nil || string(data) != `{"status":"complete","unknown":{"future":true}}` {
		t.Fatalf("unexpected data: %s, %v", data, err)
	}
}

func TestRejectInvalidBaseURLs(t *testing.T) {
	for _, base := range []string{
		"", "http://example.org/api/v2", "http://192.0.2.1/api/v2", "ftp://example.org", "https://user:secret@example.org/api/v2", "https://example.org/api/v2?poll_token=secret", "https://example.org/api/v2#secret", "https://example.org/api/v2#", "https://example.org/api/v2?", "https://example.org/api%2fv2",
	} {
		t.Run(base, func(t *testing.T) {
			_, err := (QRClient{BaseURL: base}).Create(context.Background())
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "example.org") {
				t.Fatalf("invalid base accepted or leaked: %v", err)
			}
		})
	}
	for _, base := range []string{"http://localhost:8080/api/v2", "http://127.0.0.2/api/v2", "http://[::1]:8080/api/v2", "https://example.org/api/v2"} {
		if _, err := qrBaseURL(base); err != nil {
			t.Fatalf("valid base rejected: %v", err)
		}
	}
}

func TestRejectInvalidAndExpiredSessions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid session reached server")
	}))
	defer server.Close()
	client := QRClient{BaseURL: server.URL}
	for _, mutation := range []func(*QRSession){
		func(s *QRSession) { s.ID = "" },
		func(s *QRSession) { s.PollToken = "" },
		func(s *QRSession) { s.PollToken = "bad\nvalue" },
		func(s *QRSession) { s.ExpiresAt = time.Now().Add(-time.Second).Unix() },
	} {
		session := testQRSession()
		mutation(&session)
		if _, err := client.Poll(context.Background(), session); err == nil || (session.PollToken != "" && strings.Contains(err.Error(), session.PollToken)) {
			t.Fatalf("invalid session accepted or leaked: %v", err)
		}
	}
}

func TestRejectMalformedCreateData(t *testing.T) {
	valid := testQRSession()
	for _, mutation := range []func(*QRSession){
		func(s *QRSession) { s.ID = "" },
		func(s *QRSession) { s.PollToken = "" },
		func(s *QRSession) { s.ExpiresAt = time.Now().Add(-time.Second).Unix() },
		func(s *QRSession) { s.CodeText = "" },
		func(s *QRSession) { s.CodeText = "https://qr-login?sid=session-1" },
		func(s *QRSession) { s.CodeText = "ikuuu://other?sid=session-1" },
		func(s *QRSession) { s.CodeText = "ikuuu://qr-login?sid=other" },
		func(s *QRSession) { s.CodeText = "ikuuu://qr-login?sid=session-1&extra=1" },
		func(s *QRSession) { s.CodeText = "ikuuu://qr-login?sid=session-1#fragment" },
	} {
		session := valid
		mutation(&session)
		data, _ := json.Marshal(session)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, responseEnvelope(string(data)))
		}))
		_, err := (QRClient{BaseURL: server.URL}).Create(context.Background())
		server.Close()
		if err == nil {
			t.Fatalf("invalid create data accepted: %s", data)
		}
	}
}

func TestErrorsAreRedactedAndResponsesBounded(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{
		{http.StatusNotFound, `{"msg":"secret-message"}`, "HTTP_ERROR"},
		{http.StatusUnauthorized, `{"success":false,"code":"SECRET_LEAK","msg":"secret-message"}`, "HTTP_ERROR"},
		{http.StatusOK, `{"success":false,"code":"AUTH_PENDING","msg":"secret-message","data":{}}`, "AUTH_PENDING"},
		{http.StatusOK, `{"success":false,"code":"secret-message","msg":"secret-message"}`, "INVALID_RESPONSE"},
		{http.StatusOK, `{"success":true,"code":"SUCCESS","data":null}`, "INVALID_RESPONSE"},
		{http.StatusOK, `{"success":true,"code":"SUCCESS","data":[]}`, "INVALID_RESPONSE"},
		{http.StatusOK, `{"success":true,"data":{}}`, "INVALID_RESPONSE"},
		{http.StatusOK, `{"code":"SUCCESS","data":{}}`, "INVALID_RESPONSE"},
		{http.StatusOK, `{"success":true,"code":"SUCCESS","data":{}} trailing`, "INVALID_RESPONSE"},
		{http.StatusOK, strings.Repeat("x", maxQRResponseBytes+1), "INVALID_RESPONSE"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		}))
		_, err := (QRClient{BaseURL: server.URL}).Poll(context.Background(), testQRSession())
		server.Close()
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != tc.code || apiErr.Status != tc.status {
			t.Fatalf("wrong API error: %v", err)
		}
		for _, secret := range []string{"secret-message", "SECRET_LEAK", server.URL, "secret +&?/#=token"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("secret leaked in error: %v", err)
			}
		}
	}
}

func TestRedirectNeverFollowed(t *testing.T) {
	var followed bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
	}))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/received?poll_token=secret", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := QRClient{BaseURL: server.URL, HTTPClient: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		t.Error("caller redirect policy was used")
		return nil
	}}}
	_, err := client.Poll(context.Background(), testQRSession())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTemporaryRedirect || followed {
		t.Fatalf("redirect followed or incorrectly handled: %v", err)
	}
}

func TestCreateErrorUsesActualHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, responseEnvelope(`{}`))
	}))
	defer server.Close()
	_, err := (QRClient{BaseURL: server.URL}).Create(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusCreated {
		t.Fatalf("wrong response status: %v", err)
	}
}

func TestCanceledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("canceled request reached server")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (QRClient{BaseURL: server.URL}).Create(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTransportErrorsAreRedacted(t *testing.T) {
	client := QRClient{
		BaseURL: "https://example.org/api/v2",
		HTTPClient: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("secret +&?/#=token https://example.org/unsafe")
		})},
	}
	_, err := client.Poll(context.Background(), testQRSession())
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "example.org") {
		t.Fatalf("transport detail leaked: %v", err)
	}
}
