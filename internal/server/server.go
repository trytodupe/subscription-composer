package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ttd/subscription-composer/internal/model"
	"github.com/ttd/subscription-composer/internal/refresh"
)

type Handler struct {
	manager *refresh.Manager
	tokens  map[string][32]byte
}

func New(manager *refresh.Manager, devices []model.Device) http.Handler {
	h := &Handler{manager: manager, tokens: make(map[string][32]byte, len(devices))}
	for _, d := range devices {
		h.tokens[d.ID] = sha256.Sum256([]byte(d.Token))
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/profiles/")
	if path == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(path, "/")
	id, operation := "", ""
	if len(parts) == 1 && strings.HasSuffix(parts[0], ".json") {
		id = strings.TrimSuffix(parts[0], ".json")
		operation = "profile"
	}
	if len(parts) == 2 && (parts[1] == "refresh" || parts[1] == "status") {
		id = parts[0]
		operation = parts[1]
	}
	if operation == "" {
		http.NotFound(w, r)
		return
	}
	if !h.authorized(id, r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="subscription", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	wantMethod := http.MethodGet
	if operation == "refresh" {
		wantMethod = http.MethodPost
	}
	if r.Method != wantMethod {
		w.Header().Set("Allow", wantMethod)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if operation == "status" {
		writeJSON(w, http.StatusOK, h.manager.Status())
		return
	}
	force := operation == "refresh" || r.URL.Query().Get("refresh") == "force"
	err := h.manager.Refresh(r.Context(), force)
	if r.Context().Err() != nil {
		return
	}
	status := h.manager.Status()
	stale := err != nil || status.LastError != ""
	for _, s := range status.Sources {
		stale = stale || s.Stale
	}
	w.Header().Set("X-Upstream-Checked-At", status.CheckedAt)
	w.Header().Set("X-Config-Published-At", status.PublishedAt)
	w.Header().Set("X-Config-Revision", status.Revision)
	if stale {
		w.Header().Set("X-Config-Stale", "true")
	} else {
		w.Header().Set("X-Config-Stale", "false")
	}
	if operation == "refresh" {
		code := http.StatusOK
		if err != nil {
			code = http.StatusBadGateway
		}
		writeJSON(w, code, status)
		return
	}
	body, ok := h.manager.Profile(id)
	if !ok {
		http.Error(w, "no validated configuration is available; check the authenticated status endpoint", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (h *Handler) authorized(id string, r *http.Request) bool {
	expected, exists := h.tokens[id]
	var token string
	if user, password, ok := r.BasicAuth(); ok && user == id {
		token = password
	} else if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	got := sha256.Sum256([]byte(token))
	match := subtle.ConstantTimeCompare(expected[:], got[:]) == 1
	return exists && token != "" && match
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
