package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// captchaTTL bounds how long an issued login challenge stays valid.
const captchaTTL = 3 * time.Minute

type captchaEntry struct {
	answer  int64
	expires time.Time
}

// captchaEnabled reports whether the arithmetic login captcha is turned on.
func (s *Server) captchaEnabled() bool {
	cfg, err := s.Store.GetConfig(s.DBPath)
	return err == nil && cfg.Captcha
}

// issueCaptcha stores a fresh arithmetic challenge and returns its id and
// question text. An empty id means generation failed.
func (s *Server) issueCaptcha() (id, question string) {
	a, b := randInt(2, 19), randInt(2, 19)
	var answer int64
	switch randInt(0, 2) {
	case 0:
		answer = int64(a + b)
		question = fmt.Sprintf("%d + %d = ?", a, b)
	case 1:
		if a < b {
			a, b = b, a
		}
		answer = int64(a - b)
		question = fmt.Sprintf("%d - %d = ?", a, b)
	default:
		answer = int64(a * b)
		question = fmt.Sprintf("%d × %d = ?", a, b)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", ""
	}
	id = hex.EncodeToString(raw)
	now := time.Now()
	s.capMu.Lock()
	if s.captchas == nil {
		s.captchas = make(map[string]captchaEntry)
	}
	for k, v := range s.captchas { // opportunistic sweep
		if now.After(v.expires) {
			delete(s.captchas, k)
		}
	}
	s.captchas[id] = captchaEntry{answer: answer, expires: now.Add(captchaTTL)}
	s.capMu.Unlock()
	return id, question
}

// consumeCaptcha validates and removes a challenge (single use).
func (s *Server) consumeCaptcha(id, answer string) bool {
	if id == "" {
		return false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(answer), 10, 64)
	if err != nil {
		return false
	}
	now := time.Now()
	s.capMu.Lock()
	defer s.capMu.Unlock()
	e, ok := s.captchas[id]
	if !ok {
		return false
	}
	delete(s.captchas, id)
	if now.After(e.expires) {
		return false
	}
	return e.answer == n
}

func randInt(min, max int) int {
	span := max - min + 1
	if span <= 1 {
		return min
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return min
	}
	return min + int(v.Int64())
}

// handleCaptcha issues a login challenge; when the captcha is disabled it
// returns {"enabled": false} so the login form can hide the field.
func (s *Server) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if !s.captchaEnabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	id, question := s.issueCaptcha()
	if id == "" {
		writeErr(w, http.StatusInternalServerError, "captcha unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  true,
		"id":       id,
		"question": question,
	})
}
