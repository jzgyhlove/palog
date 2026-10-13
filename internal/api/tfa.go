package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"palog/internal/store"
)

// totpIssuer is the label shown in the authenticator app beside the account.
const totpIssuer = "palog"

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a fresh 160-bit base32 secret (no padding), the
// format Google Authenticator and compatible apps expect.
func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpAt computes the RFC 6238 6-digit code for secret at time t (HMAC-SHA1,
// 30 s step) — the default profile of every TOTP app.
func totpAt(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off])&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000), nil
}

// verifyTOTP accepts a code for the previous, current or next 30 s step so a
// slightly skewed client clock still logs in.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now()
	for _, d := range []int{-1, 0, 1} {
		want, err := totpAt(secret, now.Add(time.Duration(d)*30*time.Second))
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// otpauthURI builds the otpauth:// URI that is encoded into the enrollment QR.
func otpauthURI(account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+account) + "?" + q.Encode()
}

// qrDataURI renders text as a PNG QR and returns it as a data: URI the browser
// can drop straight into an <img src>.
func qrDataURI(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 240)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

/* ---------------- handlers (self-service) ---------------- */

// handleTFASetup generates a new secret and returns it (with a QR) WITHOUT
// persisting it; the secret only sticks once handleTFAEnable verifies a code,
// so an abandoned setup leaves no half-enrolled account behind.
func (s *Server) handleTFASetup(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	uri := otpauthURI(u.Username, secret)
	qr, err := qrDataURI(uri)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":  secret,
		"otpauth": uri,
		"qr":      qr,
	})
}

// handleTFAEnable verifies a code against the submitted secret and, on
// success, enrolls it for the current user.
func (s *Server) handleTFAEnable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Secret) == "" || !verifyTOTP(in.Secret, in.Code) {
		writeErr(w, http.StatusBadRequest, "验证码错误,请重试")
		return
	}
	if err := s.Store.SetUserTFASecret(u.ID, strings.ToUpper(strings.TrimSpace(in.Secret))); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("two-factor enabled", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTFADisable clears the user's TOTP secret after re-checking the account
// password, so a borrowed session cannot silently strip two-factor.
func (s *Server) handleTFADisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	full, err := s.Store.GetUserByUsername(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if full == nil || !store.CheckPassword(full.PassHash, in.Password) {
		writeErr(w, http.StatusUnauthorized, "密码错误")
		return
	}
	if err := s.Store.SetUserTFASecret(u.ID, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("two-factor disabled", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
