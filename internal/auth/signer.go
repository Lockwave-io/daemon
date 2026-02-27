package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Signer produces HMAC-SHA256 signatures for daemon API requests.
type Signer struct {
	credential string
}

// NewSigner creates a signer with the given credential secret.
func NewSigner(credential string) *Signer {
	return &Signer{credential: credential}
}

// SignedHeaders returns the HTTP headers needed for an authenticated request.
// The signing string is: method + "\n" + path + "\n" + sha256(body) + "\n" + timestamp + "\n" + nonce
func (s *Signer) SignedHeaders(method, path string, body []byte, hostID string) (map[string]string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("auth: generate nonce: %w", err)
	}

	bodyHash := sha256Hex(body)

	signingString := strings.Join([]string{
		method,
		path,
		bodyHash,
		timestamp,
		nonce,
	}, "\n")

	mac := hmac.New(sha256.New, []byte(s.credential))
	mac.Write([]byte(signingString))
	signature := hex.EncodeToString(mac.Sum(nil))

	return map[string]string{
		"X-Daemon-Signature": signature,
		"X-Daemon-Host-Id":   hostID,
		"X-Daemon-Timestamp": timestamp,
		"X-Daemon-Nonce":     nonce,
	}, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
