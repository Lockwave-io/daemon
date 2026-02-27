package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignedHeaders_ContainsAllRequiredHeaders(t *testing.T) {
	signer := NewSigner("test-credential-secret")

	headers, err := signer.SignedHeaders("POST", "api/daemon/v1/sync", []byte(`{"test":"data"}`), "host-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	required := []string{"X-Daemon-Signature", "X-Daemon-Host-Id", "X-Daemon-Timestamp", "X-Daemon-Nonce"}
	for _, key := range required {
		if headers[key] == "" {
			t.Errorf("missing header %s", key)
		}
	}

	if headers["X-Daemon-Host-Id"] != "host-123" {
		t.Errorf("host-id = %q, want %q", headers["X-Daemon-Host-Id"], "host-123")
	}
}

func TestSignedHeaders_SignatureIsValidHMAC(t *testing.T) {
	credential := "my-secret-key"
	signer := NewSigner(credential)

	body := []byte(`{"host_id":"abc"}`)
	method := "POST"
	path := "api/daemon/v1/sync"

	headers, err := signer.SignedHeaders(method, path, body, "host-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reconstruct the signing string
	bodyHash := sha256Hex(body)
	signingString := strings.Join([]string{
		method,
		path,
		bodyHash,
		headers["X-Daemon-Timestamp"],
		headers["X-Daemon-Nonce"],
	}, "\n")

	mac := hmac.New(sha256.New, []byte(credential))
	mac.Write([]byte(signingString))
	expected := hex.EncodeToString(mac.Sum(nil))

	if headers["X-Daemon-Signature"] != expected {
		t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", headers["X-Daemon-Signature"], expected)
	}
}

func TestSignedHeaders_DifferentBodiesProduceDifferentSignatures(t *testing.T) {
	signer := NewSigner("credential")

	h1, _ := signer.SignedHeaders("POST", "path", []byte("body1"), "host")
	h2, _ := signer.SignedHeaders("POST", "path", []byte("body2"), "host")

	if h1["X-Daemon-Signature"] == h2["X-Daemon-Signature"] {
		t.Error("different bodies produced same signature")
	}
}

func TestSignedHeaders_NonceIsUnique(t *testing.T) {
	signer := NewSigner("credential")

	h1, _ := signer.SignedHeaders("POST", "path", []byte("body"), "host")
	h2, _ := signer.SignedHeaders("POST", "path", []byte("body"), "host")

	if h1["X-Daemon-Nonce"] == h2["X-Daemon-Nonce"] {
		t.Error("nonces should be unique between calls")
	}
}
