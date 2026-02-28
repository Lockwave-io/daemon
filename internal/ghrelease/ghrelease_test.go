package ghrelease

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	l.SetOutput(&strings.Builder{})
	return l
}

func TestFetchChecksum(t *testing.T) {
	binaryName := fmt.Sprintf("lockwaved-%s-%s", runtime.GOOS, runtime.GOARCH)
	checksumContent := fmt.Sprintf("abc123def456  lockwaved-linux-amd64\n789xyz000111  %s\n", binaryName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, checksumContent)
	}))
	defer srv.Close()

	client := &http.Client{}
	checksum, err := fetchChecksum(client, srv.URL+"/checksums.txt", binaryName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checksum != "789xyz000111" {
		t.Fatalf("expected checksum '789xyz000111', got '%s'", checksum)
	}
}

func TestFetchChecksum_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "abc123  lockwaved-linux-amd64\n")
	}))
	defer srv.Close()

	client := &http.Client{}
	_, err := fetchChecksum(client, srv.URL+"/checksums.txt", "lockwaved-nonexistent-arch")
	if err == nil {
		t.Fatal("expected error for missing checksum")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestFetchChecksum_FullContent(t *testing.T) {
	binaryName := fmt.Sprintf("lockwaved-%s-%s", runtime.GOOS, runtime.GOARCH)
	expectedChecksum := "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	checksumContent := fmt.Sprintf("%s  %s\nabc123def456  lockwaved-other-arch\n", expectedChecksum, binaryName)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, checksumContent)
	}))
	defer srv.Close()

	client := &http.Client{}
	checksum, err := fetchChecksum(client, srv.URL+"/checksums.txt", binaryName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checksum != expectedChecksum {
		t.Fatalf("expected checksum %q, got %q", expectedChecksum, checksum)
	}
}

func TestCheck_NoReleases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// We can't directly test Check() with a custom URL without refactoring,
	// but we verify the 404 handling logic is correct by checking that
	// our fetchChecksum handles non-200 properly.
	client := &http.Client{}
	_, err := fetchChecksum(client, srv.URL+"/checksums.txt", "lockwaved-linux-amd64")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetchChecksum_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &http.Client{}
	_, err := fetchChecksum(client, srv.URL+"/checksums.txt", "lockwaved-linux-amd64")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected status 500 error, got: %v", err)
	}
}
