package ghrelease

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultRepo is the GitHub repository for the daemon.
	DefaultRepo = "lockwave-io/lockwaved"

	// releaseAPIURL is the GitHub API endpoint for the latest release.
	releaseAPIURL = "https://api.github.com/repos/%s/releases/latest"
)

const httpTimeout = 30 * time.Second

// Release holds the parsed information from a GitHub release.
type Release struct {
	Version  string // Tag name without leading "v"
	URL      string // Direct download URL for the current OS/arch binary
	Checksum string // SHA-256 hex digest from checksums.txt
}

// githubRelease is the subset of GitHub's release API response we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset is a single file attached to a GitHub release.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Check queries the GitHub Releases API for the latest release and returns
// a Release with the download URL and checksum for the current OS/arch.
// Returns nil if no suitable release is found (no matching binary or no checksums).
func Check(repo string, logger *logrus.Logger) (*Release, error) {
	if repo == "" {
		repo = DefaultRepo
	}

	url := fmt.Sprintf(releaseAPIURL, repo)
	client := &http.Client{Timeout: httpTimeout}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ghrelease: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "lockwaved")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghrelease: fetch latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		logger.Debug("ghrelease: no releases found")
		return nil, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("ghrelease: rate limited (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("ghrelease: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("ghrelease: decode response: %w", err)
	}

	version := strings.TrimPrefix(rel.TagName, "v")
	if version == "" {
		return nil, fmt.Errorf("ghrelease: empty version in tag %q", rel.TagName)
	}

	// Find the binary for current OS/arch
	binaryName := fmt.Sprintf("lockwaved-%s-%s", runtime.GOOS, runtime.GOARCH)
	var binaryURL string
	var checksumsURL string

	for _, asset := range rel.Assets {
		if asset.Name == binaryName {
			binaryURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.BrowserDownloadURL
		}
	}

	if binaryURL == "" {
		logger.WithFields(logrus.Fields{
			"version": version,
			"binary":  binaryName,
		}).Debug("ghrelease: no matching binary in release")
		return nil, nil
	}

	if checksumsURL == "" {
		return nil, fmt.Errorf("ghrelease: checksums.txt not found in release %s", version)
	}

	// Download and parse checksums.txt
	checksum, err := fetchChecksum(client, checksumsURL, binaryName)
	if err != nil {
		return nil, err
	}

	return &Release{
		Version:  version,
		URL:      binaryURL,
		Checksum: checksum,
	}, nil
}

// fetchChecksum downloads checksums.txt and extracts the SHA-256 for the given filename.
func fetchChecksum(client *http.Client, url, filename string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("ghrelease: build checksum request: %w", err)
	}
	req.Header.Set("User-Agent", "lockwaved")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ghrelease: fetch checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ghrelease: checksums.txt returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("ghrelease: read checksums: %w", err)
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<sha256>  <filename>" (two spaces, sha256sum standard output)
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			return parts[0], nil
		}
	}

	return "", fmt.Errorf("ghrelease: checksum for %s not found in checksums.txt", filename)
}
