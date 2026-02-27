package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lockwave-io/daemon/internal/auth"
	"github.com/lockwave-io/daemon/internal/state"
)

// Client communicates with the Lockwave control plane.
type Client struct {
	baseURL    string
	hostID     string
	signer     *auth.Signer
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new API client.
func NewClient(baseURL, hostID, credential string, logger *slog.Logger) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		hostID:  hostID,
		signer:  auth.NewSigner(credential),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// Register performs the initial host registration using an enrollment token.
// This is called once during setup and does not require HMAC signing.
func Register(ctx context.Context, apiURL, token string, hostInfo state.HostInfo, users []state.UserEntry, logger *slog.Logger) (*state.RegisterResponse, error) {
	reqBody := state.RegisterRequest{
		EnrollmentToken: token,
		Host:            hostInfo,
		ManagedUsers:    users,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("api: marshal register request: %w", err)
	}

	endpoint := strings.TrimRight(apiURL, "/") + "/api/daemon/v1/register"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("api: create register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api: register request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("api: read register response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("api: register failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result state.RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("api: parse register response: %w", err)
	}

	return &result, nil
}

// Sync sends the current host status and retrieves desired state.
func (c *Client) Sync(ctx context.Context, syncReq *state.SyncRequest) (*state.SyncResponse, error) {
	body, err := json.Marshal(syncReq)
	if err != nil {
		return nil, fmt.Errorf("api: marshal sync request: %w", err)
	}

	path := "api/daemon/v1/sync"
	endpoint := c.baseURL + "/" + path

	return c.doWithRetry(ctx, http.MethodPost, endpoint, path, body, func(respBody []byte) (*state.SyncResponse, error) {
		var result state.SyncResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("api: parse sync response: %w", err)
		}
		return &result, nil
	})
}

// doWithRetry executes a signed request with exponential backoff retries.
func (c *Client) doWithRetry(ctx context.Context, method, endpoint, path string, body []byte, parse func([]byte) (*state.SyncResponse, error)) (*state.SyncResponse, error) {
	const maxRetries = 3

	for attempt := range maxRetries {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			c.logger.Info("retrying request", "attempt", attempt+1, "backoff", backoff)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		headers, err := c.signer.SignedHeaders(method, path, body, c.hostID)
		if err != nil {
			return nil, fmt.Errorf("api: sign request: %w", err)
		}

		parsedURL, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("api: parse endpoint URL: %w", err)
		}
		if parsedURL.Scheme != "https" && !strings.Contains(parsedURL.Host, "localhost") && !strings.Contains(parsedURL.Host, "127.0.0.1") {
			return nil, fmt.Errorf("api: refusing non-TLS endpoint %s (TLS required)", endpoint)
		}

		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("api: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.logger.Warn("request failed", "error", err, "attempt", attempt+1)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			c.logger.Warn("read response failed", "error", err, "attempt", attempt+1)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			c.logger.Warn("server error, retrying", "status", resp.StatusCode, "attempt", attempt+1)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("api: sync failed with status %d: %s", resp.StatusCode, string(respBody))
		}

		return parse(respBody)
	}

	return nil, fmt.Errorf("api: sync failed after %d retries", maxRetries)
}
