package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/lockwave-io/daemon/internal/api"
	"github.com/lockwave-io/daemon/internal/authorizedkeys"
	"github.com/lockwave-io/daemon/internal/config"
	"github.com/lockwave-io/daemon/internal/state"
	"github.com/lockwave-io/daemon/internal/telemetry"
	"github.com/lockwave-io/daemon/internal/update"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	// Subcommand: register
	registerCmd := flag.NewFlagSet("register", flag.ExitOnError)
	regToken := registerCmd.String("token", "", "Enrollment token (required)")
	regAPIURL := registerCmd.String("api-url", "", "Lockwave API base URL (required)")
	regOSUsers := registerCmd.String("os-user", "", "Comma-separated OS users to manage (required)")
	regPollSecs := registerCmd.Int("poll-seconds", 60, "Polling interval in seconds")
	regConfigPath := registerCmd.String("config", config.DefaultConfigPath, "Config file path")

	// Default: run daemon
	runFlags := flag.NewFlagSet("run", flag.ExitOnError)
	runConfigPath := runFlags.String("config", config.DefaultConfigPath, "Config file path")
	runDebug := runFlags.Bool("debug", false, "Enable debug logging")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: lockwaved <register|run> [flags]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		registerCmd.Parse(os.Args[2:])
		if err := runRegister(*regToken, *regAPIURL, *regOSUsers, *regPollSecs, *regConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
			os.Exit(1)
		}
	case "run":
		runFlags.Parse(os.Args[2:])
		level := slog.LevelInfo
		if *runDebug {
			level = slog.LevelDebug
		}
		if err := runDaemon(*runConfigPath, level); err != nil {
			fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("lockwaved %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nUsage: lockwaved <register|run|version> [flags]\n", os.Args[1])
		os.Exit(1)
	}
}

func runRegister(token, apiURL, osUsers string, pollSecs int, configPath string) error {
	if token == "" || apiURL == "" || osUsers == "" {
		return fmt.Errorf("--token, --api-url, and --os-user are required")
	}

	logger := telemetry.NewLogger(slog.LevelInfo)
	logger.Info("registering host", "api_url", apiURL)

	hostname, _ := os.Hostname()

	users := []state.UserEntry{}
	for _, u := range strings.Split(osUsers, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			users = append(users, state.UserEntry{OSUser: u})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := api.Register(ctx, apiURL, token, state.HostInfo{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		DaemonVersion: version,
		IP:            "0.0.0.0", // Server will use the actual request IP
	}, users, logger)
	if err != nil {
		return err
	}

	logger.Info("registration successful", "host_id", resp.HostID)

	// Build managed users config
	managedUsers := make([]config.ManagedUser, len(users))
	for i, u := range users {
		managedUsers[i] = config.ManagedUser{OSUser: u.OSUser}
	}

	cfg := &config.Config{
		APIURL:     apiURL,
		HostID:     resp.HostID,
		Credential: resp.Credential,
		PollSecs:   pollSecs,
		Users:      managedUsers,
	}

	if err := config.Save(configPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	logger.Info("config saved", "path", configPath)
	fmt.Printf("Host registered successfully.\n  Host ID: %s\n  Config:  %s\n\nStart the daemon with: lockwaved run\n", resp.HostID, configPath)
	return nil
}

func runDaemon(configPath string, level slog.Level) error {
	logger := telemetry.NewLogger(level)
	logger.Info("starting lockwaved", "version", version, "config", configPath)

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	client := api.NewClient(cfg.APIURL, cfg.HostID, cfg.Credential, logger)

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Track last apply status
	lastResult := "pending"
	var lastDrift bool

	logger.Info("entering sync loop", "poll_seconds", cfg.PollSecs)

	// Initial sync immediately, then poll
	ticker := time.NewTicker(time.Duration(cfg.PollSecs) * time.Second)
	defer ticker.Stop()

	// Run sync immediately on start, then on ticker
	for {
		resp, syncErr := doSync(ctx, client, cfg, configPath, logger, lastResult, lastDrift)
		if syncErr != nil {
			logger.Error("sync failed", "error", syncErr)
			lastResult = "failure"
		} else {
			lastResult = "success"
			lastDrift = false

			if resp != nil && resp.Update != nil && resp.Update.Version != version && version != "dev" {
				logger.Info("update available", "current", version, "target", resp.Update.Version)
				if err := update.Apply(resp.Update.URL, logger); err != nil {
					logger.Warn("update failed, continuing", "error", err)
				} else {
					logger.Info("update applied, exiting for restart")
					os.Exit(0)
				}
			}
		}

		select {
		case <-ctx.Done():
			logger.Info("daemon stopped")
			return nil
		case <-ticker.C:
			// Continue loop
		}
	}
}

func doSync(ctx context.Context, client *api.Client, cfg *config.Config, configPath string, logger *slog.Logger, lastResult string, driftDetected bool) (*state.SyncResponse, error) {
	// Build observed state from current authorized_keys files
	observed := make([]state.Observed, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		path := u.ResolveAuthorizedKeysPath()
		parsed, err := authorizedkeys.Parse(path)
		if err != nil {
			logger.Warn("failed to parse authorized_keys", "user", u.OSUser, "path", path, "error", err)
			observed = append(observed, state.Observed{
				OSUser:                  u.OSUser,
				ManagedBlockPresent:     false,
				ManagedKeysFingerprints: []string{},
			})
			continue
		}
		observed = append(observed, state.Observed{
			OSUser:                  u.OSUser,
			ManagedBlockPresent:     parsed.HasManagedBlock,
			ManagedKeysFingerprints: parsed.ManagedKeys,
		})
	}

	now := time.Now().UTC().Format(time.RFC3339)
	syncReq := &state.SyncRequest{
		HostID:        cfg.HostID,
		DaemonVersion: version,
		Status: state.HostStatus{
			LastApplyResult: lastResult,
			DriftDetected:   driftDetected,
			AppliedAt:       &now,
		},
		Observed: observed,
	}

	resp, err := client.Sync(ctx, syncReq)
	if err != nil {
		return nil, err
	}

	logger.Info("sync response received",
		"break_glass", resp.HostPolicy.BreakGlass.Active,
		"desired_users", len(resp.DesiredState),
	)

	// Apply desired state for each managed user
	for _, ds := range resp.DesiredState {
		var user *config.ManagedUser
		for i := range cfg.Users {
			if cfg.Users[i].OSUser == ds.OSUser {
				user = &cfg.Users[i]
				break
			}
		}
		if user == nil {
			logger.Warn("server returned state for unknown user", "os_user", ds.OSUser)
			continue
		}

		path := user.ResolveAuthorizedKeysPath()
		if err := authorizedkeys.Apply(path, ds.AuthorizedKeys); err != nil {
			logger.Error("failed to apply authorized_keys", "user", ds.OSUser, "path", path, "error", err)
			continue
		}

		logger.Info("applied authorized_keys", "user", ds.OSUser, "keys", len(ds.AuthorizedKeys))
	}

	// Handle credential rotation if server provides one
	if resp.CredentialRotation != nil {
		logger.Info("credential rotation received, updating config")
		cfg.Credential = *resp.CredentialRotation
		if err := config.Save(configPath, cfg); err != nil {
			logger.Error("failed to save rotated credential", "error", err)
		}
	}

	return resp, nil
}
