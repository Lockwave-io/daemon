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
	"github.com/lockwave-io/daemon/internal/drift"
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
	regAPIURL := registerCmd.String("api-url", "https://lockwave.io", "Lockwave API base URL")
	regOSUsers := registerCmd.String("os-user", "", "Comma-separated OS users to manage (required)")
	regAuthorizedKeysPaths := registerCmd.String("authorized-keys-path", "", "Optional comma-separated authorized_keys paths (same order as --os-user)")
	regPollSecs := registerCmd.Int("poll-seconds", 60, "Polling interval in seconds")
	regConfigPath := registerCmd.String("config", config.DefaultConfigPath, "Config file path")

	// Default: run daemon
	runFlags := flag.NewFlagSet("run", flag.ExitOnError)
	runConfigPath := runFlags.String("config", config.DefaultConfigPath, "Config file path")
	runDebug := runFlags.Bool("debug", false, "Enable debug logging")

	// Subcommand: configure
	configureCmd := flag.NewFlagSet("configure", flag.ExitOnError)
	cfgPath := configureCmd.String("config", config.DefaultConfigPath, "Config file path")
	cfgAddUser := configureCmd.String("add-user", "", "Add a managed OS user")
	cfgRemoveUser := configureCmd.String("remove-user", "", "Remove a managed OS user")
	cfgPollSecs := configureCmd.Int("poll-seconds", 0, "Change poll interval (0 = no change)")
	cfgAPIURL := configureCmd.String("api-url", "", "Change API URL (empty = no change)")

	// Subcommand: status
	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)
	statusConfigPath := statusCmd.String("config", config.DefaultConfigPath, "Config file path")

	// Subcommand: check
	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	checkConfigPath := checkCmd.String("config", config.DefaultConfigPath, "Config file path")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: lockwaved <register|run|configure|status|check|version> [flags]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		if err := registerCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		if err := runRegister(*regToken, *regAPIURL, *regOSUsers, *regAuthorizedKeysPaths, *regPollSecs, *regConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
			os.Exit(1)
		}
	case "run":
		if err := runFlags.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		level := slog.LevelInfo
		if *runDebug {
			level = slog.LevelDebug
		}
		if err := runDaemon(*runConfigPath, level); err != nil {
			fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
			os.Exit(1)
		}
	case "configure":
		if err := configureCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		if err := runConfigure(*cfgPath, *cfgAddUser, *cfgRemoveUser, *cfgPollSecs, *cfgAPIURL); err != nil {
			fmt.Fprintf(os.Stderr, "Configure failed: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := statusCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		if err := runStatus(*statusConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Status failed: %v\n", err)
			os.Exit(1)
		}
	case "check":
		if err := checkCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
		if err := runCheck(*checkConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Check failed: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("lockwaved %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nUsage: lockwaved <register|run|configure|status|check|version> [flags]\n", os.Args[1]) // #nosec G705 -- CLI error output to stderr, not a web response
		os.Exit(1)
	}
}

func runRegister(token, apiURL, osUsers, authorizedKeysPaths string, pollSecs int, configPath string) error {
	if token == "" || osUsers == "" {
		return fmt.Errorf("--token and --os-user are required")
	}

	logger := telemetry.NewLogger(slog.LevelInfo)
	logger.Info("registering host", "api_url", apiURL)

	hostname, _ := os.Hostname()

	// Parse paths (optional; same order as os-user; fewer or empty is ok)
	pathStrs := []string{}
	if authorizedKeysPaths != "" {
		for _, p := range strings.Split(authorizedKeysPaths, ",") {
			pathStrs = append(pathStrs, strings.TrimSpace(p))
		}
	}

	users := []state.UserEntry{}
	for i, u := range strings.Split(osUsers, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			entry := state.UserEntry{OSUser: u}
			if i < len(pathStrs) && pathStrs[i] != "" {
				entry.AuthorizedKeysPath = pathStrs[i]
			}
			users = append(users, entry)
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

	// Build managed users config (include path so daemon uses it)
	managedUsers := make([]config.ManagedUser, len(users))
	for i, u := range users {
		managedUsers[i] = config.ManagedUser{
			OSUser:             u.OSUser,
			AuthorizedKeysPath: u.AuthorizedKeysPath,
		}
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
	detector := drift.NewDetector()

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
	currentPollSecs := cfg.PollSecs

	logger.Info("entering sync loop", "poll_seconds", currentPollSecs)

	// Initial sync immediately, then poll
	ticker := time.NewTicker(time.Duration(currentPollSecs) * time.Second)
	defer ticker.Stop()

	// Run sync immediately on start, then on ticker
	for {
		resp, syncErr := doSync(ctx, client, cfg, configPath, logger, lastResult, lastDrift, detector)
		if syncErr != nil {
			logger.Error("sync failed", "error", syncErr)
			lastResult = "failure"
		} else {
			lastResult = "success"
			lastDrift = false

			// Respect server-provided poll interval
			if resp != nil && resp.HostPolicy.PollSeconds > 0 && resp.HostPolicy.PollSeconds != currentPollSecs {
				newPoll := resp.HostPolicy.PollSeconds
				if newPoll < 10 {
					newPoll = 10
				}
				logger.Info("server updated poll interval", "old_seconds", currentPollSecs, "new_seconds", newPoll)
				currentPollSecs = newPoll
				ticker.Reset(time.Duration(currentPollSecs) * time.Second)
			}

			if resp != nil && resp.Update != nil && resp.Update.Version != version && version != "dev" {
				logger.Info("update available", "current", version, "target", resp.Update.Version)
				if err := update.Apply(resp.Update.URL, resp.Update.Checksum, logger); err != nil {
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

func doSync(ctx context.Context, client *api.Client, cfg *config.Config, configPath string, logger *slog.Logger, lastResult string, driftDetected bool, detector *drift.Detector) (*state.SyncResponse, error) {
	// Check for drift before sending sync request
	for _, u := range cfg.Users {
		path := u.ResolveAuthorizedKeysPath()
		drifted, err := detector.Check(u.OSUser, path)
		if err != nil {
			logger.Warn("drift check failed", "user", u.OSUser, "error", err)
			continue
		}
		if drifted {
			logger.Warn("drift detected: managed block was modified externally", "user", u.OSUser, "path", path)
			driftDetected = true
		}
	}

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

		// Record post-apply hash for drift detection
		if err := detector.RecordApplied(ds.OSUser, path); err != nil {
			logger.Warn("failed to record post-apply hash", "user", ds.OSUser, "error", err)
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

// runConfigure modifies the daemon config without re-registering.
func runConfigure(configPath, addUser, removeUser string, pollSecs int, apiURL string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	changed := false

	if addUser != "" {
		// Check for duplicate
		for _, u := range cfg.Users {
			if u.OSUser == addUser {
				return fmt.Errorf("user %q is already managed", addUser)
			}
		}
		cfg.Users = append(cfg.Users, config.ManagedUser{OSUser: addUser})
		fmt.Printf("Added managed user: %s\n", addUser)
		changed = true
	}

	if removeUser != "" {
		found := false
		filtered := make([]config.ManagedUser, 0, len(cfg.Users))
		for _, u := range cfg.Users {
			if u.OSUser == removeUser {
				found = true
				continue
			}
			filtered = append(filtered, u)
		}
		if !found {
			return fmt.Errorf("user %q is not managed", removeUser)
		}
		if len(filtered) == 0 {
			return fmt.Errorf("cannot remove last managed user")
		}
		cfg.Users = filtered
		fmt.Printf("Removed managed user: %s\n", removeUser)
		changed = true
	}

	if pollSecs > 0 {
		if pollSecs < 10 {
			pollSecs = 10
		}
		cfg.PollSecs = pollSecs
		fmt.Printf("Poll interval set to %d seconds\n", pollSecs)
		changed = true
	}

	if apiURL != "" {
		cfg.APIURL = apiURL
		fmt.Printf("API URL set to %s\n", apiURL)
		changed = true
	}

	if !changed {
		fmt.Println("No changes specified. Use --add-user, --remove-user, --poll-seconds, or --api-url.")
		return nil
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config after changes: %w", err)
	}

	if err := config.Save(configPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("Config saved to %s\n", configPath)
	return nil
}

// runStatus reports the current daemon configuration and state.
func runStatus(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Config file info
	info, _ := os.Stat(configPath)
	fmt.Printf("Lockwave Daemon Status\n")
	fmt.Printf("──────────────────────\n")
	fmt.Printf("  Host ID:        %s\n", cfg.HostID)
	fmt.Printf("  API URL:        %s\n", cfg.APIURL)
	fmt.Printf("  Poll interval:  %d seconds\n", cfg.PollSecs)
	fmt.Printf("  Config file:    %s\n", configPath)
	if info != nil {
		fmt.Printf("  Config modified: %s\n", info.ModTime().Format(time.RFC3339))
	}
	fmt.Printf("  Daemon version: %s\n", version)
	fmt.Printf("\n  Managed Users:\n")

	for _, u := range cfg.Users {
		path := u.ResolveAuthorizedKeysPath()
		parsed, err := authorizedkeys.Parse(path)
		blockStatus := "no managed block"
		if err != nil {
			blockStatus = fmt.Sprintf("error: %v", err)
		} else if parsed.HasManagedBlock {
			blockStatus = fmt.Sprintf("managed block present (%d keys)", len(parsed.ManagedKeys))
		}
		fmt.Printf("    - %s\n      Path: %s\n      Status: %s\n", u.OSUser, path, blockStatus)
	}

	return nil
}

// runCheck performs a single sync to verify connectivity and exits.
func runCheck(configPath string) error {
	logger := telemetry.NewLogger(slog.LevelInfo)

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	client := api.NewClient(cfg.APIURL, cfg.HostID, cfg.Credential, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build minimal observed state
	observed := make([]state.Observed, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		observed = append(observed, state.Observed{
			OSUser:                  u.OSUser,
			ManagedBlockPresent:     false,
			ManagedKeysFingerprints: []string{},
		})
	}

	now := time.Now().UTC().Format(time.RFC3339)
	syncReq := &state.SyncRequest{
		HostID:        cfg.HostID,
		DaemonVersion: version,
		Status: state.HostStatus{
			LastApplyResult: "pending",
			DriftDetected:   false,
			AppliedAt:       &now,
		},
		Observed: observed,
	}

	resp, err := client.Sync(ctx, syncReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Health check OK\n")
	fmt.Printf("  Server time:   %s\n", resp.ServerTime)
	fmt.Printf("  Poll seconds:  %d\n", resp.HostPolicy.PollSeconds)
	fmt.Printf("  Break glass:   %v\n", resp.HostPolicy.BreakGlass.Active)
	fmt.Printf("  Desired users: %d\n", len(resp.DesiredState))
	return nil
}
