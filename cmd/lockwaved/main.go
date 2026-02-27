package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

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
	app := &cli.Command{
		Name:    "lockwaved",
		Usage:   "Lockwave SSH key sync daemon",
		Version: version,
		Commands: []*cli.Command{
			registerCommand(),
			runCommand(),
			configureCommand(),
			statusCommand(),
			checkCommand(),
			versionCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func registerCommand() *cli.Command {
	return &cli.Command{
		Name:  "register",
		Usage: "Register this host with the Lockwave control plane",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "token",
				Usage:    "Enrollment token (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "api-url",
				Usage: "Lockwave API base URL",
				Value: "https://lockwave.io",
			},
			&cli.StringFlag{
				Name:     "os-user",
				Usage:    "Comma-separated OS users to manage (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "authorized-keys-path",
				Usage: "Optional comma-separated authorized_keys paths (same order as --os-user)",
			},
			&cli.IntFlag{
				Name:  "poll-seconds",
				Usage: "Polling interval in seconds",
				Value: 60,
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "Config file path",
				Value: config.DefaultConfigPath,
			},
			&cli.BoolFlag{
				Name:  "allow-insecure",
				Usage: "Allow HTTP (non-TLS) connections to the API (unsafe, for development only)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runRegister(
				cmd.String("token"),
				cmd.String("api-url"),
				cmd.String("os-user"),
				cmd.String("authorized-keys-path"),
				int(cmd.Int("poll-seconds")),
				cmd.String("config"),
				cmd.Bool("allow-insecure"),
			)
		},
	}
}

func runCommand() *cli.Command {
	return &cli.Command{
		Name:  "run",
		Usage: "Start the daemon sync loop",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Config file path",
				Value: config.DefaultConfigPath,
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Enable debug logging",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runDaemon(cmd.String("config"), cmd.Bool("debug"))
		},
	}
}

func configureCommand() *cli.Command {
	return &cli.Command{
		Name:  "configure",
		Usage: "Modify daemon configuration without re-registering",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Config file path",
				Value: config.DefaultConfigPath,
			},
			&cli.StringFlag{
				Name:  "add-user",
				Usage: "Add a managed OS user",
			},
			&cli.StringFlag{
				Name:  "remove-user",
				Usage: "Remove a managed OS user",
			},
			&cli.IntFlag{
				Name:  "poll-seconds",
				Usage: "Change poll interval (0 = no change)",
			},
			&cli.StringFlag{
				Name:  "api-url",
				Usage: "Change API URL (empty = no change)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runConfigure(
				cmd.String("config"),
				cmd.String("add-user"),
				cmd.String("remove-user"),
				int(cmd.Int("poll-seconds")),
				cmd.String("api-url"),
			)
		},
	}
}

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Show current daemon configuration and state",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Config file path",
				Value: config.DefaultConfigPath,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runStatus(cmd.String("config"))
		},
	}
}

func checkCommand() *cli.Command {
	return &cli.Command{
		Name:  "check",
		Usage: "Perform a single sync to verify connectivity and exit",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Config file path",
				Value: config.DefaultConfigPath,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runCheck(cmd.String("config"))
		},
	}
}

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print the daemon version",
		Action: func(_ context.Context, _ *cli.Command) error {
			fmt.Printf("lockwaved %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

func runRegister(token, apiURL, osUsers, authorizedKeysPaths string, pollSecs int, configPath string, allowInsecure bool) error {
	logger := telemetry.NewLogger(false)

	if !strings.HasPrefix(apiURL, "https://") {
		if !allowInsecure {
			return fmt.Errorf("refusing non-HTTPS API URL %q (use --allow-insecure to override)", apiURL)
		}
		logger.Warn("using non-HTTPS API URL — credentials will be sent in cleartext")
	}

	logger.WithField("api_url", apiURL).Info("registering host")

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
				if err := config.ValidateAuthorizedKeysPath(pathStrs[i]); err != nil {
					return fmt.Errorf("invalid authorized-keys-path for user %s: %w", u, err)
				}
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

	logger.WithField("host_id", resp.HostID).Info("registration successful")

	// Build managed users config (include path so daemon uses it)
	managedUsers := make([]config.ManagedUser, len(users))
	for i, u := range users {
		managedUsers[i] = config.ManagedUser{
			OSUser:             u.OSUser,
			AuthorizedKeysPath: u.AuthorizedKeysPath,
		}
	}

	cfg := &config.Config{
		APIURL:       apiURL,
		HostID:       resp.HostID,
		Credential:   resp.Credential,
		PollSecs:     pollSecs,
		Users:        managedUsers,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := config.Save(configPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	logger.WithField("path", configPath).Info("config saved")
	fmt.Printf("Host registered successfully.\n  Host ID: %s\n  Config:  %s\n\nStart the daemon with: lockwaved run\n", resp.HostID, configPath)
	return nil
}

func runDaemon(configPath string, debug bool) error {
	logger := telemetry.NewLogger(debug)
	logger.WithFields(logrus.Fields{
		"version": version,
		"config":  configPath,
	}).Info("starting lockwaved")

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
		logger.WithField("signal", sig).Info("received signal, shutting down")
		cancel()
	}()

	// Track last apply status
	lastResult := "pending"
	var lastDrift bool
	currentPollSecs := cfg.PollSecs
	consecutiveFailures := 0
	const maxBackoffSecs = 300 // 5 minutes

	// Determine if we're in the 2-minute fast-sync window after registration
	fastSyncUntil := time.Time{}
	if cfg.RegisteredAt != "" {
		if regTime, err := time.Parse(time.RFC3339, cfg.RegisteredAt); err == nil {
			fastSyncUntil = regTime.Add(2 * time.Minute)
		}
	}

	inFastSync := func() bool {
		return !fastSyncUntil.IsZero() && time.Now().Before(fastSyncUntil)
	}

	// Use fast-sync interval if within window
	if inFastSync() {
		currentPollSecs = 10
		logger.WithField("until", fastSyncUntil.Format(time.RFC3339)).Info("in fast-sync window, using 10s interval")
	}

	logger.WithField("poll_seconds", currentPollSecs).Info("entering sync loop")

	// Initial sync immediately, then poll
	ticker := time.NewTicker(time.Duration(currentPollSecs) * time.Second)
	defer ticker.Stop()

	// Run sync immediately on start, then on ticker
	for {
		syncCtx, syncCancel := context.WithTimeout(ctx, 30*time.Second)
		resp, syncErr := doSync(syncCtx, client, cfg, configPath, logger, lastResult, lastDrift, detector)
		syncCancel()
		if syncErr != nil {
			consecutiveFailures++
			logger.WithError(syncErr).WithField("consecutive_failures", consecutiveFailures).Error("sync failed")
			lastResult = "failure"

			// Exponential backoff: 2^failures * base poll, capped at 5 min
			backoffSecs := currentPollSecs * (1 << min(consecutiveFailures, 5))
			if backoffSecs > maxBackoffSecs {
				backoffSecs = maxBackoffSecs
			}
			if backoffSecs > currentPollSecs {
				logger.WithField("backoff_seconds", backoffSecs).Warn("applying backoff due to repeated failures")
				ticker.Reset(time.Duration(backoffSecs) * time.Second)
			}
		} else {
			if consecutiveFailures > 0 {
				logger.WithField("recovered_after", consecutiveFailures).Info("sync recovered")
				ticker.Reset(time.Duration(currentPollSecs) * time.Second)
			}
			consecutiveFailures = 0
			lastResult = "success"
			lastDrift = false

			// Respect server-provided poll interval (with fast-sync override)
			if resp != nil && resp.HostPolicy.PollSeconds > 0 {
				desiredPoll := resp.HostPolicy.PollSeconds
				if desiredPoll < 10 {
					desiredPoll = 10
				}
				if desiredPoll > 3600 {
					logger.WithField("server_value", desiredPoll).Warn("server poll interval exceeds 1h cap, clamping to 3600s")
					desiredPoll = 3600
				}
				// During fast-sync window, cap at 10 seconds
				if inFastSync() && desiredPoll > 10 {
					desiredPoll = 10
				}
				if desiredPoll != currentPollSecs {
					logger.WithFields(logrus.Fields{
						"old_seconds": currentPollSecs,
						"new_seconds": desiredPoll,
					}).Info("poll interval adjusted")
					currentPollSecs = desiredPoll
					ticker.Reset(time.Duration(currentPollSecs) * time.Second)
				}
			}
			// Clear fast-sync window once expired
			if !inFastSync() && !fastSyncUntil.IsZero() {
				fastSyncUntil = time.Time{}
			}

			// Check auto_update flag from config section (defaults to true if no config)
			autoUpdate := resp == nil || resp.Config == nil || resp.Config.AutoUpdate
			if autoUpdate && resp != nil && resp.Update != nil && resp.Update.Version != version && version != "dev" {
				logger.WithFields(logrus.Fields{
					"current": version,
					"target":  resp.Update.Version,
				}).Info("update available")
				if err := update.Apply(resp.Update.URL, resp.Update.Checksum, logger); err != nil {
					logger.WithError(err).Warn("update failed, continuing")
				} else {
					logger.Info("update applied, exiting for restart")
					os.Exit(0)
				}
			} else if !autoUpdate && resp != nil && resp.Update != nil {
				logger.WithField("target", resp.Update.Version).Debug("update available but auto-update disabled")
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

func doSync(ctx context.Context, client *api.Client, cfg *config.Config, configPath string, logger *logrus.Logger, lastResult string, driftDetected bool, detector *drift.Detector) (*state.SyncResponse, error) {
	// Check for drift before sending sync request
	for _, u := range cfg.Users {
		path := u.ResolveAuthorizedKeysPath()
		drifted, err := detector.Check(u.OSUser, path)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"user":  u.OSUser,
				"error": err,
			}).Warn("drift check failed")
			continue
		}
		if drifted {
			logger.WithFields(logrus.Fields{
				"user": u.OSUser,
				"path": path,
			}).Warn("drift detected: managed block was modified externally")
			driftDetected = true
		}
	}

	// Build observed state from current authorized_keys files
	observed := make([]state.Observed, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		path := u.ResolveAuthorizedKeysPath()
		parsed, err := authorizedkeys.Parse(path)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"user":  u.OSUser,
				"path":  path,
				"error": err,
			}).Warn("failed to parse authorized_keys")
			observed = append(observed, state.Observed{
				OSUser:                  u.OSUser,
				ManagedBlockPresent:     false,
				ManagedKeysFingerprints: []string{},
			})
			continue
		}
		fingerprints := parsed.ManagedKeys
		if fingerprints == nil {
			fingerprints = []string{}
		}
		observed = append(observed, state.Observed{
			OSUser:                  u.OSUser,
			ManagedBlockPresent:     parsed.HasManagedBlock,
			ManagedKeysFingerprints: fingerprints,
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

	logger.WithFields(logrus.Fields{
		"break_glass":   resp.HostPolicy.BreakGlass.Active,
		"desired_users": len(resp.DesiredState),
	}).Info("sync response received")

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
			logger.WithField("os_user", ds.OSUser).Warn("server returned state for unknown user")
			continue
		}

		path := user.ResolveAuthorizedKeysPath()
		if err := authorizedkeys.Apply(path, ds.AuthorizedKeys); err != nil {
			logger.WithFields(logrus.Fields{
				"user":  ds.OSUser,
				"path":  path,
				"error": err,
			}).Error("failed to apply authorized_keys")
			continue
		}

		// Record post-apply hash for drift detection
		if err := detector.RecordApplied(ds.OSUser, path); err != nil {
			logger.WithFields(logrus.Fields{
				"user":  ds.OSUser,
				"error": err,
			}).Warn("failed to record post-apply hash")
		}

		logger.WithFields(logrus.Fields{
			"user": ds.OSUser,
			"keys": len(ds.AuthorizedKeys),
		}).Info("applied authorized_keys")
	}

	// Handle credential rotation if server provides one
	if resp.CredentialRotation != nil {
		logger.Info("credential rotation received, updating config")
		cfg.Credential = *resp.CredentialRotation
		if err := config.Save(configPath, cfg); err != nil {
			logger.WithError(err).Error("failed to save rotated credential")
		} else {
			client.RotateCredential(*resp.CredentialRotation)
			logger.Info("credential rotated for subsequent requests")
		}
	}

	// Reconcile config from control plane
	if resp.Config != nil {
		reconcileConfig(cfg, resp.Config, configPath, logger, detector)
	}

	return resp, nil
}

// reconcileConfig applies server-pushed config changes to the local config file.
func reconcileConfig(cfg *config.Config, sc *state.SyncConfig, configPath string, logger *logrus.Logger, detector *drift.Detector) {
	configChanged := false

	// Build a map of current users for quick lookup
	currentUsers := make(map[string]config.ManagedUser, len(cfg.Users))
	for _, u := range cfg.Users {
		currentUsers[u.OSUser] = u
	}

	// Build a map of server-desired users
	serverUsers := make(map[string]state.ConfigUser, len(sc.ManagedUsers))
	for _, u := range sc.ManagedUsers {
		serverUsers[u.OSUser] = u
	}

	// Detect removed users and strip their managed blocks
	for _, u := range cfg.Users {
		if _, exists := serverUsers[u.OSUser]; !exists {
			path := u.ResolveAuthorizedKeysPath()
			logger.WithField("os_user", u.OSUser).Info("removing managed user per server config")
			if err := authorizedkeys.StripManagedBlock(path); err != nil {
				logger.WithFields(logrus.Fields{
					"os_user": u.OSUser,
					"error":   err,
				}).Warn("failed to strip managed block for removed user")
			}
			configChanged = true
		}
	}

	// Build new user list from server config (with path validation)
	if len(sc.ManagedUsers) > 0 {
		newUsers := make([]config.ManagedUser, 0, len(sc.ManagedUsers))
		for _, su := range sc.ManagedUsers {
			if err := config.ValidateAuthorizedKeysPath(su.AuthorizedKeysPath); err != nil {
				logger.WithFields(logrus.Fields{
					"os_user": su.OSUser,
					"path":    su.AuthorizedKeysPath,
					"error":   err,
				}).Warn("rejecting server-pushed authorized_keys_path: failed validation")
				continue
			}
			newUsers = append(newUsers, config.ManagedUser{
				OSUser:             su.OSUser,
				AuthorizedKeysPath: su.AuthorizedKeysPath,
			})
		}
		// Check if users actually changed
		if !managedUsersEqual(cfg.Users, newUsers) {
			cfg.Users = newUsers
			configChanged = true
			logger.WithField("count", len(newUsers)).Info("managed users updated from server config")
		}
	}

	// Reconcile poll interval
	if sc.PollSeconds > 0 && sc.PollSeconds != cfg.PollSecs {
		logger.WithFields(logrus.Fields{
			"old": cfg.PollSecs,
			"new": sc.PollSeconds,
		}).Info("poll interval updated from server config")
		cfg.PollSecs = sc.PollSeconds
		configChanged = true
	}

	if configChanged {
		if err := config.Save(configPath, cfg); err != nil {
			logger.WithError(err).Error("failed to save reconciled config")
		} else {
			logger.Info("config saved after server reconciliation")
		}
	}
}

// managedUsersEqual checks if two managed user slices are equivalent.
func managedUsersEqual(a []config.ManagedUser, b []config.ManagedUser) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].OSUser != b[i].OSUser || a[i].AuthorizedKeysPath != b[i].AuthorizedKeysPath {
			return false
		}
	}
	return true
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
	logger := telemetry.NewLogger(false)

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
