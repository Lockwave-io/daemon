# Lockwave Daemon

**lockwaved** is the host agent for [Lockwave](https://lockwave.io): it polls the Lockwave control plane and keeps SSH `authorized_keys` in sync by managing a dedicated block in each configured user's file. All communication is **outbound-only** from the host to the Lockwave API.

- **Product:** [Lockwave](https://lockwave.io) — centralized SSH key lifecycle management
- **Repository:** [github.com/lockwave-io/lockwaved](https://github.com/lockwave-io/lockwaved)

---

## What it does

- **Register** once with an enrollment token (from the Lockwave UI); receives a host ID and HMAC credential.
- **Sync** on a configurable interval: reports current state, receives desired SSH public keys per OS user, and writes them into a **managed block** inside each user's `authorized_keys` file.
- **Preserve** any keys outside the managed block (by default); only the section between the Lockwave markers is updated. When the server sends **exclusive keys** mode for a user, the daemon replaces the entire `authorized_keys` file with only Lockwave-managed keys.
- **SSH server hardening** (optional): when the control plane enables **block password authentication** for the host, the daemon writes an sshd drop-in config to disable password and keyboard-interactive authentication; see [SSH server hardening](#ssh-server-hardening) below.
- **Self-update** from [GitHub Releases](https://github.com/lockwave-io/lockwaved/releases): the daemon checks for new releases every 10 minutes and automatically updates itself.
- **Credential rotation**: picks up rotated credentials from the sync response and persists them to the config file.

---

## Requirements

- **Run:** Linux, macOS, or FreeBSD. Typically run as root so it can write to `/etc/lockwave/` and to users' `~/.ssh/authorized_keys` (or custom paths).
- **Network:** Outbound HTTPS to your Lockwave control plane (e.g. `https://lockwave.io`) and to `github.com` (for self-updates).
- **Build (from source):** Go 1.25 or later.

---

## Quick start

From the [Lockwave dashboard](https://lockwave.io), create a host and generate an **enrollment token**. Then on the server:

```bash
curl -fsSL https://get.lockwave.io/install.sh | sudo bash -s -- \
  --token YOUR_64_CHAR_ENROLLMENT_TOKEN \
  --os-user deploy
```

The API URL defaults to **https://lockwave.io**; omit `--api-url` unless you use a different endpoint. For multiple OS users or custom paths, see [Installation](#installation) below.

---

## Installation

### Option 1: Install script (recommended)

The script downloads the binary from [GitHub Releases](https://github.com/lockwave-io/lockwaved/releases), installs it to `/usr/local/bin/lockwaved`, config to `/etc/lockwave/`, and (on systemd systems) the `lockwaved.service` unit.

```bash
curl -fsSL https://get.lockwave.io/install.sh | sudo bash -s -- \
  --token <enrollment_token> \
  --os-user deploy \
  [--api-url https://lockwave.io] \
  [--authorized-keys-path /home/deploy/.ssh/authorized_keys] \
  [--poll-seconds 60]
```

- `--token` (required): 64-character enrollment token from Lockwave.
- `--api-url` (optional): Lockwave API base URL; defaults to **https://lockwave.io**.
- `--os-user` (required): OS user(s) to manage — single user or comma-separated list (e.g. `deploy` or `deploy,www-data`).
- `--authorized-keys-path` (optional): Override `authorized_keys` path; if not set, edit config after install for per-user paths.
- `--poll-seconds` (optional): Polling interval in seconds (default 60).

### Option 2: Manual install

1. **Download** the binary for your OS/arch from [GitHub Releases](https://github.com/lockwave-io/lockwaved/releases/latest) (e.g. `lockwaved-linux-amd64`) into `/usr/local/bin/lockwaved` and `chmod +x`.
2. **Create** config directory: `mkdir -p /etc/lockwave && chmod 700 /etc/lockwave`.
3. **Register** (one-time):

   ```bash
   lockwaved register \
     --token YOUR_ENROLLMENT_TOKEN \
     --os-user deploy \
     --config /etc/lockwave/config.yaml
   ```

   Add `--api-url <url>` only if you use a different API endpoint; the default is **https://lockwave.io**. This writes `/etc/lockwave/config.yaml` (mode 0600).
4. **Run** as a service: use the provided [systemd unit](packaging/lockwaved.service) or your process manager.

### Uninstall

#### Option A: Uninstall script (recommended)

```bash
curl -fsSL https://get.lockwave.io/install.sh | sudo bash -s -- --uninstall
```

This automatically removes **everything**: the systemd service, binary, sshd drop-in config, and the config directory (`/etc/lockwave`).

#### Option B: Manual uninstall

1. **Stop and disable the service:**

   ```bash
   sudo systemctl stop lockwaved
   sudo systemctl disable lockwaved
   ```

2. **Remove the systemd unit:**

   ```bash
   sudo rm /etc/systemd/system/lockwaved.service
   sudo systemctl daemon-reload
   ```

3. **Remove the binary:**

   ```bash
   sudo rm /usr/local/bin/lockwaved
   ```

4. **Remove the sshd drop-in config** (if SSH hardening was enabled):

   ```bash
   sudo rm -f /etc/ssh/sshd_config.d/99-lockwave.conf
   sudo systemctl reload sshd || sudo systemctl reload ssh
   ```

5. **Remove config and state** (contains host credentials):

   ```bash
   sudo rm -rf /etc/lockwave
   ```

6. **(Optional) Clean up the host in Lockwave:** Delete the host from the Lockwave dashboard so it no longer appears in your inventory.

After uninstalling, keys previously written by the daemon remain in each user's `authorized_keys` inside the managed block markers. You can remove these blocks manually or leave them (they become static entries that the daemon no longer manages).

---

## Configuration

Config file path: **`/etc/lockwave/config.yaml`** (must be mode **0600**). The daemon refuses to start if the file is group- or world-readable.

Example:

```yaml
api_url: https://lockwave.io   # optional; default is https://lockwave.io
host_id: "uuid-from-registration"
credential: "hmac-secret-from-registration"
poll_seconds: 60
managed_users:
  - os_user: deploy
  - os_user: www-data
    authorized_keys_path: /home/<os_user>/.ssh/authorized_keys`
```

- **api_url** (optional): Lockwave API base URL; defaults to **https://lockwave.io** (no trailing slash).
- **host_id**: Set by the server during `lockwaved register`.
- **credential**: HMAC secret from registration; used to sign sync requests. Keep confidential.
- **poll_seconds**: Seconds between syncs (server may enforce a minimum).
- **managed_users**: List of OS users. Optional `authorized_keys_path` overrides the default `~/.ssh/authorized_keys` (i.e. `/home/<os_user>/.ssh/authorized_keys`). The server can push **exclusive_keys** per user via the sync response (`config.managed_users`); when true, the daemon replaces the entire `authorized_keys` file with only Lockwave keys instead of preserving keys outside the block.

---

## Commands

- **`lockwaved register`** — One-time enrollment. Requires `--token` and `--os-user`; optional `--api-url` (default **https://lockwave.io**), `--config`, `--poll-seconds`. Writes config and exits.
- **`lockwaved run`** — Run the daemon (sync loop). Options: `--config` (default `/etc/lockwave/config.yaml`), `--debug` (enable debug logs).
- **`lockwaved check`** — Perform a single sync to verify connectivity and display host policy (poll interval, password auth status, break-glass, etc.).
- **`lockwaved status`** — Show current config and authorized_keys state for each managed user.
- **`lockwaved configure`** — Modify config without re-registering (add/remove users, change poll interval, change API URL).
- **`lockwaved update`** — Check GitHub Releases for a new version and install it.
- **`lockwaved version`** — Print version and OS/arch.

---

## How sync works

1. Daemon reads each managed user's `authorized_keys` and finds the **Lockwave managed block** (see below).
2. It POSTs to the Lockwave sync API with:
   - Host ID and HMAC-signed headers (signature, timestamp, nonce).
   - Current status (including **password_auth_blocked** when SSH hardening is applied) and the list of keys (or fingerprints) in the managed block.
3. Server responds with **desired state**: which SSH public keys should be present for each OS user. Each entry may include **exclusive_keys** (replace entire file vs. only the block). The response may also include:
   - **config**: managed users (with optional **exclusive_keys**), **poll_seconds**; the daemon may persist these.
4. Daemon rewrites the managed block (or the entire file when **exclusive_keys** is true) in each `authorized_keys` file. Writes are atomic (temp file + rename).

Sync runs immediately on start, then every `poll_seconds`. If the server sends **credential rotation**, the daemon updates the config file.

---

## authorized_keys format

The daemon manages a single block per file, delimited by:

```text
# --- BEGIN LOCKWAVE MANAGED BLOCK ---
ssh-ed25519 AAAA... key1 # lockwave:<key_id>
ssh-rsa AAAA... key2     # lockwave:<key_id>
# --- END LOCKWAVE MANAGED BLOCK ---
```

- Keys **outside** this block are never modified (unless **exclusive keys** mode is enabled for that user; then the whole file is replaced by Lockwave keys only).
- Keys **inside** are fully controlled by Lockwave (assignments, revocations, break-glass). Do not edit the block by hand; changes will be overwritten on the next sync.

---

## SSH server hardening

When the Lockwave control plane enables **block password authentication** for a host, the daemon can write an sshd drop-in configuration so that only key-based authentication is allowed.

- **Location:** `/etc/ssh/sshd_config.d/99-lockwave.conf` (or the drop-in directory used on your system, e.g. `/etc/ssh/sshd_config.d` on Linux).
- **Content:** The daemon sets `PasswordAuthentication no` (or `yes` when unblocked) in this file. The file is prefixed with a comment that it is managed by Lockwave and will be overwritten on the next sync.
- **Validation:** Before applying, the daemon runs `sshd -t`. If validation fails, the drop-in is removed and the daemon reports an error (no broken sshd config is left in place).
- **Reload:** After writing, the daemon reloads sshd (tries both `sshd` and `ssh` service names for compatibility across distributions). If reload fails, the error is reported.
- **Status:** The daemon reports `password_auth_blocked` in the sync request status so the control plane can show whether the setting is in effect.

This behavior is optional and controlled per host from the Lockwave dashboard. If the control plane does not set `block_password_auth`, the daemon does not write or modify the sshd drop-in.

---

## Exclusive keys mode

By default, the daemon only updates the **managed block** inside `authorized_keys` and leaves any other keys in the file unchanged. When the server sends **exclusive_keys: true** for a managed user (in the sync response's `desired_state` or in `config.managed_users`), the daemon instead **replaces the entire** `authorized_keys` file with only the Lockwave-managed keys. No keys outside the block are preserved. Use this for strict compliance or when the host user should have only Lockwave-provisioned access. The setting is configured per host or per OS user in the Lockwave dashboard.

---

## Self-update

The daemon automatically checks [GitHub Releases](https://github.com/lockwave-io/lockwaved/releases) every 10 minutes for a newer version. When a new release is found, the daemon will:

1. Download the correct binary for the current OS/arch from the release assets.
2. Verify the SHA-256 checksum from `checksums.txt` in the release.
3. Validate the new binary by running its `version` subcommand.
4. Replace its own executable atomically.
5. Restart the service via `systemctl restart lockwaved` (or exit with code 0 for process manager restart).

Builds with version `dev` do not self-update. If the replace fails (e.g. read-only filesystem), the daemon logs a warning and keeps running the current binary.

You can also trigger a manual update check: `lockwaved update`.

---

## Security

- **TLS:** All API requests use HTTPS; the daemon refuses non-TLS endpoints (except localhost).
- **Authentication:** Sync requests are signed with HMAC-SHA256 using the credential; the server validates signature, timestamp skew, and nonce replay.
- **Config:** Config file must be 0600; the daemon exits if it is not.
- **Updates:** Binaries are downloaded from GitHub Releases over HTTPS with mandatory SHA-256 checksum verification.
- **Least privilege:** The systemd unit uses hardening options (e.g. `NoNewPrivileges`, `ProtectSystem`, `ReadWritePaths` limited to `/home`, `/etc/lockwave`, and `/etc/ssh/sshd_config.d`).

---

## Building from source

Requires **Go 1.25+**.

```bash
git clone https://github.com/lockwave-io/lockwaved.git
cd lockwaved
go build -o lockwaved ./cmd/lockwaved
```

Set version at build time:

```bash
go build -ldflags '-X main.version=1.2.0' -o lockwaved ./cmd/lockwaved
```

Cross-compile for Linux from macOS:

```bash
GOOS=linux GOARCH=amd64 go build -o lockwaved-linux-amd64 ./cmd/lockwaved
```

---

## Development

```bash
go build ./...
go test ./...
```

Run the daemon locally (with a config pointing at your Lockwave instance or a test server):

```bash
./lockwaved run --config /etc/lockwave/config.yaml [--debug]
```

---

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `config: ... has insecure permissions` | Config not 0600 | `chmod 600 /etc/lockwave/config.yaml` |
| `401 Invalid signature` | Credential mismatch or clock skew | Rotate credential from Lockwave UI; sync host time (NTP). |
| `401 Unknown host` | Host not registered or wrong host_id | Re-register with a new enrollment token. |
| `401 Nonce already used` | Replay or duplicate request | Ensure only one daemon instance per host. |
| Sync returns empty desired state | Break-glass active or no assignments | Check Lockwave dashboard for break-glass and key assignments. |
| Daemon not updating keys | Permissions on `~/.ssh` or `authorized_keys` | Ensure daemon can read and write the file (e.g. run as root or appropriate user with access). |
| Password auth still allowed / drop-in not applied | sshd_config.d missing or not used; reload failed | Ensure `/etc/ssh/sshd_config.d` exists and sshd is configured to include it; check daemon logs for reload errors. |
| Self-update not working | GitHub API rate limit or network blocked | Ensure outbound HTTPS to `api.github.com` and `github.com` is allowed; check daemon logs. |

Logs (systemd):

```bash
journalctl -u lockwaved -f
```

---

## Documentation

- [Lockwave](https://lockwave.io) — product and dashboard.
- [Lockwave Docs](https://lockwave.io/docs) — installation, daemon behavior, API, and security model.
- [GitHub Releases](https://github.com/lockwave-io/lockwaved/releases) — download binaries and install script.

---

## License

See the repository's license file for terms.
