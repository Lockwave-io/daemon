# Lockwave Daemon

**lockwaved** is the host agent for [Lockwave](https://lockwave.io): it polls the Lockwave control plane and keeps SSH `authorized_keys` in sync by managing a dedicated block in each configured user’s file. All communication is **outbound-only** from the host to the Lockwave API.

- **Product:** [Lockwave](https://lockwave.io) — centralized SSH key lifecycle management
- **Repository:** [github.com/Lockwave-io/daemon](https://github.com/Lockwave-io/daemon)

---

## What it does

- **Register** once with an enrollment token (from the Lockwave UI); receives a host ID and HMAC credential.
- **Sync** on a configurable interval: reports current state, receives desired SSH public keys per OS user, and writes them into a **managed block** inside each user’s `authorized_keys` file.
- **Preserve** any keys outside the managed block; only the section between the Lockwave markers is updated.
- **Self-update** when the control plane advertises a newer version (optional; can be disabled by not setting the version on the server).
- **Credential rotation**: picks up rotated credentials from the sync response and persists them to the config file.

---

## Requirements

- **Run:** Linux, macOS, or FreeBSD. Typically run as root so it can write to `/etc/lockwave/` and to users’ `~/.ssh/authorized_keys` (or custom paths).
- **Network:** Outbound HTTPS to your Lockwave control plane (e.g. `https://lockwave.io`).
- **Build (from source):** Go 1.25 or later.

---

## Quick start

From the [Lockwave dashboard](https://lockwave.io), create a host and generate an **enrollment token**. Then on the server:

```bash
curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- \
  --token YOUR_64_CHAR_ENROLLMENT_TOKEN \
  --os-user deploy
```

The API URL defaults to **https://lockwave.io**; omit `--api-url` unless you use a different endpoint. For multiple OS users or custom paths, see [Installation](#installation) below.

---

## Installation

### Option 1: Install script (recommended)

The script installs the binary to `/usr/local/bin/lockwaved`, config to `/etc/lockwave/`, and (on systemd systems) the `lockwaved.service` unit.

```bash
curl -fsSL https://lockwave.io/install.sh | sudo bash -s -- \
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

Override the binary source with:

```bash
LOCKWAVE_BINARY_URL=https://releases.lockwave.io/lockwaved/latest
```

### Option 2: Manual install

1. **Download** the binary for your OS/arch from [releases](https://releases.lockwave.io/lockwaved/latest/) (e.g. `lockwaved-linux-amd64`) into `/usr/local/bin/lockwaved` and `chmod +x`.
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
    authorized_keys_path: /var/www/.ssh/authorized_keys
```

- **api_url** (optional): Lockwave API base URL; defaults to **https://lockwave.io** (no trailing slash).
- **host_id**: Set by the server during `lockwaved register`.
- **credential**: HMAC secret from registration; used to sign sync requests. Keep confidential.
- **poll_seconds**: Seconds between syncs (server may enforce a minimum).
- **managed_users**: List of OS users. Optional `authorized_keys_path` overrides the default `~/.ssh/authorized_keys` (i.e. `/home/<os_user>/.ssh/authorized_keys`).

---

## Commands

- **`lockwaved register`** — One-time enrollment. Requires `--token` and `--os-user`; optional `--api-url` (default **https://lockwave.io**), `--config`, `--poll-seconds`. Writes config and exits.
- **`lockwaved run`** — Run the daemon (sync loop). Options: `--config` (default `/etc/lockwave/config.yaml`), `--debug` (enable debug logs).
- **`lockwaved version`** — Print version and OS/arch.

---

## How sync works

1. Daemon reads each managed user’s `authorized_keys` and finds the **Lockwave managed block** (see below).
2. It POSTs to the Lockwave sync API with:
   - Host ID and HMAC-signed headers (signature, timestamp, nonce).
   - Current status and the list of keys (or fingerprints) in the managed block.
3. Server responds with **desired state**: which SSH public keys should be present for each OS user.
4. Daemon rewrites only the **managed block** in each `authorized_keys` file, leaving keys above and below untouched. Writes are atomic (temp file + rename).

Sync runs immediately on start, then every `poll_seconds`. If the server sends **credential rotation**, the daemon updates the config file. If the server sends an **update hint** (newer version URL), the daemon can download and replace its own binary, then exit so systemd restarts the new build (see [Self-update](#self-update)).

---

## authorized_keys format

The daemon manages a single block per file, delimited by:

```text
# --- BEGIN LOCKWAVE MANAGED BLOCK ---
ssh-ed25519 AAAA... key1 # lockwave:<key_id>
ssh-rsa AAAA... key2     # lockwave:<key_id>
# --- END LOCKWAVE MANAGED BLOCK ---
```

- Keys **outside** this block are never modified.
- Keys **inside** are fully controlled by Lockwave (assignments, revocations, break-glass). Do not edit the block by hand; changes will be overwritten on the next sync.

---

## Self-update

When the Lockwave control plane is configured with a “current” daemon version and your running daemon reports an older version, the sync API may include an **update** object with a download URL. The daemon will:

1. Download the new binary from that URL.
2. Replace its own executable atomically.
3. Exit with code 0 so systemd (or your process manager) restarts the new binary.

Builds with version `dev` do not self-update. If the replace fails (e.g. read-only filesystem), the daemon logs a warning and keeps running the current binary.

---

## Security

- **TLS:** All API requests use HTTPS; the daemon refuses non-TLS endpoints (except localhost).
- **Authentication:** Sync requests are signed with HMAC-SHA256 using the credential; the server validates signature, timestamp skew, and nonce replay.
- **Config:** Config file must be 0600; the daemon exits if it is not.
- **Least privilege:** The systemd unit uses hardening options (e.g. `NoNewPrivileges`, `ProtectSystem`, `ReadWritePaths` limited to `/home` and `/etc/lockwave`).

---

## Building from source

Requires **Go 1.25+**.

```bash
git clone https://github.com/Lockwave-io/daemon.git
cd daemon
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

Logs (systemd):

```bash
journalctl -u lockwaved -f
```

---

## Documentation

- [Lockwave](https://lockwave.io) — product and dashboard.
- [Daemon docs](https://lockwave.io/docs/daemon) — installation and operations (when available).
- [Install script](https://lockwave.io/install.sh) — one-line install used in Quick start.

---

## License

See the repository’s license file for terms.
