# v-sftp

A minimal, self-hosted SFTP server written in Go. It supports password and public‑key authentication backed by a SQL user store (SQLite by default, PostgreSQL optional). Each user is confined to a per‑user root directory with configurable permissions (read/list/write/delete). Logs are written to a rotating log file.


## Overview
- Protocols: SSH/SFTP
- Auth methods: Password (bcrypt) and/or SSH public key
- Per‑user virtual filesystem roots with path‑traversal protection
- Permission bitmask per user: 1=Read, 2=List, 4=Write, 8=Delete
- Auto‑applies DB schema at startup if the `sftp_users` table is missing (uses `sqlite_ddl.sql` or `postgres_ddl.sql`)
- Rotating structured logs via lumberjack + zap


## Stack and Project Metadata
- Language: Go (Go modules)
- Go version in go.mod: 1.24.4
- Package manager: Go modules (go.mod/go.sum)
- Main entry point: `main.go`
- Executable artifact (example present): `v-sftp.exe`
- Key dependencies:
  - github.com/pkg/sftp — SFTP server machinery
  - golang.org/x/crypto — SSH, bcrypt
  - go.uber.org/zap — logging
  - gopkg.in/natefinch/lumberjack.v2 — log rotation
  - github.com/joho/godotenv — environment file loading
  - database drivers: modernc.org/sqlite (default), github.com/lib/pq (PostgreSQL)


## Requirements
- Go toolchain matching the version in go.mod (1.24.x) or newer
- OS: Windows/Linux/macOS supported by Go and the selected DB driver
- If using SQLite (default): no external DB needed
- If using PostgreSQL: reachable PostgreSQL instance and a valid DSN


## Configuration (Environment Variables)
The server reads configuration from a `.env` file at startup (required). If the `.env` file is missing, the process exits with an error.

- DB_TYPE: Database driver name (default: `sqlite`). Supported values: `sqlite`, `postgres`.
- DB_DSN: Database DSN/connection string (default: `./data/sftp.db`).
  - SQLite example: `DB_TYPE=sqlite`, `DB_DSN=./data/sftp.db`
  - PostgreSQL example: `DB_TYPE=postgres`, `DB_DSN=postgres://user:pass@host:5432/dbname?sslmode=disable`
- LISTEN_ADDR: TCP address for the SFTP server (default: `0.0.0.0:2022`).
- HOST_KEY_PATH: Path to SSH host private key file (default: `./data/host_key`). If missing, a new RSA key will be generated here on first run.
- BASE_FS_ROOT: Base directory under which each user’s root directory is created or enforced (default: `./data/fs`).
- LOG_PATH: Log file path (default: `./logs/sftp.log`). Directory is created if needed.
- LOG_LEVEL: `info` (default) or `debug`.

Example .env:

```
DB_TYPE=sqlite
DB_DSN=./data/sftp.db
LISTEN_ADDR=0.0.0.0:2022
HOST_KEY_PATH=./data/host_key
BASE_FS_ROOT=./data/fs
LOG_PATH=./logs/sftp.log
LOG_LEVEL=info
```


## Database and Users
On startup, the server checks for a `sftp_users` table and applies the appropriate DDL file if it’s missing:
- SQLite: `sqlite_ddl.sql`
- PostgreSQL: `postgres_ddl.sql`

Schema fields (abbreviated; see SQL files):
- id (pk), display_name, group_name, username (unique)
- password_hash (bcrypt, nullable if using only key auth)
- public_key (OpenSSH authorized_key string)
- root_path (user’s filesystem root; if empty, defaults to `BASE_FS_ROOT/<username>`)
- perms (bitmask: 1=Read, 2=List, 4=Write, 8=Delete)
- disabled (bool)

Notes:
- Password auth uses bcrypt.CompareHashAndPassword. Store a bcrypt hash in `password_hash`.
  - You can generate bcrypt hashes with your own tooling or a small Go helper. Ensure you use a reasonable cost.
- Public‑key auth expects the same key material as appears in an `authorized_keys` entry (single‑line OpenSSH format).
- The server ensures resolved file paths remain inside the user’s root and prevents `..` traversal.


## Setup and Run
1) Prepare a `.env` file (see Configuration above).
2) Ensure data directories exist or let the app create them on startup:
   - Host key directory (from `HOST_KEY_PATH`)
   - User base FS directory (`BASE_FS_ROOT`)
   - Log directory (from `LOG_PATH`)

Run from source:

- Build: `go build -o v-sftp .`
- Run: `go run .`
- Or run the built binary: `./v-sftp` (Windows: `v-sftp.exe`)

The server will listen on `LISTEN_ADDR` and log to both console and the rotating log file.


## Managing Users
Insert user rows into `sftp_users`. Examples (adjust paths/values as needed):

SQLite (illustrative):
```
INSERT INTO sftp_users (display_name, group_name, username, password_hash, public_key, root_path, perms, disabled)
VALUES ('Alice Doe', 'default', 'alice', '$2y$...bcrypt-hash...', NULL, 'C:/sftp/alice', 1+2+4+8, 0);
```

PostgreSQL (illustrative):
```
INSERT INTO sftp_users (display_name, group_name, username, password_hash, public_key, root_path, perms, disabled)
VALUES ('Bob Doe', 'default', 'bob', '$2y$...bcrypt-hash...', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... bob@host', '/srv/sftp/bob', 7, FALSE);
```

Tips:
- `perms` is a bitmask; add the values you need (Read=1, List=2, Write=4, Delete=8). For read+list+write use 1+2+4=7.
- If `root_path` is empty, it will default to `BASE_FS_ROOT/<username>` and be created if missing.
- Setting `disabled` disables login for that user.


## Scripts and Developer Commands
There are no custom scripts in this repository. Useful Go commands:
- `go mod tidy` — ensure dependencies are in sync
- `go build .` — build the server
- `go run .` — run the server from source


## Logs
- Default log file: `./logs/sftp.log` (rotated: max size ~20MB, 7 backups, 14 days, compressed)
- Console logs are also emitted. Set `LOG_LEVEL=debug` for more detail.


## Testing
- There are currently no automated tests in this repository. TODO: add unit tests for path resolution, permission checks, and store operations.
- You can manually verify with any SFTP client (e.g., `sftp`, FileZilla, WinSCP) using a user configured in the DB.


## Project Structure
```
.
├── README.md                   # This file
├── main.go                     # Program entry; server setup & SSH/SFTP loop
├── handlers.go                 # SFTP request handlers (read/write/cmd/list)
├── store.go                    # User store (SQLite/PostgreSQL) and DDL bootstrap
├── sqlite_ddl.sql              # SQLite schema for sftp_users
├── postgres_ddl.sql            # PostgreSQL schema for sftp_users

```


## Security Notes
- The server will create an RSA host key if none exists at `HOST_KEY_PATH`. For production, manage your host keys securely and with backups.
- Always store password hashes (bcrypt), never plaintext passwords.
- Consider running behind a firewall and restricting `LISTEN_ADDR` to known interfaces.


## License
MIT License — see LICENSE for details.


## Maintenance and Contributions
- Issues and PRs are welcome. Please include details about your environment and steps to reproduce problems.
- Before submitting changes, run `go build` to ensure the project compiles and consider adding tests where possible.

## Known Issues
- Failure to open empty directories on WinSCP