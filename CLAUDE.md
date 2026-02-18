# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ethsy-ssh is a remote tmux session sharing platform. Users authenticate via Google OAuth, register per-device SSH keys, and connect to shared tmux sessions on `ethsy.me`. The project is a Go monorepo with two applications. Specifications are written in Korean — see the SPEC.md files for full details.

## Repository Structure

- **`server/`** — `ethsy-server`: Host server running on ethsy.me (HTTPS, OAuth, admin panel, REST API, SSH key management, tmux session lifecycle, SQLite)
- **`connect/`** — `ethsy-connect`: CLI client installed via Homebrew (`ethsy` command)

## Architecture

**Authentication flow:** CLI opens browser → Google OAuth on `connect.ethsy.me` → server issues JWT → CLI polls for token → token stored locally.

**Two-tier key system:**
- JWT tokens for API authentication (30-day expiry)
- Per-device Ed25519 SSH keys for tmux session access (registered in `~/.ssh/authorized_keys` with `ethsy-managed` tags)

**Session model:** tmux sessions are owned by user (email), not device. Multiple devices can attach to the same session for real-time screen sharing. Sessions use naming convention `ethsy_{user_id}_{session_number}`.

**Server components:** Web server (HTTPS 443 with Let's Encrypt) → SSH Key Manager (authorized_keys manipulation) → Session Manager (tmux lifecycle) → SQLite DB (users, ssh_keys, sessions, auth_sessions tables).

**Admin panel** is localhost-only (127.0.0.1), accessible at `ethsy.me/admin`.

## Build & Distribution

- **Language:** Go (single binary, no external runtime dependencies)
- **Build:** `goreleaser` for cross-platform binaries (macOS arm64/amd64, Linux amd64)
- **Server install:** `go install github.com/devsigner9920/ethsy-ssh/server@latest`
- **Client install:** `brew tap devsigner9920/tap && brew install ethsy-connect`
- **Homebrew tap repo:** `github.com/devsigner9920/homebrew-tap`

## Key Paths (Runtime)

| Path | Purpose |
|------|---------|
| `~/.ethsy/server/config.yaml` | Server configuration (OAuth creds, JWT secret, SSH port) |
| `~/.ethsy/server/ethsy.db` | SQLite database |
| `~/.ethsy/server/tmux.conf` | tmux config applied to all sessions |
| `~/.ethsy/connect/config.json` | Client auth state (token, email, username) |
| `~/.ethsy/connect/key/` | Client SSH keypair (id_ed25519) |

## Networking

| Port | Purpose |
|------|---------|
| 443 | HTTPS (OAuth + API) |
| 80 | Let's Encrypt HTTP challenge |
| 9920 | SSH (mapped to internal 22) |

Domains: `ethsy.me` (admin), `connect.ethsy.me` (OAuth + CLI API).
