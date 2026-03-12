# ethsy-connect on Termux (Android)

## Quick install (recommended)

```bash
pkg update -y
pkg install -y curl tar openssh
curl -fsSL https://raw.githubusercontent.com/devsigner9920/ethsy-ssh/main/install-termux.sh | bash
```

or directly:

```bash
curl -fsSL https://raw.githubusercontent.com/devsigner9920/ethsy-ssh/main/install.sh | bash
```

## `pkg install ethsy-connect` (custom repo mode)

`pkg install <name>` requires a Termux apt repository. This repo now includes scripts to build and publish one.

### A. Build package + repo metadata

Run on a Termux/Linux environment with Go + dpkg tools:

```bash
pkg install -y golang dpkg dpkg-dev
cd ethsy-ssh
./packaging/termux/scripts/build-deb.sh
./packaging/termux/scripts/build-repo-index.sh
```

Outputs:
- `packaging/termux/repo/ethsy-connect_<version>_aarch64.deb`
- `packaging/termux/repo/Packages`
- `packaging/termux/repo/Packages.gz`
- `packaging/termux/repo/Release`

### B. Host the repo directory

Host `packaging/termux/repo` on any static host (GitHub Pages, S3, your server).

### C. Install via pkg from custom repo

On a Termux device:

```bash
REPO_BASE_URL=https://<your-host>/termux/repo ./packaging/termux/scripts/install-from-custom-repo.sh
```

That script adds:

```bash
deb [trusted=yes] https://<your-host>/termux/repo ./
```

then runs:

```bash
pkg update -y
pkg install -y ethsy-connect
```

## Runtime requirements

- `ssh` (from `openssh` package)
- internet access to `connect.ethsy.me` and `ssh.ethsy.me`

## Verify

```bash
ethsy status
ethsy
```

## Troubleshooting

### Browser did not open
- Open the printed URL manually in Android browser.
- Ensure Termux has ability to launch intents.

### SSH not found
```bash
pkg install -y openssh
```

### Permission/storage prompts
If needed:
```bash
termux-setup-storage
```
