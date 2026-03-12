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

## Why `pkg install ethsy-connect` is not default yet

`pkg install <name>` works only for packages published in a Termux apt repository.

Current support in this repo provides:
- Termux-compatible `linux/arm64` binary
- Termux browser-open fallback (`termux-open-url`, `am start`, `xdg-open`)
- Termux install script (`install-termux.sh`)

If you want true `pkg install ethsy-connect`, publish this package to a Termux apt repo (official or custom).

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
