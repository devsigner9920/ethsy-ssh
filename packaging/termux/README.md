# Termux APT Packaging

This folder contains helper scripts to support `pkg install ethsy-connect` via a custom Termux apt repository.

## Scripts

- `scripts/build-deb.sh` — builds `ethsy-connect_<version>_aarch64.deb`
- `scripts/build-repo-index.sh` — generates `Packages`, `Packages.gz`, `Release`
- `scripts/install-from-custom-repo.sh` — adds custom apt source and installs package

## Typical flow

1. Build package + index
2. Upload `packaging/termux/repo/*` to static hosting
3. On Termux device, set `REPO_BASE_URL` and run install script
