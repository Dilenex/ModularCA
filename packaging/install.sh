#!/usr/bin/env bash
#
# ModularCA install / upgrade for a systemd Linux host.
#
# This archive is built on Windows, so it carries NO Unix permission bits or executable flags —
# tar records them, but the source filesystem has nothing meaningful to record. Everything this
# script does about ownership and mode is therefore mandatory, not cosmetic: without it the
# apphost is not executable and the secret-bearing config files are world-readable.
#
# Idempotent. Safe to re-run for an upgrade; it never overwrites config/ or keystores/.
#
#   sudo ./install.sh
#
set -euo pipefail

APP_DIR=/opt/modularca
SERVICE_USER=modularca
SERVICE_GROUP=modularca
UNIT=/etc/systemd/system/modularca.service

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"
[[ -f "$SRC/ModularCA.API" ]] || die "ModularCA.API not found next to this script — run it from inside the extracted archive"

# ── Service account ────────────────────────────────────────────────────────────
if ! getent group "$SERVICE_GROUP" >/dev/null; then
    note "creating group $SERVICE_GROUP"
    groupadd --system "$SERVICE_GROUP"
fi
if ! getent passwd "$SERVICE_USER" >/dev/null; then
    note "creating system user $SERVICE_USER"
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$APP_DIR" \
            --shell /usr/sbin/nologin --comment "ModularCA service account" "$SERVICE_USER"
fi

# ── Stop a running instance before replacing binaries ──────────────────────────
if systemctl is-active --quiet modularca 2>/dev/null; then
    note "stopping modularca"
    systemctl stop modularca
    STOPPED=1
fi

# ── Payload ────────────────────────────────────────────────────────────────────
note "installing to $APP_DIR"
mkdir -p "$APP_DIR"

# Binaries and static assets are replaced. config/ and keystores/ are NOT in this list: they
# hold the install's identity and secrets, and an upgrade must never touch them.
#
# Note the copy below MERGES rather than replaces, so a file the new build no longer ships
# survives on disk. That is handled for wwwroot (removed first, below). Stale runtime
# assemblies in the app directory are a known remaining gap.
for item in ModularCA.API ModularCA.Keystore.Unlocker wwwroot; do
    [[ -e "$SRC/$item" ]] || die "missing from archive: $item"
done

# wwwroot is removed before the copy rather than merged into.
#
# `cp -a` merges directories: it overwrites what exists in both and leaves behind anything the
# new build no longer ships. Vite names every chunk by content hash, so a new release overwrites
# nothing and only adds — the old chunks stay on disk and stay served. A browser holding a cached
# index.html then keeps fetching a bundle from several releases ago, successfully, and the
# operator debugs behaviour from code that is no longer deployed.
#
# Safe to delete outright: everything under wwwroot is build output shipped in this archive.
# config/, keystores/ and logs/ are excluded from the copy below and are never touched.
rm -rf "$APP_DIR/wwwroot"

find "$SRC" -maxdepth 1 -mindepth 1 \
     ! -name config ! -name keystores ! -name logs ! -name deploy \
     ! -name install.sh ! -name README-DEPLOY.md \
     -exec cp -a {} "$APP_DIR/" \;

mkdir -p "$APP_DIR/config" "$APP_DIR/keystores" "$APP_DIR/logs"

# Config examples are only seeded on a first install — never over an operator's real config.
for f in "$SRC"/config/*.example; do
    [[ -e "$f" ]] || continue
    dest="$APP_DIR/config/$(basename "$f")"
    [[ -e "$dest" ]] || cp -a "$f" "$dest"
done

# ── Ownership and modes ────────────────────────────────────────────────────────
# The archive carries none of this; see the header.
note "setting ownership and permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR"

# Executables. The .NET apphost and the break-glass unlocker both need +x.
chmod 0755 "$APP_DIR/ModularCA.API" "$APP_DIR/ModularCA.Keystore.Unlocker"

# Application directory: traversable, not world-writable.
chmod 0750 "$APP_DIR"

# Secrets. config/ holds db.yaml (database credentials) and keystore.yaml (the secondary
# keystore passphrase); keystores/ holds the CA private keys. Owner-only, both.
chmod 0700 "$APP_DIR/config" "$APP_DIR/keystores"
find "$APP_DIR/config" -type f -exec chmod 0600 {} \;
find "$APP_DIR/keystores" -type f -exec chmod 0600 {} \; 2>/dev/null || true

chmod 0750 "$APP_DIR/logs"

# ── systemd ────────────────────────────────────────────────────────────────────
# A missing unit used to fall through this block in silence: the installer printed its success
# banner and the service was never registered. The archive is built from a source tree where
# deploy/ was gitignored, so this was reachable from an ordinary clean clone — an install that
# reports success and did not do the thing. Fail loudly instead.
if [[ ! -f "$SRC/deploy/modularca.service" ]]; then
    echo "ERROR: $SRC/deploy/modularca.service is missing from this distribution." >&2
    echo "       Without it the systemd unit cannot be installed and modularca will not start" >&2
    echo "       at boot. This usually means the archive was built from a tree with no deploy/" >&2
    echo "       directory. Rebuild with scripts/build-linux-dist.sh from a complete checkout," >&2
    echo "       or install the unit by hand before starting the service." >&2
    exit 1
fi

if [[ -f "$UNIT" ]] && ! cmp -s "$SRC/deploy/modularca.service" "$UNIT"; then
    note "unit file differs from the packaged one; leaving yours in place at $UNIT"
    note "  packaged copy: $SRC/deploy/modularca.service"
else
    note "installing systemd unit"
    install -m 0644 "$SRC/deploy/modularca.service" "$UNIT"
fi
systemctl daemon-reload

# ── Ports below 1024 ───────────────────────────────────────────────────────────
# The unit grants CAP_NET_BIND_SERVICE, which is the right mechanism. Nothing to do here, but
# say so, because the usual reflex is to reach for setcap and that would be redundant.
note "privileged ports are handled by AmbientCapabilities=CAP_NET_BIND_SERVICE in the unit"

if [[ "${STOPPED:-0}" == "1" ]]; then
    note "restarting modularca"
    systemctl start modularca
fi

cat <<'DONE'

Installed.

Next steps on a FIRST install:
  1. Create the database and a root credential, then populate:
       /opt/modularca/config/setup-database.yaml   (from the .example)
  2. Start the service:  sudo systemctl enable --now modularca
  3. Open the setup wizard and complete it. It runs only while the install is
     unconfigured, and closes itself afterwards.

For an UPGRADE there is nothing further to do — config/ and keystores/ were left
untouched and database migrations are applied automatically on start.

Verify:
  systemctl status modularca
  journalctl -u modularca -f
DONE
