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
# On an upgrade (an existing config/db.yaml) the NEW build's --upgrade-check runs first, as the
# service account against the installed config: it dry-runs every pending migration and rolls
# back. If it does not pass, nothing in /opt/modularca is changed and the stopped units are
# started again on the installed build. If the script dies after stopping the units and before it
# finishes, it says the install is incomplete; it starts the units again only when nothing in
# /opt/modularca was replaced yet, and otherwise leaves them stopped and says how to recover.
#
#   sudo ./install.sh [--skip-upgrade-check]
#
set -euo pipefail

APP_DIR=/opt/modularca
SERVICE_USER=modularca
SERVICE_GROUP=modularca
UNIT=/etc/systemd/system/modularca.service
STAGE_PARENT=${APP_DIR%/*}
SKIP_UPGRADE_CHECK=0
STAGE=
RESTART=()
STOPPED=0          # the units were stopped (or found stopped) for this run
STARTED=0          # start_units has run
TOUCHED=0          # something in $APP_DIR was replaced
DONE=0             # the install finished
FAILED_LINE=

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$*" >&2; }

usage() {
    cat <<'USAGE'
Usage: sudo ./install.sh [--skip-upgrade-check]

  --skip-upgrade-check   Install without first running the new build's --upgrade-check. For
                         emergencies only: the service still dry-runs every migration when it
                         starts and applies nothing if one refuses, but it then refuses to start
                         on the new build.
USAGE
}

parse_args() {
    local arg
    for arg in "$@"; do
        case $arg in
            --skip-upgrade-check) SKIP_UPGRADE_CHECK=1 ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; die "unknown option: $arg" ;;
        esac
    done
}

# Starts the units this run stopped, the node before the signer, without waiting: the node checks
# both databases and applies migrations before it reports ready.
start_units() {
    local unit
    STARTED=1
    for unit in ${RESTART[@]+"${RESTART[@]}"}; do
        note "starting $unit"
        systemctl start --no-block "$unit" || warn "could not start $unit; start it with: systemctl start $unit"
    done
}

remove_stage() {
    if [[ -n $STAGE && -d $STAGE ]]; then
        rm -rf -- "$STAGE"
    fi
    STAGE=
}

# Every part of the archive the install copies or installs, checked before any unit is stopped
# and before anything in $APP_DIR is touched. The systemd unit is one of them: an archive built
# from a tree without deploy/ would otherwise install a build that is never registered with systemd.
precheck_archive() {
    local item
    for item in ModularCA.API ModularCA.Keystore.Unlocker modularca-migrate wwwroot share/sql/adopt-ownership.sql \
                deploy/modularca.service; do
        [[ -e "$SRC/$item" ]] || die "missing from archive: $item; nothing was changed"
    done
}

# ERR trap: remembers where the script failed, for the EXIT trap's message.
on_err() { FAILED_LINE=$1; }

# EXIT trap: removes the staged copy and, when the script dies after stopping the units and before
# it finished (and nothing has started them again), says the install is incomplete. Before anything
# in $APP_DIR was replaced it starts the stopped units again on the installed build; after, it
# leaves them stopped, since they would run a partly copied build, and says how to recover. Runs
# without errexit, so one failing step cannot cut the report short. The exit status is kept.
on_exit() {
    local rc=$? line=$FAILED_LINE units
    set +e
    trap - ERR
    units=${RESTART[*]+"${RESTART[*]}"}
    remove_stage
    if [[ $STOPPED -eq 1 && $DONE -eq 0 && $STARTED -eq 0 ]]; then
        printf '\n\033[31mThe install is INCOMPLETE:\033[0m it stopped with status %s%s.\n' "$rc" "${line:+ at line $line}" >&2
        if [[ -n $units ]]; then
            printf 'It had stopped %s.\n' "$units" >&2
        else
            printf 'No ModularCA unit was running, so none was stopped.\n' >&2
        fi
        if [[ $TOUCHED -eq 1 ]]; then
            printf '%s may hold a partly copied build, so nothing was started on it.\n' "$APP_DIR" >&2
            printf 'Restore %s from your backup, or fix the cause and run install.sh again.\n' "$APP_DIR" >&2
            if [[ -n $units ]]; then
                printf 'Either way, then start them yourself (a re-run finds them stopped and leaves them so), node first:\n' >&2
                printf '  systemctl start %s\n' "$units" >&2
            fi
        else
            printf 'Nothing in %s was changed.\n' "$APP_DIR" >&2
            start_units
        fi
    fi
    return "$rc"
}

# True when the service account can run the new build where it was unpacked.
can_run_in_place() {
    runuser -u "$SERVICE_USER" -- test -x "$1/ModularCA.API" -a -r "$1/ModularCA.API.dll" 2>/dev/null
}

# Copies the new build, without wwwroot or anything the install leaves alone, into a root-owned
# directory beside $APP_DIR (same filesystem, so it is not noexec) that the service account can
# read and run but not write.
stage_build() {
    STAGE=$(mktemp -d "$STAGE_PARENT/.modularca-upgrade-check.XXXXXX") || return 1
    chmod 0755 "$STAGE" || return 1
    find "$SRC" -mindepth 1 -maxdepth 1 \
         ! -name config ! -name keystores ! -name logs ! -name deploy ! -name share ! -name wwwroot \
         ! -name install.sh ! -name README-DEPLOY.md \
         -exec cp -R -t "$STAGE" -- {} + || return 1
    chmod -R u=rwX,go=rX "$STAGE" || return 1
    chmod 0755 "$STAGE/ModularCA.API" || return 1
    can_run_in_place "$STAGE"
}

# Runs DIR's --upgrade-check as the service account, with a clean environment and the installed
# config directory named explicitly. Only the database settings an operator may export are passed on.
run_upgrade_check() {
    local name env=(PATH=/usr/sbin:/usr/bin:/sbin:/bin "HOME=$APP_DIR" LANG=C.UTF-8 DOTNET_ENVIRONMENT=Production
                    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1)
    for name in MODULARCA__DB__APP__PASSWORD MODULARCA__DB__AUDIT__PASSWORD MODULARCA__DB__APP__SSLMODE MODULARCA__DB__AUDIT__SSLMODE; do
        if [[ -n ${!name:-} ]]; then env+=("$name=${!name}"); fi
    done
    (cd / && runuser -u "$SERVICE_USER" -- env -i "${env[@]}" "$1/ModularCA.API" --upgrade-check --config-dir "$APP_DIR/config")
}

# On an upgrade, checks it with the new build before anything in $APP_DIR is replaced. Returns on
# a pass, a fresh install or --skip-upgrade-check; otherwise starts the stopped units again and
# exits with the check's status, having changed nothing.
upgrade_check() {
    if [[ ! -e "$APP_DIR/config/db.yaml" ]]; then
        note "no $APP_DIR/config/db.yaml: a fresh install, so there is no upgrade to check"
        return 0
    fi
    if [[ $SKIP_UPGRADE_CHECK -eq 1 ]]; then
        warn "--skip-upgrade-check: this upgrade was NOT checked before the installed build is replaced."
        warn "The service still dry-runs every pending migration when it starts and applies nothing if one"
        warn "refuses, but it then exits with status 3 on the NEW build; the fix is in the journal."
        return 0
    fi

    local dir=$SRC rc=0
    if ! can_run_in_place "$SRC"; then
        if ! stage_build; then
            remove_stage
            start_units
            die "could not stage the new build for the upgrade check; nothing was changed"
        fi
        dir=$STAGE
    fi
    note "checking the upgrade with the new build, as $SERVICE_USER, against $APP_DIR/config (its dry run is rolled back)"
    run_upgrade_check "$dir" || rc=$?
    remove_stage
    if [[ $rc -eq 0 ]]; then
        note "upgrade check passed"
        return 0
    fi

    case $rc in
        3) printf '\n\033[31mThe upgrade would be refused; nothing was changed.\033[0m The check above lists every problem it found and how to fix each.\n' >&2 ;;
        75) printf '\n\033[31mThe upgrade could not be checked: a database could not be reached or was locked; nothing was changed.\033[0m Try again.\n' >&2 ;;
        *) printf '\n\033[31mThe upgrade check failed (exit status %s); nothing was changed.\033[0m\n' "$rc" >&2 ;;
    esac
    printf 'The installed build in %s is untouched. --skip-upgrade-check overrides this check (emergencies only).\n' "$APP_DIR" >&2
    start_units
    exit "$rc"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    return 0
fi

parse_args "$@"
set -E
trap 'on_err $LINENO' ERR
trap on_exit EXIT

[[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"
[[ -f "$SRC/ModularCA.API" ]] || die "ModularCA.API not found next to this script — run it from inside the extracted archive"
precheck_archive

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

# ── Stop what is running before replacing binaries ─────────────────────────────
# Both units run the binary in $APP_DIR. Each one running now is started again at the end, the
# node before the signer; one that was stopped stays stopped.
for unit in modularca.service modularca-signer.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        RESTART+=("$unit")
    fi
done
# From here until the install finishes, a failure is reported as incomplete (on_exit): before the
# payload is touched it starts these units again; after, it leaves them stopped.
STOPPED=1
if [[ ${#RESTART[@]} -gt 0 ]]; then
    note "stopping ${RESTART[*]}"
    systemctl stop "${RESTART[@]}"
fi

# ── Upgrade check ──────────────────────────────────────────────────────────────
upgrade_check

# ── Payload ────────────────────────────────────────────────────────────────────
note "installing to $APP_DIR"
TOUCHED=1
mkdir -p "$APP_DIR"

# Binaries and static assets are replaced. config/ and keystores/ are NOT in this list: they
# hold the install's identity and secrets, and an upgrade must never touch them. Every part
# copied below was checked present by precheck_archive before anything was stopped.
#
# Note the copy below MERGES rather than replaces, so a file the new build no longer ships
# survives on disk. That is handled for wwwroot (removed first, below). Stale runtime
# assemblies in the app directory are a known remaining gap.

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
     ! -name config ! -name keystores ! -name logs ! -name deploy ! -name share \
     ! -name install.sh ! -name README-DEPLOY.md \
     -exec cp -a {} "$APP_DIR/" \;

mkdir -p "$APP_DIR/config" "$APP_DIR/keystores" "$APP_DIR/logs"

# The schema-ownership repair SQL is run as the PostgreSQL superuser, so it goes root-owned under
# /usr/share and never into $APP_DIR, which the service account owns and can rewrite.
install -d -o root -g root -m 0755 /usr/share/modularca /usr/share/modularca/sql
install -o root -g root -m 0644 "$SRC/share/sql/adopt-ownership.sql" /usr/share/modularca/sql/adopt-ownership.sql

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
chmod 0755 "$APP_DIR/ModularCA.API" "$APP_DIR/ModularCA.Keystore.Unlocker" \
           "$APP_DIR/modularca-migrate"
# On the path, so the MariaDB-to-PostgreSQL migration is one word from anywhere. The .deb
# ships the same link; this is the tarball doing it by hand.
ln -sf "$APP_DIR/modularca-migrate" /usr/local/bin/modularca-migrate

# Application directory: traversable, not world-writable.
chmod 0750 "$APP_DIR"

# Secrets. config/ holds db.yaml (database credentials) and keystore.yaml (the secondary
# keystore passphrase); keystores/ holds the CA private keys. Owner-only, both.
chmod 0700 "$APP_DIR/config" "$APP_DIR/keystores"
find "$APP_DIR/config" -type f -exec chmod 0600 {} \;
find "$APP_DIR/keystores" -type f -exec chmod 0600 {} \; 2>/dev/null || true

chmod 0750 "$APP_DIR/logs"

# ── systemd ────────────────────────────────────────────────────────────────────
# The unit was checked present by precheck_archive, before anything was stopped or replaced.
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

# The node checks both databases and applies migrations before it reports ready, which can take
# longer than an installer should sit waiting. The signer is ordered after it.
DONE=1
start_units

cat <<'NEXT_STEPS'

Installed.

Next steps on a FIRST install:
  1. Create the database (PostgreSQL 14 or later) and a SUPERUSER credential, then populate:
       /opt/modularca/config/setup-database.yaml   (from the .example)
  2. Start the service:  sudo systemctl enable --now modularca
  3. Open the setup wizard and complete it. It runs only while the install is
     unconfigured, and closes itself afterwards.

For an UPGRADE: config/ and keystores/ were left untouched, and unless --skip-upgrade-check
was given, the new build's --upgrade-check passed before anything was replaced. The service
checks both databases,
dry-runs every pending migration and then applies them itself on start. If it refuses
(exit status 3), it has applied nothing, and the journal says why and prints the fix; for
an install made by the setup wizard or --bootstrap before 0.4.0, that is a one-time
ownership repair run as postgres.

Verify:
  systemctl status modularca
  journalctl -u modularca -f
NEXT_STEPS
