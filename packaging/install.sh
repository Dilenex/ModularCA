#!/usr/bin/env bash
#
# ModularCA install / upgrade for a systemd Linux host.
#
# This archive is built on Windows, so it carries NO Unix permission bits or executable flags —
# tar records them, but the source filesystem has nothing meaningful to record. Everything this
# script does about ownership and mode is therefore mandatory, not cosmetic: without it the
# apphost is not executable and the secret-bearing config files are world-readable.
#
# Idempotent. Safe to re-run for an upgrade. The program files belong to root; the service account
# owns only the runtime directories (RUNTIME_DIRS), and once one exists the script never changes
# its ownership, its mode or its contents, so a split install's signer keeps what it was given.
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
SIGNER_USER=modularca-signer
UNIT=/etc/systemd/system/modularca.service
SIGNER_UNIT=/etc/systemd/system/modularca-signer.service
# The directories under $APP_DIR the service writes at run time. Everything else there is program
# files, owned by root. packaging/debian/postinst keeps the same list, and ReadWritePaths= in
# deploy/modularca.service names the same directories.
RUNTIME_DIRS=(config keystores logs backups)
# Parts of the archive that are not copied into $APP_DIR.
NOT_INSTALLED=(deploy share install.sh README-DEPLOY.md)
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
                deploy/modularca.service deploy/modularca-signer.service; do
        [[ -e "$SRC/$item" ]] || die "missing from archive: $item; nothing was changed"
    done
}

# Prints the name of each top-level entry of the archive that is copied into $APP_DIR: the program
# files.
program_entries() {
    local name skip
    while IFS= read -r name; do
        for skip in "${RUNTIME_DIRS[@]}" "${NOT_INSTALLED[@]}"; do
            [[ $name == "$skip" ]] && continue 2
        done
        printf '%s\n' "$name"
    done < <(find "$SRC" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
}

runtime_mode() {
    case $1 in
        logs) echo 0750 ;;
        *) echo 0700 ;;
    esac
}

# True on a split install: the signer's account exists and owns keystores/.
is_split_install() {
    getent passwd "$SIGNER_USER" >/dev/null 2>&1 \
        && [[ -d $APP_DIR/keystores && $(stat -c %U "$APP_DIR/keystores") == "$SIGNER_USER" ]]
}

# Copies the program files into $APP_DIR. wwwroot is removed first rather than merged into: Vite
# names every chunk by content hash, so a merge keeps serving the old chunks to any browser that
# cached an old index.html. Everything under it is build output shipped in this archive.
install_payload() {
    local name
    rm -rf "$APP_DIR/wwwroot"
    while IFS= read -r name; do
        cp -a "$SRC/$name" "$APP_DIR/"
    done < <(program_entries)
}

# Program files belong to root: directories and the executables 0755, everything else 0644. The
# signer runs these binaries too, so the node's account must not be able to replace them.
set_program_ownership() {
    local name
    chown root:root "$APP_DIR"
    chmod 0755 "$APP_DIR"
    while IFS= read -r name; do
        chown -R root:root "$APP_DIR/$name"
        find "$APP_DIR/$name" -type d -exec chmod 0755 {} +
        find "$APP_DIR/$name" -type f -exec chmod 0644 {} +
    done < <(program_entries)
    chmod 0755 "$APP_DIR/ModularCA.API" "$APP_DIR/ModularCA.Keystore.Unlocker" "$APP_DIR/modularca-migrate"
}

# Creates each missing runtime directory for the service account, and hands over one that is
# still root's (a run that stopped part way). One that belongs to anyone else, or is a symlink, is
# left exactly as it is, contents included: on a split install the signer owns keystores/ and
# config/keystore.yaml, and the operator set config/'s group and mode.
prepare_runtime_dirs() {
    local dir path
    for dir in "${RUNTIME_DIRS[@]}"; do
        path=$APP_DIR/$dir
        [[ -L $path ]] && continue
        if [[ ! -d $path ]]; then
            install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m "$(runtime_mode "$dir")" "$path"
        elif [[ $(stat -c %U "$path") == root ]]; then
            chown "$SERVICE_USER:$SERVICE_GROUP" "$path"
            chmod "$(runtime_mode "$dir")" "$path"
        fi
    done
}

# Config examples are only seeded where absent, never over an operator's real config.
seed_examples() {
    local f dest
    for f in "$SRC"/config/*.example; do
        [[ -e "$f" ]] || continue
        dest="$APP_DIR/config/$(basename "$f")"
        [[ -e "$dest" ]] || install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 "$f" "$dest"
    done
}

# Says which top-level entries of $APP_DIR the service account owns that are neither program files
# nor runtime directories: files an older build shipped, or a directory a configured path names.
# They are left as they are.
warn_leftovers() {
    local path name skip found=()
    for path in "$APP_DIR"/* "$APP_DIR"/.[!.]*; do
        [[ -e $path || -L $path ]] || continue
        name=${path##*/}
        for skip in "${RUNTIME_DIRS[@]}"; do
            [[ $name == "$skip" ]] && continue 2
        done
        [[ -e "$SRC/$name" ]] && continue
        [[ $(stat -c %U "$path") == "$SERVICE_USER" ]] && found+=("$name")
    done
    if [[ ${#found[@]} -gt 0 ]]; then
        warn "not part of this build and still owned by $SERVICE_USER, left as they are: ${found[*]}"
        warn "remove what an older build left; a path in config.yaml needs ReadWritePaths= in a drop-in"
    fi
}

# Every ownership and mode the install sets, after the payload is copied.
set_ownership() {
    if is_split_install; then
        note "split install: keystores/ belongs to $SIGNER_USER; the runtime directories are left as they are"
    fi
    set_program_ownership
    prepare_runtime_dirs
    seed_examples
    warn_leftovers
}

# Installs a packaged systemd unit, unless one there differs from it.
install_unit() {
    if [[ -f $2 ]] && ! cmp -s "$1" "$2"; then
        note "unit file differs from the packaged one; leaving yours in place at $2"
        note "  packaged copy: $1"
    else
        note "installing systemd unit $2"
        install -m 0644 "$1" "$2"
    fi
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
    local name
    STAGE=$(mktemp -d "$STAGE_PARENT/.modularca-upgrade-check.XXXXXX") || return 1
    chmod 0755 "$STAGE" || return 1
    while IFS= read -r name; do
        [[ $name == wwwroot ]] && continue
        cp -R -t "$STAGE" -- "$SRC/$name" || return 1
    done < <(program_entries)
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

# The program files are replaced; the runtime directories are never copied into. Every part
# copied was checked present by precheck_archive before anything was stopped. The copy merges, so
# a top-level file the new build no longer ships survives; warn_leftovers names any the service
# account owns.
install_payload

# The schema-ownership repair SQL is run as the PostgreSQL superuser, so it goes root-owned under
# /usr/share rather than into $APP_DIR.
install -d -o root -g root -m 0755 /usr/share/modularca /usr/share/modularca/sql
install -o root -g root -m 0644 "$SRC/share/sql/adopt-ownership.sql" /usr/share/modularca/sql/adopt-ownership.sql

# ── Ownership and modes ────────────────────────────────────────────────────────
# The archive carries none of this; see the header.
note "setting ownership and permissions"
set_ownership

# On the path, so the MariaDB-to-PostgreSQL migration is one word from anywhere. The .deb
# ships the same link; this is the tarball doing it by hand.
ln -sf "$APP_DIR/modularca-migrate" /usr/local/bin/modularca-migrate

# ── systemd ────────────────────────────────────────────────────────────────────
# Both units were checked present by precheck_archive, before anything was stopped or replaced.
# The signer's unit is installed for a split install and never enabled here.
install_unit "$SRC/deploy/modularca.service" "$UNIT"
install_unit "$SRC/deploy/modularca-signer.service" "$SIGNER_UNIT"
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
