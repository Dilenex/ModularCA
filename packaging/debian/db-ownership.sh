#!/bin/sh
# ModularCA — schema ownership check and repair on a local PostgreSQL. Run as root.
#
#   sh /usr/share/modularca/db-ownership.sh check    read-only: 0 sound, 1 not sound, 2 cannot tell
#   sh /usr/share/modularca/db-ownership.sh repair   0 sound or repaired, 1 not sound afterwards, 2 skipped
#
# The .deb postinst runs `repair` on every configure. It acts only when all of these hold for a
# database: its Host in db.yaml is local (localhost, 127.0.0.1, ::1, or the socket directory
# /var/run/postgresql, /run/postgresql or /tmp, and no other: db.yaml is not root's), every
# name read from db.yaml matches a strict pattern, and a read-only probe finds objects its runtime
# role cannot alter that an administrator created (a wizard or CLI install made before 0.4.0). It
# then stops the ModularCA units, runs the root-owned adopt-ownership.sql as the postgres OS user
# over peer authentication, and starts again the units it stopped. Without systemd it repairs only
# when pgrep confirms no ModularCA.API process runs, and otherwise prints the command to run by
# hand. It never fails the caller.
#
# db.yaml is writable by the service account: it is read as that account, never opened by root,
# and every value reaches psql only as a -v variable. Nothing under /opt/modularca is executed, no
# credential is read or stored, and nothing is written outside the database and the journal.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset IFS
umask 022

APP_DIR=/opt/modularca
DB_YAML=$APP_DIR/config/db.yaml
REPAIR_SQL=/usr/share/modularca/sql/adopt-ownership.sql
SERVICE_USER=modularca
PG_OS_USER=postgres
UNITS="modularca.service modularca-signer.service"
SYSTEMD_DIR=/run/systemd/system
PGREP=pgrep
TAG=modularca-db-ownership
PROBE_TIMEOUT=60
REPAIR_TIMEOUT=360

DBYAML=
STOPPED=

say() {
    printf 'modularca: %s\n' "$*" >&2
    if command -v logger >/dev/null 2>&1; then
        logger -t "$TAG" -- "$*" 2>/dev/null || true
    fi
}

relay() {
    printf '%s\n' "$1" | while IFS= read -r line; do
        if [ -n "$line" ]; then say "  $line"; fi
    done
}

is_identifier() {
    case $1 in
        ''|-*|*[!A-Za-z0-9_-]*) return 1 ;;
    esac
    [ "${#1}" -le 63 ]
}

is_port() {
    case $1 in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

local_socket() {
    case $1 in
        localhost|127.0.0.1|::1) return 0 ;;
        /var/run/postgresql|/run/postgresql|/tmp)
            printf '%s' "$1"
            return 0 ;;
    esac
    return 1
}

yaml_get() {
    printf '%s\n' "$DBYAML" | awk -v s="$1" -v k="$2" '
        { sub(/\r$/, "") }
        /^[^ \t#]/ { sec = $0; sub(/[ \t]*:.*$/, "", sec); next }
        sec == s && $1 == k ":" {
            v = $0
            sub(/^[ \t]*[^:]*:[ \t]*/, "", v)
            sub(/[ \t]+$/, "", v)
            if (v ~ /^".*"$/ || v ~ /^'\''.*'\''$/) v = substr(v, 2, length(v) - 2)
            print v
            exit
        }'
}

load_target() {
    T_DB=$(yaml_get "$2" Database)
    T_ROLE=$(yaml_get "$2" Username)
    T_PORT=$(yaml_get "$2" Port)
    _host=$(yaml_get "$2" Host)
    [ -n "$T_PORT" ] || T_PORT=5432
    if [ -z "$T_DB" ] && [ -z "$T_ROLE" ]; then
        say "db.yaml has no $2 database; the $1 database is left alone."
        return 1
    fi
    if ! is_identifier "$T_DB" || ! is_identifier "$T_ROLE"; then
        say "$2.Database or $2.Username in db.yaml is not a plain name (letters, digits, _ and -, at most 63, not starting with -); the $1 database is left alone."
        return 1
    fi
    if ! is_port "$T_PORT"; then
        say "$2.Port in db.yaml is not a port number; the $1 database is left alone."
        return 1
    fi
    if ! T_SOCKET=$(local_socket "$_host"); then
        say "$2.Host in db.yaml is not local (localhost, 127.0.0.1, ::1, or the socket directory /var/run/postgresql, /run/postgresql or /tmp); the $1 database '$T_DB' is left alone."
        return 1
    fi
    return 0
}

psql_local() {
    _port=$1 _socket=$2 _limit=$3 _opts=$4
    shift 4
    set -- -X -q -w -v ON_ERROR_STOP=1 -p "$_port" -d postgres "$@"
    if [ -n "$_socket" ]; then set -- -h "$_socket" "$@"; fi
    timeout -k 5 "$_limit" runuser -u "$PG_OS_USER" -- env -i PATH="$PATH" LC_ALL=C.UTF-8 \
        PGCONNECT_TIMEOUT=10 PGAPPNAME="$TAG" PGOPTIONS="$_opts" psql "$@"
}

probe() {
    psql_local "$1" "$2" "$PROBE_TIMEOUT" \
        '-c default_transaction_read_only=on -c statement_timeout=30s -c lock_timeout=5s' \
        -A -t -F ' ' -v "db=$3" -v "role=$4" <<'SQL'
\connect :"db"
SELECT (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = :'role'),
       count(*) FILTER (WHERE x.adoptable),
       count(*)
  FROM (SELECT (w.rolsuper OR w.rolcreatedb OR w.rolcreaterole OR w.oid = d.datdba)
               AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend s
                                WHERE s.classid = 'pg_catalog.pg_class'::regclass AND s.objid = c.oid
                                  AND c.relkind = 'S' AND s.deptype IN ('a', 'i')) AS adoptable
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_roles w ON w.oid = c.relowner
          JOIN pg_catalog.pg_database d ON d.datname = current_database()
         WHERE c.relnamespace = 'public'::regnamespace
           AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
           AND NOT pg_catalog.pg_has_role((SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :'role'), c.relowner, 'USAGE')
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e
                            WHERE e.classid = 'pg_catalog.pg_class'::regclass AND e.objid = c.oid AND e.deptype = 'e')) x;
SQL
}

adopt() {
    psql_local "$1" "$2" "$REPAIR_TIMEOUT" '-c statement_timeout=300s' \
        -v "db=$3" -v "kind=$4" -v "target=$5" -v "repair_sql=$REPAIR_SQL" <<'SQL'
\connect :"db"
\i :repair_sql
SQL
}

# probe_db LABEL PORT SOCKET DB ROLE: sets P_ADOPT and P_TOTAL; 0 probed, 1 cannot tell.
probe_db() {
    P_ADOPT=0 P_TOTAL=0
    _label=$1 _port=$2 _db=$4 _role=$5
    _out=$(probe "$2" "$3" "$4" "$5" 2>&1)
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        say "could not read the $_label database '$_db' as $PG_OS_USER on local port $_port (psql exit $_rc); it is left alone:"
        relay "$_out"
        return 1
    fi
    case $_out in
        *[!0-9\ ]*|'') say "unexpected probe output for the $_label database '$_db'; it is left alone."; return 1 ;;
    esac
    # shellcheck disable=SC2086
    set -- $_out
    if [ "$#" -ne 3 ]; then
        say "unexpected probe output for the $_label database '$_db'; it is left alone."
        return 1
    fi
    if [ "$1" -eq 0 ]; then
        say "role '$_role' does not exist in the local cluster on port $_port; the database '$_db' is left alone."
        return 1
    fi
    P_ADOPT=$2 P_TOTAL=$3
    return 0
}

manual_command() {
    _h=
    if [ -n "$2" ]; then _h=" -h '$2'"; fi
    _p=
    if [ "$1" != 5432 ]; then _p=" -p $1"; fi
    printf "sudo -u postgres psql -X%s%s -d '%s' -v kind=%s -v target='%s' -f %s" "$_h" "$_p" "$3" "$4" "$5" "$REPAIR_SQL"
}

repair_sql_ok() {
    if [ ! -f "$REPAIR_SQL" ] || [ -L "$REPAIR_SQL" ]; then
        say "$REPAIR_SQL is missing or not a regular file; the repair is not attempted."
        return 1
    fi
    for _path in "$REPAIR_SQL" "${REPAIR_SQL%/*}"; do
        if ! _st=$(stat -c '%u %a' -- "$_path" 2>/dev/null); then
            say "cannot stat $_path; the repair is not attempted."
            return 1
        fi
        _mode=${_st#* }
        _other=${_mode#"${_mode%?}"}
        _group=${_mode%?}
        _group=${_group#"${_group%?}"}
        case "${_st%% *}:$_group$_other" in
            0:*[2367]*|0:) say "$_path is writable by others than root; the repair is not attempted."; return 1 ;;
            0:*) ;;
            *) say "$_path is not owned by root; the repair is not attempted."; return 1 ;;
        esac
    done
    return 0
}

stop_units() {
    if [ ! -d "$SYSTEMD_DIR" ]; then
        if command -v "$PGREP" >/dev/null 2>&1; then
            "$PGREP" -x ModularCA.API >/dev/null 2>&1
            case $? in
                1) return 0 ;;
                0) say "systemd is not running here and a ModularCA.API process is; the repair is not attempted while it runs." ;;
                *) say "systemd is not running here and pgrep failed; the repair is not attempted." ;;
            esac
        else
            say "systemd is not running here and without pgrep no ModularCA process can be confirmed stopped; the repair is not attempted."
        fi
        return 1
    fi
    _active=
    for _u in $UNITS; do
        if systemctl is-active --quiet "$_u" 2>/dev/null; then _active="$_active $_u"; fi
    done
    if [ -z "$_active" ]; then return 0; fi
    STOPPED=$_active
    say "stopping$_active for the repair"
    # shellcheck disable=SC2086
    if systemctl stop $_active; then return 0; fi
    say "could not stop$_active; the repair is not attempted."
    return 1
}

restore_units() {
    for _u in $STOPPED; do
        say "starting $_u again"
        systemctl start --no-block "$_u" || say "could not start $_u; start it with: systemctl start $_u"
    done
    STOPPED=
}

main() {
    case ${1:-} in
        check|repair) MODE=$1 ;;
        *) echo "usage: $0 check|repair" >&2; return 2 ;;
    esac
    if [ "$(id -u)" != 0 ]; then
        echo "run as root" >&2
        return 2
    fi
    cd / || return 2

    if [ ! -e "$DB_YAML" ]; then
        if [ "$MODE" = check ]; then say "no $DB_YAML yet: nothing to check."; fi
        return 2
    fi
    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        say "there is no $SERVICE_USER account; schema ownership not checked."
        return 2
    fi
    if ! getent passwd "$PG_OS_USER" >/dev/null 2>&1 || ! command -v psql >/dev/null 2>&1; then
        say "no local PostgreSQL client and $PG_OS_USER account; schema ownership not checked by the package."
        return 2
    fi
    if ! DBYAML=$(runuser -u "$SERVICE_USER" -- head -c 65536 -- "$DB_YAML" 2>/dev/null); then
        say "$DB_YAML could not be read as $SERVICE_USER; schema ownership not checked."
        return 2
    fi

    APP_OK=0 AUDIT_OK=0
    if load_target application App; then
        APP_OK=1 APP_DB=$T_DB APP_ROLE=$T_ROLE APP_PORT=$T_PORT APP_SOCKET=$T_SOCKET
    fi
    if load_target audit Audit; then
        AUDIT_OK=1 AUDIT_DB=$T_DB AUDIT_ROLE=$T_ROLE AUDIT_PORT=$T_PORT AUDIT_SOCKET=$T_SOCKET
    fi
    if [ "$APP_OK" = 1 ] && [ "$AUDIT_OK" = 1 ]; then
        if [ "$APP_DB" = "$AUDIT_DB" ] || [ "$APP_ROLE" = "$AUDIT_ROLE" ]; then
            say "db.yaml names the same database or role for App and Audit; both are left alone."
            APP_OK=0 AUDIT_OK=0
        fi
    fi

    UNKNOWN=0 NOT_SOUND=0 NEED_APP=0 NEED_AUDIT=0
    if [ "$APP_OK" = 1 ]; then
        if probe_db application "$APP_PORT" "$APP_SOCKET" "$APP_DB" "$APP_ROLE"; then
            report application "$APP_DB" "$APP_ROLE" && NEED_APP=1
        else
            UNKNOWN=1
        fi
    else
        UNKNOWN=1
    fi
    if [ "$AUDIT_OK" = 1 ]; then
        if probe_db audit "$AUDIT_PORT" "$AUDIT_SOCKET" "$AUDIT_DB" "$AUDIT_ROLE"; then
            report audit "$AUDIT_DB" "$AUDIT_ROLE" && NEED_AUDIT=1
        else
            UNKNOWN=1
        fi
    else
        UNKNOWN=1
    fi

    if [ "$NEED_APP" = 0 ] && [ "$NEED_AUDIT" = 0 ]; then
        if [ "$NOT_SOUND" = 1 ]; then return 1; fi
        if [ "$UNKNOWN" = 1 ]; then return 2; fi
        return 0
    fi
    if [ "$MODE" = check ]; then
        say "a repair is needed. Run: sudo sh $0 repair"
        return 1
    fi

    FAILED=0
    if ! repair_sql_ok || ! stop_units; then
        FAILED=1
    else
        if [ "$NEED_APP" = 1 ]; then
            repair_one application app "$APP_PORT" "$APP_SOCKET" "$APP_DB" "$APP_ROLE" || FAILED=1
        fi
        if [ "$NEED_AUDIT" = 1 ]; then
            repair_one audit audit "$AUDIT_PORT" "$AUDIT_SOCKET" "$AUDIT_DB" "$AUDIT_ROLE" || FAILED=1
        fi
    fi
    restore_units

    if [ "$FAILED" = 0 ]; then
        say "schema ownership repaired."
        return 0
    fi
    say "schema ownership was NOT repaired. The package install continues; the service will refuse to start"
    say "(exit status 3) until it is. With every ModularCA unit stopped (systemctl stop $UNITS), run:"
    if [ "$NEED_APP" = 1 ]; then say "  $(manual_command "$APP_PORT" "$APP_SOCKET" "$APP_DB" app "$APP_ROLE")"; fi
    if [ "$NEED_AUDIT" = 1 ]; then say "  $(manual_command "$AUDIT_PORT" "$AUDIT_SOCKET" "$AUDIT_DB" audit "$AUDIT_ROLE")"; fi
    return 1
}

# report LABEL DB ROLE: logs the probe result; 0 when the package should repair.
report() {
    if [ "$P_TOTAL" -eq 0 ]; then
        say "$1 database '$2': every object is owned by '$3'."
        return 1
    fi
    if [ "$P_ADOPT" -eq 0 ]; then
        say "$1 database '$2': $P_TOTAL object(s) are owned by ordinary roles other than '$3'. The package does not move those; the service lists them if it refuses to start."
        NOT_SOUND=1
        return 1
    fi
    say "$1 database '$2': $P_TOTAL object(s) that '$3' cannot alter, $P_ADOPT created by an administrator (a pre-0.4.0 wizard or CLI install)."
    return 0
}

# repair_one LABEL KIND PORT SOCKET DB ROLE: runs adopt-ownership.sql, then probes again.
repair_one() {
    say "handing the $1 database '$5' to '$6': $REPAIR_SQL as $PG_OS_USER (kind=$2, target=$6)"
    _out=$(adopt "$3" "$4" "$5" "$2" "$6" 2>&1)
    _rc=$?
    relay "$_out"
    if [ "$_rc" -ne 0 ]; then
        say "the repair of '$5' failed (psql exit $_rc); nothing in it was changed."
        return 1
    fi
    if ! probe_db "$1" "$3" "$4" "$5" "$6"; then
        return 1
    fi
    if [ "$P_TOTAL" -ne 0 ]; then
        say "after the repair, '$6' still cannot alter $P_TOTAL object(s) in '$5'."
        return 1
    fi
    say "$1 database '$5': every object is now owned by '$6'."
    return 0
}

if [ "${DB_OWNERSHIP_SOURCED:-}" != 1 ]; then
    main "$@"
    exit $?
fi
