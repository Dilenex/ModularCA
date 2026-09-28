#!/bin/bash
# Runs packaging/debian/db-ownership.sh (the .deb's legacy ownership repair) against hostile and
# benign db.yaml files, with psql, runuser, timeout, systemctl, id, getent, stat and logger
# replaced by stubs. Needs no PostgreSQL and no root.
#
#   bash packaging/debian/tests/db-ownership-test.sh
#
# Asserts: a hostile, remote or escaping value in db.yaml is refused before any psql call, nothing
# in it is ever executed, and the names that pass validation reach psql only as -v variables.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../db-ownership.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASSES=0
FAILS=0

mkdir -p "$WORK/bin" "$WORK/sql"
: > "$WORK/sql/adopt-ownership.sql"

printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/pgrep-running"
printf '#!/bin/sh\nexit 1\n' > "$WORK/bin/pgrep-none"
chmod +x "$WORK/bin/pgrep-running" "$WORK/bin/pgrep-none"

cat > "$WORK/bin/psql" <<'STUB'
#!/bin/bash
st="$(cd "$(dirname "$0")/.." && pwd)"
{ printf 'ARGV:'; for a in "$@"; do printf ' [%s]' "$a"; done; printf ' PGPASSWORD=[%s]\n' "${PGPASSWORD:-}"; } >> "$st/calls"
db=; role=; kind=; target=
while [ $# -gt 0 ]; do
  case "$1" in
    -v)
      case "$2" in
        db=*) db="${2#db=}" ;;
        role=*) role="${2#role=}" ;;
        kind=*) kind="${2#kind=}" ;;
        target=*) target="${2#target=}" ;;
      esac
      shift 2 ;;
    *) shift ;;
  esac
done
input=$(cat)
f="$st/db-$db"
if [ ! -f "$f" ]; then echo "psql: error: FATAL:  database \"$db\" does not exist" >&2; exit 2; fi
. "$f"
case "$input" in
  *'count(*) FILTER'*)
    if [ "$role" = "$ROLE" ]; then echo "1 $ADOPT $TOTAL"; else echo "0 0 0"; fi ;;
  *'\i :repair_sql'*)
    echo "psql:adopt-ownership.sql:41: NOTICE:  modularca: $ADOPT object(s) in $db now owned by $target" >&2
    printf 'ROLE=%s\nADOPT=0\nTOTAL=0\n' "$ROLE" > "$f"
    echo "REPAIRED db=$db kind=$kind target=$target" >> "$st/calls" ;;
  *) echo "unexpected script" >&2; exit 7 ;;
esac
STUB
chmod +x "$WORK/bin/psql"

# run MODE: runs main MODE in a subshell with the stubs; prints its output, returns its status.
run() {
    : > "$WORK/calls"
    : > "$WORK/systemctl"
    rm -f "$WORK/PWNED"
    (
        DB_OWNERSHIP_SOURCED=1 . "$SCRIPT"
        PATH="$WORK/bin:$PATH"
        DB_YAML="$WORK/db.yaml"
        REPAIR_SQL="$WORK/sql/adopt-ownership.sql"
        SYSTEMD_DIR="${T_SYSTEMD_DIR:-$WORK}"
        PGREP="${T_PGREP:-pgrep}"
        PGPASSWORD=leaked
        export PGPASSWORD
        id() { echo 0; }
        getent() { return 0; }
        logger() { :; }
        stat() { echo "0 644"; }
        runuser() { shift 3; "$@"; }
        timeout() { shift 3; "$@"; }
        systemctl() {
            echo "$*" >> "$WORK/systemctl"
            case "$1" in is-active) return 1 ;; esac
            return 0
        }
        main "$1"
        exit $?
    ) 2>&1
}

ok() { PASSES=$((PASSES + 1)); printf 'ok   %s\n' "$1"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# yaml APP_LINES AUDIT_LINES: writes db.yaml with the given App and Audit blocks.
yaml() {
    printf 'App:\n%s\nAudit:\n%s\n' "$1" "$2" > "$WORK/db.yaml"
}

state() { printf 'ROLE=%s\nADOPT=%s\nTOTAL=%s\n' "$2" "$3" "$4" > "$WORK/db-$1"; }

BENIGN_AUDIT='  Host: localhost
  Port: 5432
  Database: modularca-audit
  Username: modularca_audit'

# hostile NAME APP_BLOCK: App is hostile, Audit is benign and sound. The App values must never
# reach psql in any form, nothing may run, and no unit may be stopped.
hostile() {
    name=$1
    rm -f "$WORK"/db-*
    state modularca-audit modularca_audit 0 0
    yaml "$2" "$BENIGN_AUDIT"
    out=$(run repair)
    rc=$?
    if [ -e "$WORK/PWNED" ]; then fail "$name" "a value was executed"; return; fi
    if [ "$rc" -ne 2 ]; then fail "$name" "exit $rc, expected 2 (skipped); output: $out"; return; fi
    if grep -q "stop" "$WORK/systemctl"; then fail "$name" "a unit was stopped"; return; fi
    if grep -q "REPAIRED" "$WORK/calls"; then fail "$name" "a repair ran"; return; fi
    if grep -v 'modularca-audit\|modularca_audit' "$WORK/calls" | grep -q .; then
        fail "$name" "psql was called for something other than the benign audit database: $(cat "$WORK/calls")"; return
    fi
    if ! printf '%s' "$out" | grep -q "left alone"; then fail "$name" "no refusal was printed: $out"; return; fi
    ok "$name"
}

P="$WORK/PWNED"

hostile "single quote and statement in the database name" '  Host: localhost
  Port: 5432
  Database: "x'"'"'; DROP DATABASE postgres; --"
  Username: modularca_app'

hostile "double quote in the database name" "  Host: localhost
  Port: 5432
  Database: 'a\"b'
  Username: modularca_app"

hostile "semicolon in the database name" '  Host: localhost
  Port: 5432
  Database: x;touch '"$P"'
  Username: modularca_app'

hostile "command substitution in the role" '  Host: localhost
  Port: 5432
  Database: modularca-app
  Username: "$(touch '"$P"')"'

hostile "backticks in the role" '  Host: localhost
  Port: 5432
  Database: modularca-app
  Username: "`touch '"$P"'`"'

hostile "a quoted name broken over two lines" '  Host: localhost
  Port: 5432
  Database: "modularca
    -app"
  Username: modularca_app'

hostile "an escaped newline in the database name" '  Host: localhost
  Port: 5432
  Database: "modularca\napp"
  Username: modularca_app'

hostile "a database name that is a psql option" '  Host: localhost
  Port: 5432
  Database: -f/etc/shadow
  Username: modularca_app'

hostile "a variable in the database name" '  Host: localhost
  Port: 5432
  Database: $HOME
  Username: modularca_app'

hostile "a space in the role" '  Host: localhost
  Port: 5432
  Database: modularca-app
  Username: modularca app'

hostile "a name longer than 63 bytes" '  Host: localhost
  Port: 5432
  Database: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  Username: modularca_app'

hostile "an option smuggled in the port" '  Host: localhost
  Port: "5432 -h evil.example"
  Database: modularca-app
  Username: modularca_app'

hostile "a remote host name" '  Host: db.example.com
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "a remote address" '  Host: 10.0.0.5
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "a socket path that climbs out" '  Host: /var/run/postgresql/../../tmp
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "a socket path carrying a command" '  Host: "/var/run/postgresql;touch '"$P"'"
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "a socket directory the service account could create" '  Host: /opt/modularca/run
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "a socket directory below an allowed one" '  Host: /tmp/evil
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

hostile "an allowed socket directory with a trailing slash" '  Host: /run/postgresql/
  Port: 5432
  Database: modularca-app
  Username: modularca_app'

# Each allowed socket directory reaches psql as -h.
for dir in /var/run/postgresql /run/postgresql /tmp; do
    rm -f "$WORK"/db-*
    state modularca-app modularca_app 0 0
    state modularca-audit modularca_audit 0 0
    yaml "  Host: $dir
  Port: 5432
  Database: modularca-app
  Username: modularca_app" "$BENIGN_AUDIT"
    out=$(run check)
    rc=$?
    name="the socket directory $dir is allowed"
    if [ "$rc" -ne 0 ]; then fail "$name" "exit $rc; output: $out"
    elif ! grep -q "\[-h\] \[$dir\]" "$WORK/calls"; then fail "$name" "the socket was not passed: $(cat "$WORK/calls")"
    else ok "$name"
    fi
done

# A benign install over a unix socket on a non-default port: repaired, and every name reaches
# psql only as a -v variable, the socket and port only as -h and -p, and PGPASSWORD never.
rm -f "$WORK"/db-*
state modularca-app modularca_app 7 7
state modularca-audit modularca_audit 2 2
yaml '  Host: /var/run/postgresql
  Port: 5433
  Database: modularca-app
  Username: modularca_app' '  Host: /var/run/postgresql
  Port: 5433
  Database: modularca-audit
  Username: modularca_audit'
out=$(run repair)
rc=$?
name="a local socket install is repaired with names passed only as psql variables"
bad=$(grep -o '\[[^]]*modularca[^]]*\]' "$WORK/calls" | grep -v '^\[\(db\|role\|target\)=modularca[-_]\(app\|audit\)\]$')
if [ "$rc" -ne 0 ]; then fail "$name" "exit $rc; output: $out"
elif ! grep -q "REPAIRED db=modularca-app kind=app target=modularca_app" "$WORK/calls"; then fail "$name" "the app database was not repaired"
elif ! grep -q "REPAIRED db=modularca-audit kind=audit target=modularca_audit" "$WORK/calls"; then fail "$name" "the audit database was not repaired"
elif [ -n "$bad" ]; then fail "$name" "a name reached psql outside a -v variable: $bad"
elif ! grep -q '\[-h\] \[/var/run/postgresql\]' "$WORK/calls" || ! grep -q '\[-p\] \[5433\]' "$WORK/calls"; then fail "$name" "socket or port not passed"
elif grep -q 'PGPASSWORD=\[leaked\]' "$WORK/calls"; then fail "$name" "PGPASSWORD reached psql"
else ok "$name"
fi

# The read-only check never repairs and never stops a unit.
rm -f "$WORK"/db-*
state modularca-app modularca_app 3 3
state modularca-audit modularca_audit 0 0
yaml '  Host: localhost
  Port: 5432
  Database: modularca-app
  Username: modularca_app' "$BENIGN_AUDIT"
out=$(run check)
rc=$?
name="check reports a needed repair and changes nothing"
if [ "$rc" -ne 1 ]; then fail "$name" "exit $rc; output: $out"
elif grep -q "REPAIRED" "$WORK/calls"; then fail "$name" "check repaired"
elif grep -q "stop" "$WORK/systemctl"; then fail "$name" "check stopped a unit"
else ok "$name"
fi

# Without systemd the repair runs only when pgrep confirms no ModularCA.API process; otherwise it
# is skipped, the manual command is printed, and nothing is repaired.
no_systemd() {
    name=$1 pgrep=$2 expect_repair=$3
    rm -f "$WORK"/db-*
    state modularca-app modularca_app 3 3
    state modularca-audit modularca_audit 0 0
    yaml '  Host: localhost
  Port: 5432
  Database: modularca-app
  Username: modularca_app' "$BENIGN_AUDIT"
    out=$(T_SYSTEMD_DIR="$WORK/no-systemd" T_PGREP="$pgrep" run repair)
    rc=$?
    if [ "$expect_repair" = 1 ]; then
        if [ "$rc" -ne 0 ]; then fail "$name" "exit $rc; output: $out"
        elif ! grep -q "REPAIRED db=modularca-app" "$WORK/calls"; then fail "$name" "the repair did not run"
        else ok "$name"
        fi
    else
        if [ "$rc" -ne 1 ]; then fail "$name" "exit $rc, expected 1; output: $out"
        elif grep -q "REPAIRED" "$WORK/calls"; then fail "$name" "the repair ran"
        elif ! printf '%s' "$out" | grep -q "sudo -u postgres psql -X -d 'modularca-app' -v kind=app"; then fail "$name" "no manual command: $out"
        else ok "$name"
        fi
    fi
}
no_systemd "without systemd and without pgrep the repair is skipped" "$WORK/bin/no-such-pgrep" 0
no_systemd "without systemd and with ModularCA.API running the repair is skipped" "$WORK/bin/pgrep-running" 0
no_systemd "without systemd and with no ModularCA.API process the repair runs" "$WORK/bin/pgrep-none" 1

printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
