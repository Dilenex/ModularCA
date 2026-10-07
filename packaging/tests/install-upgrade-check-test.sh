#!/bin/bash
# Runs the upgrade-check step of packaging/install.sh with its functions loaded and runuser and
# systemctl replaced by stubs; the new build is a stub that records how it was run and exits with
# a chosen status. Needs no root, no PostgreSQL and no systemd.
#
#   bash packaging/tests/install-upgrade-check-test.sh
#
# Asserts: a fresh install and --skip-upgrade-check skip the check; otherwise the new build runs as
# the service account with a clean environment and the installed config directory; a staged copy
# leaves out config, keystores and wwwroot and is removed afterwards; a non-zero status starts the
# stopped units again, says nothing was changed and exits with that status. The archive pre-check
# refuses a missing part, the systemd unit included, before anything is touched. When the script
# dies before it finished, the EXIT trap says the install is incomplete (accurately when nothing
# was running), runs to the end even if a step in it fails, and starts the stopped units again,
# once, only if nothing in the install directory was replaced; otherwise it leaves them stopped
# and says to restore or re-run, then start them.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../install.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASSES=0
FAILS=0

mkdir -p "$WORK/src/config" "$WORK/src/keystores" "$WORK/src/wwwroot" "$WORK/src/runtimes" "$WORK/app/config" "$WORK/stage-parent"
: > "$WORK/src/ModularCA.API.dll"
: > "$WORK/src/config/db.yaml.example"
: > "$WORK/src/keystores/secret"
: > "$WORK/src/wwwroot/index.html"
: > "$WORK/src/runtimes/lib.so"
echo installed > "$WORK/app/marker"
cat > "$WORK/src/ModularCA.API" <<STUB
#!/bin/bash
{
  printf 'ARGV:'; for a in "\$@"; do printf ' [%s]' "\$a"; done; printf '\n'
  printf 'DIR=%s\n' "\$(cd "\$(dirname "\$0")" && pwd)"
  printf 'HOME=%s LEAK=[%s] APPPW=[%s] CWD=%s\n' "\$HOME" "\${LEAK:-}" "\${MODULARCA__DB__APP__PASSWORD:-}" "\$(pwd)"
  printf 'FILES=%s\n' "\$(cd "\$(dirname "\$0")" && ls | tr '\n' ' ')"
} >> "$WORK/check-calls"
echo "UPGRADE CHECK: stub"
exit "\$(cat "$WORK/check-exit")"
STUB
chmod +x "$WORK/src/ModularCA.API"

# run MODE STATUS [ARGS...]: runs parse_args ARGS then upgrade_check in a subshell with the stubs.
# MODE is inplace or staged. Prints the output; returns the subshell's status.
run() {
    local mode=$1
    echo "$2" > "$WORK/check-exit"
    shift 2
    : > "$WORK/check-calls"
    : > "$WORK/systemctl"
    : > "$WORK/runuser"
    (
        . "$SCRIPT"
        set +e
        APP_DIR="$WORK/app"
        SRC="$WORK/src"
        STAGE_PARENT="$WORK/stage-parent"
        RESTART=(modularca.service modularca-signer.service)
        LEAK=leaked
        MODULARCA__DB__APP__PASSWORD='p w;$(touch PWNED)'
        export LEAK MODULARCA__DB__APP__PASSWORD
        runuser() { printf '%s\n' "$2" >> "$WORK/runuser"; shift 3; "$@"; }
        systemctl() { printf '%s\n' "$*" >> "$WORK/systemctl"; }
        if [ "$mode" = staged ]; then
            can_run_in_place() { [[ $1 != "$SRC" ]]; }
        fi
        parse_args "$@"
        trap remove_stage EXIT
        upgrade_check
        echo "RETURNED"
    ) 2>&1
}

check() {
    if eval "$2"; then
        PASSES=$((PASSES + 1))
    else
        FAILS=$((FAILS + 1))
        printf 'FAIL: %s\n  (%s)\n' "$1" "$2"
        printf '  output: %s\n' "$OUT"
    fi
}

OUT=$(run inplace 0); RC=$?
check "a fresh install runs no check" '[ "$RC" = 0 ] && [ ! -s "$WORK/check-calls" ] && printf "%s" "$OUT" | grep -q "fresh install" && printf "%s" "$OUT" | grep -q RETURNED'

: > "$WORK/app/config/db.yaml"

OUT=$(run inplace 3 --skip-upgrade-check); RC=$?
check "--skip-upgrade-check runs no check and warns" '[ "$RC" = 0 ] && [ ! -s "$WORK/check-calls" ] && printf "%s" "$OUT" | grep -q "was NOT checked" && printf "%s" "$OUT" | grep -q RETURNED'
check "--skip-upgrade-check starts nothing" '[ ! -s "$WORK/systemctl" ]'

OUT=$(run inplace 0); RC=$?
check "a passing check returns" '[ "$RC" = 0 ] && printf "%s" "$OUT" | grep -q RETURNED && printf "%s" "$OUT" | grep -q "upgrade check passed"'
check "the check runs as the service account" '[ "$(sort -u "$WORK/runuser")" = modularca ]'
check "the check names the installed config directory" 'grep -qF "ARGV: [--upgrade-check] [--config-dir] [$WORK/app/config]" "$WORK/check-calls"'
check "the check runs in place when it can" 'grep -qx "DIR=$WORK/src" "$WORK/check-calls"'
check "the environment is clean but for the database settings" 'grep -qF "HOME=$WORK/app LEAK=[] APPPW=[p w;\$(touch PWNED)] CWD=/" "$WORK/check-calls"'
check "a database setting is passed as data" '[ ! -e PWNED ] && [ ! -e /PWNED ] && [ ! -e "$WORK/PWNED" ]'
check "a pass starts nothing" '[ ! -s "$WORK/systemctl" ]'

OUT=$(run staged 0); RC=$?
check "a staged check passes" '[ "$RC" = 0 ] && printf "%s" "$OUT" | grep -q RETURNED'
check "the staged copy is beside the install" 'grep -q "^DIR=$WORK/stage-parent/.modularca-upgrade-check\." "$WORK/check-calls"'
check "the staged copy leaves out config, keystores and wwwroot" 'grep -qx "FILES=ModularCA.API ModularCA.API.dll runtimes " "$WORK/check-calls"'
check "the staged copy is removed" '[ -z "$(ls -A "$WORK/stage-parent")" ]'

OUT=$(run staged 3); RC=$?
check "a refusal exits 3" '[ "$RC" = 3 ] && ! printf "%s" "$OUT" | grep -q RETURNED'
check "a refusal says nothing was changed" 'printf "%s" "$OUT" | grep -q "The upgrade would be refused; nothing was changed."'
check "a refusal prints the check output" 'printf "%s" "$OUT" | grep -q "UPGRADE CHECK: stub"'
check "a refusal starts the stopped units again, node first" '[ "$(cat "$WORK/systemctl")" = "$(printf "start --no-block modularca.service\nstart --no-block modularca-signer.service")" ]'
check "a refusal leaves the installed payload alone" '[ "$(cat "$WORK/app/marker")" = installed ] && [ -e "$WORK/app/config/db.yaml" ]'
check "a refusal removes the staged copy" '[ -z "$(ls -A "$WORK/stage-parent")" ]'

OUT=$(run inplace 75); RC=$?
check "an unreachable database exits 75" '[ "$RC" = 75 ] && printf "%s" "$OUT" | grep -q "could not be checked"'
check "an unreachable database starts the units again" '[ "$(wc -l < "$WORK/systemctl" | tr -d " ")" = 2 ]'

OUT=$(run inplace 0 --bogus); RC=$?
check "an unknown option is refused before anything runs" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "unknown option: --bogus" && [ ! -s "$WORK/check-calls" ]'

OUT=$(run inplace 0 --help); RC=$?
check "--help prints the usage" '[ "$RC" = 0 ] && printf "%s" "$OUT" | grep -q -- "--skip-upgrade-check"'

# precheck SRC: runs precheck_archive against SRC in a subshell. Prints the output; returns its status.
precheck() {
    (
        . "$SCRIPT"
        set +e
        SRC=$1
        precheck_archive
        echo "PRECHECKED"
    ) 2>&1
}

mkdir -p "$WORK/archive/wwwroot" "$WORK/archive/share/sql"
: > "$WORK/archive/ModularCA.API"
: > "$WORK/archive/ModularCA.Keystore.Unlocker"
OUT=$(precheck "$WORK/archive"); RC=$?
check "the pre-check refuses an archive without modularca-migrate" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "missing from archive: modularca-migrate; nothing was changed" && ! printf "%s" "$OUT" | grep -q PRECHECKED'
: > "$WORK/archive/modularca-migrate"
OUT=$(precheck "$WORK/archive"); RC=$?
check "the pre-check refuses an archive without the ownership repair SQL" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "missing from archive: share/sql/adopt-ownership.sql"'
: > "$WORK/archive/share/sql/adopt-ownership.sql"
OUT=$(precheck "$WORK/archive"); RC=$?
check "the pre-check refuses an archive without the systemd unit" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "missing from archive: deploy/modularca.service; nothing was changed"'
mkdir -p "$WORK/archive/deploy"
: > "$WORK/archive/deploy/modularca.service"
OUT=$(precheck "$WORK/archive"); RC=$?
check "the pre-check refuses an archive without the signer's unit" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "missing from archive: deploy/modularca-signer.service; nothing was changed"'
: > "$WORK/archive/deploy/modularca-signer.service"
OUT=$(precheck "$WORK/archive"); RC=$?
check "the pre-check passes a complete archive" '[ "$RC" = 0 ] && printf "%s" "$OUT" | grep -q PRECHECKED'
check "no check for the unit is left after the units are stopped" '! sed -n "/^STOPPED=1/,\$p" "$SCRIPT" | grep -q "is missing from this distribution"'
check "the closing heredoc does not reuse the name of the DONE variable" '! grep -qE "<<.?DONE" "$SCRIPT" && ! grep -qx "DONE" "$SCRIPT"'

# Every presence check in the main path is the pre-check, and it runs before any unit is stopped.
check "no presence check is left after the units are stopped" '! sed -n "/^STOPPED=1/,\$p" "$SCRIPT" | grep -q "missing from archive"'
check "the pre-check runs before the units are stopped" '[ "$(grep -n "^precheck_archive$" "$SCRIPT" | cut -d: -f1)" -lt "$(grep -n "^STOPPED=1$" "$SCRIPT" | cut -d: -f1)" ]'

# trapped STATE...: sources the script, sets the given state, installs its EXIT trap with the
# stubs, then fails the way set -e does (or, with "finish", exits cleanly). Prints the output;
# returns the subshell's status.
trapped() {
    : > "$WORK/systemctl"
    (
        . "$SCRIPT"
        APP_DIR="$WORK/app"
        RESTART=(modularca.service modularca-signer.service)
        systemctl() { printf '%s\n' "$*" >> "$WORK/systemctl"; }
        trap 'on_err $LINENO' ERR
        trap on_exit EXIT
        for assignment in "$@"; do
            [ "$assignment" = finish ] && exit 0
            eval "$assignment"
        done
        false
        echo "NOT REACHED"
    ) 2>&1
}

OUT=$(trapped STOPPED=1); RC=$?
check "a failure after the units stopped keeps its status" '[ "$RC" = 1 ] && ! printf "%s" "$OUT" | grep -q "NOT REACHED"'
check "a failure after the units stopped says the install is incomplete" 'printf "%s" "$OUT" | grep -q "The install is INCOMPLETE" && printf "%s" "$OUT" | grep -q "Nothing in $WORK/app was changed"'
check "a failure after the units stopped starts them again, node first" '[ "$(cat "$WORK/systemctl")" = "$(printf "start --no-block modularca.service\nstart --no-block modularca-signer.service")" ]'

OUT=$(trapped STOPPED=1 TOUCHED=1); RC=$?
check "a failure while copying says the build may be partly copied" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "may hold a partly copied build"'
check "a failure while copying leaves the units stopped" '[ ! -s "$WORK/systemctl" ]'
check "a failure while copying says to restore or re-run, then start the units" 'printf "%s" "$OUT" | grep -q "Restore $WORK/app from your backup, or fix the cause and run install.sh again." && printf "%s" "$OUT" | grep -qF "systemctl start modularca.service modularca-signer.service"'

OUT=$(trapped 'RESTART=()' STOPPED=1); RC=$?
check "a failure on a fresh install says no unit was running" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "The install is INCOMPLETE" && printf "%s" "$OUT" | grep -q "No ModularCA unit was running, so none was stopped." && ! printf "%s" "$OUT" | grep -q "It had stopped" && [ ! -s "$WORK/systemctl" ]'

OUT=$(trapped 'RESTART=()' STOPPED=1 TOUCHED=1); RC=$?
check "a failure while copying a fresh install says to run it again and names no unit" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "run install.sh again" && ! printf "%s" "$OUT" | grep -q "systemctl start" && [ ! -s "$WORK/systemctl" ]'

OUT=$(trapped STOPPED=1 'remove_stage() { false; }'); RC=$?
check "a failing step in the EXIT trap does not cut it short" '[ "$RC" = 1 ] && printf "%s" "$OUT" | grep -q "Nothing in $WORK/app was changed" && [ "$(wc -l < "$WORK/systemctl" | tr -d " ")" = 2 ]'

OUT=$(trapped); RC=$?
check "a failure before the units stopped starts nothing" '[ "$RC" = 1 ] && [ ! -s "$WORK/systemctl" ] && ! printf "%s" "$OUT" | grep -q INCOMPLETE'

OUT=$(trapped STOPPED=1 TOUCHED=1 DONE=1 finish); RC=$?
check "a finished install leaves the starting to itself" '[ "$RC" = 0 ] && [ ! -s "$WORK/systemctl" ] && ! printf "%s" "$OUT" | grep -q INCOMPLETE'

OUT=$(trapped STOPPED=1 start_units); RC=$?
check "units already started again are not started twice" '[ "$RC" = 1 ] && [ "$(wc -l < "$WORK/systemctl" | tr -d " ")" = 2 ] && ! printf "%s" "$OUT" | grep -q INCOMPLETE'

# The refusal path end to end with the real trap: upgrade_check starts the units and exits 3; the
# trap neither starts them a second time nor calls the install incomplete.
: > "$WORK/check-calls"
echo 3 > "$WORK/check-exit"
: > "$WORK/systemctl"
OUT=$(
    (
        . "$SCRIPT"
        APP_DIR="$WORK/app"
        SRC="$WORK/src"
        STAGE_PARENT="$WORK/stage-parent"
        RESTART=(modularca.service modularca-signer.service)
        runuser() { shift 3; "$@"; }
        systemctl() { printf '%s\n' "$*" >> "$WORK/systemctl"; }
        trap on_exit EXIT
        STOPPED=1
        upgrade_check
        echo "RETURNED"
    ) 2>&1
); RC=$?
check "a refused check with the trap set exits 3 and starts each unit once" '[ "$RC" = 3 ] && [ "$(wc -l < "$WORK/systemctl" | tr -d " ")" = 2 ] && ! printf "%s" "$OUT" | grep -q INCOMPLETE'

printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
