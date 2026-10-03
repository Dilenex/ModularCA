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
# stopped units again, says nothing was changed and exits with that status.
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

printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
