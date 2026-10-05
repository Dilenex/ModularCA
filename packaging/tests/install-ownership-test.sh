#!/bin/bash
# Runs the ownership steps of packaging/install.sh and packaging/debian/postinst against a fake
# /opt/modularca. chown, chmod, install, stat, getent and dpkg-query are replaced by stubs that
# keep each path's owner, group and mode in a side table, so nothing needs root and every change
# the scripts make is recorded. Needs no root, no dpkg and no systemd.
#
#   bash packaging/tests/install-ownership-test.sh
#
# Asserts, for install.sh and for postinst: a fresh install gives the program files to root (0755
# directories and executables, 0644 the rest) and creates the runtime directories for modularca;
# an upgrade of a single-process install gives back to root what an older installer gave to
# modularca and touches nothing in config/, keystores/ or logs/; an upgrade of a split install
# leaves the signer's keystores/, keystore.yaml and identity and the config/ group and modes
# exactly as they were. Also: one list of runtime directories in both scripts and the unit.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL_SH="$HERE/../install.sh"
POSTINST="$HERE/../debian/postinst"
UNIT_FILE="$HERE/../../deploy/modularca.service"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASSES=0
FAILS=0
OUT=

export META="$WORK/meta" CALLS="$WORK/calls" ACCOUNTS="$WORK/accounts" DPKG_LIST="$WORK/dpkg-list"
export STUBLIB="$WORK/stublib.sh"
mkdir -p "$WORK/bin"

cat > "$STUBLIB" <<'LIB'
# The side table: one file per path under $META, holding "owner group mode".
meta_key() {
    local p=$1
    [[ $p == /* ]] || p=$PWD/$p
    while [[ $p == */ && $p != / ]]; do p=${p%/}; done
    printf '%s' "${p//\//%}"
}
meta_get() { cat "$META/$(meta_key "$1")" 2>/dev/null || echo "? ? ?"; }
meta_put() { echo "$2 $3 $4" > "$META/$(meta_key "$1")"; }
meta_owner() {
    local o g m
    read -r o g m < <(meta_get "$1")
    meta_put "$1" "$2" "${3:-$g}" "$m"
}
meta_mode() {
    local o g m
    read -r o g m < <(meta_get "$1")
    meta_put "$1" "$o" "$g" "$(printf '%04o' "$((8#$2))")"
}
log_call() { printf '%s\n' "$*" >> "$CALLS"; }
LIB

cat > "$WORK/bin/chown" <<'STUB'
#!/bin/bash
. "$STUBLIB"
log_call chown "$@"
rec=0 args=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -R) rec=1 ;;
        -h) ;;
        --) shift; args+=("$@"); break ;;
        *) args+=("$1") ;;
    esac
    shift
done
spec=${args[0]} owner=${spec%%:*} group=
[[ $spec == *:* ]] && group=${spec#*:}
for p in "${args[@]:1}"; do
    if [[ $rec == 1 ]]; then
        while IFS= read -r q; do meta_owner "$q" "$owner" "$group"; done < <(find "$p")
    else
        meta_owner "$p" "$owner" "$group"
    fi
done
STUB

cat > "$WORK/bin/chmod" <<'STUB'
#!/bin/bash
. "$STUBLIB"
log_call chmod "$@"
[[ $1 =~ ^[0-7]+$ ]] || { echo "chmod stub: only octal modes: $1" >&2; exit 2; }
mode=$1
shift
for p in "$@"; do meta_mode "$p" "$mode"; done
STUB

cat > "$WORK/bin/install" <<'STUB'
#!/bin/bash
. "$STUBLIB"
log_call install "$@"
dir=0 owner=root group=root mode=0755 args=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) dir=1 ;;
        -o) owner=$2; shift ;;
        -g) group=$2; shift ;;
        -m) mode=$2; shift ;;
        *) args+=("$1") ;;
    esac
    shift
done
if [[ $dir == 1 ]]; then
    for p in "${args[@]}"; do
        mkdir -p "$p" && meta_put "$p" "$owner" "$group" "$(printf '%04o' "$((8#$mode))")"
    done
else
    dest=${args[1]}
    [[ -d $dest ]] && dest=$dest/${args[0]##*/}
    cp "${args[0]}" "$dest" && meta_put "$dest" "$owner" "$group" "$(printf '%04o' "$((8#$mode))")"
fi
STUB

cat > "$WORK/bin/stat" <<'STUB'
#!/bin/bash
. "$STUBLIB"
[[ $1 == -c && $2 == %U ]] || { echo "stat stub: only -c %U" >&2; exit 2; }
read -r o g m < <(meta_get "$3")
echo "$o"
STUB

cat > "$WORK/bin/getent" <<'STUB'
#!/bin/bash
grep -qx "$1:$2" "$ACCOUNTS"
STUB

cat > "$WORK/bin/dpkg-query" <<'STUB'
#!/bin/bash
[[ $1 == -L && $2 == modularca ]] || exit 2
cat "$DPKG_LIST"
STUB
chmod +x "$WORK/bin/"* 2>/dev/null
. "$STUBLIB"

check() {
    if eval "$2"; then
        PASSES=$((PASSES + 1))
    else
        FAILS=$((FAILS + 1))
        printf 'FAIL: %s\n  (%s)\n' "$1" "$2"
        printf '  output: %s\n' "$OUT"
    fi
}

# is PATH "OWNER GROUP MODE": the side table holds exactly that for PATH.
is() { [[ $(meta_get "$1") == "$2" ]] || { printf '  %s is [%s], expected [%s]\n' "$1" "$(meta_get "$1")" "$2"; return 1; }; }

# untouched DIR: no stub call named DIR or anything under it.
untouched() { ! grep -qF "$1" "$CALLS"; }

# put PATH OWNER GROUP MODE: creates PATH (a directory when it ends in /) with that metadata.
put() {
    local p=${1%/}
    if [[ $1 == */ ]]; then mkdir -p "$p"; else mkdir -p "$(dirname "$p")"; : > "$p"; fi
    meta_put "$p" "$2" "$3" "$4"
}

reset() {
    rm -rf "$WORK/root" "$META" "$WORK/src"
    mkdir -p "$WORK/root" "$META"
    : > "$CALLS"
    printf 'passwd:modularca\ngroup:modularca\n' > "$ACCOUNTS"
}

# The archive as build-linux-dist.sh lays it out.
make_src() {
    local s="$WORK/src"
    mkdir -p "$s/runtimes/linux-x64/native" "$s/wwwroot/admin" "$s/config" "$s/keystores" "$s/logs" \
             "$s/deploy" "$s/share/sql"
    : > "$s/ModularCA.API"; : > "$s/ModularCA.Keystore.Unlocker"; : > "$s/modularca-migrate"
    : > "$s/ModularCA.API.dll"; : > "$s/runtimes/linux-x64/native/libx.so"
    : > "$s/wwwroot/admin/index.html"
    : > "$s/config/config.yaml.example"; : > "$s/config/db.yaml.example"
    : > "$s/deploy/modularca.service"; : > "$s/deploy/modularca-signer.service"
    : > "$s/share/sql/adopt-ownership.sql"; : > "$s/install.sh"; : > "$s/README-DEPLOY.md"
}

# run_install: sources install.sh and runs the payload and ownership steps of its main path, in
# its order, against the fake root with the stubs.
run_install() {
    (
        . "$INSTALL_SH"
        set +e
        PATH="$WORK/bin:$PATH"
        APP_DIR="$WORK/root/opt/modularca"
        SRC="$WORK/src"
        mkdir -p "$APP_DIR"
        install_payload
        set_ownership
        echo "RETURNED"
    ) 2>&1
}

# run_postinst: sources postinst and runs its ownership step against the fake root.
run_postinst() {
    (
        MODULARCA_POSTINST_SOURCED=1 . "$POSTINST"
        set +e
        PATH="$WORK/bin:$PATH"
        APP_DIR="$WORK/root/opt/modularca"
        set_ownership
        echo "RETURNED"
    ) 2>&1
}

A="$WORK/root/opt/modularca"

# ── install.sh: fresh install ──────────────────────────────────────────────────────────────────
reset; make_src
OUT=$(run_install)
check "install: a fresh install runs to the end" 'printf "%s" "$OUT" | grep -q RETURNED'
check "install: the application directory is root's, 0755" 'is "$A" "root root 0755"'
check "install: the executables are root's, 0755" 'is "$A/ModularCA.API" "root root 0755" && is "$A/ModularCA.Keystore.Unlocker" "root root 0755" && is "$A/modularca-migrate" "root root 0755"'
check "install: other program files are root's, 0644" 'is "$A/ModularCA.API.dll" "root root 0644" && is "$A/runtimes/linux-x64/native/libx.so" "root root 0644" && is "$A/wwwroot/admin/index.html" "root root 0644"'
check "install: program directories are root's, 0755" 'is "$A/runtimes" "root root 0755" && is "$A/runtimes/linux-x64/native" "root root 0755" && is "$A/wwwroot" "root root 0755"'
check "install: the runtime directories are created for modularca" 'is "$A/config" "modularca modularca 0700" && is "$A/keystores" "modularca modularca 0700" && is "$A/logs" "modularca modularca 0750" && is "$A/backups" "modularca modularca 0700"'
check "install: the examples are seeded owner-only for modularca" 'is "$A/config/config.yaml.example" "modularca modularca 0600" && is "$A/config/db.yaml.example" "modularca modularca 0600"'
check "install: deploy, share and the installer are not copied in" '[ ! -e "$A/deploy" ] && [ ! -e "$A/share" ] && [ ! -e "$A/install.sh" ] && [ ! -e "$A/README-DEPLOY.md" ]'
check "install: a fresh install warns about nothing" '! printf "%s" "$OUT" | grep -q -e WARNING -e "split install"'

# ── install.sh: upgrade of a single-process install, as a pre-0.4.0 installer left it ───────────
reset; make_src
put "$A/" modularca modularca 0750
put "$A/ModularCA.API" modularca modularca 0755
put "$A/ModularCA.API.dll" modularca modularca 0644
put "$A/old-only.dll" modularca modularca 0644
put "$A/runtimes/" modularca modularca 0750
put "$A/runtimes/linux-x64/native/libx.so" modularca modularca 0644
put "$A/wwwroot/admin/index-OLD.js" modularca modularca 0644
put "$A/config/" modularca modularca 0700
put "$A/config/config.yaml" modularca modularca 0600
put "$A/config/db.yaml" modularca modularca 0600
put "$A/config/keystore.yaml" modularca modularca 0600
put "$A/config/config.yaml.example" modularca modularca 0600
put "$A/config/db.yaml.example" modularca modularca 0600
put "$A/config/dp-keys/key-1.xml" modularca modularca 0600
put "$A/keystores/" modularca modularca 0700
put "$A/keystores/ca-certs.keystore" modularca modularca 0600
put "$A/logs/" modularca modularca 0750
put "$A/logs/modularca-20261001.log" modularca modularca 0640
BEFORE_CONFIG=$(meta_get "$A/config/config.yaml")
OUT=$(run_install)
check "upgrade: runs to the end" 'printf "%s" "$OUT" | grep -q RETURNED'
check "upgrade: the application directory goes back to root, 0755" 'is "$A" "root root 0755"'
check "upgrade: the program files go back to root" 'is "$A/ModularCA.API" "root root 0755" && is "$A/ModularCA.API.dll" "root root 0644" && is "$A/runtimes" "root root 0755" && is "$A/runtimes/linux-x64/native/libx.so" "root root 0644"'
check "upgrade: the old wwwroot is replaced, not merged" '[ ! -e "$A/wwwroot/admin/index-OLD.js" ] && is "$A/wwwroot/admin/index.html" "root root 0644"'
check "upgrade: config/, keystores/ and logs/ are never chowned or chmodded" 'untouched "$A/config" && untouched "$A/keystores" && untouched "$A/logs"'
check "upgrade: config/, keystores/ and logs/ keep their ownership and modes" 'is "$A/config" "modularca modularca 0700" && is "$A/config/config.yaml" "$BEFORE_CONFIG" && is "$A/config/keystore.yaml" "modularca modularca 0600" && is "$A/keystores" "modularca modularca 0700" && is "$A/keystores/ca-certs.keystore" "modularca modularca 0600" && is "$A/logs" "modularca modularca 0750"'
check "upgrade: a missing backups/ is created for modularca" 'is "$A/backups" "modularca modularca 0700"'
check "upgrade: a leftover the service account owns is named and left alone" 'printf "%s" "$OUT" | grep -q "left as they are: old-only.dll" && is "$A/old-only.dll" "modularca modularca 0644"'
check "upgrade: a single-process install is not taken for a split one" '! printf "%s" "$OUT" | grep -q "split install"'

# ── install.sh: upgrade of a split install ─────────────────────────────────────────────────────
split_state() {
    put "$A/" root root 0755
    put "$A/ModularCA.API" root root 0755
    put "$A/config/" modularca modularca-signer 0750
    put "$A/config/config.yaml" modularca modularca-signer 0640
    put "$A/config/db.yaml" modularca modularca-signer 0640
    put "$A/config/keystore.yaml" modularca-signer modularca-signer 0600
    put "$A/config/signer-identity-ca.pfx" modularca-signer modularca-signer 0600
    put "$A/config/signer-server.pfx" modularca-signer modularca-signer 0600
    put "$A/config/signer-client.pfx" modularca modularca 0600
    put "$A/config/config.yaml.example" modularca modularca 0600
    put "$A/config/db.yaml.example" modularca modularca 0600
    put "$A/keystores/" modularca-signer modularca-signer 0700
    put "$A/keystores/ca-certs.keystore" modularca-signer modularca-signer 0600
    put "$A/keystores/ca-trust.keystore" modularca-signer modularca-signer 0600
    put "$A/logs/" modularca modularca 0750
    put "$A/backups/" modularca modularca 0700
    printf 'passwd:modularca-signer\ngroup:modularca-signer\n' >> "$ACCOUNTS"
}
split_kept() {
    is "$A/config" "modularca modularca-signer 0750" \
        && is "$A/config/config.yaml" "modularca modularca-signer 0640" \
        && is "$A/config/db.yaml" "modularca modularca-signer 0640" \
        && is "$A/config/keystore.yaml" "modularca-signer modularca-signer 0600" \
        && is "$A/config/signer-identity-ca.pfx" "modularca-signer modularca-signer 0600" \
        && is "$A/config/signer-server.pfx" "modularca-signer modularca-signer 0600" \
        && is "$A/config/signer-client.pfx" "modularca modularca 0600" \
        && is "$A/keystores" "modularca-signer modularca-signer 0700" \
        && is "$A/keystores/ca-certs.keystore" "modularca-signer modularca-signer 0600" \
        && is "$A/keystores/ca-trust.keystore" "modularca-signer modularca-signer 0600"
}
reset; make_src; split_state
OUT=$(run_install)
check "split: runs to the end and says it is a split install" 'printf "%s" "$OUT" | grep -q RETURNED && printf "%s" "$OUT" | grep -q "split install: keystores/ belongs to modularca-signer"'
check "split: the signer keeps keystores/, keystore.yaml and its identity; config/ keeps its group and modes" 'split_kept'
check "split: no runtime directory is chowned or chmodded" 'untouched "$A/config" && untouched "$A/keystores" && untouched "$A/logs" && untouched "$A/backups"'
check "split: the binaries the signer runs are root's" 'is "$A" "root root 0755" && is "$A/ModularCA.API" "root root 0755" && is "$A/ModularCA.API.dll" "root root 0644"'

# ── install.sh: a run that stopped part way, and a symlinked runtime directory ──────────────────
reset; make_src
put "$A/config/" root root 0755
mkdir -p "$WORK/elsewhere"
ln -s "$WORK/elsewhere" "$A/logs"
OUT=$(run_install)
check "partial: a runtime directory still root's is handed to modularca" 'is "$A/config" "modularca modularca 0700"'
if [ -L "$A/logs" ]; then
    check "partial: a symlinked runtime directory is left alone" 'untouched "$A/logs" && untouched "$WORK/elsewhere"'
else
    echo "skipped: this filesystem made no symlink, so the symlinked runtime directory is not checked"
fi

# ── postinst: first install, as dpkg unpacked it ───────────────────────────────────────────────
deb_payload() {
    put "$A/" root root 0755
    put "$A/ModularCA.API" root root 0755
    put "$A/ModularCA.API.dll" root root 0644
    put "$A/runtimes/" root root 0755
    put "$A/runtimes/libx.so" root root 0644
    put "$A/config/config.yaml.example" root root 0644
    put "$A/config/db.yaml.example" root root 0644
    printf '%s\n' /. /opt "$A" "$A/ModularCA.API" "$A/ModularCA.API.dll" "$A/runtimes" "$A/runtimes/libx.so" \
        "$A/config" "$A/config/config.yaml.example" "$A/config/db.yaml.example" "$A/keystores" "$A/logs" \
        /usr/share/doc/modularca/copyright /etc/modularca > "$DPKG_LIST"
}
reset; deb_payload
put "$A/config/" root root 0755
put "$A/keystores/" root root 0700
put "$A/logs/" root root 0750
OUT=$(run_postinst)
check "postinst: a first install runs to the end" 'printf "%s" "$OUT" | grep -q RETURNED'
check "postinst: the runtime directories dpkg created go to modularca" 'is "$A/config" "modularca modularca 0700" && is "$A/keystores" "modularca modularca 0700" && is "$A/logs" "modularca modularca 0750" && is "$A/backups" "modularca modularca 0700"'
check "postinst: the configuration is seeded owner-only for modularca" 'is "$A/config/config.yaml" "modularca modularca 0600" && is "$A/config/db.yaml" "modularca modularca 0600"'
check "postinst: the program files stay root's" 'is "$A" "root root 0755" && is "$A/ModularCA.API" "root root 0755" && is "$A/ModularCA.API.dll" "root root 0644" && is "$A/runtimes" "root root 0755"'
check "postinst: nothing outside the application directory is touched" '! grep -qF "/usr/share" "$CALLS" && ! grep -qF "/etc/modularca" "$CALLS"'

# ── postinst: upgrade from 0.3.x, whose postinst gave the whole tree to modularca ──────────────
reset; deb_payload
put "$A/" modularca modularca 0750
put "$A/runtimes/" modularca modularca 0750
put "$A/config/" modularca modularca 0700
put "$A/config/config.yaml" modularca modularca 0600
put "$A/config/db.yaml" modularca modularca 0600
put "$A/keystores/" modularca modularca 0700
put "$A/keystores/ca-certs.keystore" modularca modularca 0600
put "$A/logs/" modularca modularca 0750
OUT=$(run_postinst)
check "postinst upgrade: the application directory and the package's directories go back to root" 'is "$A" "root root 0755" && is "$A/runtimes" "root root 0755"'
check "postinst upgrade: config/, keystores/ and logs/ are never chowned or chmodded" 'untouched "$A/config" && untouched "$A/keystores" && untouched "$A/logs"'
check "postinst upgrade: they keep their ownership and modes" 'is "$A/config" "modularca modularca 0700" && is "$A/config/config.yaml" "modularca modularca 0600" && is "$A/keystores/ca-certs.keystore" "modularca modularca 0600"'

# ── postinst: upgrade of a split install ───────────────────────────────────────────────────────
reset; deb_payload; split_state
OUT=$(run_postinst)
check "postinst split: runs to the end" 'printf "%s" "$OUT" | grep -q RETURNED'
check "postinst split: the signer keeps keystores/, keystore.yaml and its identity; config/ keeps its group and modes" 'split_kept'
check "postinst split: no runtime directory is chowned or chmodded" 'untouched "$A/config" && untouched "$A/keystores" && untouched "$A/logs" && untouched "$A/backups"'

# ── install.sh: the signer's unit ──────────────────────────────────────────────────────────────
reset; make_src
echo packaged > "$WORK/src/deploy/modularca-signer.service"
mkdir -p "$WORK/root/etc"
OUT=$(
    (
        . "$INSTALL_SH"
        set +e
        PATH="$WORK/bin:$PATH"
        install_unit "$WORK/src/deploy/modularca-signer.service" "$WORK/root/etc/modularca-signer.service"
        echo local > "$WORK/root/etc/modularca.service"
        install_unit "$WORK/src/deploy/modularca-signer.service" "$WORK/root/etc/modularca.service"
    ) 2>&1
)
check "install: the signer's unit is installed where there is none" '[ "$(cat "$WORK/root/etc/modularca-signer.service")" = packaged ] && is "$WORK/root/etc/modularca-signer.service" "root root 0644"'
check "install: a unit that differs is left in place" '[ "$(cat "$WORK/root/etc/modularca.service")" = local ] && printf "%s" "$OUT" | grep -q "leaving yours in place"'
check "install: the main path installs the signer's unit and enables nothing" 'grep -q "^install_unit \"\$SRC/deploy/modularca-signer.service\" \"\$SIGNER_UNIT\"$" "$INSTALL_SH" && ! grep -qE "^[[:space:]]*systemctl enable" "$INSTALL_SH"'

# ── One list ───────────────────────────────────────────────────────────────────────────────────
INSTALL_LIST=$(sed -n 's/^RUNTIME_DIRS=(\(.*\))$/\1/p' "$INSTALL_SH")
POSTINST_LIST=$(sed -n 's/^RUNTIME_DIRS="\(.*\)"$/\1/p' "$POSTINST")
UNIT_LIST=$(sed -n 's/^ReadWritePaths=//p' "$UNIT_FILE" | tr ' ' '\n' | sed 's|^/opt/modularca/||' | tr '\n' ' ' | sed 's/ $//')
check "install.sh, postinst and the unit's ReadWritePaths name the same runtime directories" '[ -n "$INSTALL_LIST" ] && [ "$INSTALL_LIST" = "$POSTINST_LIST" ] && [ "$INSTALL_LIST" = "$UNIT_LIST" ]'
check "neither script hands the whole tree to the service account" '! grep -qE "chown -R \"?\\\$SERVICE_USER" "$INSTALL_SH" "$POSTINST"'
check "install.sh sets ownership after copying the payload" '[ "$(grep -n "^install_payload$" "$INSTALL_SH" | cut -d: -f1)" -lt "$(grep -n "^set_ownership$" "$INSTALL_SH" | cut -d: -f1)" ]'
check "postinst runs its ownership step on configure" 'sed -n "/^configure)/,/^    ;;/p" "$POSTINST" | grep -qx "    set_ownership"'

printf '%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
