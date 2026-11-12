#!/usr/bin/env bash
#
# Builds the linux-x64 distribution tarball.
#
# Runs from Windows (git-bash) or from Linux — .NET cross-publishes either way. Note that when
# built on Windows the archive carries no Unix permission bits, which is why install.sh sets
# ownership and modes explicitly rather than relying on what tar restored.
#
#   ./scripts/build-linux-dist.sh
#   ./scripts/build-linux-dist.sh --rid linux-arm64
#   ./scripts/build-linux-dist.sh --configuration Staging
#
# Output: dist/modularca-<VERSION>-linux-x64.tar.gz plus a .sha256 alongside it.
#
# --configuration Staging builds the same payload with JS sourcemaps included (the csproj sets
# MODULARCA_SOURCEMAP=1 for that configuration only, which each vite.config.ts reads). It exists
# because a minified stack like `te.map is not a function` at `index-DbKwh5kT.js:14` is most of a
# day's work to trace on a deployed host, and a filename and line number is not. Directory.Build.props
# sets Optimize=true for Staging, so the IL matches Release and the maps are the only difference.
#
# A Staging archive is named ...-staging.tar.gz rather than sharing the Release name. Two artifacts
# that differ in what they ship must not be indistinguishable on disk — the point of the maps is to
# know what is running, and an archive you cannot identify defeats that before it starts.
set -euo pipefail

RID=linux-x64
CONFIG=Release
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rid) RID="$2"; shift 2 ;;
        -c|--configuration) CONFIG="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

case "$CONFIG" in
    Release|Staging) ;;
    # Debug is rejected rather than allowed through: it skips BuildWebUIs entirely, so the payload
    # check below would fail on a missing wwwroot after a full self-contained publish had run.
    *) echo "unsupported configuration: $CONFIG (expected Release or Staging)" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d ' \r\n' < VERSION)"
# Release keeps the bare name so build-deb.sh and every existing deploy instruction still resolve it.
SUFFIX=""
[[ "$CONFIG" != "Release" ]] && SUFFIX="-$(printf '%s' "$CONFIG" | tr '[:upper:]' '[:lower:]')"
NAME="modularca-${VERSION}-${RID}${SUFFIX}"
STAGE="$(mktemp -d)/${NAME}"
OUT="${DIST_OUT:-$ROOT/dist}"   # DIST_OUT overrides, e.g. when the default archive is held open by a transfer tool
mkdir -p "$OUT"
TARBALL="$OUT/${NAME}.tar.gz"
# The KRL fetcher an administrator copies to each SSH server; packaging/install.sh and
# packaging/nfpm.yaml name the same four files.
SSH_KRL_FILES=(modularca-krl-fetch.sh modularca-krl-fetch.service modularca-krl-fetch.timer modularca-krl-fetch.env.example)

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

mkdir -p "$STAGE" "$OUT"

# Release and Staging both trigger the BuildWebUIs target, so all five SPAs are typechecked and
# bundled as part of this publish rather than needing a separate step.
# ReadyToRun: the assemblies carry precompiled native code beside their IL, so a start compiles
# less at run time. Every start pays that cost, and in the pod so does each of the three init
# containers. The price is size: about a third more unpacked (145 MB to 194 MB when this was
# added). All three programs get the flag, so the ModularCA.*.dll they share are the same
# everywhere. Measured on a pod it takes about 2.5 s off a start (11.4 s to 8.9 s) and a quarter
# to a third off the CPU of each --check-ready, so it stays. Set MODULARCA_READYTORUN=0 to build
# without it.
R2R="-p:PublishReadyToRun=true"
if [ "${MODULARCA_READYTORUN:-1}" = "0" ]; then R2R="-p:PublishReadyToRun=false"; fi

# Each program is published into a directory of its own and the three are then merged, the API
# last. They used to be published straight into one directory, which left it to file timestamps
# which program's copy of a shared assembly stayed. The two command-line tools reference older
# packages than the web framework carries (Microsoft.Extensions.ObjectPool 7.0.0 against the
# framework's 10.0), and 0.4.4-dev.1.1 shipped the tool's copy: the server died at start with
# "Could not load file or assembly Microsoft.Extensions.ObjectPool, Version=10.0.0.0". Merged in
# a fixed order, the API's copy of every file it publishes is the one in the archive, whatever
# the timestamps; the tools run with those newer copies, as they always have.
PUBLISH="$(mktemp -d)"

note "publishing ModularCA.API ($CONFIG, $RID, self-contained)"
dotnet publish ModularCA.API/ModularCA.API.csproj \
    -c "$CONFIG" -r "$RID" --self-contained true \
    -o "$PUBLISH/api" -v minimal --nologo $R2R

# The break-glass unlocker is a separate executable and a separate publish. It ships in the SAME
# directory as the API deliberately: the runtime is shared, so it costs only the files unique to
# the CLI rather than a duplicate ~70 MB runtime. Its own deps.json / runtimeconfig.json are
# named after its assembly, so nothing collides with the API's.
note "publishing ModularCA.KeystoreCli"
dotnet publish ModularCA.KeystoreCli/ModularCA.KeystoreCli.csproj \
    -c "$CONFIG" -r "$RID" --self-contained true \
    -o "$PUBLISH/cli" -v minimal --nologo $R2R

# The MariaDB-to-PostgreSQL migration helper, in the same directory for the same reason as
# the CLI above. It ships with the release it migrates TO, which is the point: an operator on
# 0.3.0 unpacks 0.3.1, finds the tool beside the binary that refuses to start against MariaDB,
# and needs nothing they did not already download.
note "publishing ModularCA.Migrate"
dotnet publish ModularCA.Migrate/ModularCA.Migrate.csproj \
    -c "$CONFIG" -r "$RID" --self-contained true \
    -o "$PUBLISH/migrate" -v minimal --nologo $R2R

note "merging the three programs, the API last"
cp -R "$PUBLISH/migrate/." "$STAGE/"
cp -R "$PUBLISH/cli/." "$STAGE/"
cp -R "$PUBLISH/api/." "$STAGE/"
# Every file the API publishes must be the API's own copy, byte for byte. This is the check that
# would have refused 0.4.4-dev.1.1.
while IFS= read -r -d '' published; do
    relative="${published#"$PUBLISH/api/"}"
    cmp -s "$published" "$STAGE/$relative" \
        || { echo "REFUSING: $relative in the archive is not the copy ModularCA.API published" >&2; exit 1; }
done < <(find "$PUBLISH/api" -type f -print0)
# And each tool must have found every file of its own in the merge.
for tool in cli migrate; do
    while IFS= read -r -d '' published; do
        relative="${published#"$PUBLISH/$tool/"}"
        [[ -f "$STAGE/$relative" ]] \
            || { echo "REFUSING: $relative, published by the $tool program, is missing from the archive" >&2; exit 1; }
    done < <(find "$PUBLISH/$tool" -type f -print0)
done
rm -rf "$PUBLISH"

# Start the program once, where this machine can run it. --upgrade-check first builds the web
# host and says "THIS BUILD CANNOT START" when it cannot; pointed at an empty directory it then
# stops with status 1 for want of a db.yaml, having touched nothing. A payload with a wrong
# framework assembly, which no file check here would notice, fails the build instead of the
# first install. Skipped when the build host cannot run the target (a Windows host, another CPU).
if [[ "$(uname -s)" == "Linux" && "$RID" == "linux-$(uname -m | sed -e 's/x86_64/x64/' -e 's/aarch64/arm64/')" ]]; then
    note "starting the program once"
    SMOKE="$(mktemp -d)"
    chmod +x "$STAGE/ModularCA.API"
    set +e
    SMOKE_OUT="$("$STAGE/ModularCA.API" --upgrade-check --config-dir "$SMOKE" 2>&1)"
    SMOKE_RC=$?
    set -e
    chmod -x "$STAGE/ModularCA.API"
    rm -rf "$SMOKE"
    # The run may have left a start-up log beside the program; none belongs in the archive.
    find "$STAGE/logs" -type f -delete 2>/dev/null || true
    if [[ "$SMOKE_RC" -ne 1 ]] || grep -q "THIS BUILD CANNOT START" <<<"$SMOKE_OUT"; then
        echo "REFUSING: the published program does not start (status $SMOKE_RC, expected 1 for an empty config directory):" >&2
        echo "$SMOKE_OUT" | tail -n 15 >&2
        exit 1
    fi
else
    note "not starting the program: this host cannot run $RID"
fi

note "staging config, deploy files and installer"
mkdir -p "$STAGE/config" "$STAGE/keystores" "$STAGE/logs" "$STAGE/deploy" "$STAGE/share/sql"
cp config/*.example "$STAGE/config/" 2>/dev/null || true
# The schema-ownership repair, run as the PostgreSQL superuser. install.sh and the .deb install it
# root-owned under /usr/share/modularca/sql and never under /opt/modularca, which the service
# account owns. The byte-for-byte copy of what ModularCA.Database embeds.
cp ModularCA.Database/Sql/adopt-ownership.sql "$STAGE/share/sql/adopt-ownership.sql"
cmp -s ModularCA.Database/Sql/adopt-ownership.sql "$STAGE/share/sql/adopt-ownership.sql" \
    || { echo "REFUSING: the staged adopt-ownership.sql differs from ModularCA.Database/Sql" >&2; exit 1; }
# The KRL fetcher for SSH servers: a script, its systemd service and timer, and its settings.
# None of it runs on the CA. install.sh and the .deb put it root-owned under
# /usr/share/modularca/ssh-krl, where an administrator copies it from to each server. A carriage
# return in any of them breaks it on the server (the shebang, the unit, the URL), so one is refused
# here; -U because git-bash's grep otherwise strips the CR before matching.
mkdir -p "$STAGE/share/ssh-krl"
for krl_file in "${SSH_KRL_FILES[@]}"; do
    cp "deploy/ssh-krl/$krl_file" "$STAGE/share/ssh-krl/$krl_file" \
        || { echo "REFUSING: deploy/ssh-krl/$krl_file is missing" >&2; exit 1; }
    if LC_ALL=C grep -qU "$(printf '\r')" "$STAGE/share/ssh-krl/$krl_file"; then
        echo "REFUSING: deploy/ssh-krl/$krl_file has CRLF line endings. Convert it to LF." >&2
        exit 1
    fi
done
# The two systemd units are required (the payload check below refuses an archive without them:
# install.sh installs both). The nginx and nftables templates and the drop-ins are examples, so a
# missing one is tolerated.
if [[ -d deploy ]]; then
    cp deploy/modularca.service deploy/modularca-signer.service \
       deploy/nginx-modularca.conf deploy/nftables-modularca.conf \
       "$STAGE/deploy/" 2>/dev/null || true
    # The per-role unit drop-ins for a split install; examples, applied by the operator.
    if [[ -d deploy/dropins ]]; then
        mkdir -p "$STAGE/deploy/dropins"
        cp deploy/dropins/*.conf "$STAGE/deploy/dropins/" 2>/dev/null || true
    fi
fi
# LICENSE and THIRD-PARTY-NOTICES.md are not optional extras. This archive is a binary
# distribution of AGPL-3.0 software containing MIT, BSD and Apache-2.0 components, and every
# one of those licences permits redistribution only on the condition that its notice travels
# with the binary. Shipping the payload without them is the omission nobody notices until
# somebody does.
cp LICENSE THIRD-PARTY-NOTICES.md "$STAGE/" || {
    echo "REFUSING: LICENSE or THIRD-PARTY-NOTICES.md missing. Regenerate with:" >&2
    echo "  node scripts/generate-third-party-notices.mjs" >&2
    exit 1
}
cp packaging/install.sh packaging/README-DEPLOY.md "$STAGE/" 2>/dev/null || {
    echo "WARNING: packaging/install.sh not found — the archive will have no installer" >&2
}
# Set explicitly rather than inheriting: on Windows the source file's mode carries no meaning,
# and an installer the operator cannot execute is a poor first impression. Everything ELSE in
# the archive is deliberately left non-executable — install.sh sets those modes on the target,
# which is the only place they can be set correctly.
chmod 0755 "$STAGE/install.sh" 2>/dev/null || true

# Sanity: refuse to ship an archive missing a piece, or carrying a host-platform binary.
note "verifying payload"
for required in ModularCA.API ModularCA.Keystore.Unlocker LICENSE THIRD-PARTY-NOTICES.md wwwroot/admin/index.html \
                wwwroot/public/index.html \
                wwwroot/setup/index.html wwwroot/docs/index.html share/sql/adopt-ownership.sql \
                "${SSH_KRL_FILES[@]/#/share/ssh-krl/}" \
                deploy/modularca.service deploy/modularca-signer.service; do
    [[ -e "$STAGE/$required" ]] || { echo "MISSING from payload: $required" >&2; exit 1; }
done
# The interfaces bundle the vendored Plex fonts; SIL OFL 1.1 requires its text to travel with them.
grep -q 'SIL OPEN FONT LICENSE' "$STAGE/THIRD-PARTY-NOTICES.md" || {
    echo "REFUSING: THIRD-PARTY-NOTICES.md lacks the vendored font licence. Regenerate with:" >&2
    echo "  node scripts/generate-third-party-notices.mjs" >&2
    exit 1
}
if compgen -G "$STAGE/*.exe" > /dev/null; then
    echo "REFUSING: a Windows .exe leaked into a $RID payload" >&2
    exit 1
fi

note "creating $TARBALL"
rm -f "$TARBALL" "$TARBALL.sha256"
tar --format=gnu -czf "$TARBALL" --owner=0 --group=0 \
    -C "$(dirname "$STAGE")" "$(basename "$STAGE")"

sha256sum "$TARBALL" > "$TARBALL.sha256"
rm -rf "$(dirname "$STAGE")"

printf '\n  %s\n  %s\n\n' \
    "$(ls -lh "$TARBALL" | awk '{print $5}')  $TARBALL" \
    "$(awk '{print $1}' "$TARBALL.sha256")"
