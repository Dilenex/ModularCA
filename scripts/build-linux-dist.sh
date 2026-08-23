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
#
# Output: dist/modularca-<VERSION>-linux-x64.tar.gz plus a .sha256 alongside it.
set -euo pipefail

RID=linux-x64
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rid) RID="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d ' \r\n' < VERSION)"
STAGE="$(mktemp -d)/modularca-${VERSION}-${RID}"
OUT="$ROOT/dist"
TARBALL="$OUT/modularca-${VERSION}-${RID}.tar.gz"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

mkdir -p "$STAGE" "$OUT"

# Release configuration triggers the BuildWebUIs target, so all five SPAs are typechecked and
# bundled as part of this publish rather than needing a separate step.
note "publishing ModularCA.API ($RID, self-contained)"
dotnet publish ModularCA.API/ModularCA.API.csproj \
    -c Release -r "$RID" --self-contained true \
    -o "$STAGE" -v minimal --nologo

# The break-glass unlocker is a separate executable and a separate publish. Into the SAME
# directory deliberately: the runtime assemblies are byte-identical (same solution, same RID,
# same run), so this costs only the four files unique to the CLI rather than a duplicate ~70 MB
# runtime. Its own deps.json / runtimeconfig.json are named after its assembly, so nothing
# collides with the API's.
note "publishing ModularCA.KeystoreCli"
dotnet publish ModularCA.KeystoreCli/ModularCA.KeystoreCli.csproj \
    -c Release -r "$RID" --self-contained true \
    -o "$STAGE" -v minimal --nologo

note "staging config, deploy files and installer"
mkdir -p "$STAGE/config" "$STAGE/keystores" "$STAGE/logs" "$STAGE/deploy"
cp config/*.example "$STAGE/config/" 2>/dev/null || true
# deploy/ is gitignored (operator-specific), so tolerate its absence on a clean clone.
if [[ -d deploy ]]; then
    cp deploy/modularca.service deploy/nginx-modularca.conf deploy/nftables-modularca.conf \
       "$STAGE/deploy/" 2>/dev/null || true
fi
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
for required in ModularCA.API ModularCA.Keystore.Unlocker wwwroot/admin/index.html \
                wwwroot/user/index.html wwwroot/public/index.html \
                wwwroot/setup/index.html wwwroot/docs/index.html; do
    [[ -e "$STAGE/$required" ]] || { echo "MISSING from payload: $required" >&2; exit 1; }
done
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
