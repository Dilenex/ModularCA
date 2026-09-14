#!/usr/bin/env bash
#
# Builds the win-x64 distribution zip.
#
# The counterpart to build-linux-dist.sh. Same self-contained publish (the .NET runtime is bundled,
# so the target Windows host needs nothing installed), but packaged as a .zip with a Windows run
# guide instead of a tarball with install.sh and a systemd unit. Runs from Windows (git-bash) or
# from Linux — dotnet cross-publishes win-x64 either way; the zip is produced with `zip` where it
# exists and PowerShell's Compress-Archive otherwise.
#
#   ./scripts/build-windows-dist.sh
#   ./scripts/build-windows-dist.sh --rid win-arm64
#   ./scripts/build-windows-dist.sh --configuration Staging
#
# Output: dist/modularca-<VERSION>-win-x64.zip plus a .sha256 alongside it.
set -euo pipefail

RID=win-x64
CONFIG=Release
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rid) RID="$2"; shift 2 ;;
        -c|--configuration) CONFIG="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

case "$RID" in
    win-x64|win-arm64) ;;
    *) echo "unsupported RID: $RID (expected win-x64 or win-arm64)" >&2; exit 1 ;;
esac
case "$CONFIG" in
    Release|Staging) ;;
    *) echo "unsupported configuration: $CONFIG (expected Release or Staging)" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d ' \r\n' < VERSION)"
SUFFIX=""
[[ "$CONFIG" != "Release" ]] && SUFFIX="-$(printf '%s' "$CONFIG" | tr '[:upper:]' '[:lower:]')"
NAME="modularca-${VERSION}-${RID}${SUFFIX}"
STAGE="$(mktemp -d)/${NAME}"
OUT="$ROOT/dist"
ZIP="$OUT/${NAME}.zip"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

mkdir -p "$STAGE" "$OUT"

note "publishing ModularCA.API ($CONFIG, $RID, self-contained)"
dotnet publish ModularCA.API/ModularCA.API.csproj \
    -c "$CONFIG" -r "$RID" --self-contained true \
    -o "$STAGE" -v minimal --nologo

note "publishing ModularCA.KeystoreCli"
dotnet publish ModularCA.KeystoreCli/ModularCA.KeystoreCli.csproj \
    -c "$CONFIG" -r "$RID" --self-contained true \
    -o "$STAGE" -v minimal --nologo

note "staging config, licences and the run guide"
mkdir -p "$STAGE/config" "$STAGE/keystores" "$STAGE/logs"
cp config/*.example "$STAGE/config/" 2>/dev/null || true

# Same licence obligation as the tarball: this is a binary distribution of AGPL-3.0 software with
# MIT/BSD/Apache-2.0 components, each of which permits redistribution only with its notice.
cp LICENSE THIRD-PARTY-NOTICES.md "$STAGE/" || {
    echo "REFUSING: LICENSE or THIRD-PARTY-NOTICES.md missing. Regenerate with:" >&2
    echo "  node scripts/generate-third-party-notices.mjs" >&2
    exit 1
}

# There is no install.sh or systemd unit here: Windows has neither. A short run guide instead,
# covering the console run, the first-run setup wizard, and registering a service with sc.exe.
cat > "$STAGE/RUN-WINDOWS.md" <<'GUIDE'
# Running ModularCA on Windows

This build is self-contained: the .NET runtime is bundled. Nothing needs to be installed.

## First run

1. Open a terminal in this folder.
2. Run the server:

       .\ModularCA.API.exe

3. On first start with no configuration, it enters setup mode and prints a one-time setup token
   to the console. Open the URL it logs (HTTPS) and complete the setup wizard, pasting that token
   when asked. Configuration is written under `config\`, key material under `keystores\`.

## Running as a Windows service

Once setup is complete, register the executable as a service so it starts at boot. From an
elevated prompt, with an absolute path to the executable:

    sc.exe create ModularCA binPath= "C:\path\to\ModularCA.API.exe" start= auto DisplayName= "ModularCA"
    sc.exe start ModularCA

Stop and remove with `sc.exe stop ModularCA` and `sc.exe delete ModularCA`. A service wrapper such
as NSSM is an alternative if you want richer restart and logging behaviour.

## Break-glass keystore access

`ModularCA.Keystore.Unlocker.exe` is the offline tool for inspecting or recovering the keystore.
It refuses to write plaintext key material without an explicit override; run it with no arguments
for usage.

## Licence

ModularCA is AGPL-3.0-only (see LICENSE). Third-party component notices are in
THIRD-PARTY-NOTICES.md. If you run a modified version as a network service, AGPL section 13
requires you to offer its source to users of that service.
GUIDE

note "verifying payload"
EXE_EXT=".exe"
for required in "ModularCA.API${EXE_EXT}" "ModularCA.Keystore.Unlocker${EXE_EXT}" \
                LICENSE THIRD-PARTY-NOTICES.md RUN-WINDOWS.md \
                wwwroot/admin/index.html wwwroot/user/index.html wwwroot/public/index.html \
                wwwroot/setup/index.html wwwroot/docs/index.html; do
    [[ -e "$STAGE/$required" ]] || { echo "MISSING from payload: $required" >&2; exit 1; }
done

note "creating $ZIP"
rm -f "$ZIP" "$ZIP.sha256"
if command -v zip >/dev/null 2>&1; then
    ( cd "$(dirname "$STAGE")" && zip -rq "$ZIP" "$(basename "$STAGE")" )
elif command -v powershell >/dev/null 2>&1; then
    # cygpath converts the git-bash POSIX paths to the Windows paths PowerShell needs.
    win_stage="$(cygpath -w "$STAGE")"
    win_zip="$(cygpath -w "$ZIP")"
    powershell -NoProfile -NonInteractive -Command \
        "Compress-Archive -Path '${win_stage}' -DestinationPath '${win_zip}' -Force" \
        || { echo "Compress-Archive failed" >&2; exit 1; }
else
    echo "REFUSING: neither 'zip' nor 'powershell' is available to create the archive" >&2
    exit 1
fi

sha256sum "$ZIP" > "$ZIP.sha256"
rm -rf "$(dirname "$STAGE")"

printf '\n  %s\n  %s\n\n' \
    "$(ls -lh "$ZIP" | awk '{print $5}')  $ZIP" \
    "$(awk '{print $1}' "$ZIP.sha256")"
