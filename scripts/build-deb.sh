#!/usr/bin/env bash
#
# Builds the Ubuntu .deb from the same payload as the tarball.
#
#   ./scripts/build-deb.sh                 # publishes, then packages
#   ./scripts/build-deb.sh --from-tarball  # repacks dist/*.tar.gz without republishing
#
# Output: dist/modularca_<DEB_VERSION>-1_amd64.deb plus a .sha256 alongside it.
#
# The payload is taken from the tarball rather than from a second publish, so the .deb and the
# tarball cannot drift: whatever ships in one ships byte-identically in the other.
#
# Requires nfpm (https://nfpm.goreleaser.com). It is a single static binary and needs no Debian
# toolchain, which is what makes this runnable from Windows git-bash as well as from Linux.
set -euo pipefail

RID=linux-x64
FROM_TARBALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-tarball) FROM_TARBALL=1; shift ;;
        --rid) RID="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v nfpm >/dev/null 2>&1 || die \
"nfpm not found. Install it from https://nfpm.goreleaser.com/install/ — it is a single binary.
       On Linux:   go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
       On Windows: scoop install nfpm   (or download the release archive)"

VERSION="$(tr -d ' \r\n' < VERSION)"

# Debian version ordering.
#
# VERSION is "0.1.0-rc3". dpkg compares "0.1.0-rc3" as GREATER than "0.1.0", so shipping it as-is
# would make the eventual 0.1.0 release look like a downgrade and apt would decline to install it
# over the candidate. A tilde sorts before everything, including the empty string, which is
# precisely what a pre-release means. Rewrite the first hyphen that introduces a pre-release tag.
#
#   0.1.0-rc3  ->  0.1.0~rc3        0.1.0  ->  0.1.0  (unchanged)
DEB_VERSION="$(printf '%s' "$VERSION" | sed -E 's/^([0-9]+(\.[0-9]+)*)-(.+)$/\1~\3/')"
[[ "$DEB_VERSION" == *-* ]] && die "version '$VERSION' still contains a hyphen after conversion; dpkg would misorder it"

TARBALL="$ROOT/dist/modularca-${VERSION}-${RID}.tar.gz"

if [[ $FROM_TARBALL -eq 0 ]]; then
    note "building the payload"
    "$ROOT/scripts/build-linux-dist.sh" --rid "$RID"
fi
[[ -f "$TARBALL" ]] || die "no tarball at $TARBALL (drop --from-tarball to build one)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/payload"
mkdir -p "$STAGE"

note "unpacking $(basename "$TARBALL")"
tar -xzf "$TARBALL" -C "$WORK"
INNER="$WORK/modularca-${VERSION}-${RID}"
[[ -d "$INNER" ]] || die "unexpected archive layout: $INNER not found"

# The tarball's own installer and deploy stubs are for the manual path. Inside a .deb the
# maintainer scripts do that work, and shipping a second installer alongside them invites someone
# to run it and fight dpkg over the same files.
mv "$INNER"/* "$STAGE"/ 2>/dev/null || true
rm -f "$STAGE/install.sh" "$STAGE/README-DEPLOY.md"
rm -rf "$STAGE/deploy"
# Runtime state directories are created by postinst with the right modes; an empty one here would
# be package-owned and so removed on purge, which is the opposite of what postrm is careful about.
rm -rf "$STAGE/keystores" "$STAGE/logs"

[[ -x "$STAGE/ModularCA.API" || -e "$STAGE/ModularCA.API" ]] || die "payload is missing ModularCA.API"

# Carve the two ELF entrypoints out of the payload tree.
#
# They need mode 0755 and nothing else does, but nfpm takes a tree wholesale and refuses a
# second entry for a destination the tree already covers. Moving them aside lets the tree keep
# its blanket umask while these two get an explicit mode. The exec bit cannot come from the
# source file: on Windows there is none for nfpm to read.
BINDIR="$WORK/bin"
mkdir -p "$BINDIR"
mv "$STAGE/ModularCA.API" "$STAGE/ModularCA.Keystore.Unlocker" "$BINDIR/"

# Refuse to ship a maintainer script with CRLF line endings.
#
# dpkg runs these from inside the package, after unpacking, so a carriage return in the shebang
# aborts the install with a "bad interpreter" error and leaves the package half-configured --
# the most expensive moment for it to fail. .gitattributes pins them to LF, but this repo is
# developed on Windows with core.autocrlf=true and these files have no extension, so the *.sh
# rule does not reach them. Check the bytes rather than trusting the configuration.
note "checking maintainer scripts"
CR="$(printf '\r')"
for script in preinst postinst prerm postrm; do
    path="packaging/debian/$script"
    [[ -f "$path" ]] || die "missing maintainer script: $path"
    # -U (--binary) is required: on MSYS/git-bash grep reads text mode and strips the CR
    # before matching, so the check silently passes on exactly the platform that produces
    # the problem. On Linux the flag is documented as a no-op.
    if LC_ALL=C grep -qU "$CR" "$path"; then
        die "$path has CRLF line endings; dpkg would fail on its shebang. Convert it to LF."
    fi
done

note "packaging modularca ${DEB_VERSION}-1 (amd64)"
mkdir -p "$ROOT/dist"

# Render the config rather than relying on nfpm to expand ${...} from the environment.
#
# Two reasons. nfpm did not substitute the staging path from an env prefix, and on Windows the
# binary is a native one: it cannot resolve an MSYS path like /tmp/xxx/payload at all. cygpath -m
# gives the mixed form (C:/path, forward slashes) that Go tools accept; on Linux there is no
# cygpath and the path is already in the right form.
if command -v cygpath >/dev/null 2>&1; then
    STAGE_NATIVE="$(cygpath -m "$STAGE")"
else
    STAGE_NATIVE="$STAGE"
fi

if command -v cygpath >/dev/null 2>&1; then
    BINDIR_NATIVE="$(cygpath -m "$BINDIR")"
else
    BINDIR_NATIVE="$BINDIR"
fi

RENDERED="$WORK/nfpm.yaml"
sed -e "s|\${DEB_VERSION}|${DEB_VERSION}|g" \
    -e "s|\${STAGE}|${STAGE_NATIVE}|g" \
    -e "s|\${BINDIR}|${BINDIR_NATIVE}|g" \
    packaging/nfpm.yaml > "$RENDERED"
grep -q '\${' "$RENDERED" && die "unsubstituted placeholder left in the rendered nfpm config"

# Relative paths inside the config (deploy/, packaging/debian/) resolve against the working
# directory, which is the repo root, so the rendered copy living elsewhere is fine.
nfpm package --config "$RENDERED" --packager deb --target "$ROOT/dist"

DEB="$ROOT/dist/modularca_${DEB_VERSION}-1_amd64.deb"
[[ -f "$DEB" ]] || die "nfpm reported success but $DEB is missing"

rm -f "$DEB.sha256"
sha256sum "$DEB" > "$DEB.sha256"

printf '\n  %s\n  %s\n\n' \
    "$(ls -lh "$DEB" | awk '{print $5}')  $DEB" \
    "$(awk '{print $1}' "$DEB.sha256")"

cat <<'NEXT'
  Install:    sudo apt install ./dist/modularca_<version>_amd64.deb
  Remove:     sudo apt remove modularca      (keeps keys, config and database)
  Purge:      sudo apt purge modularca       (still keeps keys, config and database - by design)

NEXT
