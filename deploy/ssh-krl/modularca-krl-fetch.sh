#!/bin/sh
#
# modularca-krl-fetch: fetches the key revocation list (KRL) of a ModularCA SSH CA key and installs
# it as the file sshd's RevokedKeys names.
#
# sshd refuses every public-key login while the file RevokedKeys names cannot be read. So the
# installed file is replaced only by a complete list that ssh-keygen reads as a KRL, and only by
# renaming a finished file over it. On any failure the installed file is left exactly as it is,
# and the exit status is not zero.
#
#   modularca-krl-fetch [--url URL] [--dest FILE] [--cacert FILE] [--allow-lower-version]
#
# Each setting is an option or an environment variable; an option wins.
#
#   --url URL               MODULARCA_KRL_URL     The KRL URL of the SSH CA key, as its page in the
#                                                 console shows it. Must be https.
#   --dest FILE             MODULARCA_KRL_DEST    Where to install it. Default /etc/ssh/revoked_keys.krl.
#   --cacert FILE           MODULARCA_KRL_CACERT  A PEM bundle to verify the server with, in place of
#                                                 the system's trust store.
#   --allow-lower-version   MODULARCA_KRL_ALLOW_LOWER_VERSION=1
#                                                 Install a list whose version is lower than the
#                                                 installed one's. A lower version is refused
#                                                 otherwise, because it normally means an older list.
#                                                 It is legitimate once: after the CA's database was
#                                                 restored from a backup.
#                           MODULARCA_KRL_CONNECT_TIMEOUT  Seconds to connect. Default 10.
#                           MODULARCA_KRL_MAX_TIME         Seconds for the whole transfer. Default 60.
#
# Beside the installed file it keeps FILE.etag: the ETag of the installed list, a checksum of the
# installed file and the URL. The ETag is sent as If-None-Match only while all three still hold,
# and a 304 answer then means the installed list is current.
#
# Exit status: 0 the installed list is current; 1 the fetch or a check failed; 2 a setting is wrong.
#
# Needs sh, curl, ssh-keygen (OpenSSH 8.0 or later, for -Q -l) and coreutils.

set -u
umask 077
LC_ALL=C
export LC_ALL

PROG=modularca-krl-fetch
MAX_BYTES=67108864

url=${MODULARCA_KRL_URL:-}
dest=${MODULARCA_KRL_DEST:-/etc/ssh/revoked_keys.krl}
cacert=${MODULARCA_KRL_CACERT:-}
allow_lower=${MODULARCA_KRL_ALLOW_LOWER_VERSION:-0}
connect_timeout=${MODULARCA_KRL_CONNECT_TIMEOUT:-10}
max_time=${MODULARCA_KRL_MAX_TIME:-60}

tmp=
hdr=
state_tmp=
cr=$(printf '\r')
tab=$(printf '\t')

note() { printf '%s: %s\n' "$PROG" "$*"; }
warn() { printf '%s: %s\n' "$PROG" "$*" >&2; }
fail() { warn "$*"; warn "the installed list was left as it is: $dest"; exit 1; }
misuse() { warn "$*"; exit 2; }

cleanup() {
    [ -n "$tmp" ] && rm -f "$tmp"
    [ -n "$hdr" ] && rm -f "$hdr"
    [ -n "$state_tmp" ] && rm -f "$state_tmp"
    return 0
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

usage() {
    printf '%s\n' \
        "usage: $PROG [--url URL] [--dest FILE] [--cacert FILE] [--allow-lower-version]" \
        "  --url URL              the KRL URL of the SSH CA key (https); or MODULARCA_KRL_URL" \
        "  --dest FILE            where to install it (default /etc/ssh/revoked_keys.krl); or MODULARCA_KRL_DEST" \
        "  --cacert FILE          a PEM bundle to verify the server with; or MODULARCA_KRL_CACERT" \
        "  --allow-lower-version  install a list with a lower version than the installed one;" \
        "                         or MODULARCA_KRL_ALLOW_LOWER_VERSION=1"
}

while [ $# -gt 0 ]; do
    case $1 in
        --url) [ $# -ge 2 ] || misuse "--url needs a value"; url=$2; shift 2 ;;
        --url=*) url=${1#--url=}; shift ;;
        --dest) [ $# -ge 2 ] || misuse "--dest needs a value"; dest=$2; shift 2 ;;
        --dest=*) dest=${1#--dest=}; shift ;;
        --cacert) [ $# -ge 2 ] || misuse "--cacert needs a value"; cacert=$2; shift 2 ;;
        --cacert=*) cacert=${1#--cacert=}; shift ;;
        --allow-lower-version) allow_lower=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; misuse "unknown argument: $1" ;;
    esac
done

is_number() {
    case $1 in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Prints the krl_version in a listing made by ssh-keygen -Q -l, or nothing.
version_in() {
    printf '%s\n' "$1" | while IFS= read -r line; do
        line=${line%"$cr"}
        case $line in
            '# KRL version '*) printf '%s\n' "${line#'# KRL version '}"; break ;;
        esac
    done
}

# Prints the value of the last ETag header in the header file $1, or nothing.
etag_in() {
    found=
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%"$cr"}
        case $line in
            [Ee][Tt][Aa][Gg]:*)
                found=${line#*:}
                while :; do
                    case $found in
                        ' '*|"$tab"*) found=${found#?} ;;
                        *' '|*"$tab") found=${found%?} ;;
                        *) break ;;
                    esac
                done
                ;;
        esac
    done < "$1"
    printf '%s\n' "$found"
}

# An ETag is kept and sent back only when it is made of characters that are safe in a header.
is_etag() {
    case $1 in
        ''|*[!A-Za-z0-9\"/_.:+=-]*) return 1 ;;
    esac
    [ "${#1}" -le 256 ]
}

case $url in
    '') usage >&2; misuse "no KRL URL: give --url or set MODULARCA_KRL_URL" ;;
    https://?*) ;;
    *) misuse "the KRL URL must begin with https://: a KRL is not signed, so TLS is all that protects it" ;;
esac
case $url in
    *[[:space:]]*|*[[:cntrl:]]*) misuse "the KRL URL has a space or a control character in it" ;;
esac
[ -n "$dest" ] || misuse "no destination: give --dest or set MODULARCA_KRL_DEST"
is_number "$connect_timeout" && [ "$connect_timeout" -gt 0 ] || misuse "MODULARCA_KRL_CONNECT_TIMEOUT must be a number of seconds"
is_number "$max_time" && [ "$max_time" -gt 0 ] || misuse "MODULARCA_KRL_MAX_TIME must be a number of seconds"
case $allow_lower in
    1|yes|true) allow_lower=1 ;;
    0|no|false|'') allow_lower=0 ;;
    *) misuse "MODULARCA_KRL_ALLOW_LOWER_VERSION must be 1 or 0" ;;
esac

command -v curl >/dev/null 2>&1 || misuse "curl is not installed"
command -v ssh-keygen >/dev/null 2>&1 || misuse "ssh-keygen is not installed"

dir=$(dirname -- "$dest") || misuse "the destination cannot be read as a path: $dest"
base=$(basename -- "$dest") || misuse "the destination cannot be read as a path: $dest"
state=$dest.etag
[ -d "$dir" ] || misuse "the destination's directory does not exist: $dir"
[ -w "$dir" ] || misuse "the destination's directory cannot be written: $dir"
[ ! -d "$dest" ] || misuse "the destination is a directory: $dest"
if [ -n "$cacert" ]; then
    [ -f "$cacert" ] && [ -r "$cacert" ] || misuse "the CA bundle cannot be read: $cacert"
fi

# What is installed now, and whether the saved ETag still describes it.
installed_sum=
if [ -f "$dest" ] && [ -s "$dest" ]; then
    installed_sum=$(cksum < "$dest") || installed_sum=
fi
send_etag=
if [ -n "$installed_sum" ] && [ -f "$state" ]; then
    saved_etag=; saved_sum=; saved_url=
    {
        IFS= read -r saved_etag || :
        IFS= read -r saved_sum || :
        IFS= read -r saved_url || :
    } < "$state"
    if [ "$saved_sum" = "$installed_sum" ] && [ "$saved_url" = "$url" ] && is_etag "$saved_etag"; then
        send_etag=$saved_etag
    fi
fi

# The download goes beside the destination, so that the rename is within one file system.
tmp=$(mktemp "$dir/.$base.new.XXXXXX") || fail "could not create a temporary file in $dir"
hdr=$(mktemp "$dir/.$base.hdr.XXXXXX") || fail "could not create a temporary file in $dir"

set -- -q --silent --show-error --globoff --proto '=https' --tlsv1.2 \
    --connect-timeout "$connect_timeout" --max-time "$max_time" --max-filesize "$MAX_BYTES" \
    --dump-header "$hdr" --output "$tmp" --write-out '%{http_code}'
[ -z "$cacert" ] || set -- "$@" --cacert "$cacert"
[ -z "$send_etag" ] || set -- "$@" --header "If-None-Match: $send_etag"
set -- "$@" --url "$url"

status=$(curl "$@") || fail "the KRL could not be fetched from $url (curl exit status $?)"

case $status in
    304)
        [ -n "$send_etag" ] || fail "the server answered 304 Not Modified to a request that named no ETag"
        note "not modified: the installed list is current ($dest)"
        exit 0
        ;;
    200) ;;
    *) fail "the server answered HTTP $status for $url" ;;
esac

[ -s "$tmp" ] || fail "the server answered with an empty body"

listing=$(ssh-keygen -Q -l -f "$tmp" 2>&1) || fail "what the server sent is not a KRL that ssh-keygen can read"
new_version=$(version_in "$listing")
is_number "$new_version" && [ "${#new_version}" -le 18 ] || fail "what the server sent is not a KRL with a version ssh-keygen can list"

old_version=
if [ -n "$installed_sum" ]; then
    if old_listing=$(ssh-keygen -Q -l -f "$dest" 2>/dev/null); then
        old_version=$(version_in "$old_listing")
        is_number "$old_version" && [ "${#old_version}" -le 18 ] || old_version=
    else
        warn "the installed file is not a KRL that ssh-keygen can read; replacing it"
    fi
fi
if [ -n "$old_version" ] && [ "$new_version" -lt "$old_version" ]; then
    if [ "$allow_lower" = 1 ]; then
        warn "installing version $new_version over version $old_version, as --allow-lower-version asks"
    else
        fail "the server's list has version $new_version, lower than the installed version $old_version. " \
            "That is an older list unless the CA's database was restored from a backup; if it was, run once with --allow-lower-version"
    fi
fi

new_sum=$(cksum < "$tmp") || fail "could not read the downloaded list"
new_etag=$(etag_in "$hdr")

chmod 0644 "$tmp" || fail "could not set the mode of the new list"
sync "$tmp" 2>/dev/null || sync 2>/dev/null || :
mv -f "$tmp" "$dest" || fail "could not move the new list into place"
tmp=
sync "$dir" 2>/dev/null || :

# The ETag is saved only now, after the list it names is in place.
if is_etag "$new_etag"; then
    if state_tmp=$(mktemp "$dir/.$base.etag.XXXXXX") \
        && printf '%s\n%s\n%s\n' "$new_etag" "$new_sum" "$url" > "$state_tmp" \
        && chmod 0644 "$state_tmp" \
        && mv -f "$state_tmp" "$state"; then
        state_tmp=
    else
        rm -f "$state"
        warn "the list is installed, but its ETag could not be saved; the next run fetches the whole list again"
    fi
else
    rm -f "$state"
fi

if [ -n "$old_version" ]; then
    note "installed KRL version $new_version (was $old_version): $dest"
else
    note "installed KRL version $new_version: $dest"
fi
exit 0
