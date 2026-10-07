#!/bin/sh
# Regenerates the OpenSSH golden fixtures that SshWireFormatGoldenTests reads.
# Needs OpenSSH ssh-keygen 8.7 or later (UTC validity, -V always:forever). Run from any directory.
# The *.testkey files are CA private keys made for these tests only; nothing trusts them.
# The tests take only each certificate's nonce and signature from these files; every other field
# is spelled out in the test, so the parameters below must stay in step with SshFixtureCases.
set -eu
cd "$(dirname "$0")"
rm -f -- *.testkey *.pub *.krl *.serials

VALIDITY=20260101000000Z:20270101000000Z

key() { # name type [bits]
    if [ -n "${3:-}" ]; then
        ssh-keygen -q -t "$2" -b "$3" -N "" -C "$1" -f "$1"
    else
        ssh-keygen -q -t "$2" -N "" -C "$1" -f "$1"
    fi
    mv -- "$1" "$1.testkey"
}

key ca-ed25519 ed25519
key ca-p256 ecdsa 256
key ca-p384 ecdsa 384
key ca-p521 ecdsa 521
key ca-rsa rsa 3072
key subj-ed25519 ed25519
key subj-p256 ecdsa 256
key subj-p384 ecdsa 384
key subj-p521 ecdsa 521
key subj-rsa rsa 2048
rm -f -- subj-*.testkey

cert() { # case ca subject serial principals [extra ssh-keygen args...]
    name=$1; ca=$2; subj=$3; serial=$4; principals=$5; shift 5
    cp -- "subj-$subj.pub" "$name.pub"
    ssh-keygen -q -s "ca-$ca.testkey" -I "$name" -n "$principals" -z "$serial" "$@" "$name.pub"
    rm -- "$name.pub"
}

cert user-ed25519 ed25519 ed25519 1001 alice,bob -V "$VALIDITY"
cert host-ed25519 ed25519 ed25519 1002 host1.example.com,host1 -h -V "$VALIDITY"
cert user-p256 p256 p256 2001 alice,bob -V "$VALIDITY"
cert host-p256 p256 p256 2002 host1.example.com,host1 -h -V "$VALIDITY"
cert user-p384 p384 p384 3001 alice,bob -V "$VALIDITY"
cert host-p384 p384 p384 3002 host1.example.com,host1 -h -V "$VALIDITY"
cert user-p521 p521 p521 4001 alice,bob -V "$VALIDITY"
cert host-p521 p521 p521 4002 host1.example.com,host1 -h -V "$VALIDITY"
cert user-rsa-sha512 rsa rsa 5001 alice,bob -t rsa-sha2-512 -V "$VALIDITY"
cert host-rsa-sha512 rsa rsa 5002 host1.example.com,host1 -h -t rsa-sha2-512 -V "$VALIDITY"
cert user-rsa-sha256 rsa rsa 5003 alice,bob -t rsa-sha2-256 -V "$VALIDITY"
cert host-rsa-sha256 rsa rsa 5004 host1.example.com,host1 -h -t rsa-sha2-256 -V "$VALIDITY"
cert user-options ed25519 rsa 18446744073709551000 deploy -V "$VALIDITY" \
    -O clear -O permit-pty -O permit-X11-forwarding -O no-touch-required \
    -O "force-command=/usr/bin/rsync --server" -O source-address=10.0.0.0/8,192.0.2.1 \
    -O verify-required -O extension:login@example.com=alice
cert user-forever p256 ed25519 7 alice -V always:forever

printf 'serial: 1001\nserial: 5000000\nserial: 18446744073709551000\n' > revoked.serials
ssh-keygen -q -k -f revoked.krl -z 42 -s ca-ed25519.pub revoked.serials
: > empty.serials
ssh-keygen -q -k -f empty.krl -z 7 -s ca-ed25519.pub empty.serials
rm -f -- *.serials

ssh-keygen -Q -f revoked.krl user-ed25519-cert.pub >/dev/null 2>&1 && { echo "KRL did not revoke serial 1001" >&2; exit 1; }
ssh-keygen -Q -f revoked.krl host-ed25519-cert.pub >/dev/null
echo "fixtures regenerated"
