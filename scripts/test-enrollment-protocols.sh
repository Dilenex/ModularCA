#!/usr/bin/env bash
#
# Exercises EST (RFC 7030) and CMP (RFC 4210) against a running ModularCA using nothing but
# openssl and curl — the tools an actual client would use, rather than the service classes a unit
# test can reach.
#
# The distinction matters here more than usual. Both protocols have unit coverage of their
# services, and both are reachable only through a controller, a middleware chain, an
# authentication handler and a TLS listener that no unit test touches. A protocol can be
# completely correct in its service and still be unusable by every real client, and that is not a
# theoretical worry: see the EST HTTP-auth case below.
#
#   ./scripts/test-enrollment-protocols.sh https://ca4.maroongang.net my-ca-label
#   ./scripts/test-enrollment-protocols.sh https://ca4.maroongang.net my-ca-label \
#        --client-cert client.pem --client-key client.key   # EST mTLS enrolment
#
# NOTE on the mTLS probe: Kestrel asks for a client certificate only when the TLS SNI matches
# Mtls.AuthSubdomain, so pointing this at the ordinary CA hostname produces a successful
# server-auth handshake in which the certificate is never requested, and EST then refuses with
# "requires a client certificate (mTLS)". That is the server's SNI gate, not a fault in the
# certificate or this script — pass the mTLS hostname as the base URL to exercise it.
#   ./scripts/test-enrollment-protocols.sh https://ca4.maroongang.net my-ca-label \
#        --cmp-secret 'shared-secret'                       # CMP PBM enrolment
#
# Exit status is the number of checks that failed, so this is usable from CI once a disposable CA
# exists to point it at.
set -uo pipefail

BASE="${1:-}"
CA_LABEL="${2:-}"
[ -z "$BASE" ] || [ -z "$CA_LABEL" ] && {
    echo "usage: $0 <base-url> <ca-label> [--client-cert F --client-key F] [--cmp-secret S] [--insecure]" >&2
    exit 2
}
shift 2

CLIENT_CERT=""; CLIENT_KEY=""; CMP_SECRET=""; INSECURE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --client-cert) CLIENT_CERT="$2"; shift 2 ;;
        --client-key)  CLIENT_KEY="$2";  shift 2 ;;
        --cmp-secret)  CMP_SECRET="$2";  shift 2 ;;
        --insecure)    INSECURE="1";     shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=$((FAILED + 1)); }
note() { printf '        %s\n' "$1"; }
head2() { printf '\n\033[36m== %s\033[0m\n' "$1"; }

CURL=(curl -sS --max-time 30)
[ -n "$INSECURE" ] && CURL+=(-k)

# ── preflight ────────────────────────────────────────────────────────────────
head2 "Preflight"
if info=$("${CURL[@]}" "$BASE/api/v1/public/info" 2>&1); then
    pass "reachable: $BASE"
    note "$(printf '%s' "$info" | head -c 200)"
else
    fail "cannot reach $BASE — $info"
    echo; echo "Nothing else can run. Exiting."; exit 1
fi

# Which protocols the server says are on. A disabled protocol answers 503 to everything, and
# reporting that as a stack of failures blames the protocol for an administrative setting — the
# exact misdirection this tool exists to catch elsewhere.
enabled=$(printf '%s' "$info" | tr -d ' ' | sed -n 's/.*"enabledProtocols":\[\([^]]*\)\].*/\1/p' | tr -d '"')
case ",$enabled," in *,EST,*) EST_ON=1 ;; *) EST_ON="" ;; esac
case ",$enabled," in *,CMP,*) CMP_ON=1 ;; *) CMP_ON="" ;; esac
note "enabled protocols: ${enabled:-none reported}"
[ -z "$EST_ON" ] && note "EST is DISABLED on this server — enable it per-CA before its checks mean anything."
[ -z "$CMP_ON" ] && note "CMP is DISABLED on this server — enable it per-CA before its checks mean anything."

# ── EST ──────────────────────────────────────────────────────────────────────
head2 "EST (RFC 7030)"

if [ -z "$EST_ON" ]; then
    note "SKIPPED — EST is not enabled on this server. Every endpoint answers 503 regardless of"
    note "the request, so nothing here would be testing EST."
else
# /cacerts is unauthenticated by design and is the only EST endpoint that can be checked without
# credentials, which makes it the first thing to confirm before blaming auth for anything else.
if body=$("${CURL[@]}" -w '\n%{http_code}' "$BASE/est/$CA_LABEL/cacerts" 2>&1); then
    code=$(printf '%s' "$body" | tail -1)
    payload=$(printf '%s' "$body" | sed '$d')
    if [ "$code" = "200" ]; then
        printf '%s' "$payload" | tr -d '\r\n' | base64 -d > "$WORK/cacerts.p7b" 2>/dev/null
        if openssl pkcs7 -inform DER -in "$WORK/cacerts.p7b" -print_certs -noout >/dev/null 2>&1; then
            n=$(openssl pkcs7 -inform DER -in "$WORK/cacerts.p7b" -print_certs 2>/dev/null | grep -c "BEGIN CERTIFICATE")
            pass "/cacerts returned a parseable PKCS#7 with $n certificate(s)"
        else
            fail "/cacerts returned 200 but the body is not a PKCS#7 this openssl can parse"
        fi
    else
        fail "/cacerts returned HTTP $code"
        note "$(printf '%s' "$payload" | head -c 200)"
    fi
else
    fail "/cacerts request failed — $body"
fi

# RFC 7030 section 3.2.2 puts EST at /.well-known/est/. ModularCA routes /est/{ca} and
# /api/v1/est/{ca} only. Compliant clients — libest, and the embedded stacks in network gear —
# construct the well-known path and will not find this server.
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/.well-known/est/$CA_LABEL/cacerts" 2>/dev/null)
if [ "$code" = "200" ]; then
    pass "/.well-known/est/ is served (RFC 7030 section 3.2.2)"
elif [ "$code" != "404" ]; then
    # Only a 404 proves the path is unrouted. Anything else — 503, 403, 500 — is the server
    # answering for some other reason, and calling that an RFC violation would be asserting more
    # than the response supports.
    note "/.well-known/est/{ca}/cacerts returned HTTP $code — inconclusive, not a 404"
else
    fail "/.well-known/est/{ca}/cacerts returned HTTP 404 — RFC 7030 mandates this path"
    note "ModularCA serves /est/{ca} and /api/v1/est/{ca}. A client that follows the RFC and"
    note "builds the well-known path cannot reach this server at all."
fi

# A CSR to enrol with. Key type deliberately EC P-256: it is what a constrained client would use,
# and it exercises the ECDSA path rather than the better-trodden RSA one.
# The doubled slash on -subj is for Git Bash and is load-bearing. MSYS rewrites any argument
# beginning with a single slash into a Windows path, so -subj "/CN=x" reaches openssl as
# "C:/Program Files/Git/CN=x" and is rejected; no CSR is written, the enrol step posts an empty
# body, and the server answers "Empty request body" — which reads as a server fault and is not one.
# A leading "//" is left alone by MSYS and collapsed back to "/" for openssl.
#
# MSYS_NO_PATHCONV=1 is the obvious alternative and is wrong here: it also stops $WORK (a POSIX
# path) being translated, so a Windows openssl cannot open the output files and fails the same way
# for a different reason. Escape the one argument, not the whole command.
SUBJ_PREFIX="/"
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) SUBJ_PREFIX="//" ;; esac

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$WORK/est.key" -out "$WORK/est.csr" \
    -subj "${SUBJ_PREFIX}CN=est-probe.example.test" >/dev/null 2>&1
if [ ! -s "$WORK/est.csr" ]; then
    fail "could not generate a CSR with openssl — nothing below would be testing the server"
    note "openssl: $(openssl version 2>&1)"
    exit "$FAILED"
fi
# EST wants the base64 of the DER CSR, with no PEM armour.
openssl req -in "$WORK/est.csr" -outform DER 2>/dev/null | base64 | tr -d '\n' > "$WORK/est.b64"

enroll() {   # $1 = label, remaining = extra curl args
    local label="$1"; shift
    local out
    out=$("${CURL[@]}" -w '\n%{http_code}' "$@" \
        -H 'Content-Type: application/pkcs10' \
        -H 'Content-Transfer-Encoding: base64' \
        --data-binary "@$WORK/est.b64" \
        "$BASE/est/$CA_LABEL/simpleenroll" 2>&1)
    local code payload
    code=$(printf '%s' "$out" | tail -1)
    payload=$(printf '%s' "$out" | sed '$d')

    if [ "$code" = "200" ]; then
        printf '%s' "$payload" | tr -d '\r\n' | base64 -d > "$WORK/est.p7b" 2>/dev/null
        if openssl pkcs7 -inform DER -in "$WORK/est.p7b" -print_certs -noout >/dev/null 2>&1; then
            pass "$label — certificate issued"
            openssl pkcs7 -inform DER -in "$WORK/est.p7b" -print_certs 2>/dev/null \
                | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/        /'
            return 0
        fi
        fail "$label — HTTP 200 but the response is not a parseable PKCS#7"
        return 1
    fi
    fail "$label — HTTP $code"
    note "$(printf '%s' "$payload" | head -c 300)"
    return 1
}

if [ -n "$CLIENT_CERT" ] && [ -n "$CLIENT_KEY" ]; then
    # curl linked against Schannel — the stock Windows build, including the one in Git Bash —
    # cannot present a client certificate from a file. A PEM fails with 0x80092002 and a
    # file-based PKCS#12 fails with SEC_E_NO_CREDENTIALS, because Schannel wants a reference into
    # the Windows certificate store rather than a file at all. Both errors name the certificate
    # and neither is about the certificate, which is a long way to travel to learn nothing about
    # the server.
    #
    # Refusing to run beats reporting a failure the server had no part in: a FAIL line here would
    # be read as "EST mTLS is broken", and the evidence would not support it.
    if curl -V 2>/dev/null | grep -qi schannel; then
        note "SKIPPED /simpleenroll over mTLS — this curl is built against Schannel, which cannot"
        note "load a client certificate from a file. That is a limitation of this curl, not of the"
        note "server, so running it here would prove nothing either way."
        note "Run from Linux or WSL, or use a curl built against OpenSSL."
    else
        enroll "/simpleenroll over mTLS" --cert "$CLIENT_CERT" --key "$CLIENT_KEY"
    fi
else
    note "SKIPPED /simpleenroll over mTLS — pass --client-cert and --client-key to run it."
    note "mTLS is currently the ONLY working EST authentication path; see below."
fi

# HTTP Basic is what RFC 7030 section 3.2.3 designates as the baseline client authentication and
# what most EST clients send by default. ModularCA registers exactly one authentication scheme —
# JwtBearer — so a Basic header never authenticates, HttpContext.User.Identity.IsAuthenticated
# stays false, and EnrollmentAuthorizationService.ValidateEst refuses. The CaProtocolConfig field
# that turns this on is documented as "EST accepts HTTP Basic/Digest authentication for
# enrollment", which is a promise nothing in the pipeline keeps.
#
# This probe is expected to fail today. It is here so the failure is visible and dated rather than
# discovered by a customer whose EST client cannot enrol.
note ""
note "Probing HTTP Basic (expected to fail — no Basic scheme is registered):"
enroll "/simpleenroll with HTTP Basic" -u "est-probe:est-probe" || true

# ── CMP ──────────────────────────────────────────────────────────────────────
fi

# ââ CMP ââ
head2 "CMP (RFC 4210)"

if ! openssl cmp -help >/dev/null 2>&1; then
    fail "this openssl has no 'cmp' command — need OpenSSL 3.0 or newer"
    note "openssl version: $(openssl version 2>/dev/null)"
elif [ -z "$CMP_SECRET" ]; then
    note "SKIPPED — pass --cmp-secret to run an initial request."
    note "CMP treats its own message protection as authentication (PBM or signature), so a"
    note "shared secret is all that is needed; no HTTP credentials are involved."
else
    # -cmd ir is the initial request: no prior certificate, authenticated by PBMAC over the
    # shared secret. This is the flow a device uses on first contact with a CA.
    if openssl cmp -cmd ir \
        -server "$BASE/cmp/$CA_LABEL" \
        -ref "cmp-probe" -secret "pass:$CMP_SECRET" \
        -subject "/CN=cmp-probe.example.test" \
        -newkey "$WORK/cmp.key" -certout "$WORK/cmp.crt" \
        ${INSECURE:+-tls_used -no_check_time} \
        >"$WORK/cmp.log" 2>&1; then
        pass "initial request (ir) — certificate issued"
        openssl x509 -in "$WORK/cmp.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/        /'
    else
        fail "initial request (ir) failed"
        tail -12 "$WORK/cmp.log" | sed 's/^/        /'
    fi
fi

# ── summary ──────────────────────────────────────────────────────────────────
printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf '\033[32mAll checks passed.\033[0m\n'
else
    printf '\033[31m%d check(s) failed.\033[0m\n' "$FAILED"
fi
exit "$FAILED"
