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
#   ./scripts/test-enrollment-protocols.sh https://ca.example.test my-ca-label
#   ./scripts/test-enrollment-protocols.sh https://ca.example.test my-ca-label \
#        --client-cert client.pem --client-key client.key   # EST mTLS enrolment
#
# NOTE on the mTLS probe: Kestrel asks for a client certificate only when the TLS SNI matches
# Mtls.AuthSubdomain, so pointing this at the ordinary CA hostname produces a successful
# server-auth handshake in which the certificate is never requested, and EST then refuses with
# "requires a client certificate (mTLS)". That is the server's SNI gate, not a fault in the
# certificate or this script — pass the mTLS hostname as the base URL to exercise it.
#   ./scripts/test-enrollment-protocols.sh https://ca.example.test my-ca-label \
#        --cmp-secret 'shared-secret'                       # CMP PBM enrolment
#   ./scripts/test-enrollment-protocols.sh https://ca.example.test my-ca-label \
#        --basic-netrc est.netrc --cmp-secret-file cmp.secret --cmp-ref R --enforcement
#                                                           # and the request profile's refusals
#
# Exit status is the number of checks that failed, so this is usable from CI once a disposable CA
# exists to point it at.
set -uo pipefail

BASE="${1:-}"
CA_LABEL="${2:-}"
[ -z "$BASE" ] || [ -z "$CA_LABEL" ] && {
    echo "usage: $0 <base-url> <ca-label> [--client-cert F --client-key F] [--basic-netrc F] [--cmp-secret S | --cmp-secret-file F] [--cmp-ref R] [--enforcement] [--insecure]" >&2
    exit 2
}
shift 2

CLIENT_CERT=""; CLIENT_KEY=""; CMP_SECRET=""; INSECURE=""; BASIC_NETRC=""; CMP_REF="cmp-probe"; ENFORCEMENT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --client-cert) CLIENT_CERT="$2"; shift 2 ;;
        --client-key)  CLIENT_KEY="$2";  shift 2 ;;
        # A netrc file rather than --basic-user/--basic-pass: the credentials then never appear
        # on a command line, in shell history, or in whatever transcript is driving this script.
        # Format: machine <host> login <user> password <pw>
        --basic-netrc) BASIC_NETRC="$2"; shift 2 ;;
        --cmp-secret)  CMP_SECRET="$2";  shift 2 ;;
        # The secret from a file, so it never appears on a command line or in a transcript.
        --cmp-secret-file) CMP_SECRET="$(tr -d '[:space:]' < "$2")"; shift 2 ;;
        # The reference value (senderKID) the credential was created with. It selects which
        # shared secret the server verifies the MAC against.
        --cmp-ref)     CMP_REF="$2";     shift 2 ;;
        --insecure)    INSECURE="1";     shift ;;
        # After each enrolment that issues, the same request with one thing changed that the
        # seeded request profile refuses. Under a looser profile the CA issues those too.
        --enforcement) ENFORCEMENT="1";  shift ;;
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

expect_refused() {   # $1 = label, $2 = URL, remaining = extra curl args; posts $WORK/est.b64
    local label="$1" url="$2"; shift 2
    local code
    code=$("${CURL[@]}" -o "$WORK/refusal.body" -w '%{http_code}' "$@" \
        -H 'Content-Type: application/pkcs10' \
        -H 'Content-Transfer-Encoding: base64' \
        --data-binary "@$WORK/est.b64" "$url" 2>/dev/null)
    case "$code" in
        400) pass "$label — refused (HTTP 400); the EST tab of the audit log names the rule" ;;
        200) fail "$label — issued. Either the request profile EST uses on this CA allows it, or the profile was not applied" ;;
        202) fail "$label — held for approval instead of refused at submission" ;;
        *)   fail "$label — HTTP $code, which is not the refusal expected"
             note "$(head -c 300 "$WORK/refusal.body" 2>/dev/null)" ;;
    esac
}

est_csr() {   # $1 = CN, $2 = subjectAltName value or empty; writes $WORK/est.b64
    local san_args=()
    [ -n "${2:-}" ] && san_args=(-addext "subjectAltName=$2")
    rm -f "$WORK/est-probe.csr"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$WORK/est-probe.key" -out "$WORK/est-probe.csr" \
        -subj "${SUBJ_PREFIX}CN=$1" "${san_args[@]}" >/dev/null 2>&1
    openssl req -in "$WORK/est-probe.csr" -outform DER 2>/dev/null | base64 | tr -d '\n' > "$WORK/est.b64"
}

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
            # The PKCS#7 may carry the chain as well as the leaf, and openssl x509 reads only the
            # first certificate it sees, which was the CA. Print each one, leaf and chain alike.
            openssl pkcs7 -inform DER -in "$WORK/est.p7b" -print_certs 2>/dev/null \
                | awk -v w="$WORK" '/BEGIN CERT/{n++} {print > (w "/est-cert-" n ".pem")}'
            for c in "$WORK"/est-cert-*.pem; do
                [ -s "$c" ] || continue
                openssl x509 -in "$c" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/        /'
                note "--"
            done
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
    note "mTLS also needs Est.AuthSubdomain configured on the server and the client pointed at it."
fi

# HTTP Basic is what RFC 7030 section 3.2.3 designates as the baseline client authentication and
# what most EST clients send by default. It is served by a named scheme confined to the EST
# controller; the account must hold cert.request on the CA, and its password must not be flagged
# for change or expired. Until the scheme existed this probe was expected to fail and said so;
# it now expects to succeed when credentials are supplied, and the CSR's CN must equal the
# username because the service binds the two.
#
# The CSR also carries DNS:<username>. The seeded "Enterprise Server (EST)" request profile requires
# a SAN, and EST accepts a SAN that repeats the caller's own name without any profile rule.
if [ -n "$BASIC_NETRC" ]; then
    if [ ! -r "$BASIC_NETRC" ]; then
        fail "--basic-netrc file is not readable: $BASIC_NETRC"
    else
        BASIC_USER=$(awk '/login/ { for (i = 1; i <= NF; i++) if ($i == "login") print $(i + 1) }' "$BASIC_NETRC" | head -1)
        if [ -z "$BASIC_USER" ]; then
            fail "--basic-netrc file has no 'login' entry"
        else
            est_csr "$BASIC_USER" "DNS:${BASIC_USER}"
            if enroll "/simpleenroll with HTTP Basic (CN=${BASIC_USER}, DNS:${BASIC_USER})" --netrc-file "$BASIC_NETRC"; then
                EST_BASIC_OK=1
            fi
        fi
    fi
else
    note "SKIPPED /simpleenroll with HTTP Basic — pass --basic-netrc FILE to run it."
    note "The file holds 'machine <host> login <user> password <pw>'; the account needs cert.request on the CA."
fi

# A wrong password must be refused without revealing anything, and must land in the audit trail
# as a UserLoginFailed row with protocol EST. Run regardless of credentials.
note ""
note "Probing HTTP Basic with a wrong password (expected to be refused):"
if out=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -u "est-probe-nobody:not-the-password" \
        -H 'Content-Type: application/pkcs10' --data-binary "@$WORK/est.b64" \
        "$BASE/est/$CA_LABEL/simpleenroll" 2>/dev/null); then
    case "$out" in
        200) fail "wrong Basic credentials were accepted (HTTP 200)" ;;
        *)   pass "wrong Basic credentials refused (HTTP $out); check the audit log for UserLoginFailed / protocol EST" ;;
    esac
fi

# The request profile, enforced. Each probe is the request that was just issued with one thing
# changed, sent with the same credentials, so a refusal can only be about that one thing. EST
# answers every refusal with the same 400 and keeps the reason for the audit log (EST tab).
if [ -n "$ENFORCEMENT" ]; then
    note ""
    note "Request profile probes (refused under the seeded 'Enterprise Server (EST)' profile):"
    if [ -z "${EST_BASIC_OK:-}" ]; then
        note "SKIPPED — they need the HTTP Basic enrolment above to have issued first."
    else
        est_csr "$BASIC_USER" ""
        expect_refused "EST, no SAN (the profile requires one)" "$BASE/est/$CA_LABEL/simpleenroll" --netrc-file "$BASIC_NETRC"
        est_csr "$BASIC_USER" "email:${BASIC_USER}"
        expect_refused "EST, an email SAN (the profile allows DNS and IP)" "$BASE/est/$CA_LABEL/simpleenroll" --netrc-file "$BASIC_NETRC"
    fi
fi
fi

# ── CMP ──────────────────────────────────────────────────────────────────────
head2 "CMP (RFC 4210)"

if ! openssl cmp -help >/dev/null 2>&1; then
    fail "this openssl has no 'cmp' command — need OpenSSL 3.0 or newer"
    note "openssl version: $(openssl version 2>/dev/null)"
elif [ -z "$CMP_SECRET" ]; then
    note "SKIPPED — pass --cmp-secret-file (or --cmp-secret) and --cmp-ref to run an initial request."
    note "CMP treats its own message protection as authentication (PBM or signature), so a"
    note "shared secret is all that is needed; no HTTP credentials are involved."
else
    # -cmd ir is the initial request: no prior certificate, authenticated by PBMAC over the
    # shared secret. This is the flow a device uses on first contact with a CA.
    # -newkey names an existing key file; openssl cmp does not generate one. EC P-256, as the
    # EST probe uses, so the two exercise the same issuance path.
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/cmp.key" >/dev/null 2>&1
    # The server signs its responses, error responses included, with the CA key; the client
    # will not even display an ERROR body until it can verify that signature, so it needs the CA
    # certificate as a trust anchor. The EST section already fetched it via /cacerts.
    TRUSTED_ARGS=()
    if [ -s "$WORK/cacerts.p7b" ] && openssl pkcs7 -inform DER -in "$WORK/cacerts.p7b" -print_certs > "$WORK/ca.pem" 2>/dev/null; then
        TRUSTED_ARGS=(-trusted "$WORK/ca.pem")
    fi
    if openssl cmp -cmd ir \
        -server "$BASE/cmp/$CA_LABEL" \
        -ref "$CMP_REF" -secret "pass:$CMP_SECRET" "${TRUSTED_ARGS[@]}" -unprotected_errors \
        -subject "${SUBJ_PREFIX}CN=cmp-probe.example.test" \
        -newkey "$WORK/cmp.key" -certout "$WORK/cmp.crt" \
        ${INSECURE:+-tls_used -no_check_time} \
        >"$WORK/cmp.log" 2>&1; then
        pass "initial request (ir) — certificate issued"
        openssl x509 -in "$WORK/cmp.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/        /'

        # Key update (kur), signed with the certificate just issued. This is the signature-protected
        # exchange: the request is signed by the client certificate, and the RESPONSE is signed by the
        # server, so it is the one path that exercises the CA's CMP signing certificate. Without a
        # dedicated signer the server signs with the CA certificate, whose key usage lacks
        # digitalSignature, and openssl refuses the response with "no suitable sender cert".
        note ""
        note "Probing key update (kur) signed with the issued certificate:"
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/cmp2.key" >/dev/null 2>&1
        if openssl cmp -cmd kur             -server "$BASE/cmp/$CA_LABEL"             -cert "$WORK/cmp.crt" -key "$WORK/cmp.key"             -newkey "$WORK/cmp2.key" -certout "$WORK/cmp2.crt" "${TRUSTED_ARGS[@]}" -unprotected_errors             ${INSECURE:+-tls_used -no_check_time}             >"$WORK/cmp-kur.log" 2>&1; then
            pass "key update (kur) — certificate reissued; the server's CMP signing certificate verified"
            openssl x509 -in "$WORK/cmp2.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/        /'
        else
            fail "key update (kur) failed"
            grep -E "CMP (error|info: received)|no suitable sender|PKIStatus" "$WORK/cmp-kur.log" | tail -6 | sed 's/^/        /'
        fi

        # The initial request again with a DNS SAN added. The server words every refusal as a
        # system failure on the wire and keeps the reason for the audit log (CMP tab).
        if [ -n "$ENFORCEMENT" ]; then
            note ""
            note "Request profile probe (refused under the seeded 'Enterprise User (CMP)' profile, which allows email SANs only):"
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/cmp3.key" >/dev/null 2>&1
            if openssl cmp -cmd ir \
                -server "$BASE/cmp/$CA_LABEL" \
                -ref "$CMP_REF" -secret "pass:$CMP_SECRET" "${TRUSTED_ARGS[@]}" -unprotected_errors \
                -subject "${SUBJ_PREFIX}CN=cmp-probe.example.test" -sans "cmp-probe.example.test" \
                -newkey "$WORK/cmp3.key" -certout "$WORK/cmp3.crt" \
                ${INSECURE:+-tls_used -no_check_time} \
                >"$WORK/cmp-sans.log" 2>&1; then
                fail "CMP, a DNS SAN — issued. Either the request profile CMP uses on this CA allows it, or the profile was not applied"
                openssl x509 -in "$WORK/cmp3.crt" -noout -subject -ext subjectAltName 2>/dev/null | sed 's/^/        /'
            elif grep -qi "rejection" "$WORK/cmp-sans.log"; then
                pass "CMP, a DNS SAN — refused; the CMP tab of the audit log names the rule"
            else
                fail "CMP, a DNS SAN — failed, but not with a rejection from the server"
                tail -8 "$WORK/cmp-sans.log" | sed 's/^/        /'
            fi
        fi
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
