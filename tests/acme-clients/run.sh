#!/usr/bin/env bash
#
# Runs the ACME client matrix: installs ModularCA unattended in a container, then has each ACME
# client ask it for a certificate over http-01, and checks every certificate against the root.
#
#   MODULARCA_IMAGE=modularca:ci tests/acme-clients/run.sh              # every client
#   MODULARCA_IMAGE=modularca:ci tests/acme-clients/run.sh certbot      # only the ones named
#
# Needs docker with the compose plugin, and openssl. KEEP=1 leaves the containers and volumes up
# afterwards for a look around; "docker compose -p acme-clients down -v" removes them.
#
# A client that fails does not stop the others. The exit code is 0 only when every client that
# was asked for got a certificate that verifies.
set -euo pipefail

cd "$(dirname "$0")"

ALL_CLIENTS=(certbot acmesh caddy traefik)
clients=("$@")
[[ ${#clients[@]} -gt 0 ]] || clients=("${ALL_CLIENTS[@]}")
for client in "${clients[@]}"; do
    case " ${ALL_CLIENTS[*]} " in
        *" $client "*) ;;
        *) echo "unknown client: $client (expected one of: ${ALL_CLIENTS[*]})" >&2; exit 2 ;;
    esac
done

: "${MODULARCA_IMAGE:?set MODULARCA_IMAGE to the image under test}"
export MODULARCA_IMAGE

DIRECTORY=https://ca.acme.test:8443/acme/ci-root/directory

work="$(mktemp -d)"
export SEED_DIR="$work/seed"
mkdir -p "$SEED_DIR"

# The database lives only as long as this run, so its superuser password is made here and
# written nowhere but the two places that need it.
POSTGRES_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
export POSTGRES_PASSWORD
cp bootstrap.yaml "$SEED_DIR/bootstrap.yaml"
cat > "$SEED_DIR/setup-database.yaml" <<EOF
SqlRoot:
  Host: db
  Port: 5432
  Username: postgres
  Password: "$POSTGRES_PASSWORD"

SqlApp:
  Database: modularca-app
  Username: modularca_app

SqlAudit:
  Database: modularca-audit
  Username: modularca_audit
EOF
# The seed container reads these as root; the directory mktemp made is private to this user.
chmod 0755 "$work" "$SEED_DIR"
chmod 0644 "$SEED_DIR"/*.yaml

compose() { docker compose --profile clients "$@"; }
tools() { compose exec -T tools "$@"; }

cleanup() {
    if [[ "${KEEP:-}" == 1 ]]; then
        echo "KEEP=1: leaving the project up. Remove it with: docker compose -p acme-clients --profile clients down -v"
    else
        compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# wait_for <seconds> <what> <command...>: retries the command every 3 seconds.
wait_for() {
    local deadline=$((SECONDS + $1)) what="$2"
    shift 2
    until "$@" >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "timed out waiting for $what" >&2
            return 1
        fi
        sleep 3
    done
}

# check_certificate <name> <pem file>: the leaf chains to the root and names the host.
check_certificate() {
    local name="$1" pem="$2"
    [[ -s "$pem" ]] || { echo "  no certificate was written" >&2; return 1; }
    openssl verify -CAfile "$work/root.pem" "$pem" >/dev/null || { echo "  the certificate does not chain to the root" >&2; return 1; }
    openssl x509 -in "$pem" -noout -ext subjectAltName | grep -q "DNS:$name" || { echo "  the certificate does not name $name" >&2; return 1; }
}

# served_certificate <name>: a TLS request to the name verifies against the root alone.
served_certificate() {
    tools curl -sS -o /dev/null --cacert /trust/root.pem "https://$1/"
}

run_certbot() {
    compose run --rm --no-deps --use-aliases certbot || return 1
    tools cat /certs/certbot/live/certbot.acme.test/cert.pem > "$work/certbot.pem" || return 1
    check_certificate certbot.acme.test "$work/certbot.pem"
}

run_acmesh() {
    compose run --rm --no-deps --use-aliases acmesh || return 1
    # acme.sh names the directory after the key type: <domain>_ecc for its default EC key.
    tools sh -c 'cat /certs/acmesh/acmesh.acme.test*/acmesh.acme.test.cer' > "$work/acmesh.pem" || return 1
    check_certificate acmesh.acme.test "$work/acmesh.pem"
}

run_caddy() {
    compose up -d --no-deps caddy || return 1
    wait_for 180 "Caddy to serve a certificate from ModularCA" served_certificate caddy.acme.test
}

run_traefik() {
    compose up -d --no-deps traefik || return 1
    wait_for 180 "Traefik to serve a certificate from ModularCA" served_certificate traefik.acme.test
}

echo "== Installing ModularCA unattended ($MODULARCA_IMAGE)"
compose up -d db modularca tools

# Bootstrap runs first and serves nothing; the root is downloadable once the node is up.
fetch_root() {
    tools curl -fsS -H 'Accept: application/x-pem-file' -o /trust/root.pem http://ca.acme.test:8080/ca/ci-root
}
if ! wait_for 300 "ModularCA to serve its root certificate" fetch_root; then
    compose logs --no-color --tail 200 seed modularca
    exit 1
fi
tools cat /trust/root.pem > "$work/root.pem"
openssl x509 -in "$work/root.pem" -noout -subject -fingerprint -sha256

# The node starts on a temporary certificate and replaces it with one from its own root a moment
# later. Clients verify the ACME server, so wait until the directory verifies against that root.
if ! wait_for 180 "the ACME directory to verify against the root" tools curl -fsS --cacert /trust/root.pem "$DIRECTORY"; then
    compose logs --no-color --tail 200 modularca
    exit 1
fi
echo "== ACME directory: $DIRECTORY"

declare -A result
failed=0
for client in "${clients[@]}"; do
    echo
    echo "== $client"
    if "run_$client"; then
        result[$client]=pass
        echo "== $client: certificate issued and verified"
    else
        result[$client]=FAIL
        failed=1
        echo "== $client: FAILED" >&2
        case "$client" in caddy|traefik) compose logs --no-color --tail 120 "$client" || true ;; esac
    fi
done

echo
echo "== Result"
for client in "${clients[@]}"; do
    printf '  %-10s %s\n' "$client" "${result[$client]}"
done

if (( failed )); then
    echo
    echo "== ModularCA log (last 300 lines)"
    compose logs --no-color --tail 300 modularca || true
fi
exit "$failed"
