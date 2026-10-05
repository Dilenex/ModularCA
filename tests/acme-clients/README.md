# ACME client matrix

Real ACME clients taking a certificate from a fresh ModularCA.

`run.sh` installs ModularCA unattended in a container, from `bootstrap.yaml`, next to a
PostgreSQL. Each client then runs in a container of its own and asks for a certificate for its
own name over http-01. A client passes when the certificate it ends up with chains to the
instance's root and names the host.

| Client | How it is run | What is checked |
|---|---|---|
| certbot | `certonly --standalone` | The certificate file it wrote |
| acme.sh | `--issue --standalone` | The certificate file it wrote |
| Caddy | A site in a Caddyfile, with `acme_ca` and `acme_ca_root` | The certificate it serves |
| Traefik | A certificate resolver with `httpChallenge` | The certificate it serves |

The images are the clients' current releases (`latest`, `caddy:2`, `traefik:v3`), so a run also
says whether today's client still works. Pin one with `CERTBOT_IMAGE`, `ACMESH_IMAGE`,
`CADDY_IMAGE` or `TRAEFIK_IMAGE`.

## Run it

It needs Docker with the compose plugin, `openssl`, and a ModularCA image:

```sh
bash scripts/build-linux-dist.sh
docker build -f deploy/container/Containerfile \
  --build-arg DIST="$(ls dist/modularca-*-linux-x64.tar.gz)" -t modularca:ci .

MODULARCA_IMAGE=modularca:ci tests/acme-clients/run.sh            # every client
MODULARCA_IMAGE=modularca:ci tests/acme-clients/run.sh caddy      # one client
KEEP=1 MODULARCA_IMAGE=modularca:ci tests/acme-clients/run.sh     # leave it up afterwards
```

In CI it is the "ACME clients" workflow, `.github/workflows/acme-clients.yml`.

## How the names work

Every name ends in `.acme.test` and exists only as an alias on the compose network:
`ca.acme.test` is ModularCA, `certbot.acme.test` is the certbot container, and so on. ModularCA
resolves a client's name through Docker's DNS and fetches the challenge from a private address.
A CA refuses that by default, so `bootstrap.yaml` sets `Acme.AllowPrivateAddressValidation`.

The clients trust the instance's root, which `run.sh` downloads from
`http://ca.acme.test:8080/ca/ci-root` before any client starts.

## What it does not cover

- **cert-manager.** It needs a Kubernetes cluster, an ingress controller to answer http-01, and
  a route between the cluster and ModularCA. Not written yet.
- **Proxmox VE.** Its ACME client is part of the hypervisor and does not run in a container. It
  is checked by hand against a real host.
- **dns-01**, wildcard names, external account binding, renewal and revocation. Every client
  here makes one http-01 request for one name with a new account.
