# ModularCA — Linux x64 distribution

Self-contained `linux-x64` build. No .NET runtime is required on the target.

    sudo ./install.sh

## What is in here

| Path | |
|---|---|
| `ModularCA.API` | The service. Native ELF apphost; the systemd unit runs it directly. |
| `ModularCA.Keystore.Unlocker` | Break-glass keystore CLI. Separate binary on purpose — it exists for when the service will not start, so it must not depend on the service's hosting or configuration. |
| `wwwroot/` | The five built SPAs: admin, user, public, setup, docs. |
| `config/*.example` | Templates. `install.sh` copies them in only on a first install and never over a real config. |
| `deploy/` | systemd units, per-role unit drop-ins (`dropins/`), plus nginx and nftables templates. |

## Permissions are set by the installer, not the archive

This archive is **built on Windows**, so it carries no Unix permission bits and no executable
flags. `install.sh` sets them explicitly:

- `ModularCA.API` and `ModularCA.Keystore.Unlocker` → `0755`
- `config/` and `keystores/` → `0700`, files `0600` — they hold database credentials, the
  secondary keystore passphrase, and the CA private keys
- everything owned by the `modularca` service account

Extracting the tarball and running the binary directly, without the installer, gives you a
non-executable apphost and world-readable secrets. Use the installer.

## First install

1. Create the MySQL/MariaDB database and a root credential for setup.
2. Fill in `/opt/modularca/config/setup-database.yaml` from the `.example`.
3. `sudo systemctl enable --now modularca`
4. Complete the setup wizard. It is reachable only while the install is unconfigured and closes
   itself when finished.

The wizard prints a one-time setup token to the service log:

    journalctl -u modularca | grep -i "setup token"

## Upgrading

Re-run `install.sh`. It stops the service, replaces binaries and `wwwroot`, leaves `config/` and
`keystores/` alone, and restarts. Database migrations are applied automatically on start.

Take a backup first — the CA private keys are the part you cannot recreate.

## Firewall and ports

The installer does not touch your firewall. Nothing in the package opens a port, so a fresh
install on a host with a default-deny firewall starts cleanly, listens correctly, and is
unreachable — with no error anywhere, because the packets never reach the socket.

Permit whichever ports you configured:

    sudo ufw allow 80/tcp && sudo ufw allow 443/tcp      # if you set Http.Port 80 / Https.Port 443
    sudo ufw allow 8080/tcp && sudo ufw allow 8443/tcp   # if you kept the defaults

**Do not also apply `deploy/nftables-modularca.conf` unless you kept the unprivileged
defaults.** That file redirects 80 to 8080 and 443 to 8443, for deployments where the ports must
stay unprivileged. Applied while ModularCA listens on 80/443 directly it rewrites every inbound
connection to a port nothing is listening on, and the symptoms are misleading: the service is
active, `ss` shows it bound, the firewall shows the ports allowed, and the application logs
nothing at all. Read the header of that file before installing it.

If the service is running and you cannot reach it, this settles it in one command — run it on the
server while a client tries to connect:

    sudo tcpdump -ni any tcp port 443 -c 20

Nothing at all means the packets are not reaching the machine, so look outside it (hypervisor
firewall, routing, VLAN). A SYN arriving with no SYN-ACK in reply means they reach the machine and
something on it is dropping them — a firewall rule, or the redirect above. A completed handshake
followed by silence means the network is fine and the problem is TLS.

## Things worth knowing before the first production start

**`config/OIDSeed.yaml` is not shipped.** When it is absent the OID catalog falls back to
built-in camelCase defaults. That is a supported configuration and the usage resolution handles
every spelling, but if you have a curated OID catalog, place it at `/opt/modularca/config/OIDSeed.yaml`
*before* running the wizard — the seeded certificate profiles are built from it.

**Audit history survives a reinstall.** The audit database is preserved by default; wiping it is
opt-in (`--wipe-audit` on a CLI bootstrap, or the "Erase existing audit history" checkbox in the
wizard). If you are rehearsing installs on one host, expect audit rows to carry across.

**The initial administrator password must be changed on first login.** When the password was
generated rather than chosen, it is printed once to the service log and the account is flagged
`PasswordChangeOnNextLogon`; the first login returns 403 and directs you through a change.

**Privileged ports** are granted by `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit. Do
not also `setcap` the binary — the unit already covers it, and a stale file capability survives
upgrades in ways the unit does not.

## Two units: the signer apart from the node

By default one process holds everything, keys included. The hardened shape runs the keys in a
second unit, `modularca-signer.service`, under its own user: it holds `keystores/`, the keystore
passwords and any PKCS#11 session, and answers the node over gRPC with mutual TLS on loopback.
The node (`modularca.service` with `--role node`) then holds no key and no keystore password;
each side pins the other's public key, and there is no trust-store lookup.

Do this after the first install has completed its wizard as a single process, so the keystores
and `config/keystore.yaml` exist.

1. Create the signer's user and give it the keys. The node keeps everything else.

       sudo useradd --system --home /opt/modularca --shell /usr/sbin/nologin modularca-signer
       sudo systemctl stop modularca
       sudo chown -R modularca-signer:modularca-signer /opt/modularca/keystores
       sudo chown modularca-signer:modularca-signer /opt/modularca/config/keystore.yaml
       sudo chmod 0700 /opt/modularca/keystores
       sudo chmod 0640 /opt/modularca/config/config.yaml /opt/modularca/config/db.yaml
       sudo chgrp modularca-signer /opt/modularca/config /opt/modularca/config/config.yaml /opt/modularca/config/db.yaml
       sudo chmod 0750 /opt/modularca/config

   Both units read `config/config.yaml` and `config/db.yaml`; only the signer reads
   `keystore.yaml`. The node no longer needs `keystore.yaml` or `keystores/` at all, and on two
   hosts they are simply not copied to the node.

2. On the signer, create the identity CA and the signer's server certificate, then issue the
   node its client certificate:

       cd /opt/modularca
       sudo -u modularca-signer ./ModularCA.API --role signer --init-identity
       sudo -u modularca-signer ./ModularCA.API --role signer --issue-node-identity /tmp/node-identity

   The first writes `config/signer-identity-ca.pfx` and `config/signer-server.pfx`
   (owner-only). The second writes `/tmp/node-identity/signer-client.pfx` and
   `signer-pin.txt` and prints two things: the `PinnedClientSpki` for the signer, and the
   `Signer:` section for the node.

3. Configure both sides in `config/config.yaml`. The signer side:

       Signer:
         Listen: "127.0.0.1:8446"
         ServerCertificate: "config/signer-server.pfx"
         PinnedClientSpki: "<printed by --issue-node-identity>"

   The node side, after moving `/tmp/node-identity/signer-client.pfx` to
   `/opt/modularca/config/` (owned by `modularca`, mode 0600):

       Signer:
         Mode: "Remote"
         Endpoint: "https://127.0.0.1:8446"
         ClientCertificate: "config/signer-client.pfx"
         PinnedServerSpki: "<the contents of signer-pin.txt>"

   On one host both sections live in the same file; each process reads the keys for its role.

4. Point the node's unit at the node role and start the signer first, then the node:

       sudo mkdir -p /etc/systemd/system/modularca.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role node\n' \
           | sudo tee /etc/systemd/system/modularca.service.d/role.conf
       sudo cp /opt/modularca/deploy/modularca-signer.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now modularca-signer
       sudo systemctl start modularca

   `journalctl -u modularca-signer` shows the listener and the pins it holds; `/health/ready`
   on the node shows the signer as a step. While the signer is down the node answers 503 on
   every enrollment endpoint with "The signer is unreachable" and reconnects on its own.

Backups taken by the node's scheduled job go through the signer and keep working. The
command-line `--backup` and `--restore` read the keystore files directly, so on a split
install run them on the signer host as the signer's user. The node's client certificate lives
one year; reissue it with `--issue-node-identity` and replace the file and the pin.

## Three processes: signer, control, enrollment and validation

The node itself splits into roles, and a process runs any subset: `--role control`,
`--role enrollment,validation`, `--role node` (the three together, the two-unit shape above).
Each role hosts only its own controllers, so an inactive role's paths do not exist on that
process (404, no sign-in prompt), and only its own background work:

| Role | Serves | Runs |
|---|---|---|
| `control` | the console and setup wizard, the admin, auth, user and account API, `/health` | every scheduled job that mutates (CRL publishing, LDAP, renewals, backups, audit retention, TLS renewal) and every startup write (migrations, repairs, policy sync) |
| `enrollment` | ACME, EST, SCEP, CMP, MSAE, token and integration enrollment, the TSA, `/health` | the protocol cleanup jobs, under their own scheduler lease |
| `validation` | CRL, OCSP, AIA and CA certificates on HTTPS and on the plain-HTTP port, `/health` | nothing scheduled; OCSP is signed through the signer |

The layout this is for is three processes: the signer, the control plane, and one process
running enrollment and validation. Why one would do it: the enrollment process parses five
protocols, CMS and Kerberos from the network, and is the one most likely to be reached by an
attacker; on its own it holds no console, no admin API and no key, and a compromise there
cannot reach the ceremonies, the backups or the user database except through the database
permissions it has. The control plane can then sit on the admin network only, be restarted
for maintenance without interrupting issuance or OCSP, and be the one place migrations and
scheduled writes happen. Validation can be scaled on its own for CRL and OCSP load, since it
needs only the database and the signer.

Every node process reads the same `config.yaml` shape, so each host gets its own install with
the same database, the same `JWT.Secret` (a token the console issued must verify on every
host's `/health/ready`), and a `Signer:` section pointing at the signer. Two
node processes cannot share one install directory on one host: they would bind the same
ports. The signer's `Signer.Listen` must then be reachable from the enrollment and validation
hosts (not loopback), and each of them needs its own client certificate from
`--issue-node-identity`; the pinning works the same.

1. Complete the first install as a single process and split the signer out as above.

2. On each node host, select the role with a unit drop-in. The examples are in
   `/opt/modularca/deploy/dropins/`; `--role` on the command line wins over `Roles:` in
   `config.yaml`, so the config file can be shared across hosts unchanged.

       # control host
       sudo mkdir -p /etc/systemd/system/modularca.service.d
       sudo cp /opt/modularca/deploy/dropins/role-control.conf /etc/systemd/system/modularca.service.d/role.conf

       # enrollment + validation host
       sudo mkdir -p /etc/systemd/system/modularca.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role enrollment,validation\n' \
           | sudo tee /etc/systemd/system/modularca.service.d/role.conf

       sudo systemctl daemon-reload && sudo systemctl restart modularca

   `role-enrollment.conf` and `role-validation.conf` are there for a host that runs one of
   the two alone.

3. Route by path in front of them until the ingress role exists: `/admin`, `/user`, `/login`,
   `/setup`, `/docs`, `/public`, `/api/v1/admin`, `/api/v1/auth`, `/api/v1/user`,
   `/api/v1/account`, `/api/v1/me`, `/api/v1/setup`, `/api/v1/version`,
   `/api/v1/public/info`, `/api/v1/public/csp-report` to the control host;
   `/acme`, `/.well-known/est`, `/scep`, `/cmp`, `/msae`, `/tsa`, `/api/v1/acme`,
   `/api/v1/scep`, `/api/v1/cmp`, `/api/v1/msae`, `/api/v1/public/enroll`,
   `/api/v1/public/templates`, `/api/v1/public/tsa`, `/api/v1/integration` to the enrollment
   host; `/ca`, `/crl`, `/ocsp`, `/ssh`, `/api/v1/public/ca`, `/api/v1/public/crl`,
   `/api/v1/public/ocsp`, `/api/v1/public/ssh` to the validation host. The CDP and AIA URLs
   already in issued certificates point at the public domain, so the validation host is the
   one that must answer there on plain HTTP.

`/health` on any process lists the roles it runs; `/health/ready` reports, per role, what it
needs and whether it has it: validation the signer reachable, enrollment the signer unlocked,
control the database. A process without the control role refuses to start an unconfigured
install, because the wizard is the control plane's.

## Break-glass

    cd /opt/modularca
    sudo -u modularca ./ModularCA.Keystore.Unlocker \
        --keystore keystores/ca-certs.keystore --print

It verifies the keystore's file signature and each entry's signature against the pinned signing
CA, then prints the entries as PEM. `--insecure-no-verify` skips the database-backed checks for
the case where the database is what you have lost; it is also required before the tool will
write decrypted keys to disk.
