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
| `deploy/` | systemd unit, plus nginx and nftables templates. |

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

## Break-glass

    cd /opt/modularca
    sudo -u modularca ./ModularCA.Keystore.Unlocker \
        --keystore keystores/ca-certs.keystore --print

It verifies the keystore's file signature and each entry's signature against the pinned signing
CA, then prints the entries as PEM. `--insecure-no-verify` skips the database-backed checks for
the case where the database is what you have lost; it is also required before the tool will
write decrypted keys to disk.
