# Spike: a tenant node in a container behind SNI

Proves the containerised layout with zero changes to ModularCA: the unchanged 0.2.0 dist runs as
a node in a Podman pod with its own database, nginx on the host routes by the name in the TLS
hello, the node terminates TLS with a certificate from its own root, and the lab forest enrolls
through it exactly as it does against the host install. Everything here is lab tooling; nothing
touches the product.

Names in this spike:

| Name | What answers |
|---|---|
| `ca4.maroongang.net` | the host install (staging), as before |
| `ca.lab.msae.test` | the spike node, in the pod |

Both resolve to the ca4 address; nginx tells them apart.

## 0. What a fresh ca4 needs

- Debian 12 or Ubuntu 24.04. Podman 4.4 or newer for the unit files below (Ubuntu 24.04 ships
  4.9; Debian 12 ships 4.3, which needs the `podman generate systemd` route instead, or Podman
  from backports).
- The 0.2.0 dist installed the normal way (`install.sh`), which brings nginx with the shipped
  stream passthrough on 443 and 80 in front of `127.0.0.1:8443` / `:8080`. The host install
  already sits behind SNI-capable passthrough, so the spike only adds a map.
- The host install's `Https.PublicPort` set to 443 so advertised URLs carry no port.

## 1. Build the node image

On ca4, with the dist tarball and this directory:

The Containerfile is the product's, at `deploy/container/`; the release workflow publishes the
same image as `ghcr.io/dilenex/modularca:<version>`. To build it here from a staging tarball, from
the repository root:

```sh
podman build -f deploy/container/Containerfile --build-arg DIST=dist/modularca-0.3.0-dev-linux-x64-staging.tar.gz -t modularca-node:0.3.0-dev .
```

Or pull the published image and use its tag in `modularca-node.container` instead.

## 2. Configuration volume

The bootstrap reads its inputs from the config volume on first start. Create the volume, put
the three files in it, and set the database root password in both places it appears:

```sh
podman volume create modularca-node-config
V=$(podman volume inspect modularca-node-config --format '{{.Mountpoint}}')
cp config/bootstrap.yaml config/setup-database.yaml "$V/"
# config.yaml: start from the dist's example and apply config/config.yaml.overrides
tar -xzf modularca-0.2.0-linux-x64-staging.tar.gz -O --wildcards '*/config/config.yaml.example' > "$V/config.yaml"
#   then edit "$V/config.yaml" so the Https section matches config/config.yaml.overrides
sed -i 's/change-me-once/<a real password>/' "$V/setup-database.yaml"
sed -i 's/change-me-once/<the same password>/' modularca-node-db.container
```

## 3. Start the pod

```sh
mkdir -p ~/.config/containers/systemd
cp modularca-node.pod modularca-node-db.container modularca-node-signer.container modularca-node.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start modularca-node-pod
journalctl --user -u modularca-node -f
```

The pod runs the image twice: `modularca-node-signer` with `--role signer`, the only container
that mounts the keystores volume, and `modularca-node` with `--role node`, which holds no key and
reaches the signer over the pod's loopback with mutual TLS. The first start still has to be a
single process, because bootstrap writes the keystore locally; see "Split the signer" below for
the order.

The first start runs the headless bootstrap: it creates the schemas from `setup-database.yaml`,
the tenant root from `bootstrap.yaml`, the node's own TLS certificate for `ca.lab.msae.test`,
and prints the initial administrator password once. Copy it from the journal and change it at
first sign-in. Later starts just run.

Rootless pods stop when the user session ends unless lingering is on: `loginctl enable-linger`.

## 3a. Split the signer

Bootstrap runs once as a single process (all roles), because it creates the keystore. Then:

```sh
# 1. Identity: the signer creates its identity CA and server certificate, and issues the node's
#    client certificate, all into the shared config volume. One-off runs against the volumes.
podman run --rm --pod modularca-node   -v modularca-node-config:/opt/modularca/config:Z -v modularca-node-keystores:/opt/modularca/keystores:Z   localhost/modularca-node:0.3.0-dev --role signer --init-identity --host 127.0.0.1
podman run --rm --pod modularca-node   -v modularca-node-config:/opt/modularca/config:Z -v modularca-node-keystores:/opt/modularca/keystores:Z   localhost/modularca-node:0.3.0-dev --role signer --issue-node-identity /opt/modularca/config
# 2. In the config volume's config.yaml, the Signer section, with the two pins the runs printed:
#    Listen: "127.0.0.1:8446"            ServerCertificate: "config/signer-server.pfx"
#    PinnedClientSpki: "<printed>"       Mode: "Remote"   Endpoint: "https://127.0.0.1:8446"
#    ClientCertificate: "config/signer-client.pfx"   PinnedServerSpki: "<signer-pin.txt>"
# 3. Restart the pod: the signer container unlocks the keystore and listens; the node container
#    starts keyless and reports the signer reachable on /health/ready.
systemctl --user restart modularca-node-pod
```

In this lab the two containers share the config volume, so the keystore password file is
readable by the node container too. A production pod gives the signer its own config volume and
the node only its client certificate and pin; the unit files show where each volume goes.

## 4. Route the name

Replace the `stream` block in the host's nginx configuration with `nginx-sni.conf`, then
`nginx -t && systemctl reload nginx`. From this point `https://ca.lab.msae.test/` reaches the
node and `https://ca4.maroongang.net/` still reaches the host install.

## 5. DNS and the forest

On the Samba DC, publish the name as an A record (never a CNAME; see the runbook for why):

```sh
samba-tool dns add localhost lab.msae.test ca A 10.100.105.27 -U Administrator
```

Register the second service principal on the same service account, so its existing key seals
tickets for the new name too:

```sh
samba-tool spn add HTTP/ca.lab.msae.test svc-lab-msae
```

## 6. Bind the forest in the node

Sign in at `https://ca.lab.msae.test/admin/` with the initial password, then as for any CA:
bind `LAB.MSAE.TEST` on the tenant with service principal `HTTP/ca.lab.msae.test`, import the
key (the same password or keytab as the host install; the key is the account's, not the
name's), enable Kerberos on the node's CA, offer a template. The Windows Autoenrollment page
should go green; download the kit.

## 7. Prove it from the client

The client must trust the node's root (in the kit) and resolve `ca.lab.msae.test` through the
DC. Then, as SYSTEM, the kit's `3-client-check.ps1`: a 200 from whoami naming the machine, then
a certificate from `Lab Tenant Root` in the machine store. Every row lands in the node's MSAE
audit tab, not the host install's, which is the isolation half of the proof.

## What this does not exercise

Plain-HTTP revocation (CRL, OCSP, AIA) still routes to the host install, since HTTP carries no
server name in the handshake; a node serving revocation under its own name needs an `http` block
routing by `Host`, which is real design work for 0.3.0. Nothing enrolled during the spike
depends on it.
