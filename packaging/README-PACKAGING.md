# Packaging ModularCA for Ubuntu

Target: **Ubuntu 24.04 (noble)**, distributed as a **bare `.deb`** — no apt repository, no PPA.

```
./scripts/build-deb.sh                 # publish, then package
./scripts/build-deb.sh --from-tarball  # repackage an existing dist/*.tar.gz
```

The tarball it packages comes from `./scripts/build-linux-dist.sh`, which can be run on its own.

## Release and Staging

```
./scripts/build-linux-dist.sh                          # dist/modularca-<VERSION>-linux-x64.tar.gz
./scripts/build-linux-dist.sh --configuration Staging  # ...-linux-x64-staging.tar.gz
```

Staging is Release **plus JavaScript sourcemaps** — roughly 90 `.map` files and about 2 MB. It is
the configuration to deploy to a box you expect to debug on: a minified stack like
`te.map is not a function` at `index-DbKwh5kT.js:14` costs most of a day to trace on a deployed
host, and a filename with a line number costs minutes. The IL is identical, because
`Directory.Build.props` sets `Optimize=true` for Staging — without it the SDK would fall through to
its Debug-side defaults for any configuration it does not recognise by name, and the artifact would
quietly carry unoptimized code while looking like a release build.

The two archives are named differently on purpose. Knowing which one is on a host is the entire
point of shipping maps to it, and two files that differ in what they contain must not be
indistinguishable on disk. `build-deb.sh` always builds Release; the `.deb` is a release artifact
and there is no staging variant of it.

Anything other than `Release` or `Staging` is rejected. `Debug` in particular skips the
`BuildWebUIs` target entirely, so it would publish a full self-contained payload and only then fail
the `wwwroot` check at the end.

Requires [nfpm](https://nfpm.goreleaser.com/install/), a single static binary. No Debian
toolchain is needed, which is what lets this run from Windows git-bash as well as from Linux.

```
sudo apt install ./dist/modularca_0.1.0~rc3-1_amd64.deb
```

---

## Layout, and why it is not FHS

Everything lives under `/opt/modularca`, with `/etc/modularca` and `/var/log/modularca` as
symlinks into it.

That is a consequence of the application, not a packaging preference. Config, keystores, logs and
backups all resolve from `AppContext.BaseDirectory` — **84 call sites**, with no override — and the
systemd unit's `ProtectSystem=strict` plus `ReadWritePaths=/opt/modularca` is built around that.
A genuine `/etc` + `/var/lib` + `/usr/lib` split needs the application to learn a base-path
override first; it is not something the package can impose from outside.

Debian Policy §9.1.1 explicitly permits `/opt/<package>` for software that is not part of the
distribution, so this is a legal layout rather than a workaround. It would need revisiting before
any attempt at a PPA or archive inclusion.

## Configuration is deliberately not a dpkg conffile

The package ships only the `*.yaml.example` files. `postinst` copies each to its real name **only
where no file exists**, and never overwrites.

Conffiles were rejected on purpose. `config.yaml` and `db.yaml` hold the database password and the
JWT signing secret, and dpkg keeps hashes and backup copies of every conffile in its own
bookkeeping under `/var/lib/dpkg`. Worse, the upgrade prompt — *keep the local version or take the
maintainer's?* — offers, in one keystroke, to replace a working CA's identity with defaults. The
seed-if-absent behaviour gives the useful half of conffiles with none of that.

The consequence: the real config is not a package file at all. dpkg does not track it, diff it,
prompt about it, or remove it.

## systemd

The unit ships to `/lib/systemd/system/modularca.service`. `/etc/systemd/system` belongs to the
administrator; local changes go in `/etc/systemd/system/modularca.service.d/*.conf` drop-ins.

**Upgrading from a tarball install:** `packaging/install.sh` writes the unit to
`/etc/systemd/system/modularca.service`, which takes precedence over the packaged one and does so
silently — the old unit keeps running and every change to the new one appears to do nothing.
`postinst` detects this and prints instructions rather than leaving it as a puzzle.

On **first install** the service is enabled but **not started**: there is no database, keystore or
configuration yet, so starting would fail-loop and `StartLimitBurst` would then block the
operator's own first start. On **upgrade** it restarts only if it was already enabled.

## Migrations happen in the service, not the package

The application calls `Database.MigrateAsync()` at startup. `postinst` deliberately does not run
migrations.

The consequence is worth knowing: `apt upgrade` reports success, then the schema changes when the
service restarts. A migration failure appears in `journalctl -u modularca`, not in apt's output.
`preinst` warns about this on upgrade and tells you to back up first.

## Uninstall: purge does not delete the CA

This is the one place the package deviates from what dpkg conventionally means.

| Command | Effect |
|---|---|
| `apt remove modularca` | stops the service, removes binaries; **all data kept** |
| `apt purge modularca` | also removes the seeded `.example` files and empty directories; **keys, config and database still kept** |

`purge` normally means "remove configuration too", and for most software that is right. For a
certificate authority it is not. The keystores hold the CA private keys: without them every
certificate this CA has issued becomes unverifiable and unrevocable — no CRL can be signed, no OCSP
response produced, and no replacement CA can adopt the existing chain. The database holds the
issuance record, revocation state and audit trail. None of it survives a mistake, and `apt purge`
looks routine enough to be made by mistake.

So purge removes what the package created and can recreate, names precisely what it is leaving
behind, and prints the commands to remove it deliberately. The `postgresql` packages take the same
position on `/var/lib/postgresql`.

For lab and CI teardown there is an opt-in:

```
sudo touch /opt/modularca/config/purge-keys    # next purge removes everything
```

A sentinel file, not a debconf prompt — a prompt gets answered by reflex, and an unattended
`apt purge` answers it with no human present at all.

The service account is removed on purge **only if nothing it owns remains**. Deleting it while
files survive would orphan them to a bare uid that the system may later reassign to a different
service, quietly granting that service access to whatever was left behind.

## Dependencies

Derived by parsing `DT_NEEDED` from every shipped ELF, then confirming the two libraries .NET
loads with `dlopen` (and which therefore never appear as linked dependencies) from the soname
strings embedded in the runtime:

| Kind | Libraries | Package |
|---|---|---|
| Linked | `libc`, `libdl`, `libm`, `libpthread`, `librt` | `libc6` |
| Linked | `libgcc_s.so.1` | `libgcc-s1` |
| Linked | `libstdc++.so.6` | `libstdc++6` |
| dlopen | `libssl.so.3`, `libcrypto.so.3` | `libssl3t64` (noble; `libssl3` pre-t64) |
| dlopen | `libicuuc`, `libicui18n` | `libicu74` (noble) |
| Bundled | `libsodium`, zlib | — none |

`liblttng-ust` is **not** declared. It is referenced only by `libcoreclrtraceptprovider.so`, which
the runtime dlopens for optional tracing and does without silently.

`ca-certificates` is a functional dependency rather than a linked one: without it, outbound TLS for
ACME, LDAPS and OCSP fetching fails in ways that are hard to diagnose.

Alternatives are listed for the t64-renamed and older ICU packages so the same `.deb` also
installs on 22.04.

## Version ordering

`VERSION` reads `0.1.0-rc3`. dpkg compares `0.1.0-rc3` as **greater** than `0.1.0`, so shipping it
unchanged would make the eventual release look like a downgrade and apt would decline to install
over the candidate. `build-deb.sh` rewrites it to `0.1.0~rc3`; a tilde sorts before everything,
including the empty string, which is exactly what a pre-release means.

## The tarball is still the other path

`scripts/build-linux-dist.sh` and `packaging/install.sh` remain, for non-Ubuntu hosts and for
operators who would rather not involve a package manager. `build-deb.sh` unpacks that same tarball
rather than publishing a second time, so the two cannot drift.
