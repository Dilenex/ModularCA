# SSH KRL delivery

Status: built 2026-10-08, for 0.4.2: the time of each revocation, a KRL that does not change
between revocations, a conditional fetch on both KRL routes, and a fetcher for SSH servers with
its systemd units. The fetcher's script was run for real under `sh` and `dash` with `curl` and
`ssh-keygen` against a stand-in server. The systemd units were not started, and no `sshd` was
pointed at a fetched list: that is for the live proof on ca4. The login-time status check is the
second half, and is not built.

It belongs with `ssh-keystore.md` (who builds the KRL) and `ssh-login-names.md` (what revokes).

## Why

The CA revokes a user certificate within seconds of the change that calls for it. A host learns of
a revocation only when it next fetches the SSH CA key's KRL, and before this the product shipped
nothing that fetched it. The docs said to "fetch it over HTTPS on a timer". Three things stood in
the way of doing that often:

- every fetch returned different bytes, because the list was stamped with the time of the fetch;
- there was no ETag, so every poll built and sent the whole list;
- `sshd` refuses every public-key login when its `RevokedKeys` file cannot be read, so a careless
  fetcher that leaves a truncated or missing file locks everyone out of the host.

## When a certificate was revoked

`SshCertificates.RevokedAt` (UTC, nullable), added by migration
`20261009020550_SshCertificateRevokedAt`.

- **One place marks a certificate revoked.** `SshCertificateEntity.Revoke(at)` sets `IsRevoked` and
  `RevokedAt` together. Both setters are private, so no code can set the flag without the time:
  a fourth revocation path cannot forget it, because it does not compile.
- **The three callers.** `SshCaService.RevokeCertificateAsync` (an administrator),
  `SshCaService.DisableAsync` (every live certificate of the key, at one time), and
  `SshLoginNameService.RevokeAsync`, which every hook of the login name rule and the periodic
  sweep go through (one time per batch).
- **A revocation is not undone and its time does not move.** `Revoke` on a revoked certificate
  changes nothing. Asking to revoke the same certificate again keeps the first time.
- **Rows from before.** The migration adds the column empty. A certificate that was already
  revoked stays revoked with no time: none was recorded, and none is invented.
- **Read.** The certificate views of the admin API carry `revokedAt`, and a certificate's page in
  the console shows it.

The migration also adds a partial index, `IX_SshCertificates_SshCaKeyId_RevokedAt` on
(`SshCaKeyId`, `RevokedAt`) where `IsRevoked`. The state of a key's KRL is a count and a maximum
over the revoked rows of that key, read on every poll by every host; the index keeps that
independent of how many certificates the key has issued.

## A list that is the same bytes until something is revoked

`SshCaService.BuildKrlAsync` builds the list; `GenerateKrlAsync` returns its bytes.

| Field | Value |
|---|---|
| `krl_version` | the number of revoked certificates of the key, as before (`KrlVersionOf`) |
| generation time | the newest `RevokedAt` of the key, in whole seconds (`KrlGeneratedAt`) |
| serials | every revoked serial of the key, expired ones included |

- **The version stays the count.** It cannot go down in operation: nothing un-revokes a
  certificate (`Revoke` is one-way), and no code deletes a certificate row. The only deletions of
  `SshCaKeys` rows are of a creation that failed before anything was issued. Two things outside
  operation lower it: restoring an older database, and a reset.
- **The generation time is never the time of the fetch.** With no revocation time known, which is
  nothing revoked, or only certificates revoked before the column, it is when the SSH CA key was
  created. That never changes, so the empty list is stable too. OpenSSH only displays this field.
- **Expired entries are not pruned.** The list grows with every revocation.

So two fetches with no revocation between them return the same bytes, and a revocation changes
them: the version goes up by one.

## Conditional fetch

Both routes (`GET /ssh/ca-keys/{id}/krl`, anonymous, and
`GET /api/v1/admin/ssh/ca-keys/{id}/krl`) answer through `SshKrlHttp.ServeAsync`.

- **ETag.** Strong, 32 hex digits in quotes: the first 16 bytes of the SHA-256 of the list's
  header (as `SshKrl.Encode` writes it for that version and generation time) and the CA public key
  blob (`SshCaService.KrlETagOf`). It needs no serial, so it is computed without building the list.
  It changes exactly when the list does, because every revocation raises the version.
- **The state.** `ISshCaService.GetKrlStateAsync` reads one row for a key: its public key, when it
  was created, the number of its revoked certificates and the newest `RevokedAt`
  (`SshKrlState`: version, revoked count, generation time, last revocation, ETag).
  `GetKrlStatesAsync` does the same for the keys of the admin list in one query.
- **A request with `If-None-Match`.** The state is read first. A match is `304` with the ETag and
  no body, and the list is not built. The comparison is the weak one RFC 9110 gives
  `If-None-Match`, so `W/"..."` (a proxy that compresses may weaken a tag) and `*` match.
- **A request without, or with a stale tag.** The list is built and sent with the ETag computed
  from the rows that list was built from. This is the direction that matters: an ETag newer than
  the bytes beside it would make a host skip the list it lacks, for ever. A revocation that lands
  between the two reads can only cost one extra download.
- **`Cache-Control: no-cache`** on both answers. On the admin route `SecurityHeadersMiddleware`
  replaces it with `no-store, no-cache, must-revalidate`, as it does for every `/api/v1/admin/`
  path; the ETag and the 304 are unaffected.
- **The answers for nothing served** (`SshCaService.ServeKrlWithNoEntries` turned off: 204 on the
  public route, a JSON message on the admin one) carry no ETag and are never 304.

### Rate limiting

The public route has none. `ProtocolRateLimitMiddleware` buckets by path prefix (`/crl/`,
`/ocsp`, `/ca/`, `/est/`, ...), and neither `/ssh` nor `/api/v1/public/ssh` is in its table;
`LoginRateLimitMiddleware` covers sign-in paths only. A host that polls once a minute is therefore
within every limit there is. `/ssh` is not on the plain-HTTP allow-list
(`HttpSchemeEnforcementMiddleware`), so a plain HTTP request is redirected to HTTPS, and the
fetcher refuses a URL that is not `https`.

Whether the route should get a bucket is open (see below). If it does, the buckets are per client
address: a fleet behind one NAT address polling once a minute needs one request per host per
minute from that address, so a limit of 60 a minute, the default of the other public buckets,
would fail the sixty-first host.

## The fetcher

Source: `deploy/ssh-krl/`. It runs on each SSH server, never on the CA.

| File | On the CA host | On an SSH server |
|---|---|---|
| `modularca-krl-fetch.sh` | `/usr/share/modularca/ssh-krl/` | `/usr/local/sbin/modularca-krl-fetch`, `0755` |
| `modularca-krl-fetch.service` | same | `/etc/systemd/system/` |
| `modularca-krl-fetch.timer` | same | `/etc/systemd/system/` |
| `modularca-krl-fetch.env.example` | same | `/etc/default/modularca-krl-fetch` |

- **Packaging.** `build-linux-dist.sh` stages the four files under `share/ssh-krl/` of the tarball
  and refuses one that is missing or has a carriage return. `install.sh` and the `.deb`
  (`nfpm.yaml`) install them root-owned to `/usr/share/modularca/ssh-krl/`, beside the other
  root-owned shared files and outside `/opt/modularca`, because they are copied from there to
  servers and run as root. Nothing is enabled on the CA host.
- **Getting it to a server.** An administrator copies the four files from the CA host, or from
  the tarball, with whatever moves files to servers (`scp`, configuration management). The
  console does not serve them.

### What the script does

POSIX `sh`; it needs `curl`, `ssh-keygen` (OpenSSH 8.0 or later, for `-Q -l`) and coreutils, and
nothing else. Settings come from options or from `MODULARCA_KRL_*` variables, which is how the
unit's `EnvironmentFile=` delivers them: the URL, the destination (default
`/etc/ssh/revoked_keys.krl`), an optional CA bundle, and whether a lower version is allowed.

1. Refuse a URL that is not `https`, a missing destination directory, a destination that is a
   directory, an unreadable CA bundle (exit status 2, nothing fetched).
2. Read `<destination>.etag`: the ETag of the installed list, a checksum of the installed file,
   and the URL. The ETag is sent as `If-None-Match` only while the installed file still has that
   checksum and the URL is the same. A file replaced by hand, or a changed URL, gets a full fetch,
   so a 304 never vouches for a file it was not issued for.
3. Fetch with `curl` into a temporary file in the destination's directory: HTTPS only, no
   redirects followed, no `.curlrc`, a connect timeout (10 s) and a total timeout (60 s), at most
   64 MiB.
4. `304`: success, when an ETag was sent; a failure otherwise.
5. `200`: refuse an empty body; refuse what `ssh-keygen -Q -l -f` does not read as a KRL; read its
   version from that listing; refuse a version lower than the installed file's unless
   `--allow-lower-version` (or `MODULARCA_KRL_ALLOW_LOWER_VERSION=1`) says otherwise. An installed
   file that is itself not a KRL is replaced.
6. Set mode `0644`, flush the file to disk, rename it over the destination, flush the directory.
   The rename is the only command that writes the destination.
7. Only then save the new ETag, checksum and URL, by the same write-then-rename.

Any other status, any `curl` failure and any refusal exits 1 and leaves the installed file and
its ETag file byte for byte as they were; temporary files are removed on every exit.

### The units

- **Service.** `Type=oneshot`, settings from `/etc/default/modularca-krl-fetch`, and
  `ProtectSystem=strict` with `ReadWritePaths=/etc/ssh`: the script can write only beside the
  list. A destination elsewhere needs its directory in a drop-in. A failed run leaves the unit
  failed, which is the signal an operator has.
- **Timer.** `OnCalendar=*:*:00` with `RandomizedDelaySec=30s`, and `OnBootSec=15s`. A calendar
  timer fires again whatever the last run's result was; the delay spreads a fleet over the minute.
  A revoked certificate can therefore still log in to a host for up to about ninety seconds.

### Bootstrap order

Run the fetcher once (`systemctl start modularca-krl-fetch.service`), then name the file in
`sshd_config` (`RevokedKeys /etc/ssh/revoked_keys.krl`), then `sshd -t` and reload `sshd`. Naming
the file before it exists locks every public-key login out of the host. `sshd` reads the file at
each login, so later lists need no reload.

### After a database restore

The version is a count, so a restored database can serve a lower one, and every host then refuses
the list until it is run once with `--allow-lower-version`. What the operator has to know before
allowing it: the restored list does not name the certificates revoked after the backup. One issued
before the backup still has its row and can be revoked again. One issued after it is unknown to
the restored CA and stays valid until it expires. Until the lower version is allowed, a host keeps
the old list and learns of no revocation made since the restore. Neither choice is right for every
case, so the fetcher refuses and the operator decides.

## Console and docs

- **SSH CA key page** (`SshCaKeyDetail.tsx`, helpers in `sshKrl.ts`): a "Revocation list (KRL)"
  section with the URL, the version, the last revocation, and for a user CA "Set up a host": the
  commands with the key's URL filled in, in the bootstrap order. The admin key list carries
  `krlVersion`, `krlRevokedCertificates` and `krlLastRevokedAt` for it.
- **SSH certificate page**: when it was revoked.
- **Docs site**: "Getting the revocation list to hosts" in the Admin UI guide, and the two KRL
  endpoint entries. `packaging/README-DEPLOY.md` has the operator's page.

## Tests

- `SshRevocationTimeTests`: every revocation path records when (an administrator, disabling the
  key, the reconciliation, a disabled user, the sweep), and the setters are private.
- `SshCaServiceTests`: the same bytes and ETag across fetches, a new certificate and a repeated
  revocation; different after each revocation; the generation time with and without a known time.
- `SshEndpointTests`: ETag, `Cache-Control` and 304 on both routes, without building the list.
- `PostgresUpgradeHarnessTests` and `PostgresSshCaTests`: the migration, and the state query and
  the stored time on PostgreSQL.
- `SshKrlFetchScriptTests`: the script under `sh` and `dash` with the real `curl` and
  `ssh-keygen` against an HTTPS stand-in: a good list, a 304, an empty body, garbage, a list and a
  transfer cut short, a lower version, an error status, an unreachable and an untrusted server.
  Each failure leaves the installed file byte-identical. It is skipped where the tools are missing.
- `SshKrlFetchFileTests`: the destination is written by one command; HTTPS only; POSIX `sh` and no
  tool beyond the three; what the tarball and the package carry.

## Not built, and open

- **The login-time status check** and any `AuthorizedPrincipalsCommand` helper: the second half.
- **Pruning expired serials, signing the KRL, default validity periods**: not this work.
- **A rate limit on the public KRL route.** There is none today. A bucket would have to allow for
  fleets behind one address.
- **Serving the fetcher from the CA.** An administrator copies the files by hand today. A download
  route, or a link on the key's page, would save a step and would make the CA a source of a script
  that servers run as root.
- **Several SSH CA keys on one host.** `RevokedKeys` takes one file, and the fetcher installs one
  key's list. A host that trusts two SSH CA keys would need the lists merged.
- **Staleness is not reported to the CA.** A host that cannot fetch keeps its last list. The
  failed unit is the only signal, and it is on the host.
- **Unverified here.** The units were written and not started; no `sshd` read a fetched list; the
  script ran under Git Bash's `sh` and `dash` on Windows, not on Linux.
