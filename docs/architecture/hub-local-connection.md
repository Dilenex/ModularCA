# The hub's local connection, the affiliation token and the instance mode

Written for whoever builds the hub's side. It describes what a ModularCA instance does from
0.4.5: the listener it opens for its hub, the proof it asks for, what the mode stops, and where
the mode is kept. The code is the authority where this note and the code disagree:

- contract, client and listener: `ModularCA.HubConnection/`
- what the node does for each request: `ModularCA.Core/Services/Hub/NodeHubOperations.cs`
- the mode's table and its state file: `ModularCA.Shared/Modes/`
- the filter that enforces the mode on requests: `ModularCA.Auth/Authorization/ModeGateFilter.cs`

An instance with no hub is unchanged. With `MODULARCA__HUB__SOCKET` unset it opens no listener,
creates no socket file, and its mode is full unless an administrator sets another by hand.

## Settings at a glance

| Where | Name | Meaning |
|---|---|---|
| Environment | `MODULARCA__HUB__SOCKET` | Path of the Unix domain socket. Unset: nothing is opened for a hub. At most 100 bytes. |
| Environment | `MODULARCA__HUB__SOCKETMODE` | The socket file's mode, octal, read and write bits only. Default `0660`. |
| Environment | `MODULARCA__HUB__STARTMODE` | `full`, `restricted`, `maintenance` or `dr`: the mode of a node that has a hub socket and no recorded mode. Default `restricted`. Any other value stops the start. |
| bootstrap.yaml | `Hub.AffiliationTokenSha256` | SHA-256 of the affiliation token, 64 hex digits. Optional. |
| Host command | `--new-hub-token` | Prints a token, its hash and the bootstrap.yaml lines. Touches nothing. |
| Host command | `--set-hub-token-hash <hex or none>` | Sets, replaces or removes the hash on an existing instance. Restart the node afterwards. |
| File | `instance-mode.json` | The mode. Beside the socket when a socket is configured, otherwise in `config/`. |
| File | `hub-requests.json` | The request identifiers already carried out. Beside the socket. |

## The listener

- **Who hosts it.** The process that runs the control role. A process without that role, and the
  setup wizard, open nothing.
- **What it is.** A Kestrel host of its own, listening on the Unix socket only, speaking
  HTTP/1.1 without TLS. It shares no listener, route or middleware with the HTTPS, HTTP and
  loopback health listeners. Nothing reachable on those reaches a hub request, and a request on
  the socket reaches nothing but the operations listed below: the console, the API, the
  enrollment protocols and `/health/ready` are not served on it.
- **Start.** The socket's directory is created if missing. A socket file left by a run that did
  not stop cleanly is removed. After the bind the file's mode is set. A socket that cannot be
  bound stops the node's start.
- **Stop.** The listener stops with the node and removes its socket file.
- **Why a Unix socket and JSON over HTTP.** A pod's TCP ports are the ingress's. A socket in a
  volume that only the runner and the node mount needs no port. JSON over HTTP/1.1 was chosen
  over gRPC because the token can be checked from the headers before any body is read, a runner
  can relay it without generated code, `curl --unix-socket` can drive it, and unknown JSON fields
  are ignored, which is what lets the contract grow.

### The socket file's owner and mode

The node creates the socket as its own user, with mode `0660` unless
`MODULARCA__HUB__SOCKETMODE` says otherwise. Connecting to a Unix socket needs write permission
on the socket file and search permission on its directory.

The runner connects from outside the pod's user namespace. Whether its user, as mapped into the
namespace, is the owner or in the group of the socket file depends on how the runner maps ids
and on the image's service account. That has not been tested: this build's tests were run on
Windows, where a socket file has no mode. The test that reads the mode back runs on Linux only,
and nothing tests ownership across a user namespace. If the group cannot be shared, `0666` on a socket in a directory only the runner can
reach is the fallback, with the directory's own mode as the fence.

## The contract

Version `1.1`. Within major version 1 the contract only grows: operations and optional fields
are added, none is removed or changes meaning. Both sides ignore fields they do not know.
The minor version is raised when an operation is added. A hub that states any `1.x` is served,
`1.0` included; it learns what the instance has from `hello`, and an operation the instance
does not have is answered `404 operation_not_listed`.

| Version | Added |
|---|---|
| `1.0` | `hello`, `health.read`, `mode.read`, `mode.set`, `backup.create`, `affiliation-token.replace` |
| `1.1` | `inventory.read`, `backup.prune`; `instanceId` in the answer of `hello` |

A hub that states `1.0` is served as before: the header is checked for its major version only.
A hub learns what an instance has from `hello`, not from the version number: an instance at `1.0`
answers `inventory.read` and `backup.prune` with `404 operation_not_listed`.

### Request headers

| Header | Required | Meaning |
|---|---|---|
| `Authorization: Bearer <token>` | When the instance holds a hash | The affiliation token. |
| `X-ModularCA-Hub-Contract: 1.1` | Always | The hub's contract version; any `1.x` is served. |
| `X-ModularCA-Hub-Request-Id` | On requests that change something | 1 to 128 of letters, digits, `.`, `_`, `:`, `-`. |
| `X-ModularCA-Hub-Operator` | No | The name of the person at the hub. Recorded as the hub's claim; never trusted. Cut to 128 characters. |

### Operations

| Operation | Request | Body | Answer |
|---|---|---|---|
| `hello` | `POST /hub/v1/hello` | `{ contractVersion, operations[] }` | `{ contractVersion, operations[], instanceVersion, tokenCheck, instanceId? }` |
| `health.read` | `GET /hub/v1/health` | none | `{ status, mode, tokenCheck, instanceVersion, contractVersion, timestampUtc, checks }` |
| `mode.read` | `GET /hub/v1/mode` | none | `{ mode, source, setBy, reason, setAtUtc }` |
| `mode.set` | `PUT /hub/v1/mode` | `{ mode, reason? }` | the mode record, as `mode.read` |
| `backup.create` | `POST /hub/v1/backup` | `{}` | `{ fileName, sizeBytes, createdAtUtc }` |
| `affiliation-token.replace` | `PUT /hub/v1/affiliation-token` | `{ newTokenSha256 }` | `{ tokenCheck: "enforced" }` |
| `inventory.read` | `GET /hub/v1/inventory` | none | the inventory; see "The inventory" below |
| `backup.prune` | `POST /hub/v1/backup/prune` | `{ keep?, maxAgeDays? }` | `{ deleted[], remaining[], keptByMinimumRetention[], notDeleted[] }` |

- `status` is `healthy`, `degraded` or `unhealthy`. `checks` is what `/health/ready` reports
  under `checks`; its shape is the instance's own and may grow.
- In `health.read` the `mode` member is the mode record, the same object `mode.read` answers:
  `{ mode, source, setBy?, reason?, setAtUtc?, crlsExpireFromUtc? }`, with a member left out when
  the instance has nothing for it. (The first test build's text called it a string; the answer was always the
  record.)
- `crlsExpireFromUtc` is in the mode record while the mode is `dr`, and left out otherwise. DR
  mode signs no new CRL, so the CRLs in force run out: this is the earliest `nextUpdate` among the
  newest full CRLs of the instance's enabled CAs. From then on a relying party that checks a CRL
  sees an expired one, until the mode is changed. It is in `mode.read`, in the answer of
  `mode.set`, and in `health.read`'s `mode`. Left out too when no CRL has been signed. Added
  within `1.1`: a member of an answer, which a hub that does not know it ignores.
- `mode` is `full`, `restricted`, `maintenance` or `dr`. `source` is `default` (nobody set it), `start` (the
  start rule), `hub`, `administrator`, or `unreadable` (the record could not be read and the
  instance holds itself restricted). `setBy` is the administrator's username, or the operator
  name the hub gave.
- `tokenCheck` is `enforced`, or `off` while the instance holds no hash.
- `instanceId`, in the answer to `hello`, is the instance's identifier; see "The instance
  identifier in `hello`" below. It was added to the answer within `1.1`: a field in an answer,
  which a hub that does not know it ignores.
- `backup.create` writes the same archive as the console's "Create backup", into the instance's
  backup directory, and answers when it is complete. Allow minutes. Older archives are pruned by
  the next scheduled or console backup, or by `backup.prune`, not by this request.
- `backup.prune` deletes old archives from the instance's backup directory. With both `keep` and
  `maxAgeDays`, an archive is deleted when either selects it; the newest archive, and any younger
  than the instance's `Backup.MinimumRetentionDays`, are never deleted by either. See "Pruning
  backups" below.
- Not in the list, and so refused: stopping the instance, licences, a CRL number
  floor, keystore confirmation, and everything else. The runner stops containers itself.

### The instance identifier in `hello`

    { "contractVersion": "1.1", "operations": [ "hello", "..." ], "instanceVersion": "0.4.5",
      "tokenCheck": "enforced",
      "instanceId": "9f2c4a1b8e7d6350f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708" }

- **What it is.** The identifier of the instance: 64 lower-case hex digits. It names the
  instance, not the host or the process: every node of the instance answers the same value, and
  an instance restored onto another host answers the value it had before. Two installs have
  different identifiers. It is not a secret.
- **It equals the `instanceId` of a backup manifest.** A backup writes the same value into its
  manifest, and `--backup-manifest <archive>` prints it. A hub matches an archive to a running
  instance by comparing the two as text.
- **It never changes once stored.** The instance keeps it with its data, in the application
  database (the `Settings` row `Instance_Id`), so it travels with the database and its backups
  and is in no file on any host. The control role writes it once, at the first start of a build
  that stores it, and nothing writes it again: not a later start, not the console, not the
  settings API or the host's `--settings` command, and no operation of this connection. The
  value written is the SHA-256 of the public key of the instance's system signing CA as it is at
  that start, which is what earlier 0.4.5 builds derived for the manifest each time, so archives
  made before it was stored carry the same value. Re-keying that CA later does not change the
  identifier.
- **`null` or absent means not known**, not a mismatch. The instance leaves the field out when
  it cannot say: an install from before keystore pins that has not been backfilled
  (`--backfill-keystore-pins`), so nothing could be stored or derived; a stored row that holds no
  usable value; or a database it could not read for this answer. An instance of a build before
  the field existed leaves it out as well. A hub that holds an identifier for the instance keeps
  it and asks again later.
- **Before the first store.** A node whose control role has started on this build has stored the
  identifier before the socket opens. Should the store have failed at that start (it never stops
  a start), `hello` answers the derived value, which is the value the next start stores.

### The inventory

`inventory.read` (`GET /hub/v1/inventory`, since `1.1`) answers one JSON object: what the
instance already knows about itself.

- **It only reads.** It signs no CRL, verifies no backup, runs no job and does not call the
  signer. Each value is one other work already left: rows in the database, state the readiness
  check keeps in memory, the listing of the backup directory, and the record the backup
  verification job writes. It costs a handful of small queries and one directory listing, so it
  can be asked for every minute.
- **What is never in it.** No issued certificate, no user, no private key, no secret, no audit
  entry; and no certificate or CRL bytes, serial numbers, subjects or thumbprints, the CAs'
  own included. CA names and labels, states, numbers and dates only.
- **Health and the mode are not repeated.** The hub has them from `health.read` and `mode.read`.
- **Nulls are sent.** Unlike the other answers, which leave out a field that is null, every
  field below is always present, and one with nothing to say is `null` (a list is `[]`).
- **Times** are UTC, ISO 8601.
- **Audit.** Counted with the other reads; see "Audit records".

```json
{
  "instanceVersion": "0.4.5",
  "schema": {
    "application": { "newestMigration": "20261109101500_InstanceContinuity", "appliedCount": 31 },
    "audit": { "newestMigration": "20261020090000_AuditHubActions", "appliedCount": 7 }
  },
  "signer": { "state": "unlocked", "checkedAtUtc": "2026-11-12T08:59:30Z" },
  "webTlsCertificate": { "expiresAtUtc": "2027-02-14T10:30:00Z" },
  "newestBackup": {
    "fileName": "modularca-backup-20261112-010000-5f0c1f6e9a3b4c7d8e1f2a3b4c5d6e7f.enc",
    "createdAtUtc": "2026-11-12T01:00:07Z",
    "ageSeconds": 28793,
    "valid": true,
    "verifiedAtUtc": "2026-11-12T01:00:30Z"
  },
  "failingJobs": [
    { "name": "LdapPublisher:0b9f6c1e-3a52-4c0e-9d0a-5a4c1d2e3f40", "kind": "LdapPublisher", "lastRunUtc": "2026-11-12T08:30:00Z" }
  ],
  "certificateAuthorities": [
    {
      "name": "Example Issuing CA",
      "label": "issuing",
      "state": "active",
      "certificateExpiresAtUtc": "2031-06-30T12:00:00Z",
      "crl": { "number": 412, "nextUpdateUtc": "2026-11-12T18:00:00Z" },
      "ocspResponderCertificateExpiresAtUtc": "2027-03-01T00:00:00Z"
    },
    {
      "name": "Example Root CA",
      "label": "root",
      "state": "disabled",
      "certificateExpiresAtUtc": "2046-01-01T00:00:00Z",
      "crl": null,
      "ocspResponderCertificateExpiresAtUtc": null
    }
  ]
}
```

(The migration names in the example are made up.)

| Field | Meaning | Null when |
|---|---|---|
| `instanceVersion` | The product version, as in `hello` and `health.read`. | Never. |
| `schema.application` | The migrations applied to the application database: `newestMigration` is the id of the newest, `appliedCount` how many. Read from the database's migration history. | The history could not be read. `newestMigration` alone is null when no migration is applied. |
| `schema.audit` | The same for the audit database. | The process has no audit database of its own, or its history could not be read. |
| `signer` | The signer as the instance knew it the last time its readiness check asked (`/health/ready`, and so every `health.read`). `state` is `unlocked` (it holds its keys), `locked` (it answered and its keystore is not open) or `unreachable` (it did not answer). `checkedAtUtc` is when the instance asked: the state is as old as that. | The readiness check has not run since this process started. |
| `webTlsCertificate.expiresAtUtc` | The notAfter of the certificate the instance's own HTTPS listener serves now. | `webTlsCertificate` is null when no certificate is loaded. |
| `newestBackup` | The newest archive in the instance's backup directory, chosen as the console and the verification job choose it (`modularca-backup-*` ending `.zip` or `.enc`, by creation time). `createdAtUtc` is the file's creation time, `ageSeconds` its age when the answer was made. | There is no archive, or the directory is missing or cannot be read. |
| `newestBackup.valid`, `.verifiedAtUtc` | What the last run of the backup verification job found for this archive, and when that run was. `true`: it passed the job's checks. `false`: it failed them. Never a check made for this request. | Both are null when that job has not checked this archive: it has never run (or not since 0.4.5), verification is switched off, or the archive is newer than its last run. |
| `failingJobs[]` | Every scheduled job whose last run failed or was cancelled by its timeout, by name. A job that runs per row is `Name:id`, as on the console's Schedules page. `kind` is the name without the id (`CrlExport` for `CrlExport:<id>`; the name itself for a job that runs once), which is what a hub shows. `lastRunUtc` is when. The error is not sent. A per-row job whose CRL schedule or LDAP publisher has since been deleted is left out. | `[]` when none. `lastRunUtc` is null when the scheduler recorded none. |
| `certificateAuthorities[]` | Every X.509 CA that is not deleted, by name. `state` is `active` or `disabled`. | `[]` when there is none. `label` is null for a CA without one. |
| `…certificateExpiresAtUtc` | The notAfter of the CA's certificate. | The CA has no certificate on record. |
| `…crl` | The newest full CRL already signed for the CA: its CRL `number`, and `nextUpdateUtc`, the nextUpdate written in it, by which the next is due. Delta CRLs are not counted. | No full CRL has been signed for the CA. |
| `…ocspResponderCertificateExpiresAtUtc` | The notAfter of the CA's delegated OCSP responder certificate. | The CA has none. |

- **SSH CAs are not listed.** An SSH CA has no certificate that expires, no CRL and no OCSP
  responder, so every field here would be null for it.
- **The verification record.** The backup verification job writes what each run found to
  `backup-verification.json` in the backup directory: the time, and for each archive it checked
  its file name and whether it passed. That file is what `valid` is read from. It is not an
  archive and nothing lists, prunes or restores it as one.
- **A failing job stays listed** until its next run succeeds. A per-row job whose CRL schedule
  or LDAP publisher was deleted while it was failing is left out: it can be neither fixed nor
  cleared.
- **A failing job's error is not sent.** It is the text of an exception, which can name a host, a
  directory entry or an account, and a hub never sees an instance's data. The answer says which
  job failed and when; the reason is on the instance's own Schedules page.

### What a request goes through, in order

1. **The token.** See below. A refusal here is answered before the body is read.
2. **The list.** A method and path that are not an operation: `404 operation_not_listed`.
3. **The version.** A missing, unreadable or other-major `X-ModularCA-Hub-Contract`:
   `400 contract_version_unsupported`. So is a `hello` whose body states another major version.
4. **The request identifier**, for `mode.set`, `backup.create`, `affiliation-token.replace` and
   `backup.prune`.
5. **The operation.**

### Errors

Every refusal and failure has the body
`{ "error": "<code>", "message": "...", "contractVersion": "1.1", "operations": [...]? }`.

| Status | Code | When |
|---|---|---|
| 401 | `token_required` | The instance holds a hash and the request carried no bearer token. |
| 401 | `token_invalid` | The token is not the one the instance holds the hash of. |
| 404 | `operation_not_listed` | The method and path are not an operation. `operations` lists what the instance has. |
| 400 | `contract_version_unsupported` | See step 3. `operations` is included. |
| 400 | `request_id_required` | A changing request with no usable identifier. |
| 409 | `request_id_reused` | The identifier was already used for a different operation or body. |
| 400 | `invalid_request` | The body is not what the operation takes: not JSON, not a mode, not a SHA-256, a reason over 500 characters, a body over 16 KB, or a `backup.prune` with neither value or one out of range. |
| 500 | `backup_failed` | The backup did not complete. The instance's log has the cause. |
| 500 | `internal_error` | The instance failed to carry out the request. |

### Once

A changing request is carried out once per request identifier. The same identifier sent again,
for the same operation and the same body, is answered with the first answer and the header
`X-ModularCA-Hub-Replayed: true`; nothing is done again. This holds across a restart of the node:
the last 256 identifiers are kept in `hub-requests.json` beside the socket.

- A request that failed with a 5xx is not remembered. Sending it again with the same identifier
  tries again.
- A repeated `mode.set` does not undo what an administrator set in between: it returns the first
  answer and leaves the mode as it now is.
- After a token replacement, a repeat authorised by the old token is refused 401, because the
  token check comes first. Repeat it with the new token and the same identifier.

### Pruning backups: `backup.prune`

`backup.create` does not prune, so the archives a hub asks for accumulate until the instance's
own scheduled or console backup next runs. `backup.prune` is how the hub removes them.

    POST /hub/v1/backup/prune
    X-ModularCA-Hub-Request-Id: prune-2026-11-12
    { "keep": 10, "maxAgeDays": 30 }

| Field | Meaning | Accepted |
|---|---|---|
| `keep` | Keep this many of the newest archives; delete the rest. | 1 to 10000 |
| `maxAgeDays` | Delete archives created more than this many days ago. | 1 to 36500 |

Give one or both. With both `keep` and `maxAgeDays`, an archive is deleted when either selects
it; the newest archive, and any younger than the instance's `Backup.MinimumRetentionDays`, are
never deleted by either. So `keep: 10, maxAgeDays: 30` leaves at most ten archives, none older
than thirty days, except that the newest stays however old it is and an archive inside the
instance's floor stays however many there are.

- **The rule is the instance's own.** The request runs the code the scheduled and the console
  backups prune with (`BackupRetention`), with the request's numbers in place of
  `Backup.RetentionCount`. The archives are the files `modularca-backup-*.enc` and
  `modularca-backup-*.zip` directly in the backup directory, ordered by the file's creation time.
  Nothing else there is touched; a `pre-restore-*.zip` snapshot is not an archive.
- **The newest archive is never deleted**, whatever is asked: not by `keep`, which cannot be
  below 1, and not by `maxAgeDays`, however old the newest is.
- **The instance's floor holds.** An archive younger than `Backup.MinimumRetentionDays` (3 days
  by default) is never deleted, by this request or by the instance's own pruning. The floor
  exists so that a flood of backup requests cannot purge weeks of archives in seconds. Archives
  the request selected and the floor kept are named in `keptByMinimumRetention`, so the hub can
  see why more remain than it asked for. An administrator of the instance sets the floor; the
  hub cannot.
- **Refused, `400 invalid_request`, with nothing deleted:** a body with neither field, `keep`
  below 1 or above 10000, `maxAgeDays` below 1 or above 36500, a value that is not a whole
  number, a body that is not JSON.
- **The answer.**

      {
        "deleted":   [ { "fileName": "modularca-backup-20261001-020000-....enc", "sizeBytes": 48211, "createdAtUtc": "2026-10-01T02:00:07Z" } ],
        "remaining": [ { "fileName": "modularca-backup-20261112-020000-....enc", "sizeBytes": 50113, "createdAtUtc": "2026-11-12T02:00:06Z" } ],
        "keptByMinimumRetention": [],
        "notDeleted": []
      }

  `deleted` and `remaining` are newest first. `notDeleted` names archives the rule selected that
  the file system refused to delete; they are among `remaining`, and the instance's log has the
  cause. The answer is still 200: what could be deleted was.
- **Once.** It is a changing request: it needs a request identifier, and the same identifier with
  the same body is answered with the first answer and deletes nothing more, even when newer
  archives have arrived in between.
- **Audit.** One `BackupsPruned` record under `hub` per prune, written before anything is
  deleted, listing the files it is about to delete, the numbers asked for, the floor in force and
  the operator the hub claimed. A file that then cannot be deleted adds a second, failed
  `BackupsPruned` record naming it. The request itself is recorded as every changing request is
  (`HubRequestServed`, or `HubRequestRefused`).
- **The mode.** Pruning is not held back by the instance mode: like `backup.create` it is the
  hub's housekeeping, and it issues, revokes and reconfigures nothing.

### What the hub does not do over the socket: restore

A restore replaces the database the node is using, so it is not an operation of this connection.
The runner stops the node and runs the image's `--restore` as a one-off container; its exit
status says whether anything was changed. Before it stops anything it can read what an archive
is with `--backup-manifest`. Both are described in `packaging/README-DEPLOY.md`, "Restoring with
nobody at the instance".

## The affiliation token

The interim shape, the same as the claim token's. The richer design (a group identity and
certified keys) is not built.

- **The hub makes a random token and keeps it.** The instance never sees it at rest: it holds
  the SHA-256 of the token's UTF-8 bytes, with surrounding white space removed.
- **Where the hash comes from.** `Hub.AffiliationTokenSha256` in bootstrap.yaml; the host command
  `--set-hub-token-hash` on an instance that already exists; or `affiliation-token.replace`.
- **Where it is kept.** As the instance-wide setting `Hub_AffiliationTokenSha256` in the settings
  store, in the instance's database. It follows the instance to every copy of its data and into
  every backup. No table was added for it. The console's settings neither show nor edit it.
- **The check.** Every request's bearer token is hashed and compared with the stored hash in
  constant time, before the request's body is read and before the path is interpreted.
- **While the instance holds no hash, the check is off.** Reaching the socket is then the only
  proof. `health.read` and `hello` say `tokenCheck: "off"`, and the node logs a warning at start.
  In that state `affiliation-token.replace` needs no token, which is how a hub gives the first
  hash to an instance it already runs.
- **Replacing it.** `affiliation-token.replace`, authorised by the old token, with the new
  token's hash in the body. The new hash is in force for the next request. If it cannot be saved
  the old one stays in force and the request fails.
- **A stored value that is not a SHA-256** refuses every request. It does not turn the check off.
- **What reading the hash gives.** Nothing: it is the hash of a random token of 32 bytes.
- **`--set-hub-token-hash`** writes the store directly, so a running node does not see the change
  until it restarts.

## The instance mode

One question the core asks: what may this instance do right now? The answers:

| | Full | Restricted | Maintenance | DR mode |
|---|---|---|---|---|
| Issuing, renewing, reissuing, approving a request, enrollment over every protocol (ACME, EST, CMP, SCEP, MSAE), SSH certificates, scheduled renewal | Yes | Yes | No | No |
| Revoking, placing a hold, revoking a serial with no certificate, adopting a supplied certificate, disabling a CA or a space, locking or deactivating an account | Yes | Yes | Yes | No |
| Users, groups, roles, grants, badges, profiles, templates, policy, settings | Yes | No | No | No |
| New CAs, key operations, ceremonies | Yes | No | No | No |
| Releasing a hold, un-revoking, undoing a retirement, re-enabling a CA | Yes | No | No | No |
| Signing in, the caller's own password and second factors, step-up | Yes | Yes | Yes | Yes |
| Reading and setting the mode, creating a backup, restoring one | Yes | Yes | Yes | Yes |
| Serving a CRL that is already signed, CA certificates | Yes | Yes | Yes | Yes |
| What the enrollment protocols only read: the ACME directory, nonces, and an order, authorization, account or issued certificate read back (POST-as-GET); SCEP GetCACert and GetCACaps; EST `cacerts` and `csrattrs`; the MSAE enrollment policy | Yes | Yes | Yes | Yes |
| Signing a new CRL, answering OCSP, timestamps | Yes | Yes | Yes | No |

**Maintenance** is for an instance that is being updated or audited: it issues nothing and
accepts no change to how it is run, and it still revokes and still answers revocation checks,
because a relying party must be able to check a certificate, and an administrator to revoke one,
whatever is being done to the node. It is stricter than restricted, which issues, and looser than
DR mode, which neither revokes nor answers OCSP. Its name on the wire is `maintenance`. CMP
carries enrollment and revocation on one route: in maintenance a revocation request is served and
an enrollment is refused.

### How it is enforced

- **Every mutating endpoint declares a class**: a fact, a restriction, frozen, or manage.
  `[ModeGate(ModeOperation.X)]` on the action; a test fails an endpoint that declares nothing.

  | Class | Full | Restricted | DR mode |
  |---|---|---|---|
  | Fact | Yes | Yes | No |
  | Restriction | Yes | Yes | No |
  | Frozen | Yes | No | No |
  | Manage | Yes | Yes | Yes |

- **A refused request** is recorded in the audit trail (`InstanceModeRefused`) and answered
  `503` with `Retry-After: 60` and a body that names the mode and says what still works. The
  codes are `MCA-MOD-001` (restricted), `MCA-MOD-003` (maintenance) and `MCA-MOD-002` (DR mode). The check runs after the
  endpoint's authorization and before its step-up.
- **Two endpoints decide from the request**: changing a CA is a restriction when it only
  disables the CA, and changing a user is a restriction when it only locks or deactivates the
  account. Anything else in the same request waits for full mode.
- **OCSP in DR mode** answers `tryLater`, unsigned, the protocol's own "unavailable". An answer
  signed from locked data could report a certificate as good after another copy revoked it.
- **CRLs in DR mode**: no new CRL is signed, by the schedule or by hand. The ones already
  signed are served as before.
- **The scheduler** asks before each job. While restricted it holds only the directory group
  sync and the audit retention. In DR mode it holds every job but the backup and its
  verification. A held job is not marked as run, so it runs when the mode allows it again.
  Scheduled issuance (auto-renewal, the web TLS renewal, CRL generation) continues while
  restricted and stops in DR mode.
- **Key operations** are refused at the node before it asks the signer to generate a key. The
  signer process itself does not ask the mode.
- **Bootstrap and the setup wizard are not gated.** They make the instance; the mode applies
  once it is serving.

### Where the mode is kept

In a small file on the host, never in the database, so it does not replicate to a standby copy.

- **Path.** `instance-mode.json` in the directory of the hub's socket when
  `MODULARCA__HUB__SOCKET` is set (that volume is one per copy); otherwise in the node's
  `config/` directory. Written to a temporary name and moved into place; readable by its owner.
- **Content.** `{ "version": 1, "mode": "restricted", "source": "hub", "setBy": "...",
  "reason": "...", "setAtUtc": "..." }`.
- **No file, with a hub socket**: the mode `MODULARCA__HUB__STARTMODE` names, or restricted. The
  start mode is not written down, so it applies on every start until somebody sets a mode.
- **No file, no hub socket**: full.
- **A file that cannot be read** holds the instance restricted (`source: "unreadable"`) until a
  mode is set. Guessing full could undo a deliberate DR mode.
- **A copy a failover starts** has its own socket volume, so no file, so the start rule applies.
- **More than one process of an instance** on the same directory read the same file; a change is
  seen within a second.

### Who sets it

- **The hub**, with `mode.set`. Recorded in the audit trail as `InstanceModeChanged` by `hub`,
  with the operator name it gave.
- **An administrator**, under Settings, General, Instance mode, or
  `PUT /api/v1/admin/instance-mode` with `{ mode, reason }`. It needs `system.manage` at system
  scope and a step-up (`set-instance-mode`), and a reason. Recorded as `InstanceModeChanged` by
  that administrator.
- **The last writer wins.** The record says who and when; the console and `health.read` show it.
- **Setting the mode is allowed in every mode.** An administrator who can sign in can always
  leave DR mode. That is how an instance whose hub has gone silent is recovered.
- The console shows a standing banner whenever the mode is not full. `/health/ready` carries the
  record under `checks.instanceMode`.

## Audit records

| Action | Actor | When |
|---|---|---|
| `HubRequestServed` | `hub` | A request that was served. `hello` and every changing request are one record each, with the operation, request identifier, the claimed operator, the contract version, whether it was a replay, and whether the token check was on. Served reads (`health.read`, `mode.read`, `inventory.read`) are counted: the first is recorded at once, and after that one record per five minutes carries the counts per operation since the last, under the target `reads`. A hub that polls health every few seconds therefore writes twelve records an hour, not thousands. Reads counted after the last record and before the node stops are not recorded. |
| `HubRequestRefused` | `hub` | Every request that was refused or failed, with the error code. |
| `InstanceModeChanged` | `hub`, or the administrator | The mode was set. Details: from, to, reason, who. |
| `InstanceModeRefused` | the caller | A request the mode did not allow. |
| `HubAffiliationTokenReplaced` | `hub`, or `host:<machine>:<user>` | The hash was set, replaced or removed. The hash itself is not recorded. |
| `BackupCreated` | `hub` | A backup the hub asked for, with `trigger: "hub"`. |
| `BackupsPruned` | `hub` | Old archives deleted at the hub's request: one record per prune, listing them. A second, failed record names any file that could not be deleted. |

Served reads are counted, as the `HubRequestServed` row above says: a hub may poll `health.read`,
`mode.read` and `inventory.read` every few seconds without filling the audit trail.

## Not built

- Committing without waiting for a standby while restricted.
- Asking the mode before the work the control role does at start (startup repairs, the policy
  sync, the bootstrap audit replay, sealing retired audit chains).
- The mode check inside the signer process.
- The affiliation token's final contents.
