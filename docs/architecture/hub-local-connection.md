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
  enrolment protocols and `/health/ready` are not served on it.
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

Version `1.0`. Within major version 1 the contract only grows: operations and optional fields
are added, none is removed or changes meaning. Both sides ignore fields they do not know.

### Request headers

| Header | Required | Meaning |
|---|---|---|
| `Authorization: Bearer <token>` | When the instance holds a hash | The affiliation token. |
| `X-ModularCA-Hub-Contract: 1.0` | Always | The hub's contract version. |
| `X-ModularCA-Hub-Request-Id` | On requests that change something | 1 to 128 of letters, digits, `.`, `_`, `:`, `-`. |
| `X-ModularCA-Hub-Operator` | No | The name of the person at the hub. Recorded as the hub's claim; never trusted. Cut to 128 characters. |

### Operations

| Operation | Request | Body | Answer |
|---|---|---|---|
| `hello` | `POST /hub/v1/hello` | `{ contractVersion, operations[] }` | `{ contractVersion, operations[], instanceVersion, tokenCheck }` |
| `health.read` | `GET /hub/v1/health` | none | `{ status, mode, tokenCheck, instanceVersion, contractVersion, timestampUtc, checks }` |
| `mode.read` | `GET /hub/v1/mode` | none | `{ mode, source, setBy, reason, setAtUtc }` |
| `mode.set` | `PUT /hub/v1/mode` | `{ mode, reason? }` | the mode record, as `mode.read` |
| `backup.create` | `POST /hub/v1/backup` | `{}` | `{ fileName, sizeBytes, createdAtUtc }` |
| `affiliation-token.replace` | `PUT /hub/v1/affiliation-token` | `{ newTokenSha256 }` | `{ tokenCheck: "enforced" }` |

- `status` is `healthy`, `degraded` or `unhealthy`. `checks` is what `/health/ready` reports
  under `checks`; its shape is the instance's own and may grow.
- `mode` is `full`, `restricted`, `maintenance` or `dr`. `source` is `default` (nobody set it), `start` (the
  start rule), `hub`, `administrator`, or `unreadable` (the record could not be read and the
  instance holds itself restricted). `setBy` is the administrator's username, or the operator
  name the hub gave.
- `tokenCheck` is `enforced`, or `off` while the instance holds no hash.
- `backup.create` writes the same archive as the console's "Create backup", into the instance's
  backup directory, and answers when it is complete. Allow minutes. Older archives are pruned by
  the next scheduled or console backup, not by this request.
- Not in the list, and so refused: stopping the instance, inventory, licences, a CRL number
  floor, keystore confirmation, and everything else. The runner stops containers itself.

### What a request goes through, in order

1. **The token.** See below. A refusal here is answered before the body is read.
2. **The list.** A method and path that are not an operation: `404 operation_not_listed`.
3. **The version.** A missing, unreadable or other-major `X-ModularCA-Hub-Contract`:
   `400 contract_version_unsupported`. So is a `hello` whose body states another major version.
4. **The request identifier**, for `mode.set`, `backup.create` and `affiliation-token.replace`.
5. **The operation.**

### Errors

Every refusal and failure has the body
`{ "error": "<code>", "message": "...", "contractVersion": "1.0", "operations": [...]? }`.

| Status | Code | When |
|---|---|---|
| 401 | `token_required` | The instance holds a hash and the request carried no bearer token. |
| 401 | `token_invalid` | The token is not the one the instance holds the hash of. |
| 404 | `operation_not_listed` | The method and path are not an operation. `operations` lists what the instance has. |
| 400 | `contract_version_unsupported` | See step 3. `operations` is included. |
| 400 | `request_id_required` | A changing request with no usable identifier. |
| 409 | `request_id_reused` | The identifier was already used for a different operation or body. |
| 400 | `invalid_request` | The body is not what the operation takes: not JSON, not a mode, not a SHA-256, a reason over 500 characters, a body over 16 KB. |
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
| Issuing, renewing, reissuing, approving a request, enrolment over every protocol (ACME, EST, CMP, SCEP, MSAE), SSH certificates, scheduled renewal | Yes | Yes | No | No |
| Revoking, placing a hold, revoking a serial with no certificate, adopting a supplied certificate, disabling a CA or a space, locking or deactivating an account | Yes | Yes | Yes | No |
| Users, groups, roles, grants, badges, profiles, templates, policy, settings | Yes | No | No | No |
| New CAs, key operations, ceremonies | Yes | No | No | No |
| Releasing a hold, un-revoking, undoing a retirement, re-enabling a CA | Yes | No | No | No |
| Signing in, the caller's own password and second factors, step-up | Yes | Yes | Yes | Yes |
| Reading and setting the mode, creating a backup, restoring one | Yes | Yes | Yes | Yes |
| Serving a CRL that is already signed, CA certificates | Yes | Yes | Yes | Yes |
| What the enrolment protocols only read: the ACME directory, nonces, and an order, authorization, account or issued certificate read back (POST-as-GET); SCEP GetCACert and GetCACaps; EST `cacerts` and `csrattrs`; the MSAE enrolment policy | Yes | Yes | Yes | Yes |
| Signing a new CRL, answering OCSP, timestamps | Yes | Yes | Yes | No |

**Maintenance** is for an instance that is being updated or audited: it issues nothing and
accepts no change to how it is run, and it still revokes and still answers revocation checks,
because a relying party must be able to check a certificate, and an administrator to revoke one,
whatever is being done to the node. It is stricter than restricted, which issues, and looser than
DR mode, which neither revokes nor answers OCSP. Its name on the wire is `maintenance`. CMP
carries enrolment and revocation on one route: in maintenance a revocation request is served and
an enrolment is refused.

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
| `HubRequestServed` | `hub` | A request that was served. `hello` and every changing request are one record each, with the operation, request identifier, the claimed operator, the contract version, whether it was a replay, and whether the token check was on. Served reads (`health.read`, `mode.read`) are counted: the first is recorded at once, and after that one record per five minutes carries the counts per operation since the last, under the target `reads`. A hub that polls health every few seconds therefore writes twelve records an hour, not thousands. Reads counted after the last record and before the node stops are not recorded. |
| `HubRequestRefused` | `hub` | Every request that was refused or failed, with the error code. |
| `InstanceModeChanged` | `hub`, or the administrator | The mode was set. Details: from, to, reason, who. |
| `InstanceModeRefused` | the caller | A request the mode did not allow. |
| `HubAffiliationTokenReplaced` | `hub`, or `host:<machine>:<user>` | The hash was set, replaced or removed. The hash itself is not recorded. |
| `BackupCreated` | `hub` | A backup the hub asked for, with `trigger: "hub"`. |

Reads are recorded too. A hub that polls `health.read` every few seconds writes that many audit
records; poll at the rate the audit trail should carry.

## Not built

- Committing without waiting for a standby while restricted.
- Asking the mode before the work the control role does at start (startup repairs, the policy
  sync, the bootstrap audit replay, sealing retired audit chains).
- The mode check inside the signer process.
- The affiliation token's final contents.
