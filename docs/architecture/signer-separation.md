# Signer separation

Status: design accepted 2026-09-17; stages 1 and 2 are the 0.3.0 work that precedes the first
published container image. Stages 3 and 4 follow it.

## Why

Today one process holds every private key ModularCA has: the CA keys, the OCSP responder keys,
the timestamp key, the keys of end-entity certificates the CA generated for export. The keystore
file is scrypt-protected, signed and pinned, and the API process decrypts it at startup and keeps
the keys in memory for as long as it runs. Every code path that needs a signature reaches those
keys through `IPrivateKeyHandle`, and several reach past it to the raw key.

That makes the API process the thing an attacker wants, and it is also the process with the
largest attack surface: five enrollment protocols, a console, an admin API, Kerberos parsing,
CMS parsing, and every dependency those bring. A bug in any of them is a bug in the room where
the keys are.

Separation moves key custody into a small process with a narrow contract. The node still asks
for signatures, so a compromised node can still get certificates signed while it is compromised,
and that is answered by policy, rate limits and audit at the signer, and by an HSM behind it for
anyone who needs extraction resistance. What a compromised node can no longer do is read a key,
copy the keystore, or sign after the incident is over. That is the property this buys.

## Roles

The binary gains roles. A process runs any subset; all of them by default, so a single-server
install is unchanged.

| Role | Holds | Talks to |
|---|---|---|
| **signer** | the keystore, the keystore passwords, the PKCS#11 session | nothing outbound; answers the node |
| **enrollment** | protocol handlers (ACME, EST, SCEP, CMP, MSAE), the issuance pipeline | database, signer |
| **validation** | CRL and OCSP serving; the delegated OCSP responder keys only | database (read), signer for responder keys |
| **control plane** | console, admin API, spaces, principals, ceremonies, audit, the fleet module | database, signer for ceremonies |
| **ingress** | TLS termination for every hostname, routing by name (YARP) | the other roles over loopback |

Only the signer is separated in stages 1 and 2. Enrollment and control plane stay one process
until there is a reason to split them; validation and ingress are stages 3 and 4.

## Where keys are touched today

Every path that reaches a private key, from the code as of `a4f492c`. This is the migration
list for stage 1; when it is done, nothing outside `ModularCA.Keystore` holds an
`AsymmetricKeyParameter` for a stored key.

| Caller | Key | Operation |
|---|---|---|
| `CertificateBuilderService` | CA | sign a certificate |
| `CertificateIssuanceService` | CA | sign; also generates end-entity keys for server-side key generation |
| `CrlService` | CA | sign a CRL |
| `OcspResponderService` | delegated responder key, or the CA key when none | sign an OCSP response |
| `ScepService` | CA (RA) | sign and decrypt SCEP envelopes |
| `CmpService` | CA | sign CMP responses |
| `TimestampService` | TSA | sign timestamp tokens |
| `CaCreationService` | new CA | generate a key, self-sign or produce a CSR, store |
| `CertificateExportService` | end-entity | export a private key as PKCS#12 |
| `AdminCaController` | CA | infrastructure certificate reissue (OCSP, CMP signers) |
| `MtlsController` | CA | sign client certificates used for console sign-in |
| ceremonies | CA | key generation and cross-certification through `CaCreationService` |
| backup | all | export the keystore files |
| `StartModularCA` | all | unlock the keystore at startup with the main and secondary passwords |

Not in scope, because they are not signing keys: the console's own TLS key and the tenant
hostname keys (PKCS#12 files owned by the ingress/TLS layer, retired in 0.4.0), the Kerberos realm keys (symmetric,
protected by data protection, used by the acceptor), and DPoP or session secrets.

## The contract

One service, `ISigningService`, is the only door to a stored private key. Callers hold a key
reference, never a key.

```
SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext ctx) -> byte[]
DecryptAsync(KeyRef key, byte[] enveloped, SigningContext ctx) -> byte[]        // SCEP only
GenerateKeyAsync(KeySpec spec, SigningContext ctx) -> KeyRef + public key
ImportKeyAsync(KeyMaterial wrapped, SigningContext ctx) -> KeyRef                // migration, HSM import
ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext ctx) -> byte[]      // PKCS#12 under a caller password, policy-gated
ListKeysAsync(SigningContext ctx) -> KeyRef[] with public keys and attributes
RetireKeyAsync(KeyRef key, SigningContext ctx)
HealthAsync() -> unlocked, key count, backend (software | pkcs11)
```

`KeyRef` is the certificate id the key belongs to plus the keystore name, which is how the
keystore already addresses entries. `SigningContext` names the caller's identity, the purpose
(certificate, CRL, OCSP, SCEP, CMP, TSA, ceremony, backup, export) and the space and CA the
operation is for. The signer decides from that whether the operation is allowed: a CA key signs
certificates, CRLs and protocol responses for its own CA; a responder key signs OCSP responses
only; export is allowed only for end-entity keys and only for a caller holding the export right;
key generation and import are allowed only under a ceremony or bootstrap context. Every decision
is audited at the signer with the context, so the signer's audit is the record of what was
signed even if the node's audit is lost.

End-entity keys generated for server-side key generation are not CA keys and do not need custody;
they are handed to the customer. They are generated in the node, used once to build the PKCS#12,
and never enter the keystore. This is a change from today, where they are stored; the export
service reads its keys from the keystore because they are there, not because they need to be.
Existing stored end-entity keys stay readable through `ExportKeyAsync` until they expire.

## Stage 1: the seam, in process

- `ISigningService` in `ModularCA.Shared`; `InProcessSigningService` in `ModularCA.Keystore`
  wrapping the keystore, the PKCS#11 session manager and the unlock state.
- `IPrivateKeyHandle` becomes an implementation detail of the keystore project. Every caller in
  the table above is migrated to `ISigningService` with a `KeyRef`. `PrivateKeyHandleSignatureFactory`
  becomes a `SigningServiceSignatureFactory` so BouncyCastle generators keep working unchanged.
- `KeystoreService.LoadCertKeys` and `CertKey(AsymmetricKeyParameter)` are removed from the
  public surface; the API process no longer receives key parameters at startup.
- The startup unlock moves behind the signer: the node asks `HealthAsync` and refuses to serve
  enrollment until the signer reports unlocked.
- Policy and audit as above, evaluated in process for now.
- Tests: a contract test suite runs every operation against `InProcessSigningService`; the
  existing issuance, CRL, OCSP, SCEP, CMP, TSA, ceremony and backup tests stay green with no
  behaviour change; mutation checks on the policy table.

No schema change, no configuration change, no change to the keystore file format. A 0.2.0
install upgraded to a stage-1 build behaves identically.

## Stage 2: the signer out of process

- The same contract as a gRPC service over mutual TLS: `RemoteSigningService` on the node,
  `--role signer` running `InProcessSigningService` behind a Kestrel gRPC endpoint on loopback by
  default. Loopback today; a sidecar container, another host or an HSM front tomorrow, without
  the contract changing. This is why gRPC over a local socket was not chosen.
- Identity: at bootstrap the node creates a local **node identity CA**, self-signed, held by the
  signer, which issues one client certificate to the node and one server certificate to the
  signer. Each side pins the other's certificate; there is no trust store lookup. When the
  controller exists, its mutual-TLS CA can issue these instead; the pinning stays.
- The signer holds the keystore passwords. The node's configuration loses them. On a single
  server this means the passwords move from the node's environment to the signer's; in a pod they
  are the signer container's secret only.
- Ceremonies: approval and quorum stay in the control plane; execution sends the signer a
  request carrying the ceremony's id and the approvals, which the signer verifies against the
  database before generating or importing a key. The signer has read access to the ceremony
  tables for this and nothing else.
- Backup: `ExportKeyAsync` with the backup wrap replaces the node reading keystore files; the
  backup archive carries the signer's export, encrypted as backups are today. Restore imports
  through `ImportKeyAsync` under the restore context.
- Failure: the node caches nothing signable. If the signer is down, issuance, CRL, OCSP and
  protocol responses return a service-unavailable error with a clear message, the readiness page
  shows the signer's health as a step, and validation serving continues from the last published
  CRL. Reconnection is automatic.
- Configuration: `Signer.Mode: InProcess | Remote`, `Signer.Endpoint`, `Signer.ClientCertificate`,
  `Signer.PinnedServerSpki`; for the signer role, `Signer.Listen`, `Signer.ServerCertificate`,
  `Signer.PinnedClientSpki`. Defaults keep a single process in-process.
- Tests: the contract suite runs a second time against `RemoteSigningService` talking to an
  in-test signer over loopback; refusal cases (wrong purpose, wrong CA, unpinned peer, unlocked
  false) are asserted at the wire; the live proof on ca4 issues a certificate, publishes a CRL,
  answers OCSP, runs SCEP and CMP, executes a ceremony and takes a backup with the signer as a
  second systemd unit.

## Deployment shapes

| Shape | Processes | Signer transport |
|---|---|---|
| Single server, as today | one, all roles | in process |
| Single server, hardened | node + signer as two units, signer under its own OS user | gRPC over loopback, mutual TLS |
| Container tier | node container + signer sidecar in one pod, sharing only the channel | gRPC over the pod's loopback |
| HSM | signer alone in front of PKCS#11; node anywhere it can reach it | gRPC, mutual TLS |

The image published after stage 2 is one image with both roles; the pod definition runs it
twice.

## What this does not fix

- A compromised node can request signatures for as long as it is compromised. Policy narrows
  what it can ask for, rate limits bound how much, the signer's audit records all of it.
- The signer's own memory holds keys when the backend is software. Extraction resistance is the
  HSM's job, and the signer is where PKCS#11 lives so that an HSM is a configuration change.
- The database is shared. A node with database access can alter what the signer reads for
  ceremony verification; the signer verifies approvals against signed audit rows, not against
  mutable state, which is the reason the audit chain matters for this design.

## Order of work

1. `ISigningService` and `InProcessSigningService`; contract tests.
2. Migrate callers in the order of blast radius: issuance and CRL, OCSP, SCEP and CMP, TSA,
   CA creation and ceremonies, export, backup, startup unlock. Each migration is one commit with
   the existing tests green.
3. Remove raw key access from the public surface; the build proves nothing outside the keystore
   project references `AsymmetricKeyParameter` for stored keys.
4. gRPC contract and `RemoteSigningService`; the signer role; identity bootstrap; configuration.
5. Live proof on ca4 with the signer as a second unit.
6. The container image and pod definition, then stage 3.

## Decisions on the open questions (2026-09-17)

- The timestamp key stays a signer key.
- Re-download of server-generated private keys ends. A key the CA generates is held on its
  request row under Data Protection, never in the keystore or the signer, until the certificate
  is issued and the holder downloads certificate, chain and key as one PKCS#12; it is deleted
  on delivery, and undelivered when the request is rejected or cancelled or its certificate is
  revoked or expires. The console's key-generation form says so. Keys already stored expire in
  place behind the signer's export policy and are not migrated.
- The signer's audit is its own table in the shared database.

## Stage 1 as built (2026-09-17)

Stage 1 is complete on `0.3.0-dev`: seventeen commits from `6c0c8fc` to `fad9d08`, the suite at
1549 tests, and an architecture test that fails the build if any type in Core, API, Auth or
Bootstrap references a key handle, the key registry, the keystore persistence, or any keystore
member returning key parameters. Where the code differs from the design above, the code is right
and this section records why.

- **`CommitKeyAsync` joined the contract.** A generated key is held pending in the signer's memory
  under a signer-minted reference and signs only under the purpose, space and CA it was generated
  for. It is written to the keystore and bound to its certificate row by an explicit, audited
  commit after the CA's database transaction succeeds; any failure before that retires it, so a
  failed creation leaves nothing usable on disk. The keystore format has no entry removal, which
  is why the write waits for the commit. Each commit rewrites the keystore file, so creating a CA
  costs three rewrites today; a batched commit is a later convenience.
- **Server-generated keys are held briefly, then delivered once as PKCS#12.** Every server-side
  key-generation flow is approval-gated, so the certificate does not exist when the key is made.
  The node keeps the key wrapped under data protection on the request row, bound to that row,
  never in the keystore or the signer; when the certificate issues, one download returns a
  PKCS#12 with certificate, chain and key under the requester's password, and the key is deleted
  in the same transaction. A rejected or cancelled request, a permanently revoked certificate, or
  an expired one drops its key on the next cleanup sweep. Keys stored before this change are
  carried on their rows as ciphertext and exportable until they expire; renewals never carry a
  key forward. The clear-text PEM export is withdrawn.
- **Backups carry whole keystore files.** The signer exports and imports keystore files as units
  (`SigningPurpose.Backup` and `Restore`), verified on import against the pinned signer. Per-key
  restore was rejected because the key that signs the keystore file is one of the keys being
  restored. These two operations are permitted while the signer is locked, since they hand out no
  usable key and restoring into an empty node is how a signer comes to hold keys.
- **Locked means unavailable, visibly.** Enrollment protocol controllers and admin issuance answer
  503 with a retry hint until the signer reports unlocked; the health endpoint and the MSAE
  readiness page both show the signer's state.
- **Stricter than the table.** Every key is held to its owning CA and, when named, its space; a
  CA certificate without a CA row cannot sign; an audit-write failure does not withhold a
  signature in process, which stage 2 must change to fail closed at the signer.

Follow-ups found on the way, not part of stage 1: the automatic renewal job's rekey path
generates a key it then discards; bootstrap still writes CA-key wraps onto certificate rows.

## Stage 2 as built (2026-09-17)

Stage 2 is complete on `0.3.0-dev`: commits `e088697` to `2049172`, the suite at 1783 tests,
the contract suite run a second time over the wire against a real signer host on loopback, and
five deliberate breaks (either pin removed, fail-closed made fail-open, the ceremony check
removed, the refusal reason dropped from the wire) each caught by a test.

- **One project, `ModularCA.Signer`**, holding the proto, the client and the host, referencing
  only `ModularCA.Shared`; the seam test seals it with the other four assemblies. Refusals cross
  the wire as a permission-denied status with the reason name in a trailer, so the node rethrows
  the same `SigningRefusedException`; transport failures become `SignerUnavailable`, which the
  unlocked-signer filter and the readiness page report as "the signer is unreachable".
- **Roles.** `--role signer` hosts only the gRPC service and a health route on the same
  mutual-TLS listener; `--role node` with `Signer.Mode: Remote` loads no keystore and needs no
  keystore password; the default, all roles in one process, is stage 1 unchanged. A node in
  remote mode reads the CA certificates it used to get from the keystore from the database
  instead (`DatabaseKeystoreCertificates`), which the design had not covered.
- **Identity.** `--init-identity` creates the identity CA (ECDSA P-256, ten years) and the
  signer's server certificate; `--issue-node-identity` issues the node's client certificate (one
  year) and writes the server pin. Both sides check the SPKI pin and nothing else: no trust
  store, no chain, no dates. Rotation is reissue and re-pin.
- **Fail closed in the signer role**: an audit row that cannot be written refuses the operation
  before any result leaves; key generation records before the pending key becomes reachable. In
  process the stage 1 behaviour stays.
- **Ceremony at the signer.** When a context names a ceremony, the signer verifies the row
  exists, is approved and names the same CA and space before generating, committing or
  importing a key. Contexts without a ceremony id are still allowed, because spaces that do not
  require ceremonies create CAs directly; the follow-up is for the signer to read the space's
  requirement and refuse id-less key management where a ceremony is required. Ceremony expiry
  is not checked, matching the controller.
- **Operations.** The gRPC channel's reconnect backoff is bounded to five seconds, found by the
  reconnect test; the default would have left a node refusing enrollment two minutes after its
  signer returned. The command-line backup and restore read keystore files locally, so on a
  split install they run on the signer's host; the scheduled backup goes through the signer. The
  first install completes as a single process before splitting, because bootstrap writes the
  keystore locally.
- **Deployment.** `deploy/modularca-signer.service` runs the signer under its own user with the
  node unit's sandboxing; the deploy readme carries the two-unit steps.

Follow-ups: the signer audit row does not carry the ceremony id or the client certificate's
identity; the pod definition for the container tier needs the signer as a sidecar.

## Roles as built (2026-09-17)

Enrollment, validation and control plane are real roles on `0.3.0-dev`, in any combination,
the default still every role in one process. A process hosts only its own controllers and
background work; an inactive role's paths do not exist. Where the code differs from the roles
table above, this section records it.

- **One declaration per controller.** `[NodeRole(ProcessRole.X)]` on every controller; an
  application-model convention removes the controllers of the roles the process does not run
  before routing exists, so their paths answer 404 with no authentication challenge. A
  controller with no role, or with more than one, stops startup; the architecture test over the
  API assembly fails first. Validation: OCSP, the CRL and CA certificate controllers, the SSH
  CA keys, the short URLs (`/ca`, `/crl`, `/ocsp`), and the plain-HTTP listener, which only
  validation opens. Enrollment: ACME, EST, SCEP, CMP, MSAE, token enrollment, the public
  template list, the integration API (cert-manager, infrastructure), and the TSA, whose `/tsa`
  alias moved off the short-URL controller for that reason. Control: everything admin, auth,
  user, account, the setup wizard, version, the portal's info endpoint and the CSP report,
  with the SPAs and static files, the setup redirect, the CSRF cookie, the docs gate and the
  console CSP applied only there.
- **One declaration per job.** `SchedulerJobRoles` names the owner of every scheduled job.
  Enrollment owns the two protocol sweeps (ACME cleanup, protocol cleanup). Control owns
  CRL export, LDAP publishing and group sync, expiry notification, compliance, auto-renewal,
  certificate expiry, backup creation and verification, audit retention and TLS renewal. A
  validation-only process hosts no scheduler. Migrations, the startup repairs, the policy
  sync, the bootstrap audit replay and the pending web TLS provisioning run where control
  runs; the OCSP responder warning runs where validation runs.
- **Two leases, not one.** The lease logic is unchanged, but a process without the control
  role contends for `scheduler:enrollment` rather than `scheduler`; two processes with
  different job sets on one lease would leave the loser's jobs unrun for as long as the winner
  refreshed it. A single process, and any process with control, keeps the name every install
  has used.
- **Health.** `/health` lists the roles a process runs; `/health/ready` carries a `roles`
  entry with what each active role needs and whether it has it: validation the signer
  reachable, enrollment the signer unlocked, control the database.
- **Configuration.** `--role enrollment,validation` and the like on the command line, or
  `Roles` in `config.yaml` when the command line names none; the command line wins, so the
  drop-ins under `deploy/dropins/` select the role per host over a shared file. A process
  without control refuses an unconfigured install, since the wizard is control's. Two node
  processes need two installs (they would bind the same ports), so the three-process layout in
  the deploy readme is one node process per host.

Follow-ups: the ingress role (stage 4) is what makes the split reachable under one name
(done, see "Ingress as built"); the plain-HTTP TSA alias is lost on a validation-only host,
since the listener is validation's and the TSA is enrollment's.

## Signer follow-ups done (2026-09-17)

The two follow-ups stage 2 left on the signer are closed, in three commits after `2049172`,
with the contract suite at 440 tests over both bindings and four deliberate breaks (the
requirement check removed, the expiry check removed, the ceremony id not recorded, the peer
not recorded) each caught.

- **The space's ceremony requirement is enforced at the signer.** A ceremony context that
  names no ceremony is held to the space's own row: the space it names, or the space of the
  CA it names. `RequireKeyCeremony` set, or a space the signer cannot find, refuses generate,
  commit and import as `CeremonyRequired`; a context naming neither space nor CA is
  `ContextRequired`. Bootstrap and retire are exempt as before, and a space that waives
  ceremonies is unchanged. A ceremony that is named is also held to its `ExpiresAt`. One
  consequence to weigh: infrastructure reissue (`ReissueInfrastructureCertsAsync`) sends a
  ceremony context with no ceremony id, so for a space that requires ceremonies the signer now
  refuses it until the node either gates reissue behind a ceremony or carries one.
- **The audit row names the ceremony and the peer.** `SignerAudit.CeremonyId` is the ceremony
  the context named, on every decision including refusals of ceremonies the signer could not
  verify. `SignerAudit.PeerIdentity` is the SPKI pin of the client certificate on the
  connection, computed by the gRPC host from the certificate Kestrel admitted and stamped on
  the context as a server-set property that the wire has no field for; null in process.

## Ingress as built (2026-09-17)

The ingress role is real on `0.3.0-dev`, in five commits after the signer follow-ups, the
suite at 1924 tests, and four deliberate breaks (merge precedence inverted, the local
fallthrough removed, the Kerberos headers stripped in the proxy, the dangerous flag accepted
off loopback) each caught by a test, the last one twice (at configuration validation and in
the trust policy). Where the code differs from the roles table above, this section records
it.

- **A role, not a node role.** `ProcessRole.Ingress = 16`; `All` includes it, `Node` stays
  the three. The default single process therefore runs the ingress with no route and routes
  nothing: every name is served by its own roles, which is the behaviour every install had.
  An ingress-only process holds a locked, empty in-process signer as setup mode does (no
  keystore, no keystore password, no signer client certificate on that host), the role
  convention leaves it no controller, the scheduler is not hosted, the console is control's;
  it serves `/health` and the health probes. The TLS handshake is the node's, unchanged: the
  same SNI selection over the same tenant hostname certificate cache, so the ingress and a
  node present exactly the same certificates.
- **Two sources, one table, pure rules.** `IngressRouteTable.Merge` in Core: `Ingress.Routes`
  and the tenant hostnames whose new `NodeUpstream` column is set; configuration wins for the
  same host; no upstream is not a route; a value that does not parse is dropped and logged
  rather than routed somewhere odd. `IngressRouteTableService` serves a dictionary snapshot,
  rebuilds on `Ingress.RouteRefreshSeconds` and after every change the hostname service
  makes, keeps the last database rows when the database is unreachable, and raises a change
  only when the set differs; `IngressProxyConfigProvider` in the API turns each entry into
  one YARP route (host match, any path) and one cluster.
- **A branch, not an endpoint.** The design said YARP before the local endpoints; the proxy
  is a `MapWhen` branch right after the forwarded-headers step instead. Endpoint routing
  would have run every local middleware first, and `HttpSchemeEnforcementMiddleware` would
  have redirected a tenant's plain-HTTP revocation request to HTTPS before YARP saw it. The
  branch meets no local redirect, security header, rate limit or authentication; the node
  applies its own. A host with no upstream, the public domain included, never enters the
  branch and continues down the local pipeline as before.
- **Two destinations per cluster, chosen by arrival.** The plain-HTTP listener is the
  ingress's as well as validation's. A cluster holds the HTTPS upstream and, when the route
  names one, the node's own plain-HTTP listener; the pipeline step picks the destination by
  which listener the request arrived on, so `http://tenant/crl/...` reaches that node's plain
  listener and its CRL, with no redirect. When the chosen destination is withheld by the
  active probe (`/health/live` on every upstream, consecutive failures), the step answers 503
  with a body naming the host rather than sending the request to a node known to be down.
  YARP's default answer would have been an empty 503 or a 502 from the failed connection.
- **Upstream trust, in a fixed order.** Per cluster: a route's SPKI pin; else the shared
  upstream CA (chain only, the name is not checked, since a node is reached by address and
  its certificate names its public name); else, for loopback destinations only, anything
  under `DangerousAcceptAnyUpstreamCertificate`; else the system store. A non-loopback
  `https://` route under the flag stops startup, and a database route that is not loopback
  never gets the exception whatever the flag says. The client factory replaces a cluster's
  client when its metadata changes, so a new pin is not served by the old callback.
- **Headers.** `X-Forwarded-For`, `-Proto` and `-Host` are set on the way to the node (YARP's
  default), which the node honours from loopback and `Http.TrustedProxyCidrs`; the Host
  header sent to the node is the upstream's, as YARP does by default, and the node takes the
  original from `X-Forwarded-Host`. `Authorization: Negotiate` and `WWW-Authenticate` pass
  through untouched, held by a test that hosts the real wiring in front of a stub node.
- **Health.** `/health/ready` gains an `ingress` entry: the table built, the database
  reachable, the routes by source, and per upstream what the probe last found. A node that is
  down is reported, not made the whole ingress's failure, since the other hosts are still
  served; the design's "routes loaded, upstream health summary" is read that way.

Limits, recorded rather than hidden: the ingress terminates TLS, so a client certificate
presented to it is not forwarded; the mTLS sign-in name and the EST client-certificate name
must stay on the process that hosts control and enrollment (no upstream for them). The
public domain is proxied only when a route names it; the design's "served locally when it
has no route" holds. Kestrel's 10 MB request body limit applies on the ingress as on a node.

Follow-ups: a console field for `NodeUpstream` (the API and the audit row exist); HTTP/2
and gRPC to upstreams are not needed today and not configured; the pod definition for the
container tier with the ingress as its own container.

**Since 0.4.0 S2 (2026-09-28)** tenant hostnames are gone (see `instance-tenancy.md`), and with
them the database source above. `Ingress.Routes` is the only source, built once at startup:
no refresh, no `RouteRefreshSeconds`, no `NodeUpstream`, no route source in the cluster
metadata. Every name, on the ingress and on a node, is presented the instance's web TLS
certificate. The `ingress` health entry carries the route count and the probe results. The
branch, the destinations chosen by arrival, the upstream trust order and the header handling
are unchanged.

## The pod as built (2026-09-19)

Step 6 of the order of work: `deploy/container/modularca-pod.yaml`, a Kubernetes pod manifest
that Podman runs as written and Kubernetes runs as a Pod. One image, run twice — `--role signer`
and `--role node` — sharing the pod's network namespace and nothing else that matters. The
signer alone mounts the keystores volume; the node never does. The config volume is shared and
the signer mounts it read-only. The signer publishes no port.

What the design left to the operator's hands, the pod does with init containers, and that needed
one addition to the product. The identity commands printed two config sections for an operator
to transcribe onto two hosts. `--issue-node-identity --apply <config.yaml>` now writes both halves
into the one `Signer:` section of a shared file — the node reads `Mode`, `Endpoint`,
`ClientCertificate` and `PinnedServerSpki`; the signer reads `Listen`, `ServerCertificate` and
`PinnedClientSpki`; `SignerConfig` was already one class carrying both — splicing that section
and leaving every other byte of the file alone, then loading it back and restoring the backup if
it did not read as written. It is idempotent, which is what makes it an init container: a file
that already names a remote signer with both pins set is not touched. `--init-identity` already
refused to replace an existing CA, and the entrypoint gained a `--bootstrap-only` mode so the
first-install bootstrap runs once, by one process, before anything else from the image starts.
The entrypoint also refuses to bootstrap for a signer or ingress role: two processes from one
volume racing to create the keystore was the failure that check exists to prevent.

The image is unchanged from stage 2. Both systemd units now order after `postgresql.service`
rather than the MySQL units they still named.

Not done here, and recorded: the ingress as its own container in the pod (its follow-up above
still stands — the pod is the "node container + signer sidecar" row of the deployment table, not
the multi-tenant shape), and a live proof of the pod on ca4, which needs Podman on a host that
has it. Stage 3 follows that proof.

## Secrets the node must keep, wrapped behind the signer (2026-09-18)

The signer holds every private key, and a node in remote mode holds none. Three database columns
are not covered by that, because what they hold is not a signing key: `KerberosRealmEntity.ProtectedKey`
(symmetric Kerberos keys), `CertRequestEntity.HeldPrivateKey` (a requester's key held between
request and collection) and `EnrollmentTokenEntity`'s CMP shared secret, which the authority has
to be able to recover because password-based message authentication is symmetric. All three are
wrapped with ASP.NET Data Protection, whose keys live on the node. A stolen database plus a stolen
node therefore yields all three in the clear, which is weaker at rest than the separation suggests.

The wrapping key moves behind the signer, so that recovering those columns needs the keystore as
well. The contract gains two operations over opaque bytes, distinct from `ExportKeyAsync`, which
is about keys the signer already holds:

```
WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext ctx) -> byte[] wrapped
UnwrapSecretAsync(byte[] wrapped, SigningContext ctx) -> byte[] secret
```

`kind` is not a key reference: the caller never chooses which key wraps for it. A wrap names what
the secret **is**, and the signer decides what may wrap and unwrap that kind.

### Which key wraps, and where it lives

The wrapping key is derived, per blob, from a private key the keystore already holds — the key
pinned for `ca-certs.keystore`, which is the system signer `FileKeystorePersistence` already
resolves and which the legacy end-entity wrap already unwraps under:

```
kek = HKDF-SHA256(ikm = PKCS#8 of the designated keystore key,
                  salt = 32 random bytes, per blob,
                  info = "ModularCA.SecretWrap.v1" || kind || key id)
```

and the secret is then AES-256-GCM under that KEK, with the blob's own header as associated data.
The KEK exists only where that private key exists, which is the keystore, which is behind the
signer. A node in remote mode cannot derive it.

A dedicated wrapping key pair, generated by the signer and appended to the keystore as its own
entry, was the first design and was dropped. A keystore entry is a private key **paired with a
certificate**; the certificate goes into `ca-trust.keystore`, and everything loaded from there is
a trusted authority, which EST `/cacerts`, SCEP, the CRL service and the trust bundle publish. A
wrapping key is not a trust anchor and has no business in any of them. Deriving avoids inventing a
second keystore format, avoids a runtime keystore rewrite, and works whatever algorithm the
designated key is — RSA, ECDSA, Ed25519 or ML-DSA — because the key is HKDF input material, not an
encryption key. It is worth saying plainly that this is key reuse: the same private key signs and
seeds a KEK. It is a one-way derivation from the private key, not an encryption under it, so there
is no chosen-ciphertext interaction between the two uses; it is still reuse, and an HSM-held key
cannot do it at all (below).

### How a blob names the key that wrapped it

The blob is self-describing, so a key can be rotated:

```
"MCAW" | version (1) | kind (1) | key id (32) | salt (32) | nonce (12) | ciphertext+tag
AAD  = "MCAW" | version | kind | key id          (the first 38 bytes)
```

The **key id** is SHA-256 over the DER `SubjectPublicKeyInfo` of the designated key's certificate:
the same SPKI digest the keystore pins, the signer's identity pins and the registry matches on.
Unwrapping resolves the key by that id and by nothing else. So:

- new secrets are wrapped under whichever key is designated now;
- old blobs keep unwrapping under the key their id names, for as long as the keystore holds it —
  and the keystore has no entry removal, so it does;
- rotation is: designate a new key, and let each column's owner re-wrap its rows on its own sweep.
  Nothing has to be re-wrapped at once, and nothing breaks if nothing ever is.
- a blob whose key id the signer does not hold is `UnknownKey`, not a decryption failure.

The **kind** is in the associated data, so the separation below is not only a policy check: a blob
wrapped as a held private key does not authenticate as a CMP secret even if the policy were
bypassed, because the AAD would differ and AES-GCM would refuse.

### Who may wrap and unwrap what

| `SigningPurpose` | may wrap | may unwrap |
|---|---|---|
| `Cmp` | `CmpSharedSecret` | `CmpSharedSecret` |
| `Certificate` | `HeldPrivateKey` | — |
| `Export` | — | `HeldPrivateKey` |
| every other purpose | nothing | nothing |

`KerberosRealmKey` is a kind the format knows and the policy permits to no purpose, so today it
cannot be wrapped or unwrapped at all; adopting it means adding its purpose and its row, and the
availability question below has to be answered first.

A CMP caller therefore cannot unwrap a held private key, and the issuance path that wraps a held
key cannot read one back — reading it back is the export path's right, which is already the
right a person holds. Wrap and unwrap are separately permitted for that reason. Neither is held
to a CA or a space: the wrapping key is the signer's, not a CA's, so there is no owner to hold it
to. The context still names them and the audit still records them.

Neither operation runs while the signer is locked, and neither runs when the designated key is on
a PKCS#11 token, since the token will not hand out the key material HKDF needs. An HSM install
therefore keeps Data Protection for these columns until the signer gains a token-side wrap
(PKCS#11 C_WrapKey), which is the same shape and a later change.

### What the audit row says

One row per call, allowed or refused, as for every other decision. `Operation` is `WrapSecret` or
`UnwrapSecret`; `Purpose`, `Caller`, `CaId`, `SpaceId` and `PeerIdentity` as usual; `SecretKind`
names what kind of secret it was, and `WrappingKeyId` the key id the blob names, so the record
shows which key a rotation has left in use. `DataHash` is SHA-256 **of the wrapped blob**, on both
operations and in both directions — never of the plaintext, which would make the audit a
verification oracle for the secret it is protecting. A refusal records the kind and the key id it
was told, the way a refused ceremony records the ceremony it was told.

### The CMP secret, first

`EnrollmentTokenEntity.CmpSecretPlaintext` becomes `CmpSecretWrapped`: base64 of the blob above,
written by `EnrollmentTokenService.GenerateCmpSharedSecretAsync` and read by
`CmpService.TryVerifyPbmAsync`, which is the only consumer. The column has never been deployed, so
the rename and the widening fold into `InitialCreate` rather than arriving as a migration. The
console's "last four characters" hint moves to its own `CmpSecretLastFour` column, because it can
no longer be taken from a column that is now ciphertext, and four characters of a 43-character
random secret was already what that screen showed.

The other two columns are not migrated yet. For `CertRequestEntity.HeldPrivateKey` it is the same
shape and a bigger blast radius: `HeldKeyService` binds its ciphertext to the request id through
the Data Protection purpose string, which the wrap does not do, so adopting it means either
accepting that a blob moved between rows still unwraps, or binding the row id into the AAD — the
latter, and it is a format the envelope already has room for. For `KerberosRealmEntity.ProtectedKey`
see the next paragraph, which is the reason it is last.

### Availability, honestly

These secrets become unreadable when the signer is unreachable. For CMP that is the right
coupling: CMP cannot issue anything without the signer either, so the protocol was already down,
and one extra round trip per CMP transaction is nothing beside the signing round trips in the
same transaction.

Kerberos realm keys are not like that. They are read on **every** MSAE authentication — every
Windows autoenrollment request, at machine-account scale, on a schedule the domain sets and not
us. Putting the signer in that path makes an unreachable signer into a domain-wide authentication
outage rather than an issuance outage, and makes the signer's throughput the ceiling on
autoenrollment. So the caching story has to be decided before that column moves, and this is what
it should be: the realm key is unwrapped once and held in the node's memory, per realm, with a
bounded lifetime (minutes) and a refresh that fails soft — an unreachable signer keeps serving
from the cached key until the entry expires, and only then does authentication stop. That is the
opposite of the fail-closed rule for signing, deliberately: a signature is a new artifact the
world will trust, and a Kerberos acceptor check is a door that was already open.

And the part that cannot be engineered away: **caching a decrypted secret puts plaintext back in
the node's memory.** So does using it once without caching. The node has to compute a MAC, so the
node has to hold the key, so an attacker with code execution on a running node gets every secret
that node uses while they are there. Caching only widens the window from "during the request" to
"for the cache's lifetime". It is a real cost and it is chosen, not overlooked.

### What this buys, and what it does not

Wrapping protects these columns **at rest**, and only at rest. A stolen database is now useless
without the keystore; a stolen database plus a stolen node is now useless too, where before it was
enough. What it does not buy: a live compromised node can ask the signer to unwrap anything its
purpose permits, for as long as it is compromised, exactly as it can ask for signatures — bounded
by the policy table, recorded in the signer's audit, and not prevented. And once unwrapped, the
secret is plaintext in the node's memory because that is the only place it can be used. This moves
a class of offline attack out of reach. It does nothing about online ones.
