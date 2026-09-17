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
| **control plane** | console, admin API, tenants, principals, ceremonies, audit, the fleet module | database, signer for ceremonies |
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
hostname keys (PKCS#12 files owned by the ingress/TLS layer), the Kerberos realm keys (symmetric,
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
(certificate, CRL, OCSP, SCEP, CMP, TSA, ceremony, backup, export) and the tenant and CA the
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
- Re-download of server-generated private keys ends. A key the CA generates is delivered once,
  in the response that carries the certificate, and never stored; the console's key-generation
  form says so. Keys already stored expire in place behind the signer's export policy and are
  not migrated.
- The signer's audit is its own table in the shared database.

## Stage 1 as built (2026-09-17)

Stage 1 is complete on `0.3.0-dev`: seventeen commits from `6c0c8fc` to `fad9d08`, the suite at
1549 tests, and an architecture test that fails the build if any type in Core, API, Auth or
Bootstrap references a key handle, the key registry, the keystore persistence, or any keystore
member returning key parameters. Where the code differs from the design above, the code is right
and this section records why.

- **`CommitKeyAsync` joined the contract.** A generated key is held pending in the signer's memory
  under a signer-minted reference and signs only under the purpose, tenant and CA it was generated
  for. It is written to the keystore and bound to its certificate row by an explicit, audited
  commit after the CA's database transaction succeeds; any failure before that retires it, so a
  failed creation leaves nothing usable on disk. The keystore format has no entry removal, which
  is why the write waits for the commit. Each commit rewrites the keystore file, so creating a CA
  costs three rewrites today; a batched commit is a later convenience.
- **Server-generated keys travel with the request, not the certificate.** Every server-side
  key-generation flow is approval-gated, so the certificate does not exist when the key is made.
  The key is returned once, as PEM beside the CSR, and never stored. Keys stored before this
  change are carried on their rows as ciphertext and exportable until they expire; renewals no
  longer carry them forward. The clear-text PEM export is withdrawn; export is PKCS#12 only.
- **Backups carry whole keystore files.** The signer exports and imports keystore files as units
  (`SigningPurpose.Backup` and `Restore`), verified on import against the pinned signer. Per-key
  restore was rejected because the key that signs the keystore file is one of the keys being
  restored. These two operations are permitted while the signer is locked, since they hand out no
  usable key and restoring into an empty node is how a signer comes to hold keys.
- **Locked means unavailable, visibly.** Enrollment protocol controllers and admin issuance answer
  503 with a retry hint until the signer reports unlocked; the health endpoint and the MSAE
  readiness page both show the signer's state.
- **Stricter than the table.** Every key is held to its owning CA and, when named, its tenant; a
  CA certificate without a CA row cannot sign; an audit-write failure does not withhold a
  signature in process, which stage 2 must change to fail closed at the signer.

Follow-ups found on the way, not part of stage 1: the automatic renewal job's rekey path
generates a key it then discards; bootstrap still writes CA-key wraps onto certificate rows.
