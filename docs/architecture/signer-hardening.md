# Signer hardening

Status: draft, for owner review (2026-10-05). Nothing here is built.

## Why

`signer-separation.md` moved the keys out of the node. Three things the node can still reach undo
part of that:

1. **Ceremony approvals are rows the node writes.** The signer believes a key operation was
   approved because a row says so.
2. **The signer's record of what it signed lives in the node's database.** It is restored, with
   the database, to whatever the backup held.
3. **The node's secrets sit in plaintext in `config.yaml`**, and every backup carries the file.

The rule for all three: **a compromised node must not be able to make the signer misuse a key.**
A compromised node can still ask for ordinary signatures while it is compromised. That is accepted
in `signer-separation.md` and is not changed here. What changes is that the node can no longer
forge the authority for the operations that matter, rewrite the record of what was signed, or
read the instance's secrets from a disk or an archive.

## Decisions in one place

1. **The signer types what it signs.** It parses the bytes for every purpose. A `cA=TRUE`
   certificate, and an OCSP-signing certificate for a key the signer does not hold, need verified
   evidence. Today a label on the request is the only check.
2. **An approval is a WebAuthn assertion over a canonical statement**, and the signer checks it
   against an approver registry the signer holds. Rows in `KeyCeremonies` stay the workflow.
   They stop being the evidence.
3. **The approver registry is a signer-side file, signed by the instance key.** It is changed
   only by ceremonies the current registry approves, or by a command on the signer's host. Trust
   in the first approvers is trust on first use, at setup or at migration.
4. **Ceremony policy moves into the signer too**: whether a scope requires ceremonies, its
   quorum, and the scope each key belongs to. The database can no longer waive a ceremony.
5. **Evidence is generic.** A kind, a closed set of bindings the core understands, a trust set
   and a threshold, all held in the registry. HA kinds such as member enrolment and wrapping a
   key to a recipient need no core code.
6. **The signer keeps an append-only journal on its own disk.** It is hash-chained, with
   checkpoints signed by the member's system key. It holds the full TBS of every certificate and
   every changed CRL, a summary of OCSP per minute, and every key and ceremony operation.
   Restoring the database never touches it.
7. **After a restore, the journal is replayed.** Certificates issued since the backup are adopted
   and revocations made since are reapplied. Today they are lost silently.
8. **Node secrets move to the settings store** (`settings-store.md`), each wrapped by the signer
   with its setting name bound into the ciphertext. API keys become hashes. What a process needs
   in order to reach the database or the signer stays in host files, and the signer's own secrets
   stay in the signer's own directory.

## Owner decisions (2026-10-05)

- **TOTP approvals stay allowed, alongside passkeys.** The signer can only verify a code it can
  recompute, so each approver's TOTP seed is enrolled into the signer's registry, separately from
  the sign-in seed the node holds. A TOTP code does not bind the operation the way a WebAuthn
  assertion over the statement digest does: a compromised node can submit a fresh code for a
  different operation within the code's window. Each piece of evidence records its method, codes
  are single-use per approver and statement, and the registry can require passkeys per scope.
  Passkeys remain the recommended method.
- **External OCSP responders are allowed, with a ceremony.** An OCSP-signing certificate for a key
  the signer does not hold needs verified evidence; one for a signer-held responder key does not.
- **The JWT secret lives in the settings store, wrapped by the signer** (see `settings-store.md`).

## Item 1: ceremony approvals the signer can verify

### Where it stands

- **The ceremony check reads node-written rows.** `InProcessSigningService.cs:705-778`
  (`JudgeCeremonyAsync`) loads the `KeyCeremonies` row the context names. It accepts it when
  `Status == "Approved"`, `ExpiresAt` is in the future, `OperationType` is in
  `KeyManagementCeremonies`, the space matches, and `TargetEntityId` is the context's CA.
- **The approvals are JSON in that row.** `KeyCeremonyService.cs:88-134` appends
  `{userId, username, timestamp}` to `ApprovalsJson` and sets `Status = "Approved"` when the count
  reaches `RequiredApprovals`. Self-approval is refused in the node (`:103`). No approval carries
  anything the signer can check.
- **The node owns every table.** The application database is created owned by the app role
  (`PostgresRoleLayout.cs:390-391`). The signer connects with the same connection string
  (`SignerRole.cs:124-125`), so the signer has full DML rights rather than read access to the
  ceremony tables. A compromised node can insert an `Approved` row with any `OperationType`,
  space and target it likes.
- **The policy is node-written too.** The signer resolves `RequireKeyCeremony` and the quorum from
  `SecurityPolicies` and `Spaces` rows (`:789-801`, `SecurityPolicyEntity.cs:166-169`,
  `SpaceEntity.cs:102-109`). A system-super can already turn the instance requirement off with
  step-up only (`AdminSecurityPolicyController.cs:77-79`). A node with database access does not
  need the step-up.
- **The scope of a key is node-written.** The space a CA belongs to, and the kind of each key, come
  from `CertificateAuthorities` and `Certificates` rows (`ClassifyAsync`, `:1349-1389`). Moving a
  CA row into a space that waives ceremonies waives them for that CA.
- **The kinds are hard-coded.** `KeyManagementCeremonies` is `{ "CreateRootCA",
  "CreateIntermediateCA" }` (`:683`). `CreateSshCa` is not in it (`ssh-keystore.md` adds it).
  Nothing the HA module needs can be expressed.
- **`Infrastructure` is exempt.** `JudgeKeyManagement` (`:672-680`) admits it, and
  `JudgeCeremonyAsync` returns early for every purpose but `Ceremony`. Responder, TSA and CMP keys
  are made at CA creation and at reissue (`CaCreationService.cs:983`, `:1542-1544`) with no
  ceremony. Only the commit is held to a non-CA certificate (`:297`).
- **The doc claims more than the code does.** `signer-separation.md:170-172` says the signer
  verifies approvals "against signed audit rows, not against mutable state". There are no signed
  audit rows. The audit chain (`AuditHashChainService`) is an unkeyed SHA-256 chain in a database
  the node also writes. This design replaces that sentence.

### The larger hole: the signer does not look at what it signs

`SignAsync` (`:114-131`) hashes the data for the audit and signs it. `JudgeSign` (`:611-630`) checks
the key's kind, the purpose label and the owner. It never parses the bytes. So:

- **A compromised node can get a subordinate CA certificate signed by any CA key**, for a key of
  its own, under `SigningPurpose.Certificate`. No ceremony row is needed, forged or otherwise. The
  node-side guard that keeps CA profiles off enrolment paths
  (`CertificateIssuanceService.cs:225-232`) is not a guard against the node.
- **The purpose label constrains nothing.** A CA key may sign under `Certificate`, `Crl`, `Ocsp`,
  `Scep` and `Cmp`. A TBSCertificate submitted under `Ocsp` is signed just the same.
- **It can get a delegated OCSP-signing certificate signed for a key of its own.** It can then
  answer "good" for every revoked certificate of that CA, from anywhere, for the life of that
  certificate.

Gating key generation with verified approvals is worth little while this stays open. A node that
cannot create a CA key can still create a CA. So typed signing comes first.

### Typed signing

For a key of kind `Ca`, the signer parses the data before it signs:

| Purpose | The data must parse as | Further rule |
|---|---|---|
| `Certificate` | a v3 `TBSCertificate` | `cA=TRUE` or `keyCertSign` needs evidence (below). `id-kp-OCSPSigning` needs the subject key to be an infrastructure key the signer holds for this CA, pending or committed. The `signature` field names the algorithm requested |
| `Crl` | a `TBSCertList` | the issuer is this CA's subject. Journaled (Item 2) |
| `Ocsp` | a `ResponseData` | the responder ID is this CA or its responder |
| `Scep`, `Cmp` | anything that does **not** parse as a `TBSCertificate` or a `TBSCertList` | none |

An OCSP responder key signs only `ResponseData`. A TSA key signs only CMS signed attributes, which
are a DER `SET` and so can never parse as a TBS structure. A v1 or v2 `TBSCertificate` is refused
outright, since some verifiers treat v1 certificates as CAs.

The evidence a `cA=TRUE` signature needs binds the subject public key and the subject name. For a
new intermediate, that is the same evidence that licensed generating its key. For cross-certifying
an external key, it is a ceremony naming that key. No path today reissues a CA certificate over an
existing key: certificate reissue refuses CA profiles (`CertificateIssuanceService.cs:636`). A
future one, such as CA certificate renewal, needs a ceremony naming that key as well.

This also settles `Infrastructure` without a ceremony. A delegated certificate is safe to issue
when its key never leaves the signer, and typed signing makes that the rule. Reissuing a responder
stays an operator's action.

### Evidence: a statement and the signatures over it

A ceremony is **opened at the signer**. The node sends the kind, the bindings and a
human-readable description. The signer returns a **statement**: deterministic CBOR
(`System.Formats.Cbor` in `Ctap2Canonical` mode, already in the dependency graph through Fido2):

```
statement = {
  v: 1,
  instance:  SHA-256 of the instance key's SPKI        ; not valid on another instance
  id:        16 random bytes, minted by the signer
  kind:      "ca.key.create" | "ca.cross-certify" | ... | a registered module kind
  scope:     null (instance) | space id
  bindings:  { name: bytes, ... }                     ; the closed set below
  detail:    SHA-256 of the description shown to approvers
  initiator: approver id
  quorum:    approvals required when opened
  epoch:     approver registry epoch when opened
  opened:    time
  notAfter:  time                                    ; at most 24 h, as today
}
digest = SHA-256("ModularCA.Ceremony.v1\0" || statement)
```

The signer journals the opening (Item 2). Each person signs `digest` as the WebAuthn challenge:
`navigator.credentials.get({ challenge: digest, allowCredentials: [their approval credentials],
userVerification: "required" })`. The initiator signs at opening and each approver signs on
approval. The assertions are stored with the ceremony row. They verify themselves, so where they
are stored does not matter.

To execute, the node sends the statement and the assertions in the `SigningContext` of the
operation. The signer accepts them when **all** of these hold:

- it opened the statement, the statement is not expired, and it has not been consumed (the
  journal says);
- the kind licenses this operation and every binding the operation needs matches the request;
- for each assertion:
  - the credential is active in the registry for the statement's scope;
  - `authenticatorData.rpIdHash` is SHA-256 of the registry's relying-party ID;
  - the UP and UV flags are set;
  - `clientDataJSON.type` is `webauthn.get`, its `challenge` is `digest`, and its `origin` is
    one of the registry's origins;
  - the signature over `authenticatorData || SHA-256(clientDataJSON)` verifies under the
    credential's COSE key (ES256, EdDSA or RS256);
  - a non-zero sign counter is above the last one the signer saw for that credential;
- the quorum rule below.

The statement is then **consumed** in the journal. One statement executes once. Since the journal
is not in the database, restoring an older database does not make an executed approval usable
again.

### Quorum

- **One person counts once.** The signer counts distinct approver ids, not credentials.
- **The initiator never counts.** The initiator must be a registered approver and must sign. The
  signer then requires `quorum` further approvers, all different from the initiator. That is the
  rule the node already applies (`KeyCeremonyService.cs:103`), now enforced where the node cannot
  lie about who initiated. A quorum of 1 needs one person other than the initiator. A quorum of 0
  is not representable.
- **The quorum applied is the higher one.** A ceremony needs `max(statement.quorum, current
  quorum for the scope)`. Approvers must be in the registry **now**: someone removed after
  approving no longer counts.

### Who the signer trusts: the approver registry

The signer cannot trust `Fido2Credentials.PublicKey` (`Fido2CredentialEntity.cs:31`). A
compromised node would add its own credential to the table and approve with it. So the signer
keeps its own registry, `approvers.registry`, in its own directory. It is CBOR, signed by the
instance key, and carries a monotonic epoch:

- **Relying party**: the relying-party ID and the accepted origins. Today these are
  `Https.PublicDomain` and its origin (`StartModularCA.cs:1233-1247`). With HA they become the set
  in `member-names-and-passkeys.md`.
- **Approvers**: an id (the user id), a display name, one or more credentials (credential ID,
  COSE public key, last sign count), and the scopes they may approve for.
- **Policy per scope**: whether key management requires a ceremony, and the quorum. Scopes not
  listed get the instance's policy. A space the node creates later is therefore strict until a
  ceremony says otherwise.
- **Key scopes**: for every key the signer holds, the scope it was committed under. Policy reads
  the scope from here and never from `CertificateAuthorities.SpaceId`.
- **Kinds**: each kind's trust set, threshold and the operations and bindings it licenses
  (below).

It is signed by the instance key, not just kept under file permissions, for two reasons. In a pair
both members hold the instance key (`instance-secret-wrap-key.md`), so a registry change made on
one member verifies on the other. And a registry copied in from a backup or another host is
refused unless it verifies under this instance's key.

**Changing it.** The registry changes through ceremonies of kind `approvers.change` and
`policy.change`, verified against the current registry at the instance quorum. Adding an approver
also needs the new approver's own assertion over the statement, as proof that they hold the
credential. Lowering a quorum, or waiving ceremonies for a scope, therefore needs the current
quorum. Every change is journaled.

**The host is always trusted.** A command on the signer's host (`--role signer --approvers ...`)
can list, add and remove approvers and change policy, with no ceremony. Anyone with that access can
already read the keystore passphrases, so this adds no power. It is the recovery path when
approvers are lost, and the bootstrap path.

### Bootstrap

The first approvers are trusted on first use. There is no other honest answer. Anything the node
relays at bootstrap, the node could have substituted.

- **New install, single process.** The setup wizard enrols the first administrator's passkey as
  the first approver and writes the registry before setup ends. The trust anchor is the person who
  installed the product, at a moment when nothing is exposed.
- **Split install or existing install.** An administrator runs approver enrolment in the console.
  The node produces an enrolment file: the candidates, their credentials and the policy taken from
  the database. On the signer host, `--role signer --approvers adopt <file>` prints each name with
  a credential fingerprint and writes the registry. Each approver then signs a test statement, so
  everyone sees their own approval verify before verified mode is switched on.
- **Until a registry exists**, the signer behaves as today: it reads the database rows, and the
  readiness page says "ceremony approvals are not verified by the signer". **Once a registry
  exists, the signer never falls back.** Deleting the file on the signer host is the only way
  back.

This protects against a node compromised **after** enrolment. Against a node already compromised
at enrolment it does nothing. That is the same bargain as every SPKI pin in this product.

### Kinds the core does not hard-code

A kind is data in the registry, not code in the signer:

```
kind "ha.member-enrol":
  trust:     approvers(instance)          ; or pinned-keys(hub-witnesses), or pinned-keys(peer-member)
  threshold: policy(instance).quorum      ; or a number
  licenses:  WrapKeyTo  requires binding recipient-kem-spki-sha256
```

- **Bindings are a closed set the core defines:**
  - `scope`, `ca-id` and `key-ref`;
  - `key-spec` and `public-key-sha256` (SPKI);
  - `subject-dn-sha256`;
  - `recipient-kem-spki-sha256`;
  - `member-id` and `term`.

  A module kind may carry more in `detail`, and that is covered by the digest, but the signer
  enforces only bindings it understands.
- **Trust sets** are the approver registry for a scope, or a set of pinned keys: the hub keys
  from `hub-enrolment.md`, the peer member's system key. For a pinned-key set the evidence is
  plain signatures over `digest` rather than WebAuthn assertions.
- **The kinds the core ships**:
  - `ca.key.create`, `ca.key.import` and `ca.cross-certify`;
  - `ssh.key.create`;
  - `approvers.change` and `policy.change`.
- **A module's kinds are added to the registry by a `policy.change` ceremony**, or by the host
  command. A compromised node cannot introduce a permissive kind.
- **`VerifyEvidence` is exposed on its own**, so a module can have the signer verify a decision
  that licenses no key operation. The signer journals the verification.

### Which operations need evidence

| Operation | Evidence | Notes |
|---|---|---|
| `GenerateKey`, `CommitKey`, `ImportKey` for a CA or SSH CA key | `ca.key.create`, `ca.key.import`, `ssh.key.create` | Unless the key's scope waives ceremonies in the registry |
| `Sign` of a `cA=TRUE` TBS | the same `ca.key.create` (matching SPKI and subject), or `ca.cross-certify` | Also any future renewal of a CA certificate over its existing key |
| `Sign` of an OCSP-signing certificate | none, if the key is the signer's infrastructure key for this CA; otherwise refused | This is the `Infrastructure` answer |
| Infrastructure `GenerateKey` and `CommitKey` | none | Bound to a CA the signer has a scope for |
| `ExportKey` (PKCS#12, legacy stored end-entity keys) | none; rate-limited and journaled | See below |
| `WrapKeyTo` (HA replication) | `ha.member-enrol` binding the recipient | A module kind |
| `Unlock` on evidence (HA) | `ha.unlock` binding member and term | A module kind, trust set hub witnesses or the peer's handover |
| Registry changes | `approvers.change`, `policy.change` | At the instance quorum |

**PKCS#12 export stays without a ceremony.** The callers are holders downloading their own key
(`UserCertificateController.cs:264` to `CertificateExportService.cs:82-104`). A quorum of
administrators for a self-service download is wrong, and the holder is not in any registry the
signer could trust. Two things bound this instead:

- the signer rate-limits `ExportKey` per hour (signer configuration, not node configuration) and
  journals every export;
- the stored keys are legacy and expiring. `Signer.LegacyKeyExportUntil`, a date in the signer's
  own configuration, ends export entirely.

Keys held for delivery (`HeldKeyService.cs:303-304`) are still under Data Protection on the node,
so the signer cannot gate them at all until they move to the secret wrap with their row bound in
(the envelope v2 in Item 3 supplies that).

**Spaces that waive ceremonies.** A waiver is a registry entry made by `policy.change` or on the
host. Keys committed under a waived scope are recorded with that scope. They cannot be used to
reach a stricter one, because the scope comes from the registry and not from a database row. A
waived scope gets no protection from this design against a compromised node, and the console says
so beside the switch.

### What approvers have to do

- **A passkey is required to initiate or approve key-management ceremonies** once verified mode
  is on. Approval today accepts TOTP or WebAuthn step-up (`MfaStepUpController.cs:111-172`,
  `:221-339`), with a random challenge (`:198-204`) that binds nothing. TOTP cannot become signer
  evidence: the TOTP seed is stored, under Data Protection, on the node, so a compromised node can
  compute every approver's codes.
- **An existing login passkey can be enrolled.** No new device is needed. The assertion replaces
  the separate step-up for approval: it is the step-up.
- **The other ceremony types keep TOTP**: controlled-user changes and policy changes the node
  owns. They touch no key.
- **WebAuthn must be on.** `WebAuthn.Enabled` defaults to true (`SystemConfig.cs:1278`), and
  `EnforceForGroups` defaults to empty (`:1289`). An install with WebAuthn off cannot use
  verified mode.
- **The console shows, per scope, how many eligible approvers have a passkey.** Verified mode
  cannot be switched on for a scope with fewer than quorum + 1.
- **Renaming `Https.PublicDomain` orphans every approval credential**, as it orphans every login
  passkey. The registry's relying party is changed only by `policy.change`.

### What this does not fix

**The console is served by the node.** A compromised node controls the page an approver approves
on. It can show one statement and have the browser sign the digest of another. WebAuthn has no
way to display what is being signed. What the design still buys:

- every approval costs a real person's gesture;
- an attacker needs quorum + 1 people tricked during real approvals;
- the statement is journaled at the signer when it is opened, so the record of what was actually
  approved cannot be rewritten.

The full fix is approving on something the node does not serve: the Hub's console, a separate
approval page served by the signer host, or a hardware key that can display a transaction. That
is an open question below.

### Alternatives rejected

- **A separate database role for the signer.** The node still writes the rows the signer reads.
  Privileges cannot fix provenance.
- **Signing the ceremony rows with a node key.** The node is the attacker.
- **Trusting `Fido2Credentials` rows.** The node writes them.
- **TOTP evidence.** The node holds the seeds.
- **mTLS client certificates as evidence.** TLS terminates at the node (or the ingress), so the
  signer never sees the handshake. A CMS signature by an approver's own certificate, made with an
  offline tool, would work, and is kept as a possible second evidence format. It is not in the
  first stage.
- **Hard-coding the HA kinds in the core.** `ARCHITECTURE-OPEN-CORE.md` allows no hole for private
  code, and the module's kinds change on the module's schedule.

### Signer contract changes

```proto
service Signer {
  // ... existing calls ...
  rpc OpenCeremony (OpenCeremonyRequest) returns (OpenCeremonyResponse);
  rpc VerifyEvidence (VerifyEvidenceRequest) returns (VerifyEvidenceResponse);
  rpc ApplyRegistryChange (ApplyRegistryChangeRequest) returns (ApplyRegistryChangeResponse);
  rpc GetRegistry (GetRegistryRequest) returns (GetRegistryResponse);  // public view, for the console
}

message Binding { string name = 1; bytes value = 2; }

message OpenCeremonyRequest {
  string kind = 1;
  repeated Binding bindings = 2;
  string description = 3;        // shown to approvers; its hash is in the statement
  string initiator = 4;          // approver id
  int64 not_after = 5;
  SigningContext context = 6;
}
message OpenCeremonyResponse { bytes statement = 1; bytes digest = 2; }

message Assertion {
  bytes credential_id = 1;
  bytes authenticator_data = 2;
  bytes client_data_json = 3;
  bytes signature = 4;
}
message KeySignature { bytes key_id = 1; bytes signature = 2; }   // pinned-key trust sets

message Evidence {
  bytes statement = 1;
  repeated Assertion assertions = 2;
  repeated KeySignature signatures = 3;
}

message SigningContext {
  // ... fields 1-6 unchanged ...
  Evidence evidence = 7;         // replaces ceremony_id as the authority; ceremony_id stays for linkage
}

message VerifyEvidenceRequest { Evidence evidence = 1; bool consume = 2; SigningContext context = 3; }
message VerifyEvidenceResponse { string kind = 1; repeated Binding bindings = 2; repeated string approvers = 3; }
```

New refusal reasons: `EvidenceRequired`, `EvidenceInvalid` (with which check failed),
`EvidenceConsumed`, `QuorumNotMet` and `UntypedData`. The audit row and the journal record which
one applied.

### Migration

- **Stage A (typed signing)** needs no data migration. `CaCreationService` passes the ceremony to
  the parent CA's signing context when it issues an intermediate. Until Stage B, the database row
  is what is checked, as today. A `cA=TRUE` TBS signed with no ceremony named and no waiver is
  refused. The upgrade check lists CA certificates issued outside a ceremony in the last year, so
  an operator knows whether any workflow depended on that.
- **Stage B (verified approvals)** is opt-in per install. Enrolment and adoption are as described
  under Bootstrap. The adoption also snapshots every key's scope from the database into the
  registry, on the same trust-on-first-use footing. Ceremonies open at the time of the switch are
  cancelled and must be re-initiated, because they have no statement.
- **Stage C** makes verified mode the default for new installs and moves the policy fully into
  the registry. Database policy fields become a read-only mirror the signer writes back through
  the node's API for display.

### Effort

L overall:

- **Stage A, M**: the parsers, the rules, the callers, and a contract suite with deliberate
  breaks: an unparsed `Sign` allowed, `cA=TRUE` without evidence, an OCSP-signing certificate for
  an outside key, a TBS under `Ocsp`.
- **Stage B, L**: the statement, the WebAuthn verifier, the registry, the host commands, the
  console approval flow and enrolment.
- **Stage C, M**: registry-held policy and key scopes, module kinds, and `VerifyEvidence`.

### Open questions

1. Approve typed signing for 0.4.1, including that **any `cA=TRUE` signature needs a ceremony or a
   signer-held waiver**, which rules out a future CA renewal path without one?
2. **An OCSP-signing certificate only for a signer-held key.** Does any customer need an external
   delegated responder? If so, it becomes `ca.cross-certify`-style evidence.
3. **The initiator must be a registered approver and must sign** (recommended). The alternative
   lets anyone initiate, at the cost of trusting the node about who initiated.
4. **TOTP-only administrators cannot initiate or approve key ceremonies** in verified mode.
   Accept?
5. **Bootstrap by trust on first use**, at setup or at adoption, with the signer-host command as
   the anchor and the recovery path. Accept?
6. **Approval phishing by a compromised console.** Accept the limit for now, or put approval on a
   surface the node does not serve (the Hub, or the signer host) in Stage C?
7. **Should a hub ever count toward a key quorum?** Recommended: no. Hubs only appear in unlock
   trust sets.
8. **A date for `Signer.LegacyKeyExportUntil`** on existing installs, or leave it unset?

## Item 2: a signer-local issuance journal

### Where it stands

- **One row per decision in the node's database.** `SignerAudit` (`SignerAuditEntity.cs`) holds
  the operation, context, outcome and `DataHash`, SHA-256 of the signed bytes (`:84-86`). The
  insert is `DatabaseSignerAuditSink.cs:23-30`.
- **Unchained and unsigned.** Nothing links one row to the next. A node with database access can
  delete or rewrite any row.
- **Restored with the database.** A restore brings back the backup's rows and loses every
  decision since.
- **Not enough to rebuild anything.** A hash is not the certificate, and the signer keeps nothing
  else.
- **Unpruned and per OCSP response.** Every OCSP response is a fresh signature
  (`OcspResponderService.cs:369`) and so a fresh row. The table grows with OCSP traffic and has no
  retention.
- **Fail closed in the signer role.** An audit insert that fails refuses the operation
  (`InProcessSigningService.cs:1416-1437`, `SignerRole.cs:138-147`). So the signer's availability
  is already tied to a table the node owns.

What a restore does today:

- **Every certificate issued after the backup is unknown.** For an issuer the instance is
  authoritative for, OCSP answers "revoked, certificateHold, 1970" for an unknown serial
  (`OcspResponderService.cs:283-295`). A valid certificate issued an hour before the failure
  becomes revoked to every relying party that checks.
- **Every revocation made after the backup is undone.** The next CRL omits them. The CRL number
  is floored at the restore time (`BackupRestore.cs:795-797`, `:906-915`), so numbering is safe,
  but the content goes backwards. Nothing tells the operator.

### The threat

Two different ones:

- **Losing the record by accident.** The database is restored from an older backup, or lost.
- **Rewriting the record.** A compromised node edits or deletes what the signer recorded about
  what it was made to sign.

A journal the node cannot write, on a disk the database restore does not touch, answers both on a
split install. On a single-process install it answers the first only (see "Where it lives").

### Format

The journal is a directory of segment files: `journal/<member>/<segment>.mcaj`.

```
record = length (u32) | body | hash (32)
body   = "MCAJ" | version (1) | seq (u64) | at (i64, µs UTC) | type (u8) | prev (32) | payload (CBOR)
hash   = SHA-256(body)                 ; prev is the hash of record seq-1
```

- **Chained**: each record names the hash of the one before it. The first record of a journal is
  a `Genesis`. It names the member, the instance and, after a host move, the head of the journal
  it continues.
- **Signed at checkpoints, not per record.** A `Checkpoint` record carries a signature, by the
  member's system key, over `"ModularCA.Journal.Checkpoint.v1\0" || member || seq || prev`. That
  covers the whole chain before it. One is written every second there was activity, or every
  1,000 records, whichever comes first.
  - The domain prefix keeps a checkpoint signature from being mistaken for a keystore-file
    signature, which the same key makes.
  - The member's key is used and not the instance key, because in a pair both members hold the
    instance key, and one member must not be able to forge the other's journal.
- **A tail after the last checkpoint is chained but not yet signed.** Truncating it is detectable
  only against a later checkpoint or an off-host copy. The interval keeps that tail to about a
  second.
- **Sealed segments.** A segment is sealed by a `Seal` record, a final checkpoint, when it reaches
  64 MiB or 24 hours. It is then compressed (Brotli, in the box), made read-only, and never
  written again.
- **Fail closed.** In the signer role, an operation whose record cannot be appended is refused. The
  journal takes over that duty from the `SignerAudit` insert. Appends are group-committed: one
  `fsync` per batch, at most 5 ms or 64 KiB, and a signature leaves the signer only after the
  `fsync` that covers its record.

### What is recorded

| Operation | Recorded |
|---|---|
| `Sign`, purpose `Certificate` | the context; the **full TBS** and the signature, so the certificate can be rebuilt byte for byte; an index of serial, issuer, subject hash, SPKI hash, validity and `cA` |
| `Sign`, purpose `Crl` | the context, CRL number, `thisUpdate` and `nextUpdate`; the **full TBS** when the revoked set changed since the previous CRL of that CA, otherwise a reference to the record that holds the same set and the TBS hash; the signature |
| `Sign`, purpose `Ocsp` | **summarised**: one record per responder key per minute, with count, a histogram of good, revoked and unknown, and an accumulator (a SHA-256 chain over each `ResponseData` hash) |
| `Sign` for `Scep`, `Cmp`, `Tsa` | the context, the data hash and the signature hash |
| Key operations: generate, commit, import, retire, export, wrap-to, take-in | the context, key ref, public key hash, keystore, evidence id; never key material |
| Secret wrap and unwrap | as the audit row: kind, key id, blob hash; never the plaintext or its hash |
| Ceremonies | opened (the statement), verified, consumed, refused |
| Registry changes, lock, unlock, lease and term (HA) | the change and its evidence |
| Facts the node asserts (`RecordFact`) | revocations at the time they are made, restore markers; marked as node-asserted |
| Refusals | everything the audit row has |

**Revocations are recorded as facts as they happen**, not only when the next CRL is signed. The
node calls `RecordFact(Revocation)` after its transaction commits, so a rolled-back revocation is
never recorded. A failed call is retried from a queue, and the next CRL closes any gap. A
compromised node can assert a false revocation. Revocation is fail-safe, and such a node could
revoke through the console anyway.

**OCSP is summarised, not journaled per response.** A modest responder at 200 responses a second
would write 17 million records a day. The summary keeps what an investigation needs: how much was
signed, of what status, and an accumulator against which a full log kept elsewhere can be checked.
Summaries are written each minute from memory, so a crash loses up to a minute of OCSP counts. It
loses no certificate or CRL. If the summary cannot be written, OCSP is refused until it can. When
OCSP responses are pre-signed per serial (a separate, later change), the volume drops to the
number of live certificates per refresh, and per-response journaling becomes affordable.

### Size and performance

| Record | Typical size |
|---|---|
| Certificate, RSA or ECDSA | 1.5–3 KB |
| Certificate, ML-DSA-65 | 7–9 KB (public key 1,952 bytes, signature 3,309) |
| CRL, revoked set changed | the TBS: about 40 bytes per entry |
| CRL, revoked set unchanged | about 300 bytes |
| OCSP summary | about 200 bytes per responder per minute (290 KB a day) |
| Checkpoint | about 150 bytes plus the signature |

- **A private CA issuing 10,000 certificates a day** writes about 30 MB a day before compression,
  about 11 GB a year.
- **A CA with 100,000 revoked serials and an hourly CRL** writes 4 MB per CRL only on the hours
  when a revocation happened.
- **Compression** of sealed segments saves roughly a third. Serial numbers and signatures do not
  compress.
- **Cost on the hot path**: one append to a memory buffer and a wait of at most 5 ms for the
  batch `fsync` on issuance. OCSP does not wait. At thousands of OCSP responses a second, the
  per-response work is one `ResponseData` parse, which typed signing does anyway, and one hash.
- **The database gets lighter.** `SignerAudit` stops taking a row per OCSP response (below).

### Where it lives

| Install | Location | What it protects against |
|---|---|---|
| Single process | `journal/` beside `keystores/`, owned by the service account | Database restore and database loss. **Not a process compromise**: the same process holds the signing key and the file |
| Split, two units | the signer's data directory, owned by the signer's account, `0700` | Restore, loss, and a compromised node, which has no access to the host path |
| Pod | the signer's own volume, the one that holds the keystores; the node never mounts it | As split |
| HSM | as split; checkpoints are signed on the token if the member key is there | As split |

**Off-host copies are opt-in.** Each checkpoint (sequence, head hash, signature) can be written to
the signer's log, so syslog or journald forwarding carries the heads. That is about 100 bytes a
second at most. A truncated tail is then provable against the forwarded heads. It is on by
default, since it costs nothing.

### Rotation and retention

- **Segments rotate** at 64 MiB or 24 hours.
- **Retention is set in the signer's configuration, never the node's**: `Journal.RetainDays`,
  default `0`, meaning keep everything. Pruning removes whole sealed segments older than that,
  never the active segment or the newest two. It writes a `Pruned` record naming the hash of the
  last record removed, as `AuditChainPruned` does for the audit chain, so verification starts an
  epoch there.
- **The node cannot prune**, and no RPC deletes anything.

### Reading it

- **`ReadJournal`** pages through records from a sequence number. A request takes at most 1,000
  records or 4 MiB, with filters by record type and CA. The response carries the raw record bytes
  and the latest checkpoint, so the reader verifies the chain itself. Nothing is taken on the
  signer's word.
- **`JournalHead`** returns the member, the sequence, the head hash and the latest signed
  checkpoint.
- **A new purpose, `JournalRead`**, is permitted to the control role's caller. The journal holds
  no secret by construction, so there is nothing finer to separate.
- **On the signer host**, `--role signer --journal verify` checks the chain and every checkpoint,
  and `--journal export <from> <to>` writes sealed segments for an auditor. A verifier in
  `ModularCA.Shared` does the same offline from the exported files and the member's certificate.
- **The console** gets a "Signer journal" page under the audit section: the head, the last
  verification, a filtered list, and a comparison against `SignerAudit` that marks rows the
  journal does not have and records the database does not have.

### What it feeds

**Post-restore recovery.**

1. Every backup asks for `JournalHead` before it dumps the database, and writes it into the
   manifest. Records written during the dump may already be in it, and adoption is idempotent.
2. A restore never writes the live journal. On a host that already has a journal, the restored
   database meets the journal that kept running.
3. At the first start after a restore, the control role reads the journal from the manifest's
   head:
   - **Certificates.** Every certificate record whose serial is not in the database is rebuilt
     from TBS and signature, checked under the CA's public key, and inserted as **adopted from the
     journal**: issued, requester unknown, flagged for review. OCSP stops calling them revoked.
   - **Revocations.** Every revocation fact, and every serial on the newest journaled CRL of each
     CA, that is not revoked in the database is reapplied. Revoked wins and the earliest date wins,
     the rules in `reconciliation-services.md`.
   - **CRL numbers.** The next CRL number is the highest journaled number plus one. This replaces
     the time-derived floor whenever the journal reaches back far enough.
   - **Keys.** A key generated after the backup is not in the restored keystore files. The journal
     cannot bring it back, and must not hold key material. The report names each such key and its
     CA, and says what to do: retire the CA, or restore a newer keystore.
4. The console shows one report: N certificates adopted, M revocations reapplied, K keys missing.
   The report is also written to the audit log and as a `RecordFact(RestoreRecovered)` in the
   journal.

On a new host whose journal was lost with the old one, the archive's copy of the sealed segments
(see Backup) is installed as the starting journal. Recovery then reaches as far as the last
segment sealed before the backup, and no further. The report says so.

**Warm-standby adoption after a failover.** Streaming replication is asynchronous unless
configured otherwise, so a promoted standby's database can lack the active's last seconds. The
active's signer ships checkpoints and records to the standby's signer over the signer-to-signer
channel the key replication uses. The standby therefore holds the active's journal up to a recent
checkpoint, and the adopt services read it exactly as post-restore recovery does: certificates
issued and revocations recorded on the active that the standby's database never received.

**Audit verification.** The journal is the reference `SignerAudit` is checked against. A row with
no record means the database was written by something other than the signer. A record with no row
means the database lost or dropped one.

**Checks only the signer can make**, in Stage 3:

- **CRL monotonicity.** The signer refuses a CRL for a CA that omits an unexpired serial its
  previous CRL listed, or that does not raise the CRL number. A compromised node can then no
  longer unrevoke through a CRL. This is revocation continuity enforced at the signer.
- **OCSP consistency.** The signer refuses to sign "good" for a serial on the newest journaled
  CRL of that CA. The serials are held in memory per CA, which is small next to the CRL itself.
- **Single use of evidence** (Item 1) and **the highest term seen** (HA). Both are signer state
  that must survive a database restore, and the journal is where they live.

### Backup

- The archive gets a copy of the **sealed** segments, under `journal/`, for the case where the
  host is lost. It is never restored over a live journal.
- The manifest carries `JournalHead`.
- `SignerAudit` stays in the dump as it is, since it is the node's projection.

### `SignerAudit` from here

It stays, written by the signer as today, as the projection the console queries. It is no longer
the fail-closed record: the journal is. A failed `SignerAudit` insert is logged and retried, not
refused. OCSP decisions write one row per minute summary instead of one per response.

### Alternatives rejected

- **Chaining `SignerAudit` in place.** It is still in the node's database and still restored with
  it. Chaining makes a rewrite detectable only if a copy of the head survives elsewhere.
- **A database of the signer's own on the same cluster.** It shares the cluster's superuser,
  backups and restores. It also makes the signer depend on PostgreSQL to sign, when today it
  depends on it only to classify.
- **A signature on every record.** At issuance rates it is affordable. At OCSP rates it is not,
  and checkpoints give the same assurance up to the last second.
- **Every OCSP response in full.** The volume is above.
- **Recording plaintext or hashes of wrapped secrets.** A hash of a secret is an oracle for it.

### Signer contract changes

```proto
service Signer {
  rpc JournalHead (JournalHeadRequest) returns (JournalHeadResponse);
  rpc ReadJournal (ReadJournalRequest) returns (ReadJournalResponse);
  rpc RecordFact (RecordFactRequest) returns (RecordFactResponse);
}

message JournalHeadRequest { SigningContext context = 1; }
message JournalHeadResponse { string member_id = 1; uint64 seq = 2; bytes head = 3; bytes checkpoint = 4; }

message ReadJournalRequest {
  uint64 from_seq = 1;
  uint32 max_records = 2;           // capped at 1000
  repeated string types = 3;        // empty = all
  string ca_id = 4;                 // empty = all
  SigningContext context = 5;       // purpose JournalRead
}
message JournalRecord { uint64 seq = 1; bytes encoded = 2; }        // raw bytes, verifiable
message ReadJournalResponse { repeated JournalRecord records = 1; uint64 next_seq = 2; bytes checkpoint = 3; bool at_end = 4; }

message RecordFactRequest { string kind = 1; bytes body = 2; SigningContext context = 3; }  // Revocation, RestoreMarker, RestoreRecovered
message RecordFactResponse { uint64 seq = 1; }
```

### Migration

- At the first start of the version, the signer writes a `Genesis` record. The journal starts
  then: nothing before it can be recovered, and the console says so.
- `SignerAudit` needs no schema change. Its OCSP rows switch to summaries from that version.
- The first backup after the upgrade records the journal head in the manifest. Restoring an older
  archive, with no head, adopts from `Genesis`, which is safe because adoption is idempotent.
- A split install upgrades the signer first, as for any contract addition. A node in front of an
  older signer gets `Unimplemented` from `JournalHead`, takes backups without a head, and says so.

### Effort

L overall:

- **Stage 1, M**: the format, writer, checkpoints, rotation, `JournalHead` and `ReadJournal`, the
  verify command, the head in the manifest, and the change to `SignerAudit`.
- **Stage 2, M**: `RecordFact`, post-restore recovery and the report.
- **Stage 3, S–M**: CRL monotonicity, OCSP consistency, and shipping to the standby, which arrives
  with the HA work.

### Open questions

1. **OCSP summarised per minute** (recommended), or an option to journal every response for
   installs that want it?
2. **Retention**: keep everything by default (recommended), or a default such as the longest
   certificate lifetime plus a year?
3. **Should adoption after a restore be automatic** (recommended, with a report), or
   administrator-confirmed for certificates?
4. **Checkpoints signed by the member's system key** (recommended), or a dedicated journal key?
   A dedicated key is cleaner for separation but is one more key per member to make, back up and
   rotate.
5. **The journal replaces the `SignerAudit` insert as the fail-closed record.** Accept that a
   database outage then refuses signing only through classification, not through the audit
   insert?

## Item 3: `config.yaml` secrets out of reach

### Where it stands

| Secret | Field | Read by |
|---|---|---|
| JWT signing secret | `JWT.Secret`, `SystemConfig.cs:884`; generated at setup (`StartModularCA.cs:1148-1164`) | every node role that authenticates (`JwtTokenService.cs:48`) |
| LDAP sign-in bind password | `LdapAuth.BindPassword`, `:586` | control |
| SMTP password, OAuth2 token and client secret | `Email.Password`, `OAuth2AccessToken`, `OAuth2ClientSecret`, `:801`, `:806`, `:813` | control |
| Webhook HMAC secrets | `Webhook.Endpoints[].Secret`, `:938` | control |
| Integration and cert-manager API keys | `IntegrationApi.ApiKey`, `CertManager.ApiKey`, `:1458`, `:1502` | enrollment |
| Redis connection string, which may hold a password | `Redis.ConnectionString`, `:1539` | every node role |
| Web TLS PFX password | `Https.CertificatePassword`, `:710` | node and ingress |
| HSM PIN | `Hsm.Pin`, `HsmConfig.cs:19` | signer (`SignerRole.cs:104`) |
| Signer certificate passwords | `Signer.ClientCertificatePassword`, `ServerCertificatePassword`, `IdentityCaPassword`, `SignerConfig.cs:40`, `:58`, `:75` | node; signer; offline only |

The file is shared between node and signer on a pod (read-only for the signer). The settings save
rewrites it with `"***"` and `"(env)"` placeholders round-tripping through the console
(`AdminConfigController.cs:912`, `:950-966`). Backups copy it with the `DB` section stripped and
everything else in it (`BackupRestore.cs:234-245`).

The owner's direction (2026-10-05): instance-wide settings move into a database table, audited,
versioned, live-reloaded across nodes and changed only through the API. That is
`settings-store.md`. This item covers what that table holds for secrets, how they are wrapped, and
what stays in files.

### The threat

- **At rest.** `config.yaml` on disk, and in every archive, gives the reader:
  - the means to mint a session token for any user (the JWT secret);
  - the directory service account;
  - the mail account;
  - the webhook signing keys;
  - the integration API keys;
  - on an HSM install, the token PIN.
- **The node reads the signer's secrets.** On a pod, the HSM PIN and the signer's certificate
  password sit in a file the node can read.

Wrapping protects at rest only. A node that is running and compromised has these secrets in memory
because it uses them. That is said once here and holds for the whole item.

### The split

| Secret | Lives in | Needed by | Wrapped by the signer |
|---|---|---|---|
| JWT signing secret | settings store | node roles that authenticate | yes |
| LDAP bind password | settings store | control | yes |
| SMTP password, OAuth2 token and secret | settings store | control | yes |
| Webhook secrets | settings store, per endpoint | control | yes |
| Integration and cert-manager API keys | settings store, **as a salted hash** | enrollment | no: a key presented by a client only has to be checked. Shown once when generated |
| `db.yaml` passwords | `db.yaml`, unchanged | every process | no: needed to reach the database |
| Redis connection string | node host file | node roles | no: infrastructure, needed at start |
| Web TLS PFX password | node host file | node, ingress | no: TLS must serve while the signer is down |
| Signer client certificate password | node host file | node | no: needed to reach the signer |
| HSM PIN | signer directory | signer | no: the wrap needs an unlocked signer, which may need the PIN |
| Signer server certificate password | signer directory | signer | no |
| Identity CA password | **nowhere at runtime**; offline with the identity CA | `--issue-node-identity` only | no |
| Keystore passphrases | signer directory (`keystore.yaml` moves there) | signer | no |

The test for each row: a secret is wrapped by the signer when the process that needs it already
needs the signer to do its job. It stays in a file when it is needed to reach the database or the
signer, or to keep serving while the signer is down.

### The wrap: envelope v2

The secret wrap (`WrappedSecretEnvelope.cs:32-50`) has room for one gap: nothing binds a blob to
where it is stored. A blob copied from the webhook secret's row to the JWT secret's row would
unwrap. Version 2 adds a context:

```
"MCAW" | version (2) | kind (1) | key id (32) | context length (u16) | context (UTF-8) | salt (32) | nonce (12) | ciphertext+tag
AAD = everything before the salt
kek = HKDF-SHA256(ikm = PKCS#8 of the instance key, salt,
                  info = "ModularCA.SecretWrap.v2" || kind || key id || context)
```

- **The context for a setting** is `setting:` followed by its stable key, for example
  `setting:JWT.Secret` or `setting:Webhook/<endpoint id>/Secret`. `UnwrapSecret` takes the context
  as a field, and a blob unwrapped under any other context fails authentication.
- **A new kind, `SettingSecret`.** A new purpose, `Configuration`, may wrap it and unwrap it.
  Nothing else may do either.
- **Version 1 blobs keep unwrapping.** The CMP secret and the backup bundles move to v2 on their
  next write.
- **`HeldPrivateKey` can use the same envelope** with `request:<id>` as its context. That is the
  binding `signer-separation.md` said it needed before that column could leave Data Protection.
- **The key is the instance key**, as decided in `instance-secret-wrap-key.md`, so a secret
  wrapped on one member unwraps on the other.

### Startup ordering, and a signer that is down

1. Read `db.yaml` and the host file. Open the database.
2. Reach the signer. In process, it unlocks first, as it does today. Remote, it is reached with
   the client certificate from the host file.
3. Read the settings. Unwrap the secret ones (`UnwrapSecret`, purpose `Configuration`, one call
   each; there are about ten). Hold them in memory for the life of the process. Unwrap again
   only when the settings store reports a change.
4. Start the subsystems that use them.

**If a remote signer is unreachable at step 2**, the node starts anyway and says why:

- `/health/ready` reports "settings secrets: waiting for the signer".
- Sign-in and every authenticated endpoint answer 503: "the signer is unreachable; sign-in resumes
  when it returns". The node retries on the same five-second bound as the gRPC channel.
- LDAP sign-in, mail and webhooks wait. Webhooks queue as they do for a failed delivery.
- Validation needs no secret. CRLs keep being served. OCSP needs the signer to sign, as today.

That is a real availability cost: a node restarted while its signer is down cannot let anyone
sign in. It is accepted because such a node can issue, revoke-and-publish and run ceremonies none
the less without the signer. The readiness page and the health probes, which explain the outage,
are anonymous.

`MODULARCA__JWT__SECRET` (`EnvVarConfigOverlay.cs:22-24`) remains an operator's escape hatch. When
it is set it wins, the console shows "(env)", and the readiness page notes that the JWT secret is
outside the signer's protection.

Open question 1 offers a design that removes this cost for sign-in entirely.

### What stays in files, and why

- **`db.yaml`**: the database is how settings are read.
- **The node's host file** (named in `settings-store.md`): listen addresses, the TLS certificate
  path and password, the signer endpoint and client certificate with its password, the Redis
  connection, and the roles. Each is needed before the database or the signer, or differs per
  host.
- **The signer's directory** (being added now): the HSM PIN, the server certificate and its
  password, the keystore passphrases, the approver registry (Item 1), the journal settings and
  retention (Item 2), and `Signer.LegacyKeyExportUntil`. The node never mounts or reads it.
  - **On systemd**, each secret in it can be a credential (`LoadCredentialEncrypted=`, sealed with
    `systemd-creds` to the host's TPM where there is one). The signer reads
    `$CREDENTIALS_DIRECTORY/<name>` first and the plain file second.
  - **On Windows**, the directory is ACL'd to the signer's service account.
- **The web TLS PFX password protects nothing.** It sits beside the file it unlocks. Recommended:
  write the PFX with no password, owner-only, and drop the field (open question 4).

### Console save

- **Secret fields are write-only.** `GET` returns `{ set, updatedAt, updatedBy }` and never a
  value or a placeholder. `PUT` takes `{ value }` to replace or `{ clear: true }` to clear.
  Absence means unchanged. The `"***"` / `"(env)"` sentinel round trip, and the class of bugs
  `IsRedactionSentinel` exists to catch (`AdminConfigController.cs:955-966`), go away.
- **The controller wraps before it writes.** It calls `WrapSecret(SettingSecret, value,
  Configuration, context)` and passes only the blob to the settings store, which audits, versions
  and broadcasts the change as `settings-store.md` describes. The audit records the key and
  "replaced", never the value or a hash of it. Step-up MFA as today.
- **A save while the signer is down fails with 503.** Nothing is written in plaintext, not even
  briefly.
- **API keys** have a "generate" action that returns the key once and stores its hash.

### Rotation

- **The wrapping key**: designate a new instance key and let the settings store re-wrap on its own
  sweep, as `signer-separation.md` describes for every wrapped column.
- **The JWT secret becomes a small ring**: `JWT.Keys`, each with a `kid`, a wrapped secret and a
  retire time. New tokens are signed with the newest key. Validation accepts any key not retired.
  A rotation adds a key and retires the old one after `ExpirationMinutes`, so nobody is signed
  out. A forced rotation retires it at once.
- **Webhook secrets**: an endpoint may hold a current and a next secret during a rollover, and
  sends both signatures until the next one is promoted.
- **LDAP, SMTP and OAuth2**: replace in place. Each is the other system's secret, and it rotates
  on that system's schedule.
- **API keys**: generate a new one. The old hash is kept until it is revoked by hand.

### Backups

- **Wrapped settings travel in the database dump.** Opening one needs the instance key, which is
  in the keystore files in the archive, under passphrases that are not (`keystore.yaml` is on the
  deny-list, `BackupRestore.cs:27-35`).
- **`config.yaml`** keeps only host settings with no secret, and is still copied.
- **The node's host file and the signer's directory are not archived.** A restore onto a new host
  uses that host's own, as `db.yaml` already does since `5941520`.
- **Restoring onto the original host** needs nothing new. Restoring onto a new host gives it a new
  TLS certificate and a new signer identity, as today.

### Alternatives rejected

- **Wrapped values as `!wrapped` tags in `config.yaml`, or a `config/secrets.wrapped` file.** A
  per-host file is what the owner is moving away from. It is not shared across nodes, not
  audited, not versioned, and the YAML writer would have to round-trip custom tags.
- **Data Protection.** Its key ring is on the node, so nothing moves out of the node's reach at
  rest. That is the problem `host-local-secrets.md` already has with it.
- **Wrapping the bootstrap secrets** (the database password, the TLS password, the signer client
  password, the HSM PIN). Each is needed to reach the thing that would unwrap it, or to serve
  while it is down.
- **Environment variables only.** They are fine as an override, but they do not survive into a
  multi-node fleet without a secret manager, and `/proc/<pid>/environ` is not better than a
  `0600` file.

### Signer contract changes

```proto
message UnwrapSecretRequest {
  bytes wrapped = 1;
  SigningContext context = 2;
  string secret_context = 3;     // v2 blobs: must equal the context bound at wrap time
}
message WrapSecretRequest {
  string kind = 1;
  bytes secret = 2;
  SigningContext context = 3;
  string secret_context = 4;     // set: a v2 blob is produced
}
```

The rights table gains one row:

| `SigningPurpose` | may wrap | may unwrap |
|---|---|---|
| `Configuration` | `SettingSecret` | `SettingSecret` |

### Migration

The secret part of the settings-store migration, at the first start of the version on the control
role, with the signer reachable:

1. For each secret in `config.yaml` that is not env-sourced: wrap it, write the blob to the
   settings store, and audit "moved to the settings store".
2. Hash the API keys rather than wrapping them.
3. Rewrite `config.yaml` without the secrets, atomically. The old file is overwritten once and
   replaced. No `.bak` is kept, since it would be a plaintext copy.
4. **Rotate the JWT secret.** Everyone signs in once more. Every earlier archive and snapshot
   holds the old secret, and a session token minted with it should stop working.
5. Tell the operator, in the upgrade output and once in the console, that earlier archives
   contain the LDAP, SMTP, webhook and API secrets in plaintext, and that rotating them is the
   only remedy. This is the same notice `ssh-keystore.md` gives for SSH keys.

If the signer is unreachable, the migration waits and the node keeps using the values in
`config.yaml`, so the upgrade itself never loses sign-in. The `--upgrade-check` finding lists the
secrets that will move.

The HSM PIN and the signer's passwords move to the signer's directory under that agent's work. The
upgrade check refuses when `Hsm.Pin` is still in a `config.yaml` the node can read and the
signer's directory exists.

### Effort

M, given the settings store:

- **S**: envelope v2, the `SettingSecret` kind and the `Configuration` purpose.
- **M**: the migration, write-only fields, the JWT ring, API-key hashing and the
  readiness-while-waiting behaviour.

### Open questions

1. **Signer-signed session tokens instead of a wrapped JWT secret.** The signer would sign
   access tokens at sign-in and refresh with a key derived from the instance key (HKDF to a P-256
   scalar, ES256). The node then holds only the public key, which needs no wrap.
   - **Gains**: a node restarted while the signer is down keeps accepting every existing session,
     and nothing on any disk can mint a token.
   - **Costs**: one signature per sign-in and refresh, a derived key the HSM case cannot use (it
     would keep the wrapped HMAC), and a token format change.
   - Recommended as a follow-up after the wrap ships, not instead of it.
2. **API keys stored as hashes** means an existing key can no longer be displayed, only replaced.
   Accept?
3. **Rotate the JWT secret automatically at migration** (recommended), or leave it to the
   operator?
4. **Drop `Https.CertificatePassword`** and write the PFX without one, owner-only?
5. **The Redis connection string as a host setting** (recommended), or a wrapped setting with
   Redis unavailable until the signer answers?
6. **`systemd-creds` for the signer's secrets**: the documented default for new Linux installs, or
   an option?

## Recommended staging across 0.4.x

| Release | Item 1 | Item 2 | Item 3 |
|---|---|---|---|
| 0.4.1 | **Stage A, typed signing.** Closes `cA=TRUE` and OCSP-signing certificates without a ceremony, and purpose laundering. Approvals are still database rows | **Stage 1, the journal.** Every signature is recorded where the node cannot reach and a restore does not touch. The head is in every backup | Envelope v2, `SettingSecret`, `Configuration` |
| 0.4.2 | **Stage B, verified approvals**, opt-in. Approvals are WebAuthn evidence the signer checks against its registry. Forged approval rows stop working | **Stage 2, recovery.** Restores re-adopt certificates and reapply revocations. Revocations are recorded as they happen | Secrets into the settings store with the settings-store work; the migration; write-only console fields; the JWT ring |
| 0.4.3 | **Stage C.** Policy, waivers and key scopes held in the registry; generic kinds; `VerifyEvidence`. Verified mode is the default for new installs | **Stage 3.** CRL monotonicity and OCSP consistency at the signer | Signer-signed session tokens, if open question 1 is accepted |

What each release protects against, honestly:

- **0.4.1.** A compromised node can no longer mint a CA or a delegated responder without a
  ceremony row. It can still forge the row. A database restore no longer erases the signer's
  record. The node still holds plaintext secrets in `config.yaml`.
- **0.4.2.** A compromised node can no longer forge approvals, on installs that enrol. It can
  still trick approvers through the console it serves. A restore no longer loses certificates or
  revocations. Secrets are wrapped at rest, in the database and in archives.
- **0.4.3.** A compromised node can no longer waive, lower or re-scope the ceremony policy, or
  unrevoke through a CRL. What remains is the residue named in each item:
  - ordinary signatures while compromised;
  - approval phishing;
  - secrets in the running node's memory;
  - a single-process install, where node and signer are one process.

Item 1 Stage A and Item 2 Stage 1 are independent and can start at once. Item 1 Stage B depends on
the journal for statement state and single use. Item 3 depends on `settings-store.md`.

## How this fits the HA plan

The owner's order (2026-10-05) is revocation continuity first, then a warm standby on PostgreSQL
streaming replication. The fence is a lease held by the signer, and keys are replicated signer to
signer with ML-KEM.

- **Revocation continuity is mostly Item 2.** Revocations are journaled as facts when made and as
  CRLs when signed. The journal ships to the standby's signer. The standby's signer refuses any CRL
  that is not a superset of the newest one either journal holds. So a failover cannot publish a
  CRL that forgets a revocation, even when the replica's database is seconds behind.
- **Asynchronous replication loses a tail; the journal holds it.** The adopt services in
  `reconciliation-services.md` read the active's shipped journal: certificates to adopt,
  revocations to apply, a CRL number floor. The second check that design asks for, "the
  certificate appears in the other member's audit chain", becomes "the certificate's TBS is in the
  other member's signed journal", which the core can verify itself.
- **The lease lives in the journal.** Acquiring, renewing and losing a lease, and the highest term
  seen, are journal records. The signer reads the term back at start, so a database restore cannot
  lower it. Every signature record sits between lease records, so the old active's journal proves
  it signed nothing after its lease lapsed. That is the fence, shown after the fact.
- **Unlock on evidence is a generic kind.** `ha.unlock` has the hub witnesses or the peer's
  handover as its trust set (`signer-lock-unlock.md`). The open item there, "whether the kinds are
  fixed in the core or supplied by a module", is answered: supplied, as registry data.
- **Key replication is gated by evidence.** `WrapKeyTo` needs `ha.member-enrol` bound to the
  recipient's ML-KEM SPKI hash. That answers the open question in `keystore-replication.md`:
  "the signer's check has to work on a ceremony kind the core does not define". Each wrap-out and
  each receipt is journaled on both sides.
- **The registry replicates as signed data.** It is signed by the instance key, which both members
  hold, so a member takes in the other's registry changes by verifying them. No database row is
  involved.
- **Wrapped settings survive a failover**, because they are wrapped under the instance key.

One conflict to record: `References/HubCompatibility/README.md` says PostgreSQL replication is not
used and the application ships changes itself (`change-capture.md`). The 2026-10-05 decision for
the warm standby replaces that for this stage. The journal's role, covering the tail, is the same
either way.

## How this fits the Hub plan

- **Inventory and lineage.** The journal head (member, sequence, signed checkpoint) joins the audit
  chain head as lineage in `instance-identity.md` and the hub inventory. It is better evidence than
  the audit chain head, because the node cannot write it.
- **Hub backup and restore.** Archives sent to the hub carry the journal head and sealed segments.
  A restore staged by the hub runs the same post-restore recovery at the instance.
- **The hub is never an approver for key operations** (Item 1, open question 7). It appears only
  in unlock trust sets. Approving on a hub-served surface is one answer to approval phishing, and
  stays a question for the owner.
- **Signed updates.** The signer's directory, its journal and its registry are written only by the
  signer's account. That is one more reason, alongside `ssh-keystore.md`, for the node's account
  to stop writing under the install tree.
