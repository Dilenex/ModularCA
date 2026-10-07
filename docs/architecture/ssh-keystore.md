# SSH keystore

Status: owner decisions recorded 2026-10-05 (see "Decided by the owner"). Stage 1, the wire
format, is built as its own assembly, `ModularCA.Ssh`. Stage 2 is built: the signer has the SSH
keystore, the key lifecycle (generate, commit, the migration import, list, retire) and
`SignSshCertificate`, in process and over gRPC, with its audit summary. Stage 3 is built
(2026-10-07): the node creates SSH CA keys and signs SSH certificates through the signer and
builds KRLs in process; it runs no `ssh-keygen`, and `SshCa.*` and `PUT /config/ssh-ca` are gone.
A key made before this, still a file on the node, signs nothing until stage 4 imports it: nothing
imports it yet, and its file and row are left as they are.

Release: 0.4.2 (owner, 2026-10-06). 0.4.1 is the settings release; the signer journal and verified
approvals in `signer-hardening.md` follow this, from 0.4.3.

## Why

The signer holds every X.509 private key ModularCA has: encrypted at rest, unlocked by two
passphrases, signed and pinned, optionally on a PKCS#11 token, managed only under ceremony, and
audited at the signer. SSH CA keys get none of that. They are plaintext OpenSSH key files that
the node writes, the node reads, and every backup carries. Stage 1 of `signer-separation.md`
listed every path that reaches a private key, and SSH was not on the list.

This design moves SSH CA keys behind the signer, with the same protection as X.509 CA keys.

## Where SSH keys are touched today

Every SSH signing operation shells out to `ssh-keygen`, run by the node process, through
`ProcessRunner`.

| Where | What it does with the key |
|---|---|
| `ModularCA.Core/Services/SshCaService.cs:54-70` | `ssh-keygen -t <type> [-b <bits>] -f config/ssh-ca-keys/<id> -N ""`: an unencrypted private key file |
| `SshCaService.cs:72-76` | `chmod 600`, on Unix only. On Windows the file inherits the ACL of `config/` |
| `SshCaService.cs:78`, `:151` | reads `<id>.pub` into `SshCaKeys.PublicKey`, and stores the file path in `SshCaKeys.PrivateKeyPath` (`ModularCA.Shared/Entities/SshCaKeyEntity.cs:28-29`) |
| `SshCaService.cs:294-365` | signing: writes the subject key to a temp dir, then runs `ssh-keygen -s <PrivateKeyPath> -I -n -V +Nh -z <serial> [-h] [-O ...]` and reads back `key-cert.pub`. `ValidAfter` and `ValidBefore` on the row are the node's clock, not the certificate's (`:344-345`) |
| `SshCaService.cs:439-481` | KRL: `ssh-keygen -k -f <krl> -s <PrivateKeyPath> <serials>`. `-s` here only needs the CA **public** key, but the code passes the private key path |
| `SshCaService.cs:485-489` | a failed create removes the key files with a plain `File.Delete` |
| `ModularCA.Shared/Models/Config/SystemConfig.cs:947-951` | `SshCa.SshKeygenPath` and `SshCa.KeyStoragePath` (default `config/ssh-ca-keys`) |
| `ModularCA.API/Controllers/v1/Admin/AdminConfigController.cs:472-484` | `PUT /api/v1/admin/config/ssh-ca` sets both paths at runtime, with step-up MFA |
| `AdminSshController.cs:66-140` | `POST /api/v1/admin/ssh/ca-keys`: `SystemOperator` and step-up MFA; a `CreateSshCa` ceremony when the instance requires key ceremonies (`:104-126`), otherwise generates directly |
| `AdminSshController.cs:158-280` | admin sign-user and sign-host: profile checks, then `SignUserKeyAsync` / `SignHostKeyAsync` |
| `AdminSshController.cs:379-395`, `:423-465` | admin KRL download; disable, through a `DeleteSshCa` ceremony when required |
| `ModularCA.API/Controllers/v1/User/UserSshController.cs:64-227` | self-service sign-user: request, signing and cert profiles, then `SignUserKeyAsync` (`:209`) |
| `ModularCA.API/Controllers/v1/Public/PublicSshController.cs:16`, `:86-101` | anonymous `/ssh/ca-keys/{id}/krl`, on the **validation** role, runs `ssh-keygen -k` per request |
| `AdminKeyCeremonyController.cs:702-743` | executes `CreateSshCa` (calls `GenerateKeyPairAsync` in the node) and `DeleteSshCa` |
| `ModularCA.Bootstrap/BackupRestore.cs:213-240` | backup wraps `config/ssh-ca-keys/*`, with the Data Protection key ring, through the signer as one `SecretKind.BackupConfigSecret` blob per directory (`BackupWrappedSecrets.cs:57-102`), and leaves the directory out of the config copy. The deny-list (`:27-35`) names files, not this directory |
| `BackupRestore.cs:856-882` | restore stages the wrapped blobs in `config/restore-pending/`, and the next start unwraps them into `config/ssh-ca-keys` (`BackupWrappedSecrets.cs:138`, `StartModularCA.cs:2582`). An archive from before the wrap carries the keys in plaintext under `config/`; restore writes them back with a warning (`:701`) |
| `BackupRestore.cs:1287-1300`, `:1605-1631` | the pre-restore snapshot zips `config/`, keys included, **unencrypted** (owner-only) into `backups/` |
| `ModularCA.Bootstrap/BootstrapModularCA.cs:229-236` | reset deletes `keystores/ssh-ca-*`, a directory and pattern that hold no SSH keys. The real files in `config/ssh-ca-keys` survive a reset |

### Found along the way

- **The published image cannot run any of this.** `deploy/container/Containerfile:15-16` installs
  `ca-certificates libicu72 libssl3 tzdata` on `debian:12-slim`, which has no `ssh-keygen`. In the
  image every SSH create, sign and KRL fails. This was read from the files, not tested.
- **The pod's security split does not hold for SSH keys.** `modularca-pod.yaml:33-40` says the
  config volume is shared, the signer mounts it read-only, and nothing is written to it after
  init. SSH key generation writes private keys into that volume at runtime, where both containers
  can read them.
- **An admin-settable executable path.** `PUT /config/ssh-ca` lets a holder of config rights plus
  step-up MFA choose the binary the node runs on every SSH signature. That is code execution as
  the service account, one step removed.
- **KRL generation needs the private key file on the validation host.** On a split install the
  validation-only host does not have it, so its KRL route fails.
- **Nothing refuses an empty principal list.** No controller checks `Principals.Count > 0`, and a
  principal the sanitizer empties out (`SshCaService.cs:528-535`) becomes `""`. An OpenSSH user
  certificate with no principals is valid for every user. Today the only guard is whatever
  `ssh-keygen` does with `-n ""`, which was not checked.
- **Extension semantics are `ssh-keygen`'s.** `-O` flags add to the default set (the five
  `permit-*` extensions for a user certificate) unless `clear` is given, and the code never passes
  `clear`. A profile that lists only `permit-pty` therefore issues all five. The profile form
  (`SshCertProfileForm.tsx:46-48`) documents the `no-*` flags as ssh-keygen's. The owner has
  decided that profiles become exact (decision 7 below).
- **SSH CA creation is already ceremony-gated**, by the same instance `RequireKeyCeremony` switch
  as X.509 (`AdminSshController.cs:104`, quorum at `KeyCeremonyService.cs:351`). What is missing is
  enforcement at the signer: the key is made in the node, so the signer never sees the ceremony.

## Goals

- SSH CA private keys live only in the signer, encrypted at rest under the keystore passphrases,
  never in a file the node can read.
- The node cannot obtain a signature from an SSH CA key except on a well-formed OpenSSH
  certificate that meets that key's own limits. The signer is not a raw-bytes oracle for SSH keys.
- Key generation is held to the ceremony policy at the signer, as X.509 CA keys are.
- Backups carry SSH keys only inside a signer-exported keystore file.
- Existing installs migrate without operator action where possible, and are told plainly what was
  exposed before.
- No `ssh-keygen` dependency. SSH works in the container image and on Windows without OpenSSH.

## Non-goals

- SSH CA key rotation with an overlap period. It is worth building, but it is a separate feature.
- Moving profile policy (principal patterns, allowed extensions, request approval) into the
  signer. It stays in the node, as X.509 profile policy does.
- Generating SSH keys on a PKCS#11 token. Nothing generates X.509 keys on a token either.
- FIDO (`sk-*`) subject keys. The format admits them, and adding them later is a small change.
- Deleting key material from a keystore file. The format has no entry removal, for X.509 too.

## Decisions in one place

1. The signer builds and signs the whole certificate from structured fields, through a new
   `SignSshCertificate` call. A raw `Sign` on an SSH key is refused for every purpose.
2. SSH keys live in a third keystore file, `ssh-ca.keystore`. It uses the same format, the same
   signer, the same unlock and the same secondary passphrase as `ca-certs.keystore`, and has its
   own `Keystores` row.
3. KRLs are built in process from the public key. They need no signer.
4. At the first start after upgrade, the control role imports the plaintext keys into the signer
   once and then deletes the files. The upgrade check reports the import beforehand and refuses
   when a file is missing.
5. `CreateSshCa` joins the signer's key-management ceremonies. There is no SSH-specific switch:
   the instance's `RequireKeyCeremony` covers SSH CAs, as it does today.
6. `ssh-keygen`, `SshCa.SshKeygenPath`, `SshCa.KeyStoragePath` and `PUT /config/ssh-ca` are
   removed.
7. A certificate carries exactly the extensions its profile names, with no `ssh-keygen` defaults
   added (owner decision, 2026-10-05).

## Signing: the signer builds the certificate

### How X.509 does it

The node builds the TBS structure with BouncyCastle, and `SigningServiceSignatureFactory` hands the
bytes to `SignAsync` (`signer.proto:48-53`, `InProcessSigningService.cs:114-131`). The signer does
not parse them. What bounds it is the policy table in `JudgeSign` (`InProcessSigningService.cs:611-630`):

- a CA key signs only for certificate, CRL, OCSP, SCEP and CMP purposes, and only for its own CA
  and space;
- other key kinds sign for their one purpose;
- every decision is audited with a SHA-256 of the data.

So the X.509 signer **is** an oracle, bounded by key kind, purpose and owner. `signer-separation.md`
accepts that, because a DER TBS structure and its algorithm identifier are the only thing those
keys sign.

### Why not raw bytes for SSH

- **The SSH key would sign anything.** An SSH CA key that signs arbitrary bytes under an
  "SSH certificate" purpose can also sign an `SSHSIG` blob, which is what `ssh-keygen -Y` and git
  commit signing verify. It can also sign a user-authentication challenge, wherever the CA key is
  trusted as a plain key. Nothing in the bytes ties the signature to a certificate unless the
  signer looks.
- **The audit is better.** Raw signing leaves the signer's audit with a hash. Building the
  certificate lets the audit record its type, serial, key id, principals and validity, which is
  what an investigator needs from the one record a compromised node cannot rewrite.
- **The code costs the same.** Making raw signing safe means the signer parses the certificate
  blob and checks it. Building it from fields is about as much code, and it has no
  parser-differential risk.
- **The format is small.** An OpenSSH certificate is a length-prefixed sequence of strings and
  integers (`PROTOCOL.certkeys`), a few hundred lines to encode with golden tests.

### What the signer enforces, and what stays in the node

The signer reads the `SshCaKeys` row and its `CertificateAuthorities` row, as it reads CA rows for
X.509, and refuses unless all of these hold:

- the key is an SSH CA key, its row is enabled, and its CA row is enabled, not deleted and is an
  SSH CA. This is the check `EnsureSshCaUsableAsync` (`SshCaService.cs:228-240`) makes today,
  moved to the signer;
- the context names that CA and the instance scope;
- the type is permitted by `IsUserCa` / `IsHostCa`;
- `valid_before - valid_after` is no more than `MaxValidityHours`, and `valid_after` is not more
  than ten minutes in the past or five minutes in the future (as built; the past bound waits on
  open question 1);
- there is at least one principal, and none is empty or longer than 256 bytes;
- the serial is non-zero;
- the key id is no longer than 256 bytes and has no control character, since every server the
  certificate is shown to logs it;
- the row's storage is `Signer`: a `LegacyFile` row is still waiting for its import;
- critical options are only `force-command`, `source-address` and `verify-required`; extensions
  are only the known `permit-*` names and `no-touch-required`; a host certificate carries
  neither; names are unique and sorted as `PROTOCOL.certkeys` requires;
- the subject key is Ed25519, ECDSA P-256/P-384/P-521 or RSA of at least 2048 bits, and is not the
  CA's own key.

The signer generates the 32-byte nonce, writes the CA public key as the signature key, and chooses
the signature algorithm from the CA key. The caller cannot choose any of these.

The node keeps everything about who may ask: request, signing and cert profiles, principal
patterns, allowed extensions, approvals and the serial's uniqueness check against
`SshCertificates`. The node also turns profile options into the explicit option set the signer
takes. That set is exact: a certificate carries the profile's extensions and nothing else. It does
not reproduce `ssh-keygen`'s additive `-O` semantics (the five default `permit-*` extensions unless
`clear`), so a certificate issued after the change can carry fewer permits than the same profile
issued before. A profile that named only `permit-pty` issued all five; afterwards it issues
`permit-pty` alone. The `no-*` flags lose their meaning, since there are no defaults to remove.

### Algorithms

| CA key | Certificate type string | Signer algorithm | SSH signature blob |
|---|---|---|---|
| Ed25519 | `ssh-ed25519-cert-v01@openssh.com` | `Ed25519` | `ssh-ed25519`, 64 raw bytes |
| ECDSA P-256 / P-384 / P-521 | `ecdsa-sha2-nistp256/384/521-cert-v01@openssh.com` | `SHA256/384/512withECDSA` | `ecdsa-sha2-nistpNNN`, `mpint r, mpint s` |
| RSA ≥ 2048 | `ssh-rsa-cert-v01@openssh.com` | `SHA512withRSA` | `rsa-sha2-512`; never SHA-1 `ssh-rsa` |

The encoder takes ECDSA output in either shape: DER from a software key, raw `r||s` from a PKCS#11
key (`Pkcs11SessionManager.Sign` returns the token's output as is). The caller names the shape
(`EcdsaSignatureFormat`) rather than the encoder guessing, because a raw `r||s` can happen to parse
as DER. `rsa-sha2-256` is encoded and verified as well, for the fixtures and for reading
certificates; the signer issues `rsa-sha2-512`.

## Storage: a third keystore file, same unlock

### Layout

- `keystores/ssh-ca.keystore` uses the MCAKSTR format and the same `KeystoreService` read, append
  and verify code as the other two files. It is signed by the pinned system signer.
- Each entry is a PKCS#8 private key. There is no certificate and nothing goes into
  `ca-trust.keystore`. A key is bound to its `SshCaKeys` row by public key, and the signer checks
  that binding on load, on commit and on import.
- The file has its own `Keystores` row: its own salt, scrypt parameters, main-passphrase blob, pin
  and pin MAC. Its main passphrase is random and generated by the signer. Its **secondary**
  passphrase is the one already resolved for `ca-certs.keystore`, so an operator who moved
  secondaries into `MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE` as a JSON map has nothing to add.
- The signer creates the file the first time it commits or imports an SSH key. An install with no
  SSH CA never has one.
- A key is addressed as `KeyRef(SshCaKeys.Id, "ssh-ca.keystore")`. `KeyRef` already carries the
  keystore name for this. Its first field is named `CertificateId`, and for SSH it holds the SSH
  key's row id; the wire form does not change.
- The signer loads the file at unlock, alongside the other two. A locked signer refuses SSH
  signing exactly as it refuses X.509 signing.

Runtime writes need an exportable system signer (`FileKeystorePersistence.cs:196-201`), as X.509 CA
creation does today. An install whose system signer is on a token cannot create SSH keys until
that limit is lifted for both.

### Rejected: SSH keys as entries in `ca-certs.keystore`

The format would allow it, since an entry is PKCS#8 and a key without a certificate is skipped on
load. It was rejected for three reasons:

- **Every consumer of the CA key list would have to learn to skip SSH keys.** The registry's
  signers feed `HealthAsync`, the system-signer fallback in `ResolveSystemSigner`
  (`signers[0]` when no pin matches), certificate pairing and the secret wrap. SSH uses the same
  algorithms as X.509 CA keys, so a filter by algorithm does not work. One missed filter puts an
  SSH key on an X.509 path.
- **The usage marker would live in the database.** If "this key is an SSH key" were read from
  `SshCaKeys` rows, a node with database write could point an SSH row at the public key of an
  X.509 CA key and get that key signing SSH certificates. A separate signed file makes the file
  itself the marker. A key is an SSH key because it is in `ssh-ca.keystore`, and the database can
  only select among keys already there.
- **A pseudo-certificate would make the SSH key a trust anchor.** Anything in `ca-trust.keystore`
  is published by EST `/cacerts`, SCEP and the trust bundle. This is the reason the secret wrap
  key was not given its own entry either (`signer-separation.md`, "Which key wraps").

The ML-KEM replication key planned in `keystore-replication.md` does go into `ca-certs.keystore`
as a key with no certificate. That works for it because ML-KEM is recognisable by algorithm and
can never be an X.509 or SSH signing key. SSH keys cannot be told apart that way.

### Rejected: a separate SSH keystore with its own operator passphrase

It isolates SSH keys from a leak of the CA passphrases, but:

- it adds a secret to provision, rotate, escrow and replicate per member;
- it adds a new state, "signer unlocked but SSH locked", to the readiness page, the
  unlocked-signer filter and the HA lock and unlock design;
- the passphrase lives on the same signer host as the others, so the isolation is thin.

The per-file `Keystores` row already gives SSH keys their own salt and main passphrase. What they
share with CA keys is the secondary passphrase and the unlock moment, which is the right coupling.
SSH issuance is down exactly when X.509 issuance is down.

### PKCS#11

HSM support follows the X.509 shape. It is adopt-only, and a later, optional stage:

- `SshCaKeys` gains `KeyStorageType` and `HsmKeyLabel`;
- at unlock the signer finds the key on the token by label for each enabled SSH CA whose storage
  is `Pkcs11`, as `StartupKeystoreLoader.LoadHsmSigners` does for CAs;
- the signer checks the token key's public half against the row before serving it.

Token support for Ed25519 varies. `Pkcs11AlgorithmMapper.cs:25` maps it to `CKM_EDDSA`, which is
PKCS#11 3.0, and the mapper has no EdDSA key generation (`:29-33`). Adoption checks the token's
mechanism list. The console recommends ECDSA P-256 or P-384 for a token-backed SSH CA and warns on
Ed25519.

## Signer contract changes

```proto
service Signer {
  // ... existing calls unchanged ...
  rpc SignSshCertificate (SignSshCertificateRequest) returns (SignSshCertificateResponse);
}

message SshOption {
  string name = 1;
  string value = 2;           // empty for flag extensions
}

message SignSshCertificateRequest {
  KeyRef key = 1;             // (SshCaKeys.Id, "ssh-ca.keystore")
  bytes subject_public_key = 2;   // OpenSSH wire-format public key blob
  string cert_type = 3;       // "user" | "host"
  uint64 serial = 4;
  string key_id = 5;
  repeated string principals = 6;
  int64 valid_after = 7;      // Unix seconds
  int64 valid_before = 8;
  repeated SshOption critical_options = 9;
  repeated SshOption extensions = 10;
  SigningContext context = 11;    // purpose SshCertificate, ca_id = the SSH CA's row, instance scope
}

message SignSshCertificateResponse {
  bytes certificate = 1;      // the full certificate blob; the node renders "type base64 comment"
}

message KeySpec {
  // ... existing fields ...
  string usage = 4;           // "" = X.509 (today's behaviour), "ssh"
}
```

- **`ISigningService.SignSshCertificateAsync(SshCertificateRequest, SigningContext)`** is added in
  `ModularCA.Shared/Signing`. The request is plain types, as the gRPC message is (the subject key
  as its wire blob, strings and integers), because `Shared` references no project: it is what a
  private module compiles against (`ModuleBoundaryTests.Shared_references_nothing`).
- **The OpenSSH encoder is `ModularCA.Ssh`, an assembly of its own** (owner decision,
  2026-10-06). It references no ModularCA project and only BouncyCastle, so it can be lifted
  out whole and published under its own licence later. The signer's implementation
  (`ModularCA.Keystore`) and the node (`ModularCA.Core`) reference it directly. It signs
  through `ISshSigner` (a public key, and "sign these bytes with this algorithm"), which the
  signer implements over a keystore entry or a token, and `SshCertificateIssuer` checks the
  rules, builds the certificate, and returns it only when the signature verifies under the CA
  key. BouncyCastle's OpenSSH utilities cover public-key encoding. Stage 1 checked the private side: BouncyCastle 2.7.0's
  `OpenSshPrivateKeyUtilities` reads unencrypted `openssh-key-v1` Ed25519, ECDSA P-256/P-384/P-521
  and RSA keys as `ssh-keygen` 10.2 writes them. `SshPrivateKeyFile` wraps it, checks the file's
  public key against its private key, and gives the PKCS#8 the import sends.
- **`SigningPurpose.SshCertificate`**: signs SSH certificates, and only through
  `SignSshCertificate`.
- **`SigningPurpose.SshKeyMigration`**: permits `ImportKey` into `ssh-ca.keystore` only. The
  material must be PKCS#8, the target `SshCaKeys` row must have storage `LegacyFile` and a public
  key that matches, and the signer must not already hold a key for that row. Nothing else.
- **`KeyKind.SshCa`**: assigned by the signer to every key loaded from `ssh-ca.keystore`, and to
  nothing else.
- **Policy rows**:
  - `JudgeSign` permits no purpose for `SshCa`, so a raw `Sign` is always refused.
  - `SignSshCertificate` accepts only `SshCa` keys under `SshCertificate`.
  - `Decrypt` and `Export` under `Export` refuse SSH keys. `Export` under `Backup` stays
    keystore-file only for this file.
  - A pending SSH key, between generate and commit, signs nothing.
- **Key management**:
  - `GenerateKey` with `usage = "ssh"` mints a pending reference in `ssh-ca.keystore` and
    accepts only the SSH algorithms above.
  - `CommitKey` binds it to an `SshCaKeys` row whose public key matches, whose CA is an SSH CA
    and is the CA the context names, and appends it to `ssh-ca.keystore`.
  - `ImportKey` into `ssh-ca.keystore` is held to the same checks.
  - `KeyManagementCeremonies` (`InProcessSigningService.cs:681`) gains `CreateSshCa`, so a named
    ceremony is verified. A context with no ceremony is held to the instance's
    `RequireKeyCeremony`, as for X.509 (`JudgeCeremonyRequirementAsync`).
- **`ListKeys`** returns SSH keys with kind `SshCa`, so the console and the HA module can compare
  what each signer holds.
- **Audit.** One `SignerAudit` row per call:
  - `Operation` is `SignSsh` and `Keystore` is `ssh-ca.keystore`;
  - `DataHash` is SHA-256 of the signed certificate blob, so the row matches the stored
    certificate;
  - a new nullable `Summary` column holds `type`, `serial`, `key_id`, the principal count and the
    validity window, for both allowed and refused calls.

  Principals are counted rather than listed, so the signer's audit does not become a directory of
  user names. `Summary` needs a migration, in the app schema.
- **Mixed versions.** A node that calls `SignSshCertificate` on a signer that predates it gets
  gRPC `Unimplemented`. The node reports "the signer predates the SSH keystore; upgrade the signer
  first". The signer is upgraded before the node, as for any contract addition.

## Key lifecycle

- **Create** (`SshCaService.GenerateKeyPairAsync`, directly or from the `CreateSshCa` ceremony):
  1. Check the label, as today.
  2. `GenerateKey` with usage `ssh` under a `Ceremony` context: instance scope, the ceremony id when
     there is one.
  3. Create the CA row, its groups and the `SshCaKeys` row, with `PublicKey` encoded from the
     returned SubjectPublicKeyInfo and storage `Signer`.
  4. `CommitKey`.
  5. Create the default signing profiles.

  A failure before the commit retires the pending key, so nothing is left on disk. This is the
  X.509 CA creation shape, and the "label taken during save" path no longer has files to delete.
- **Sign**: as today in the controllers, then `SignSshCertificate`. The certificate's own
  `valid_after` and `valid_before` are stored on the row. `ValidAfter` is backdated five minutes
  for clock skew, which is an open question.
- **KRL**: the `PROTOCOL.krl` encoding of a certificate section for the CA public key, with a
  serial list. It is built in process from `SshCaKeys.PublicKey`, with no signer and no private
  key. `ssh-keygen -k` does not sign KRLs either, so the bytes carry the same assurance as today.
  `krl_version` becomes the time of the newest revocation, so it increases. The validation role
  stops spawning a process per anonymous request.
- **Disable**: unchanged. The row and CA are disabled and certificates revoked. The signer refuses
  to sign for a disabled row. The key stays in the file, as a disabled X.509 CA's key does.

## Migration

Existing installs have rows with `PrivateKeyPath` set and files in `config/ssh-ca-keys`. The
schema migration adds `SshCaKeys.KeyStorage` (`LegacyFile` | `Signer` | `Pkcs11`). Rows with a path
start as `LegacyFile`, and new rows start as `Signer`. `PrivateKeyPath` becomes nullable and is
dropped one release later.

### The import

It runs once per key in the control role, after migrations and after the signer reports unlocked,
as a startup step beside the other startup repairs. For each enabled or disabled `LegacyFile` row:

1. Read the file at `PrivateKeyPath`. It must be an unencrypted `openssh-key-v1` key whose public
   half matches `SshCaKeys.PublicKey`. Convert it to PKCS#8 in memory.
2. `ImportKey` into `ssh-ca.keystore` under `SshKeyMigration`, which creates the file if absent.
   Zero the buffers.
3. Confirm with `ListKeys` that the signer holds a key for the row with the same public key. This
   does not use a test signature, which would issue an unrecorded certificate.
4. In one transaction, set `KeyStorage = Signer` and clear `PrivateKeyPath`, and write an audit
   row naming the key and the file.
5. Delete `<id>` and `<id>.pub`, and remove the directory when it is empty.

Every step is safe to repeat. A crash after step 2 makes the next start's import report "already
held". The signer treats that as success when the public key matches, and the start continues
with step 3. A row whose file is missing or does not match stays `LegacyFile`, cannot sign
(503, "SSH CA key awaiting import into the signer"), and is shown on the readiness page. The rest
of the CA starts normally: SSH is not a reason to refuse X.509 issuance.

There is no fallback to `ssh-keygen` for unmigrated keys. Keeping one would keep the dependency
and the admin-settable executable path alive for exactly the installs that most need them gone.

### Deleting the files

Before deleting, the file is overwritten once with zeros, flushed to disk, and only then removed.
That is all the code can honestly do. On SSDs, copy-on-write filesystems (btrfs, ZFS), VM
snapshots and filesystem backups, an overwrite does not guarantee erasure, and the doc and console
say so.

The keys were also in plaintext:

- in every backup archive made so far, under the backup key that sits on the same host;
- in every `pre-restore-*.zip`, which is unencrypted.

The upgrade output and the SSH CA page therefore carry one notice: these keys were stored in
plaintext before this version, and archives and snapshots made before the upgrade still contain
them. Rotating an SSH CA (a new CA and new trust lines on the servers) is the only remedy, and it
is the operator's call. The notice recommends it and names the archive and snapshot files it can
see. This release informs only; guided rotation comes later.

### Split installs

- The key files are where SSH keys were generated and used: on the host running the control role,
  since every SSH create and sign endpoint is control's. The import therefore runs there, reads
  the files locally, and sends the PKCS#8 to the signer over the pinned mutual-TLS channel. The
  node already holds these keys in the clear, so sending them to the signer once exposes nothing
  new, and afterwards the node holds none.
- A validation-only host loses nothing. Its KRL now comes from the public key in the database,
  which also fixes the KRL route that fails there today.
- Upgrade order: the signer first, then the node. A new node in front of an old signer leaves
  every row `LegacyFile` and reports why.
- The pod: the import reads from the shared config volume, which the node can write, and deletes
  there. The signer's read-only mount of that volume then no longer exposes SSH keys.

### Upgrade check

`--upgrade-check` (`UpgradeCheckCommand.cs`, `SchemaStartup.cs:288-313`) gains one finding,
"SSH CA keys", read from the application database and the configured key directory on the host
where it runs:

- no `PrivateKeyPath` rows: `ok`;
- every file present and its public half matching its row: `ok: N SSH CA key(s) will be imported
  into the signer at first start and their files deleted; archives made before this upgrade still
  contain them in plaintext`;
- any file missing or not matching: `REFUSED`, listing the SSH CA names, row ids and expected
  paths. The operator puts the files in place on this host, or disables those SSH CAs, before
  upgrading. On a split install this is the case where the check was run on a host other than the
  control host, and the message says to run it there.

## Backup and restore

- `KeyRef.BackupKeystores` (`KeyRef.cs:20`) gains `ssh-ca.keystore`. Backup exports it through the
  signer as the other two files are exported, and a signer without one skips it, as it already
  does for a missing file. Restore imports it through `ImportKeystoreFile`, verified against its
  own pin.
- **Interim: the SSH keys travel under the signer's backup wrap.** Until this design lands, an
  archive carries `config/ssh-ca-keys` wrapped by the signer (`SecretKind.BackupConfigSecret`,
  `BackupWrappedSecrets.cs`), never in plaintext; opening it needs the keystore and its secondary
  passphrase as well as the archive key. That wrap is a stopgap for files that should not exist:
  the SSH keystore replaces it. Once the keys live in `ssh-ca.keystore`, the directory drops out of
  `BackupWrappedSecrets.Targets`, which then wraps only the Data Protection key ring.
- The config copy (`BackupRestore.cs:240`) already leaves the `ssh-ca-keys` directory out, so a new
  archive never carries plaintext SSH keys, even from a host where an import failed.
- Restore still accepts `config/ssh-ca-keys` from an older archive, in plaintext or under the
  interim wrap (unwrapped at the next start, so the import must run after `ApplyPendingAsync`). That archive's database dump
  has `LegacyFile` rows and its keystores have no `ssh-ca.keystore`. A live `ssh-ca.keystore` is
  moved aside as `.bak.<timestamp>`, so that the restored state is consistent, and the next start
  imports the restored files. Restoring an old backup is therefore just another migration.
- The pre-restore snapshot (now written to `backups/`, `BackupRestore.cs:1287`) stops containing
  SSH keys once the directory is gone. Its plaintext handling of the rest of `config/` is unchanged
  and out of scope here.
- Reset (`BootstrapModularCA.cs:229-236`) deletes `keystores/ssh-ca.keystore` with the other two,
  and also the legacy `config/ssh-ca-keys` directory, which it misses today.

## Ceremonies and authorization

- **No new gate, an enforced one.** Creation keeps `SystemOperator`, step-up MFA and, when the
  instance requires it, a `CreateSshCa` ceremony at the instance's `CeremonyRequiredApprovals`.
  The change is that the signer now verifies that ceremony, or the instance's waiver, before
  generating or committing. A node can no longer create an SSH CA key the policy forbids.
- **SSH CAs are instance CAs** (`SpaceId` null). The controlled-tier rules for instance-scope
  `ca.manage` apply to who may approve, unchanged.
- **The migration needs no ceremony.** It creates no new key and no new trust: the keys already
  exist and are already trusted by servers. `SshKeyMigration` is narrow enough that a compromised
  node gains nothing by it. It can only import a key whose public half is already on an
  `LegacyFile` row. If an attacker rewrites that row to a key of their own, they get the signer
  holding a key they already have, under a public key no server trusts.
- **Disable** keeps the `DeleteSshCa` ceremony when required. It touches no key, so it needs
  nothing from the signer.
- **Who may sign** is unchanged: `CaOperator` on the admin path, `cert.request` on the SSH CA for
  self-service, and profiles. The signer adds the key-level limits above. It is a backstop, not
  the policy.
- **Importing an existing external SSH CA key** (for example from Vault) falls out of the
  migration code as an `ImportSshCa` ceremony. It is listed as an open question, not committed.

## API changes

| Endpoint | Change |
|---|---|
| `POST /api/v1/admin/ssh/ca-keys` | Same request and response; the key is generated in the signer. New 503 while the signer is locked. RSA, ECDSA and Ed25519 sizes unchanged |
| `GET /api/v1/admin/ssh/ca-keys`, `GET /ssh/ca-keys` | Admin list adds `keyStorage` (`signer`, `legacyFile`, `pkcs11`); public list unchanged |
| `POST /api/v1/admin/ssh/ca-keys/{id}/certificates/sign-user`, `.../sign-host`, `POST /api/v1/user/ssh/sign-user` | Same shapes. New 503 (signer locked, or key awaiting import). New 400 when the signer refuses the certificate (no principals, validity over the key's maximum, unknown option), with the refusal reason |
| `GET /api/v1/admin/ssh/ca-keys/{id}/krl`, `GET /ssh/ca-keys/{id}/krl` | Same responses; built in process; works on a validation-only host |
| `PUT /api/v1/admin/config/ssh-ca` | Removed. The `sshCa` section leaves `GET /config` and `config.yaml.example:137-138` |
| `POST /api/v1/admin/key-ceremonies/{id}/execute` (`CreateSshCa`) | Passes the ceremony id to the signer; unchanged to the caller |
| `/health/ready` | The signer entry gains SSH key count and any keys awaiting import |

The docs site changes with them: `docsui/.../admin/ssh.ts`, `admin/config/configuration.ts` (drop
`ssh-ca`), `admin/ca-and-certs/key-ceremonies.ts`, the public SSH endpoints, and the admin UI
guide.

## Console changes

- **Settings** (`Settings.tsx:644-656`): the SSH CA section goes, with its `ssh-keygen` path and key
  directory fields.
- **SSH certificates**, key list and generation form (`SshCertificates.tsx:43`, `~219-256`): a
  storage column; the form says the key is generated in the signer.
- **SSH CA key detail** (`SshCaKeyDetail.tsx`): storage and backend fields; "awaiting import" with
  the reason when the import failed; the one-time notice about pre-upgrade plaintext storage.
- **Backup and restore** (`BackupRestore.tsx:83`, `:93`): "SSH CA keys (if configured)" becomes
  "SSH CA keys, inside the signer's SSH keystore".
- **Readiness**: a row for SSH keys awaiting import.

## Open-core and HA fit

- **Core, ungated.** Key custody is the security baseline the product sells on, not a feature
  past a threshold. All of it sits in `Shared`, `Keystore`, `Signer` and `Core`, in layer order,
  with no module hook. PKCS#11 adoption for SSH keys is core, as it is for CA keys; the multi-HSM
  automation stays the `hsm.fleet` module's.
- **Warm standby** (`References/HubCompatibility/keystore-replication.md`) replicates keys one by
  one and never copies files. SSH keys fit unchanged:
  - the active signer wraps each new SSH key to the standby's ML-KEM key;
  - the standby checks it against the `SshCaKeys` row's public key instead of a certificate row;
  - the standby appends it to its own `ssh-ca.keystore` under its own `Keystores` row, and
    returns the same signed receipt.

  What the HA work has to add for SSH:
  - `ssh-ca.keystore` in "the command that creates a member's keystore";
  - `KeyKind.SshCa` in the receipt comparison;
  - the rule that a new SSH CA, like a new X.509 CA, is enabled only once the standby's receipt
    is in.

  The secondary-passphrase sharing is per member, so separate passphrases per member still hold.
- **Signed updates** (`signed-updates.md`) want the node's account to stop writing under the
  install tree. This removes one of the runtime writes it lists: `config/ssh-ca-keys`.

## Implementation plan

| Stage | Work | Effort |
|---|---|---|
| 1 | **Built.** `ModularCA.Ssh` (its own assembly; `ISshSigner` and `SshCertificateIssuer` added 2026-10-06): certificate encoder and parser, public key encode/decode and authorized_keys parsing, signature blobs per algorithm (DER and raw ECDSA), KRL encoder, `openssh-key-v1` private key reader, and the signer's checks as pure functions (`SshCertificateRules`). Golden tests against fixtures made with `ssh-keygen` 10.2 (`tests/ModularCA.Tests/Ssh/Fixtures/generate.sh`). No `ssh-keygen` option-set mapping, since profiles are exact. No behaviour change | M |
| 2 | Signer: `ssh-ca.keystore` (create, load, append, pin, secondary alias), `KeyKind.SshCa`, the two purposes, `SignSshCertificate` in process and over gRPC, SSH generate, commit and import, `CreateSshCa` ceremony verification, `SignerAudit.Summary` migration. Contract suite on both bindings, with deliberate breaks: raw `Sign` on an SSH key allowed, empty principals allowed, X.509 key in the SSH file, ceremony check removed. **Part 1 built (2026-10-07):** the keystore file and its `Keystores` row, created by the first commit or import and loaded at unlock; `KeySpec.usage` (`ssh`) on the contract and the wire; SSH generate, commit, retire and list; the `SshKeyMigration` import, repeatable; `CreateSshCa` verified at the signer, with an X.509 CA ceremony licensing no SSH key and the reverse; `SigningPurpose.SshCertificate` and `SshKeyMigration`; and the `SshCaKeys.KeyStorage` column with its migration (`SshKeyStorage`), brought forward from stage 3 because the import is judged on it. Contract tests on both bindings, checked against deliberate breaks of the ceremony licence, the row binding, the storage and enabled checks, the pin requirement and the raw-signature refusal. **Part 2 built (2026-10-07):** `ISigningService.SignSshCertificateAsync` over a plain request (`SshCertificateRequest`), in process and over gRPC (`rpc SignSshCertificate`; a signer that predates it answers `Unimplemented`, which the client reports as a refusal saying the signer predates the SSH keystore). The `SshCaKeys` row is read at every use and must still carry the bound key's public key, have storage `Signer` and be enabled, under an enabled, undeleted SSH CA of the instance that the context names; the type and the maximum validity come from the row, and every other rule from `SshCertificateRules` through `SshCertificateIssuer`, which verifies the signature before anything is returned. Software keys only. One `SignSsh` audit row per call, with the certificate's SHA-256 when one was issued and `SignerAudit.Summary` (migration `SignerAuditSummary`). `SshCertificateRules` gained a separate clock-skew allowance for the past and the future (`SshClockSkew`), and its duplicate-principal refusal no longer names the principal. Contract tests on both bindings, checked against deliberate breaks of the purpose, scope, row public key, row enabled, CA enabled, certificate type, maximum validity, clock skew, empty principals and verify-after-sign checks. **Stage 2 is complete**; nothing in the node calls it until stage 3 | L |
| 3 | Node cut-over: `SshCaService` over the signer; KRL from the public key; `KeyStorage` column; `ssh-keygen`, `ProcessRunner` use, `SshCaConfig` and `PUT /config/ssh-ca` removed; unlocked-signer filter on the SSH sign routes; endpoints, docs site and console. **Built (2026-10-07) except the console and docs-site pages**; see "Stage 3 as built" | M |
| 4 | Migration: startup import, file deletion, `--upgrade-check` finding, readiness row, plaintext notice; backup excludes the directory and carries `ssh-ca.keystore`; restore of old archives; reset | M |
| 5 | Live proof on ca4 with the signer as its own unit: sshd accepts user and host certificates for all three key types; a KRL revokes; backup and restore round trip; migration from a 0.4.0 install with plaintext keys; the container image issues an SSH certificate | S |
| 6 | Optional: PKCS#11 adoption for SSH keys; `ImportSshCa` ceremony | M |

Stages 1 to 5 are the release, **L** overall. Stage 1 can start at once, since it touches nothing
shared.

### Stage 3 as built

- **Create.** The label check, then `GenerateKey` with usage `ssh` under a ceremony context at
  instance scope carrying the ceremony id. One database transaction writes the CA row, its
  groups, the `SshCaKeys` row (public key rendered from the returned SubjectPublicKeyInfo, storage
  `Signer`, no path) and the default signing profiles; then `CommitKey` names the new CA. The
  profiles are written before the commit, not after it as "Key lifecycle" lists them, so that one
  transaction holds every row, as X.509 CA creation does.
- **Create, when it fails.** A failure before the transaction commits rolls it back and retires
  the key. A commit that is refused or fails retires the key and deletes the rows. A node that
  stops between the transaction and the commit leaves an enabled SSH CA whose key the signer
  does not hold; signing with it answers 400 `MCA-CFG-005`, and nothing repairs it (X.509 has
  the same window). Stage 4's readiness check should show such a row.
- **Sign.** The profile checks stay in the controllers. The node parses the subject key with
  `ModularCA.Ssh` (DSA is 400), refuses a `LegacyFile` row before asking the signer, turns the
  option strings into the exact option set (`SshCertificateOptions`), backdates `valid_after` by
  `SshCaService.ValidAfterBackdate` and calls `SignSshCertificate` under
  `SigningPurpose.SshCertificate` naming the SSH CA at instance scope. Principals, key id and
  option values reach the signer as given; nothing is rewritten for a command line any more. The
  row stored is read from the returned certificate, which is stored only when it is for the
  subject key and serial asked and signed by the row's key.
- **Options.** Names are matched without regard to case. A `no-*` name withholds its `permit-*`
  and adds nothing, `clear` is ignored, and an unknown name goes to the signer to be refused.
- **Refusals** (`SshSignerRefusals`). `SignerLocked` and `OperationUnsupported` are 503 with the
  reason, as is a `LegacyFile` row ("SSH CA key awaiting import into the signer"). `UntypedData`
  is 400 with the signer's reason. `UnknownKey` is 400 `MCA-CFG-005`. Anything else is left as
  the signer gave it. The three sign routes carry the unlocked-signer filter.
- **KRL.** Built in process by `SshKrl.Encode` from the row's public key and the revoked serials,
  for a `LegacyFile` row and on a validation-only host too. `krl_version` is the number of
  revoked certificates (open question 5).
- **Audit.** The entries of create (`SshCaKeyCreated`, new), sign, revoke and disable are written
  by the service, once. The self-service sign route, which wrote none, now has one. A refused
  create or sign has a failure entry that carries a principal count, never names. A KRL download
  has none.
- **Removed.** `ssh-keygen`, `ProcessRunner`, the command-line sanitizers, `SshCaConfig`,
  `PUT /config/ssh-ca`, the `sshCa` section of `GET /config` and of `config.yaml.example`, and
  the Settings card. A leftover `SshCa` section in `config.yaml` is ignored, with a warning only
  for a value an operator chose.
- **`ListKeys` consumers** look a key up through `X509SignerKeys`, which passes over SSH CA keys.
- **Backup, until stage 4.** With `SshCaConfig` gone, backup wraps and excludes only the default
  `config/ssh-ca-keys`. An install whose `SshCa.KeyStoragePath` named another directory inside
  `config/` would have its key files copied into an archive unwrapped. Stage 4 finds the
  directories from the `PrivateKeyPath` of `LegacyFile` rows instead, and must land before any
  build of this branch is installed.
- **Not built.** The storage column and generation-form text (`SshCertificates.tsx`), the key
  detail fields and the plaintext notice (`SshCaKeyDetail.tsx`), the backup text
  (`BackupRestore.tsx`), the readiness row, and the docs-site pages (`admin/ssh.ts`,
  `admin/ca-and-certs/key-ceremonies.ts`, the public and self-service SSH endpoints, the UI
  guides).

### Carried from stage 2 into stages 3 and 4

Part 1 of stage 2 left these for the stages that first make an `ssh-ca.keystore` on a real
install. None is reachable before stage 3, since nothing in the node generates or imports an SSH
key through the signer yet.

- **Reset.** It deletes `ssh-ca-*` and not `ssh-ca.keystore`. A file with no `Keystores` row
  leaves the signer locked at the next start, so reset must remove the file with the rows.
- **A crash while the first SSH key is written** can leave the file without its row, or the
  reverse, with the same result. The unlock message says which, and that the file is moved aside
  or restored; stage 4 documents it in the operator guide.
- **Restore.** A whole `ssh-ca.keystore` restored where no `Keystores` row exists for it is
  verified as the other files are with no pin, and is then refused at unlock. Restore must bring
  the row first, as it does for the other two.
- **Backup.** `KeyRef.BackupKeystores` names two files; stage 4 adds the third.
- ~~**Older signer, newer node.** A signer that predates `KeySpec.usage` ignores it and returns a
  pending key in `ca-certs.keystore`. The node checks the keystore of the returned reference and
  retires the key when it is not `ssh-ca.keystore`.~~ Closed in stage 3
  (`SshCaService.GenerateKeyPairAsync`): the key is retired, no row is written, and the caller
  is told the signer predates the SSH keystore and must be upgraded first (503).
- ~~**`ListKeys` consumers** (`CaCreationService`, `OcspResponderService`, `TimestampService`)
  match by id alone. They skip keys of kind `SshCa`.~~ Closed in stage 3: those three, and
  `ScepService` and `CmpService`, which matched the same way, look a key up through
  `X509SignerKeys`, which passes over a key of kind `SshCa` or in `ssh-ca.keystore`.
- **The break-glass unlocker** has not been checked against `ssh-ca.keystore`.
- **One approved `CreateSshCa` ceremony** is not held to a key count, and a pending SSH key does
  not expire. Both are as X.509 is today, and belong to verified approvals in 0.4.3.

## Decided by the owner (2026-10-05)

1. **Profile extensions are exact.** A certificate carries exactly the profile's extensions. This
   is not `ssh-keygen`'s defaults-plus-profile behaviour, which is what ships today, so a
   certificate issued after the change may carry fewer permits than the same profile issued
   before: a profile naming only `permit-pty` issued all five user permits, and afterwards issues
   `permit-pty` alone. Operators who relied on the defaults add those permits to their profiles.
2. **`ssh-ca.keystore` shares the secondary passphrase** with `ca-certs.keystore`. Operators who
   keep secondaries in `MODULARCA_KEYSTORE_SECONDARY_PASSPHRASE` have nothing to add.
3. **Migrating the existing plaintext keys needs no ceremony**, on any instance. The import runs
   automatically at the first start after the upgrade, and each key's import is audited.
4. **The plaintext history gets a notice only in this release.** A console notice and the upgrade
   output explain that the keys were stored in plaintext, that earlier archives and snapshots still
   hold them, and recommend rotating the SSH CA. Guided rotation comes in a later release.

## Open questions for the owner

1. **`valid_after` backdating**: five minutes for clock skew, or none, matching `ssh-keygen`?
   Still open. What the signer does meanwhile (stage 2): it refuses a `valid_after` more than
   **ten minutes before** its own clock or more than **five minutes after** it. That is one
   constant, `SshValidAfterAllowance` in `InProcessSigningService.SshCertificates.cs`, marked as
   this open decision, and it changes with the answer. The past bound is wider than the five
   minutes "What the signer enforces" gives so that a node which backdates by five minutes and
   runs up to five minutes behind the signer is still served; the future bound is not widened,
   since nothing asks for a certificate that is not valid yet. `SshCertificateRules` takes the two
   bounds separately for this (`SshClockSkew`); its own default stays five minutes both ways. If
   the answer is "no backdating", the past bound can come down to the five minutes of clock skew
   alone; if the node backdates by more than five minutes, it has to go up by as much.
   What the node does meanwhile (stage 3): it backdates by five minutes. That is one constant,
   `SshCaService.ValidAfterBackdate`, marked as this open decision and naming the signer's
   allowance that depends on it. The window is counted from the backdated start, so that it never
   exceeds what a profile or the key allows: a certificate asked for N hours is valid for N hours
   less five minutes from the moment it is issued. With `ssh-keygen` it ran N hours from that
   moment. "No backdating" is that constant set to zero.
2. **Empty KRL**: keep today's 204 / JSON message, or always return a valid KRL with no entries,
   which an `sshd` `RevokedKeys` fetcher can install without special-casing? Stage 1 does not force
   this: `SshKrl.Encode` with no serials writes the header-only KRL, byte for byte what
   `ssh-keygen -k` writes, so either answer is available.
   What is built meanwhile (stage 3): always a valid KRL and 200, on both routes. The decision
   is one switch, `SshCaService.ServeKrlWithNoEntries`. Turned off, it gives back what was there
   before: with nothing revoked the admin route answers 200 with the JSON message "No revoked
   certificates; KRL is empty." and the public route answers 204 with no body. Both controllers
   still hold those answers for that case.
3. **`ssh-dss` subject keys** are accepted today (`SshCaService.cs:600`) and OpenSSH has removed
   DSA. Refuse them now? Stage 1 follows the signer's list in this design, which already leaves DSA
   out: `SshCertificateRules.CheckSubjectKey` refuses it and the encoder cannot make a DSA
   certificate. So DSA is refused from stage 3 whatever the answer. The parser still reads
   `ssh-dss`, so the node can name the key type in its refusal. What stays open is only whether the
   node refuses DSA before stage 3.
   As built (stage 3): the node refuses a DSA subject key itself, with 400 and a sentence that
   names DSA, before it asks the signer. Refusing DSA before stage 3 is no longer a question now
   that stage 3 is built.
4. **Stage 6**: is importing an external SSH CA key (`ImportSshCa`) wanted, and is PKCS#11 for SSH
   needed before HA?
5. **`krl_version`** (raised by stage 3). "Key lifecycle" makes it the time of the newest
   revocation. No row records when an SSH certificate was revoked: `SshCertificates` has
   `IsRevoked` and no time. Stage 3 added no column, so what is built is the number of revoked
   certificates of the CA key (`SshCaService.KrlVersionOf`): zero for an empty list, one more
   with each revocation, and never less, since a revocation is not undone and a certificate row
   is not deleted. Is the count enough, or is a
   `SshCertificates.RevokedAt` column wanted, with its migration, to give the time?
