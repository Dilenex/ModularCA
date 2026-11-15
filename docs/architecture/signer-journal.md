# The signer's issuance journal

Status: first version built (0.4.5). It **writes** the journal and **reads its head**. It does
not replay or adopt anything. "What is not built" at the end is exact.

The journal is an append-only, hash-chained record, in files, of what the signer signed and of
certain facts the node asserts. It exists so that a database that goes back in time (a restore,
a roll-back) no longer loses the knowledge of what was issued and revoked.

This note states the format as built. A verifier can be written from it alone. The design and its
reasons are in `signer-hardening.md`, Item 2; where the two differ, this note is what the code
does. The code: `ModularCA.Journal/` (format, writer, verifier, head; no dependency on the
database, ASP.NET or any other ModularCA project), `ModularCA.Keystore/Signing/SignerJournal.cs`
and `SignerJournalKeys.cs` (the signer's side), `ModularCA.Database/ModularCADbContext.SignerFacts.cs`
and `ModularCA.Core/Services/Journal/` (the node's side).

## 1. The home, and where the segments are

- **The home** is one directory, set on the signer: `Signer.Journal.Directory`, overridden by
  `MODULARCA__SIGNER__JOURNAL__DIRECTORY`. Default: `signer/journal`.

  | Layout | The home |
  |---|---|
  | One process holds the keys (no `--signer-dir`) | a relative path is taken from the application directory: `<base>/signer/journal`, for a packaged install `/opt/modularca/signer/journal` |
  | The signer has its own directory (`--signer-dir <dir>`) | a relative path is taken from that directory, and a leading `signer/` names the directory itself: `<dir>/journal`. For the packaged split install and the pod, whose directory is `/opt/modularca/signer`, that is the same `/opt/modularca/signer/journal` |
  | An absolute path, or the environment variable | used as it is, in either layout |

- **It is not in the keystores directory.** A journal that goes back in time with the
  keystores protects nothing: the roll-back that takes the database back would take the record
  of what was issued and revoked back with it. Give the home a volume that is never rolled
  back or restored with the keystores or the database.
- **A volume may be mounted directly on the home.** Nothing ever renames or replaces the home
  itself. Everything is inside it:

  | In the home | What it is |
  |---|---|
  | `current/` | the live segments: where the signer creates, appends and renames, and what a reader reads |
  | `set-aside-instance-<tag>-<time>/` | the journal of another instance, found in `current/` and set aside by the signer |
  | `set-aside-reset-<time>/` | the journal a factory reset set aside |

  `<tag>` is the first 16 letters and digits of the other instance's identifier; `<time>` is
  `yyyyMMdd-HHmmss-fff`, UTC. Example: `set-aside-instance-3f9c0a7b12d455e0-20261113-091502-417`,
  `set-aside-reset-20261113-091502-417`. The home holds these and nothing else.
- **The signer creates what is missing**: the home when its parent exists and it does not, and
  `current/` in a home that is empty, as a freshly mounted volume is. A home it cannot write
  (read-only, or not its account's) leaves the journal `unavailable`, with the reason.
- One journal per instance. A signer does not append to a journal that names another instance.
  - **A restore onto a host that ran another instance** leaves that instance's journal in
    `current/`. The signer **sets it aside**: it renames `current` to
    `set-aside-instance-<tag>-<time>` inside the home, whole and unchanged, makes a new
    `current/` and begins this instance's journal.
  - **A factory reset** makes another instance. It renames `current` in the default home of a
    one-process install (`<base>/signer/journal`) to `set-aside-reset-<time>`, and
    `journal.keystore` to `journal.keystore.reset-<time>`. A home a setting names elsewhere, or
    a signer directory elsewhere, is not known to the reset; the new instance's signer finds
    the old journal at its first start and sets it aside as `set-aside-instance-…`.
  - **A rename that fails** (the account may not rename inside the home) leaves the journal
    `unavailable`: the signer issues nothing until it can, or until `current` is renamed there
    by hand.
  - **Nothing prunes a set-aside journal.** It stays in the home, on the journal's volume,
    until a person removes it. The signer counts them and their size (section 13).
- **What two journals can share.** A reader that tells journals apart by `instanceId`, `term`
  and `incarnation` from their heads must know that these three do not identify a journal:
  - `term` is always 0 in this version, and `incarnation` is all zero wherever the incarnation
    variable is not set, so in practice only `instanceId` differs.
  - A factory reset does make a new instance identifier before the new `current/` gets its
    `Genesis`: the identifier comes from the new instance's system key, which the reset has
    just made. So a journal set aside by a reset and the `current` that follows it differ.
  - But an archive of an instance restored onto a host that ran another, or onto an empty
    volume, begins a **new** journal for that instance, from sequence 1, with the same
    identifier as the journal that instance had before. So two journals can carry the same
    three: a set-aside journal of instance A and a later `current` of A (A is restored onto a
    host that had set A's old journal aside), two set-aside journals of A in one home, or
    A's journals on two hosts. They are different chains: their first records differ, and so
    does the hash of every record. A reader needs the set-aside name, or the hash of the
    `Genesis` record, beside the three.
- The segments directory holds segment files and nothing else. The signer creates, appends and
  renames there. It never rewrites, truncates, compresses or deletes a record.
- Created owner-only (`0700`, files `0600`) where the system has modes.

## 2. Segment files

| State | Name |
|---|---|
| Open | `<first sequence, 20 digits>.open.mcaj` |
| Sealed | `<first sequence, 20 digits>.mcaj` |

- A segment is whole records from its first byte. Its first record is a `SegmentStart`. The
  journal's first segment is `00000000000000000001`: sequence 1 is its `SegmentStart`, sequence
  2 the `Genesis`.
- Sealing is a `Checkpoint` (when records wait for one), a `Seal`, one flush, then **one
  rename**. The bytes are not touched.
- At most one open segment. A segment is sealed when it reaches 64 MiB, when it is 24 hours old
  and has taken a record since it was opened, and when the signer stops in order. A segment may
  pass 64 MiB by the one record that crosses it and its closing records.
- **A start of the signer that records something begins a new segment, at its first record.**
  A start that records nothing creates, renames and writes nothing.
  - When the signer starts over a directory that holds a journal it only reads: the newest
    segment is checked, and that the journal is this instance's.
  - The first record offered (a certificate, a CRL, a fact from the node) is what applies the
    rule below and begins the segment: `SegmentStart`, this start's `Start`, a key change if
    there is one, a `Checkpoint`, then the record.
  - So a signer that starts and dies in a loop leaves the directory as it found it, however
    often. The one exception is the very first start, which makes the journal: its first
    segment, with `Genesis`. A second start finds that journal and waits like any other.
  - A file a start finds open and unsealed is never appended to. It keeps its open name until a
    start has something to record.
  - A `Start` record therefore marks a start that recorded something, not every start.
- **The start-up rule.** If the newest segment's last whole record is not a `Seal` (the signer
  stopped without warning, with or without a torn record at the end, and whether or not the
  file still has its open name), the signer renames it to its sealed name if needed, as it is,
  and begins a new segment. The new `SegmentStart` gives the number of bytes of whole records
  in the previous file. A reader takes that many bytes and no more.
- **After a failed write or flush** the signer does the same while it runs: the segment is left
  as it is and renamed, and the next record opens a new one. Nothing is ever appended after
  bytes that may be torn.
- **A file that holds no whole record** (its creation was interrupted before its `SegmentStart`
  reached the disk) is no part of the chain. The next segment has the same first sequence and so
  the same name, and is created over it. This is the one case where bytes are replaced; they
  were never a record. See "Where the build departs from the layout".

**Windows and Linux.** The writer closes its handle before it renames, so sealing needs nothing
of the platform. The open segment is opened for writing only and shared for reading and for a
rename, so a reader can hold it open while it is appended to and renamed. A flush is
`FileStream.Flush(flushToDisk: true)`. The rename itself is not flushed to the directory: after
a power loss the file may still have its open name, which the start-up rule above covers.

## 3. A record

All integers are big-endian.

```
record  = length (u32) | body | hash (32 bytes)
length  = number of bytes in body
hash    = SHA-256(body)

body    = "MCAJ"                 4 bytes
          format      u8         1
          type        u16        section 5
          flags       u8         bit 0: asserted by the node, not seen by the signer
          seq         u64        1 for the first record of the journal, +1 for each record
          at          i64        microseconds since 1970-01-01 UTC, the signer's clock
          term        u64        0 until terms exist
          incarnation 32 bytes   SHA-256 of the incarnation value; all zero when none is set
          prev        32 bytes   hash of record seq-1; all zero for seq 1
          payload     the rest   one CBOR map, section 4
```

- The fixed part is **96 bytes**; a record costs **132 bytes** before its payload.
- A record is at most 256 MiB.
- **Whole or torn:** fewer than 4 bytes left, or fewer than `length + 32` bytes after the length,
  or a length that would pass 256 MiB, or a hash that does not match, means the file's whole
  records end before this one. Nothing after that point is read.
- The hash is both the checksum and the link.
- `incarnation` is SHA-256 of the UTF-8 bytes of `MODULARCA__INSTANCE__INCARNATION` with
  surrounding white space removed: the hash the node stores for its continuity check
  (`rollback-continuity.md`), so a record matches a continuity event by comparing the two. The
  process that holds the keys reads the variable itself.
- A chain is checked from the fixed parts alone, without decoding a payload.

A worked record (type 37, flag bit 0, sequence 2, at 1,700,000,000,000,000, incarnation
`11…`, prev `22…`, payload `{61: 5, 64: 1, 65: "x"}`), in hex:

```
0000006b 4d43414a 01 0025 01 0000000000000002 00060a24181e4000 0000000000000000
11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111
22222222 22222222 22222222 22222222 22222222 22222222 22222222 22222222
a3183d0518400118416178
44e006789d3f86b579ecf42ec3ccd75992bc852ba5f4c4b24774e0d4040d4402
```

## 4. The payload

One CBOR map, deterministic encoding (RFC 8949, section 4.2): definite lengths, shortest
integers, keys in ascending order. Keys are unsigned integers. **A key number never changes
meaning** and is never reused; a member that is absent is left out, never written as null.

- Every **time** in a payload is an integer of microseconds since 1970-01-01 UTC, like `at`.
- Every **hash** is 32 bytes of SHA-256. A **serial** is a byte string: unsigned, big-endian, no
  leading zero byte. An **identifier** is text; a row id is a GUID in its 8-4-4-4-12 form.

| Key | Name | Holds |
|---|---|---|
| 1 | `ca` | the CA's identifier in the instance |
| 2 | `caKey` | SHA-256 of the issuing CA's public key (SubjectPublicKeyInfo, DER). For an SSH CA: of its public key blob |
| 3 | `caCert` | SHA-256 of the CA certificate current when this was signed |
| 4 | `context` | map: 1 purpose, 2 protocol, 3 requester; each only when known |
| 5 | `version` | the product version that wrote the record |
| 10 | `instanceId` | the instance identifier |
| 11 | `checkpointKey` | the checkpoint key block (section 7): map of 1 `key`, 2 `systemKey`, 3 `systemSignature`, 4 `algorithm` |
| 12 | `genesisReason` | 1 first start, 2 continues another journal |
| 13 | `continues` | map: 1 seq, 2 hash; the head of the journal this one continues |
| 14 | `previous` | map: 1 name, 2 bytes of whole records, 3 last sequence, 4 last hash, 5 whether it ended with a `Seal` |
| 15 | `keyHash` | SHA-256 of the public key that made `signature` |
| 16 | `algorithm` | the algorithm of `signature` |
| 17 | `signature` | a signature: a checkpoint's, a certificate's or a CRL's |
| 18 | `previousUnsealed` | whether the previous segment ended without a `Seal` |
| 19, 20 | `oldKeySignature`, `oldKeyAlgorithm` | the old checkpoint key's signature over the new key |
| 21, 22 | `oldSystemKeySignature`, `oldSystemKeyAlgorithm` | the old system key's signature over the new system key |
| 23 | `explains` | map: 1 kind (1 restore, 2 changed incarnation); 2 archive, 3 its instance identifier, 4 its creation time; 5 old incarnation, 6 new incarnation |
| 24 | `lastRemoved` | reserved for `Pruned` |
| 25 | `systemPublicKey` | the system key's public key (SubjectPublicKeyInfo, DER) |
| 26 | `genesisHash` | in a `SegmentStart`: the hash of the journal's `Genesis` record (32 bytes). Every `SegmentStart` carries it but the journal's first, which precedes the `Genesis` in its own segment |
| 30 | `tbs` | the whole to-be-signed structure, DER |
| 32 | `serial` | a certificate serial |
| 33, 34 | `notBefore`, `notAfter` | validity |
| 35 | `subjectKey` | SHA-256 of the subject's public key |
| 36 | `isCa` | whether the certificate is a CA's |
| 37 | `spent` | array of maps: 1 kind, 2 identifier, 3 which use (from 1) |
| 38 | `answers` | map: 1 kind, 2 identifier |
| 39 | `replaces` | map: 1 serial, 2 `caKey` |
| 40 | `belongs` | map: 1 certificate profile, 2 space, 3 owner kind, 4 owner, 5 template |
| 42 | `crlNumber` | unsigned |
| 43, 44 | `thisUpdate`, `nextUpdate` | |
| 45 | `sameSetAs` | the sequence of the record, in the same segment, that holds the same revoked set |
| 46 | `tbsHash` | SHA-256 of the to-be-signed bytes, when the record does not carry them |
| 47 | `delta` | true for a delta CRL; absent for a full one |
| 50 | `sshCertificate` | the whole SSH certificate as signed |
| 51 | `sshRevocationList` | the whole SSH revocation list (an OpenSSH KRL) |
| 60 | `revocationReason` | the CRLReason code of RFC 5280 |
| 61 | `time` | when the fact happened |
| 62 | `known` | whether the CA has a record of the certificate |
| 63 | `form` | 1 revoked, 2 hold, 3 retired |
| 64 | `kind` | the token kind in type 34; the disabled kind in type 37 |
| 65 | `id` | an identifier |
| 66, 67, 68, 69 | `archive`, `archiveInstanceId`, `archiveCreatedAt`, `archiveHead` | a restore: the archive's file name, and from its manifest the instance identifier, the creation time and the journal head (map: 1 seq, 2 hash) |
| 70, 71 | `oldIncarnation`, `newIncarnation` | the two hashes |

Kinds: **token** 1 enrollment token, 2 CMP shared secret, 3 ACME external account binding, 4
first administrator's claim. **answers** 0 none, 1 pending request, 2 ACME order, 3 enrollment
transaction. **owner** 1 user, 2 badge, 3 infrastructure registration. **disabled** 1 CA, 2 SSH
CA key, 3 space, 4 account, 5 sign-in credential.

`spent` carries a token's **identifier only**: never the token or a hash of it.

## 5. Record types

A number never changes meaning. Numbers not listed are free.

**Structure**

| Type | Name | Payload keys |
|---|---|---|
| 1 | `Genesis` | 10, 11, 12, 5, 25; 13 when it continues another journal |
| 2 | `SegmentStart` | 10, 11 (the block **in force** when the segment begins), 25, and 14 unless it is the journal's first segment |
| 3 | `Checkpoint` | 15, 16, 17 |
| 4 | `Seal` | none: the empty map, one byte `a0` |
| 6 | `Start` | 5, 18; one at every start of the signer |
| 7 | `CheckpointKeyChanged` | 11 (the new block), 25; 19 and 20 when the signer holds the old checkpoint key; and, when the system key differs, 21 and 22 when it holds the old system key, otherwise 23 |

**What the signer signed** (flags 0)

| Type | Name | Payload keys |
|---|---|---|
| 16 | `Certificate` | 1, 2, 3, 4, 5; 30 and 17, from which the certificate is rebuilt; the index 32, 33, 34, 35, 36; and 37, 38, 39, 40 as the node passed them |
| 17 | `Crl` | 1, 2, 3, 4, 5; 42, 43, 44, 17; and either 30, or 45 with 46; 47 for a delta |
| 20 | `SshCertificate` | 1, 2, 4, 5; 50; and 37, 38, 39, 40 |

- **A certificate is rebuilt** as `SEQUENCE { tbs, the AlgorithmIdentifier that is the
  to-be-signed certificate's own signature field, BIT STRING signature }`.
- Every to-be-signed certificate the signer signs is recorded, whichever key signs it: a CA key,
  and a new CA's key before it is committed (its own certificate and its delegated signers').
  `ca` and `caCert` are absent where there is none yet: a root signs itself.
- **When a `Crl` carries the whole list:** when the revoked set differs from the previous CRL of
  the same kind (full or delta) for that `caKey`, and at the first such CRL of each `caKey` in
  every segment. Otherwise it points at a record in the same segment. Two CRLs have the same
  revoked set when their entries, each as its DER encoding, are the same set.

**Facts the node asserts** (flag bit 0 set)

| Type | Name | Payload keys |
|---|---|---|
| 21 | `SshRevocationList` | 1, 2, 51 |
| 32 | `Revocation` | 1, 2, 32, 60, 61, 62, 63 |
| 33 | `Unrevocation` | 1, 2, 32, 61 |
| 34 | `SpentWithoutCertificate` | 64, 65, 61 |
| 35 | `RestoreMarker` | 66, 67, 68, 69, 61 |
| 36 | `ContinuityEvent` | 70, 71, 61 |
| 37 | `Disabled` | 64, 65, 61 |

- Enabling again is not recorded.
- A test (`SignerFactQueueTests`) lists every endpoint the mode gate classes as a restriction
  with the fact it produces, and holds the kinds of type 37 to that list, so neither changes
  alone.

**Not written by this version:** 5 `Pruned`, 18 `OcspSummary`, 19 `OtherSignature`, and the
reserved 48 (key operations), 49 (secret wrap and unwrap), 50 (ceremonies), 51 (registry, lock,
unlock, lease, term), 64 (refusals), 80 (`RestoreRecovered`).

## 6. What a reader does with what it does not know

- An unknown type: check its hash and its place in the chain, then skip it.
- An unknown key in a payload, or an unknown flag bit: ignore it.
- `format` other than 1: stop, and say which was found.

## 7. The checkpoint key

Decided by the owner on 2026-11-13: a dedicated checkpoint key, signed by the system key.

- **The system key** is the key of the system signing CA: the key whose SubjectPublicKeyInfo
  hash is pinned for `ca-certs.keystore`, which is the key that signs the keystore files. It
  signs for the journal only when a checkpoint key is made or changed. Its hash is what `hello`
  answers as `systemKey` (`hub-local-connection.md`).
- **The checkpoint key** is a key of the instance's own, used for nothing else. It is kept as
  the last entry of `journal.keystore`, a keystore file of its own beside the others, encrypted,
  signed and pinned to the system signer as they are. No reference to a key in that file is ever
  served, so nothing but a checkpoint is signed with one. It is made at the first start that
  needs it.
- **Its algorithm** is of the system key's family: RSA of the same size (4096 bits at most),
  ECDSA on the same curve, Ed25519, Ed448, or the same ML-DSA parameter set. For an SLH-DSA
  system key it is ML-DSA-65: a hash-based signature every second is too large and too slow.
- **`journal.keystore` is in the keystores directory**, whatever directory the journal is in.
- **A keystores directory put back to an older state** (a volume roll-back, not a restore)
  beside a journal whose current checkpoint key is newer: the signer holds a key that is not
  the journal's current one. With the same system key it goes on at once: at the first record
  it writes a `CheckpointKeyChanged` whose block the system key signed, the vouched form of the
  table below. Which key it holds depends on the database: an older file that still verifies
  against the database's row is loaded and becomes current again; one that does not is moved
  aside and a new key is made. Either way a verifier accepts the change. If the roll-back also
  changed the system key, the last two rows of the table apply.
- **It is not in a backup.** It vouches for one host's journal, which a backup does not carry
  either. A signer that finds `journal.keystore` with no row for it in the database (a database
  restored from before the key was made) moves the file aside as `journal.keystore.bak.<time>`
  and makes a new key; one that finds the row and no file removes the row and makes a new key;
  one that finds a file that does not verify or open against the row (another instance's, after
  a restore onto its host) records the failure as it does for any keystore, moves the file
  aside, removes the row and makes a new key. A file that does not verify is never loaded.
  In each case the system key signs the new block.
- **Where the system key cannot be exported** (a key on a PKCS#11 token), a keystore file
  cannot be signed, so none is written: a checkpoint key is made at each start and held in
  memory, and the system key signs for it on the token.

**The key block** (key 11):

| Member | Holds |
|---|---|
| 1 `key` | the checkpoint public key (SubjectPublicKeyInfo, DER) |
| 2 `systemKey` | SHA-256 of the system key's SubjectPublicKeyInfo |
| 3 `systemSignature` | the system key's signature over the message below |
| 4 `algorithm` | the algorithm of `systemSignature` |

**The signed messages.** Each begins with an ASCII prefix that ends in a zero byte, then the
instance identifier as a big-endian u16 length and its UTF-8 bytes:

| Signed by | Message |
|---|---|
| the checkpoint key, in a `Checkpoint` | `"ModularCA.Journal.Checkpoint.v1\0"`, instance identifier, the checkpoint record's own `seq` (u64) and its `prev` (32 bytes) |
| the system key, in a key block | `"ModularCA.Journal.CheckpointKey.v1\0"`, instance identifier, `key` |
| the old checkpoint key, in a `CheckpointKeyChanged` | `"ModularCA.Journal.CheckpointKeyChanged.v1\0"`, instance identifier, the new `key` |
| the old system key, in a `CheckpointKeyChanged` | `"ModularCA.Journal.SystemKeyChanged.v1\0"`, instance identifier, the new `systemKey` (32 bytes) |

**Algorithm names** are the product's own, compared without case: `SHA256WITHRSA`,
`SHA256WITHRSAANDMGF1` (RSA-PSS, MGF1, the digest's length as salt) and their SHA-384 and
SHA-512 forms, `SHA256WITHECDSA`, `SHA384WITHECDSA`, `SHA512WITHECDSA` (the signature is the
DER `Ecdsa-Sig-Value`), `Ed25519`, `Ed448`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, and the
`SLH-DSA-…` parameter sets.

**Checkpoints.** One is written within a second of the first record no checkpoint covers, or
after 1,000 such records, whichever comes first; at the end of the records a signer writes when
it opens; and before a `Seal`. With no activity there is none.

**A change of key.** A `SegmentStart` carries the block in force. When the signer's key differs,
a `CheckpointKeyChanged` follows the opening records and the block it carries is in force from
there. One rule for both keys: a change is believed when the key before it signed it, or when
what explains it is matched from outside the journal.

| What changed | The record carries | A verifier |
|---|---|---|
| The checkpoint key; the system key is the same | the new block, signed by that system key; and the old checkpoint key's signature when the signer still holds it | accepts it: the system key before it signed it |
| The system key, and the signer holds the old one | the old system key's signature over the new one | accepts it |
| The system key, and the incarnation changed since the last record | `explains` kind 2 with the two hashes | checks the hashes against the records and **reports** the change for matching from outside |
| The system key, the same incarnation | nothing at first: no checkpoint is written until the node's `RestoreMarker` arrives, and the `CheckpointKeyChanged` directly after it carries `explains` kind 1 naming that restore | checks it against the marker directly before it and **reports** the change |
| The system key, and no `RestoreMarker` comes within ten minutes | no `explains` | reports a **fault** |

A reported change is not believed on the journal's word: someone with a copy can append a
marker and a change that chain. The hub matches each to a restore or a roll-back it started.

**During the ten minutes** the instance works as usual:

- The signer signs. Certificates, CRLs and facts are recorded and flushed as always, and each
  is returned only after its flush. Only checkpoints are held back, because a checkpoint would
  be signed with a key the chain does not know yet.
- The node is ready. `checks.journal` has the status `awaiting_restore_marker`, with
  `awaitingRestoreMarkerUntilUtc`, `awaitingRestoreMarkerSecondsLeft` and a message that gives
  the time left. The status does not fail readiness.
- The ten minutes are counted once, from the start of the signer that found the change, and
  not again when its segment begins.
- The marker, when it comes, is followed at once by the `CheckpointKeyChanged` and a
  `Checkpoint`. When the wait ends without one, the change is written unexplained with the next
  record offered (a start that records nothing writes nothing, here too).

## 8. The two commands

Both open segment files for reading only. They create and lock nothing, write no log file, and
need no signer, keystore, database or credentials. They run beside a signer that is appending,
on a read-only mount and on a bare copy of the directory. Without `--journal-directory` they
read the directory the signer's settings name.

```
ModularCA.API --role signer --journal-head [--journal-directory <path>] [--sealed | --sealed-from <sequence>]
```

One line of JSON on standard output. Hashes, keys and signatures are lower-case hex:

```json
{"format":1,"instanceId":"…","genesisHash":"…","seq":18231,"hash":"…","term":0,"incarnation":"…",
 "open":{"segment":"00000000000000017001.open.mcaj","wholeBytes":1840332},
 "checkpoint":{"seq":18229,"hash":"…","key":"…","algorithm":"…","signature":"…"},
 "checkpointKey":{"key":"…","systemKey":"…","systemPublicKey":"…","systemSignature":"…","algorithm":"…"}}
```

- By default it reads the newest segment only.
- `genesisHash` is the hash of the journal's `Genesis` record: with `instanceId`, what tells
  one journal of an instance from another (section 1). The short head has it from the newest
  segment alone, whose `SegmentStart` states it (or which holds the `Genesis` itself, while the
  journal has one segment), so it is still there when older segments are gone. The verifier
  holds every `SegmentStart` to the real `Genesis` when the first segment is among those read,
  and otherwise to what the `SegmentStart` records before it state.
  - A journal written before segments carried it (only test journals of the first build): the
    short head prints `null`; with `--sealed` or `--sealed-from` the first segment is opened
    for it. The signer that goes on from such a journal reads the first segment once and
    states the hash in every segment it begins.
- `--sealed` adds `"sealed":[{"segment","wholeBytes","lastSeq","lastHash","torn"}]` for every
  sealed segment, and reads them all to do it.
- `--sealed-from <sequence>` adds the same list for the sealed segments whose **first
  sequence** is at or after the one given, and opens no older segment. A caller that holds the
  segments up to some sequence asks from the next one. A sequence inside a segment lists from
  the next segment on; a sequence past the head gives an empty list. With `--sealed` it is
  ignored.
- `checkpointKey.systemPublicKey` is the system public key itself (SubjectPublicKeyInfo, DER),
  as the journal carries it beside the block. Its SHA-256 is `systemKey`, and it verifies
  `systemSignature`, so a holder of the hash from `hello` checks the block from this line
  alone. Null for a journal whose records do not carry it.
- **What `--journal-directory` may name.** Either a home or a directory that holds segment
  files itself. The rule: a directory that holds at least one segment file is read as it is (a
  set-aside journal, `current/` named directly, a bare copy of the segments); otherwise, when
  it has a `current` directory, that is read; otherwise it holds no journal. A home with no
  `current/`, or an empty one, is exit 3. Without the option the commands read the home the
  signer's settings name, by the same rule.
- A set-aside directory is the whole journal of the other instance, and is read like any other.
- `seq`, `hash`, `term`, `incarnation`: the last whole record.
- `open` is null when there is no open segment; the head is then the last sealed segment's.
- `checkpoint` is the newest checkpoint in what was read, or null. `checkpoint.seq` is the
  checkpoint record's sequence and `checkpoint.hash` the hash its signature covers with it: the
  hash of the record before it. `checkpoint.key` is SHA-256 of the key that signed.
- `checkpointKey` is the key block in force at the head.
- It checks the chain of what it read, the key block's system signature when the journal carries
  the system public key, and the newest checkpoint's signature.
- Run beside a signer that is appending, it may report a head a few records old, never a torn
  one.
- **Exit 0** with the line. **Exit 3** when the directory holds no journal. **Exit 4** when the
  chain in what it read does not hold, with the reason on standard error. Exit 1 for a command
  line it cannot read.

```
ModularCA.API --role signer --journal-verify [--journal-directory <path>] [--system-key <hex>]
```

Checks every segment: each record's hash, the sequence and the chain, what each `SegmentStart`
says of the segment before it, every checkpoint's signature, and each key block's system
signature. With `--system-key` the journal must begin under that system key. One line of JSON:
`ok`, `segments`, `records`, `checkpoints`, the head, `unvouched` (the key changes to match from
outside) and `notes`; and `fault` with `segment`, `seq` and `reason` for the first fault.

- Like the head command it opens files for reading only, creates and locks nothing, and works
  on a read-only mount, on a bare copy, and on files that are themselves read-only.
- **Exit 0**: every record holds. **Exit 3**: the directory holds no journal, or does not
  exist. **Exit 4**: a fault, with the line on standard output and the reason on standard
  error; a journal that begins under another system key than `--system-key` names is a fault.
  **Exit 1**: a command line it cannot read.

**No one-off command writes the journal.** The journal is opened for writing by the signer
service and by a node that signs in its own process, and by nothing else. `--journal-head`,
`--journal-verify`, `--upgrade-check` (with and without `--read-only`), `--check-ready`,
`--backup-manifest`, `--backup` and `--restore` run and exit before either is made; started
with `--role signer` they begin no segment and write nothing to the directory. The restore's
marker is a row in the restored database (section 11).

A changed bit in a segment that has a successor is a fault at its record. In the newest segment
nothing says how long it was, so a changed bit there reads as a torn tail: the head goes back to
the last whole record, the segment is reported torn, and a checkpoint held elsewhere (the hub's
copy of an earlier head) is what shows that records are missing.

## 9. What the signer does with it

- **Fail closed.** A certificate, a CRL or an SSH certificate whose record cannot be appended
  and flushed is not returned: the signer refuses with `JournalUnavailable`, and the signature
  it made is dropped. Appends are group-committed: one flush covers a batch, and a signature
  leaves the signer only after the flush that covers its record. A signer whose journal cannot
  be opened still starts, and still signs what the journal does not record (OCSP, SCEP, CMP,
  timestamps).
- **The order is sign, record, return**, for a certificate, a CRL and an SSH certificate alike.
  Before it signs, the signer checks that the journal can take a record and refuses if it
  cannot. After it signs, the record is appended; a signature whose record failed is dropped,
  and the refusal says that the signer signed and could not record it.
- **A full volume.** Nothing stops issuance before a write to the journal actually fails.
  `low_space` and `critical_space` (section 13) are warnings.
- **`SignerAudit` is unchanged.** It is written as before, for every decision.

**The CRL check.** Before it signs a CRL, the signer holds it to the newest CRL it journaled
for that CA key:

- The CRL number must be above every number journaled for the key. Full and delta CRLs share one
  sequence, as the node numbers them.
- A full CRL must list every serial the newest journaled full CRL listed. A serial may leave
  when:
  - it was listed as `certificateHold`: releasing a hold takes it off the list;
  - its certificate has expired: the database holds a certificate with that serial that verifies
    under this CA's key and whose `notAfter` is not after the CRL's `thisUpdate`, which is the
    node's own rule for leaving an entry off;
  - it was revoked with no certificate, and its `ListedUntil` has passed. This one is the node's
    word: there is no certificate to verify.
- A delta CRL is held to the number only.
- A CA key with no journaled CRL has no predecessor: its first CRL is not checked.
- A CRL with no CRL number is refused.
- The node raises its counters past the journal by itself: when a CRL is refused for its number
  (a CRL was signed and its save failed, or the database was taken back), `CrlService` applies
  the time-derived floor a restore applies and generates once more.

**The OCSP check.** A response that says "good" for a serial is refused when the newest
journaled full CRL of that CA key, or a delta journaled after it, lists the serial with a reason
other than `certificateHold` or `removeFromCRL`. "Revoked" and "unknown" are never refused. The
responder then answers the client with an error for that request.

`Signer.Journal.Checks: warn` makes both checks log what they find and sign all the same. It is
the signer's own setting, and `enforce` is the default whether or not a hub is connected. It is
for the time after a database was taken back and before the lost revocations are entered again;
a serial can be revoked without its certificate.

**A refused CRL is cured by the node, and seen when it is not.** A CRL that leaves out revoked
serials is what a database that went back in time produces. The node makes the lost
revocations again from the journal before it generates the CRL, and once more when the signer
refuses one (section 16), so the refusal that follows stands only where that merge could not
cure it. When the signer refuses a full CRL because it leaves out revoked serials, it keeps
that fact for the CA key until it signs a full CRL for it:

- `checks.journal` has the status `crl_refused`, and `refusedCrls` lists each CA: its
  identifier and name, how many serials are missing, when the signer last refused, the number
  of the journaled CRL that lists them, and `publishedCrlExpiresAtUtc`, the `nextUpdate` of the
  CA's newest stored full CRL, which is when the CRL now published runs out. The console's
  "Needs attention" shows the same.
- It does not make the node not ready. The instance issues, serves and answers OCSP; only new
  CRLs for that CA stop. A revoked certificate stays revoked on the published CRL and in OCSP.
- **Every missing serial** is read with
  `GET /api/v1/admin/authorities/{caId}/revoked-serials/missing-from-crl`, under the capability
  revocation needs (`cert.revoke` on that CA). Each entry has `serialNumber`, `reason` (the name
  the revocation request takes), `reasonCode` and `revocationDate`, as the journaled CRL gives
  them, and `certificateHeld`, whether the CA still has a certificate with that serial.
  `POST …/revoked-serials` with a `serialNumber`, a `reason` and a note records one as
  revoked again; where the database still has the certificate, revoke the certificate.
- **A page for it.** The CA's page in the console,
  `/admin/authorities/manage/{caId}#missing-from-crl`, lists the serials under "Certificates
  This CA Does Not Hold" while a refusal stands: serial, reason and date, a link to the
  certificate where the CA holds it, and "Revoke serial" for one, for those selected, or for
  all that have no certificate. The path is `consolePath` in the list's answer and beside
  `serialsAt` in `refusedCrls`, for a link from another system. Revoking several asks for one
  step-up (the one revoking a single serial asks for) and one note, and goes to
  `POST /api/v1/admin/authorities/{caId}/revoked-serials/bulk` with
  `{ "serials": [{ "serialNumber", "reason" }], "note" }`, at most 5,000 a request: each is
  recorded and audited as a single one is, the CRL is generated once after the last, and the
  answer lists `recorded` and `refused` (a serial the CA holds a certificate for, one already
  recorded) with the reason.
- The refusal's own message names the first five serials, counts them all, and gives that
  path.
- The list is the signer's, as of the last CRL it refused. It shrinks as serials are revoked
  again and the node offers the next CRL. It is held in memory: after a restart of the signer
  it is empty until the node next offers a CRL for the CA, which the CRL schedule does.
- With `Checks: warn` nothing is refused and nothing stands.
- There is no one-off command for the list: it needs the running signer, which is the one
  that holds the journaled CRL and the last CRL offered.

After a restart the newest CRL of each key and the revocation facts after it are read back
from the journal, in the background, by record lengths alone; both checks wait for that
reading and for nothing else. The verification of the whole journal follows it and holds up
neither check, nor signing (section 16).

## 10. What the node does

**With an issuance** the node passes what it knows (`SigningContext.Issuance`):

| Path | `answers` | `spent` | `replaces` | `belongs` |
|---|---|---|---|---|
| A request row: the console, the API, an approved pending request, auto-renewal, web TLS, integration API, cert-manager, public enrollment | the request row | a token the request spent | when the row names the certificate it renews | profile, space, requesting user |
| ACME | the order | | as above | as above |
| SCEP, CMP | the transaction | the enrollment token or CMP shared secret it spent | as above | as above |
| EST | the request row | a token it spent | as above | as above |
| MSAE | the request row | | when the renewal was proven | as above, and the template |
| A request that waited for approval | the request row | | as above | as above |
| Reissue | the request row | | the certificate reissued | as above |
| A CA being created, and reissued delegated signers | none (the ceremony, when there was one) | | | space |
| A CA's delegated signer certificates | the request row | | | profile, space |
| An mTLS sign-in certificate | none | | | space, the user |
| An SSH certificate | none | | | the user it is for |

- A value the node does not know is absent: a renewal it cannot recognize, a protocol with no
  transaction identifier, a request nobody's account made.
- **Not filled:** the owner when it is a badge or an infrastructure registration (the request
  row does not name them); the protocol and its transaction for a request that waited for
  approval, which is issued later from its row alone.
- **Not recorded at all:** the certificates the first bootstrap makes (the root, the system
  signing CA and what is issued beside them). They are signed before a signer exists.

**Facts.** The node queues a fact in the table `SignerFactQueue`, **in the same save** as the
change it describes, so a change that is rolled back leaves no fact. A background service in
every process that has a signer offers the queue to it, oldest first, and removes what it took.
A fact the signer does not take stays queued, through a restart, and is offered again after a
wait that grows to five minutes. It never stops or undoes what it describes. A fact may be
recorded twice when a process stops between the signer's answer and the removal of the row.
A pass takes 500 facts. Revocations and released holds of different serials are offered to the
signer together, so that it flushes its journal once for many of them; among themselves they
may be recorded in another order than they were queued. Two facts about the same serial, and
every fact of another kind, keep their place in the order.

Most facts are read off the changes a save is about to make, so a new code path that revokes or
disables something is covered without knowing about the journal:

| Change | Fact |
|---|---|
| A certificate revoked, put on hold, a hold made permanent | `Revocation` (form 1 or 2) |
| A hold released | `Unrevocation` |
| A certificate retired | `Revocation` (form 3) |
| A serial revoked with no certificate | `Revocation` with `known` false |
| A CA, an SSH CA key or a space disabled or deleted; an account deactivated, locked (`IsLocked`) or deleted; an mTLS sign-in credential or an API key revoked | `Disabled` |
| An ACME external account binding used; the first administrator's claim token redeemed | `SpentWithoutCertificate` |
| The stored incarnation replaced by another | `ContinuityEvent` |
| SSH certificates revoked | `SshRevocationList`: the key's list as it then stands |
| A restore ran | `RestoreMarker`, queued by the restore in the restored database |

`SshRevocationList` is the node's assertion, with flag bit 0: the product's revocation list for
SSH is built by the node and is not signed, so the signer never sees one.

**An account locked out for a time by failed sign-ins is not a `Disabled` fact.** With a
lockout time in the password policy, too many failed sign-ins set the time the lockout ends
(`LockoutEndUtc`) and nothing else. That lock is the product's own, it ends by itself, and
nobody decided it. A `Disabled` fact says that something was disabled and stays so, which a
replay would have to make true again; a lockout that has since ended is not that.

The fact follows the account's `IsLocked` flag, and the journal cannot tell who set it. An
administrator's lock sets it. So does a failed-sign-in lockout **when the policy has no lockout
time** (`LockoutMinutes` 0): that lock does not end by itself, an administrator has to lift it,
and it is recorded as `Disabled` like any other lock.

## 11. Restore and backup

- **A restore never writes or removes the journal directory**, and reads nothing in it.
  `--restore --role signer` writes to the journal directory: nothing. What it does write for
  the journal is one row, below, in the database it restored. (On a split install it also
  records itself in the signer's keystore-events journal, `audit-journal/`, which is another
  directory and another thing.)
- A restore queues a `RestoreMarker` in the database it has restored: the archive's file name
  and, from its manifest, the instance identifier, the creation time and the journal head. The
  node hands it to the signer at its next start. A database from before the queue has no table
  for it; the restore says so and goes on.
- **A backup's manifest carries the journal head** (`JournalHead`: `Seq` and `Hash`), read
  before the database is dumped, so records written during the dump may already be in the dump
  and never the other way about. From the signer when it answers; from the files when the
  backup runs on the host that has them.
- **Journal segments are not in the archive.**

## 12. What it protects against

| Install | The journal | Protects against |
|---|---|---|
| Single process | `<base>/signer/journal/` | A database restore and a database loss; a roll-back of the keystores and the database when the home is on a volume of its own. **Not a compromise of the process:** the same process holds the keys and the files. Not a snapshot of the whole machine, which takes the journal back with the database |
| Split, two units | `/opt/modularca/signer/journal/`, in the signer's own directory, which the node's account cannot read or write | A restore, a loss, and a node that was taken over, which has no access to the path |
| Pod | a volume of its own mounted on `/opt/modularca/signer/journal`; the node never mounts it | As split, provided the volume is not put back with the others |

What it proves: nothing against someone who holds the signer; everything against someone who
holds only copies.

## 13. Seen coming

`/health/ready` reports the journal under `checks.journal`. One status, the first of these that
holds:

| `status` | Means | Ready |
|---|---|---|
| `none` | the signer keeps no journal | yes |
| `unavailable` | the journal cannot take a record: the signer issues no certificate and signs no CRL | **no** |
| `not_verified` | the journal on disk at the signer's start did not verify, as `--journal-verify` would say of it; the signer goes on recording and checking, and revocations are restored only from records a believed checkpoint covers (section 16) | yes |
| `crl_refused` | the signer refused the last full CRL of at least one CA for leaving out revoked serials (section 9) | yes |
| `merge_pending` | revocations the journal holds are missing from the database and wait, because the instance is in DR mode (section 16) | yes |
| `merge_running` | the node is making lost revocations again (section 16) | yes |
| `awaiting_restore_marker` | the journal waits for a restore to explain a changed system key (section 7); the signer signs meanwhile | yes |
| `critical_space` | free space on the journal's volume is under `Signer.Journal.CriticalSpaceMiB` (128 by default) | yes |
| `low_space` | free space is under `Signer.Journal.LowSpaceMiB` (1024 by default) | yes |
| `stale_checkpoint` | records have waited more than 60 seconds for a checkpoint | yes |
| `ok` | none of the above | yes |

- **Readiness.** Only `unavailable` degrades the node: `/health/ready` then answers 503 and
  the hub's `health.read` says `degraded`. Every other status leaves the node healthy, so an
  upgrade or a roll-back is not reported failed for a warning. The journal's check is never
  unhealthy, so `/health/live`, which `--check-ready` asks, does not answer 503 for the
  journal at all: revocation checking goes on without it, and a node taken out of service for
  it would stop answering OCSP too.
- **The two space levels are the signer's settings**, `Signer.Journal.LowSpaceMiB` and
  `Signer.Journal.CriticalSpaceMiB`, in MiB of free space on the journal's volume; 0 turns a
  warning off. They change what is reported and nothing else: **at `critical_space` the
  signer goes on issuing until a write to the journal actually fails**, and from then it is
  `unavailable`.
- **Members**, the same in every status: `status`, `message`, `available`, `seq`, `hash`,
  `sizeBytes`, `freeBytes`, `lowSpaceBytes`, `criticalSpaceBytes`, `lastCheckpointAtUtc`,
  `lastCheckpointAgeSeconds`, `uncheckpointedRecords`, `queuedFacts`,
  `awaitingRestoreMarkerUntilUtc`, `awaitingRestoreMarkerSecondsLeft`, `setAsideJournals`,
  `setAsideBytes` (the journals set aside in the home and what their files take),
  `refusedCrls`, a list of `caId`, `caName`, `caKey`, `missingSerials`, `refusedAtUtc`,
  `journaledCrlNumber`, `publishedCrlExpiresAtUtc`, `serialsAt`, `consolePath`; `verified`
  (null while the signer is still verifying), `verificationFault`, and how far that
  verification has got, `verifiedBytes` of `verifyTotalBytes` (both null before it begins,
  equal when it has read to the end); and `merge`, a list with one entry for
  each CA the merge has looked at in this process: `caId`, `caName`, `state` (`running`,
  `pending`, `done`, `not_trusted`, `failed`), `merged`, `remaining`, `journalEntries`,
  `atUtc`, `message`.
- A signer that has started over an existing journal and recorded nothing yet is `available`:
  it has not tried to write. A directory that cannot be written is found at the first record,
  which is refused.
- The console's dashboard shows every status but `ok` and `none` under "Needs attention"; for
  `crl_refused` with each CA, its missing serials and when its published CRL runs out.
- The hub reads it in `health.read` and in `inventory.read` (`hub-local-connection.md`).

## 14. Where the build departs from the layout

- **The default home is `signer/journal`, with the segments in `current/` inside it** (decided
  by the owner on 2026-11-13). The layout says "`journal/` beside the keystores" and has the
  segments directly in the directory. The home is under the signer's own directory so that it
  is the signer's alone on a split install; the segments are one level down so that a journal
  can be set aside by a rename inside the home, and the home can be a mount point.

- **A file that holds no whole record is created over.** The layout says a segment that did not
  end with a `Seal` is renamed as it is. A file whose first record never reached the disk has no
  sequence of its own: the next segment has the same first sequence, and so the same two names.
  The start-up creates the new segment over it.
- **`systemPublicKey` (key 25) is added** beside the key block in `Genesis`, `SegmentStart` and
  `CheckpointKeyChanged`. The block names the system key by hash only, so its signature could
  not be checked from the files alone. The block itself has exactly the four members; the
  head's `checkpointKey` shows the key beside them as `systemPublicKey`.
- **A segment begins at a start's first record, not at the start.** The layout has a segment
  for every start. A signer restarted in a loop would then make a file, and use four sequence
  numbers, for each start. The start-up rule is unchanged; it is applied when there is
  something to record. The alternative, going on in an open segment that holds only opening
  records, would append to a file a signer left without warning, which the rule forbids.
- **Another instance's journal is set aside, not refused** (section 1).
- **Every `SegmentStart` after the first states the `Genesis` hash** (key 26), and the head
  prints it. The layout has no such member; unknown keys are ignored by readers, so the format
  number is unchanged.
- **Two faults of the first build's own making are gone.** The signer opens its journal by
  checking the newest segment alone. After it had recorded a change of system key that nothing
  explained, or one explained by a changed incarnation at the start of a segment, that check
  took the record for a fault and the signer could not open its own journal again. The check
  now reads past the first (the verify command still reports it), and does not hold the second
  to records it has not read.
- **The node makes lost revocations again from the journal** (section 16). The layout has no
  replay in the first version; this is replay for revocations only.
- **A system key change with nothing to explain it is written without `explains`** after a
  wait. The layout names two explanations and no third case; the signer may meet one.
- **`SshRevocationList` is written as a fact of the node**, flag bit 0, not as something the
  signer signed.
- **The domain prefixes and the encoding of the signed messages** (section 7), the key numbers
  (section 4) and the algorithm names are this build's: the layout left them to be assigned.
- **Full and delta CRLs are separate for the whole-list rule**: "the previous CRL of that
  `caKey`" is read as the previous of the same kind.

## 15. What is not built

- **Replay and adoption of anything but revocations.** The merge (section 16) makes lost
  revocations again. Nothing else is read back into a database: certificates issued in the
  lost time, spent tokens, things disabled. A signer that finds its journal's head past what
  the database knows starts; a node whose database lacks what the journal holds starts.
- `ReadJournal`, the console page, shipping to a standby, pruning and retention, the journal in
  the archive, a second location.
- `OcspSummary`, `OtherSignature` and the reserved types.
- Where the merge cannot cure a refused CRL (section 16, "When it cannot"), an operator enters
  the revocations again from the list of section 9.
- A better OCSP answer than an error for a serial the journal has as revoked and the database
  does not, in the time before the merge reaches it.
- Pruning of set-aside journals.
- A verification at start of only what was written since the last one: the whole journal is
  read at every start (section 17 has the time).
- One audit row for a batch in place of one for each revocation when a merge is large
  (section 17: proposed, for the owner to decide).
- A flush of the directory after a rename.
- On Linux: nothing was run. The suite ran on Windows. The owner-only modes of the directory
  and its files, a rename under a reader, and free space read through `statvfs` are written for
  Linux and not exercised there.

## 16. The merge: lost revocations are made again

Decided by the owner on 2026-11-13. After a database has gone back in time, the instance cures
itself in the safe direction: the node makes again, in its database, every revocation the
signer's journal holds and the database no longer has. Nobody has to act, and no step-up is
asked. It is replay for revocations only.

**The signer's check stays the enforcement.** With `Checks: enforce` the signer never signs a
CRL that drops an unexcused serial (section 9). The merge is what the node does so that its
CRL no longer drops any.

**What the signer answers** (`JournaledRevocations`, a call of the signer's contract; the node
never reads a journal file, and on a hub has no mount of it). For one CA key, a part at a time:

1. the entries of the newest full CRL journaled for the key;
2. changed by a delta CRL journaled after it (an entry it adds, or removes with
   `removeFromCRL`);
3. then every `Revocation` and `Unrevocation` fact the node recorded after that full CRL, in
   the order of their records: a revocation adds or replaces the entry, with the fact's own
   date and reason; a hold adds it as a hold; a released hold removes it; a retirement is not
   a revocation and adds nothing. With no journaled CRL yet, the facts alone.

So a revocation made after the last CRL was signed is restored too, a hold made and released
in the lost time is not, and a hold that still stood is restored as a hold.

**What the signer believes.** One rule, record by record:

> A record is believed when a `Checkpoint` follows it **in its own segment** that is signed by
> a checkpoint key whose key block carries a signature by the system key **the signer holds
> now**. A CRL record must also carry a signature that verifies under the CA's own public key
> over its to-be-signed bytes.

Nothing else about the journal decides it: not whether a change of system key in it was signed
for or explained, and not which system key it was last written under. There is no bar on the
journal as a whole.

- **Why a checkpoint is enough.** A checkpoint signs its own sequence and the hash of the
  record before it, and every record carries the hash of the one before it. So a checkpoint's
  signature fixes the whole chain before it. A genuine checkpoint replayed after other records
  does not verify: the sequence and hash it signed are not theirs.
- **What someone with only the files can do, and why it gets them nothing.** They can append
  records, a change to a system key and a checkpoint key of their own (explained by a restore
  marker they also write), checkpoints signed with their key, and a change back that replays a
  genuine key block. All of it chains, and the verifier reports the change as unvouched. None
  of what they wrote is followed by a checkpoint of a key the held system key signed for,
  because they cannot sign one. So none of it is believed.
- **Why the checkpoint must be in the record's own segment.** The signer's next start writes a
  genuine checkpoint over whatever the files then hold. That checkpoint is in a new segment:
  the signer never appends to a segment it did not begin in the same run. So records someone
  appended, and the tail a signer that stopped without warning left (at most a second of it),
  are never in a segment with a genuine checkpoint after them, and are never believed, also
  not later.
- **After a change of system key nobody signed for** (the keystores were put back to a state
  with another system key): what was recorded before it, under keys the held system key did
  not sign for, is not believed. What the signer records after it is. For a CA the merge has
  a source again once the signer has signed a full CRL for it under the key it holds; until
  then the answer for that CA is a refusal, and a refused CRL is cured by hand (section 9).
- **A whole genuine journal put in the place of another** (an older copy of this journal, or a
  set-aside journal of the same instance) is believed, as far as the held system key signed
  for its checkpoint keys: it is genuine. What it can bring back is a revocation this CA once
  made, or a hold that was since released. That is the journal going back in time, which the
  layout leaves to whoever holds copies of the head to notice (section 12).
- **When each check is made.** At each start the signer first reads the index (the newest
  CRLs and the facts after them, by record lengths; the CRL and OCSP checks wait for that
  alone). Then, in the background, it verifies the whole journal as `--journal-verify` does
  (every record's hash, the chain, every checkpoint's signature, every key block's system
  signature) and marks each record of the index as believed or not by the rule. The merge's
  question waits for that; signing does not. `verified` and the two progress figures in
  `checks.journal` say how far it is. The CA's signature on a journaled CRL is checked when
  the merge first asks for that CA.
- **In memory afterwards**: for each CA key, the newest full and the newest delta CRL (their
  entries, reasons and dates, and where their records are), the highest CRL number, and the
  revocation facts since the newest full CRL, each marked as believed or not. What the signer
  signs or records while it runs is its own and is believed.
- A full CRL that is not believed makes the answer for its CA a refusal; a delta or a fact
  that is not believed is passed over.
- The CRL check and the OCSP check use every record, believed or not: they can only refuse.
- `verified` false (`not_verified`) means `--journal-verify` would report a fault. It does not
  by itself stop the merge: the rule above is applied to every record read before the fault,
  and past a change of system key that nothing explains.

**What the node does with the answer.** For each entry:

| The database has | The node |
|---|---|
| the certificate, not revoked, not expired | revokes it, with the entry's date and reason; a hold as a hold |
| the certificate, expired | nothing: it is on no CRL |
| the certificate, already revoked | keeps it revoked; the earlier of the two dates stands; a hold the journal has as permanent becomes permanent |
| no certificate, and no tombstone for the serial | records the serial as revoked with no certificate (a tombstone, as "revoke a serial number alone" writes them), with the entry's date and reason, listed until the entry's date plus the CA's longest validity |
| no certificate, and the entry is a hold | nothing: a tombstone cannot be released. The signer's check lets a hold leave the CRL |

It never releases, removes or un-revokes anything. Tombstones are permanent.

**When it runs.**

- **In the background after every start of the node**, for every X.509 CA, by the control
  role. The node is ready without waiting for it. It does not depend on the roll-back having
  been detected, or on `Checks`.
- **Before a CA's first CRL of the process**, which waits for that CA's pass or performs it.
- **Once more when the signer still refuses a CRL** for dropped serials (a revocation lost
  while the process ran): the merge runs again, and the CRL is generated again, once.
- In batches of 500, each its own save, so a CA with tens of thousands of entries holds no
  long transaction. A pass that is interrupted goes on where the database stands: an entry
  already made again is found revoked and passed over. Nothing is kept between starts; the
  merge is worked out again from the journal and the database.
- It cannot loop. A merged revocation is a `Revocation` fact like any other and goes to the
  journal, where it adds an entry the database already has; the CRL is generated again once.

**The modes.** A revocation is a restriction, so the merge runs in full, restricted and
maintenance mode. **In DR mode it is deferred, not skipped**: the instance has promised to
change nothing, and signs no CRL. The pass counts what is missing, leaves the CA `pending`,
and `checks.journal` says `merge_pending` with the count. The background pass comes back every
15 seconds and makes them once the mode has been changed; a start in another mode makes them
too.

**It is loud.**

- One audit row for each revocation made, `RevocationMergedFromJournal`, actor
  `journal-merge`: the CA, the serial, the date and reason, what was made, and the source: a
  CRL's number and its journal sequence, or the sequence of the fact.
- One `JournalRevocationMergeCompleted` row for each CA and pass that made any.
- One continuity event, kind `RevocationsMergedFromJournal`, which stands as a notice in the
  console and in `checks.continuity` until an administrator acknowledges it, as the continuity
  notice does: "N revocation(s) were restored from the signer's journal for CA X after the
  database went back in time."
- `checks.journal` shows the merge while it runs (`merge_running`, and `merge` with what is
  made and what remains for each CA). None of it makes the node not ready.

**The time before the merge reaches a serial.** From the start of the signer, an OCSP "good"
for a serial that the newest journaled CRL lists as revoked, or that the node's last
revocation fact says is revoked, is refused by the signer (section 9). The client gets the
responder's error for that request, not "good". The background pass begins when the node
starts and takes seconds for a CA with few entries; before this version the window lasted
until the CA's next scheduled CRL and a person's action.

**When it cannot.** The merge makes nothing and the state is the refused CRL of section 9,
with its list, when: the signer does not answer from its journal for the CA (its entry in
`merge` is `not_trusted`, with the reason); the signer cannot be asked (`failed`,
tried again every 15 seconds); or a write fails. (A hold on a certificate the database does
not hold is passed over, and refuses no CRL: the check lets a hold leave.) With the merge
working that state is rare.

**Why no step-up.** The merge only adds revocations, and only ones this CA's own signer signed
onto a CRL, or the node itself recorded with the signer at the time.

- A fact was asserted by the node when it happened and recorded by the signer in a chain the
  node cannot rewrite. Restoring it gives the node back only what it once said itself.
- Someone who can write the journal's volume and holds no key cannot add to the answer: what
  they append has no checkpoint after it.
- Someone who holds the signer could make the journal say anything, and could force
  revocations through the merge. That fails safe (a certificate wrongly revoked, never one
  wrongly good), and is no more than they can do with the signer they hold: sign a CRL that
  revokes everything.

## 17. Measuring

The figures below were taken on 2026-11-13 on a developer's Windows machine (Debug build, local
disk, virus scanner on, and another full test run using the machine at the same time), against
the local test PostgreSQL. They show the shape of each cost and its order of size. They are not
a benchmark; measure again on the hardware that matters with the commands given here.

The tools are in the test project (`tests/ModularCA.Tests/Journal/JournalMeasurementTools.cs`).
They are not part of the product: `scripts/build-linux-dist.sh` publishes `ModularCA.API`,
`ModularCA.KeystoreCli` and `ModularCA.Migrate` only, so nothing of them is in a tarball. Each
is a test that does nothing unless its environment variable is set.

### A journal to measure with

```
MODULARCA_JOURNAL_GENERATE_DIR=/path/to/an/empty/directory \
MODULARCA_JOURNAL_GENERATE_MIB=1024 \
MODULARCA_JOURNAL_GENERATE_RECORD_BYTES=2048 \
MODULARCA_JOURNAL_GENERATE_SEGMENT_MIB=64 \
MODULARCA_JOURNAL_GENERATE_CRL_ENTRIES=0 \
dotnet test tests/ModularCA.Tests -c Debug \
  --filter "FullyQualifiedName~Generate_a_journal_for_timing" --logger "console;verbosity=detailed"
```

(In PowerShell set each with `$env:NAME = "value"` first.)

| Variable | Meaning | Default |
|---|---|---|
| `MODULARCA_JOURNAL_GENERATE_DIR` | The journal home to write. Its `current/` must not hold files. Without it the tool does nothing. | none |
| `MODULARCA_JOURNAL_GENERATE_MIB` | Total size, MiB. | 1024 |
| `MODULARCA_JOURNAL_GENERATE_RECORD_BYTES` | Sizes of the certificate records in bytes, cycled: `2048`, or a mix such as `2048,2048,600`. | 2048 |
| `MODULARCA_JOURNAL_GENERATE_SEGMENT_MIB` | Size at which a segment is sealed, MiB. | 64 |
| `MODULARCA_JOURNAL_GENERATE_CRL_ENTRIES` | When above 0, the journal ends with a full CRL of a made-up CA that lists this many revoked serials. | 0 |

It writes with the product's own writer, so the result is a journal `--journal-verify` passes:
certificate records, a checkpoint as the signer writes them, sealed segments, and a `Seal` at
the end.

> **The generated journal is a made-up instance with made-up keys, for timing only.** Its
> instance identifier is the SHA-256 of the text "ModularCA journal generated for timing
> only", its system key and checkpoint key are random and thrown away, and its records
> describe certificates that were never issued. **Never mount it as the journal of a real
> instance, and never put it where a real signer will open it.** A real signer would set it
> aside as another instance's journal; do not rely on that.

Measured: 1 GiB of 2,048-byte records with a CRL of 100,000 entries at the end is 503,449
records in 16 segments, written in 33 s. On it:

```
ModularCA.API --role signer --journal-verify --journal-directory /path/to/that/directory
ModularCA.API --role signer --journal-head   --journal-directory /path/to/that/directory
```

took 6.3 s (`"ok":true`, 504,009 records with the segment and checkpoint records, 526
checkpoints; about 160 MiB/s) and 0.9 s.

### The verification at the signer's start

```
MODULARCA_MEASURE_VERIFY_MIB=1024 dotnet test tests/ModularCA.Tests -c Debug \
  --filter "FullyQualifiedName~Measure_the_start_up_verification" --logger "console;verbosity=detailed"
```

It generates a journal of that size under the test's own keys, starts a signer over it, and
says when each thing is ready. For 1 GiB (503,448 certificate records of 2,048 bytes, 16
segments):

| | |
|---|---|
| The verifier alone, whole journal | 5.4 s, 189 MiB/s (twice, the same) |
| The journal is open and takes a record | 0.3 s after the start |
| The index is read: the CRL and OCSP checks answer | 1.6 s |
| The verification has ended: the merge is answered | 7.2 s (142 MiB/s over the whole start) |
| Certificates signed and recorded while it verified | 1,216, at 220 a second |

So the signer signs from the first third of a second, checks CRLs and OCSP answers from the
moment the index is read, and only the merge's question waits for the verification. The whole
journal is read at every start; the time grows with its size in a straight line, about 7 s a
GiB here. Nothing is kept between starts to shorten it (section 15).

### The merge

```
MODULARCA_TEST_PG="$(cat <file with the test server's connection string>)" \
MODULARCA_MEASURE_MERGE="0,1000,10000,100000" dotnet test tests/ModularCA.Tests -c Debug \
  --filter "FullyQualifiedName~Measure_the_merge" --logger "console;verbosity=detailed"
```

For each size N it makes a database with one CA and N revocations (half certificates the
database holds, half serials with no certificate), signs a CRL so that the journal holds them,
runs a pass that finds nothing missing, then takes the revocations out of the database and
runs the pass that makes them again. The database has statistics (`ANALYZE`) and the
connections are pooled, as a node's are. The audit trail in this measurement is kept in
memory; the real one is measured apart, below.

**How the comparison is made.** In sets, never a query for each serial. The node asks the
signer for the list 2,000 entries at a time. For each 500 entries it sends two queries: one
for the certificates of this CA whose serial is among them, one for the tombstones. Each
carries the 500 serials as one array parameter (each as stored, and with one and two leading
zeros), is answered from the serial indexes, and reads only the six columns the comparison
needs. A row is loaded whole only when it has to be changed. Serials are compared as the
product stores them, in upper case; a certificate row whose serial some other tool wrote in
lower case is not found, and its serial is then recorded as a serial with no certificate, which
revokes it all the same.

**(a) An ordinary start: nothing is missing.**

| Journaled list | Time | Database | Signer |
|---|---|---|---|
| 0 | 0.09 s | 4 commands, 4 ms | 1 call |
| 1,000 | 0.08 s | 8 commands, 26 ms | 1 call |
| 10,000 | 0.6 s | 44 commands, 0.44 s | 5 calls, 0.15 s |
| 100,000 | 7.3 s | 404 commands, 6.0 s | 50 calls, 1.3 s |

Nothing is written. It is 4 commands for the CA and 2 for every 500 entries, in the
background, once for each CA at each start of the node.

**(b) The cure.**

| Missing | Time | A second | Transactions | Audit rows | Facts queued |
|---|---|---|---|---|---|
| 1,000 | 0.9 s | 1,080 | 2 + 1 | 1,000 + 1 | 1,000 |
| 10,000 | 5.1 s | 1,960 | 20 + 1 | 10,000 + 1 | 10,000 |
| 100,000 | 44.8 s | 2,230 | 200 + 1 | 100,000 + 1 | 100,000 |

One transaction for every 500 revocations and one for the summary and the notice. Afterwards
the CRL lists every serial again and is signed (0.4 s for 10,000, 4.5 s for 100,000).

**The audit trail is what the cure really costs.** The table above was taken with the audit
rows kept in memory. In the product each row is appended to the audit hash chain: a lock on
the chain, a read of its head, an insert and a commit, one row at a time. Measured apart
(`MODULARCA_MEASURE_AUDIT_ROWS=10000`, test `Measure_the_audit_rows_of_a_merge`): 186 rows a
second and 981 bytes a row with its indexes, on a test server that does not wait for the disk.
So in an installed instance:

| Missing | Audit rows | Time for them alone | Added to the audit database |
|---|---|---|---|
| 1,000 | 1,001 | about 5 s | about 1 MiB |
| 10,000 | 10,001 | about 1 minute | about 9 MiB |
| 100,000 | 100,001 | about 9 minutes | about 94 MiB |

and more where a commit waits for the disk. The chain stays one chain and stays verifiable; it
grows by that many links, which a later verification of the chain has to walk, and every other
audit row written in that time takes its turn at the same lock (each turn is one row long).
The revocations of a batch are in the database before their audit rows are written, so the
CRL does not wait for the audit trail more than one batch at a time.

*Proposed, not built: nothing about the audit rows was changed.* Above some count for one CA
and pass (1,000 is suggested), write one `RevocationMergedFromJournal` row for each batch of
500 that carries the batch's serials with their dates, reasons and sources, in place of one
row for each revocation. 100,000 revocations would then be 200 rows and under a minute, with
the same facts in the trail. It changes what a query for one serial's audit history finds
(the serial is inside a row's details, not the row's target), and the details column must
take a batch (about 60 KB). That is a change of audit semantics and is the owner's to decide.

**The queue of facts for the journal.** Each revocation made queues one `Revocation` fact, in
the transaction that makes it. The drain takes 500 at a time and offers them to the signer
together (facts about different serials at once; two facts about the same serial in their
order), so the signer writes many records for each flush of its journal:

| Facts | Time | A second | Flushes of the journal |
|---|---|---|---|
| 1,000 | 0.24 s | 4,100 | 7 |
| 10,000 | 1.6 s | 6,200 | 40 |
| 100,000 | 15.6 s | 6,400 | 440 |

Before this was measured the drain offered 50 facts in a pass, one after another, each with a
flush of its own.

**(c) What still works meanwhile.** A loop that has the signer sign and record a certificate
and sign an OCSP answer took 22 to 72 ms a turn on average before the merge and 22 to 45 ms
while it ran (single slow turns, up to 1.6 s, were there before the merge as well: the
machine was busy). The merge is one background task with one database connection; it does not hold the
signer, and it holds no lock longer than one batch's transaction.

- The node is ready, issues, and answers requests throughout.
- The signer signs throughout. Its answer to the merge is worked out once for a CA (about a
  second for 100,000 entries) and kept while nothing it was made from changes.
- OCSP: for a serial the merge has not reached yet the signer refuses a "good" (section 16).
- The CA's first CRL of the process waits for that CA's pass: for 100,000 missing, the time in
  (b) plus the audit rows.

**What remains.** The audit rows of a large cure (above), and the 7 s that an ordinary start
spends comparing a list of 100,000 for one CA, in the background.

### Many revoked serials on a test instance

To see the merge at size on a running test instance, the serials have to get into the
database first. The product has no action that makes up revoked serials in number, by decision
(the console's page of section 9 records only serials the signer names as missing, with
step-up). This statement writes them straight into the application database:

> **For a throwaway test instance only.** It bypasses the audit trail, step-up and the queue
> of facts for the journal. The revocations reach the journal only through the CA's next CRL.
> Never run it against an instance whose revocations mean anything.

```sql
INSERT INTO "RevokedSerialTombstones"
    ("Id", "CaCertificateId", "CertificateAuthorityId", "IssuerDN", "SerialNumber",
     "RevocationDate", "RevocationReason", "ListedUntil", "Note", "CreatedByUsername", "CreatedAt")
SELECT gen_random_uuid(), ca."CertificateId", ca."Id", c."SubjectDN",
       ltrim(upper(md5(random()::text || g::text)), '0'),
       now() - interval '1 day', 'Superseded', now() + interval '1 year',
       'Inserted for timing on a test instance', 'timing-test', now()
FROM "CertificateAuthorities" ca
JOIN "Certificates" c ON c."CertificateId" = ca."CertificateId"
CROSS JOIN generate_series(1, 100000) AS g
WHERE ca."Id" = '00000000-0000-0000-0000-000000000000'
ON CONFLICT DO NOTHING;
```

Put the CA's identifier (the one in the address of its page in the console) in the last line
but one and the count in `generate_series`. Each serial is 32 random hex digits (16 octets),
upper case and without leading zeros as the product stores them, revoked as `Superseded` one
day ago and listed for a year.

1. Run the statement in the test instance's application database.
2. Have a CRL generated for the CA, so that the journal holds the serials: in the console,
   Schedules, "run now" on the CA's CRL schedule; or
   `POST /api/v1/admin/scheduler/schedules/crl/{taskId}/run` (it asks for step-up).
3. Take them out again, as a database that went back would have lost them:
   `DELETE FROM "RevokedSerialTombstones" WHERE "CreatedByUsername" = 'timing-test';`
4. Restart the node. Its merge makes them again; `checks.journal` shows it running, and the
   audit trail and the notice say what it made.

The sequence is a test against PostgreSQL
(`Serials_inserted_by_the_documented_statement_reach_the_journal_with_a_crl_and_come_back_by_the_merge`):
the statement inserts N, the CRL lists N, the rows are deleted, the merge brings back the same
N serials.
