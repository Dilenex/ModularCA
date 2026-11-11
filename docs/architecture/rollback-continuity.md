# Rollback continuity

Status: draft, for owner review (2026-11-11). Nothing here is built.

## Why

A CA that is taken back in time forgets what it did in the time it lost. It can be taken back in
three ways, and only one of them goes through code that knows it is happening:

1. **The product's own restore** (`--restore`). It raises every CRL number past a time-derived
   floor (`CrlNumberFloor`), keeps or replaces the audit trail, and records itself.
2. **A snapshot rollback of the machine.** A Proxmox, VMware or Hyper-V snapshot is reverted, or
   a backup of the whole VM is restored. The product is not told. This is what a home lab does
   before an upgrade, and what the owner did on the test host on 2026-11-10.
3. **A volume restore by an orchestrator.** The hub's upgrade goes back by putting the archived
   volumes back (`References/backlog/hub-upgrade-of-an-instance.md`). A failover to a standby
   loses the tail of asynchronous replication in the same way.

What is lost is the same in all three:

- **A certificate issued in the lost time is real and unknown.** It carries a valid signature.
  For an issuer the instance is authoritative for, OCSP answers "revoked, certificateHold, 1970"
  for an unknown serial (`OcspResponderService.cs`, the extended-revoke branch). The CRL cannot
  list a serial the database does not hold, so a relying party that checks only the CRL accepts
  the certificate until it expires. It cannot be revoked: revoke-by-serial answers 404.
- **A revocation made in the lost time is undone.** The certificate is good again, in OCSP and in
  the next CRL.
- **CRL numbers go backwards** on paths 2 and 3, which bypass the floor. A relying party that
  cached a later CRL may refuse the earlier-numbered one, and a delta CRL may no longer match its
  base.
- **A key created in the lost time is gone** if the keystore went back too.
- **Nothing tells anyone.** A database that was rolled back looks exactly like one that was
  switched off for a while.

## What already exists on paper

`signer-hardening.md`, Item 2, designs **a signer-local issuance journal**: append-only,
hash-chained, on the signer's own disk, holding the full TBS of every certificate and every
changed CRL. Its "What it feeds" section already describes replaying it after a restore:
certificates issued since the backup are adopted, revocations are reapplied, and the next CRL
number comes from the journal. It also gives the signer two checks of its own: it refuses a CRL
that drops an unexpired serial, and it refuses "good" for a serial on its newest CRL.

This note does not redesign any of that. It adds what that design does not cover:

- **Detection.** The journal's replay is triggered by "the first start after a restore". Paths 2
  and 3 are not restores as far as the product knows, so nothing triggers it.
- **The single machine.** On a single-process install the journal sits beside the database
  (`signer-hardening.md`, "Where it lives"). A snapshot of the machine takes both back together,
  so the journal remembers nothing the database forgot.
- **Certificates nobody journaled.** Until the journal is built, and wherever it went back with
  the database, a certificate from the lost time is known only from its own bytes.

## Decisions proposed

1. **Every start compares an incarnation ID with the one the database last saw.** A difference
   means this database is running on a machine, or a timeline, other than the one that last wrote
   it: a rollback, a restore, a clone or a move.
2. **The incarnation ID has pluggable sources:** the hypervisor's VM generation ID where there is
   one, a value the orchestrator injects where there is not, and none otherwise.
3. **On a change, the instance repairs what it can alone and says what it cannot.** It raises the
   CRL numbers (the floor the product's restore already applies), replays the signer's journal
   where one exists, records the event and shows a standing notice until an administrator
   acknowledges it. It does not refuse to start.
4. **New serial numbers carry a timestamp and an incarnation tag** in front of their random bits.
   A certificate that turns up unknown then says when it was issued and by which timeline.
5. **A serial can be revoked without a certificate row** (a tombstone), so that a certificate
   known only from outside can be put on the CRL.
6. **The hub is the off-box witness for its instances,** and the rule for an instance that has
   issued since its archive is restore and reconcile, not restore.

## 1. The incarnation ID

**What it is.** An opaque value that changes whenever the machine's state may have been taken
back or copied. The instance stores the last value it saw, in the database it would be rolled
back with. At each start it compares.

| Database holds | Machine reports | Meaning |
|---|---|---|
| nothing | anything | first start with this feature; store it |
| A | A | same timeline |
| A | B | rolled back, restored, cloned or moved |
| A | nothing | the source went away (moved to a host without one); warn once, store "none" |

**Sources, in order of preference.**

- **Injected by an orchestrator.** An environment variable (working name
  `MODULARCA__INSTANCE__INCARNATION`). The hub sets a new value whenever it restores an
  instance's volumes or promotes a standby. It always knows when it did. Containers have no
  hypervisor ID, so this is the only source in a pod.
- **The VM generation ID.** Hypervisors give a VM a 128-bit ID and change it when the VM is
  reverted to a snapshot or restored. On QEMU, which Proxmox uses, the guest can read it from
  `/sys/firmware/qemu_fw_cfg/by_name/etc/vmgenid_guid/raw`. Proxmox regenerates it on a snapshot
  rollback.
- **None.** Bare metal, and virtual machines without the device. Detection is then limited to
  what sections 3 and 6 add.

**Not yet verified** (see "Open questions"): that the file exists on the owner's hosts and who
may read it; that a Proxmox clone and a restore from Proxmox Backup Server both change the ID;
how a guest reads the ID on Hyper-V and VMware, where that file does not exist.

**Reading it.** The file is expected to be readable by root only. The service account should not
gain a way to read firmware tables. A root-owned oneshot unit ordered before
`modularca.service` copies the 16 bytes to a file under `/run/modularca/` that the service
account can read. The installer adds the unit; without it the source is "none".

**It is not a secret and not a random source.** It is compared, and hashed into a tag (section
4). It never seeds or replaces the random generator.

## 2. What a change triggers

At a start where the incarnation differs, before the scheduler runs and before the first CRL is
generated:

1. **Raise the CRL numbers** with `CrlNumberFloor`, exactly as the product's restore does. It is
   idempotent and never lowers a counter, so doing it on a move that was not a rollback costs a
   jump in numbering and nothing else.
2. **Replay the signer's journal** where one exists and reaches past the database
   (`signer-hardening.md`, "What it feeds"). On a split install or a pod it will. On a single
   machine it will not, and the report says so.
3. **Record it.** One audit row (`InstanceIncarnationChanged`) with the old and new tag, the
   newest record the database holds, and what steps 1 and 2 did.
4. **Raise a standing notice** in the console and in `/health/ready`, until an administrator
   acknowledges it with step-up: "This instance is running from an earlier or copied state.
   Certificates issued and revocations made after `<time of the newest record>` on the earlier
   timeline are not known here." With the counts from the journal when there is one.
5. **Store the new incarnation.**

**It does not refuse to start.** A CA that will not come back after a rollback turns a
recoverable gap into an outage, and the home lab user has no second administrator to call.

**The clone.** A copy of the machine started beside the original is the case a rollback is not:
both now issue. Each sees a changed incarnation and raises its notice, but neither can see the
other. Tags in the serial (section 4) make their certificates tell them apart afterwards. Stopping
two copies from both serving needs the lease in the HA design and is out of scope here.

## 3. The newest thing the database knows

The notice needs a time: "everything after this is unknown". Certificate ids are already UUID
version 7 (the first 48 bits are the Unix time in milliseconds; seen on the test host as
`01a1c92b-3eb0-75dc-…`), so the newest certificate id is a creation time that needs no extra
column. Request ids are version 4 and carry no time; requests have `SubmittedAt`. The audit
trail's newest row is another. The instance reports the latest of them as the edge of its memory.

This is also the cheap detector where there is no incarnation source at all: **the published
CRL.** Where CRLs are published to another host (the LDAP publisher, an external distribution
point), the instance can read back its own latest one. A CRL number out there that is higher than
the database's counter proves the database went back. This check is worth making at start
wherever a publisher is configured, incarnation source or not.

## 4. Serial numbers that say when and where

**Today** a serial is 128 random bits (`CertificateIssuanceService.cs`, `CaCreationService.cs`,
`BouncyCastleCertificateAuthority.cs`: sixteen bytes from the system's secure generator behind a
zero byte).

**Proposed**, for newly issued certificates:

| Part | Bits | What |
|---|---|---|
| Timestamp | 48 | Unix time in milliseconds at issuance, as in UUID version 7 |
| Incarnation tag | 32 | a keyed hash of the incarnation ID, truncated |
| Random | 80 | from the system's secure generator |

- **It fits.** 160 bits is twenty octets, the most RFC 5280 allows. The top bit of the timestamp
  is zero until the year 6429, so the value is positive without a padding byte.
- **It keeps the randomness.** 80 bits is above the 64 the CA/Browser Forum requires of public
  CAs. The random part comes from the same generator as today. The timestamp and the tag are in
  addition to it, never a substitute.
- **It leaks little.** The issue time is already in `notBefore`. The tag is an HMAC of the
  incarnation ID under a key the instance holds, so nobody outside can link it to a hypervisor's
  ID; it does show that a restore happened, by changing. That is acceptable for a private CA and
  should be said in the documentation.
- **With no incarnation source the tag is zero** and the serial still carries its time.
- **Old serials stay as they are.** Nothing is reissued. Lookups, OCSP and CRLs treat a serial as
  an opaque number, as now. Only code that wants the time or the tag parses it, and only when the
  serial has the new length and a plausible timestamp.

**What it gives.**

- **An unknown certificate dates itself.** A serial whose time is after the edge of memory, with
  the tag of the timeline the database came from, was issued in the lost time. One with a time
  before the edge and no row was never issued here.
- **OCSP can answer precisely.** Today every unknown serial is "revoked, certificateHold, 1970".
  A serial from the lost time could carry its own reason and the time of the rollback, which
  tells a relying party's administrator what happened.
- **A clone's certificates are attributable** to the copy that issued them.
- **It does not need the clock to be right** to separate the lost timeline from the new one: the
  tag differs.

**What it does not give.** A CRL lists serials one by one. There is no way to say "everything
after 10:00 from timeline G1". The serials still have to come from somewhere: the journal, or the
tombstone below.

**One generator.** The three places that make a serial today each fill their own bytes. This
change puts serial generation in one function, with tests for the layout, the positive sign, the
length and the source of the random part.

## 5. Revoking a serial with no certificate behind it

**Today** revocation needs the certificate's row. A serial the database does not hold answers
404.

**Proposed:** an administrator with `cert.revoke` on the CA can record a revoked serial for that
CA with no certificate: issuer, serial, revocation date, reason, who and why. Working name: a
tombstone.

- **The CRL lists it** like any other entry. OCSP already answers "revoked" for it; with the
  tombstone it answers with the recorded date and reason.
- **It needs an expiry to be pruned.** A normal entry leaves the CRL when the certificate
  expires. A tombstone has no `notAfter`, unless the administrator supplies the certificate
  itself. Without it the entry stays until the longest validity the CA's profiles allowed, counted
  from the serial's own timestamp when it has one, or from the tombstone's date when it does not.
- **Supplying the certificate is better.** If the subscriber, an ACME client or a log can produce
  the certificate, the instance verifies its signature under the CA's key and adopts it as a
  normal row ("adopted from outside, requester unknown"), then revokes it or not as the
  administrator chooses. This is the same adoption the journal replay does, with a different
  source.
- **It is audited and step-up gated,** like any revocation. A tombstone for a serial that does
  have a row is refused: revoke the certificate.

This is small, it does not depend on anything else in this note, and it is the difference
between "we cannot revoke it" and "tell us the serial".

## 6. Two kinds of installation

**A home lab on one machine.**

- Snapshot before an upgrade, roll back when it goes wrong: this is normal and will stay normal.
- Everything is on one disk. The journal, when built, goes back with the database.
- The stakes are low and mostly self-healing: few certificates, internal relying parties, short
  lifetimes where ACME is used. The quiet risks are the undone revocation and the CRL number.
- **What this note gives them:** detection through the VM generation ID, the CRL numbers raised
  without being asked, a notice that says what time was lost, dated serials, and the tombstone.
- **What it does not:** the lost certificates themselves. For that the journal needs a second
  location (a path on other storage, written as well as the local one). That is an option to add
  to the journal's design, off by default.
- **The documentation should say plainly:** take the snapshot with the service stopped or accept
  that anything issued or revoked after it is forgotten by a rollback; prefer the product's
  backup and restore for anything but an upgrade that failed at once.

**An MSP's instances under the hub.**

- A rollback is something the hub does, on purpose, as its way back from a failed upgrade, and a
  failover loses a replication tail.
- A valid certificate the CA cannot account for is an audit finding, across customers.
- The signer has its own volume in the pod, so the journal survives a restore of the database
  volume, provided the hub does not restore the signer's volume to the same archive.
- **What this note asks of the hub:**
  - set the incarnation variable to a new value on every restore and every promotion;
  - keep, per instance, the high-water marks it can read without credentials or with a
    read-only identity: the newest CRL number of each CA, and the audit chain head;
  - before a restore, compare them with what the archive holds. If the instance issued or
    revoked since the archive, the restore is a restore and reconcile: the journal is not
    restored, the instance replays it at start, and the hub waits for the reconciliation report
    before it calls the instance healthy.
- **What the core owes the hub for that:** the reconciliation report as something a machine can
  read, and the notice in `/health/ready`.

## Order of work

| Step | What | Depends on | Helps |
|---|---|---|---|
| 1 | Tombstone revocation, and adoption of a supplied certificate | nothing | both |
| 2 | Incarnation ID: the injected source, the comparison at start, the CRL floor, the audit row and the notice | nothing | hub at once; home lab once step 3 lands |
| 3 | The VM generation ID source and its boot unit | step 2, and the open questions below | home lab |
| 4 | The published-CRL check at start | nothing | both, where CRLs are published elsewhere |
| 5 | One serial generator; timestamp and tag in new serials; OCSP's precise answer for the lost time | step 2 for the tag | both |
| 6 | The journal and its replay | `signer-hardening.md` Item 2 | hub and split installs; one machine only with a second location |

Steps 1, 2 and 4 are each small. Step 5 changes the format of every new serial and wants its own
review. Step 6 is the large one and is already designed elsewhere.

## Open questions

1. **Is the generation ID file there, and who can read it?** To check on a Proxmox guest:
   `ls -l /sys/firmware/qemu_fw_cfg/by_name/etc/vmgenid_guid/` (the `qemu_fw_cfg` module may need
   loading), then read `raw` as root before and after a snapshot rollback, a clone, and a restore
   from a backup.
2. **Does a clone get a new ID on Proxmox?** The patch that added the device regenerates it on
   rollback; a clone was not confirmed.
3. **Hyper-V and VMware guests.** Both have the device; how a Linux guest reads the value there
   was not found. Without an answer those hosts are "none".
4. **Does a live migration change the ID?** It should not. If it does on some hypervisor, every
   migration would raise the notice.
5. **Should a moved installation count?** Restoring the product's own backup onto a new machine
   changes the incarnation and goes through `--restore`, which already does the repairs. The
   restore should store the new incarnation itself, so the next start does not report a second
   event.
6. **The tag's key.** An HMAC key held by the instance. If it is wrapped by the signer like the
   other secrets it survives a database rollback only where the signer's storage does. Whether
   the tag must be stable across a restore of everything (so old serials can still be attributed)
   decides where the key lives.
7. **Public trust.** If an instance is ever used under a public root, a serial that shows restore
   events may not be acceptable. The tag would need a switch.
8. **How long a tombstone with no certificate stays on the CRL,** and whether the administrator
   may set it.

## What was rejected

- **Refusing to start after a rollback.** It protects nothing that the notice does not, and it
  takes the CA away from the person least able to get help.
- **Revoking by time window.** X.509 cannot express it. The only blunt instrument is replacing
  the issuing CA, which is an operator's decision, not a default.
- **Using the generation ID as the serial's randomness.** It is not secret and changes rarely.
- **Storing a "last incarnation" in a file beside the database.** A snapshot takes the file back
  with it. The comparison only works because one side of it comes from outside the rolled-back
  state.
- **Detecting a rollback from the clock.** A gap between the newest record and now is also what
  a machine that was switched off looks like.
