# CA certificate renewal

Status: built in 0.4.5 (same key). Re-key is not built; the last section says how it would
extend this.

## Why

A CA certificate has an end. Before this, the only way past it was a new CA: a new key, a new
name in every trust store, and every client enrolled again. NIST SP 800-57 Part 1 separates the
two things that end: the period a key may be used, and the validity of a certificate that
binds it. Renewal addresses the second and leaves the first alone. A CA whose key is still
within the period its organization allows gets a new certificate over that key: the same key,
the same subject, a new serial and a new validity.

What is **not** built, and is refused or absent rather than half-present:

- renewal with a new key (re-key), and the cross-signed "link" certificates that go with it;
- a changed subject;
- renewal of an intermediate by a CA outside this instance (the product has no flow that
  sends a request out and takes a certificate back, at creation either);
- renewal on a schedule (`CaCertificateRenewalService.RenewAsync` takes nothing of a request,
  so a scheduled trigger can call it; none is registered).

## The model

A CA has **one current certificate** and, over time, several.

- `CertificateAuthorities.CertificateId` names the current one. It is the issuer certificate
  of everything the CA signs from then on, the certificate its label serves at `/ca/{label}`,
  and the one the signer resolves the CA's key through.
- `CaCertificates` (migration `20261113110511_CaCertificates`, additive, starts empty) records
  every certificate a CA has had: the CA, the certificate row, the
  key it is over (`KeyId`, SHA-256 of the public key, the journal's `caKey`), how it became the
  CA's (`Initial`, `Renewal`), when, by whom, and under which ceremony. The first row is
  written when the CA is created; a CA made before the table existed, or by bootstrap, gets
  its `Initial` row after the next start of the node (`CaCertificateHistoryService`, a
  background pass over `CaCertificateHistory.EnsureInitialRowsAsync`, which only adds rows).
  The migration itself cannot write it: the key id is a hash of the certificate's public key,
  which SQL cannot compute. **The pass writes nothing in DR mode**, where the instance changes
  nothing by itself: it comes back every 15 seconds, as the journal's revocation merge does,
  and writes once the mode is left. It does write in restricted and maintenance mode: those
  freeze what a person configures, and this is the instance recording a fact about itself
  (`ModeOperation.Fact`, the class CRLs are signed under). While a CA has no row, every reader
  takes its one certificate from the CA's own row, as before the table existed.
- The earlier certificate is **not revoked** by renewal. It stays valid until it expires and
  stays served at its serial. Every certificate issued under it ends before it does, because
  issuance has always shortened a certificate to end before its issuer.
- `IssuerChainResolver` is the one place that answers "whose certificate is this". It asks
  `CaCertificates` first and falls back to the name-and-key matching it had for rows older than
  the table. `SameKeyCaCertificateIdsAsync` and `SameKeyScopeAsync` give every certificate a CA
  has had over one key: the set a leaf's `IssuerCertificateId` is compared with wherever
  "issued by this CA" is asked. `CurrentSameKeyCertificateIdAsync` brings an earlier
  certificate's id to the current one.

### What moves at a renewal

In one transaction, after the signer has signed:

| Row | Before | After |
|---|---|---|
| `CertificateAuthorities.CertificateId` | old certificate | new certificate |
| `SigningProfiles.IssuerId` (every profile that issued from the old certificate) | old | new |
| `CrlConfigurations.CaCertificateId` (full and delta schedules; their `Crls` rows follow by `TaskId`) | old | new |
| `CaServiceUrls.CaCertificateId` | old | new |
| `CaCertificates` | (none, or the old row) | old row with `SupersededAt`; new row |
| old certificate row | | expiry warning dismissed ("CA certificate renewed") |

What does not move: the leaves' `IssuerCertificateId` (each names the certificate that was
current when it was issued), `RevokedSerialTombstones.CaCertificateId`, the CA's delegated
OCSP, timestamp and CMP certificates, subordinate CAs, and the keystore files.

### The key

The signer pairs certificates with keys by public key, so the new certificate finds the key
the old one was committed with; nothing is written to `ca-certs.keystore` or
`ca-trust.keystore`, which keep the certificate each key was committed with. The node's
registry of CA certificates is told of the renewed certificate at once
(`IKeystoreCertificates.RegisterRenewedCaCertificate`) and again at every start, from
`CaCertificates`, so the certificate a CA is known by is the current one. A node with a remote
signer reads its CA certificates from the database and needs neither. After the repoint, a key
reference to the old certificate signs nothing: the signer classifies a CA certificate that no
CA row names as a key of unknown kind.

## The URL question

**CRL distribution points and CA-issuer URLs name the CA by its label**, not by a serial
(`CaServiceUrlService.ResolveForCaAsync`): `{base}/crl/{label}`, `{base}/ca/{label}`,
`{base}/ocsp`. The serial is only the fallback for a CA with no label. So a renewal changes no
URL in any certificate, old or new.

The endpoints also accept a serial (`/ca/{serial}`, `/crl/{serial}`,
`/api/v1/public/crl/{serial}`), and those must keep working:

- `/ca/{old serial}` serves the **old** certificate: it was asked for by its serial.
- `/ca/{label}` and `/ca/{new serial}` serve the **new** certificate.
- `/crl/{old serial}`, `/crl/{new serial}` and `/crl/{label}` all serve **the same CRL**.

One CRL is right, and is the only thing that can be right. A CRL is bound to an issuer name and
a key. Both certificates have the same name and the same key, so a CRL signed by that key
validates under either certificate, and a relying party cannot tell, and has no need to tell,
which certificate "issued" it. The CRL lists what was revoked under either certificate
(`SameKeyCaCertificateIdsAsync`). Its number continues, because the schedule moved rather than
being started again; the signer's journal would refuse a CRL that started over, since it keeps
one CRL stream for each CA key. `CrlService` maps an earlier certificate's id to the current
one on every entry point, so a caller that still holds the old id (revoking a leaf issued
before the renewal, a URL with the old serial) reaches the one CRL.

OCSP is the same: `issuerNameHash` and `issuerKeyHash` are equal for both certificates, so a
request built from either matches the CA, and the serial is looked for under every certificate
the CA has had over the key.

Proved by `PostgresCaCertificateRenewalTests` (the CRL bytes at all three addresses, each
certificate at its serial, the CRL number continuing, the journal's stream) and
`CaCertificateRenewalTests` (a leaf issued before the renewal under the new CA certificate, a
leaf issued after under the old one, OCSP asked with either).

## The signer

Renewal is an operation of its own at the signer: `SigningPurpose.CaCertificateRenewal`. The
ordinary certificate purpose still signs no `cA=TRUE` certificate for a committed key.

The context names the CA whose key signs (the CA itself for a root, the parent for an
intermediate). The signer finds the CA being renewed from the certificate offered: the one CA
of the instance whose current certificate carries the subject public key. It then requires:

| Check | Refusal |
|---|---|
| the subject key is the key of a CA's current certificate, and a key the signer holds | `EvidenceRequired` |
| the subject is that CA's subject, byte for byte | `EvidenceRequired` |
| `cA=TRUE` | `PurposeNotPermitted` |
| a root renews itself; an intermediate is renewed by the parent its row names | `CaMismatch` |
| the signing key signed the certificate being renewed | `EvidenceRequired` |
| the path length is not wider than the current one, and is below the parent's | `PurposeNotPermitted` |
| every extension of the current certificate is present with the same criticality and value, and none is added; for an intermediate the authority key identifier, CRL distribution points and authority information access may differ | `PurposeNotPermitted` |
| the serial is not the current one's | `PurposeNotPermitted` |
| the validity ends after the signer's clock, starts no later than ten minutes after it and, for an intermediate, lies within the parent certificate's | `PurposeNotPermitted` |
| where the CA's scope requires a key ceremony: the context names an approved, unexpired `RenewCaCertificate` ceremony of that scope, targeting that CA, naming the certificate that is current, whose parameters give exactly this end of validity | `CeremonyRequired`, `CeremonyNotApproved` |

The evidence is the key, as it is for creation: a renewal can only ever certify a key the
signer already holds as that CA's key, under that CA's name, with that CA's extensions. A
ceremony names the certificate it replaces, so one approval renews a CA once.

The signature is a `Certificate` record in the journal like any other: `ca` and `caKey` are
the signing CA's, `caCert` is the certificate that was current when it signed (for a root, the
old root certificate), `isCa` is true, and `replaces` names the old serial. Records after the
renewal carry the new `caCert` and the same `caKey` and `ca`. The CRL stream is keyed by
`caKey` and continues. The revocation merge reads the journal by the CA's key and matches rows
by serial within the same-key scope, so it restores revocations of certificates issued under
either certificate.

## Guarding

As creation: `POST /api/v1/admin/authorities/{caId}/renew-certificate` is frozen outside full
mode (`ModeOperation.Frozen`; the service asks the gate again below the filter), needs step-up
bound to the CA (`renew-ca-certificate`), a system administrator for a root or `ca.manage` in
the space for an intermediate, and opens a ceremony where the CA's scope requires one. The
ceremony's quorum is the stricter of the scope's key quorum and the CA's administrators'. The
ceremony records the exact end of validity; the signer holds the certificate to it. Every
attempt, refused or not, is audited (`CaCertificateRenewed`).

The administrator chooses the validity (1 to 50 years; an intermediate's is shortened to its
parent's certificate, and a renewal that would not end after the current certificate is
refused) and nothing else.

## Every place that assumed one certificate per CA

Changed:

- `IssuerChainResolver`: ownership from `CaCertificates`; `SameKeyScopeAsync`,
  `CurrentSameKeyCertificateIdAsync`.
- `CrlService`: generate, delta and the four "latest" reads map an earlier id to the current.
- `CertificateIssuanceService.ResolveCaAsync`: a CA's current certificate is read from its row
  when the registry does not hold it, rather than matched by name to an earlier one.
- `EstService` (client certificate revocation and retirement), `ScepService` (signer
  revocation and renewal link), `MsaeEnrollmentService` (renewal), `MtlsCredentialStatus`
  (presented certificate): "issued by this CA" is the same-key scope.
- `ModularCADbContext.SignerFacts`: a revocation fact for a certificate issued under an earlier
  certificate names its CA; a legacy row's issuer is found by name when every certificate with
  that name is the same CA's over the same key.
- `ModularCAHealthCheck`: a certificate that has a later one of the same name and key is not
  "expiring".
- `MultiCARegistry`, `DatabaseKeystoreCertificates`, startup: the renewed certificate is
  registered ahead of the earlier one.
- `AdminCaController`, `UserCaController`: a fenced caller sees an earlier certificate of a CA
  in their space.
- `InProcessSigningService`: the renewal purpose and its journal record.

Checked and left:

- CDP and AIA construction (`CaServiceUrlService`): by label; the row moves.
- `OcspResponderService`: matches by name and key hash; looks up within the same-key scope;
  the delegated responder is checked by name and signature, so one issued under the earlier
  certificate keeps signing.
- Chain builders that walk the signing profile (EST `cacerts`, SCEP `GetCACert`, ACME, CMP
  `caPubs`, MSAE, the enrollment pipeline, Web TLS): the profile moved, so they give the
  current certificate. The new row keeps the old row's `SigningProfileId`, which the walk above
  an intermediate uses.
- Chain builders that follow a leaf's `IssuerCertificateId` (admin and user chain download,
  PKCS#12 export, held keys): a leaf issued before the renewal gets the earlier CA certificate,
  which is valid for as long as the leaf is.
- `X509ChainValidationUtil.ValidateAgainstAnchor`, `AnchorIssuerPath`, EST and mTLS anchors:
  matching is by name, key identifier and signature, so either certificate anchors either leaf.
  A renewed root's row links `IssuerCertificateId` to itself, as `IsRoot` expects.
- The hub's `inventory.read`: reports the current certificate's expiry and the CRL of the
  moved schedule. No member was added.
- Backup and restore: whole databases and keystore files. The renewed certificate is in the
  database; the keystore files are unchanged by a renewal.
- SSH: unaffected.

## What relying parties must do

**Root.** A root's new certificate is a new trust anchor to anyone who compares certificates
rather than keys. Everyone who trusts the old root certificate has to be given the new one
before the old one expires: operating system and browser stores, devices, clients that pin the
root. The product cannot do that. Both are downloadable from the CA's page and at
`/ca/{serial}`. Until a relying party has the new one, it keeps validating everything, old and
new, under the old one, until that expires.

**Intermediate.** Nothing has to be redistributed to those who trust the root. Clients receive
the new intermediate certificate in the chain of their next certificate; servers that present
a stored chain keep working with the earlier one until it expires.

**Afterwards, for either.** Reissue the CA's OCSP responder, timestamp and CMP certificates
(Infrastructure Certificates on the CA's page): they were issued to end no later than the
earlier certificate. The instance's own TLS certificate carries the chain it was issued with
until it is next renewed.

## Revoking a renewed CA

Revoking, holding or releasing a CA certificate acts on every certificate that CA has over
the same key (`CertificateRevocationService`, through `SameKeyScopeAsync`): one save, one
reason, one date. Each row is a `Revocation` fact for the journal, each other than the one
named is audited by the service (the caller audits the one it named), and the result lists
their serials. The service's rows name the person who asked (`RevocationActor`: the account,
the request's address and, for a `RevokeCa` ceremony, the ceremony) and say which certificate
was named (`SameKeyAs`); a row says "system" only for a caller that has no person, such as a
protocol. The console lists the certificates before a revocation, a hold and a release. One that is already permanently revoked is left as it is; a release does not
bring it back. `GET /api/v1/admin/certificates/serial/{serial}/revocation-scope` gives the
console the list to show before the administrator confirms.

An intermediate's certificates each name a certificate of the parent as issuer, all within the
parent's same-key scope, so the parent's one CRL lists them all. A root's rows name themselves,
and the root's own CRL lists them: that is what the product did for a root before, and it is
all a self-signed certificate can have. A relying party does not learn that a root is revoked
from a CRL the root signs; it learns it by the root being removed from its trust store. Inside
the instance the revocation is real: a revoked CA issues nothing and is not renewed.

## The system signing CA

It is renewed like any root: a system administrator, step-up, a ceremony where the instance
requires one, the signer's check, audit, and a journal record. Everything that depends on it
depends on its key, which a renewal keeps:

| What | Read by | After a renewal |
|---|---|---|
| Keystore file pins (`Keystores.SigningCaSpkiSha256`) and signatures | public key; the signature block carries no certificate, and no validity is checked | unchanged; no file is rewritten |
| Instance identifier (`Instance_Id`) | the first keystore pin, stored once and never recomputed | unchanged |
| Hub `hello.instanceId`, `hello.systemKey` | the stored identifier and the pin | unchanged |
| Journal checkpoint key block | the system key's hash | unchanged; no `CheckpointKeyChanged`, no wait for a restore marker |
| Wrapped settings and secrets | key id = hash of the public key | unchanged |
| Approver registry | not built | |
| Certificates under it | none: it issues nothing, and has no responder, TSA or CMP certificate | |
| Its CRL schedule and service URLs | certificate id | moved with the renewal |
| A separate signer | classifies from the database, finds the key by public key | nothing to restart or re-read |
| A restore of an archive from before the renewal | the database names the earlier certificate again; the key is the same | signs as before; the renewal can be made again |

Bootstrap gives the system signing CA a certificate valid for 100 years, and a renewal has to
end after the current certificate and may ask for at most 50 years. On an install as bootstrap
made it, a renewal is therefore refused as renewing nothing until fewer than 50 years remain.
The console says so on the CA's page, with the date the certificate runs to, instead of
offering an action that would be refused; this holds for any CA whose certificate runs further
than a renewal could reach. Re-issuing to an equal or shorter validity, and a schedule, are
not built.
A system certificate from a very old install that carries the OCSP-signing usage would be
refused by the signer, which signs no CA certificate with it.

## Validity

1 to 50 years. No standard that binds a private PKI caps the validity of a root or an
intermediate. NIST SP 800-57 Part 1 recommends cryptoperiods by key type and bounds algorithm
strength by date; the CA/Browser Forum's requirements and the browser root programs bind
publicly trusted CAs. Common practice is a root of 10 to 25 years and an intermediate of 5 to
10. `CaKeyPolicy.ValidityAdvisories` says so when a validity goes beyond that (a notice, in the
creation and renewal dialogs and in the renewal's answer), and raises a warning that has to be
acknowledged when a CA whose key is RSA under 3072 bits would get a certificate that runs past
2030, the date the standing notice on such a CA already gives. Neither refuses: an existing CA
has to be able to stay in service while its replacement is prepared. A renewal that goes
through a ceremony keeps both in the ceremony's parameters (`advisories`, with each text, and
`acknowledged`), and the Ceremonies page shows them to the approvers, so the warning is
approved knowingly. The signer does not judge them: it holds the certificate to the CA, the
certificate being renewed and the exact end of validity, as before. This is practice, and no
claim of compliance with a standard.

## Readiness

A CA certificate close to its end, or past it, never makes the node not ready. The keystore
check counts them (`expiringCaCerts`, `expiredCaCerts`) and stays healthy; `checks.caLifecycle`
gives the level (`notice` until 30 days, `attention` with a `warning` from 30 days and
`critical` from 7 days and once expired); the dashboard lists the CA; and the expiry
notification job raises a security alert for it on every run.

## The notices

Every notice text is at most 40 words (a test counts them): what is so, and what to do. The
console shows a `notice` in blue, a `warning` in amber and `critical` in red.

`CaProfilesOutliveCertificate` compares the CA certificate's remaining time with the longest
maximum validity among the end-entity profiles linked to the CA. Two things keep it quiet where
it has nothing to say:

- **Infrastructure profiles are left out.** The profile a CA names for its OCSP responder,
  timestamp signer or CMP signer, and the seeded profile of each of those roles, are not
  end-entity profiles: their certificates are issued to end with the CA's. They are found by the
  CA's own references and by `InfrastructureCertProfiles.ResolveAsync`, the way issuance finds
  them. When a CA has no other profile with a maximum, the longest of them is still shown as a
  fact, marked `longestProfileIsInfrastructure`, and raises nothing.
- **A tenth.** A certificate profile has a minimum and a maximum validity and no default: a
  request that names no end gets the maximum. Every such request is shortened from the day the
  CA has less than the maximum left, which for a 10-year profile on a 10-year CA is its first
  day. The notice is raised once a certificate issued now would lose a tenth of the profile's
  maximum or more (`CaCryptoperiod.ShortensMaterially`): about a year into that 10-year CA, or
  with 357 days left for a 397-day profile.

## Known limits
- A CA whose key is on a PKCS#11 token resolves by public key like any other; this was not run
  against a token.
- The 60 seconds for which the signer caches what kind of key a certificate has: a key
  reference to the old certificate is still served as the CA's for up to that long after the
  repoint. Nothing in the node uses the old reference after the transaction commits.

## Re-key, later

Re-key gives a CA a new key under the same name. What is here was built to take it:

- `CaCertificates.KeyId` already says which key each certificate is over, and `Origin` has
  room for `Rekey` and for the link certificates (old key signs new, new key signs old).
- Revocation scope is already by key (`SameKeyCaCertificateIdsAsync` leaves out a certificate
  of the same CA over another key), so each key gets its own CRL stream, as the journal
  already requires.
- The cryptoperiod facts are computed over the certificates of the **current key**
  (`KeyInUseSince`, `CertificateCount`), so a re-key starts a new period without a change.

What would have to change:

- `CertificateAuthorities.CertificateId` stays "the current certificate", but a re-keyed CA
  has two keys in service for a time: the old key must keep signing CRLs and OCSP for what it
  issued. `CrlConfigurations` and `CrlService` would be per key, not per CA, and
  `CurrentSameKeyCertificateIdAsync` already declines to map across keys.
- The signer classifies a CA key through the CA row's current certificate. A second key of the
  same CA needs a classification through `CaCertificates`, limited to CRL and OCSP purposes.
- The URLs by label would need a key-specific form for the old key's CRL (`/crl/{serial}`
  already is one), and new certificates would point at the new key's.
- The signer's renewal check would gain a sibling for re-key, with real evidence: a new key
  generated under a ceremony, as at creation.
