# Changelog

All notable changes to ModularCA are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning: a new capability is a minor release, a fix is a patch.

## [Unreleased]

Builds between releases are numbered after the line they belong to: `0.4.1-dev.1.0`,
`0.4.1-dev.1.1` and so on. They go to test hosts, and are neither tagged nor published. What they
change is listed here and becomes the release's section.

### 0.4.2-dev.1.10 — 2026-10-10

The profile pickers get a second column that says what the chosen profiles impose, on top of
`0.4.2-dev.1.9`. The new layout has not been seen in a browser yet.

**Changed**

- **Request Certificate, step 1, is two cards.** On the left the request, signing and certificate
  profile, one under the other and each as wide as the card. On the right, "What These Profiles
  Allow": the names the request profile permits (required and forbidden subject fields, values
  it sets or fills in, patterns, SAN types, approval), the issuing CA and its name constraints,
  the certificate's key usage, extended key usage, validity range and wildcard setting, and the
  keys the pair accepts. The key list used to appear only under Generate Key Pair; it now shows
  for a pasted or uploaded CSR too. The same on the self-service form.
- **The CA page's Infrastructure Certificate Profiles section is two columns.** The three pickers
  on the left; on the right, what the profile each picker holds gives its certificate (key usage,
  extended key usage, validity range, and the problem when it has one), and what all three get
  whatever their profile: the key, which follows the CA's key, and the lifetime. The right side
  follows the pickers before anything is saved.
- A picker on the CA page no longer offers the default profiles of the other two certificates.

**Fixed**

- **A CA that named a profile shorter than ten years could not issue that certificate.** The
  OCSP responder, TSA signer and CMP signer were always asked for ten years, and issuance
  refuses a date past the profile's longest validity. The lifetime is now ten years, or the
  profile's longest validity, or the CA's own expiry, whichever is soonest. Found in
  `0.4.2-dev.1.8`, where naming a profile became possible.
- **The admin Request Profiles pages showed a seeded profile's SAN rules wrongly, and saving
  the page wrote the wrong ones back.** The same case-sensitive reading that `0.4.2-dev.1.9`
  fixed for enforcement was still in the admin view: a seeded profile showed "DNS and IP, SAN
  optional" whatever it held, so from `0.4.2-dev.1.9` the page and the enforcement disagreed,
  and editing a seeded profile replaced its SAN rules with those misread ones. The page reads
  the rules as stored now. A seeded profile already saved from the console before this build
  holds whatever was written then; check its SAN rules.
- The validity hint called a ceiling of hours "Max 0 days". It says "less than a day".

**Added**

- The `key-options` answer of both portals carries `constraints`: the issuing CA's name and
  name constraints, and the certificate profile's usages, validity range and wildcard setting
  after inheritance.
- `GET /api/v1/admin/authorities/{caId}/infrastructure-profiles` lists each candidate profile's
  usages and validity range, each role's default profile id, and `subjectKey`, `lifetimeYears`
  and `caNotAfter`.

### 0.4.2-dev.1.9 — 2026-10-10

The request profile is enforced by the server at every step, and four purpose-specific
certificate profiles are added, on top of `0.4.2-dev.1.8`. Nothing here has been seen in a
browser or tried against a live protocol client yet.

**Changed**

- **A request is held to its request profile when it is submitted, approved and issued.** Until
  now only the enrollment protocols checked it; the console's request routes took a signing and a
  certificate profile and never saw the request profile, which only the form applied. Every
  request now records the request profile it was made under, and the names checked are the ones
  the certificate would carry, with any subject or SAN override applied. An override used to
  bypass the request profile entirely.
- **Console and API request routes require `requestProfileId`.** `POST` on
  `/api/v1/user/requests`, `.../requests/upload`, `.../requests/request-with-key`,
  `/api/v1/admin/requests`, `/api/v1/admin/requests/upload` and
  `/api/v1/admin/certificates/issue-with-key` answer 400 without it. A script that calls these
  routes must send it. The refusal of a request the profile does not permit is 400 with
  `MCA-CFG-022` and the reason.
- **The certificate profile must be one the request profile allows:** its default or one in its
  allowed list. A request profile that names none takes any certificate profile for an operator
  and cannot be used for a self-service request. The admin form's certificate profile picker
  now offers only the allowed ones when the request profile names any.
- **Approval re-checks the request and counts approvals from the request's own profile.** A
  request that no longer satisfies its profile is refused with 409 and the reason. The number of
  approvals needed used to be read from whichever request profile the CA's protocol
  configuration named.
- **The server supplies what a profile fixes or defaults.** A subject field with a fixed value
  carries that value, and one with a default carries the default when the request left it out.
  On EST, SCEP and ACME these values were checked and then left out of the certificate, which was
  built from the CSR's own subject; they are now carried into it.
- **A request profile with requests still waiting under it cannot be deleted** (409).

**Fixed**

- **The SAN rules of the seeded request profiles were never enforced.** Bootstrap stores them
  with lower-case keys and the server read them case-sensitively, so each seeded profile was read
  as "DNS and IP allowed, no SAN required, no per-type limit" whatever it said. They are read as
  written now, by the protocols and by the form's preview.
- **"At least one SAN is required" could not trigger** on the enrollment protocols: a request
  with no SAN arrived as an empty list, which skipped the check.
- **A profile that lists no SAN type allowed every type** on the server, while the console showed
  "None" and the form's preview refused them. It now allows none.

**Added**

- **Four certificate profiles:** `TLS Server` (server authentication, up to 397 days),
  `Device Client` (client authentication, up to 2 years), `User Authentication and Email`
  (client authentication and email protection, up to 1 year) and `Code Signing` (code signing,
  digitalSignature only, up to 1 year). Each seeded request profile defaults to the one made for
  it, and `Web TLS (Internal)` to `Web TLS Certificate Profile`. The seeded "Code Signing"
  request profile used to issue certificates that could not sign code.

**Upgrade**

- Two migrations. `RequestProfileOnRequests` adds a nullable column to `CertificateRequests`;
  existing requests are left without a request profile and are not held to one.
  `StandardCertProfiles` adds the four profiles and sets a seeded request profile's default
  only where it has neither a default nor an allowed list. A profile of yours whose name matches
  one of the four in any letter case is left alone, and its request profile gets no default.
- **Protocol configurations are not changed.** ACME, EST, SCEP and CMP keep the certificate
  profile they are configured with (`Main Certificate Profile` on a default install). Only the
  default is set on the request profiles, not an allowed list, because a list would override the
  protocol's own profile.
- **Protocol requests that used to pass may now be refused, as their profile says they should
  be.** On a default install: an EST request with no SAN (`Enterprise Server (EST)` requires
  one), a SCEP request with a SAN other than DNS, a CMP request with a SAN other than email, and
  any SAN under `Code Signing`. A Windows autoenrollment template is held to the request profile
  it names in the same way, so that profile must allow the SAN types the template's certificates
  carry (UPN, DNS). Check your clients against the request profile of each protocol before
  upgrading a host that serves them.
- Where a profile fixes or defaults a subject field, a protocol request now carries that value
  as a subject override, and requests with overrides get the override checks: standard subject
  fields only, and the certificate profile's wildcard setting on DNS SANs.
- Not covered: automatic renewals, the API-key integration route and requests stored before
  this build carry no request profile and are not checked against one.

### 0.4.2-dev.1.8 — 2026-10-09

A CA names the certificate profile its own certificates are issued under, and the profiles the
application depends on can no longer be renamed or deleted from under it, on top of
`0.4.2-dev.1.7`. The new pages have not been seen in a browser yet.

**Added**

- **A CA chooses the profile of its OCSP responder, its TSA signer and its CMP signer.** The CA
  page has a new section, "Infrastructure Certificate Profiles", with a picker for each. Each
  starts on the seeded default, which is what every CA used before. A picker offers the
  end-entity profiles the CA may issue under that list the usage the certificate exists for.
  Saving reissues nothing: the choice applies the next time that certificate is issued, from
  "Reissue Infrastructure Certificates" below it. A profile that can no longer do the job is
  flagged under its picker.
- `GET` and `PUT /api/v1/admin/authorities/{caId}/infrastructure-profiles`. The `PUT` takes
  `ocspResponderCertProfileId`, `tsaCertProfileId` and `cmpSignerCertProfileId`, null for the
  default, and needs `ca.manage` on the CA and step-up.
- Certificate profiles carry `systemPurpose` and `infrastructureUses` in the API, and the
  console marks such a profile "In use".

**Changed**

- **Five seeded certificate profiles are found by name, and their names are now fixed.**
  `TSA Certificate Profile`, `OCSP Responder Certificate Profile`,
  `CMP Signer Certificate Profile`, `Web TLS Certificate Profile` and
  `Main CA Certificate Profile` cannot be renamed, deleted, bound to one CA or changed between
  a CA profile and an end-entity profile (409, `MCA-RES-007`). Before, a rename made the next
  CA creation, infrastructure reissue or console TLS certificate issue fail with "profile not
  found", and nothing stopped a delete. Everything else on them can still be edited.
- **A profile a CA's own certificate is issued from keeps what that certificate needs.** The
  three default profiles, and any profile a CA names, cannot be saved without the usage their
  certificate exists for (time stamping, OCSP signing, the digitalSignature key usage), cannot
  become a CA profile, and cannot be bound to a different CA. A profile a CA names cannot be
  deleted until the CA names another.
- A CMP signer is refused before anything is issued when its profile lacks digitalSignature.
  It used to be issued first and refused afterwards.
- Empty lists that said "Change the scope in the sidebar" say "in the top bar", where the scope
  switcher is.

**Upgrade**

- One migration, `CaInfrastructureCertProfiles`: three nullable columns on
  `CertificateAuthorities`. No row changes; every existing CA keeps the default profiles.
- Not changed: the first CA's TSA and OCSP certificates are still built by bootstrap itself and
  only recorded against the default profiles; the key algorithm of these certificates still
  follows the CA's key, and their validity is still ten years capped at the CA's.

### 0.4.2-dev.1.7 — 2026-10-09

The X.509 request form asks for the profiles first and then offers only the keys they accept,
on top of `0.4.2-dev.1.6`. The form has not been seen in a browser yet.

**Changed**

- **Request Certificate (X.509) starts with the profiles.** Step 1 is the request profile, the
  signing profile and the certificate profile, side by side. Step 2 is the key: paste a CSR,
  upload one, or have the CA generate the key pair. The fields follow, then the validity window.
  The signing and certificate profiles used to be the last step, under "Issuance Options".
- **Generate Key Pair offers only the keys the chosen profiles accept.** It used to list every
  algorithm the certificate profile named and every size, and a key the signing profile, the
  size list or the signature list refused was only found out on submit. The list now comes from
  the server, which runs the checks submission and issuance run. Under it, "Keys not offered"
  gives the reason for each key left out, and the line above it names the signature the CA
  signs the request with.
- **Self-service chooses the certificate profile.** The form used to take the request profile's
  default silently. It now lists the certificate profiles the request profile names, default
  first, and a request profile that names several lets the requester pick.

**Added**

- `GET /api/v1/admin/certificates/key-options` and `GET /api/v1/user/requests/key-options`,
  each with `signingProfileId` and `certProfileId`: the keys the CA may generate for a request
  under that pair, and the ones the pair refuses with the reason. The admin route asks what
  the validity pre-flight asks; the user route asks `cert.request` on the signing profile's CA.
- The self-service request profile list names each profile's certificate profiles
  (`certProfiles`, id and name).

### 0.4.2-dev.1.6 — 2026-10-09

SSH leaves its own menu and becomes tabs on the pages that already exist, on top of
`0.4.2-dev.1.5`. None of the moved pages has been seen in a browser yet.

**Changed**

- **The "SSH CA" menu entry and the self-service "SSH" group are gone.** Each piece is now an
  SSH tab beside the X.509 one:

  | What | Where |
  |---|---|
  | SSH CA keys, generating one, the plaintext notice | Authorities |
  | SSH certificates, revoking, finding one from a host log line | All Certificates |
  | Signing a key for a user, a service identity or a host | Request Certificate |
  | Self-service: requesting a certificate | Request Certificate |
  | Self-service: the certificates issued for you | My Certificates |

  A tab is shown only to someone who can use it, and each piece keeps the right it asked
  before. A page with an SSH tab also opens for someone who can use only that tab. The old
  addresses redirect.
- **The SSH certificate list covers every key.** It used to list one key at a time, chosen from
  a drop-down. It now lists the certificates of every SSH CA key the reader may view, with the
  key as a column and as a filter, and includes the certificates of disabled keys.
- **Sign key asks first what the certificate is for**, a user, a service identity or a host,
  and then offers only the profiles that fit.

**Added**

- **A type on SSH request and certificate profiles**: user, host, or either. A profile with a
  type is refused, with a 400 that names it, for a certificate of the other type. The
  self-service form no longer offers host profiles; it used to list the host request profile
  first and select it. The profile forms have the field.
- `GET /api/v1/admin/ssh/certificates`: the SSH certificates of every key the caller holds
  `cert.view` on, a page at a time, optionally for one key.

**Upgrade**

- One migration adds the type and sets it on the five profiles a new install seeds, found by
  their exact names. Every other profile stays "either" and works as before.
- A script that signs a user key through the seeded host profiles, or a host key through a
  seeded user certificate profile, is refused from this build on.
- A self-service user who may request from no SSH CA no longer has the SSH tabs, and so no
  longer sees SSH certificates issued for them earlier.

### 0.4.2-dev.1.5 — 2026-10-09

A default SSH CA setup, on top of `0.4.2-dev.1.4`. An existing install keeps the profiles and
the limits it has; only what is created from now on follows the new defaults.

**Security**

- **A new user certificate no longer permits forwarding by default.** The signing profile
  created with a new SSH CA key grants a terminal and nothing else. It used to add agent and
  port forwarding, and agent forwarding lets a compromised server use its visitor's access
  elsewhere. A new install seeds a second certificate profile, `SSH User Cert - Forwarding`,
  for where forwarding is wanted; it is attached to no request profile until an administrator
  attaches it.

**Added**

- **A review date on each SSH CA key.** An SSH CA key does not expire, and nothing reminded
  anyone to look at one. Each key now has a "Review by" date: two years after its creation for
  a key that signs user certificates, five for a key that signs host certificates only. The
  console warns from 90 days ahead, and the daily expiry notification job sends one reminder
  per key and date. The date can be moved on the key's page. Nothing is disabled, refused or
  revoked because of it.
- `PUT /api/v1/admin/ssh/ca-keys/{caKeyId}/review-by`, and `reviewBy` in the key list.

**Changed**

- **The form for a new SSH CA key asks for one type**, user or host, and no longer offers a key
  that signs both. It pre-fills the longest certificate as 24 hours for a user key and one year
  for a host key; it used to pre-fill 30 days. The API still accepts both flags.
- **A key's maximum, left out of an API request, is 24 hours for a key that signs user
  certificates and one year for a host-only key.** It was 24 hours for both.
- **The signing profiles created with a key take the key's maximum.** The user one used to be
  capped at 24 hours whatever the key allowed. The key holds the hard ceiling, the request
  profile the everyday number, and the profiles in between are left at the ceiling.
- **On a new install** the user request profile is 12 hours, down from 24, and the standard
  user certificate profile takes any valid login name, three at most, with no forwarding. It
  used to take five lower-case POSIX names, which refused names a grant allows.

**Upgrade**

- One migration adds the review date and sets it for existing keys from their creation time.
  A key whose date is already past gets one reminder on the first notification run, where
  expiry notifications are switched on.
- `--upgrade-check` lists a user signing profile created from this build on in its note about
  profiles that name fewer permits than certificates once carried. That is accurate and not
  a problem to fix.

### 0.4.2-dev.1.4 — 2026-10-08

Getting the SSH revocation list to hosts, on top of `0.4.2-dev.1.3`. Nothing here has run on a
Linux host yet: the fetcher was exercised under Git Bash, and its systemd units were never started.

**Security**

- **A fetcher for SSH servers ships with the CA.** A host refuses a revoked certificate only
  once it has the SSH CA key's new KRL, and the product gave a host nothing to fetch it with.
  `modularca-krl-fetch` is a shell script with a systemd service and timer that fetches the
  list every minute. It replaces the installed list only with a complete one that
  `ssh-keygen` reads as a KRL, by renaming a finished file over it, because `sshd` refuses
  every public-key login while that file cannot be read. It refuses a list with a lower
  version than the installed one, and takes HTTPS only. The four files install under
  `/usr/share/modularca/ssh-krl/`; an administrator copies them to each server.

**Added**

- **The time an SSH certificate was revoked is recorded** (`SshCertificates.RevokedAt`) and
  shown on the certificate's page. A certificate revoked before this build shows none.
- **The KRL routes answer conditional requests.** A KRL is now the same bytes until a
  certificate of its key is revoked, and both routes send a strong `ETag` and answer 304 to a
  matching `If-None-Match` without building the list, so a host can poll every minute.
- The SSH CA key's page shows the KRL's version and last revocation, with the commands that
  set up a host.

**Changed**

- A KRL's generation time is the time of its newest revocation, not the time it was asked for.
- `GET /api/v1/admin/ssh/ca-keys` also answers `krlVersion`, `krlRevokedCertificates` and
  `krlLastRevokedAt`; a certificate also answers `revokedAt`.

**Upgrade**

- One migration adds the column and an index. No existing row is changed.
- After the CA's database is restored from a backup, its KRL has a lower version and hosts
  refuse it until the fetcher is run once with `--allow-lower-version`.

### 0.4.2-dev.1.3 — 2026-10-08

Losing the right to request revokes, on top of `0.4.2-dev.1.2`.

**Security**

- **A user who may no longer request from an SSH CA loses their certificates on it.** A
  certificate used to outlive the right it was issued on: a user taken out of the group that
  let them request kept every certificate they had until it expired. Every live certificate
  issued for a user on an SSH CA is now revoked once that user no longer holds `cert.request`
  on it. That happens at once when the right goes with a group membership, a group, a role
  assignment or a capability grant, or when a role loses a capability or is deleted. The
  `SshLoginNameSweep` job checks the same thing every 15 minutes, so a right lost any other
  way revokes within one period.
- **The admin sign route no longer signs for a user who may not request.** It asked only that
  the user be active and known to the SSH CA, so an operator could issue a certificate for
  someone who held no right to one. The user must now hold `cert.request` on the SSH CA. The
  Sign key form says so when the chosen user does not.

**Changed**

- `GET /api/v1/admin/ssh/ca-keys/{caKeyId}/users/{userId}/login-names` also answers
  `mayRequest`.
- The `SshLoginNameSweepCompleted` audit entry counts `RequestRightLost` beside the other rules.

**Upgrade**

- The first sweep after the upgrade also revokes the live SSH certificates of users who no
  longer hold `cert.request` on the SSH CA, where the certificate records that user. A user who
  still requests today keeps theirs.
- A script that signs through the admin route for a user who cannot request gets 400.

### 0.4.2-dev.1.2 — 2026-10-07

Three tightenings of SSH login names, on top of `0.4.2-dev.1.1`.

**Security**

- **`root` is never an own username.** A user named `root`, in any case, no longer holds `root`
  on an SSH CA key just because the key allows own usernames: `root` always needs a grant.
  Whoever may create or rename a user decides that user's username, and this keeps that right
  from handing out `root`.
- **Signing a host key through the admin route asks step-up MFA**, as signing a user key does.
  A host certificate lets its holder answer as that host. The operation for both is now
  `sign-ssh-cert`; `0.4.2-dev.1.1` called it `sign-ssh-user-cert`.
- **A periodic sweep revokes what a missed hook left live.** Revocation follows a change at
  once, but as a second step: a node that stopped between the two left a certificate valid
  until its user or SSH CA was next looked at. The `SshLoginNameSweep` job now checks every
  live certificate on a schedule, every 15 minutes unless `SshLoginNameSweep.Schedule` says
  otherwise. It revokes a certificate whose user is not active, was deleted or was renamed,
  and one that carries a login name its holder no longer has. It cannot be turned off, and it
  writes nothing when it finds nothing.

**Upgrade**

- The first sweep after the upgrade revokes the live SSH certificates of users who are already
  disabled, where the certificate records that user. Nothing else that exists today is revoked.

### 0.4.2-dev.1.1 — 2026-10-07

SSH login names: the CA decides who may log in as which account, and writes the name hosts
log. **This changes the sign API**, so scripts that send `keyId`, or that sign for an account
the requester was never given, get 400. No existing certificate is revoked by the upgrade. The
console pages have not been seen in a browser yet.

**Security**

- **The CA writes the key id of every SSH certificate.** `sshd` logs it with each login, so it
  is the record of who logged in to a shared account. It was taken from the request. It is now
  the username of the user the certificate is for, `svc:` and a label for a service identity
  with no account, or the first hostname of a host certificate. A `keyId` in a sign request is
  refused.
- **A certificate for a user carries only login names that user holds.** A login name is the
  SSH principal: the account the certificate may log in as. Principals were checked only
  against the certificate profile's patterns, and the seeded profile allows any account name,
  so anyone who could request could issue themselves a certificate for `root`. A user now
  holds their own username, where the SSH CA key allows it, and the names granted on that key
  to them or to a group they are in.
- **Login names are granted per SSH CA key**, to a user or a group, with an optional longest
  certificate and an optional end. Granting, changing and removing a grant, and the
  own-username switch, need `ca.manage` on the SSH CA and step-up MFA, and each is audited.
- **A certificate lasts no longer than its login names allow**: the smallest limit among the
  names asked for, and never past the earliest end of a grant used.
- **Taking a name away revokes the certificates that carried it.** That covers removing a
  grant, moving its end earlier, turning own usernames off, leaving a group and deleting a
  group, unless the holder still has the name another way. Disabling, renaming or deleting a
  user revokes every live certificate issued for them.
- **Each certificate records who it is for, who asked for it, and why its holder had each
  login name** at the time it was issued.

**Added**

- **Login names on the SSH CA key page**: the own-username switch and the grants, with how many
  live certificates each grant carries.
- **SSH login names and live SSH certificates on the user page**, with "Revoke all", and the
  login names granted to a group on the group page.
- **A request form on the self-service SSH Certificates page.** The API existed; the console had
  only the list. It offers the requester's login names as a tick list and shows the name hosts
  will log.
- **Find a certificate from a host log line**: paste the `sshd` line of a login and the console
  finds the certificate by its serial, key id and CA fingerprint.
- `GET /api/v1/user/ssh/request-options`, `GET /api/v1/admin/ssh/certificates/find`,
  `GET /api/v1/admin/ssh/certificates/{id}`, and the login name routes under
  `/api/v1/admin/ssh/ca-keys/{caKeyId}/login-names`, `/api/v1/admin/ssh/users/{userId}` and
  `/api/v1/admin/ssh/groups/{groupId}`.
- **The upgrade check notes what changes for requests** and counts the live user certificates
  that carry a name other than their key id. It informs and never refuses.

**Changed**

- **The admin sign route signs for a named subject.** `sign-user` takes exactly one of
  `subjectUserId` and `serviceLabel`. For a user, only names that user holds can be asked for:
  an administrator grants a name first, so the grant is on record. For a service identity the
  names are typed and checked against the certificate profile, as before. The route now asks
  step-up MFA, since whoever signs decides whose name a public key is certified under; signing
  a host key does not.
- **The Sign key form has no "Identity (Key ID)" field.** It asks who the certificate is for and
  shows what the CA will write.
- **A user's own SSH certificate list shows the certificates issued for them**, whoever asked.
  One an administrator signs for a user appears in that user's list.
- **An omitted validity means the most allowed**: the smallest of the profiles', the key's and
  the login names' limits. It used to mean the signing profile's maximum.
- **"Login names" replaces "Principals"** on the SSH pages. The API field is still `principals`.
- `GET /api/v1/admin/ssh/ca-keys` also answers each key's `certificateAuthorityId`.

**Upgrade**

- Every existing SSH CA key allows own usernames until that is turned off on the key. Grant the
  other login names people use before their certificates are due again.
- Existing certificates are untouched and expire on their own. A user certificate whose key id
  is its requester's username is recorded as that user's; the others record no subject.

### 0.4.2-dev.1.0 — 2026-10-07

The first build of the 0.4.2 line, on top of `0.4.1-dev.1.7`. SSH CA keys move into the signer.
**Upgrade the signer before the node.** Installing it is one-way for an install with SSH CAs: the
key files are imported and deleted at first start. It has not run on Linux yet.

**Security**

- **SSH CA private keys are held by the signer.** Each was an unencrypted file under
  `config/ssh-ca-keys`, and the node ran `ssh-keygen` to sign with it. The keys now live in a
  third keystore file, `ssh-ca.keystore`, and the signer builds and signs every SSH certificate
  itself. It takes the certificate's fields, never bytes to sign, so an SSH CA key cannot be
  made to sign anything that is not a certificate. The node holds no SSH CA key and runs no
  program.
- **Existing key files are imported at first start**, by the node with the control role, once
  the signer is unlocked. Each file is then overwritten with zeros and deleted. A key whose
  file is missing, protected by a passphrase or not its key stays "awaiting import" with the
  reason; it signs nothing, and stops neither the other keys nor the start.
- **A notice says these keys were stored in plaintext.** Archives and snapshots made before the
  import still hold them, and an overwrite does not guarantee erasure. Rotating an SSH CA is
  the only remedy; this release informs and does not rotate.
- **The signer enforces what the node used to be trusted with.** It checks the ceremony, or
  the instance's waiver, before it generates an SSH CA key. It refuses a certificate of a type
  the key does not sign, one valid for longer than the key allows, one with no principal, and
  one with an option it does not know.
- **What was approved is what is certified.** Principals, key id and options reach the
  certificate exactly as given. The old path rewrote them for a command line after the profile
  checks had passed the originals.
- **Self-service SSH signing is audited.** It wrote no audit entry before.

**Changed**

- **A certificate carries exactly the extensions its profiles and request name.** `ssh-keygen`
  added five permits to every user certificate by default; none is added now. A profile that
  names only `permit-pty` issued all five and now issues that one. The upgrade check lists the
  profiles this narrows.
- **A certificate needs at least one principal**, and "Allow any principal" is gone from the
  sign form. A DSA public key is refused.
- **`valid_after` is five minutes before issue**, for servers whose clock runs behind, and the
  validity is counted from there.
- **A KRL download always answers 200 with a valid KRL**, also with nothing revoked, and works
  on a validation-only host. The public route answered 204 before.
- **SSH signing answers 503** while the signer is locked or a key awaits import, and 400 with
  the signer's reason for a certificate it refuses.
- **Backup carries `ssh-ca.keystore`.** A key file still awaiting import travels wrapped by the
  signer. Restoring an older archive brings its key files back, and the next start imports
  them. Reset deletes the SSH keystore and any key files.
- **`--upgrade-check` reports the SSH CA keys** the first start will import, and refuses when
  the file of an enabled SSH CA is missing or is not its key.
- **`/health/ready` and the admin key list say where each SSH CA key is held.** An SSH key
  that is not held never makes the node unready.
- **Console.** A Storage column and state on the SSH pages, signing disabled for a key that
  cannot sign, the plaintext notice, SSH keys on System Health, and the API's own error text
  in the create and sign forms.
- **The break-glass unlocker opens the SSH keystore**, and needs the application database for
  it: that keystore's passphrase exists only there.

**Removed**

- The `ssh-keygen` dependency, the `SshCa` settings, `PUT /api/v1/admin/config/ssh-ca` and the
  SSH CA card on the Settings page. A leftover `SshCa` section in `config.yaml` is ignored.
- `openssh-client` from the container image.

**Fixed**

- The admin SSH key list's `publicKeyUrl` pointed at a route that does not exist.

### 0.4.1-dev.1.7 — 2026-10-07

**Changed**

- The Restart Application card on the Settings page says what a restart is for now: the
  settings marked Restart, a rotated JWT secret, and a restored backup. It named logging and
  HTTP, most of which apply without one.

### 0.4.1-dev.1.6 — 2026-10-07

**Changed**

- **Fourteen settings that waited for a restart now apply to the next request**, on the node
  that saves them. Each was copied once at start by whatever uses it, and is now read when it
  is used. The Settings page shows them as Live. Other nodes still take a change at their
  next start.
  - **IP whitelist switch.** Turning it on with rules that exclude your own address locks you
    out at once, where it used to wait for a restart.
  - **mTLS required paths**, where mTLS was on at start (turning mTLS itself on or off, and
    its trusted CAs, still need a restart). Adding `/api/v1/admin` without a way to present a
    client certificate refuses the console immediately.
  - **JWT IP binding.** New tokens already carried the binding at once; it is now also
    enforced, or stops being enforced, at once.
  - **Network audit**: on or off, log all requests, and the excluded paths.
  - **CORS**: on or off, and the allowed origins.
  - **HSTS, the EST trust anchor refresh interval and RSA signature padding** are read live as
    well. Nothing in the console changes them on a running node yet, so nothing is seen.
  - **The scheduler's missed-run policy** was already read on every tick and was only
    labelled Restart.
- Eight settings still wait for a restart on purpose:
  - **The JWT secret, issuer and audience.** Changing any of them live ends every session at
    once, and on more than one node the nodes would refuse each other's sessions until all
    had restarted. A rotated JWT secret is still used from each node's next start.
  - **The five syslog settings.** The syslog sink is built with the logging pipeline.
- The answers to `PUT /api/v1/admin/config/http`, `/scheduler` and `/ip-whitelist` no longer
  say a restart is required for what now applies at once.

### 0.4.1-dev.1.5 — 2026-10-06

**Added**

- **The JWT secret can be rotated from the console.** Settings, Security, JWT has a Rotate
  secret button: the server generates a new secret and stores it wrapped by the signer.
  Nothing is typed and nothing is shown. Since the secret moved to the database there was no
  way to replace it but an environment variable.
  - **The new secret is used from each node's next start.** Until then the node keeps the one
    it started with, and the card says a new one is waiting. From the restart on, access
    tokens signed with the old secret are refused, so everyone signed in signs in again.
  - With more than one node, restart them together: a node on the old secret and one on the
    new do not accept each other's sessions.
  - Refused where an environment variable supplies the secret, and when the signer is locked
    or out of reach. Step-up is required (`rotate-jwt-secret`), and the change is audited as
    a settings change that names the secret and holds no value.
  - New endpoint `POST /api/v1/admin/settings/jwt-secret/rotate`.
    `GET /api/v1/admin/settings` gains `waitingForRestart`.

**Fixed**

- **A node running on a temporary JWT secret stored it at the next settings save.** A start
  that cannot read the stored secret makes one up for that start (dev.1.3). The first save of
  any setting from the console then took the made-up secret for a change and, if the signer
  could be reached by then, stored it over the real one. It is no longer stored; the start
  log says to rotate the secret if the stored one is lost for good.

### 0.4.1-dev.1.4 — 2026-10-06

**Fixed**

- **On the Settings page, a card's tag and the headings inside it now say what their fields
  say.** dev.1.3 put a badge on each field and left some of the older labels around them
  disagreeing with it.
  - A card's tag is taken from the fields the card shows, where it was taken from every
    setting of the section. Logging and Certificate Policy read "Live and restart" over fields
    that are all live.
  - **Per-Username Rate Limit and the refresh token binding rules were headed Restart and are
    live**: both are read on each request. The headings follow their fields, and the notes
    above them no longer say when a change applies.
  - Login Protection and Token Binding & Lifetime had no tag.
  - The JWT card said its settings are managed in `config.yaml`. They are in the database, and
    changed on the host with `--settings`.
  - A badge inside a field label was set in capitals; beside a switch it was not.
- **JWT IP Binding showed Off whatever the mode was**, and the card's summary read "JWT IP
  binding: undefined". The server sends the mode by name and the page read it as a number.
  The stored mode was never changed by this: saving the group sent back what the server had
  sent. The field has its badge now (Restart).

### 0.4.1-dev.1.3 — 2026-10-06

**Changed**

- **The secrets the node uses move to the database, wrapped by the signer.** The JWT secret,
  the LDAP bind password, the mail password and OAuth2 secrets, and the webhook endpoints leave
  `config.yaml` at the control role's next start. Each is stored as a blob only the signer can
  open, bound to its own setting. `config.yaml` then holds this host's settings and nothing
  secret but what belongs to the host (the web TLS and signer-channel passwords).
  - The copy of `config.yaml` kept at the rewrite no longer holds the moved secrets.
    **Copies kept by dev.1.0 to dev.1.2 (`config.yaml.pre-settings-*.bak`) and backup archives
    made before this build still hold them in the clear.** Delete those copies; rotate the
    secrets if an old archive may have left your hands.
  - **A node now needs its signer at start to read them.** When the signer is locked or out of
    reach, the secrets cannot be read: sign-in still works, on a JWT secret made up for that
    start (everyone is signed out at the next restart, and another node will not accept those
    sessions), and LDAP sign-in, mail and webhooks wait. The log says which secret could not
    be read. Supplying a secret through the environment still wins.
  - When the signer cannot be reached at the move itself, the secrets stay in `config.yaml`,
    where they keep working, and move at a later start.
  - **The two single integration API keys stay in `config.yaml`.** Named API keys replace
    them; the single keys keep working as they are.
  - `--settings` can clear a secret from the host. Setting one needs the signer, so it is done
    in the console.
- **The Settings page says, beside each setting, when a saved change takes effect and where
  the setting is kept.**
  - **Live**: at once on this node. Other nodes take it at their next start.
  - **Restart**: when this node next starts.
  - **This host**: kept in this host's `config.yaml`, not in the database.
  - **Environment**: decided by an environment variable; the field cannot be changed.

  A card's tag is now what its settings say, so it cannot disagree with them. Twenty-two
  settings that were shown, or assumed, to apply at once are marked Restart, because
  something reads them once at start: CORS, HSTS, the JWT issuer and audience, binding a
  session to an address, the syslog target, the IP whitelist switch, network audit, the mTLS
  required paths, the EST trust anchor refresh, RSA signature padding and the scheduler's
  missed-run policy. New endpoint `GET /api/v1/admin/settings`.

### 0.4.1-dev.1.2 — 2026-10-06

**Fixed**

- **The move no longer stores a default an earlier build wrote.** A `config.yaml` written
  before the project's repository moved carries the old address as `SourceCode.Url`. Nobody
  chose it: it was that build's default, and the page already publishes the new address for
  it. dev.1.0 stored it in the database as if it had been chosen. The move now leaves it out,
  and the control role's next start clears it where it was stored, with a history entry saying
  why. An address an operator set for their own fork is stored as before.

### 0.4.1-dev.1.1 — 2026-10-06

**Added**

- **Log tables can be refreshed.** A log shows what had happened when the page was opened, so
  a new entry did not appear until the page was reloaded. The table header now has a Refresh
  button and an "Auto 30s" switch, on the Audit Logs page (every tab), the ACME audit section
  and the audit tables on record pages.
  - Rows stay on screen while they reload.
  - Auto-refresh is remembered per table, like its columns. It pauses while rows are ticked,
    while a row's drawer is open, and while the page is in the background.

### 0.4.1-dev.1.0 — 2026-10-06

Installing this build adds five tables in two migrations (`SettingsStore`, `ApiKeys`) and, at
the control role's first start, moves the instance-wide settings out of `config.yaml` into the
database. As for any schema change, going back to 0.4.0 afterwards means restoring a backup.

**Added**

- **Named API keys for the integrations.** The infrastructure API and the cert-manager issuer
  each had one key, typed by an administrator into `config.yaml` and shared by every client,
  so replacing it broke all of them at once. Each client can now hold its own.
  - **Generated, shown once, stored as a hash.** A key is created under Settings, Integrations,
    in the integration's card. It is 256 random bits starting `mca_`, shown once, and only its
    SHA-256 is kept, so nobody can read it back, from the console or the database.
  - **Revoked one at a time.** A revoked key stops working at once and stays listed. The table
    shows each key's name, last four characters, status, scope, expiry and when it was last
    used.
  - **Scoped and time-limited if you want.** A key can be limited to one space's CAs or to the
    instance's, and can expire. Its scope narrows the integration's and never widens it.
  - **The old key keeps working.** The single key in the integration's settings is accepted
    beside the named ones, so nothing changes for a client until you give it a key of its own.
  - cert-manager audit records name the key that was used, as `cert-manager:<name>`.
  - Creating and revoking a key need step-up MFA. API: `GET`, `POST` and
    `DELETE /api/v1/admin/api-keys`. A new table, `ApiKeys`.

**Changed**

- **Instance-wide settings are kept in the database.** About 140 settings that are the same
  for the whole instance (ACME, certificate policy, scheduler, mail, LDAP, audit retention,
  alerting, the public name, and so on) move out of `config.yaml`. A change made in the console
  is now versioned, has a history, and is audited with the value before and after. Each
  setting is one row, named by its path joined with underscores (`Acme_Http01_MaxAddresses`).
  See `docs/architecture/settings-store.md`.

  **Upgrading: what happens at the first start.**
  - The control role moves every instance-wide setting that differs from its default into the
    database, then rewrites `config.yaml` with this host's settings only. The file as it was
    is kept beside it as `config.yaml.pre-settings-<time>.bak`, readable by its owner only. It
    holds the same secrets the file held; delete it once you are satisfied.
  - **From then on `config.yaml` does not decide an instance-wide setting.** A value for one
    written there is ignored, and every start says so in the log, naming the setting. Change
    it in the console, or with `--settings` on the host.
  - What stays in files, for good: the database connection (`db.yaml`), the signer's settings,
    and each host's listeners, ports, paths, certificates and proxy settings.
  - **The eight secrets stay in `config.yaml` for now**: the JWT secret, the LDAP bind
    password, the mail credentials, the webhook endpoints and the two integration API keys.
    They move in a later build.
  - Environment variables still win over both.
  - **On an install split across hosts**, only the control host's file is rewritten. Another
    host's file is left as it is; an instance-wide value in it is ignored with the same
    warning. A setting changed in the console reaches the other hosts at their next start,
    not while they run.
- **`--settings` on the host**, for reading and changing a stored setting without the console.
  It is the way back in when a setting has locked the administrators out, which editing
  `config.yaml` used to be. Run as the service user:
  `--settings list`, `get <Key>`, `set <Key> <value> [--reason <text>]`, `clear <Key>` and
  `history <Key>`. A change is recorded in the setting's history and the audit trail under a
  host actor, and a running service takes it at its next start.
- **Secret settings will be stored wrapped by the signer, or hashed.** The store keeps the JWT
  secret, the LDAP bind password, the mail credentials and the webhook endpoints as blobs only
  the signer can open, each bound to its own setting so that a blob copied to another row does
  not open there. The two API keys are kept as SHA-256 hashes, which the node can check and
  nobody can read back. The signer gains a second wrapped-secret format for this; secrets it
  wrapped before are read as before. A node and a signer run as separate processes have to be
  upgraded together, as for any release.

**Fixed**

- **ACME: certbot and Caddy can finalize an order.** Both send a certification request with an
  empty subject and the names as subject alternative names only, which RFC 8555 allows. The
  request profile bootstrap seeds requires a common name, and it was asked about the empty
  subject, so every finalize from those clients was refused; the client saw only "the
  certificate order failed". Issuance has always named such a certificate after its first DNS
  name, and the request profile is now asked about that subject. acme.sh and Traefik send a
  common name and were not affected. Found by the ACME client matrix on its first complete run.

## [0.4.0] — 2026-10-06

Everything since 0.3.0, including the work that was numbered 0.3.1 and 0.3.2 and never
published. One release candidate, `0.4.0-rc.1`, was tagged on the way; "Changes since
0.4.0-rc.1" below is for anyone who ran it.

### Upgrading from 0.3.0

- **0.4.0 runs on PostgreSQL only.** It refuses to start against MySQL or MariaDB.
  `modularca-migrate`, which ships beside the node, copies a 0.3.0 MariaDB database into a
  PostgreSQL one it creates, then brings it up to this version. 0.3.0 is the only MariaDB schema
  it reads, so upgrade to 0.3.0 first from anything older. See
  `docs/architecture/postgresql-migration.md`.
- **Check before installing.** `--upgrade-check` rehearses every migration against your database
  and lists every refusal in one run, changing nothing; `install.sh` runs it for you. "Upgrading
  to 0.4.0" in `packaging/README-DEPLOY.md` says what can be refused and how to clear each.
- **There is no downgrade.** Take a backup first; going back means restoring it.
- **Containers.** `latest` is this release. To stay on it, name it:
  `MODULARCA_IMAGE=ghcr.io/dilenex/modularca:0.4.0`.

### Changes since 0.4.0-rc.1

**Security**

- **Twenty-four admin routes that changed something without step-up now ask for it.** An API
  client that calls one must send `X-MFA-Token`; the console prompts.
  - A certificate's access list addressed by certificate id: `allow/view`, `allow/manage`,
    `downgrade` and `revoke` under `/api/v1/admin/manage/cert-permissions`. The routes addressed
    by serial already asked. These need an `UpdateCertAcl` token issued for the certificate id.
  - Restarting the audit hash chain.
  - Trust anchors: import, enable or disable, delete.
  - Revoking an SSH certificate.
  - Creating an enrollment token, a CMP shared secret or an ACME external account binding key.
  - Creating, changing or deleting another user's access badge.
  - Creating a space; creating a certificate, request or signing profile.
  - SSH certificate templates: create, change, delete.
  - Approving or rejecting a certificate request.
- **Left open on purpose:** cancelling a request, issuing an approved request, issuing with a
  server-generated key, renewing, and signing SSH keys. Issuing follows an approval, which is
  now gated.
- **A test lists every admin route that changes something.** It fails when a new one neither
  asks for step-up nor is named, with its reason, as deliberately open.

**Added**

- **A CA whose OCSP responder cannot be used is reported.** Such a CA answers every OCSP
  request "unauthorized", and nothing said so. The state is shown in three places:
  - an OCSP Responder section on the CA's page, with the responder certificate's subject, serial
    number and expiry, and a notice above the reissue action that repairs it;
  - an OCSP column on Authorities;
  - an OCSP Responders card on System Health, listing every CA that serves OCSP.

  A CA reads Answering, Refusing (with the reason), CA key signs or Not served. The reasons are
  the responder's own: no responder certificate, one that is missing, revoked, expired or not
  yet valid, one without the OCSP signing extended key usage, or one without the no-check
  extension when the security policy requires it. The CA hierarchy feed carries the state as
  `ocspResponder`. The readiness endpoint is unchanged: it answers 503 when degraded, and one
  CA's responder is no reason to take a node out of service.

  **Check after upgrading:** a CA created while the OCSP Responder Certificate Profile listed
  no extended key usage holds a responder certificate that cannot sign. It shows as Refusing;
  reissue its OCSP responder under Infrastructure Certificates on the CA's page.
- **One step-up prompt covers a bulk action.** A verification may name up to 100 targets
  (`targetIds` on `verify-stepup/totp` and `verify-stepup/webauthn`). The token is still bound to
  the operation and to each named target, and is spent once per target. Approving or denying
  several requests, revoking several SSH certificates and enabling, disabling or deleting
  several trust anchors each prompt once.
- `GET /api/v1/admin/audit/action-types`, and a `success` parameter on `GET /api/v1/admin/audit`.

**Changed**

- **Console: colour means status.** Types and kinds (Root, Leaf, protocol names, Built-in) and
  group chips are neutral tags. Action bars hold neutral buttons, at most one primary, and the
  destructive action last in red.
- **Table headers have two lines.** The first carries the title with Find, Columns and Export.
  The second carries what can be done with the ticked rows (the count, Details, the table's
  actions and Deselect) and, at its right end, the create button. The second line is always
  there on a table with checkboxes, with its buttons disabled until a row is ticked, so the
  rows do not move when one is ticked.
- **Every table's create button is in the same place.** It is "+ New", and reads Cancel while
  its form is open. This covers Authorities, Profiles, Templates, Users, Service identities,
  Groups, Roles, Spaces, Kerberos realms, Enrollment, ACME EAB keys, SSH CA keys, CRL schedules,
  LDAP publishers and Whitelists.
  - Three say what they do where "New" would mislead: "+ Import" on Trust Anchors, "+ Sign key"
    on SSH Certificates and "+ Bind" on Kerberos realms.
  - New Certificate Authority opened from a collapsed bar under the table, and Import Trust
    Anchor from another; both forms now open from the button.
  - A heading row that only repeated the table's title is removed.
- **Filters share one layout**, and a filter that repeats the CA scope is hidden under a scope.
  The audit log gained an Outcome filter and lists every action name the server can record;
  the users table gained Status, Signed in and Group; certificates gained "Expiring within".
- **Detail pages and drawers line their values up**, and drawers are a little wider. The
  certificate page shows extensions without a button. The audit drawer names its fields in
  words.
- **Tables:** text columns start wider and grow into free space. The Authorities and Profiles
  tables have a find box. A profile's validity reads "10 months to 13 months", not `P10M`.
- **Dashboard:** cards are as tall as their content and none scrolls inside the page; the group
  counts are a tile in the top row.

**Fixed**

- **The distribution builds on Linux.** The release build of `0.4.0-rc.1` failed with
  NETSDK1152, so that candidate published no tarball and no image. The console bundles were
  being picked up twice by the publish step.
- **Reissuing a CA's OCSP responder or timestamp signer changes nothing when it cannot work.**
  A reissue from a certificate profile that lists no extended key usage issued the new
  certificates, moved the CA to them, destroyed the old keys and then reported that the old
  ones had been left in place. The profile is now checked first, and a failure after that rolls
  everything back.
- **A CA is not created from an infrastructure profile that lists no usage.** It would have had
  a responder that every client rejects.
- **The missing-CMP-signer notice no longer misdescribes the CA certificate.** A CA page with
  no CMP signing certificate said the CA certificate "carries no digitalSignature key usage
  and is rejected by OpenSSL-based clients", whatever the certificate carried. That is now
  said only of a CA certificate without the usage. For one that has it, the page says that
  CMP responses are signed with the CA's own key and that a CMP signer can be issued. The
  server's log line follows the same rule, and the CA hierarchy feed carries the answer as
  `certificate.carriesDigitalSignature`.
- **CA Distribution offers no link to a CRL the CA does not publish.** The delta CRL link led
  to a 404 when the CA had no delta schedule.
- **A session refresh that was allowed is not recorded as a failed sign-in.** A refresh from a
  changed address or client, or without proof of the session key in observe mode, was written
  as `UserLoginFailed` with a successful outcome. It is now `SessionRefreshNotice`. Refusals
  keep `UserLoginFailed`. Records written before this keep their old name.
- **Scheduled jobs write their audit records under one actor, `scheduler`.** Five jobs wrote
  `Scheduler` and five wrote `scheduler`, so filtering the audit log by either found half.
  Records written before this keep the name they were written with.
- **System Health counts every certificate.** Its statistics counted the first page of the
  certificate list, so an instance with more than 25 certificates read "Total 25".
- **The certificate page shows the key and signature algorithm.** Only the list returned them.
- **Three filters that did nothing now work.** The audit log's user filter sent a parameter the
  server never read; the users table's "Last login" was always blank; the certificate list's key
  algorithm filter could not find ML-DSA or SLH-DSA keys.
- **The dashboard's count of system groups** read a field the server does not send and always
  showed 0.
- **The SSH certificates table no longer says "Loading…" forever when there is no SSH CA key.**
- **Every console has a tab icon.** Only the public pages declared one, so a browser on the
  admin, setup or docs console asked for `/favicon.ico` and was answered 401.

### PostgreSQL

- **The database is PostgreSQL.** The MySQL provider had no release for the framework ModularCA
  targets and no sign of one. The node refuses a MySQL connection string outright instead of
  failing somewhere inside a provider.
- **Whether two names differ only in case is decided per column.** MySQL answered that once for
  the whole database and PostgreSQL answers it the other way. Usernames, CA labels, protocol
  names and the like stay case-insensitive, by column, so `Admin` still signs in as `admin` and a
  label in an enrollment URL still resolves.
- **The database no longer holds secrets it can read.** An enrollment token was stored as
  itself, and the admin API handed live tokens to every CA operator. It is stored as a SHA-256:
  tokens already issued keep working and stop being readable. CMP shared secrets are wrapped by
  the signer.
- **The audit hash chain verifies.** It never had: the hash was computed over a timestamp with
  more precision than the column keeps, so every record failed recomputation and the verify
  endpoint would have reported tampering on every deployment. Records written before the fix
  cannot be recomputed, so a chain can be restarted by an audited marker; the node does it once
  for each chain that needs it, and the verify report says what is intact and since when.

### Security fixes since 0.3.0

- **A CA that is revoked, disabled or expired does not sign.** Issuance only checked that the
  tenant was enabled, so a CA whose certificate had been revoked, by the CA-compromise ceremony
  included, kept issuing over ACME, EST, SCEP, admin issuance, reissue and auto-renewal. New
  error codes `MCA-CFG-014`, `015` and `016`.
- **A client certificate is one factor.** Certificate sign-in asked for a second factor and then
  accepted the same certificate as that factor.
- **A replayed refresh token ends the session.** Two requests with one token could both rotate
  it. Rotation is now one conditional update, and presenting a rotated token revokes the whole
  family.
- **Every certificate knows which CA issued it.** One resolver walks the issuer chain; CA-scoped
  access, the console's lists and the CRL and OCSP scope all decide by issuer, never by name
  alone.
- **Every route to privilege goes through the controlled-user ceremony.** A review found many
  ways for a lone administrator to mint or remove privileged users around it. Rank now comes
  from what an account can do, not from which groups it is in.
- **The audit chain holds under concurrent writers**, including two processes writing to one
  chain: the record is stamped and linked under a database lock.
- **The consoles keep one session between tabs.** Renewal runs once across tabs, so two tabs
  never present the same refresh token, and a transient failure no longer signs the user out.

### A backup restores onto a new host, and a test proves it

A new test runs the built node as an operator does: it installs an instance unattended, starts
it, backs it up, destroys the host and both databases, restores the archive onto a second host
from the archive, the backup key and `keystore.yaml` alone, starts it, and checks the root, a
newly signed web certificate and CRL, the stored-data secrets and the audit chain. It runs with
the PostgreSQL harness in CI. Its first runs found every fault below; none of them could be seen
without restoring for real.

- **A restore onto a host with no keystores was refused.** The step that saves the live state
  before a restore failed when there was no `keystores/` directory, so restoring onto a clean
  host with hand-made databases never worked.
- **After restoring into empty databases the restore could not read them.** It created the
  `citext` extension after the database driver had read the type list, so the CRL counters were
  not raised and the keystores were refused.
- **A node restored over a fresh install did not start.** The fresh install's web certificate
  file stayed, the restored `config.yaml` held another password for it, and the node exited with
  an unhandled exception. The restore now removes that file, and a file that does not open is
  treated as missing.
- **A restored node served a throwaway self-signed web certificate.** The certificate's key is
  in no archive, nothing reissued it, and the startup message suggested `--bootstrap`, which
  would have erased the restored CA. The node now issues itself a replacement at start, with
  the subject, names and lifetime of the last one.
- **A restored node went on serving the CRL from the archive** until its schedule came round,
  numbered below CRLs already published. A restore now makes every CRL schedule due, so the
  first start publishes one above the floor.
- **A backup whose database dump failed reported success.** It printed a warning, wrote an
  archive with no database in it and exited 0, and the verification job cannot see inside an
  encrypted archive. A failed dump now ends the backup with no archive.
- **A restore whose database step failed carried on** to replace the keystores and `config/`,
  and reported success. It now stops first. An archive with no application database is refused
  before anything changes.
- **A backup that could not load its key left the plaintext archive behind** in `backups/`. The
  key is now loaded first, and an archive that was not encrypted is deleted.
- **`pg_dump` and `pg_restore` were killed after two minutes.** The limit is now
  `Backup.DatabaseTimeoutMinutes`, 60 by default.
- **An unattended install crashed when `bootstrap.yaml` gave the root no locality or state**,
  after creating the databases. Only the common name is needed, as in the wizard.

The deploy guide's "Backup and recovery" section is now the procedure, including what a restore
does not bring back: certificates issued and revocations made after the backup.

### Setup asks whether ACME clients are on a private network

- **Ticking ACME in the wizard asks "Will ACME clients be on a private network?"** The default
  is No. HTTP-01 validation refuses private addresses unless a per-CA switch is on, and that
  switch was only on the console's protocol settings page, so the first ACME request on a home
  or office network failed until the administrator found it. "Yes" turns the switch on for the
  root CA the wizard creates, and is audited. Unattended bootstrap takes
  `Acme.AllowPrivateAddressValidation` in `bootstrap.yaml`; without the key it is off.
  `POST /api/v1/setup/initialize` takes `features.acmeAllowPrivateAddressValidation`, which is
  optional. Neither is read unless ACME is on.
- **The Setup UI guide said ACME starts on.** It starts off.

### ACME client matrix in CI

- **A new workflow, "ACME clients", has certbot, acme.sh, Caddy and Traefik each take a
  certificate over http-01** from the container image built from the commit, installed
  unattended. It is also the first thing in CI to build the Containerfile and start the image.
  `tests/acme-clients/README.md` lists what it does not cover: cert-manager, Proxmox VE, dns-01,
  wildcards, external account binding, renewal and revocation.

### An unattended install starts

- **`--bootstrap` wrote no public name, and the node then refused to start.** The headless path
  left `Https.PublicDomain` empty in `config.yaml`, which startup treats as fatal, so every
  unattended install needed a hand edit before its first start. Bootstrap now writes one:
  `HttpsApi.PublicDomain` from `bootstrap.yaml`, or without that key the first DNS name under
  `HttpsApi.SANs` that is not `localhost`, or `localhost`. The CRL, OCSP and AIA URLs use the
  same name. A value that is not a bare hostname or IP address is refused before any change.
- **The web certificate covers the public name.** A name the SANs do not list is added.
- **The deploy guide asked for a `config.yaml` in the pod's config volume.** Bootstrap replaces
  that file, so what was put there was lost. The guide now says to set the name in
  `bootstrap.yaml`.
- **`bootstrap.yaml.example` set `HttpsApi.ValidityYears`,** a key nothing reads. It now sets
  `ValidityDays: 397`, which is the value that was in effect.

### Containers: a compose quick start, and an image that can back itself up

- **`deploy/compose` runs ModularCA and PostgreSQL on one host.** `docker compose up -d`, read
  the setup token from the log, and finish the wizard in a browser. See README-DEPLOY.md,
  "Compose: one host, one process".
- **The image starts the setup wizard when it is not configured.** It used to run the headless
  bootstrap unconditionally and fail without a `bootstrap.yaml`. With one in the config volume
  it still bootstraps headlessly.
- **The image now carries `pg_dump`, `pg_restore` and `ssh-keygen`.** Without them no backup
  could be taken or restored in a container, and SSH certificates could not be signed. The
  PostgreSQL tools are version 16; build with `--build-arg PG_MAJOR=17` for a newer server.
- **Backups and logs are volumes.** Backups were written inside the container and lost with it;
  the image declared `/var/lib/modularca`, which nothing writes to. The volumes are now
  `config`, `keystores`, `logs` and `backups` under `/opt/modularca`. The pod manifest mounts
  its data volume at `/opt/modularca/backups`.
- **Program files in the image belong to root**, as on a host install. The service account
  writes only the four volumes.
- **The pod manifest is in the repository.** `deploy/container/modularca-pod.yaml` was matched by
  an ignore rule and never committed, so the documented file was missing from every checkout.

### One administrator can run an instance

- **Setup asks whether more than one person will administer the CA.** The question has no
  default. "Just me" starts key ceremonies off for the instance policy and the first space;
  "Several people" starts them on, as before. The choice is audited. Unattended bootstrap takes
  `Administration.MultipleAdministrators` in `bootstrap.yaml`; without the key, ceremonies start
  on. `POST /api/v1/setup/initialize` refuses a body without `admin.multipleAdministrators`.
- **A ceremony nobody else could approve is no longer opened.** The initiator never counts, so
  with one administrator every ceremony sat pending until it expired. CA creation, SSH CA
  creation and deletion, CA revocation, the generic initiate endpoint, space and instance policy
  changes and controlled-user changes now answer 409 and open nothing: `MCA-CFG-020` when no
  other account can approve, `MCA-CFG-021` when some can but fewer than the quorum. Service
  identities and disabled or locked accounts do not count. The response names the scope whose
  switch applies and whether the caller, a system super-administrator, may turn it off.
- **The console shows the way out.** The refusal appears where the action was taken, with links
  to the key ceremony switch (Settings, Security, Key Ceremonies for the instance; a space's own
  page for a space) and to Users, each only for a viewer who can use it. Both switches warn, and
  do not block, before the requirement is turned on while nobody else could approve. A ceremony
  already pending that can no longer be approved says so in its drawer, where its initiator can
  cancel it.
- **Bootstrap audit lines reach the audit trail.** The replay at first start read the lines with
  the wrong key casing and skipped every one. Keystore events written before the audit database
  is reachable are now replayed, a failed one as a failure.
- **Audit rows keep on/off values.** The audit scrubber blanked every value whose name contains
  "key", "pin" or "token", so a change to `RequireKeyCeremony` was recorded as `***` before and
  after. True and false are now kept; everything else under such a name is still blanked.

### Keys, backups and packaging hardened before release

- **The signer no longer exports CA keys as PKCS#12 under Backup.** The node, the signer's
  only client, could ask for any CA, OCSP, TSA, CMP or system key with a password of its choosing.
  PKCS#12 export is now Export-only and end-entity only; backups take whole keystore files.
- **Backup archives no longer carry openable secrets.** The Data Protection key ring (which
  opens TOTP secrets, held end-entity keys, Kerberos keys and LDAP passwords) and the SSH CA keys
  travel wrapped by the signer and are unwrapped at the first start after a restore, so a restored
  host needs the original secondary passphrase. Every writer of `config.yaml` used to copy the
  database passwords into it, and so into every archive; none does now, archives strip the
  section, and restore uses the new host's own `db.yaml`. New archive passwords need 16
  characters and use scrypt N=2^17; old archives still restore.
- **CRL numbers never go backwards after a restore.** Every counter is raised to the restore
  time in Unix seconds, and the change is audited. Certificates revoked after the backup must be
  revoked again.
- **Program files belong to root.** Upgrades no longer chown the install tree: only `config`,
  `keystores`, `logs` and `backups` stay with the service account, and existing ones are never
  touched. On a split install the node could rewrite the signer's binary and, after any upgrade,
  read its keystore and passphrase; the signer could also not reach its own binary at all. The
  signer unit now ships and is installed. The pre-restore snapshot and the default `--backup`
  archive live under `backups/`.
- **The signer reads its settings from a directory the node cannot write.** With
  `--signer-dir /opt/modularca/signer`, now on the packaged signer unit, the signer reads
  `signer.yaml`, `db.yaml`, `keystore.yaml` and its identity from that directory and nothing
  under `config/`, and logs there. On one host the node could otherwise set the PKCS#11 module
  the signer loads, its client pin and its listen address. The keystore unlock no longer reads
  `config/config.yaml` and `db.yaml` behind the caller's back. Existing split installs keep
  running on `config/` with a warning until moved (`--migrate-signer-dir`; README-DEPLOY.md,
  "Two units").
- **The signer reads what it signs.** Each purpose accepts one structure only: a certificate,
  a CRL, an OCSP response, a CMP or SCEP message, a timestamp, or a key's own request. Anything
  else is refused and audited with the hash of the bytes offered. A CA certificate is signed
  only for a key the signer itself generated for a new CA, and an OCSP-signing certificate only
  for a responder key it generated for that CA, so a compromised node cannot have either issued
  to a key it holds. Two things that worked before are now refused: an OCSP responder
  certificate for an outside key (until approvals are verified by the signer), and an
  intermediate beneath an intermediate, which never validated because every intermediate is
  created with path length 0. Node and signer must be upgraded together.
- **Licences fail closed** while the vendor key is a placeholder.
- **Expired certificates say what to do.** The dashboard counted from one page of the list; it
  now uses a scoped lifecycle summary, separates expired certificates that were replaced (renewed
  or reissued) from those that were not, lists what needs attention, and links every count to a
  filtered list. The list and detail pages say when a certificate expired and what replaced it.
  `status=expired` no longer includes revoked certificates.

### Review of 0.4.0: what changes for operators

With the tenant filters gone, every check that relied on them was reviewed twice. The fixes
below close cross-scope gaps; several change behaviour an operator or a client can see.

- **Creating accounts in another space's groups is refused.** Assigning a group checked whether
  the caller belonged to *any* system group, `system-auditor` included, and read memberships past
  the worn badge. A system auditor who operated one CA could create an account with a password of
  their choosing in another space's Operator group. Assignment now needs `group.manage` at the
  target group's own scope (its CA, its space, or the instance), read through the badge; system
  groups still need a super. System operators and auditors no longer count as administrators of
  CA groups.
- **ACME accounts belong to the CA they registered at.** An account registered at a CA without
  EAB could order and finalize at one that requires it. Each account is now bound to its CA
  (migration `BindAcmeAccountsToCa`, backfilled by label, ignoring case; label-less accounts to the
  default CA). On label-less routes an account keeps using its own CA, so changing the default no
  longer breaks existing clients; only new registrations go to the default. Order, authorization,
  challenge, finalize and certificate URLs are under `/acme/{ca-label}/`. Finalize is refused for
  an order placed at another CA. An account the upgrade could not bind recovers by posting
  new-account with its key, subject to that CA's EAB policy. New-account and new-order refuse a CA
  that does not serve ACME.
- **Enrollment tokens work only where they were minted for.** A SCEP challenge password or QR
  token was accepted at any CA. A token bound to a CA now works only there, one bound to a space
  only at that space's CAs, and one bound to neither only at instance CAs. Tokens take their CA
  from the signing profile's issuer. Tokens that do not match where they are used must be minted
  again.
- **CAs are found by key and certificate, not subject name.** OCSP, CRL generation and export,
  LDAP publishing, revocation, the certificate impact view, integration chains and compliance
  reports matched a CA by its subject DN, which two CAs can share once one is renamed. The impact
  view could list another space's certificates. Each now follows the issuer link or the CA's key.
- **Security settings need a system administrator.** System operators could read the lockout
  thresholds and change token binding, `BehindReverseProxy`, the IP allowlist, mTLS, network
  audit, alerts, webhooks, integration keys and the password policy, some without step-up.
  `/admin/security-policy`, `/admin/config` and `/admin/password-policy` now need a system
  administrator, and every write needs step-up. `RefreshTokenDays` is limited to 1–30. A password
  policy below 8 characters, with minimums above the maximum, or with a history above 24 is
  refused; a dictionary must be a file in `config/password-dictionaries`. Operators see the email
  delivery summary at `GET /admin/notifications/delivery`. Changing
  `AllowSystemSuperSelfApproval` needs a system super.
- **Unbinding a profile from its CA needs instance scope.** A space operator could unbind a
  request or signing profile and so offer it to every space.
- **Policy ceremonies are approved and rejected by admins.** A space policy change needs a space
  admin, an instance policy change a system admin; operators can no longer approve or veto them.
- **Audit records keep their space** (migration `AuditRecordSpace`). Kerberos realm, service
  identity and failed CA-creation records carried no space and were missed by the space filter.
  The space is hashed only when set, so existing records verify unchanged.
- **Sealed audit chains stay sealed through retention.** Retention could prune a retired chain's
  seal, or the succession record that anchors it, after which a deleted or altered seal read as
  healthy. Successions are now carried forward with their original seal hash, retention never
  prunes a retired chain past its anchored seal, and a missing seal reports `TailMissing`. Upgrade
  step 6 accepts only `Sealed`.
- **Integration keys can be scoped to instance CAs.** `IntegrationApi.SpaceId` and
  `CertManager.SpaceId` accept `instance`. A key naming the old system tenant, or a space that
  does not exist, matched nothing silently; it is now named at startup, and `--upgrade-check`
  refuses it on every host.
- **A CA label is fixed once anything references it** (issued certificates, ACME accounts or
  orders, protocol audit), so a freed label can no longer inherit another CA's history.
- **Smaller changes.** Several CAs marked default resolve deterministically and are named at
  startup; the label-less timestamp endpoint again needs a CA marked default. Unreadable ceremony
  parameters block rather than pass. A super's badges need a super. An instance group must be
  requested with `scope: "instance"`; an SSH CA naming a space is refused. Verifying an unknown
  audit chain returns 404. The OpenAPI document is valid again. `install.sh` checks the whole
  archive before stopping anything, restarts the units if it fails before touching the install,
  and leaves them stopped with instructions if it fails after.

### Fixed

- **A system admin can no longer seize another approver's account.** An admin could reset the
  password and MFA of any account whose tiers theirs dominated, and a peer dominates a peer. One
  system admin could therefore reset another's password, which the response returned, strip their
  MFA, sign in as them with the temporary password, enrol their own authenticator, and then approve
  their own ceremonies as that account, and as every other admin in turn: the quorum was one person.
  The same held for any account their rank dominated, such as a system operator or a space
  admin, and for re-enabling, unlocking or re-addressing an approver. Resetting the password or the
  MFA of an account that holds an admin, operator or CA-admin tier, or changing its username, email,
  enabled or locked state, password expiry or forced change, now opens a controlled-user ceremony
  at that account's tier unless a system-super acts. As with every such ceremony the initiator never
  counts and the account itself cannot approve. Disabling or locking is gated too, since locking out
  approvers starves the quorum, and doing so to the last other active admin of a scope is refused,
  as deleting them is. The temporary password is generated only when the approved ceremony is
  executed and is returned only to whoever executes it; it is never stored in the ceremony or the
  audit. Changes to accounts holding no controlled tier, and to your own account, apply directly
  as before. A password sent in a user update, which was always ignored, is now refused, and the
  password-expiry and forced-change flags of an update, which were also ignored, are applied.

- **LDAP identity settings are super-only.** A sign-in accepts a directory bind for the local
  account of the same name, super included, so whoever chooses the directory chooses who can sign
  in as whom. A system admin could point LDAP at a directory they ran, create an entry named after
  any account, and sign in as it. Changing the server, port, TLS, bind identity or password, the
  user or group search settings or the group mappings, on either the LDAP settings or the group
  mappings endpoint, or turning LDAP sign-in on, now needs a system-super (403 otherwise). Turning
  LDAP sign-in off and the group-sync and auto-provisioning switches stay with operators. The
  console shows those fields read-only to everyone else.
- **A promotion expires if the target's credentials change.** An admin could open a ceremony to
  promote a colleague who held no privileged tier, wait for a peer to approve it, then reset the
  colleague's password and MFA directly, which needed no ceremony because the colleague was not
  yet privileged, and execute: the colleague became an approver the admin could sign in as. A
  promotion now records the security stamp and a digest of the MFA enrolment of each account it
  promotes, and execute marks it Expired (409) if either changed. While a promotion is pending or
  approved, a direct password reset, MFA reset or account change of that user is refused (409)
  unless a system-super makes it. An MFA reset now rotates the security stamp and ends the user's
  sessions, as a password reset does, and so does a username or email change by an admin. An
  approved account change likewise expires if the account's username, email, enabled or locked
  state changed since it was opened, so it cannot undo a super's incident response. An empty
  username or email in a user update, which was written as a change, is refused (400). A promotion
  or account change opened before this release carries none of that state, and is expired at
  execute (409) with "This ceremony predates the credential check; open it again."
- **A promotion discloses recent credential resets, and the resetter can neither open nor approve
  it.** Resetting a colleague's password or MFA and then promoting them still gave the resetter an
  approver account they could sign in as, as long as the reset came first. Opening a promotion now
  looks in the audit trail for any password or MFA reset, or the creation, of each account it
  promotes in the last 30 days, by anyone, and the ceremony description leads with a warning line
  per reset ("alice's password was reset by bob on 2026-09-30") that the Ceremonies page
  highlights for approvers. If the audit trail cannot be read, the promotion opens and says
  "could not check recent resets". Because a failed audit write (Audit.FailMode=LogAndContinue)
  loses the record of a reset, the promotion also reads the account itself: one that must change
  its password at next logon, as an administrator's reset leaves it, is disclosed as "alice's
  password was set by an administrator and has not been changed since" unless the audit trail
  already names the reset. An administrator who made a password or MFA reset of the account cannot
  open the promotion (409) or approve it (403, with the reason, which the Ceremonies page shows in
  the ceremony's drawer) unless they are system-super; they can still see and reject it. Execute
  reads the audit trail again, falling back to the resets recorded when the promotion was opened,
  and an approval by a resetter no longer counts toward the quorum, so a promotion left short of
  it is expired (409).
- **The Kerberos realm enrollment identity is confined to the realm's scope.** Every ticket a
  realm accepts acts with its enrollment identity's rights on the space's CAs, and whoever holds
  the realm's keys can mint a ticket for any principal. A space administrator could bind their
  realm to any account, a system-super included, and enroll with its rights. A binding's
  enrollment identity must now be a service identity of the realm's space (any service identity
  for an instance realm), checked when a binding is created, re-pointed or re-enabled (400
  otherwise). Existing bindings keep working; each start names the ones that do not comply.
- **Unlocking resets the failed-login count.** Unlocking an account left its failed-login count
  as it was, so a single wrong password locked it again. Unlocking, directly or through a
  ceremony, now clears the count and any temporary lockout, and an unlock also lifts a temporary
  lockout on an account that is not hard-locked. A hard-locked account that no one left can
  unlock, such as the only system-super with a permanent lockout policy, is recovered on the host
  with `ModularCA.API --unlock-user <username>`, run as the service user. Each use is written to the
  audit trail as `UserUnlockedOnHost` by `host:break-glass`; when the audit database cannot be
  reached the account is still unlocked and the command warns that no record was written.
- **The LDAP auto-provisioning hint was wrong.** Settings said a first LDAP login creates the
  account. It does not: every account is created locally, and the switch has no effect.

- **The instance operator rank is now controlled.** Holding `ca.manage` at instance scope, with
  no space and no CA, makes an account an approver of every key ceremony on the instance and in
  every space. It was not a controlled tier, so a single system admin could grant it by a direct
  grant, a role assignment or a capability added to a role held instance-wide, with no ceremony,
  and then fill any quorum with accounts of their choosing. It is now the system-operator tier.
  Granting it, removing it or deleting a holder needs a controlled-user ceremony at the instance
  user quorum, approved by a system admin or another system operator, unless a system-super acts.
  Existing holders keep it; at each start the server names those who hold it by direct grant or
  role. A key ceremony on a CA whose quorum comes from its groups now takes the Administrator
  group's quorum, never the Operator group's.

- **Reissuing a CA's responder certificates works again.** Since 0.3.0, reissuing the OCSP,
  TSA or CMP signing certificate of any CA whose scope requires a key ceremony (the default)
  failed with CeremonyRequired: the new responder key was generated under the ceremony purpose
  with no ceremony. It is now generated as infrastructure of that CA, and committed only to that
  CA's own responder certificate.
- **The signer is fail-closed on scope.** A key-management request that states no scope is
  refused rather than read as instance-wide; the Bootstrap purpose manages keystore files only,
  never individual keys; imports and commits are held to the CA that owns the certificate. The
  signer audit records the scope each decision was made under.

### Removed

- **Tenant hostnames (0.4.0).** The instance is the isolation boundary and serves its own names,
  so per-tenant names, their SNI certificates and their database ingress routes are gone. The
  `RetireTenantHostnames` migration drops the table and refuses while any hostname remains;
  `Ingress.RouteRefreshSeconds` is no longer read. See "Upgrading to 0.4.0" in the deploy readme.

- **The system tenant (0.4.0).** It is folded into the instance by the `FoldSystemTenant`
  migration. The system signing CA, SSH CAs, the system groups and those CAs' groups now have no
  space, which means instance scope. The instance's CA policy (key-ceremony requirement and
  quorum, validity ceiling, CA-level user quorum) moves to the security policy, with the system
  tenant's values copied as they were. Scopes are independent: the instance's policy governs
  instance CAs only, and a space keeps its own. The `org-system-*` groups and the
  `Tenants.IsSystemTenant` column are removed. A null space is never read as "no policy" any more,
  so revoking the system signing CA or disabling an SSH CA now needs the instance's ceremony. The
  upgrade refuses, changing nothing, while open ceremonies name the system tenant, while the
  `org-system-*` groups have members or badge sources, while tenant-wide grants, role assignments,
  service identities or unbound profiles on the system tenant would become instance-wide. Every
  organisation tenant, however many, becomes a space with its CAs, groups, profiles and policy
  as they were. An earlier 0.4.0 build also refused more than one organisation tenant; that was
  dropped once scopes became independent and an instance could hold several spaces, after
  staging, which has two organisations, was refused. New audit records go to one instance chain, and
  each per-tenant chain is sealed at the first start, with its final hash anchored in the instance
  chain (`GET /api/v1/admin/audit/verify/chains`). The licence no longer counts the system tenant,
  and now gates no space at all ("tenants are spaces", under Changed). Instance policy changes
  by anyone but a system-super open an `InstancePolicyChange` ceremony. Down is not supported:
  restore the pre-upgrade dump. See "Upgrading to 0.4.0" in the deploy readme.

- **Tenant quotas (0.4.0).** The tenant-level maximum CAs, certificates and users are removed,
  with their columns, by the `InstanceUniqueCaNames` migration, whatever values were set: nothing
  is refused over them. Quotas are per CA, on the CA's admin group, as before. The space API no
  longer returns or accepts the three fields, and the console no longer shows them.

- **The tenant query filter (0.4.0).** Spaces are an access scope, not a partition of data, so
  the database no longer filters rows by space; the only global filters left hide soft-deleted
  spaces, CAs and users. Every endpoint that lists or reads rows of several spaces applies the
  caller's fence explicitly, and a test drives each of them through the real authorization policy
  as users of one space and asserts no row of another space or of the instance comes back.

### Changed

- **The upgrade check lists every problem in one run (0.4.0).** `--upgrade-check`, and the
  service's own dry run at start, no longer stop at the first migration that refuses. Each
  statement runs under its own savepoint, so one run reports every precondition that refuses,
  across all pending migrations and both databases, numbered and with its message verbatim.
  Refusals after the first are marked "also found": real on the current data, but their outcome
  may change once the earlier ones are fixed. A migration whose later steps fail because of its
  own refusal has those steps reported as skipped; any other error stops the check, which then
  says the checks after it could not run. The check passes (exit 0) only when every statement of
  every pending migration ran; exit codes are unchanged, and nothing is applied either way. The
  real apply is unchanged. See "Checking an upgrade before installing it" in the deploy readme.

- **BREAKING: tenants are spaces (0.4.0).** The delegation scope is called a space in the schema,
  the API, the console, the configuration and new audit records. A space delegates administration
  within one organisation; the instance is the whole installation. Scripts and integrations that
  call the admin API must change with the server, because nothing old is aliased:
  - **API paths.** `/api/v1/admin/tenants`, `/tenants/{id}` and `/tenants/{id}/settings` are
    `/api/v1/admin/spaces…`; `/admin/tenants/{tenantId}/kerberos-realms` is
    `/admin/spaces/{spaceId}/kerberos-realms`; `/admin/quotas/by-tenant` is `/by-space`;
    `/admin/user-quorum/tenant/{id}` is `/space/{id}`. The old paths answer 404.
  - **Query parameters.** `?tenantId=` is `?spaceId=` on the audit, certificate, certificate
    template, certificate profile and CSR lists. Audit chain verification takes `?chainId=`,
    because a retired chain is not a space.
  - **JSON members.** Request and response members say space: `spaceId`, `spaceName`,
    `spaceSlug`, and `/api/v1/me` sends `spaces`. A service identity's scope is `space`, a
    validity ceiling's source is `Space`, the ceremony type is `SpacePolicyChange`, the step-up
    operations are `enable-space`, `disable-space` and `update-space-settings`, and audit rows
    read from the unchanged audit database carry `spaceId` or `chainId`.
  - **Stale bodies fail closed.** The request bodies where no space means the instance (creating
    a root or intermediate CA, a group, a role, a role assignment, a user grant, a service
    identity, an SSH CA key, and ceremony parameters) refuse unknown members. A client that still
    sends `tenantId` gets 400 naming the member, where it would otherwise have created something
    instance-wide.
  - **Console.** `/admin/tenants` and `/admin/tenants/:id` are `/admin/spaces` and
    `/admin/spaces/:id`; the old links, `?tenant=<slug>` and remembered scopes are carried over
    until 0.5. Space Admin and Space Operator replace the Org tier labels. The docs site's tenant
    model page is the space model page, with a redirect.
  - **Groups.** The `RenameTenantToSpace` migration renames each space's `org-<slug>-admin`,
    `-operator`, `-auditor` and `-user` groups to `space-<slug>-*`, the names new spaces get, and
    refuses while a new name is taken. An `LdapAuth.GroupToRoleMappings` entry that still names an
    `org-<slug>-*` group is read as its `space-<slug>-*` group, with a warning, until a super saves
    the LDAP settings or the file is edited. No other name is translated.
  - **Configuration.** `IntegrationApi.TenantId` and `CertManager.TenantId` are `SpaceId`. The
    old key is read as the new one with a warning, and the process refuses to start (status 3)
    when both are set and differ, so an integration key is never left unscoped. The first save of
    the configuration writes the new name.
  - **No space gate.** `Features.AllowMultipleOrganizations` is retired: it is ignored, with a
    warning while it is still set. Creating a space always succeeds. From the fifth, without a
    licence carrying the multi-space feature, the response and the console recommend a licence.
    `MCA-CFG-017` is retired and will not be reused; the other error codes keep their numbers.
  - **Audit.** New records use `SpaceCreated`, `SpaceUpdated`, `SpaceDisabled` and
    `SpacePolicyChangeApplied`, with target type `Space`. Recorded rows keep `TenantCreated`,
    `TenantUpdated`, `TenantDisabled`, `TenantPolicyChangeApplied` and target type `Tenant`, and
    searching by either name finds both. The audit database and its hash chain are unchanged.

  The migration renames the table, the eleven columns, their indexes and constraints in place,
  and the scope keys in stored ceremony parameters. It copies no data and has no downgrade. Older
  builds query the old names, so stop every node and the signer before the control role
  upgrades. See "Upgrading to 0.4.0" in the deploy readme.
- **CA labels and names are unique across the instance (0.4.0).** A label is the path of a CA's
  CRL, OCSP, AIA and enrolment URLs, so it names one CA, soft-deleted ones included, compared
  without regard to case; a deleted CA's label is never reused. Creating a CA, an SSH CA, or
  renaming one (`PUT /admin/authorities/{id}`, which now validates the label too) answers 409 for a
  taken label or name. The `InstanceUniqueCaNames` migration refuses, changing nothing, while two
  CAs share a label, a label up to case, or a name; see "Upgrading to 0.4.0" in the deploy readme.
  In the console, `?ca=<label>` alone names the scope. Bootstrap and the setup wizard refuse,
  before building anything, a root CA common name whose label would be invalid or reserved.
- **Instance roles see every space's CAs (0.4.0).** A holder of a capability at system scope,
  such as a system operator or system auditor, could already act on every CA but was shown only
  the instance's in lists. Lists now show what they may act on, per capability: each list opens
  every space only for the capability its endpoint demands, so a system auditor who also operates
  one CA sees every space's CAs and certificates but only that CA's space's operator
  configuration (tokens, whitelists, SSH keys, request profiles, service URLs). The same holds
  per space: a space is open to a list only for the capabilities held there, so a requester in
  one space sees none of its operator configuration.
- **A CA that has issued keeps its label (0.4.0).** Changing the label of a CA that has issued any
  certificate, under its current or a superseded CA certificate, or as a legacy row with no issuer
  link whose issuer DN is the CA's subject, is refused with 409
  (`MCA-RES-006`): the label is in those certificates' CRL, OCSP and AIA URLs. Its name can still
  change. CA-creation ceremonies check the label, name and CA profile when initiated, not only
  after approval, and an execution that fails on them answers 409, 400 or 404 instead of 500.
- **Moving a profile to another CA checks the new CA (0.4.0).** A signing profile's issuer, a
  certificate, request or SSH profile's CA, and an SSH template's key are checked against the
  CA they move to: inside the caller's fence (404), with the capability on it (403), and, except
  for signing profiles, of the row's own scope (400). A protocol configuration or certificate
  template may name only a signing profile that issues from its own CA's current certificate, and
  enrolment refuses a stored one that does not; the console offers only that CA's profiles, and
  re-saving a stored one says what to change. The `InstanceUniqueCaNames` migration refuses,
  changing nothing, while an enabled configuration or template is like that; see "Upgrading to
  0.4.0" in the deploy readme. A CA profile for a new intermediate may be unbound, bound to the
  parent CA, or space-wide in the new CA's space.
- **Grants given to a user directly work in lists (0.4.0).** A CA- or space-scoped capability
  grant or role assignment held by a user without a group in that space was hidden from the user's
  lists and pending requests. The fence now comes from all four grant sources, under a worn
  badge, and equals what authorization allows.
- **A certificate profile is used only within its scope (0.4.0).** A CA issues under an unbound
  profile, one of its own space, or one bound to it, on every path: console, user portal, EST,
  SCEP, CMP, ACME and Windows autoenrollment. Naming another space's profile, or one bound to an
  instance CA or another CA, is refused (`MCA-CFG-019`), as is configuring one on a protocol, a
  certificate template, or as an inheritance parent. A new CA is linked only to the unbound and
  space-wide profiles.
- **ACME EAB keys are instance credentials (0.4.0).** An EAB key names no CA and is accepted at
  every CA's ACME endpoint, so creating and deleting keys needs cert.revoke at system scope, and
  only a caller whose cert.revoke reaches every space sees the list. The console hides
  "Generate EAB Key" from everyone else and says why the list is empty.

## [0.3.0] — 2026-09-19

### Fixed

- **An approval-gated request profile no longer lets ACME, CMP or SCEP past.** A CA's protocol
  configuration can name a request profile, and both protocols used that profile to choose the
  certificate profile and to validate the names a client asked for. Neither ever read the flag
  saying a human must approve first. Every ACME order finalized, and every CMP certificate request
  issued, straight to a certificate with no approver, while the console showed the gate as set.
  EST and Windows autoenrollment, the two anyone had exercised, both honoured it.

  ACME and CMP now refuse and close the request, because neither offers a way for a client to come
  back for a certificate approved later: nothing links a later approval to an ACME order, and CMP
  implements no polling operation at all. SCEP, which does have a poll, answers with its pending
  status and leaves the request in the queue for an approver. A deployment with any of the three
  enabled on a CA whose request profile requires approval will see those clients start failing, or
  in SCEP's case start waiting, where they previously succeeded.

  All three were found by moving the protocols onto the shared enrollment pipeline, which is the
  point of that work: the rule now lives in one place instead of being reimplemented, correctly or
  not, five times. Three of the five were wrong, including the one whose wire format had carried a
  pending status since it was written, declared and never once used.

- **SCEP enrollment refused every request.** The key-algorithm rule read the certificate profile's
  permitted list, which is JSON, by splitting it on commas. The profile default is an empty JSON
  array, which splits into one token that matches no algorithm, and a populated list splits into
  fragments that match nothing either, so every enrollment was answered with a bad-algorithm
  failure. The same column is read correctly everywhere else. It is read as JSON now.

### Separation of duties

- **The signer is its own process.** Every stored private key is reached through one signing
  contract, and nothing outside the keystore project can hold a key handle; an architecture test
  fails the build if that changes. A key signs only for its own CA and tenant and only for the
  purposes its kind allows; every decision is recorded in the signer's own audit table with the
  ceremony it ran under and, over the wire, the peer that asked. `--role signer` runs the keystore
  behind gRPC with mutual TLS, pinned both ways from a dedicated identity CA the signer creates
  (`--init-identity`, `--issue-node-identity`), failing closed when it cannot record a decision; a
  node with `Signer.Mode: Remote` holds no key material and needs no keystore password. A tenant
  that requires ceremonies gets no key without an approved, unexpired one; a CA's OCSP, timestamp
  and CMP signer keys are reissued under an infrastructure context that can never mint a CA key.
  The default single process is unchanged.
- **Roles.** Every controller and scheduled job belongs to one role: enrollment (the protocols),
  validation (CRL, OCSP, AIA, CA certificates), control (console, admin, users, ceremonies,
  backups) and ingress. `--role` or `Roles:` in the configuration selects any subset; a process
  hosts only its roles' endpoints and jobs, and `/health/ready` reports what each active role
  needs. The deploy readme describes the three-process layout.
- **Ingress.** `--role ingress` terminates TLS for the public domain and every tenant hostname,
  selected by SNI, and routes by hostname to tenant nodes with YARP, on plain HTTP as well so a
  tenant's revocation URLs reach its node. Routes come from `Ingress.Routes` and from the tenant
  hostnames table (`NodeUpstream`); a name with no upstream is served locally, which is how a
  single process keeps working. Upstreams are trusted by a pinned key or a shared CA; a node that
  fails its health checks answers 503 for its names.
- **Tenant hostnames.** A tenant is reachable by its own names from one process: each name gets
  an endpoint certificate from a CA of the tenant, presented by SNI and renewed with the console's
  own; enrollment URLs derive from the name a request arrived on; the readiness check accepts any
  name a tenant is reached by. The console and sign-in stay on the public domain.

### Server-generated private keys are delivered once, as one PKCS#12

- **Short custody, then one file.** A private key the CA generates for a request is held on the
  request row, wrapped with ASP.NET Core Data Protection under a purpose bound to that row, until
  the certificate is issued; it never enters the keystore or the signer, and it is not in the
  response that carries the request. Once the certificate exists, the holder downloads
  certificate, chain and key together as a `.pfx` under a password of their choosing, from
  `POST /api/v1/user/requests/{id}/pkcs12` (the request must be their own) or
  `POST /api/v1/admin/requests/{id}/pkcs12` (gated as certificate export is: operator rights on
  the CA, manage rights on the certificate, step-up MFA). The held key is deleted in the same
  save that records the delivery and the delivery is audited; a second download reports the
  date the key left. A request that is rejected or cancelled loses its held key at once, and the
  protocol cleanup tick discards keys whose certificate is revoked or expired, or whose requested
  validity passed unissued. The admin console's Issue Certificate page, the user portal's
  Request Certificate page, My Requests and the admin request detail page carry the download
  and say when the key was delivered. Keys the CA stored before this change stay exportable as
  PKCS#12 from the user portal until their certificates expire; they are not copied to a
  renewal request any more, and the admin API's clear-text `pem-key` export is withdrawn.
- **Stored keys leave through the signer.** PKCS#12 export of a stored end-entity key is a
  signer operation, allowed for end-entity keys only, to a named caller, and written to the
  signer's audit like every other decision; the node no longer unwraps a key itself.
- **The signer is a readiness step.** The node unlocks its keystore behind the signer and asks
  it whether it is unlocked: `/health/ready` reports the signer (unlocked, key count, backend),
  the Windows autoenrollment checklist has a "signer" step, and the ACME, EST, SCEP, CMP, MSAE
  and admin issuance endpoints answer 503 with a clear message while the signer is locked.
  Backups take the keystore files from the signer and restores return them through it, which
  verifies each file against the pinned signer before it replaces the one in place; the archive
  layout is unchanged.

## [0.2.0] — 2026-09-16

### Windows autoenrollment (MSAE), complete

Machines and users in an Active Directory forest enroll from a ModularCA CA by Group Policy alone,
with no credential configured on any client, proven end to end against a Samba forest in the lab.

- **Kerberos, per tenant, per forest.** A tenant binds each of its Active Directory forests as a
  Kerberos realm: realm name, DNS domain, the service principal the CA is reached by, an enrollment
  identity, and whether machines and users may enroll. Keys are imported from a keytab, derived from
  the service account's password with the Active Directory salt rules, or generated; several key
  versions live side by side so a password change gives the old key a ten-hour grace before it is
  retired. Tickets are accepted by a managed SPNEGO acceptor (Kerberos.NET) that picks the key by the
  ticket's realm before decrypting anything, so a valid ticket from one tenant's forest is refused for
  another tenant's CA, a realm can be bound to only one tenant, and no forest trust and no keytab on
  disk are needed. NTLM is never accepted. The response carries the mutual-authentication token
  Windows checks. `GET /msae/{caLabel}/whoami` answers the handshake and reports the accepted
  principal or the refusal, with the diagnostic detail, for troubleshooting from any domain member.
- **Identity-built subjects.** A Kerberos caller's certificate is named from the ticket, not from the
  request: `CN=host.dns.domain` with a matching DNS name for machines, the UPN for users. Templates
  offered to Windows advertise CA-built subjects and autoenrollment, so the client never asks for a
  subject and Group Policy enrolls without a prompt.
- **Service identities.** Permission-only accounts that can never sign in, scoped to the system, a
  tenant or a CA, with their own tab under Users; the natural enrollment identity for a forest.
- **Template extension, renewal, pending.** Issued certificates carry the Certificate Template
  Information extension so a client can match a certificate to its template; without it every
  autoenrollment pulse re-enrolled. A renewal (a CMC request signed by the certificate it renews) is
  issued only when that certificate is ours, unrevoked, unexpired and of the same template, keeps its
  subject, links to the old certificate and audits as Renew. An approval-gated request profile no
  longer faults a Windows client: the request waits in the approval queue, the client is told Taken
  Under Submission, and it collects the certificate by status query once an operator issues it.
- **Template OIDs Windows can read.** Windows parses an OID arc into a signed 64-bit integer and
  silently drops a template with a larger one; the earlier generated form (`2.25.{template id as one
  integer}`) hit that for about half of all templates. Generated OIDs now spread the id over four
  31-bit arcs under a base arc set by `Msae:TemplateOidArc` (normally the operator's Private
  Enterprise Number arc); a startup repair moves generated OIDs under that arc once it is
  configured, and validation refuses unreadable OIDs from anyone.
- **Readiness and setup kit.** `GET /api/v1/admin/msae/{caId}/readiness` evaluates every
  precondition in dependency order with a fix link per failing step, including the naming rule that
  cost a week in the lab: the service principal must name the CA's public hostname and that name must
  be canonical, or the client asks its KDC for a different name and falls back to NTLM. A Windows
  Autoenrollment page under CA Management renders it as a checklist with the policy server URL and
  policy id a client needs, and offers a downloadable setup kit per forest: the service-account
  script, a Group Policy push, the tenant root, a client self-check and a readme. The MSAE audit tab
  explains every refusal in plain sentences with the fix. Lab scripts for a Samba forest and a Windows
  client live under `scripts/lab/samba-ad`.

### Console

- **One console.** The self-service portal joins the console bundle behind one sign-in at the site
  root. The console is driven by the session's capabilities and a scope, tenant first then CA
  within it, that reaches every page listing per-CA data; a link that changes the scope says so and
  offers to return. Access badges let a session wear a named subset of its own rights, with a
  persistent banner while worn. A top bar carries site search with results grouped by page.
- **Tables and records.** Tables take their query from the URL with server-side sort and paging,
  saved views, column show and hide, CSV export and bulk selection. Every entity has one record
  descriptor rendered by one drawer.
- **Usability pass.** Visible helper text (`FieldHint`, `InfoTip`) wherever a value's meaning or
  consequence is not obvious: ceilings that mean unrestricted when empty, profile inheritance pairs
  validated together, ISO 8601 durations with a live reading, revocation reasons explained in every
  picker, SSH principals and extensions, the quorum's excluded initiator, every non-obvious
  setting on the Settings page with human labels and cross-field validation for the password policy.
  Confirmations before every irreversible action that lacked one, including the console's own TLS
  reissue with a warning when the connected hostname is missing. Failed loads now say they failed
  instead of impersonating empty data, and the error shown in the page carries the same title,
  remediation and copyable code the toast does. Certificate Hold can be lifted. The toggle switch is
  keyboard-reachable and the confirm dialog has dialog semantics, Escape and focus handling.

### Authorization

- **Tenant administrators create org CAs and run their tenant's ceremonies.** A class-level
  CA-scoped policy failed closed on every mutation whose target CA is named in the body rather than
  the route, so a tenant administrator could not create a CA or approve a ceremony without system
  rights. Controllers now check the CA or tenant they act on, and body-targeted mutations resolve
  their target explicitly. Creating a group requires step-up like creating a user or a role.

### Issuance

- A request can ask for extensions beyond what its profiles produce (used by MSAE for the template
  extension); the builder refuses any OID the profiles govern. The issuance response returns the
  serial. A validity window shorter than a minute from the moment of issuance is refused. An approver
  can reject or cancel a request that is awaiting approval.

### Enrollment protocols

- **Windows autoenrollment, first step.** A Certificate Enrollment Web Service endpoint
  (MS-WSTEP over HTTPS) at `/api/v1/msae/{caLabel}/ces` answers a `RequestSecurityToken` with
  the issued certificate and chain. Callers authenticate with a WS-Security UsernameToken or HTTP
  Basic through the same credential service as EST, and must hold the enrollment capability on
  the CA. The template a client names in its CSR selects a ModularCA certificate template; a
  request naming none uses the CA's MSAE protocol configuration, which is enabled per CA on the
  protocol configuration page. The policy service (MS-XCEP), Kerberos authentication, renewal
  and pending requests are still to come.
- **Windows autoenrollment, policy service.** A Certificate Enrollment Policy Web Service
  endpoint (MS-XCEP) at `/api/v1/msae/{caLabel}/cep` answers `GetPolicies` with the templates the
  CA offers to Windows clients, each with its OID and version, key size, validity, and the key
  usage, extended key usage and template-information extensions the certificate will carry, plus
  the CA certificate and the enrollment URL. Certificate templates gain "offer to Windows" with a
  template OID (generated under the UUID arc, or supplied to keep an AD CS template's OID), a
  version, and a computer or user flag; the templates page is back in the navigation. A CSR
  that names a template by OID, as a client that fetched policy does, is issued from that
  template. Elliptic-curve templates are not offered yet; subjects are enrollee-supplied until
  Kerberos authentication arrives.
- The enrollment service accepts the CMC request the Windows autoenrollment engine, the
  Certificates snap-in and `Get-Certificate` send (a PKCS#10 wrapped in a signed PKIData as a
  `#PKCS7` token), verifying the wrapper is signed by the key being certified; `certreq -submit`
  keeps sending a bare PKCS#10 and keeps working. Templates are advertised as schema-3 (CNG)
  templates naming SHA-256 and RSA, so a Windows client signs its request with SHA-256 rather
  than the SHA-1 it defaults to for older template schemas, which the certificate profiles refuse.
- A `ProtocolCleanup` scheduled job removes the enrollment request rows a failed protocol
  issuance leaves behind, for every protocol, once they are older than a grace window
  (`ProtocolCleanup.OrphanRequestGraceMinutes`, default 60), leaving operator uploads,
  approval-gated requests and ACME-referenced rows alone. It also takes over the SCEP and CMP
  transaction sweeps, which the ACME cleanup job had been skipping whenever ACME itself had
  nothing to do.
- An instance bootstrapped by an earlier version gains feature flags this version introduces at
  startup, disabled, so the settings page can offer them; an upgrade never switches a protocol on.
- MSAE is wired through the same surfaces as the other enrollment protocols: an `MSAE.Enabled`
  feature flag (setup wizard and `bootstrap.yaml`, off by default) gating the paths, per-CA
  protocol rows seeded at CA creation, its own audit table and tab (`AuditMsae`, with the
  template the client named), IP whitelisting, rate limiting and the login-attempt budget for
  HTTP Basic, the public portal's endpoint listing, and the API documentation.

## [0.1.0] — 2026-09-14

First public release. ModularCA is a modular private certificate authority: a .NET 10 backend
with ACME, EST, CMP, SCEP, OCSP and TSA, and browser front ends for administration,
self-service, public enrollment, setup and documentation.

### Enrollment protocols

- **EST (RFC 7030)** works end to end: anonymous `/cacerts` at both the direct and the
  `.well-known/est/` path, HTTP Basic authentication through a named scheme that shares the
  interactive login's lockout and audit, and mutual-TLS enrollment on a dedicated SNI subdomain
  that requests a client certificate without requiring one so the bootstrap step still answers.
  A presented certificate is chain-validated against the CA it enrolls against, its issuer checked
  as the direct issuer with a client-authentication EKU, and the anchor set is refreshed at
  runtime.
- **CMP (RFC 4210)** works for PBMAC shared-secret enrollment and signature-protected requests.
  Each CA can hold a dedicated CMP message-signing certificate — issued beside its OCSP responder
  and TSA signer — so signature-protected responses verify in standards-based clients; a request
  is bound to the names its signer already holds.
- The admin enrollment page is a single form: choose a protocol (QR page, EST, SCEP, or a CMP
  shared-secret credential) and the fields and result follow the choice.

### Security

- Remediation of a whole-codebase security review: all High findings and the great majority of
  Medium findings across authentication, TLS trust boundaries, the enrollment protocols,
  configuration defaults, input handling and the front ends. Notable fixes include the IP
  whitelist failing closed on a cold snapshot, the setup wizard requiring a token on a
  configured-but-empty instance, SSH `force-command` argument handling, credential changes ending
  sessions, per-tenant scoping of user listings, and enforcement of per-CA ACME and CMP policy
  settings that were previously stored but never read.
- Certificate content for Windows endpoints — client-authentication, smartcard-logon and KDC
  extended key usages, and UPN `otherName` SANs — is issued and displayed correctly.

### Known limitations

- Active Directory Group Policy autoenrollment is not yet supported; it is the next line of work.
- Enrollment tokens and CMP shared secrets are stored in a recoverable form, and the SPA holds
  its session tokens in browser storage. Both are tracked for a later release.

[0.1.0]: https://github.com/Dilenex/ModularCA/releases/tag/0.1.0
