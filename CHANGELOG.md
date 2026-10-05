# Changelog

All notable changes to ModularCA are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning: a new capability is a minor release, a fix is a patch.

## [Unreleased]

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
  fails the build if that changes. A key signs only for its own CA and space and only for the
  purposes its kind allows; every decision is recorded in the signer's own audit table with the
  ceremony it ran under and, over the wire, the peer that asked. `--role signer` runs the keystore
  behind gRPC with mutual TLS, pinned both ways from a dedicated identity CA the signer creates
  (`--init-identity`, `--issue-node-identity`), failing closed when it cannot record a decision; a
  node with `Signer.Mode: Remote` holds no key material and needs no keystore password. A space
  that requires ceremonies gets no key without an approved, unexpired one; a CA's OCSP, timestamp
  and CMP signer keys are reissued under an infrastructure context that can never mint a CA key.
  The default single process is unchanged.
- **Roles.** Every controller and scheduled job belongs to one role: enrollment (the protocols),
  validation (CRL, OCSP, AIA, CA certificates), control (console, admin, users, ceremonies,
  backups) and ingress. `--role` or `Roles:` in the configuration selects any subset; a process
  hosts only its roles' endpoints and jobs, and `/health/ready` reports what each active role
  needs. The deploy readme describes the three-process layout.
- **Ingress.** `--role ingress` terminates TLS with the instance's certificate and routes by
  hostname to nodes with YARP, on plain HTTP as well so revocation URLs reach their node. Routes
  come from `Ingress.Routes`; a name with no upstream is served locally, which is how a single
  process keeps working. Upstreams are trusted by a pinned key or a shared CA; a node that fails
  its health checks answers 503 for its names.

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
