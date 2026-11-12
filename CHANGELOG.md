# Changelog

All notable changes to ModularCA are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning: a new capability is a minor release, a fix is a patch.

## [Unreleased]

Nothing yet.

## [0.4.4] — 2026-11-11

A release of fixes and tightening since 0.4.3, from a security pass, more of the November bug
hunt and five days of test builds on a live install. Who may issue, approve and administer users
now follows the roles held on a CA or a space, and a CA's operator group is a protected tier. An
account's sessions end on every credential change, the first administrator is never handed over
through the log, a restore keeps the audit history, and a separate signer and the bootstrap
deliver their own audit records. The enrolment protocols record what they refused, the console
follows the scope switcher on every page, and a listener can require the PROXY protocol. It is
built on the .NET 10.0.15 runtime, which fixes GHSA-vmv3-wvjp-wqpj, and adds four migrations.

Seven test builds went to test hosts and were not published: `0.4.4-dev.1.0` to `0.4.4-dev.1.4`,
`0.4.4-rc.1.0` and `0.4.4-rc.1.1`. They are listed at the end of this section, with what came
after the last of them.

### Upgrading from 0.4.3

This is the checklist; "Every change that can need attention" under it says more.
"Upgrading to 0.4.4" in `packaging/README-DEPLOY.md` has the same steps for a host.

**Before installing**

- **Take a backup.** The release adds four migrations: `UserPasswordSource`, `UserClaimTokens`,
  `DropUnreadSettingColumns` and `OperatorRoleUsesProfiles`. The third drops two columns that
  nothing read, so going back to 0.4.3 means restoring the backup.
- **Run the upgrade check with the new build, as the service account, and read what it prints**,
  not only its last line: `sudo -u modularca <new build>/ModularCA.API --upgrade-check
  --config-dir /opt/modularca/config`. Its notes name what on this instance the release
  changes, such as enrolment clients whose next request would be refused. `install.sh` runs the
  same check and stops on a refusal. With `--read-only` it can run beside the serving node.
- **Review who holds the Operator and Administrator roles on a CA or a space.** From this
  release those roles approve and issue with the profiles of their scope, and a scoped
  administrator administers the users of its scope. An operator no longer creates accounts.
- **Instances that provision CA operators:** adding a member to a CA's operator group now needs a
  second person, and an LDAP group mapping no longer adds members to it.
- **The backup directory** must be reachable by the service account alone.
- **Split installs:** upgrade the signer with the node. **Pods:** the signer has its own
  configuration volume.
- **The runtime comes with the release.** The tarball and the image carry .NET 10.0.15 inside
  them; installing this release is how a host gets it. Updating the host's packages does not.

**After the first start**

- `ModularCA.API.runtimeconfig.json` in the install directory names 10.0.15, and `logs/` holds a
  file for today: a systemd install of an earlier release may have written none.
- **Sessions end more often.** Logging out, removing a security key or the authenticator app,
  and a replayed refresh token each sign the account out on every device.
- **Enrolment clients and anything that reads the audit tabs.** SCEP's GetCACaps answers 400 or
  409 where SCEP is not served. CMP audit rows are named after the request (`IR`, `CR`, `KUR`),
  and an EST re-enrolment writes `SimpleReenroll`. An ACME client can change its account key.
- **Scripts on the infrastructure API:** a certificate outside the key's scope answers 404, and
  revoking a certificate on hold revokes it for good.
- **A step-up TOTP code** is accepted when the clocks differ by up to 15 seconds.

**Every change that can need attention**

- **Making someone an operator of a CA now needs a second person.** A CA's operator group is a
  protected tier, as its administrator group and a space's operator group already are. An account
  cannot be created straight into it; adding a member opens a ceremony that someone who outranks
  the tier approves (another administrator of that CA, an administrator of its space, or a system
  administrator); a change to an operator's password or state by anyone but a system-super opens
  one too; and whoever reset an account's password or MFA in the last 30 days cannot open its
  promotion. Three things to check before upgrading:
  - **LDAP group mappings to a CA's operator group stop adding members.** The directory cannot
    place anyone in a protected tier. Members already there stay. Map the directory group to the
    CA's requesters or auditors and promote by ceremony, or have a system-super add them.
  - **A system administrator who is not a system-super** no longer adds a CA operator directly:
    it opens the ceremony like anyone else.
  - **A CA with one administrator and nobody above it who will approve** cannot gain an operator
    until a system-super adds one.
- **Operators can now approve and issue too.** The built-in Operator role gains `profile.use`
  (the `OperatorRoleUsesProfiles` migration adds it to the role and to every group made from the
  Operator template). With the entry below, an operator of a CA or a space approves requests and
  issues with that scope's profiles, where before the role's `cert.approve` could approve
  nothing. Review who holds the Operator role before upgrading. To keep an operator from
  issuing, give it a custom role without `profile.use`.
- **CA and space administrators can now issue with the profiles of their own scope.** Until now
  only a system administrator could issue or approve a certificate through the admin routes, or
  see any certificate, signing or request profile in the console, unless someone had granted
  each profile to an account or role by name. The built-in roles' own profile capabilities were
  not counted. They are now, at the scope they are held: see "Profile capabilities from a role
  count" under Security. Review who holds the Administrator role on a CA or a space before
  upgrading; from this release that role issues.
- **Administrators of a CA or a space gain user administration within their scope; operators lose
  what they had of it.** From this release the Administrator role on a CA or a space can create
  accounts, change the memberships of its own groups, and reset the password of, update, disable
  and delete accounts that hold nothing outside its scope: see "Administrators of a CA or a space
  can administer the users of their own scope" under Security. Review who holds that role. The
  Operator role, at any scope, can no longer create an account, and a system operator can no
  longer reset an account's MFA: both now need `user.manage`, which the Operator role does not
  carry. Resetting MFA stays with system administrators. A script that called these routes as an
  operator must use an administrator's account. The console's Users page is still shown only to
  holders of `user.manage` at system scope; a scoped administrator reaches these routes through
  the API for now.
- **The container image declares no volumes.** A container started from the bare image with no
  mounts (`docker run` or `podman run` and nothing else) used to get an anonymous volume for
  `config`, `keystores`, `logs` and `backups`; now those directories are in the container's own
  layer and go when the container is removed. Name every mount, as `compose.yaml` and
  `modularca-pod.yaml` do; nothing changes for either. In the pod this means the signer no longer
  gets a writable `config` directory, nor the node a `keystores` directory. An orchestrator that
  passed `--image-volume=ignore` to avoid them can drop it.

- **The headless bootstrap no longer prints the first administrator's password.** It is written to
  `config/initial-admin-password`, readable by the service account only, and the bootstrap prints
  the file's path; read it there instead of in the journal or `podman logs`. Scripts that scraped
  the password from the bootstrap's output must read the file. Installs that are already
  bootstrapped are not affected. The setup wizard is unchanged.
- **With LDAP sign-in on, a password the directory refuses is final.** A stale local password no
  longer signs in an account the directory refused, disabled or expired, and while the directory
  cannot be reached password sign-in is refused, except for accounts whose password source is
  Local (WebAuthn and client certificates still work).
- **Every account gets a password source** (the `UserPasswordSource` migration). Existing accounts
  start as Inherit, which signs in as before. The bootstrap administrator of an existing install
  is not changed: to keep a break-glass account that works through an LDAP outage, another
  administrator opens it under Users, chooses Edit and sets Password source to Local; on a
  single-administrator install, run `ModularCA.API --set-password-source <username> Local` on the
  host as the service user.
- **A certificate profile with no EKUs is refused under a signing profile that restricts them**,
  for leaf certificates. Give such profiles the usages they are meant for. Windows autoenrollment
  leaves such a template out of its policy, with a warning in the log.
- **A browser clock more than a minute fast** fails token refresh on proof-of-possession sessions;
  the allowance was five minutes either way.
- **The mTLS RequiredPaths gate refuses a certificate from this instance's CAs that it has no
  record of**, and every certificate from a CA that is revoked, held, disabled or deleted.
- **A scoped integration API key no longer lists signing profiles that have no issuer**; issuing
  with one was already refused.
- **Issuance for a CA with a certificate quota runs one at a time**, so the quota holds under
  concurrency; CAs without a quota are unaffected.
- **A restore keeps the audit database.** To rebuild a host from a backup, which has no audit
  history of its own, add `--restore-audit` (on the console, tick *Also replace the audit history
  with the backup's*); "Restoring onto a new host" in the deploy guide now says so.
- **The HTTP to HTTPS redirect follows `Https.PublicPort`, else the HTTPS listener port**, like
  every other HTTPS link. With a public domain and no `PublicPort` it now goes to the listener port
  rather than 443; set `PublicPort` if a proxy publishes HTTPS on another port.
- **Profile inheritance holds through every ancestor**, so a profile two or more levels down can
  come out stricter than before, and issuance or the CA infrastructure-profile checks may refuse
  what they used to accept. Check deep profile chains after upgrading.
- **An HSM CA whose key does not match its certificate is not loaded.** The signer now compares
  the token's public key with the CA certificate at startup and refuses a duplicated label; such a
  CA logs `[HSM] ERROR` and every signing request for it is refused.
- **The keystore scrypt cost is validated, not clamped.** A non-power-of-two `KeystoreScryptN`, an
  out-of-range r or p, or a new cost above 1 GiB per derivation is refused with 400. A
  non-power-of-two N stored before this, which already broke every keystore write, now fails them
  with a message naming the setting; a cost above 1 GiB saved before this keeps working, with a
  warning.
- **The infrastructure API's renew answers 404 for a certificate outside the key's scope**, where
  it answered 403, or 400/409 for a revoked or retired one.
- **The OCSP "Sign Responses" setting is gone.** It was stored and never read: OCSP responses are
  always signed. Protocol Configuration no longer shows it, the protocol configuration API no
  longer returns `ocspSignResponses`, and a request that still sends it is accepted and the field
  ignored. Nothing changes for OCSP clients.
- **Notification preferences no longer have a "days before expiry".** No notification ever read
  it: when the certificate expiry email goes out follows each certificate's expiry warning and the
  reminder days under Settings, and no password expiry email is sent yet. The notification page no
  longer shows or edits it, `GET` and `PUT /api/v1/admin/notifications` no longer return
  `daysBeforeExpiry`, a `PUT` that still sends it is accepted and the field ignored, and new
  installs no longer seed it.
- **The `DropUnreadSettingColumns` migration drops `CaProtocolConfigs.OcspSignResponses` and
  `NotificationPreferences.DaysBeforeExpiry`**, the two settings above, which nothing read. The
  values they held are lost, which changes nothing. Anything outside ModularCA that queries those
  columns directly (a report, a hand-written SQL check) must stop naming them before the upgrade.
- **A CT log needs its public key for its SCTs to be kept.** SCTs are now verified against the
  log's configured key, and an SCT from a log with no key, or one that does not verify, is
  discarded (with a warning naming the log), so the certificate health check reports such
  certificates as having no SCTs. Give each CT log the base64 SubjectPublicKeyInfo its operator
  publishes, through `PUT /api/v1/admin/ct-logs/{id}`.
- **The infrastructure API's certificate read and revoke answer 404 for a certificate outside the
  key's scope**, where they answered 403.
- **Revoking a certificate on hold from the infrastructure API revokes it permanently.** A
  `DELETE` of a held certificate, Terraform's destroy included, used to leave it on hold; it now
  revokes it with the reason given (unspecified when none is).
- **The pod's signer has its own configuration volume.** Before starting a pod from the new
  `deploy/container/modularca-pod.yaml`, create an empty `modularca-signer-config` volume (claim
  `modularca-signer-config` on Kubernetes). The first start copies the signer's settings and
  identity into it and reissues nothing, and then removes from the node's `config` volume what
  the signer now holds, after checking each copy: `keystore.yaml`, `signer-server.pfx`,
  `signer-identity-ca.pfx`, and the signer's half of `Signer:` and `Hsm:` in `config.yaml` and in
  the `config.yaml.*.bak` copies beside it, which are kept but scrubbed (a file that does not
  check out is left, with a warning in the log). **After that the keystore
  passphrases are only in `modularca-signer-config`, so that volume MUST be in your volume
  backups**; backup archives have never carried them. Afterwards read `signer.yaml` there once
  (it was copied from a file the node could write: check `Hsm.ModulePath`,
  `Signer.PinnedClientSpki`, `Signer.Listen`) and make further changes to the signer's settings
  there. "The pod" in the deploy guide has the details. The manifest names the 0.4.4 image: the
  0.4.3 image cannot run it.
- **The backup directory must be reachable by the service account alone.** A backup, the console's
  and the scheduled one included, and a restore's pre-restore snapshot now restrict the backup
  directory (`backups/`, or `Backup.OutputPath`) to the service account when other users can
  reach it, and say so (`🔒 ... is now restricted to this account`). That changes an upgraded
  install whose `backups/` was readable by its group or by everyone (the container image created
  it 0750): it becomes 0700, or on Windows loses the permissions it inherited. Anything that read
  archives there through the group, a backup agent say, must run as the service account or copy
  them out another way. When the directory cannot be restricted (it belongs to another account),
  or it is not the backups' own (`Backup.OutputPath` set to the application directory, or an
  explicit output path in another directory), the backup or the restore is refused with what to
  do; make the service account the directory's owner and `chmod 700` it, or point
  `Backup.OutputPath` at a directory of its own. The same goes for `config/dp-keys` and the SSH CA
  key directories a restore unpacks at the next start: one other users can reach is restricted,
  and one that cannot be is left pending, with the reason in the log, instead of written into.
- **Removing a security key (a WebAuthn credential or passkey) signs the account out everywhere.**
  Removing one on My Security now ends every session of the account, the one that removed it
  included, as revoking a client certificate there already did: the confirmation says so, and the
  browser goes back to the sign-in page. Scripts that call
  `DELETE /api/v1/auth/webauthn/credentials/{id}` must sign in again afterwards; the access token
  and the refresh token they hold stop working.
- **Removing the authenticator app (TOTP) signs the account out everywhere**, in the same way:
  My Security now asks first and says so, and a script that calls `DELETE /api/v1/auth/totp` must
  sign in again afterwards.
- **Logging out signs the account out on every device at once.** Logout already revoked every
  refresh token of the account, so other devices could not renew; their access tokens kept working
  until they ran out. They now stop on their next request, with 401. An integration that shares
  one account between several clients and calls `POST /api/v1/auth/logout` from one of them signs
  the others out immediately; give each its own account, or do not log out.
- **Split installs: upgrade the signer with the node, and expect the signer's past keystore events
  in the audit trail.** A signer in its own directory (`--signer-dir`: the pod, and "Two units")
  now keeps its keystore events in `signer/audit-journal/` and the node reads them over a new
  read-only call on the signer channel. Nothing needs configuring: `signer/` is already the
  signer's to write (the unit's `ReadWritePaths`, the pod's `modularca-signer-config` volume). At
  its first start on this version the signer moves the `bootstrap-audit-*.jsonl` files an earlier
  build left in `signer/logs/` into the journal, so on a two-unit install the node then records
  every keystore event since the split, each as a `Keystore…` audit row by `system-signer`, dated
  when it is recorded and carrying the event's own time in its details. A node upgraded before its
  signer records nothing until the signer is upgraded (the old signer has no such call) and loses
  nothing. The node keeps `config/signer-audit-cursor.json`; back up `signer/audit-journal/` with
  the rest of the signer's directory.
- **New audit rows to expect, and one new actor.** Rows the node writes from a separate signer's
  journal are by `system-signer` (marked `DeliveredBySigner`); rows replayed from
  `logs/bootstrap-audit-*.jsonl` stay by `system-bootstrap`. A filter or SIEM rule that looks for
  the signer's keystore events should match `system-signer`. A test build of this version that
  already delivered signer events wrote them as `system-bootstrap`: those rows stay as they are
  and are not written again. There is a new action, `KeystoreUnlockFailed` (a keystore that could
  not be decrypted at unlock), worth an alert. `BackupCreated` and `BackupRestored` rows by
  `system-signer` record a command-line backup or restore run on the signer. On a single-process
  install the `Keystore…` rows of a running node now appear within a second or so of the event
  instead of at the next start.

**Security**

- **Built on the .NET 10.0.15 runtime.** The tarball and image carry the .NET runtime inside
  them. 10.0.14 and earlier are affected by GHSA-vmv3-wvjp-wqpj (CVE-2026-118747), published on
  2026-11-10: colliding map keys in CBOR input make `System.Formats.Cbor` spend a great deal of
  time checking them for uniqueness, a denial of service. The product reads CBOR in its FIDO2
  (passkey and security key) code. Every earlier build, `0.4.3` and `0.4.4-rc.1.0` included,
  carries 10.0.14 or older; the fix is to install this build, since the runtime is not the
  host's. The Microsoft .NET packages move from 10.0.14 to 10.0.15 with it, and
  `System.Formats.Cbor` is pinned to 10.0.15 where a dependency asked for 9.0.0.
- **An administrator of a CA can no longer make its own second approver.** With this release an
  operator of a CA approves and issues that CA's requests, and an administrator of a CA creates
  accounts and changes memberships in its own scope. The CA's operator group was the one such
  group that was not a protected tier, so one administrator could create an operator account
  with a password of its choosing, sign in as it and approve its own certificate request: the
  rule that nobody approves their own request, defeated by one person. Found on the test install
  of 0.4.4-dev.1.2, where all three steps went through. A CA's operator group is now the
  `CaOperator` tier: see the upgrade notes for what that changes. No stored data changes; the
  tier is worked out from the group and its capabilities, including `ca.manage` held on one CA
  through a direct grant or a role.
- **Administrators of a CA or a space can administer the users of their own scope, and of no
  other.** The user-administration routes (`PUT` and `DELETE /api/v1/admin/users/{id}`,
  `reset-password`, and the three group-membership routes) asked for `ca.manage` on a CA that a
  route carrying only a user id can never name, so the server refused them to everyone but a
  system administrator: an administrator of a CA or a space could not reset a password, disable
  an account or change the members of its own groups. That refusal was a containment, since
  without it an administrator of one small CA could have reset the password of a system
  administrator. The routes now ask for `user.manage` (account changes) or `group.manage`
  (memberships) at some scope, and decide against the account itself:
  - An account the caller cannot see, by the rule the user list applies, answers 404 exactly as
    an id that names nothing.
  - Updating, disabling, deleting or resetting the password of an account needs `user.manage` on
    every CA and space the account holds anything in: a group membership, a capability grant, a
    role, access to a single certificate, an SSH login name. One holding outside the caller's
    scope, anything held at instance scope (a system group included), or no holding at all, and
    only a system administrator may change the account. The caller's own account follows the same
    rule.
  - A membership needs `group.manage` on the group's own CA or space, never on another one, and
    nobody changes their own.
  - An account in no group belongs to no scope, so only a system administrator can see, place or
    change one. An administrator below system scope therefore cannot make one: it must name at
    least one group it manages when it creates an account (400 otherwise), and it may not remove
    the last thing an account holds (409). Taking someone out for good is a delete or a disable;
    moving them is an add to the new group first, then the removal. That includes demoting an
    administrator whose only group is the administrators: add them to another group first.
  - The controlled-tier rules apply as they did for system administrators: a change to an account
    that holds an administrator tier opens a ceremony instead of applying, adding someone to such
    a group opens one too, and whoever reset an account's password or MFA in the last 30 days
    cannot open its promotion. A ceremony opened below system scope expires at execute when the
    account has since been given something outside the scopes it was in.

  Two routes became stricter. Resetting an account's MFA needs `user.manage` at system scope
  (it asked for `ca.manage` there): together with a password reset it is a complete takeover, so
  an administrator of a CA or a space does not get both, and a system operator can no longer
  reset MFA. Creating an account needs `user.manage` (it asked for `ca.manage` on any CA), so an
  operator can no longer create one. Deleting an account now makes the same checks against the
  account as the other changes do. The rule that a CA-scoped permission is
  refused on a write whose route names no CA is unchanged; these routes have a gate of their own.
- **Profile capabilities from a role count, at the scope the role is held.** Using a profile to
  issue or approve asks for `profile.use` on the signing profile and the certificate profile;
  the profile lists show a profile to a holder of any `profile.*` capability on it. Both counted
  only grants that named a profile or the profile type, and ignored the unrestricted
  capabilities the built-in roles carry, so the Administrator role's `profile.use` gave nothing
  and every scoped administrator, operator and auditor (and the system auditor) saw empty
  profile lists. An unrestricted capability now covers:
  - a signing or request profile of a CA, when it is held on that CA, across the CA's space or
    at system scope;
  - a certificate profile bound to a CA or a space, when it is held on that CA or in that space;
  - a profile bound to neither, when it is held anywhere. Its use is still confined by the
    signing profile of the same request, which names its CA.

  It never reaches another CA or another space, and a signing profile whose issuer is no CA is
  covered only at system scope. What changes in practice: **the Administrator and Operator roles
  issue and approve within their CA or space**, where before only a system administrator could
  (the Operator role gains `profile.use` in this release; see the upgrade notes); the Auditor
  role sees the profiles of its scope but cannot use them, because it carries no `profile.use`;
  a requester sees and uses nothing more. Grants that name
  one profile work as before. Found on the first test install of 0.4.4-dev.1.0.
- **A requester can no longer read the users and groups of its space.** The user list, the three
  user lookups and the group list and lookups under `/api/v1/admin` asked for `cert.view`, which
  the Requester role holds so that it can see certificates. Any requester could therefore read
  every account of its space with its e-mail address, last sign-in, lock state and memberships,
  and every group. They now ask for `group.view` (policy `CaDirectoryViewer`), which the Auditor,
  Operator and Administrator roles hold and Requester does not; what each caller sees is still
  limited to its spaces. A custom role that should read the directory needs `group.view`. Found
  on the first test install of 0.4.4-dev.1.0.
- **A replayed refresh token ends every session of the account.** A refresh token that was already
  exchanged for a new one and is presented again is the sign that it was copied. The server
  already revoked that session's refresh tokens; an access token issued to the other holder kept
  working until it expired, up to the access-token lifetime. Now the account's security stamp
  rotates and every refresh token is revoked, so every access token is refused on its next
  request and the account signs in again on each device. A stale token from before a logout or a
  credential change was never exchanged, and presenting it ends nothing more. The console
  serialises refreshes across tabs, so it does not trip this itself; an API client that sends
  one refresh token twice (a retry after a lost answer) now signs the account out everywhere.
- **A separate signer's keystore events reach the audit trail.** With the signer apart from the
  node (the pod's signer container, or the two units), every keystore event the signer raised
  (keystores loaded at each start, `ssh-ca.keystore` created, a key appended for a new CA or SSH CA
  key, a file signature or pin that did not verify) was written to the signer's own `logs/`, which
  nothing read: none of them ever reached the audit trail, and in the pod they were discarded
  with the `emptyDir` at each restart. The signer cannot write the audit database (its `db.yaml`
  holds the application database only, and it keeps that). It now records those events in a
  journal in its own directory, `audit-journal/`, outside `logs/` and in the pod's persistent
  `modularca-signer-config` volume, and the node's control role reads the journal over the
  mutual-TLS signer channel (`ReadKeystoreEvents`, at start and every minute) and writes each
  event through the audit service onto the hash chain. Events wait on the signer while the node,
  the signer or the audit database is away and are recorded afterwards in the journal's order;
  each carries a `BootstrapEntryId` derived from its place and text, so a second delivery adds no
  row; the node moves on only past events it finds in the audit database. The call reads and
  nothing else: there is no call that removes, acknowledges or rewrites an event, the position
  is the node's own note, and a node that has been taken over can withhold events from the trail
  but cannot erase them from the signer. What crosses the wire is rebuilt by the signer from the
  six fields a keystore event has, so nothing else a line might hold leaves it, and no event
  carries a passphrase, a PIN or key material. The rows are written by `system-signer` and marked
  `DeliveredBySigner`, so they can be told from the node's own. A single-process install keeps
  its keystore events in `logs/bootstrap-audit-*.jsonl` (see the entry on recording them when
  they happen, below). The signer gains no database right and no credential.
- **A keystore unlock that fails to decrypt is in the audit trail.** Only verification failures
  were recorded (`KeystoreSignatureFailed`, `KeystorePinMacFailed`). A secondary passphrase that
  did not unwrap the keystore's main passphrase, a main passphrase that opened no entry, or a
  keystore file, wrapped passphrase or `keystore.yaml` too damaged to read left nothing behind
  but a console line. Each is now a `KeystoreUnlockFailed` event for the keystore concerned,
  recorded as a failure: in the journal of a separate signer, from where the node writes it by
  `system-signer`, and in `logs/bootstrap-audit-*.jsonl` on a single process, replayed by
  `system-bootstrap`. The event names the keystore and the kind of failure (the exception's type)
  and nothing else: no passphrase, nothing derived from one and no exception message is written
  to the event, the journal, the log or the console. A missing `keystore.yaml` or an unreachable
  database is not recorded as a failed unlock, since nothing was tried against the keystore.
- **The signer's command-line backup and restore leave a record.** On a split install `--backup`
  and `--restore` are run as the signer's account with `--role signer --signer-dir <dir>`. They
  are a process beside the signer and reached neither the audit database nor the journal: the
  keystore events they raised went to a `logs/` nothing reads, and the run itself was recorded
  nowhere. Both now write to `<dir>/audit-journal/`: the keystore events of the run (the keystores
  loaded for a backup, an unlock that failed) and one `BackupCreated` or `BackupRestored` event
  with the exit code and the archive's file name, as a failure when the exit code is not 0 or the
  run was stopped by an exception. The node picks them up at its next read of the journal, within
  a minute while it is running, and writes them by `system-signer` as `Backup` rows. The backup
  password, a passphrase, the archive's directory and an exception's message are never part of
  the event. Without `--signer-dir` these commands behave as before.
- **A single process records its keystore events when they happen.** With the signer in process,
  a key appended to a keystore, `ssh-ca.keystore` being created or a keystore that failed to
  verify during an append was written to `logs/bootstrap-audit-*.jsonl` and became an audit row
  only when the node next started, which could be weeks later; until then the trail did not show
  it, and an attacker who removed the file before a restart removed the event. The control role
  now records each line in the audit trail as it is written (`LocalKeystoreEventRecorder`), on
  the hash chain, as the row the replay writes and with the same `BootstrapEntryId`. The file
  stays where it is, and the replay at the next start finds its lines recorded, writes none
  again and renames it as before. If the audit database is away the lines wait in the file and
  are tried again every minute. This needs an audit database; a node without one, and a node
  with a remote signer, are unchanged.

- **Backup archives and an unpacked key ring are only written where other users cannot reach
  them.** The directory a backup archive or pre-restore snapshot went into was left exactly as it
  was when it already existed, and one created new that could not be restricted was only a
  warning; the directory a restore unpacks `config/dp-keys` (the Data Protection key ring, which
  with the database opens every protected column) or SSH CA keys into at the next start only
  warned as well, and the files were written anyway. Each must now be reachable by the service
  account alone: the backups' own directory and the unpack target are restricted when they are
  not, and otherwise the backup, the restore or the unpack is refused with what to do.
- **The first administrator's password no longer lands in the journal.** The headless bootstrap
  printed the generated password to standard output and to `/dev/tty`; under systemd and Podman
  standard output is the journal, so anyone who could read it, and anything it was forwarded to,
  kept a copy. The password now goes to the owner-only file `config/initial-admin-password`, which
  the node deletes when the first sign-in changes that password (a warning is logged if it cannot),
  and the closing banner names the file instead of repeating the password.
- **An instance can be handed to its first administrator without anyone else holding the
  password.** With `Administration.ClaimTokenSha256` in `bootstrap.yaml` (the SHA-256 of a claim
  token; the file never holds the token), `superadmin` is created with no password and a one-time
  claim that expires after `Administration.ClaimTokenLifetimeHours` (seven days by default).
  Whoever holds the token sets the password at the console's **Have a claim token?** page
  (`/claim`, `POST /api/v1/auth/claim`). The token is compared in constant time, works once, and
  every refusal (wrong, expired, used, or an account that cannot be claimed) gets the same answer;
  the endpoint is rate limited like the other anonymous credential endpoints, and a claim is
  audited as `UserAccountClaimed`. The `UserClaimTokens` migration adds the table.
- **The infrastructure API lists only the profiles inside the API key's scope.** The certificate,
  signing and request profile listings returned every profile on the instance, so a key scoped to
  one space could read every other space's profiles; they now return only profiles bound to a CA
  inside the key's scope, plus unbound certificate and request profiles.
- **The infrastructure API's revoke takes a reason by its RFC 5280 name only.** A numeric code, an
  undefined code or a comma list was accepted and stored, so a client could put a reason RFC 5280
  does not define, or a different reason from the one it named, on the CRL and OCSP response;
  these are now refused with 400 (`MCA-REQ-000`).
- **An EAB key binds one ACME account, even under a race.** Two new-account requests presenting the
  same external account binding key at once could both pass the unused check and both get an
  account; the key is now claimed atomically before the account is created, and the request that
  loses is refused with `unauthorized`.
- **A certificate request is issued once, even when two issue calls race.** Two concurrent
  issuances of one approved request, or two reissues of one certificate, each had the signer sign
  a certificate and each stored it. Issuance now locks the request before it checks or signs
  anything, so the second call waits and is refused with 409 (`CsrStateNotEligible`, or
  `AlreadyReissued`) with nothing signed for it.
- **Concurrent issuances no longer overshoot a CA's certificate quota.** For a CA with a quota,
  issuance counts under a per-CA lock held until its certificate is saved, so the second is
  refused with `QuotaExceeded` before it signs.
- **A client certificate whose issuing CA is revoked, held, disabled or deleted no longer signs
  in.** mTLS sign-in, step-up and the MFA-factor checks read only the leaf's own status. Every CA
  up the chain must now be in good standing; a refusal is audited as `mtls_issuer_revoked` or
  `mtls_issuer_disabled`.
- **The mTLS RequiredPaths gate refuses a revoked or held client certificate.** It admitted any
  certificate that chained to a trusted anchor, checking revocation only against the local CRL
  cache. A certificate issued by this instance's CAs must now be on record, not revoked or on
  hold, and under CAs in good standing.
- **Revoking your own mTLS credential revokes its certificate through the revocation service.** My
  Security changed the certificate row directly, so no CRL was regenerated, no notification was
  sent and no revocation audit entry was written. It still signs out every session of the account.
- **A command-line backup stages its files in an unpredictable, owner-only directory, or stops.**
  It staged plaintext dumps and keystores in `/tmp/modularca-backup-<timestamp>`, a name another
  local user could create first, and only warned when it could not restrict it.
- **A refused LDAP bind no longer falls back to the local password.** A password the directory
  refused, or an account it had disabled or expired, could still sign in to the console or EST
  with a stale local password. For an account whose password source is Inherit, the local
  password is used only when the directory has no entry for it; while the directory cannot be
  reached, password sign-in is refused without counting a failed attempt.
- **Each account has a password source that decides whether LDAP or the local password checks
  it.** Inherit follows the instance LDAP setting. Local checks only the local password and never
  asks the directory, so it keeps working through an LDAP outage and in direct-bind mode.
  Directory checks only LDAP and never the local password. A refused bind or a missing entry
  counts as a failed attempt; an unreachable directory, or LDAP sign-in turned off, refuses
  without counting one. The first time the directory accepts an Inherit account's password, the
  account becomes Directory (audited as `UserPasswordSourceLearned`), so deleting its directory
  entry can no longer bring a stale local password back. Administrators see and change the source
  on the user's page, with the same step-up, tier gate and controlled-user ceremony as the user's
  other credential settings; the change is audited as `UserPasswordSourceChanged` and ends the
  user's sessions, and nobody can change their own. A Directory account cannot set a local
  password by self-service, the pre-session change or an admin reset, and is not held to the local
  password's forced-change or expiry flags. A new install creates its first administrator as
  Local. On the host, `--set-password-source <username> <Inherit|Local|Directory>` makes the one
  change the console cannot, an administrator's own: like `--unlock-user` it uses the credentials
  in `db.yaml`, never HTTP, ends the account's sessions and is audited as
  `UserPasswordSourceSetOnHost` by `host:break-glass`.
- **A DPoP proof is single-use for as long as it is valid, and cannot be dated ahead.** A proof
  dated up to five minutes in the future outlived its replay record and could be used again, and
  two simultaneous requests with the same proof could both pass. A proof may now be at most a
  minute ahead of the server clock, its jti is remembered until the proof can no longer be
  accepted, and the jti is claimed in one atomic step (Redis `SET NX` when Redis is configured).
- **Every sign-in path starts the session wearing the user's default access badge.** Only
  password-only sign-in applied it; signing in with TOTP, WebAuthn or a client certificate gave a
  full-strength session.
- **The approval outlook judges other accounts on their own grants and writes no audit rows.** A
  caller wearing a badge saw nobody able to approve, because their badge was applied to everyone
  else, and system administrators outside the CA's groups got false "elevated access" audit rows
  each time the outlook was opened.
- **A leaf certificate with no extended key usages can no longer get around the signing profile's
  allow-list.** A certificate profile that listed no EKUs issued a leaf with no ExtendedKeyUsage
  extension, valid for any purpose, even when the signing profile allowed only certain usages, and
  a signing profile whose allowed EKUs were all misspelled restricted nothing. CA and system
  infrastructure certificates may still carry no EKU.
- **A certificate's maximum validity is measured from its own start date.** It was counted from
  the moment of issuance, so a request with a backdated notBefore could get a certificate that
  lived longer than the profile allows. The maximum now limits notAfter − notBefore, and the
  validity pre-flight on the issue form uses the same rule.
- **An OCSP request that names more than one issuer is refused as unauthorized.** The responder
  answered every entry using the first entry's CA, so an entry for a different CA could get "good"
  or "revoked" signed by a responder with no authority over that certificate.
- **Kerberos authenticators and pending-MFA tokens are accepted once, even under concurrent
  requests across nodes.** The MSAE Kerberos replay cache and the pending-MFA token now claim
  through the atomic replay guard (Redis `SET NX`, or an in-process claim without Redis), as the
  DPoP proof check does; a read-then-write let two concurrent requests both pass.
- **The infrastructure API's renew answers 404 for a certificate outside the key's space before
  reporting its state.** A key scoped to one space could learn whether a certificate in another
  space was revoked or retired.
- **An HSM key is used only when its public key matches the CA certificate.** The signer paired a
  CA with whatever key carried its `HsmKeyLabel`, so a wrong, swapped or duplicated label could
  make a CA sign with a key its certificate does not carry, or with another CA's key. At startup it
  now requires exactly one key under the label and compares its public key with the certificate;
  a CA that fails is not loaded, and every signing request for it is refused and audited with the
  reason.
- **The user portal's authority endpoints serve CA certificates only, and only those the caller
  can see.** `GET /api/v1/user/authorities/{serial}/file` refused every CA certificate and served
  leaf certificates to an instance-wide caller, and `GET /api/v1/user/authorities/{serial}` gave an
  instance-wide caller the details of any certificate. Both now answer 404 for anything but a CA
  certificate inside the caller's spaces.
- **Profile inheritance clamps against every ancestor, not the parent's stored row.** A profile
  whose parent left a field unset, or stored one looser than its own parent allows, could come out
  looser than the grandparent; validity, key and algorithm lists, usages, CT, wildcards, expiry
  warnings and request approval now hold all the way up the chain.
- **Restoring a keystore file waits for any write to it and replaces it in one step.** A restore
  took none of the lock keystore appends take, so the two could interleave, and it moved the live
  file aside before moving the new one in. It now holds the same per-file lock, writes and verifies
  the new file beside the old one, and swaps it in atomically, keeping the previous file as
  `name.bak.<timestamp>`.
- **Bulk revoke on Certificates acts only on certificates listed in the current scope.** Switching
  from one space to another kept the selection made in the first, so bulk revoke could revoke
  certificates the page no longer showed.
- **Protocol Configuration saves the CA it shows.** Switching CA or scope while a load was in
  flight could leave one CA's settings on the form while Save wrote them to another, and a late
  answer for the previous CA could overwrite the form.
- **SCTs from Certificate Transparency logs are verified before they are recorded.** The log's
  public key was stored and never read, so whatever a log URL answered was saved on the
  certificate as an SCT. Each SCT is now checked against the configured key: it must be v1, name
  that key's log id and carry a valid SHA-256 ECDSA or RSA signature over the submitted certificate
  (RFC 6962 section 3.2). One that does not verify is discarded with a warning in the log. The CT
  log API refuses a public key that is not an ECDSA P-256 or RSA (2048 bits or more)
  SubjectPublicKeyInfo in base64 or PEM.
- **TOTP and WebAuthn sign-in and step-up are single-use under concurrency.** The verify
  endpoints read the pending-MFA token, checked the code or assertion and only then removed the
  token, and a TOTP code's replay check was a read of its last used time step, so concurrent
  requests with one token, one code or one signed assertion could each complete and each get a
  session or step-up token. The pending-MFA token is now consumed, and each TOTP time step and
  WebAuthn challenge claimed, through the atomic single-use guard (Redis `SET NX` when Redis is
  configured), so exactly one of them succeeds; a code used to sign in is also refused for step-up
  within its time step.
- **A step-up token is spent once, even when requests race.** The check read the token and only
  then removed it, so two simultaneous requests carrying one `X-MFA-Token` (two revokes, two
  exports, two ceremony approvals) could both pass and both perform the guarded operation. A
  matching token is now claimed through the atomic single-use guard (Redis `SET NX` when Redis is
  configured) before anything is allowed, and only the request that makes the claim goes ahead; a
  token issued for a list of targets is still spent once per target.
- **A restore confirmation token starts one restore, even when requests race.** The token from
  `/preview-restore` was read and then removed, so two simultaneous `POST /api/v1/admin/backup/restore`
  calls carrying it could both pass and run two restores over each other. It is now claimed through
  the atomic single-use guard before the restore begins, and the request that loses is refused as
  an invalid or expired token.
- **The infrastructure API's certificate read and revoke no longer reveal which certificates exist
  outside the key's scope.** `GET` and `DELETE /api/v1/integration/infra/certificates/{serial}`
  answered 403 for a certificate in another space and 404 for one that did not exist, so a key
  scoped to one space could probe every other space's serials. Both now answer 404 with the same
  body, before anything about the certificate is said.
- **A restore stops when it cannot stage the archive where only the service user can read it.**
  The directory a restore extracts the archive into, and the one the pre-restore snapshot stages
  the live keystores in, were created and then restricted to their owner, and a failure to
  restrict them was only a warning, so plaintext CA keys could be staged where other local users
  could read them. Both are now created owner-only from the start under an unpredictable name, as
  the backup's staging directory already was, and the restore stops before extracting anything
  when that fails.
- **In the pod, the node can no longer change what the signer loads.** The signer read its
  settings from the config volume the node mounts read-write, so a node that had been taken over
  could set `Hsm.ModulePath` (a library the signer loads), `Signer.PinnedClientSpki` or
  `Signer.Listen` for the signer's next start. The signer now runs with `--signer-dir` on a volume
  of its own, `modularca-signer-config`, which the node does not mount. A new init container,
  `signer-dir`, fills it once with `--migrate-signer-dir` and never refills it from the node's
  files; `signer-init` creates the identity there; and `--issue-node-identity --apply` with
  `--signer-dir` (refused until now) writes the node's half of the channel into the node's
  `config.yaml` and the signer's pin into `signer.yaml`, checking on later starts that the pins
  match the certificates and reissuing when they do not. `--migrate-signer-dir` exits 0, changing
  nothing, when the directory already holds every file it would write. The image has the
  owner-only `/opt/modularca/signer` the volume is mounted on, and the entrypoint waits for that
  directory's files rather than `config/` for a signer given `--signer-dir`.
- **Behind a proxy that passes TLS through, the node can learn each client's address.** Such a
  proxy (the hub's HAProxy, nginx `stream`) cannot add `X-Forwarded-For`, so the node saw every
  client as the proxy, and under rootless Podman as the host's own LAN address: the audit recorded
  the server, the IP allow-list let in everyone or no one, one client's failed sign-ins locked out
  every user, and JWT IP binding checked nothing. A listener can now require the PROXY protocol
  (version 2, or version 1 as nginx sends it), read before TLS, from the proxies an operator names;
  the header's client address is then the connection's address for all of those. A connection to
  such a listener from any other address, or without a valid header within 5 seconds, is closed
  and never read as TLS or HTTP, so a client cannot choose its address by sending a header itself.
  On those connections `X-Forwarded-For`, `-Proto` and `-Host` are ignored, even from an address
  the forwarded-headers step trusts (loopback always is), so they cannot replace the header's
  address. Listing a passthrough proxy in `Http.TrustedProxyCidrs`, the tempting workaround, would
  have let every client pick its own address; the deploy guide now warns against it.
- **`--unlock-user` ends the account's sessions.** The host command rotated the account's security
  stamp, which stops its access tokens, but left its refresh tokens alone, and token refresh does
  not read the stamp: a refresh token issued before the lock could mint a new session once the
  account was unlocked. The command now revokes every refresh token the account holds, as
  unlocking from the console always has, says so in its output, and records the count in its audit
  entry. Whoever is unlocked signs in again.
- **Removing a WebAuthn credential ends the account's sessions.** A security key or passkey could
  be removed from an account, because it was lost or no longer trusted, while every session it had
  opened carried on: the removal touched neither the security stamp nor the refresh tokens. It now
  rotates the stamp and revokes every refresh token the account holds in the save that removes the
  credential, as revoking an mTLS credential does, since a session does not record which credential
  opened it. The ending is audited as `UserSessionsEnded` with the reason
  `webauthn_credential_removed`, beside the `MfaWebAuthnRemoved` entry.
- **Removing TOTP ends the account's sessions.** The same gap, for the authenticator app:
  `DELETE /auth/totp` removed the secret and left every session running. It now rotates the stamp
  and revokes every refresh token in the save that removes the secret, audited as
  `UserSessionsEnded` with the reason `totp_removed`, beside the `MfaTotpRemoved` entry.
- **Logout stops the access tokens on other devices.** Logging out revoked every refresh token of
  the account but only the access token that asked, so a session on another device, a stolen one
  included, kept working until its access token expired. There is no per-device sign-out and no
  session list, so logout is "everywhere": it now also rotates the security stamp, and every
  access token of the account is refused on its next request. The `UserLogout` audit entry records
  how many refresh tokens were revoked.
- **A session-ending change cannot commit without revoking the refresh tokens.** Four changes
  rotated the security stamp in one commit and revoked the account's refresh tokens in a second:
  the forced password change at sign-in, a TOTP recovery code, a password change from the account
  page and an administrator's password reset. Token refresh does not read the stamp, so had the
  second write failed (a dropped database connection, a restart in between), the password would
  have been changed and the caller told of an error while every older session could still refresh.
  Each now commits the two together. Every session-ending change goes through one helper
  (`UserSessionTermination`), and a test that reads the sources fails when new code assigns the
  security stamp without ending sessions or saying why not.
- **Keystores, the web TLS PKCS#12 and backup archives are owner-only from the moment they are
  created.** Several secret-bearing files were still written at the permissions the directory and
  umask gave and restricted to the service account afterwards: a keystore's temporary file on every
  keystore write and on a keystore restore (the rename gives the keystore that file's mode),
  `config/api-tls.pfx` when web TLS is provisioned, renewed or reissued, the plaintext ZIP a backup
  builds before encrypting it, the encrypted archive, the pre-restore snapshot, and the files of
  `config/dp-keys` and the SSH CA key directories a restore unpacks. On Linux another local user
  who could reach the directory could open such a file in that moment and keep reading it after
  the `chmod`. They are now created with mode 0600 (and as a new file where one was overwritten in
  place), so there is no such moment. The keystores and the PKCS#12 are encrypted and the backup
  directory is owner-only, so this closes a gap behind other protections rather than an open
  disclosure. On Windows nothing changes: a file is created under its folder's ACL and restricted
  once written, as before.

**Fixed**

- **`--upgrade-check` says when it may not read the configuration.** Run as an account other
  than the service's, it reported `db.yaml` as not found and suggested another `--config-dir`,
  though the file was there and only unreadable. It now says the account cannot read it and
  names the command to run as the service account. The exit status is 1 as before.

- **SCEP's GetCACaps is answered for the CA it is asked of.** It was answered without looking at
  the CA, so a client was told `POSTPKIOperation`, `SHA-256` and the rest by a CA whose key is
  not RSA, by a CA with SCEP switched off, and under a label that names no CA. It is now refused
  as GetCACert is: 409 with `reason: "ScepRequiresRsaKey"` for a CA SCEP cannot run on, 400
  otherwise. A CA whose key is not RSA gives that 409 on all three operations even while SCEP is
  switched off on it, which is its usual state; it gave the generic 400.
- **The CMP audit tab names the request that was made.** Every certificate CMP issued was
  recorded as `IR` and every refusal as `IRRejected`, so a key update could not be told from a
  first enrolment. The rows now read `IR`, `CR` or `KUR`, and `IRRejected`, `CRRejected` or
  `KURRejected`. Anything that filters the CMP tab on `IR` to count issuance should include the
  other two.
- **An ACME client can change its account key.** The key-change request was refused unless its
  inner payload carried a `newKey` member, which RFC 8555 does not define and no standard
  client sends: the new key is the one in the inner header. A standard request is now accepted.
  A `newKey` member that is sent must still match the header's key.
- **"My Certificates" lists the caller's certificates.** The self-service page and its dashboard
  counts showed every certificate the caller could view, which for an operator or administrator
  is every certificate of their CAs. They now show the caller's own: those issued from a request
  the caller made, and those shared with the caller by name. The page has a choice to list
  every certificate the caller can view, as before. `GET /api/v1/user/certificates` gains
  `?mine=true` for this; without it the answer is unchanged.
- **The self-service sidebar marks one page as current.** On My Requests, "Request Certificate"
  was marked as well.
- **The Deleted tab of the Users page shows its values whole.** Usernames, dates and a header
  were cut off with an ellipsis while most of the table was empty.
- **An ACME account key change is audited.** Replacing an account's key replaces its only
  credential, and it left no record anywhere. A rollover is now in the main audit log as
  `AcmeAccountKeyChanged`, with the old and new key thumbprints, and on the ACME tab as
  `AccountKeyChanged`. A refused one is an unsuccessful `KeyChangeRefused` row with the reason.
- **A refused CMP revocation is on the CMP audit tab.** A granted revocation wrote an `RR` row; a
  refused one reached only the log file, including an attempt to revoke a certificate the caller
  has no right to. Each refused entry is now an unsuccessful `RRRejected` row with the serial,
  the caller and the reason.
- **The EST audit tab names a re-enrolment as one.** Enrolment and re-enrolment share a path, and
  its rows were all named after enrolment. A re-enrolment now writes `SimpleReenroll`,
  `SimpleReenroll-PendingApproval` or `EstReenrollRejected`. Anything that counts EST issuance
  by filtering on `SimpleEnroll` should include `SimpleReenroll`.
- **Two more ACME events are on the ACME audit tab:** a change of an account's contact
  (`AccountUpdated`; the addresses are not copied into the row), and a challenge response the
  server refused (`ChallengeRefused`, unsuccessful, with the reason that only reached the log
  file).
- **Deactivating an ACME account is on the ACME audit tab.** It was written to the main audit
  log only, so the tab showed an account being registered and never its end. An
  `AccountDeactivated` row is added; the main audit entry is unchanged.
- **A request against a deleted CA's signing profile is refused when it is made.** It was
  stored, and could be approved, although issuance refuses a deleted CA: the request then sat
  there for good. The console and its API now answer 400 with `MCA-CFG-015`, the code issuance
  uses, and say to choose another signing profile.
- **The node writes its log file again on Linux.** The log file was opened in Serilog's shared
  mode, which off Windows creates a named system mutex before it opens the file. .NET cannot
  create one when the service account's home directory is not writable, which is the case under
  the hardened systemd unit (the home is the read-only install directory) as it was in the
  container image before it set `HOME=/tmp`. The step failed for every file name the sink tried;
  the sink then dropped every event, and the test install had written no `logs/modularca-*.log` since 19 October. The journal kept
  everything, and the only sign was `[Serilog SelfLog] ... was locked` and `could not be opened or
  created` lines at start. The node and the signer role now open their log file unshared; each
  file has one writer. **Check an install:** if `logs/` holds no file for today, it was affected.
- **A requester can request a certificate in the console.** The request form fills its signing
  profile picker from `GET /api/v1/user/signing-profiles`, which listed a profile only to a
  caller holding a `profile.*` capability. The Requester role holds `cert.request` and
  `cert.view`, so its picker was empty, although the server accepted the same account's
  submission. Both self-service lists now follow the check a submission goes through:
  - `GET /api/v1/user/signing-profiles` lists a signing profile when the caller holds
    `cert.request` on its CA, the CA is live, and it is inside the caller's space fence.
  - `GET /api/v1/user/request-profiles` lists a request profile when one of those signing
    profiles goes with it, and names on each row only the certificate profiles that CA admits.

  Some callers see fewer rows than before, each of them a row a submission would have refused:
  a `profile.*` capability alone no longer lists a signing profile; membership of a CA's group
  without `cert.request` there (an auditor) no longer lists that CA's request profiles; a
  signing profile with no issuer is listed only to a holder of `cert.request` at system scope;
  profiles of a deleted CA, and request profiles bound to a CA with no signing profile, are
  listed to nobody, system administrators included; and a caller with nothing to submit against
  gets an empty request-profile list. The administration lists under `/api/v1/admin` are
  unchanged.
- **Deleting an account with a history works, and keeps the history.** An account that made a
  certificate request or approved one could not be deleted: `DELETE /api/v1/admin/users/{id}`
  answered 500. It now answers 200 with `retained: true`. The account is gone from every list
  and can never sign in again, but its row is kept so that its requests and approvals still name
  it; a request list shows the requester as `name (deleted)`. What goes: group memberships,
  roles, direct grants, badges, sessions, MFA and mTLS credentials, the password and its history,
  enrolment tokens the account created, access to single certificates, and the email address.
  What stays: the id and the username. **The username cannot be used again**, by a new account,
  a rename, a service identity or a directory sign-in; the email address can. Nothing restores a
  retained account. An account with no such history is removed outright as before
  (`retained: false`). The enrolment account of a Kerberos realm is refused with 409 until the
  realm is given another account. Found on the test install of 0.4.4-dev.1.2.
- **Auditors and scoped administrators can read the OID catalog.** `GET /api/v1/admin/oid-options`
  is the list the certificate profile editor builds its key usage pickers from, and was meant to
  be readable by anyone who can view certificates. A system-operator rule on the whole controller
  applied to it as well, so everyone below a system operator was refused. The rule is now on the
  two writes only. Found on the test install of 0.4.4-dev.1.2.
- **A start no longer logs failed CRL and renewal runs while a separate signer is coming up.**
  With the signer apart from the node (the pod, or the two units), the node is up a few seconds
  before the signer listens, and a scheduled CRL generation, auto-renewal or web TLS renewal run
  in that window failed with "the signer is unreachable" on every ordinary start. The scheduler
  now holds those three jobs until the signer has answered once, says so in one information
  line, and runs them as soon as it answers. The hold ends for good at that first answer, and
  after five minutes without one: a signer that goes away later, or never comes up, is reported
  as an error exactly as before. Nothing changes with the signer in process.
- **The container writes its log files.** In the image every write to `logs/modularca-*.log`
  failed ("the target file could not be opened or created"), for the node and the signer, and
  only the console had the log. The file is opened shared, which on Linux takes a named mutex,
  and .NET could not create one because the image account's home is not writable. The image now
  sets `HOME=/tmp`. An orchestrator that worked around this with `HOME=/tmp` of its own can
  drop it. Found by the hub's run; not reproduced here, where there is no container runtime.
- **A lookup of an account that does not exist answers 404.** `GET /api/v1/admin/users/{id}`,
  `by-username` and `by-email` answered 500 for an account that does not exist and 404 for one
  outside the caller's spaces, so the two could be told apart and a username in another space
  confirmed. Deleting an id that names no account, and
  `GET /api/v1/admin/ssh/ca-keys/{id}/public-key` for an unknown key, answered 500 too; all are
  404 now. Found on the first test install of 0.4.4-dev.1.0.
- **Step-up audit rows name who stepped up.** `MfaStepUpVerified` and `MfaStepUpFailed` rows
  carried the actor's id and an empty username, so a search of the audit trail by username missed
  them. They now carry the username from the access token. Rows already written are not changed.
  Found on the first test install of 0.4.4-dev.1.0.
- **A pod install keeps the bootstrap's audit records.** The bootstrap queued the records of its
  keystore writes and setup choices (whether several people administer the CA, ACME validation of
  private addresses) in `logs/bootstrap-audit-*.jsonl` for the node to replay at its first start.
  In the pod the bootstrap is an init container whose `logs/` goes with it, so those records never
  reached the audit trail; the same held for a container replaced after the setup wizard. The
  bootstrap, headless or wizard, now writes them into the audit database itself as its last step,
  on every install type, and the file is only the fallback for a write the audit database refuses
  (the bootstrap says so and goes on). The rows are the ones the replay wrote, by
  `system-bootstrap`, with one addition: each carries a `BootstrapEntryId`, by which a later
  replay recognises a line that is already in the trail, so a file written in part by one process
  and replayed by another gains no duplicate rows. The node also no longer marks a file replayed
  when a row from it did not reach the audit database; it retries at the next start. Setup
  choices are scrubbed of sensitive-named values before they are queued, not only on replay.
- **Bootstrap audit records the audit database refused are kept where the node finds them.** When
  the bootstrap's own write was refused, the queued file stayed in the bootstrap's `logs/`, which
  the pod's init container does not keep: the records were lost and only a `[WARNING]` remained.
  The bootstrap, headless or wizard, now moves what it could not write into
  `config/audit-pending/`, owner-only, on every install type, and the node replays that directory
  (and then `logs/`, as before) at each start. A file keeps its name when it is moved, so the
  lines an interrupted write already recorded keep their `BootstrapEntryId` and are not recorded
  twice; a second file of the same day goes into a numbered directory beside the first rather
  than replacing it. The files hold names and choices, never a secret. The warning now names the
  directory, and says the records are lost only if they could not be moved there.
- **Windows Autoenrollment follows the scope switcher.** The page took its CA from the URL before
  the scope, so picking another CA in the switcher kept showing the first one's checklist. Picking
  a CA there now moves the page to that CA, as Protocol Configuration does; a space or "All CAs"
  leaves it where it is, and a link naming a CA still opens that CA. The page's own CA picker
  keeps the scope in the URL.
- **The sign-in pages say how long to wait when the rate limiter refuses.** On a 429, sign-in, the
  forced password change and the claim page showed "Too many requests. Try again later.", or
  "HTTP 429" when a proxy in front answered. They now show "Too many attempts. Wait up to 15
  minutes, then try again.", with the wait the answer names (the limiter's window for that
  endpoint), or "a few minutes" when it names none.
- **A certificate profile's usages are checked against the OID catalog when it is saved.**
  Creating or updating a certificate profile accepted any key usage or extended key usage, and
  issuance then left out of the certificate whatever the catalog could not resolve, with only a
  warning in the log. `POST` and `PUT /api/v1/admin/cert-profiles` now refuse such an entry with
  400 (`MCA-PRF-002`) and a message naming it, and refuse `anyExtendedKeyUsage`, which issuance
  always refused. The fields are read as the comma-separated list the console sends or as a JSON
  array, and an entry passes by friendly name or OID in every spelling issuance resolves, so a
  profile that issued what it listed still saves; a custom extended key usage OID is accepted
  once it is added under OID Options, which is also when it is issued. An update is refused only
  for an entry it adds: a profile that already stores an unknown usage can still be edited.
- **The policy files' certificate profiles get the same check.** An entry in `cert-profiles.yaml`
  that would create a profile with a usage the OID catalog does not hold, or add one to an
  existing profile, or that names `anyExtendedKeyUsage`, is no longer written: that profile is
  left out of the sync (a new one is not created, an existing one keeps everything it had) and
  the sync's result carries an error naming the profile and the usage, ending `(MCA-PRF-002)`.
  The other entries in the file are synced, and `POST /api/v1/admin/policy/sync` and the import
  still answer 200 with the errors listed, as for other invalid entries. As in the console, the
  usages a profile already stores are not checked again, so a profile synced before this check
  keeps syncing its other fields. The sync at start now also logs each error as a warning, where
  it logged only how many there were.
- **The claim the bootstrap creates for the first administrator is audited.** With
  `Administration.ClaimTokenSha256` in `bootstrap.yaml` the headless bootstrap created the claim
  and recorded nothing, so the audit trail showed the account being claimed
  (`UserAccountClaimed`) but never the claim being issued. The bootstrap now writes
  `UserClaimTokenIssuedAtBootstrap` by `bootstrap` into the audit database, through the hash
  chain, once the install is complete: the account, when the claim expires and the host, never the
  token or its hash. If the audit database refuses the write the bootstrap still finishes, warns,
  and queues the record for the node's first start.
- **ACME answers a bad nonce with badNonce and a malformed request with 400 malformed.** A missing,
  unknown or replayed nonce was answered `malformed` and without a `Replay-Nonce`, so clients
  could not retry; it is now `badNonce` with a fresh nonce, as RFC 8555 §6.5 requires. A body that
  was not a readable JWS, or a payload a handler could not bind, returned 500.
- **ACME new-order refuses a DNS identifier no DNS name can be.** A name longer than 253
  characters, or with a label longer than 63 or empty, was accepted, and the order sat with
  authorizations no client could validate; it is now refused with 400 `rejectedIdentifier`
  (RFC 8555 §6.7) and no order is created. One trailing dot is not counted.
- **A restore keeps the audit history unless asked to replace it.** A restore replaced the live
  audit database with the archive's, so every audit record made since the backup was lost,
  against the rule that audit history survives unless it is deliberately wiped. The audit database
  is now left as it is and the restore is recorded in it; `--restore-audit`, or the console's
  *Also replace the audit history with the backup's*, puts the archive's trail in its place. The
  confirmation prompt says which databases will be overwritten.
- **Windows autoenrollment leaves out a template it could not issue, instead of offering nothing.**
  A template whose certificate profile lists no EKUs under a restricting signing profile made the
  whole policy listing fail; it is now skipped with a warning naming it, as an ECC-only template
  already was.
- **Setup and bootstrap refuse an empty section up front.** A setup request with a section set to
  null (`"admin": null`), or a `bootstrap.yaml` with a bare section key (`HttpsApi:` with nothing
  under it), failed partway through the bootstrap with a null reference. Either is now refused
  before anything is changed, naming each empty section (`MCA-REQ-000`).
- **mTLS sign-in works when the credential's signing CA is an intermediate.** Chain validation
  accepts a path that ends at an intermediate CA given as the trust anchor; every certificate
  issued under an intermediate failed with `cert_chain_validation_failed`. Revocation of the
  certificate, and every other check, still apply. One limit on Linux: with "Require mTLS OCSP
  Check" on, a certificate under an intermediate signing CA is still refused, because the
  platform checks revocation online only for a chain that reaches a self-signed root; it is
  refused rather than accepted unchecked. The database revocation check applies either way.
- **The HTTP to HTTPS redirect uses the same public port as every other HTTPS link.** It could send
  clients to 443 when the listener was on 8443, or to the listener port behind a proxy publishing a
  different one.
- **EST and CMP record a protocol audit row when enrollment fails on a configuration fault**, such
  as a CA with no certificate profile, as SCEP already did.
- **A certificate on hold can be revoked permanently without being released first.** The reason
  changes in place and the revocation date becomes the time of the permanent revocation, so the
  next CRL, delta CRL and OCSP answer carry it; the hold date becomes the invalidity date. The
  certificate page offers *Revoke permanently* on a held certificate.
- **The admin certificate export returns the public certificate as PEM, DER or PKCS#7, with the
  chain when asked.** `POST /api/v1/admin/certificates/{serial}/export` refused every format; it now
  exports `pem` (the default), `der` or `pkcs7`, honours `includeChain`, and refuses PKCS#12 with
  the reason: it carries a private key, which this endpoint never hands out.
- **An ECDSA signature from an HSM is DER-encoded before it goes into a certificate, CRL or OCSP
  response.** PKCS#11 tokens return raw r‖s, which went into signed structures unchanged and could
  not be verified. No EC CA runs on an HSM today.
- **RSA-PSS and Ed448 signatures on an HSM carry the parameters their algorithm identifier
  advertises**: the hash, MGF1 and salt length for PSS, the pure-EdDSA parameters for Ed448.
- **A keystore scrypt N that is not a power of two is refused when it is saved**, r and p are
  refused rather than clamped when out of range, and a new cost may need at most 1 GiB per
  derivation (N = 2^20 with r = 32 asked for 4 GiB on every unlock and write).
- **The "valid until" picker on issuing a request stops at the server's ceiling, in local time.**
  It took its limit from the certificate profile alone, cut to a UTC date, so the last day offered
  could be up to a day past what the server allows.
- **Dashboard, Profiles and Distribution follow the scope switcher.** After switching between two
  spaces, or between a space and all CAs, they kept showing the previous scope's CAs, counts,
  profiles, CRL schedules and service URLs.
- **A typed table filter no longer undoes a sort, page or scope change made while it waits.**
- **The LDAP settings error for a group search filter without `{0}` says what `{0}` stands for**:
  the user's DN, not the username, as the group search has always used it.
- **A list load for a scope you have left no longer replaces the current list**, on CA management,
  certificate requests, templates, enrollment credentials, ACME endpoints, the expiry calendar, the
  dashboard, profiles and distribution.
- **Enrollment credentials are narrowed by space, on the server.** The list was narrowed only under
  a CA scope, so every space showed every credential. `GET /api/v1/admin/enrollment-tokens` now
  takes `caId` (the credentials bound to that CA) and `spaceId` (those scoped to the space or bound
  to a CA inside it), applied after the caller's space fence, so naming another space opens none
  of it. A stale `tenantId` is refused with 400, as on the other lists.
- **Protocol Configuration keeps its CA selector when a CA's configuration fails to load.** The
  error hid the selector, so the only way to another CA was the scope switcher. It now shows
  inline below the selector and clears when another CA is picked.
- **Windows Autoenrollment setup shows the readiness of the CA selected.** Switching CA while a
  readiness check was in flight let the previous CA's slower answer land and stay, and the previous
  CA's steps stayed on screen while the new one was checked. A check for a CA already left is now
  dropped, and switching clears the steps at once.
- **Request Profiles and the SSH profile tabs follow the scope switcher.** They listed every
  profile under any scope. Request Profiles now keeps the profiles bound to a CA in the scope and
  the system-wide ones, as Signing Profiles does; SSH signing and request profiles keep those of
  the scoped SSH CA and the unbound ones; and under a space scope the three SSH tabs say that SSH
  CAs belong to the instance, as the other SSH tabs do.
- **A certificate on hold can be made permanent from bulk revoke, the user portal and the
  infrastructure API**, as from the admin revoke. Bulk revoke skipped a held certificate as
  already revoked, and the portal and the infrastructure API refused it (the infrastructure API
  answered "already revoked" and changed nothing). Each now revokes it with the reason given and
  reports `previousReason` `CertificateHold`; bulk revoke skips a held certificate asked to be held
  again as `already_held`, and the infrastructure API answers a repeated hold with success. The
  portal offers *Revoke permanently* on a held certificate.
- **A revoke, hold or release the certificate's state does not allow answers 409, not 500.**
  Revoking a certificate already revoked permanently, holding it again, or releasing one not on
  hold threw an error the global handler answered with 500; it is now 409 with code `MCA-RES-009`
  and the reason in the message.
- **A revoke, hold or release of a certificate that cannot be found answers 404, not 500**, with
  code `MCA-RES-000`, and one whose serial matches certificates of more than one issuer answers
  409 with the new code `MCA-RES-010` (retry with the certificate ID). The admin serial endpoints'
  existing 409 for an ambiguous serial now carries the same code. A certificate deleted between an
  endpoint's own lookup and the revoke is answered as the endpoint answers a missing one: 404 on
  the admin, portal and infrastructure API paths (the infrastructure API's body is the same as for
  a missing or out-of-scope certificate, and it now revokes by the ID it scope-checked rather than
  resolving the serial again), `not_found` in a bulk revoke (it was counted as `failed`), and
  nothing to do for the certificate behind a revoked mTLS credential. The user portal used to
  answer it 400, and a ceremony-gated CA revocation, which has no catch of its own, 500.
- **The pod starts a second time.** `--role signer --init-identity`, which the pod's `signer-init`
  init container runs on every start, exited 1 when the identity CA already existed, so every
  start after the first failed there and neither the signer nor the node came up. It now checks
  the identity it finds and, when the CA and the server certificate are both there and agree,
  says so and exits 0 without changing either. One file without the other, a file that does not
  open under its configured password, a server certificate the CA did not issue, one that has
  expired, or one naming a host other than `--host` or `Signer.Listen` still exits 1 and changes
  nothing. `--force` is still the only way to replace the CA.
- **A node that starts before its signer listens reads the wrapped secrets once the signer
  answers, without a restart.** In the pod the two start together and the node usually wins; on
  one host the signer's unit is ordered after the node's, so the node always did. The node then
  started without `JWT.Secret`, the directory bind password, the mail secrets and the webhook
  endpoints (or, on a first start, left them unmoved in `config.yaml`), and nothing tried again
  until the next restart. It now asks the signer again in the background (2 s, doubling to once a
  minute) and, when it answers, reads the secrets onto the running configuration and, on the
  control role, moves those still in `config.yaml` and rewrites the file. Until then
  `/health/live` and `/health/ready` answer 503 with a `signerSecrets` entry, and sign-in runs on
  a temporary JWT secret: access tokens are now checked against the secret in force when they
  arrive, so sessions signed with the temporary one end when the stored one is read, and a refresh
  gets a new one. The temporary secret is never stored or written to `config.yaml`.
- **Protocol Configuration keeps its CA selector when a profile list fails to load.** The page
  loaded the authority list, the signing profiles and the certificate profiles together, so a
  failed profile request showed the whole-page error in place of the CA selector, as though there
  were no authorities. Only the authority list failing does that now. A profile list that fails
  shows its own error above the protocol cards, and its picker is locked on each protocol's
  current profile, so every other setting can still be changed and saved without clearing it.
- **The Settings page's HSM card shows the HSM settings in force.** It read an `hsm` section that
  `GET /api/v1/admin/config` never returned, so it said Disabled on every install, including those
  whose CA keys are on an HSM. The response now carries a read-only summary: with the signer in
  the node's process, whether the HSM is on, the module path, the slot and which key label each CA
  uses; with a remote signer, that the signer holds the settings in its own `signer.yaml`, and
  its address, which the card says instead of showing blanks (and, from the entry under Changed
  below, what the signer itself reports). The PIN and the mappings' key ids are never returned.

**Changed**

- **A step-up TOTP code is accepted when the clocks differ by up to 15 seconds.** Step-up
  accepted only the code of the server's current 30-second step, so a correct code was refused
  whenever the server and the authenticator sat on opposite sides of a step boundary: a server
  five seconds fast refused one code in six, and each refusal counted towards the step-up
  lockout. Step-up now also accepts the previous code during the first 15 seconds of a step and
  the next code during the last 15, never more than two codes at once. Sign-in is unchanged (one
  whole step either way), and a code is still accepted once.

- **`--upgrade-check --read-only`: a check that can run beside a node that is still serving.**
  The upgrade check rehearses pending migrations, and the rehearsal holds their locks, so
  beside a serving node it made clients wait. With `--read-only` it does everything that needs
  no rehearsal (can this build start, the catalog and history reads, ownership, every refusal
  that can be decided by reading), takes no migration lock, and writes nothing: its connections
  are read-only at the server and give up on a lock after half a second. It ends one of four
  ways: exit 0, nothing to apply; exit 3, refused, worded as before; exit 75, try again; and a
  new **exit 5**, `UPGRADE PENDING, NOT REHEARSED (...)`, naming the pending migrations of each
  database. Exit 5 is not a pass: whether the migrations apply to this data is only known once
  the check has run without the flag, with the node stopped. Without the flag nothing changes.
- **The certificate request form asks for the issuing CA first.** Step 1 now leads with a
  Certificate Authority picker, on the user's request page and on the administrator's. Until a
  CA is chosen the three profile pickers are disabled. With a CA chosen they offer only what
  goes with it: that CA's signing profiles (its default preselected), the request profiles
  bound to it or to none, and the certificate profiles it admits. Changing the CA clears the
  choices made under the old one. The picker is filled in for you when there is nothing to
  choose: you can use one CA only, or the console is scoped to one CA, or to a space that has
  one. A console scoped to a space offers that space's CAs. A signing profile with no issuer is
  not offered by the form. Before, the three pickers were independent, and a pairing from two
  CAs was refused only on submit.
  - To carry this, the signing-profile lists name the CA: rows of
    `GET /api/v1/user/signing-profiles`, `GET /api/v1/admin/signing-profiles` (and `/{id}`) and
    `GET /api/v1/integration/infra/signing-profiles` gain `caId`, `caName` and `caSpaceId`, null
    for a profile with no issuer. Each `certProfiles` entry of
    `GET /api/v1/user/request-profiles` gains `spaceId` and `certificateAuthorityId`. Fields are
    added only; no list returns different rows.
  - On the administrator's page the certificate profile is no longer preselected when the page
    opens; it is chosen after the CA and the request profile.
- **Deleted accounts that are kept as a record can be seen.** The Users page has a Deleted tab
  listing each account that was deleted but retained because requests or approvals still name
  it, with when it was deleted and how many of each. It is read-only, for holders of
  `user.manage` at system scope, and backed by `GET /api/v1/admin/users/deleted`. The console's
  delete dialog now says when an account will be kept this way, and the confirmation says when
  it was.
- **`--upgrade-check` refuses a build that cannot start.** Before it looks at the configuration
  or a database it builds the web host once and throws it away. A payload with a wrong or
  missing framework assembly is refused there with `THIS BUILD CANNOT START` and exit status 3,
  while the version it would replace is still running. The check used to pass on such a build,
  as it did on 0.4.4-dev.1.1, so the old version was stopped before anyone learned the new one
  would not start. The Linux build script runs the same check on the finished payload when the
  build host can run it, and refuses to make the archive otherwise.
- **The Linux build is published ReadyToRun.** The assemblies carry precompiled code, so the node,
  the signer and every one-shot command compile less at each start. The unpacked install is about
  a third larger (145 MB to 194 MB). Nothing changes in how it is installed or run.
  `MODULARCA_READYTORUN=0 scripts/build-linux-dist.sh` builds without it. Measured on a pod: a
  start is about 2.5 s shorter (11.4 s to 8.9 s) and each `--check-ready` uses a quarter to a
  third less CPU; the container image is 75 MB larger.
- **A start that fails after applying a migration exits with status 4, not 3.** Exit status 3
  from the start-up schema check now promises that it applied nothing, so the previous release
  can run on the same databases. Status 4 means the start stopped for good after a migration had
  committed (one failed during the apply, the history could not be read to tell, or the check
  afterwards did not match): fix the cause and start this release again, or restore both
  databases before running the previous one. The journal says which. Status 75 is unchanged and
  promises nothing either way: start the same release again. `modularca.service` carries
  `RestartPreventExitStatus=3 4`; a hand-written unit or an orchestrator that treats 3 as "do
  not retry" should treat 4 the same. A start can still change `config.yaml` or import SSH key
  files after the schema check and then fail with another status, so only 3 from the schema
  check is a promise.
- **The PROXY protocol settings can come from the environment.**
  `MODULARCA__HTTPS__PROXYPROTOCOL`, `MODULARCA__HTTP__PROXYPROTOCOL` and
  `MODULARCA__HTTP__PROXYPROTOCOLTRUSTEDCIDRS` override `Https.ProxyProtocol`,
  `Http.ProxyProtocol` and `Http.ProxyProtocolTrustedCidrs` for this host and are never written
  to `config.yaml`, like `MODULARCA__HEALTH__LOOPBACKPORT`. An orchestrator sets them in each
  instance's unit instead of editing the file between the init containers and the node. A switch
  that is neither `true` nor `false` stops the start, naming the variable.

- **With a remote signer, the Settings page's HSM card shows the signer's HSM settings.** It could
  only say "held by the signer". The signer's health answer on the signer channel now also says
  what it loaded at start: whether its HSM is on, the PKCS#11 module path, the slot and which key
  label each CA uses. `GET /api/v1/admin/config` reports that under `hsm` (still
  `heldBy: "signer"`, with the signer's address), and the card shows it as "Enabled on the signer"
  or "Disabled on the signer", saying the values are the signer's and are changed in its
  `signer.yaml`. Nothing is taken from an `Hsm:` section the node's own file may still carry. The
  PIN and the mappings' key ids are not in the answer: the message has no field for either. A
  signer that does not answer within three seconds, or is older than the node, leaves the card
  saying only that the signer holds the settings, as before. This does mean a node learns its
  signer's module path, slot and key labels, which until now only the signer's host showed.

- **The request profile and SSH profile lists take the console's scope on the server.**
  `GET /api/v1/admin/request-profiles` now takes `spaceId` beside `caId`, and
  `GET /api/v1/admin/ssh/profiles/signing`, `/cert` and `/request` take `caId` and `spaceId`.
  They follow the rules the console applies to those lists today: a CA view keeps the profiles of
  that CA (for an SSH signing profile, the CA of its SSH CA key) and the ones that name no CA,
  which is every SSH cert profile; a space view keeps the request profiles bound to a CA of the
  space and the unbound ones, and no SSH profile, since SSH CAs belong to the instance. The view
  is applied after the caller's own limits, so it can only narrow, and the pre-0.4.0 `tenantId`
  key is refused with 400 on all four. Without either parameter the lists are unchanged.
- **The signing profile list takes the console's scope too, and the console sends it.**
  `GET /api/v1/admin/signing-profiles` takes `caId` and `spaceId`, by the rule the console's
  Signing Profiles list applies: a CA view keeps the profiles that CA issues under and the ones
  with no issuer yet; a space view keeps the profiles of the space's CAs and the ones with no
  issuer. A profile whose issuer is an instance CA, a CA of another space or a CA that no longer
  exists is outside every space view. The view is applied after the caller's own limits, and
  `tenantId` is refused with 400. The console's Signing Profiles, Request Profiles and three SSH
  profile lists, and the dashboard's signing profiles, now send the scope with the request and
  reload when it changes, so they fetch only the scope's rows. What they show is unchanged:
  Signing Profiles, Request Profiles and SSH Signing still apply the console's own filter to the
  answer, since they place a profile by the CAs and keys the signed-in administrator is shown,
  and a request profile that inherits from one outside the scope still names its parent.
- **The compose file has a healthcheck for the node.** `deploy/compose/compose.yaml` runs the
  node's exec check, `--role node --check-ready --live`, every 30 seconds (10 second timeout,
  three retries, a 16 minute start period), against the loopback-only health port it now sets
  with `MODULARCA__HEALTH__LOOPBACKPORT` (8081, published by nothing), so `docker compose ps`
  shows whether the process answers. The service is "starting", then "unhealthy", until setup is
  finished, and nothing restarts it for that. An install made from the earlier file is unchanged
  until it takes the new one; "Compose: one host, one process" in the deploy guide has the
  details.
- **The container image creates `backups/` owner-only (0700).** It was 0750, which the node has
  tightened at the first backup since the backup directory must be reachable by the service
  account alone; a new `backups` volume now starts that way. A volume that already exists keeps
  its mode until the node restricts it, as the upgrade note above says.
- **The pod's node has a startup and a liveness probe**, like the signer.
  The image has no `curl`, which an `httpGet` probe under Podman needs, so the node has an exec
  check of its own: `ModularCA.API --role node --check-ready` asks the node's `/health/live` over
  loopback and exits 0 only on 200 (ready: every health check passes), and with `--live` asks
  `/health`, which runs no check (alive: the process answers). The pod's probes use `--live`, so a
  node waiting for its signer or its database is not restarted; the readiness check is for the hub
  or an operator to run with `podman exec`. It asks the node's health port when the host has one
  (below; the pod sets it), and otherwise finds a listener in this host's `config.yaml`
  (`Https.Port`, else `Http.Port` where the process opens it; a wildcard bind reached at
  `127.0.0.1`), skips certificate validation on loopback only, and writes nothing. With the PROXY
  protocol on a main listener it uses one without it, or sends a v2 `LOCAL` header where loopback
  is already a trusted proxy; it never connects where the node would close it. `--check-ready`
  without `--role signer` used to be refused; with `--role signer` it is unchanged. "The pod" in
  the deploy guide has the Quadlet `HealthCmd=` lines for the node.
- **New per-host setting `Health.LoopbackPort`: a loopback-only health listener.** Off (0) by
  default. When set, the node also listens on `127.0.0.1` at that port, plain HTTP and never with
  the PROXY protocol, and serves only `GET`/`HEAD` of `/health`, `/health/live` and
  `/health/ready` there; every other path and method on the port is answered 404 before anything
  else runs, the ingress never routes from it, and `/health/ready` still needs its SystemAuditor
  token. It is what lets the node's health command, and so the pod's probes, work when both main
  listeners take the PROXY protocol from a proxy elsewhere, as behind the hub's HAProxy, without
  trusting loopback as a proxy. `MODULARCA__HEALTH__LOOPBACKPORT` overrides it and is never written
  to `config.yaml`; the pod file sets it to 8081 on the node. The start is refused when the value
  is not a port, or is `Https.Port`, `Http.Port` or the signer's port. Kept in this host's
  `config.yaml`, applied at restart.
- **Claim tokens on the host.** `ModularCA.API --new-claim-token` prints a token and the
  `ClaimTokenSha256` line for `bootstrap.yaml`, for whoever writes that file (an operator, or a hub
  that must never see the password); it needs nothing installed. `ModularCA.API --issue-claim-token
  <username> [--claim-lifetime-hours <hours>]`, run as the service user, gives an existing local
  account a new claim, replacing any earlier one, prints its token once, and is audited as
  `UserClaimTokenIssuedOnHost`; it is the way in when a bootstrap claim expired unused.
- **The .NET build has no warnings, and a new one fails it.** The 70 compiler and analyzer warnings
  are fixed, mostly deprecated BouncyCastle calls (their output pinned byte for byte first) and
  nullable references, and every project treats warnings as errors. A deliberate exception is a
  pragma at the line with its reason, never a project-wide suppression. Every public member of the
  node and the signer is documented, and neither suppresses missing-documentation warnings any
  longer.
- **Eight request validators that never ran are gone.** The FluentValidation classes for
  certificate and signing profiles, ACME orders and finalize, CSR generation and CSR submission were
  registered but never called, because nothing runs validators automatically. Their rules were
  either already enforced elsewhere (ACME identifiers, CSR presence, key and signature algorithms,
  expiry warning settings, validity bounds) or wrong for today's requests (comma-split usages where
  the console sends JSON arrays, RSA and ECDSA only, a 100-character signing profile name, an
  issuer that may be blank), so wiring them in would have refused requests that work. No request is
  handled differently. The user and sign-in validators, which the controllers call, stay.
- **The unused `DbConfig` and `SqlConfig` classes of the API project are removed.** Nothing used
  them, by reference, reflection or YAML binding; the database settings are read through the shared
  configuration model as before.
- **The unused `CertificateStore.RevokeCertificateAsync(serial, reason)` is removed.** Nothing
  called it, by reference, interface or reflection. It marked a certificate revoked without a
  revocation time, a CRL, an audit record or the hold and scope rules; every revocation goes
  through the revocation service, as before.
- **`--role signer --check-ready` tells a container manager whether the signer is up.** It exits 0
  when a TLS server at `Signer.Listen` completes a handshake with the signer's own server
  certificate, and 1 otherwise, with the reason on one line. It needs nothing the image lacks (no
  `curl`, no client certificate), makes no gRPC call and writes nothing, so it can run every few
  seconds as Quadlet's `HealthCmd=` or a Kubernetes exec probe. The pod file uses it as the
  signer's startup and liveness probes; "The pod" in the deploy guide has the Quadlet lines, and
  why the node should not be held back until the signer is healthy.
- **In the pod, the node's config volume is cleaned of the signer's files.** `--issue-node-identity
  --apply` with `--signer-dir` (the `node-identity` init container), once the pins are in place,
  removes what the node with a remote signer never reads and the signer's directory holds a
  checked copy of: `config/keystore.yaml`, when the signer's is byte-identical or holds the same
  passphrases; the identity CA and server certificate under `config/`, and the signer's half of
  `Signer:` (`Listen`, `ServerCertificate`, `PinnedClientSpki`, `IdentityCa` and their passwords)
  and `Hsm:` in `config.yaml`, when the identity in the signer's directory opens and is the one
  both pins match. `config.yaml` keeps the node's half and every other line byte for byte, and is
  copied beside itself first (`config.yaml.pre-signer-cleanup-*.bak`) and checked by loading it
  back. On the same evidence the copies of `config.yaml` beside it (`config.yaml.*.bak`, such as
  the `.pre-signer-*` and `.pre-settings-*` copies 0.4.3 left) lose the same keys, and `Hsm:` or
  else `Hsm.Pin`, keep every other line byte for byte, and are written back owner-only, never
  deleted. The copy of the node's file `--apply` keeps before writing its half, and the clean-up's
  own, are made the same way, so no copy in the config volume holds the signer's passwords or the
  HSM PIN. A file that does not check out is left with a `[WARNING]` saying why (never what it
  holds), and the pod still starts; a later start finds nothing to remove and says nothing. Two
  units on one host do not run `--apply`, and remove these by hand as before.
- **New per-host settings for the PROXY protocol: `Https.ProxyProtocol`, `Http.ProxyProtocol` and
  `Http.ProxyProtocolTrustedCidrs`.** The first two mark the HTTPS listener (the setup wizard's
  included) and the plain-HTTP listener as taking the header; the third names the proxies allowed
  to send it, as `address/prefix` entries, and is separate from `Http.TrustedProxyCidrs`, which
  stays the `X-Forwarded-For` list: neither implies the other. All three are kept in this host's
  `config.yaml` and apply at restart; all are off by default, so a standalone install is
  unchanged. The start is refused when a listener takes the protocol with no trusted proxy named,
  or when an entry does not parse or trusts every address (`/0`). "Behind a passthrough proxy: the
  PROXY protocol" in the deploy guide has the HAProxy (`send-proxy-v2`) and nginx
  (`proxy_protocol on;`) lines.

### Test builds

These builds went to test hosts between 0.4.3 and this release and were not published. Each block
says what its build added to the one before; the release carries all of them.

**After 0.4.4-rc.1.1**, the release adds two things no test build had: a step-up TOTP code is
accepted when the clocks differ by up to 15 seconds, and `--upgrade-check` says when it may not
read the configuration instead of calling it not found. No migration is added.

### 0.4.4-rc.1.1 — 2026-11-11

The second release candidate of 0.4.4, after 0.4.4-rc.1.0 was installed on a test host and its
protocols and console were gone through. Since 0.4.4-rc.1.0:

- **Built on the .NET 10.0.15 runtime.** 0.4.4-rc.1.0 and every earlier build carry 10.0.14 or
  older, which is affected by GHSA-vmv3-wvjp-wqpj, a denial-of-service flaw in
  `System.Formats.Cbor`. After installing, `ModularCA.API.runtimeconfig.json` in the install
  directory names 10.0.15.
- **An ACME client can change its account key.** A key-change request in the shape RFC 8555
  defines was refused.
- **"My Certificates" lists the caller's certificates**, where it listed every certificate the
  caller could view. The page can still show the wider list.
- **Smaller, in the console:** the self-service sidebar marks one page as current, and the
  Deleted tab of the Users page shows its values whole.

No migration is added: the schema is the one 0.4.4-dev.1.1 left.

### 0.4.4-rc.1.0 — 2026-11-11

The first release candidate of 0.4.4, for test hosts. It is 0.4.4-dev.1.4 plus what running the
enrolment protocols against the test install turned up. Since 0.4.4-dev.1.4:

- **SCEP's GetCACaps is answered for the CA it is asked of.** A CA whose key is not RSA, a CA
  with SCEP switched off, and a label that names no CA all used to list capabilities. A probe
  that used GetCACaps as a liveness check will now see 400 or 409 where SCEP is not served.
- **The protocol audit tabs say more, and two names changed.** CMP rows are named after the
  request (`IR`, `CR`, `KUR` and their `Rejected` forms; every issuance was `IR`). An EST
  re-enrolment writes `SimpleReenroll` where it wrote `SimpleEnroll`. New rows: an ACME key
  change, contact change, deactivation and refused challenge response, and a refused CMP
  revocation. Anything that counts issuance by filtering on `IR` or `SimpleEnroll` should
  include the new names.

No migration is added: the schema is the one 0.4.4-dev.1.1 left.

**Known in this candidate:** it is built on the .NET 10.0.14 runtime, which is affected by
GHSA-vmv3-wvjp-wqpj, a denial-of-service flaw in `System.Formats.Cbor` published on
2026-11-10 and fixed in 10.0.15. 0.4.4-rc.1.1 is built on 10.0.15.

### 0.4.4-dev.1.4 — 2026-11-11

The fourth test build of 0.4.4, after 0.4.4-dev.1.3 was installed and its operator tier,
requesting and user deletion were checked live. Since 0.4.4-dev.1.3:

- **The request form asks for the issuing CA first.** A CA picker at the top of the request
  form narrows the signing profiles, request profiles and certificate profiles to that CA. It
  starts empty unless the caller can use only one CA. The administrator's issue page has the
  same picker. The profile lists of the API carry the CA of each signing profile for this.
- **Deleted accounts can be seen.** The Users page has a Deleted tab listing the accounts kept
  as a record, with the requests and approvals that still name each. The delete dialog says
  beforehand when an account will be kept.
- **A signing profile of a deleted CA is refused at submit**, with a message that says so.
- **`--upgrade-check --read-only`** says whether migrations are pending without rehearsing
  them, so it can run beside a serving node. It ends with exit status 5 when migrations are
  pending and were not rehearsed.

No migration is added: the schema is the one 0.4.4-dev.1.1 left.

### 0.4.4-dev.1.3 — 2026-11-11

The third test build of 0.4.4, after 0.4.4-dev.1.2 was installed and its roles, issuance and
user administration were probed live. Since 0.4.4-dev.1.2:

- **A CA's operator group is a protected tier.** On the test install one administrator of a CA
  created an operator account, signed in as it and approved its own request. Adding a CA
  operator now needs a second person; LDAP mappings no longer add members to such a group. Read
  the upgrade notes before installing over an instance that provisions CA operators.
- **Log files on Linux.** A systemd install wrote no `logs/modularca-*.log` at all; the test
  install had had none since 19 October. Fixed. After installing, check that `logs/` holds a
  file for today.
- **Deleting users.** An account with requests or approvals could not be deleted (500). It is
  now retained: hidden, stripped of everything it could sign in with or reach, its username
  kept for good.
- **A requester can request a certificate in the console.** The self-service profile lists now
  list what the caller could submit against; some callers see fewer rows than before.
- **Smaller:** the OID catalog is readable by anyone who can view certificates;
  `--upgrade-check` refuses a build that cannot build its web host.

No migration is added: the schema is the one 0.4.4-dev.1.1 left.

### 0.4.4-dev.1.2 — 2026-11-10

0.4.4-dev.1.1 did not start: its archive carried a command-line tool's copy of
`Microsoft.Extensions.ObjectPool` (7.0.0) in place of the web framework's (10.0), and the server
stopped with "Could not load file or assembly" before it read its configuration or touched a
database. The build published its three programs into one directory and left it to file
timestamps whose copy of a shared file stayed; turning on ReadyToRun changed the outcome. The
build now merges them in a fixed order, the server last, and refuses an archive in which any
file the server published is not the server's own copy. Nothing else differs from 0.4.4-dev.1.1.

### 0.4.4-dev.1.1 — 2026-11-10

The second test build of 0.4.4, after the first was installed and probed as accounts of every
tier. Since 0.4.4-dev.1.0:

- **Who may do what changed.** Administrators and operators of a CA or a space issue and approve
  with the profiles of their own scope, and the Operator role gains `profile.use` (one
  migration, `OperatorRoleUsesProfiles`). Administrators of a CA or a space administer the users
  of their own scope through the API; MFA reset, and accounts in no group, stay with system
  administrators. A requester no longer reads the users and groups of its space. Read the upgrade
  notes before installing over an instance with delegated roles.
- **Sessions and audit.** A replayed refresh token ends every session of the account. Step-up
  audit rows carry the username. A lookup of an account that does not exist answers 404.
- **Starting and upgrading.** A start that stops for good after applying a migration exits 4, and
  3 from the schema check promises nothing was applied. The scheduler holds the jobs that need
  the signer until its first answer. The PROXY protocol settings can come from the environment.
- **The image and the build.** The image declares no volumes and sets a writable `HOME`, so its
  log files are written. The Linux build is published ReadyToRun, on trial.

### 0.4.4-dev.1.0 — 2026-11-10

The first test build of 0.4.4.

## [0.4.3] — 2026-11-08

A patch release of fixes since 0.4.2, most of them from a security review and a bug hunt: a
revoked client certificate stops signing in and its sessions end, enrollment protocols and
start-up checks are tightened, reissue and Windows autoenrollment keep to the certificate and the
identity they are for, and a certificate's expiry warning follows its profile instead of a fixed
30 days. It is built on the .NET 10.0.14 runtime and adds one migration.

One release candidate, `0.4.3-rc.1.0`, went to test hosts and was not published. "Changes since
0.4.3-rc.1.0" below is what came after it; the sections after that are the candidate's own, so
an upgrade from 0.4.2 brings both. The builds before the candidate, `0.4.3-dev.1.0` to
`0.4.3-dev.1.3`, are listed at the end of this section.

### Upgrading from 0.4.2

Each entry below says more; this is the checklist. "Upgrading to 0.4.3" in
`packaging/README-DEPLOY.md` has the same steps for a host.

**Before installing, on every host**

- **Check the reverse-proxy settings in `config/config.yaml`.** The node now refuses to start
  when an `Http.TrustedProxyCidrs` entry does not parse or has bits after its prefix
  (`10.0.1.0/24`, not `10.0.1.5/24`), or when `Security.BehindReverseProxy` is on with no trusted
  proxy listed. That includes a proxy on the same host, such as nginx in front of the node on
  loopback: list it as `127.0.0.1/32,::1/128`. Both are per-host settings in that file, so a host
  that refuses is fixed there, without the console, and started again.
- **Check `Hsm.Enabled`.** A node or signer with the HSM enabled now refuses to start when the HSM
  cannot be initialised, instead of carrying on with software keys. It exits with status 3, which
  systemd does not retry, so a wrong PIN is tried once rather than until the token locks. Fix it
  and start the unit again.
- **Log readers.** Both services run with `UMask=0077`, so log files created from now on are
  readable by the service account only. A member of the `modularca` group who reads `logs/`
  directly needs a drop-in with `UMask=0027`; `journalctl` is unaffected.
- **Ceremonies.** Execute any approved ceremony first: approvals now lapse after 7 days, and one
  approved before the upgrade keeps its old expiry, 24 hours after it was opened.
- **The runtime comes with the release.** The tarball and the image carry .NET 10.0.14 inside
  them; installing this release is how a host gets it. Updating the host's packages does not.

**What changes at the first start**

- **Expiry warnings move.** The `ProfileExpiryWarnings` migration gives every existing certificate
  its warning and alert instants: an end-entity certificate warns when 30 % of its lifetime is
  left and alerts at 10 %, a CA certificate 30 days and 7 days before it expires. Long-lived
  certificates warn much earlier than before (a one-year certificate about 110 days ahead, where
  it was 30) and short-lived ones much later (a 10-hour certificate 3 hours ahead, where it was
  always), so the dashboard's Needs attention list changes. The `Web TLS Certificate Profile` is
  set to never warn. Expiry e-mails are sent once per step from now on; each certificate already
  inside its new window, and not yet replaced, is mailed once more after the upgrade.
- **Rolling back to 0.4.2 resets `ComplianceScan.ExpiringWithinDays` to 30.** The migration
  removes the stored value, and its rollback cannot restore it. Note a custom value before
  upgrading if you might roll back, and set it again afterwards.
- **Sign-in.** Refresh tokens require proof of possession: a browser that lost its key is asked
  to sign in again. A console tab left open across the upgrade may refuse one sign-in until it is
  reloaded (the CSRF cookie is renamed). Revoked mTLS certificates stop signing in, and revoking
  or holding one signs its holder out of every session. With "Require WebAuthn user verification"
  on, a security key that is a user's only second factor now asks for its PIN or biometric at
  sign-in too.
- **Controlled-user promotions waiting for approval** can now be refused at execution because the
  target's credentials changed ("the password, MFA or account of a user it promotes changed after
  it was opened") when the target's mTLS credential expires while the ceremony waits: an expired
  credential no longer counts as an MFA factor. This fails closed; open the promotion again.
- **Issuance follows the system key policy on every path**, including approved requests still
  waiting in the queue: a key outside it (RSA below 2048, a curve other than P-256, P-384 or
  P-521) is refused even where the profile allowed it.

**Clients and scripts**

- **ACME is HTTPS only.** A client pointed at an `http://` directory gets 308 to HTTPS; certbot,
  acme.sh and lego follow it. The public portal stays on HTTP. An account that was deactivated, or
  revoked by an administrator, is refused on every request; its client must register again.
- **CMP** password-based MAC accepts SHA-2 one-way functions, HMAC-SHA1 or HMAC-SHA2, and at most
  10,000 iterations; a client built on BouncyCastle's `PKMacBuilder` defaults (SHA-1) is refused
  with `badAlg`. OpenSSL's defaults are accepted.
- **Windows autoenrollment** certificates carry the Kerberos identity as their whole subject
  (`CN=<user>` or `CN=<host>`), whatever subject the client's request asked for. The SAN and the
  SID mapping are unchanged.
- **The timestamp authority** refuses SHA-1 message imprints.
- **The TSA policy changes** from the placeholder `1.2.3.4.1` to `1.3.6.1.4.1.66874.1.5.1`
  (Settings → Certificates → Time-Stamp Authority sets another). A client that pinned
  `1.2.3.4.1`, or sends it as `reqPolicy`, must accept the new one; a request naming another
  policy is refused with `unacceptedPolicy`. Tokens issued before the upgrade keep the old policy.
- **Scripts:** retiring a certificate or undoing it needs `X-MFA-Token` (`retire-cert`,
  `undo-retire-cert`), and so does editing or deleting the access badge the session wears when
  that widens it (`switch-badge`); a reissue whose body names a different certificate than its URL
  is refused with 400; a script that copies the CSRF cookie must read `__Host-CSRF-TOKEN` over
  HTTPS; the lifecycle summary's `ExpiringWithin*` counts still work for this release, but move to
  the `InExpiry*` counts; `ComplianceScan.ExpiringWithinDays` is gone.
- **Containers.** `latest` is this release. To stay on it, name it:
  `MODULARCA_IMAGE=ghcr.io/dilenex/modularca:0.4.3`.

### Changes since 0.4.3-rc.1.0

The fixes from the November bug hunt that were chosen for 0.4.3 are here; the findings, and the
ones left for 0.4.4, are in `docs/plans/bug-hunt-2026-11.md`.

**Security**

- **Built on the .NET 10.0.14 runtime.** The tarball and image carry the .NET runtime inside them,
  and every earlier build, `0.4.2` and `0.4.3-rc.1.0` included, carries 10.0.13 or older.
  10.0.14 is Microsoft's out-of-band security release of 25 October 2026: a critical Brotli decoder
  out-of-bounds write (CVE-2026-111497; ModularCA does not itself turn Brotli decompression on), and
  a complete fix for the SocketAsyncEventArgs memory corruption that 10.0.13 only partly fixed
  (CVE-2026-70197). Updating means installing this release. Updating the host's packages does not
  reach the runtime inside the tarball.
- **Reissue acts on the certificate in the URL.** The three admin reissue endpoints
  (`{certId}/reissue`, `serial/{serial}/reissue`, `csr/{csrId}/reissue`) authorized the CA of the
  certificate named in the URL, then reissued the one named in the request body. An operator on one
  CA could reissue another CA's certificate in the same space. A body that names a different
  certificate, serial or request is now refused with 400; revocation was fixed the same way earlier.
- **A deactivated ACME account stops working.** Account status was checked only on account update
  and key change, so after an account was deactivated (or revoked by an administrator) its key
  could still place and finalize orders, answer challenges and revoke certificates. Every request
  signed by such an account is now refused with `unauthorized` (RFC 8555 §7.3.6).
- **A compromised key is not reissued.** Reissuing an expired certificate that had been revoked for
  key compromise (or CA compromise) is meant to be refused, because the reissue would carry the same
  key. The refusal was swallowed by an error handler meant for other failures, and the certificate
  was reissued. It is refused now, and a comparison that cannot be made refuses too.
- **MSAE certificates are named by the Kerberos identity alone.** The request recorded `CN=<user>`
  or `CN=<host>` from the ticket, but the certificate was built from the subject in the client's
  CSR, with the identity's common name added only when the CSR had none. A domain user could
  have any subject signed (`CN=Administrator,O=Corp`), which subject-based mappings, RADIUS and VPN
  checks would trust; the SAN and AD's SID mapping were not affected. The certificate now carries
  exactly the identity's subject. An MSAE renewal likewise keeps the renewed certificate's whole
  subject instead of only a common name taken from its first DNS name.
- **"Require WebAuthn user verification" covers sign-in.** When a security key was a user's only
  second factor, the sign-in step asked the key for user verification as "preferred" whatever the
  policy said, so a key could be used without its PIN or biometric. Sign-in now follows the
  policy, and an assertion started under weaker options is refused.
- **Editing the badge you are wearing asks for MFA when it widens the session.** Switching to a
  wider access badge needs step-up MFA, but the worn badge is read on every request, so adding a
  source to it, or deleting it, widened the session with none. Both now ask for the same step-up
  as switching; narrowing a badge, renaming it and editing other badges do not.
- **Decrypted keys are written to new owner-only files.** The keystore unlocker's `--output` and the
  decrypted archive a restore stages in the temp folder were created at default permissions and
  restricted afterwards; a local user who opened the file in between kept reading it after the
  change. Both are now created owner-only from the start, as new files, and the restore's archive
  gets an unguessable name.
- **The migration tool keeps its temporary password off the command line.** `modularca-migrate`
  created its temporary administrative role with the password in `psql`'s arguments, which any
  local user can read while the command runs; for the run, that role can act as the application
  and audit roles. The statement now goes to `psql` on standard input and carries a SCRAM verifier,
  so neither the process list nor a PostgreSQL statement log holds the password.
- **Self-service SSH signing keeps to the CA's own request profiles.** A user could pair another
  CA's SSH request profile (one without approval, allowing any profile) with this CA's signing
  profile, and get a certificate at once from a CA whose own request profiles require approval.
  A request profile bound to a CA is now accepted only for that CA's signing profiles.
- **Metrics no longer grow with made-up OCSP labels and SCEP operations.** The CA label in an OCSP
  URL and the `operation` of a SCEP request became metric labels as given, so a client could create
  any number of time series, each kept until restart and exported on every scrape, without signing
  in. OCSP metrics now carry the label of the CA that answered (empty when none did), and SCEP
  operations outside the three it defines are counted as `other`.

**Changed**

- **Dependencies:** Microsoft .NET packages 10.0.12 → 10.0.14 (Entity Framework Core, JWT bearer,
  Redis caching and data protection, systemd hosting, directory services);
  `System.Security.Cryptography.Pkcs` 10.0.13 → 10.0.14; Swashbuckle 10.2.3 → 10.3.1;
  FluentValidation 12.1.1 → 12.2.0; React 19.3.0 → 19.3.1; React Router 7.18.2 → 7.18.5. None of
  these carried a known advisory. Every version is more than seven days old, as the dependency
  policy requires.

**Fixed**

- **Certificate sign-in offers the certificate picker in a browser that already has the console
  open.** When the web TLS certificate also names the mTLS sign-in hostname, as it must, a browser
  sent the sign-in request over its existing HTTP/2 connection to the main hostname, where no
  client certificate is asked for: no picker appeared and the sign-in failed with "did not present
  a client certificate". A request for the mTLS or EST hostname that arrives on a connection made
  for another hostname is now answered `421 Misdirected Request`, and the browser retries on a new
  connection that asks for the certificate. Connections without SNI, and TLS ended at a proxy, are
  not affected.
- **The certificate buttons say what a cancelled prompt does.** Under "Sign in with Certificate"
  and "Verify with Client Certificate": cancelling the browser's certificate prompt ends on the
  browser's own error page, and going back and trying again prompts once more.
- **A failed certificate sign-in keeps its message through the login banner.** When the banner had
  not yet been accepted in that browser tab, the sign-in page sent the browser to the banner and the
  banner sent it back to a plain sign-in page, so the reason the sign-in failed was never shown. The
  reason now travels through the banner.
- **Editing an access badge saves.** Changing a badge's sources failed with "The resource was
  modified by another request" (409) whenever the edit added a source: the new source rows were
  taken for existing rows and updated, which matched nothing. Sources that stay now keep their rows,
  dropped ones are deleted and new ones inserted. The fault dates from 0.4.2 and hit every badge,
  in the account panel and the admin console alike.
- **A new intermediate CA is signed by the parent the form shows.** After switching the console's
  scope to a CA subtree with the same number of CAs, the create form kept the previous parent
  while its list showed the new scope's first CA, and Create signed the new CA under the parent no
  longer shown. The form now follows the scope, and refuses to submit a parent it is not showing.
- **A mistyped code while setting up an authenticator app no longer signs you out.** The server
  answered a wrong code with 401, which the console reads as the end of the session, so a typo
  during first-time setup or on the security page signed the user out. It now answers 400 and the
  form asks again.
- **The signer no longer watches its JSON configuration files.** It is configured from YAML, but
  its web host still put an inotify watch on `appsettings.json`, using up one of the 128 a Linux
  user gets by default. It now reads them once.
- **A configuration file made read-only stays read-only.** Since secret files became owner-only
  from creation, rewriting an existing one first set it to mode 0600, which also gave a file its
  owner had made read-only its write bit back, so `modularca-migrate` and the other writers
  overwrote it. Only the group's and others' rights are taken away now; a read-only file is
  refused and reported, as before.
- **The deploy guide asks for PostgreSQL client tools at the server's major version.** It said
  "or newer", but a `pg_restore` of 17 or later cannot restore into an older server, so a
  backup taken on such a host could not be restored there.

### Security

- **A revoked client certificate no longer signs in.** Revoking an mTLS sign-in certificate from
  the certificate pages, ACME, the integration API or a revocation ceremony changed only the
  certificate, and unless `RequireMtlsOcspCheck` was on (it is off by default) the certificate
  kept signing in, by certificate login, the mTLS redirect sign-in and MFA, and kept passing mTLS
  step-up. Every mTLS sign-in and step-up now reads the certificate's own status: a revoked
  certificate is refused, and so is one on hold until it is released. Each refusal is audited as
  a failed sign-in (or failed step-up) with the reason `mtls_certificate_revoked`. Revoking the
  certificate also revokes its mTLS credential, and a revoked certificate no longer counts as an
  MFA factor. A credential whose certificate record no longer exists (only possible if that row
  was deleted) is refused as well, with the reason `mtls_certificate_record_missing`; its owner
  enrols a new certificate.
- **Revoking or holding a sign-in certificate signs its holder out everywhere.** Revoking an mTLS
  sign-in certificate, or putting it on hold, stopped it signing in again, but the sessions it had
  already opened ran on until they expired. A session does not record which certificate opened it,
  so every session of the account that holds the certificate now ends at once, as after a password
  reset, and the ending is audited as `UserSessionsEnded`. Releasing the hold lets the certificate
  sign in again; the ended sessions stay ended. Revoking your own mTLS credential on the account's
  security page does the same, so it signs you out too, this session included.
- **Refresh tokens require proof of possession by default.** `Security.EnforceRefreshTokenPoP`
  is now on. A session bound to the browser's key at sign-in refreshes only with a proof from
  that key, so a stolen refresh token is no use elsewhere. The mTLS redirect sign-in now binds
  its session too, when the console exchanges its one-time code (`POST /auth/mtls/exchange`, which
  takes a `DPoP` header), as does `POST /auth/mtls/verify`; every console sign-in now binds.
  **Upgrade impact:** a browser that has lost its key (site data cleared) is asked to sign in
  again at its next refresh instead of being re-bound. Sessions that were never bound, from
  clients that send no proof, are not affected. To go back to observe-only, set
  `Security.EnforceRefreshTokenPoP` to false in Settings, or on the host with
  `ModularCA.API --settings set Security.EnforceRefreshTokenPoP false --reason "..."`.
- **TOTP recovery codes are stored salted and slow-hashed, and guessing them locks the account.**
  New codes are kept as PBKDF2 hashes salted per user instead of plain SHA-256. Codes issued
  before this release keep working until used; enrolling TOTP again replaces them with codes in
  the new form. A wrong recovery code now locks the account at the security policy's
  failed-attempt threshold, as a wrong password does; before, it only counted. A refusal for an
  unknown, disabled or locked account takes as long as one for a wrong code, so it no longer shows
  whether the username exists, and the lockout notifies administrators, as a password lockout does.
- **Old access tokens stop at once after a password change or a TOTP recovery.** Both rotate the
  account's security stamp, but a cached copy of the old stamp let earlier tokens work for up to
  30 seconds. The cache entry is now dropped.
- **More sign-in endpoints are rate limited per address**: certificate login and the mTLS redirect
  sign-in (10 per 5 minutes), the mTLS MFA redirect and mTLS step-up (25 per 5 minutes), the mTLS
  code exchange and handoff (20 per 5 minutes), and refresh (120 per 5 minutes), under both the
  `/auth/...` and `/api/v1/auth/...` paths.
- **The CSRF cookie is `__Host-CSRF-TOKEN` over HTTPS.** The browser only accepts a cookie with
  that prefix when it is Secure, host-only and on `/`, so a sibling subdomain can no longer plant
  a token of its own. Plain HTTP keeps `CSRF-TOKEN`. **Upgrade impact:** the consoles and setup
  wizard read the new name; a script that copies the cookie into `X-CSRF-Token` must read
  `__Host-CSRF-TOKEN` over HTTPS. A leftover `CSRF-TOKEN` from an older release is deleted and no
  longer accepted over HTTPS, so a console tab left open across the upgrade may refuse one sign-in
  until it is reloaded.
- **An approved ceremony must be executed within 7 days.** An approval used to stand until
  someone executed it, however long that took. Reaching the quorum now sets the ceremony's expiry
  to 7 days ahead; after that it is marked Expired, the expiry is audited, and Execute answers 409
  with the reason. Open a new ceremony to go ahead. **Upgrade impact:** ceremonies approved before
  this release keep their original expiry, 24 hours after they were opened, so any still waiting
  to be executed past that expire the next time ceremonies are listed or one is executed.
  CA-creation ceremonies already could not be executed past it, because the signer refused them.
- **The service now refuses to start when the reverse-proxy settings cannot work.** A
  `Http.TrustedProxyCidrs` entry that did not parse was skipped, and `Security.BehindReverseProxy`
  on with no trusted proxy only printed a warning. Either way forwarded headers were honoured from
  loopback alone, every request appeared to come from the proxy, and an internal proxy address
  passed every internal-only IP whitelist rule. Both now stop the start with a message naming the
  setting; they are per-host settings, so fix them in that host's `config/config.yaml`. Each entry
  must be `address/prefix` with no bits after the prefix (`10.0.1.0/24`, not `10.0.1.5/24`).
  The console checks the same when you save (400 naming the entry), refuses to turn
  BehindReverseProxy on before a proxy is listed, and can now clear the list. **Upgrade impact:**
  check `Http.TrustedProxyCidrs` and `Security.BehindReverseProxy` on every host before upgrading.
- **An enabled HSM that fails to initialise stops the start.** The node and the signer used to
  carry on with the software keystore, so a CA whose key is on the HSM ran without it. They now
  refuse to start and say what to check. `Hsm.Enabled: true` with an empty `Hsm.ModulePath` is
  refused the same way. The PIN is passed to the module as bytes that are zeroed after the login,
  and the running configuration drops its copy; `config.yaml` rewrites keep the PIN the file holds.
  The refusal exits with status 3, which the systemd units do not restart, so a wrong PIN is tried
  once rather than until a token that allows three tries locks.
- **Enrollment tokens no longer reach the log files, the journal or syslog.** The public
  enrollment token travels in the URL path, and the request log recorded that path whole. Every
  log event now has the token replaced with `{token}`, as the audit database already had, and the
  built-in ingress logs from Warning only, so it no longer writes the proxied path either.
- **Secret files are created owner-only from the first byte.** `config/backup.key`,
  `config/backup-password.key`, `config/keystore.yaml`, `db.yaml`, `setup-database.yaml` and the
  signer's identity PFX files were written and then restricted, and a failure to restrict them on
  Linux went unreported. They are now created with mode 0600, and a failure to restrict a secret file or
  a staging directory is reported as a warning. Both systemd units now set `UMask=0077`, so
  everything the service creates is its own alone. **Upgrade impact:** log files created after the
  upgrade are `0600`; a member of the `modularca` group who reads `logs/` directly needs a drop-in
  with `UMask=0027`. `journalctl` is unaffected.
- **mTLS on a required path trusts what the handshake trusts.** `MtlsMiddleware` read
  `Mtls.TrustedCaCertPaths` relative to the working directory and ignored the mTLS signing CAs the
  handshake falls back to, so a client certificate the TLS handshake accepted could be refused on
  a `Mtls.RequiredPaths` path. Both now use one set loaded at start.
- **Admin errors no longer echo exception messages.** A failed configuration save, and a failed
  row in the bulk CRL schedule and LDAP publisher actions, answer with a generic message and a
  correlation id; the exception is in the server log under that id.
- **A missing custom Web TLS certificate is logged and audited.** With `Https.Mode: Custom` and
  the PFX missing, the server serves a temporary self-signed certificate until the file is put back
  or the certificate is reissued. That was one console line; it is now a warning in the log with
  the temporary certificate's SHA-256 fingerprint and an audit entry,
  `WebTlsTemporaryCertificateServed`, so a browser warning can be checked against it.
- **`.gitignore` covers `*.p12` and `backups/`**, so a PKCS#12 file or a backup archive in a
  working copy is not committed by accident.
- **ACME is served over HTTPS only.** A plain-HTTP request to `/acme/...` or `/api/v1/acme/...`
  is now redirected (308) to HTTPS on the public domain instead of being answered, so account
  keys, orders and certificates no longer travel in clear text. ACME clients must use the
  `https://` directory URL; one configured with `http://` follows the redirect if it can, and
  should be changed. http-01 validation is unaffected: the CA still fetches the challenge from
  the client on port 80. The public portal stays reachable over plain HTTP; its ACME page shows
  the HTTPS directory URL there and lists the endpoints only when opened over HTTPS.
- **CMP holds password-based MAC to the CA's own "require signature" setting.** The setting was
  read from whichever CMP configuration the database returned first, from any CA, so a request
  protected by a shared secret could pass at a CA that requires signature protection. It is read
  from the CA the request is addressed to, and the refusal comes before the shared secret is
  looked up, so it no longer spends one of the credential's uses.
- **CMP accepts only sound password-based MAC parameters.** The client chooses the one-way
  function, the MAC and the iteration count, and the server did that work before checking who was
  asking, with up to 500,000 iterations of any digest. It now accepts SHA-224/256/384/512 as the
  one-way function, HMAC with SHA-1 or SHA-2 as the MAC, and at most 10,000 iterations, and
  answers anything else with `badAlg`. `openssl cmp -secret` (SHA-256, HMAC-SHA1, 500 iterations)
  works as before. A CMP client that uses SHA-1 as the one-way function (BouncyCastle's
  `PKMacBuilder` default) or more than 10,000 iterations must be reconfigured.
- **EST over client certificates compares SAN types.** Each SAN a request asks for must be a SAN
  of the same type and value in the client certificate. The types used to be ignored and the
  certificate's common name counted as any SAN, so an email address or a common name could
  vouch for a UPN or an IP address. The common name still stands for the DNS name of a device
  certificate that carries no DNS SAN.
- **The system key policy applies to every issuance.** A request whose key is not RSA 2048,
  3072, 4096, 7680 or 8192, ECDSA P-256, P-384 or P-521, Ed25519, Ed448, ML-DSA or SLH-DSA is
  refused at issuance (MCA-POL-000), judged from the key itself. It was enforced only on requests
  made in the console, so EST, SCEP, CMP, ACME, Windows autoenrollment and token enrollment could
  obtain a certificate for an RSA-1024 key or a key on another curve when the certificate profile
  listed no key sizes. Token enrollment checks the key before it spends the token (400 with the
  code), and ACME answers such a key with `badPublicKey` (400), another certificate-policy refusal
  with `badCSR`.
- **A delegated OCSP responder must be signed by its CA.** The responder certificate was checked
  for its usage and dates but not for who signed it. One the CA did not sign is now refused, and
  System Health names it, as it names a responder without the OCSP signing usage.
- **The timestamp authority refuses SHA-1 message imprints** with `badAlg` (RFC 3161). Clients
  must hash with SHA-256, SHA-384 or SHA-512, which current clients do by default.
- **ACME orders and authorizations expire when they say they do.** An order past its expiry, or
  one with an expired authorization, is refused at finalize (403 `orderNotReady`), and a challenge
  of an expired authorization is refused (400 `malformed`), whether or not the cleanup sweep has
  reached them yet.
- **Protocol refusals are audited.** ACME finalize refusals made before issuance (an expired or
  unready order, the wrong CA, a request naming other identifiers, CAA) are recorded as
  `FinalizeRefused`, and every refused ACME revocation as `RevokeRefused`. Token (QR or link)
  enrollment refusals are recorded as `QrEnrollmentRejected`. A SCEP message that cannot be read,
  verified or opened is recorded as an unsuccessful `PKIOperation`, and every CMP error answer as
  an `Error` row naming the request type and the failure. These were answered and recorded
  nowhere.
- **The TSA refuses a request for a policy it does not issue under.** A request whose `reqPolicy`
  named any policy was answered with a token claiming that policy. It is now refused with status
  rejection and failInfo `unacceptedPolicy` (RFC 3161 section 2.4.2) unless it names the TSA
  policy; a request with no `reqPolicy` is answered as before.

### Added

- **System Health lists enrollment protocols that cannot run on their CA.** A new Enrollment
  Protocols card names each enabled protocol configuration that cannot work where it is, with the
  reason and a link to the CA: today, SCEP on a CA whose key is not RSA. The console refuses to
  enable that, but a configuration saved before it did is still on, and it is not switched off
  for you. The CA's page shows the same reason beside the protocol, and the CA
  hierarchy feed carries it as `advisories` on each protocol configuration.
- **The console warns where SCEP takes requests without a challenge password.** The protocol
  page and the CA's page show an amber notice on a SCEP configuration with Require Challenge
  Password off: anyone who can reach that CA's SCEP endpoint can enroll. The setting is unchanged.
  The CA hierarchy feed now carries `scepChallengeRequired` on each protocol configuration.
- **Timestamp tokens name a real TSA policy, which the console can set.** The TSA put the
  placeholder `1.2.3.4.1` in every token's policy field. It now names `1.3.6.1.4.1.66874.1.5.1`,
  the default policy under Dilenex's registered enterprise arc. Settings → Certificates →
  Time-Stamp Authority sets a policy of your own (`PUT /api/v1/admin/config/tsa`, step-up
  `update-config`, audited with the old and new value), as does
  `--settings set Tsa_PolicyOid …` on the host. A value that is not a dotted object identifier is
  refused, and an empty one restores the default; a change applies to the next request. Tokens
  issued before keep `1.2.3.4.1`. A client that checks the policy must accept the new one.
- **The sign-in page says why a certificate sign-in failed.** A revoked or held certificate, one
  that is not enrolled, an expired sign-in session and the other refusals of the certificate
  sign-in sent the browser back to the sign-in page with nothing shown. Each now shows a plain
  message; an unknown reason shows a general one.

### Changed

- **The setup wizard keeps the audit database when it clears a previous install.** Its recovery
  from an application database left by an earlier install dropped the audit database too, though
  a command-line reset keeps audit history unless given `--wipe-audit`. It now drops the
  application database only, unless you tick "Erase existing audit history" first, and the
  bootstrap that follows keeps the audit database as well. `POST /api/v1/setup/database/drop`
  takes `{"wipeAudit": true}` for the old behaviour.
- **Service secret fields are not filled in by the browser.** The setup wizard's database
  password and the console's service secrets (LDAP bind and publisher passwords, SMTP password and
  OAuth2 secrets, the cert-manager and integration API keys, a new user's password) ask the
  browser not to offer the saved console password.
- **A certificate warns of its expiry by its profile, in two levels.** A fixed 30 days put a
  10-hour certificate on Needs attention from the moment it was issued, and warned of a one-year
  certificate only a month ahead. Each certificate is now given, when it is issued, the instants
  its expiry **warning** (amber) and its expiry **alert** (red) start, from its certificate
  profile: by default when 30 % and 10 % of its lifetime is left, so a 10-hour certificate warns 3
  hours and alerts 1 hour before it expires, a 90-day one 27 and 9 days before, a one-year one
  about 110 and 37 days before. A profile may set other percents and a longest window for either
  level (an ISO 8601 duration such as `P30D`), under Expiry warning on its page and as
  `expiryWarningPercent`, `expiryWarningMaxWindow`, `expiryAlertPercent` and `expiryAlertMaxWindow`
  in the API and in policy sync YAML; invalid values are refused with `MCA-PRF-001`. A CA
  certificate whose profile sets neither level keeps 30 days and 7 days. A profile marked
  **Renewed automatically: never warn** (`expiryNeverWarn`) gives its certificates no warning at
  all, though one that expires unreplaced still shows as expired, not replaced; the seeded
  `Web TLS Certificate Profile`, which the instance renews its own console certificate from, is
  set so. A profile that inherits takes its parent's values where it leaves them empty and may
  only warn earlier than its parent (a lower percent, a shorter window, or never-warn under a
  parent that warns is clamped to the parent's), unless it declares that it overrides its
  parent's expiry settings (`expiryWarningOverridesParent`); the resolved profile marks each
  value inherited, overridden or clamped. Saving a profile's expiry settings re-computes the
  instants of its valid certificates and of those of the profiles inheriting from it, and the
  profile's audit entry records how many (`ExpiryWarningsRecomputed`). The dashboard, the
  certificate list (new statuses `expiring` and `alert`), the certificate page (when its warning
  and alert start, or that its profile never warns), the user portal, the expiry calendar, the
  inventory, the health score, the compliance scan and the expiry e-mails all read the stored
  instants. The compliance report's 30/60/90-day forecast, the inventory's forecast cards, the
  list's "Within N days" filter and auto-renewal's `RenewDaysBeforeExpiry` are unchanged. A
  profile change and the re-compute are saved in one transaction. Policy sync leaves a profile's
  expiry settings as they are when its YAML leaves the keys out, so a file written for 0.4.2
  changes nothing; `expiryWarningOverridesParent` can be set there too.
- **Expiry e-mails are sent once per step, not every day.** A certificate is mailed once when its
  expiry warning starts and once when its alert starts. `CertExpiryNotification.WarningDaysBeforeExpiry`
  now sets reminders inside the warning: each day count that falls after the warning has started
  sends one reminder, once per certificate. This also fixes the daily repeats: the job mailed
  every certificate inside each threshold again every day, once per threshold. A certificate
  first found past several steps gets one message, for the latest, and a certificate already
  replaced gets none, and raises no security alert. The `CertExpiring` notification preference no longer offers its
  days-before-expiry field, which nothing read.
- **The lifecycle summary's fixed-window counts are deprecated.** `ExpiringWithin7Days`,
  `ExpiringWithin30Days` and their `NotReplaced` counterparts are filled as before for this
  release and removed in a later one; use the new `InExpiryWarning`, `InExpiryWarningNotReplaced`,
  `InExpiryAlert` and `InExpiryAlertNotReplaced`. Attention items carry `expiryWarningAt` and
  `expiryAlertAt`, and so does every certificate the list and detail return. The expiry chart's
  `expiringSoon` counts certificates in their expiry warning.
- **`ComplianceScan.ExpiringWithinDays` is retired.** The scan's ExpiringWithoutRenewal finding
  is raised for a certificate in its expiry warning with no renewal request. The setting is
  ignored if sent to `PUT /api/v1/admin/config/compliance-scan`, its stored value is removed by
  the migration, and a `config.yaml` that still sets it to anything other than 30 is warned
  about at start.
- **The health score's expiry factors are renamed** `ExpiryAlert` (30 points, critical) and
  `ExpiryWarning` (15 points, warning), from `ExpiringWithin7Days` and `ExpiringWithin30Days`, and
  follow the certificate's instants.
- **Retiring a certificate asks for step-up MFA, and so does undoing it.** Retire stops every
  renewal from a certificate, so it is now confirmed like revoking and reissuing. Dismissing an
  expiry warning and restoring it change only the warning and still ask for nothing. Scripts
  that call `POST` or `DELETE /api/v1/admin/certificates/{serial}/retire` must send `X-MFA-Token`,
  issued for the serial under `retire-cert` or `undo-retire-cert`; without it they get 403.
- **SCEP on a CA whose key is not RSA is refused with the reason.** A SCEP client encrypts its
  request to the CA certificate with RSA, so it cannot enroll at such a CA. GetCACert and
  PKIOperation there now answer 409 with that sentence, and the SCEP audit tab records the refusal
  and why, where before a client failed on its own and the server recorded nothing. GetCACaps is
  answered as before.
- **The account's MFA list and the controlled-user check no longer count a certificate that
  cannot sign in.** An mTLS credential whose certificate is revoked, on hold or no longer on
  record, or that has expired, is left out of `GET /api/v1/account/mfa` and of the MFA state a
  controlled-user ceremony pins, by the rule sign-in uses.
- **System Health puts OCSP Responders and Enrollment Protocols side by side** on wide screens.
- **Build tooling.** The four web apps are built with vite 8.3.4 (was 8.3.0), which fixes three
  advisories in its development server and editor launcher, and the web tests run on vitest 5.0.4
  (was 5.0.0), which fixes two in its mocking module. Neither runs in an installed CA.
  `browserslist` 4.29.3 and `baseline-browser-mapping` 2.11.28 clear two advisories in build-only
  dependencies. Every resolved version is at least seven days old, as the dependency policy
  requires.

### Fixed

- **The protocol on/off switches cover the exact paths.** Switching OCSP off did not stop
  `POST /ocsp`, the path OCSP clients use, because only `/ocsp/...` was matched; the same applied
  to `/crl`, `/acme`, `/est`, `/scep`, `/cmp` and `/msae` without a trailing path. Paths are now
  matched by whole segments, so `/ocsp` and `/ocsp/...` are both switched off and a path that
  merely starts with the same letters is not.
- **CMP error answers carry the right failure bits.** The failure reason went out as the wrong
  bit (`badRequest` as `wrongAuthority`, `badAlg` as none), so a client such as `openssl cmp`
  printed a misleading reason. The text of each answer was always right. A refused revocation
  now carries `notAuthorized` (bit 23), where it carried `wrongAuthority`.
- **An account whose temporary lockout has run out gets its attempts back.** The sign-in paths
  cleared an elapsed lockout in memory only, so the first wrong password, certificate or recovery
  code after it counted on top of the old total and locked the account again at once. The cleared
  count is now written to the database first, on password and certificate sign-in, the password
  change before sign-in, EST and Windows autoenrollment passwords, and TOTP recovery.
- **An expired approved promotion no longer blocks credential resets.** A controlled-user
  promotion that was approved but not executed before its expiry still made password and MFA resets
  of its target answer 409, though it could no longer be executed. It stops blocking at its
  expiry, as a pending one already did.
- **SCEP records a configuration fault on the SCEP tab.** A PKCSReq at a CA whose SCEP
  configuration names no certificate profile, or a signing or certificate profile that no longer
  exists, was answered badRequest with no audit row. It now writes one unsuccessful `PKCSReq` row
  with the reason, and the reply carries the request's transactionID and nonce, which it left out.
- **System Health shows the age of the last backup.** The Disaster Recovery card read a field the
  server never sends, so Backup Age was always "-"; it now reads `lastBackupAgeHours`.
- **The CA page's protocol table shows "Cannot run on this CA" in full.** The Protocol column was
  120 px wide and cut the label off; it is wider and wraps the labels when narrowed.

### The builds on the way

#### 0.4.3-dev.1.3 — 2026-10-22

- **The TSA policy can be set from the console.** Settings → Certificates has a Time-Stamp
  Authority card for the policy OID, saved through the new `PUT /api/v1/admin/config/tsa`
  (step-up `update-config`, audited with the old and new value). The change applies to the next
  timestamp request. An empty value restores `1.3.6.1.4.1.66874.1.5.1`; a value that is not a
  dotted object identifier is refused. `GET /api/v1/admin/config` now returns the `tsa` section.

#### 0.4.3-dev.1.2 — 2026-10-22

- **Timestamp tokens name a real TSA policy.** The TSA put the placeholder `1.2.3.4.1` in every
  token's policy field. It now names `1.3.6.1.4.1.66874.1.5.1`, the default policy under Dilenex's
  registered enterprise arc, and the new instance-wide setting `Tsa.PolicyOid` lets an operator
  name a policy of their own (`--settings set Tsa_PolicyOid 1.3.6.1.4.1.<pen>.…`); the store
  refuses a value that is not a dotted object identifier. Tokens issued before keep
  `1.2.3.4.1`. A client that checks the policy must accept the new one.
- **The TSA refuses a request for a policy it does not issue under.** A request whose `reqPolicy`
  named any policy was answered with a token claiming that policy. It is now refused with status
  rejection and failInfo `unacceptedPolicy` (RFC 3161 section 2.4.2) unless it names the TSA
  policy; a request with no `reqPolicy` is answered as before.
- **The sign-in page says why a certificate sign-in failed.** A revoked or held certificate, one
  that is not enrolled, an expired sign-in session and the other refusals of the certificate
  sign-in sent the browser back to the sign-in page with nothing shown. Each now shows a plain
  message; an unknown reason shows a general one.
- **The account's MFA list and the controlled-user check no longer count a certificate that
  cannot sign in.** An mTLS credential whose certificate is revoked, on hold or no longer on
  record, or that has expired, is left out of `GET /api/v1/account/mfa` and of the MFA state a
  controlled-user ceremony pins, by the rule sign-in uses.
- **The CA page's protocol table shows "Cannot run on this CA" in full.** The Protocol column was
  120 px wide and cut the label off; it is wider and wraps the labels when narrowed.
- **Build tooling:** `browserslist` 4.29.3 and `baseline-browser-mapping` 2.11.28 in the four web
  apps, clearing two advisories in build-only dependencies. Nothing shipped changes.

#### 0.4.3-dev.1.1 — 2026-10-22

- **System Health shows the age of the last backup.** The Disaster Recovery card read a field the
  server never sends, so Backup Age was always "-"; it now reads `lastBackupAgeHours`.
- **System Health puts OCSP Responders and Enrollment Protocols side by side** on wide screens.
- **The certificate profile list's drawer shows the expiry warning and alert**, as the full page does.

#### 0.4.3-dev.1.0 — 2026-10-22

The first build: everything in the candidate's sections above except what the builds above and
the fixes after `0.4.3-dev.1.3` add.

## [0.4.2] — 2026-10-22

Everything since 0.4.0: the settings work that was built as 0.4.1, which is not released on its
own, and the SSH work that takes SSH CA keys out of plaintext files the node could read. It also
holds every request to its request profile on the server, at each step.

One release candidate, `0.4.2-rc.1.0`, went to test hosts and was not published; "Changes since
0.4.2-rc.1.0" below is for anyone who installed it. The builds before it, `0.4.1-dev.1.0` to
`0.4.2-dev.1.12`, are listed at the end of this section.

### Upgrading from 0.4.0

"Upgrading to 0.4.2" in `packaging/README-DEPLOY.md` is the checklist. In short:

- **Check before installing.** `--upgrade-check` (which `install.sh` runs) rehearses the thirteen
  new migrations, lists the SSH CA keys the first start will import, and refuses when the key
  file of an enabled SSH CA is missing or is not its key. Its notes, which never refuse, list the
  enrollment clients the request profiles will now refuse, from the last 90 days of the audit
  database, and the SSH profiles that will issue fewer permits than before.
- **Upgrade the signer before the node.** The upgrade is one-way for an install with SSH CAs:
  each key file is imported into the signer's new `ssh-ca.keystore`, then overwritten and
  deleted. Archives and snapshots made before still hold those keys in plaintext; rotate an SSH
  CA whose old archives may have left your hands.
- **Instance-wide settings move into the database** at the control role's first start, and the
  node's secrets with them, wrapped by the signer. `config.yaml` is rewritten with this host's
  settings, and the old file is kept as `config.yaml.pre-settings-<time>.bak`, secrets and all:
  delete it once the instance runs. From then on a node needs its signer at start to read its
  secrets.
- **Requests are held to their request profile, also from the console.** On a default install
  an EST request without a SAN, a SCEP request with a SAN other than DNS and a CMP request with a
  SAN other than email are refused from this release. Scripts that call the console request
  routes must send `requestProfileId`. Requests under a profile that requires approval wait for
  approval on every route; on an install with one administrator, turn on Allow System Super
  Self-Approval in Settings, Security.
- **SSH scripts.** A `keyId` in a sign request is refused, `sign-user` names who the certificate
  is for, and both admin sign routes ask step-up. The first SSH sweep revokes the live
  certificates of users who are disabled or may no longer request from the SSH CA.
- **There is no downgrade.** Take a backup and dump both databases first; going back means
  restoring them.
- **Containers.** `latest` is this release. To stay on it, name it:
  `MODULARCA_IMAGE=ghcr.io/dilenex/modularca:0.4.2`.

### Changes since 0.4.2-rc.1.0

**Added**

- **An expiry warning can be cleared without revoking the certificate.** A certificate that
  expires within 30 days, or expired in the last 30, with no replacement stayed on the
  dashboard's Needs attention list, and the only way off it was to revoke the certificate. Two
  ways now, both needing cert.revoke on the issuing CA, both audited and both undone from the
  certificate's page. Neither revokes anything or changes the CRL and OCSP answers.
  - **Dismiss**, on the dashboard row or the certificate's page, silences the warning and the
    expiry e-mails. The certificate can still be renewed by hand, by auto-renewal or by its
    client.
  - **Retire**, on the certificate's page, with an optional reason, also stops every renewal
    from it. The console, the user portal, the Infra API, auto-renewal and protocol renewals
    (EST re-enrollment and EST with the certificate as its credential, SCEP, CMP, Windows
    autoenrollment) refuse it, with `MCA-RES-008` or the `CertificateRetired` refusal. Its
    subject needs a new enrollment.

  The certificate list shows either state in place of "Not replaced", and its `replaced=no`
  filter leaves both out, as the lifecycle summary does; the summary counts them in a new
  `retiredOrDismissed`. The upgrade adds five nullable columns to `Certificates`.

**Changed**

- **The CMP request profile a new install seeds no longer requires approval.** CMP refuses a
  request whose request profile requires approval, because a CMP client cannot come back for a
  certificate approved later, so on a default install CMP refused every request. `Enterprise User
  (CMP)` is now auto-approved, like the EST and SCEP profiles. An existing install keeps its
  profile: where CMP is used, untick Require approval on it, or the client keeps seeing
  "Certificate issuance failed" and the CMP audit tab says why.
- **The console no longer offers the KRL fetcher.** It is not yet proven on a host, so the SSH
  CA key page says to copy the revocation list to each host by hand, before `RevokedKeys` names
  it, and so does the Admin UI guide. The fetcher's files still ship in `share/ssh-krl`.
- **A signed SSH certificate opens on its own page**, in the console and in self-service, with
  the certificate to copy or download, where to save it and a link to sign another. My
  Certificates links each SSH certificate's page.

**Fixed**

- **No SCEP client could verify a reply from an RSA CA.** The reply's signature named the
  algorithm the CA certificate was signed with, while the CA key signs with RSA-PSS by default.
  sscep, OpenSSL and BouncyCastle refuse such a reply. It now names the algorithm used, with its
  parameters. This predates 0.4.
- **An EST, SCEP or QR token created in the console was refused at every CA in a space.** The
  form sent a signing profile only for CMP, so every other token was an instance token. The form
  now asks where the token is accepted, offering what the console scope covers, and the token
  list shows it. The create endpoint takes `scope` and `scopeId` for the same; without them the
  selected profiles decide, as before.
- **A sign-in refused at the second factor was audited as OK.** An account locked or disabled by
  the time it completed TOTP, WebAuthn or mTLS was refused, but the `UserLoginFailed` entry was
  written as a success, so the audit log's Failed filter left it out.
- **The protocol audit tabs listed old entries first** after the General tab had been opened.
- **The request form's Not After started past the certificate profile's limit**, with a red
  warning before anything was typed under a short-lived profile. It now starts at a year or the
  limit, whichever is sooner.
- **A host certificate was explained as a user's.** It is now named for its host key in
  `/etc/ssh`, with the `HostCertificate` line `sshd_config` needs, and downloads under that name.
- **SSH:** an enabled SSH CA key showed "CA Key" as its status, the Sign key form offered a host
  for a key that signs user certificates only (and the reverse), and beside each login name the
  forms showed the key's limit above the profile's smaller one.
- **Wording:** the request profile list said "Optional" for SANs on a profile that allows none;
  the drawer of an issued request offered to approve or issue it; a request's page showed its
  profiles, and profile pages their CA, as ids.

### Security

- **SSH CA private keys are held by the signer**, which builds and signs every SSH certificate
  from its fields. The node holds no SSH CA key and runs no program; `ssh-keygen` is no longer
  used. The signer checks the ceremony before it generates an SSH CA key, and refuses a
  certificate of the wrong type, one valid for longer than the key allows, one without a
  principal and one with an option it does not know.
- **SSH login names.** A certificate for a user carries only the login names that user holds:
  their own username where the key allows it (never `root`), and the names granted to them or
  their groups on that SSH CA key. The CA writes every key id, which `sshd` logs with each login.
  Taking a name or the right to request away revokes the certificates that depended on it, at
  once, and a sweep every 15 minutes catches what a missed step left live.
- **Hosts can follow revocation.** Each SSH CA key publishes its KRL, with the time of each
  revocation, for `sshd`'s `RevokedKeys`; copy it to each host. `modularca-krl-fetch`, a script
  with a systemd timer that installs the KRL on a server every minute, ships in `share/ssh-krl`
  but is not yet proven on a host, and the console does not offer it.
- **A new user certificate permits a terminal and nothing else.** On a new install, agent and
  port forwarding are in a separate seeded profile, attached to nothing until an administrator
  attaches it. An upgraded instance keeps its SSH profiles as they were; the signing profile
  created with each new SSH CA key grants a terminal only.
- **The request profile is enforced by the server** when a request is submitted, approved and
  issued, on the names the certificate will carry, overrides included. A child request profile
  is never looser than its parent, and renewals and reissues keep the profile the request was
  made under.
- **The node's secrets** (the JWT secret, the LDAP bind password, the mail credentials and the
  webhook endpoints) are stored wrapped by the signer, and the integration API keys as hashes.

### Added

- **Settings in the database**, versioned and audited, with `--settings` on the host as the way
  back in when a setting locks the administrators out. The Settings page says beside each setting
  whether a change applies at once or at the next start, and fourteen that waited for a restart
  now apply at once.
- **Named API keys** for the infrastructure API and the cert-manager issuer, generated, shown
  once, scoped, time-limited and revoked one at a time. **The JWT secret can be rotated** from the
  console.
- **SSH:** a review date on each SSH CA key, the time of each revocation, a KRL that answers 304
  while nothing changed, a user or host type on SSH profiles, a way to find a certificate from a
  host's log line, and SSH login names on the user and group pages.
- **Certificate profiles:** four purpose-specific ones (`TLS Server`, `Device Client`,
  `User Authentication and Email`, `Code Signing`) that the seeded request profiles default to.
  A CA chooses the profiles its OCSP responder, TSA signer and CMP signer are issued under, and
  the profiles the application depends on keep their names and the usages their certificates
  need.
- **The request form asks for the profiles first**, offers only the keys they accept, and says
  beside them what the profiles allow.
- **Approvals:** the request page and form say how many approvals a request needs and whether
  anyone can give them. Answering "Just me" in setup lets a system super-administrator approve
  their own requests, and the console says when that outlives a single administrator.
- **Log tables refresh**, by hand or every 30 seconds.
- `scripts/test-enrollment-protocols.sh --enforcement` checks that each protocol refuses what its
  request profile forbids.

### Changed

- **SSH lives in tabs** on Authorities, All Certificates and Request Certificate, and in
  self-service on Request Certificate and My Certificates. The SSH CA menu is gone; the old
  addresses redirect.
- **An SSH certificate carries exactly the extensions its profiles name**; `ssh-keygen` used to
  add five. Its validity starts five minutes before issue, and a KRL download always answers 200
  with a valid KRL.
- **New SSH CA keys are user or host, not both**, with a longest certificate of 24 hours for
  users and one year for hosts.

### Fixed

- **ACME: certbot and Caddy can finalize an order.** Their request has an empty subject, which the
  seeded request profile refused.
- **The SAN rules of the seeded request profiles were never enforced**, "at least one SAN" could
  not trigger on the protocols, and a profile listing no SAN type allowed every type.
- **Opening the host name from outside the network answered 403** instead of redirecting to the
  public portal.
- A CA that named a profile shorter than ten years could not issue its infrastructure
  certificates, and the admin request profile pages misread and could overwrite a seeded
  profile's SAN rules.

### Removed

- The `ssh-keygen` dependency, the `SshCa` settings, `PUT /api/v1/admin/config/ssh-ca`, the SSH CA
  card on the Settings page, and `openssh-client` from the container image.

### The builds on the way

#### 0.4.2-dev.1.12 — 2026-10-19

One fix on top of `0.4.2-dev.1.11`.

**Fixed**

- **Opening the host name from outside the network answered 403 instead of the portal.** The bare
  root `/` only redirects to `/public/`, but the IP allowlist put it under the System rule
  (private ranges and loopback by default). It follows the Public Portal rule now: open wherever
  the portal is open, closed where an operator closed the portal.

#### 0.4.2-dev.1.11 — 2026-10-16

Fixes from a review of the request profile enforcement and the per-CA infrastructure profiles,
self-approval wired to the single-administrator setup answer, an upgrade-check note about
enrollment clients, and two build fixes, on top of `0.4.2-dev.1.10`.

**Changed**

- **A request profile that requires approval now holds on the console too.** A request made from
  the console (Generate Key Pair, a pasted or uploaded CSR, a key the CA generates) or a renewal,
  under a profile that requires approval, starts as Pending Approval, and issuance refuses any
  request whose profile requires approval until it is Approved, whatever route it came by. Before,
  only the enrollment protocols waited, and an operator could issue a console request that no one
  had approved. Approving one's own request is refused unless Allow System Super Self-Approval is
  on (below).
- **The single-administrator setup answer allows self-approval, and a self-approval completes the
  request.** Answering "Just me" in setup (or `Administration.MultipleAdministrators: false`) now
  also turns on Allow System Super Self-Approval, as it turns key ceremonies off; "Several people"
  turns it off. With it on, a system-super's approval of their own request completes it whatever
  the profile's count, since nobody else could add to it; it is still an explicit, step-up approval,
  never automatic, audited with `SelfApproved` and shown as Self-approved in the request's history.
  Existing installs keep their current setting: a single-administrator instance turns it on in
  Settings › Security.
- **A request profile that inherits is never looser than its parent.** Subject rules merge field
  by field, keeping the stricter requirement (Optional, Required, Forbidden), the parent's fixed
  value and pattern, and the shorter maximum length. SAN rules allow only the types both allow,
  require a SAN when either does, and keep the parent's pattern and the lower count. A default
  certificate profile the parent does not designate gives way to the parent's. Before, a child's
  own rules replaced the parent's, and a child created in the console never took the parent's
  SAN rules at all.

**Fixed**

- **Renewals dropped the request profile and what it settled.** Self-service renewal, admin
  renewal and automatic renewal copied the original CSR but not the request profile, the subject
  and SAN overrides or the requested extensions, and issuance builds the names from the CSR: a
  value the profile fixed (since `0.4.2-dev.1.9` delivered as an override) went back to what the
  CSR said, and nothing checked the renewal against the profile. They carry all of it now, and an
  automatic renewal under a profile that requires approval waits for approval.
- **A reissue's second request row carried no request profile, overrides or SANs**, so the next
  reissue of that certificate was not checked against the profile, and could be issued without its
  SANs when the lookup found that row. The row carries them, and reissue and renewal read the
  original request first.
- **The infrastructure profile checks read a profile's own usages; issuance uses them after
  inheritance.** A seeded or CA-named profile that inherited from one without the usage passed the
  checks and issued a responder or TSA certificate without it. The CA page, its save, CA creation
  and the profile edit guard judge the usages after inheritance, an edit to a parent is refused when
  a profile that inherits from it would lose the usage, and CA creation checks the issued TSA and
  OCSP certificates as reissue does.
- **Policy import and sync bypassed the name lock and the usage guard.** A YAML entry could turn a
  name-bound profile into a CA profile or strip the usage from one a CA issues from. Such an entry
  is skipped with an error now.
- **The certificate profile list named CAs of other spaces.** A profile's "In Use" lines name only
  the CAs the caller can see and count the rest.
- **The container image had not built since `0.4.2-dev.1.4`.** It moved only `share/sql` out of the
  unpacked tarball, and `share/` also holds the KRL fetcher; it moves both now.
- **Every build stopped at restore**: `System.Security.Cryptography.Pkcs` 10.0.0, which Kerberos.NET
  and MimeKit bring, has a high-severity advisory (GHSA-846f-f764-76mx). The build references the
  patched 10.0.13.

**Added**

- **The console says whether a request can be approved.** The request page shows the approvals a
  request needs (it showed "?" before), whether its requester may approve it alone, and warns when
  fewer people can approve it than it needs. The request form says the same before a request is
  made, under profiles that require approval. New endpoints:
  `GET /api/v1/admin/requests/{id}/approval-outlook` and `GET /api/v1/admin/requests/approval-outlook`.
  The request list carries `approvalCount`, `requiredCount`, `requestProfileId` and
  `renewalOfCertificateId`, and the dashboard marks pending renewals.
- **Settings and the dashboard say when single-administrator settings outlive one administrator.**
  With more than one system super-administrator and self-approval still on, or key ceremonies still
  off, the dashboard shows a banner and Settings a hint (`GET /api/v1/admin/security-policy/administrators`).
  The request profile page says when self-approval applies.
- **`--upgrade-check` notes which enrollment clients the request profiles will refuse.** It replays
  the certificates each protocol issued in the last 90 days, found in the audit database, against
  the request profile that protocol uses now, with the rules issuance applies, and lists the ones
  whose next request would be refused, by protocol, CA and profile, with examples and the reason.
  It never changes the verdict.
- `scripts/test-enrollment-protocols.sh --enforcement` follows each enrolment that issues with
  requests the seeded profile refuses (EST without a SAN and with an email SAN, CMP with a DNS
  SAN). The EST HTTP Basic request carries `DNS:<username>`, which the seeded EST profile requires.

#### 0.4.2-dev.1.10 — 2026-10-10

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

#### 0.4.2-dev.1.9 — 2026-10-10

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

#### 0.4.2-dev.1.8 — 2026-10-09

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

#### 0.4.2-dev.1.7 — 2026-10-09

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

#### 0.4.2-dev.1.6 — 2026-10-09

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

#### 0.4.2-dev.1.5 — 2026-10-09

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

#### 0.4.2-dev.1.4 — 2026-10-08

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

#### 0.4.2-dev.1.3 — 2026-10-08

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

#### 0.4.2-dev.1.2 — 2026-10-07

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

#### 0.4.2-dev.1.1 — 2026-10-07

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

#### 0.4.2-dev.1.0 — 2026-10-07

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

#### 0.4.1-dev.1.7 — 2026-10-07

**Changed**

- The Restart Application card on the Settings page says what a restart is for now: the
  settings marked Restart, a rotated JWT secret, and a restored backup. It named logging and
  HTTP, most of which apply without one.

#### 0.4.1-dev.1.6 — 2026-10-07

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

#### 0.4.1-dev.1.5 — 2026-10-06

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

#### 0.4.1-dev.1.4 — 2026-10-06

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

#### 0.4.1-dev.1.3 — 2026-10-06

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

#### 0.4.1-dev.1.2 — 2026-10-06

**Fixed**

- **The move no longer stores a default an earlier build wrote.** A `config.yaml` written
  before the project's repository moved carries the old address as `SourceCode.Url`. Nobody
  chose it: it was that build's default, and the page already publishes the new address for
  it. dev.1.0 stored it in the database as if it had been chosen. The move now leaves it out,
  and the control role's next start clears it where it was stored, with a history entry saying
  why. An address an operator set for their own fork is stored as before.

#### 0.4.1-dev.1.1 — 2026-10-06

**Added**

- **Log tables can be refreshed.** A log shows what had happened when the page was opened, so
  a new entry did not appear until the page was reloaded. The table header now has a Refresh
  button and an "Auto 30s" switch, on the Audit Logs page (every tab), the ACME audit section
  and the audit tables on record pages.
  - Rows stay on screen while they reload.
  - Auto-refresh is remembered per table, like its columns. It pauses while rows are ticked,
    while a row's drawer is open, and while the page is in the background.

#### 0.4.1-dev.1.0 — 2026-10-06

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
