# SSH defaults

Status: built 2026-10-08, for 0.4.2. The numbers were decided by the owner on 2026-10-08 and are
held by tests (`SshDefaultsTests`, `sshCaDefaults.test.ts`): changing one fails a test.

It belongs with `ssh-keystore.md` (who holds and creates a key), `ssh-login-names.md` (who may log
in as what) and `ssh-krl-delivery.md` (how a revocation reaches a host).

## Why

The SSH defaults were set one at a time. The console pre-filled 30 days for a new SSH CA key,
offered one key for both user and host certificates, turned agent forwarding on for everyone, and
spread one lifetime over four places with four numbers. This is the default setup as a whole.

Only what is created from now on changes. An install that already has SSH profiles keeps every
profile row it has, and every existing key keeps its limits.

## The one-place rule

A certificate's lifetime is the smallest of four numbers: the key's maximum, the signing
profile's, the certificate profile's and the request profile's, and then of what a login name
grant allows. That is unchanged. What is new is which of them a default install uses:

- **The key holds the hard ceiling.** `SshCaKeys.MaxValidityHours`. No profile and no grant can
  go over it, and the signer refuses a certificate that does.
- **The request profile holds the everyday number.** It is what a person asks through, so it is
  the one to edit.
- **The signing and certificate profiles in between are left at the ceiling.** They exist for
  other things: which key, which extensions, which principals.

To change how long people's certificates last, change the request profile. To change what can
never be exceeded, create a key with another maximum.

## A new SSH CA key

- **One type.** The console's form asks for a type, user or host, and creates a key that signs
  that type only. The two public keys go to different places (a user CA key to servers'
  `TrustedUserCAKeys`, a host CA key to clients' `known_hosts`), they need different lifetimes,
  and a leaked host CA key then cannot mint logins.
- **The longest certificate** is pre-filled from the type and follows it until it is edited:
  **24 hours** for a user key, **8760 hours** (one year) for a host key.
- **The API still takes both flags.** Existing keys may sign both, and scripts may send both.
  When `maxValidityHours` is omitted it is 24 for a key that signs user certificates, alone or
  with host certificates, and 8760 for a host-only key. The create answer now carries
  `maxValidityHours` and `reviewBy`, so a script sees what it was given.

`SshCaKeyDefaults` (`ModularCA.Shared/Utils/SshCaKeyDefaults.cs`) is the one place these numbers
are. The console has its own copy (`modularca.adminui/src/pages/sshCaDefaults.ts`), which a test
reads the C# file to check.

## The signing profiles created with a key

`SshCaService` writes a user signing profile, a host signing profile, or both, with the key.

- Both take the key's own maximum as `MaxValidityHours`. The user one used to be capped at 24
  hours whatever the key allowed; by the one-place rule it is now left at the ceiling.
- The user one's default extensions are `["permit-pty"]`. They used to include
  `permit-agent-forwarding` and `permit-port-forwarding`. Agent forwarding lets a compromised
  server use the holder's access to other servers for as long as the session lasts, so it is no
  longer given to everyone who asks for nothing.

## The profiles seeded on a new install

`BootstrapProfileSeeder.SeedDefaultSshProfiles` runs only when no SSH certificate profile exists.
No migration edits a profile row.

| Profile | Lifetime | What it holds |
|---|---|---|
| `SSH User Cert - Standard` | 24 h | Any valid login name, at most 3. Allows `permit-pty` and `permit-user-rc` |
| `SSH User Cert - Forwarding` | 24 h | As Standard, with all five `permit-*` extensions allowed and `permit-port-forwarding` and `permit-agent-forwarding` required |
| `SSH Host Cert - Standard` | 8760 h | Hostname patterns, at most 10. Unchanged |
| `SSH User Request - Default` | **12 h** | Over Standard only. No approval |
| `SSH Host Request - Default` | 8760 h | Over the host profile. Unchanged |

- **The principal pattern is the login name grammar.** `SshLoginNameRules.Pattern` is the regular
  expression for what `SshLoginNameRules.IsValid` accepts, and the seeder writes that. The pattern
  seeded before was a lower-case POSIX one of 32 characters, which refused names a grant allows
  (`Deploy`, `svc.backup`, `ops@corp`). A test holds the pattern and the rule to the same answer
  for every character. In .NET the pattern's `$` also matches before one final line feed; the
  rule refuses that name and the signer refuses a control character in any principal.
- **An allowed list that is not empty is the whole list.** `SshExtensionPolicy` reads an empty
  `AllowedExtensions` as no restriction and a non-empty one as exactly those names. Standard's
  list is not empty, so a request through it that asks for a forwarding extension is refused
  with 400 on both the self-service and the admin route.
- **Forwarding is seeded but attached to nothing.** It is in no request profile's list. An
  administrator adds it to a request profile where forwarding is wanted; a person who then
  chooses it gets a certificate with both forwarding extensions and, from the signing profile's
  default, a terminal.

## The review date

An SSH CA key does not expire, and nothing rotates it. `SshCaKeys.ReviewBy` (UTC, nullable) is a
date that reminds.

- **Set at creation**: the creation time plus **2 years** for a key that signs user certificates,
  alone or with host certificates, and plus **5 years** for a host-only key.
- **Existing keys.** Migration `20261009061612_SshCaKeyReviewBy` adds the column and sets it by
  the same rule from each key's `CreatedAt`, counted in UTC. A key older than that gets a date
  already past, and is shown as due.
- **It never acts.** Nothing is disabled, refused or revoked because of this date. Signing, KRLs
  and every check behave the same before and after it. Only the route below, the creation, the
  reminder and the pages read the column, and a test fails when another source file names it.
- **Moving it.** `PUT /api/v1/admin/ssh/ca-keys/{caKeyId}/review-by` with `{ "reviewBy": "..." }`.
  The date must be in the future and at most 10 years ahead, otherwise 400. It needs `ca.manage`
  on the key's CA, and a key outside the caller's fence is 404, as on the other key routes. The
  audit entry is `SshCaKeyReviewDateChanged`, with the new date and the one before.
- **No step-up MFA.** The route changes a reminder and nothing else, so it is named in
  `StepUpGuardTests.DeliberatelyOpen` with that reason.
- **Read.** `GET /api/v1/admin/ssh/ca-keys` answers `reviewBy` per key. There is no separate
  route for one key; the key's page reads the list. The public key list does not carry it.
- **The console.** The key's page has a Review section with the date, the sentence that nothing
  stops working on it, and, for whoever may manage the SSH CA, a date field that moves it. From
  90 days before the date, and after it, the page and the key list show an amber badge and the
  page a warning. A disabled key is never shown as due.
- **The reminder.** The daily `CertExpiryNotification` job also looks at SSH CA keys. It tells
  the administrators once about each enabled key whose date is within 90 days or past (event
  `SshCaKeyReviewDue`, by e-mail and to webhooks), and once more for each date the key is moved
  to. The `NotificationLogs` row is keyed by the key and its review date. It runs only while
  e-mail and expiry notifications are enabled, as certificate expiry does.

## Recommended setup

- Two keys: one of type user, one of type host.
- User certificates: 12 hours by default (the request profile) and 24 hours at most (the key).
  A sensitive login name such as `root` is granted with a limit of 1 hour.
- Host certificates: one year. Each is signed by hand, so a shorter life would be more work than
  it is worth. An expired host certificate does not lock anyone out: clients ask about the host
  key again, as they do for a host with no certificate.
- Forwarding only through the Forwarding profile, attached to a request profile for the people
  who need it.

## Not done here

- Host certificate renewal, rotation of SSH CA keys, and an approval workflow.
- A switch that turns the review reminder off on its own. It follows the expiry notifications.
- Refusing a key that signs neither type through the API. The console never sends one.

## Tests

- `SshDefaultsTests`: the key's default maximum by type, through the create route and through a
  ceremony; both signing profiles at the key's maximum; the user profile's default extensions;
  the seeded profiles, value by value; an install that has a profile is seeded nothing; the
  pattern is the grammar; a request through Standard is refused forwarding; Forwarding is not
  offered until attached and then yields both forwardings and a terminal; the review date at
  creation; the route's rights, fence, refusals, audit entry and that nothing else changes; a
  key past its date signs, revokes and serves its KRL as before; the reminder.
- `PostgresUpgradeHarnessTests.The_ssh_ca_key_review_date_is_set_from_each_key_s_creation_and_no_profile_or_other_column_changes`.
- `StepUpGuardTests`: the route is open on purpose, with its reason.
- `sshCaDefaults.test.ts`: the form's type and pre-filled hours, the body it sends, when a key is
  shown as due, and that the console's numbers are the server's.
