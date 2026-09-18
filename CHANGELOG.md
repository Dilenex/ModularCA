# Changelog

All notable changes to ModularCA are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning: a new capability is a minor release, a fix is a patch.

## [Unreleased]

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
