# Changelog

All notable changes to ModularCA are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning: a new capability is a minor release, a fix is a patch.

## [Unreleased]

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
