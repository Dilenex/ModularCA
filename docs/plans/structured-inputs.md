# Structured inputs: replacing raw JSON and text lists

Status: **complete.** Steps 1–5 are done (see the results sections below). Every J, L and D item is
closed; D7 stays as it is, by design. What remains is listed under "Remaining" in "Step 5 results":
server-side checks of request profile rules, and the `RoleDetail` resource picker. This inventory
was taken on 2026-10-04 (branch `0.4.0-dev`, after `e87073f`).
Each finding is marked for refactoring into a structured control. **[PROFILE]** marks findings
inside the unified profile forms (`modularca.adminui/src/pages/profiles/*`); line numbers are a
snapshot and will drift.

What the sweep did not find: no inputs in publicui, one search box in docsui, nothing JSON-shaped in
`shared/*`, and only SAN lists in setupui.

## Summary

| # | Screen › section | Field | Current input | Proposed control | Effort | Risk if left |
|---|---|---|---|---|---|---|
| J1 **[PROFILE]** | Signing profile | Name Constraints Permitted / Excluded (JSON) | 1-line text, JSON array of `"TYPE:value"` | Typed row editor (TYPE + value), Permitted and Excluded | M | **High**: invalid JSON throws at CA-cert build; bad entries silently dropped, so the constraint is weaker than intended |
| J2 | CAs › Create CA › Name Constraints | Permitted / Excluded subtrees | 2 textareas, one per line | Same component as J1 | S after J1 | **High**: no validation; unknown prefixes dropped; a bad IP fails creation, possibly only at ceremony execution after approvals |
| J3 **[PROFILE]** | Signing profile | Policy qualifiers (JSON) | 8-row textarea, JSON object | "Certificate Policies" table, merged with J4 | M | **Med**: malformed or misspelled keys silently ignored; the per-OID `critical` flag is really extension-wide |
| J4 **[PROFILE]** | Signing profile | Policy OIDs (comma-separated) | text → JSON array | Rows of the J3 table, with an OID check | (in J3) | **High**: one invalid OID makes every issuance under the profile throw |
| J5 **[PROFILE]** | Cert profile | CT Log IDs | text, JSON array of GUIDs | Multi-select from the CT log catalog | M (L with a CT-log admin page) | **High**: malformed input disables all CT submission, contrary to the hint; no UI to discover the GUIDs |
| J6 | Settings › LDAP Authentication | Group to Role Mappings (JSON) | text, JSON object | Key/value table: LDAP DN → local group select | M | **Med**: unknown group names pass and grant nothing; stale placeholder |
| J7 | Request profile › Rules › Advanced (JSON) | Whole rules object | 12-row textarea (deliberate escape hatch) | Keep, as Import/Export | S | Low |
| L1 **[PROFILE]** | SSH signing profile | Source Address Restrictions (comma-separated) | text | Chip list, CIDR/IP check | S | **Med**: certs issued that sshd rejects at login |
| L2 **[PROFILE]** | SSH cert profile | Allowed Principal Patterns (regex per line) | textarea | Chip list, regex compile check, test box | S | **Med**: invalid regex never matches (fails closed) |
| L3 | Settings › Certificate Policy | Forbidden Algorithms | comma text | Multi-select of signature algorithms + free add | S | **High**: placeholder values never match; separators eaten while typing |
| L4 | Settings › Certificate Policy | Algorithm Sunset Rules | textarea, `ALG:YYYY-MM-DD` | Row editor: algorithm + date | S–M | **Med**: bad rules skipped with only a log line |
| L5 | Settings › Compliance Scan | Deprecated Algorithms | comma text | Chip list / multi-select | S | Low |
| L6 | Settings › Cert Expiry Notifications | Warning Days | comma text | Numeric chip list | S | **High (bug)**: reads the wrong property and sends a string to `List<int>`; probably unsaveable |
| L7 | Settings › Email | Admin Recipients | comma text | Email chip list | S | **Med**: no validation, alerts fail at send |
| L8 | Notifications › preference | Override Recipients | comma text (client-validated) | Email chip list | S | Low |
| L9 | Settings › HTTP | CORS Origins | comma text | Origin chip list | S | Low–Med |
| L10 | Settings › mTLS | Required Paths; Trusted CA Cert Paths | comma text | Chip lists | S | **Med**: separators eaten |
| L11 | Settings › IP Whitelist | Exempt Paths | comma text | Chip list | S | **Med**: a wrong prefix silently opens a path |
| L12 | Settings › Network Audit | Exclude Paths | comma text | Chip list | S | Low |
| L13 | Whitelists | CIDRs (one per line) | textarea | Chip list | S | Low (already validated) |
| L14 | SSH Certificates › Sign | Principals / Hostnames | comma text | Chip list | S | Low |
| L15 | Enrollment › token create | Subject / SAN Restriction | text | Typed row editor: DNS domain, or DN `attr=value` | S–M | **Med–High**: the server splits on whitespace, so `O=Acme Corp` adds a `Corp` pattern and widens the restriction (verify) |
| L16 | Web TLS › Reissue | SANs (`TYPE:value` per line) | textarea | SAN row editor | S–M | Low |
| L17 | Certificate reissue modal | SANs | textarea | SAN row editor | S | Low |
| L18 | setupui › Web TLS Certificate | SANs | textarea | SAN row editor (in `shared/common`) | S | Low |
| L19 | setupui `Features.tsx` | API cert SANs | textarea | Delete: not rendered | S | None |

## JSON inputs

### J1. Signing profile: Name Constraints Permitted / Excluded **[PROFILE]**
- UI: `profiles/SigningProfileForm.tsx` (~59-68); `profileHelpers.tsx` `NAME_CONSTRAINTS_HINT` /
  `NAME_CONSTRAINTS_PLACEHOLDER`; state in `profiles/signingProfile.ts`.
- Who: create needs `ca.manage` on the issuer; update needs CaAdmin plus step-up
  (`AdminSigningProfileController.cs`).
- Shape: JSON array of `"TYPE:value"`. TYPE is `DNS | IP | EMAIL | URI | DN`, case-insensitive.
  DN values go through `DnComponentSanitizer`.
- Server: `CreateSigningProfileRequest.NameConstraintsPermitted/Excluded` (string), stored
  verbatim; parsed in `CertificateBuilderService.ParseSubtrees` (~623-654) from
  `AddPolicyExtensions`, only when the certificate built is a CA. The UI never says so.
- Validation: none on either side.
- Failure modes:
  - Non-array text throws at CA-cert build time.
  - Entries with no `:` or an unknown TYPE are silently dropped.
  - If every entry drops, an empty subtree list may be emitted; RFC 5280 forbids that (verify).
  - A bad IP likely throws inside BouncyCastle.
- Inconsistency: this hint shows `EMAIL:example.com` and `IP:addr/mask`, while J2 shows
  `Email:@example.com` and `IP:10.0.0.0/8`. The same parser reads both.
- Proposal: a `NameConstraintsEditor` (Permitted and Excluded sections). Each row is a TYPE select
  plus a value with per-type validation (hostname or `.domain`; v4/v6 CIDR; mailbox, domain or
  `.domain`; URI host; RFC 4514 DN). It serializes to the same JSON, and notes that constraints
  apply to CA certificates only.
- Server hardening: run `ParseSubtrees` at save and return 400.

### J2. Create CA: Name Constraints
- UI: `CaManagement.tsx` (~541-580; state ~96-133; body ~297-298).
- Shape: `List<string>` of `TYPE:value`.
- Server: `AdminCaController` create-root and create-intermediate, plus the ceremony path
  (`AdminKeyCeremonyController.cs` ~665-695), into `CaCreationService.BuildNameConstraints` →
  `ParseSubtrees`, copied onto the CA's signing profile.
- Validation: none.
- Failure modes: unknown prefixes are dropped. Malformed IP or DN values throw at creation; on the
  ceremony path that is at execution, after approvals were collected. `Email:@example.com` is
  likely not a valid rfc822Name constraint (verify).
- Proposal: the J1 component.

### J3 + J4. Signing profile: Policy OIDs and Policy qualifiers **[PROFILE]**
- UI: `profiles/SigningProfileForm.tsx`; `profiles/signingProfile.ts` (`policyQualifiersError`).
- Shape:
  - `PolicyOids`: JSON array of dotted OIDs.
  - `PolicyQualifiersJson`: `{ "<oid>": { "cpsUri", "userNotice", "critical" } }`.
- Server: stored verbatim (`SigningProfileService`, plus YAML via `PolicySyncService`). Parsed for
  every certificate in `CertificateBuilderService` (~492-556): `new DerObjectIdentifier(oid)`.
- Validation: qualifiers must be a JSON object (client only). OIDs are not checked.
- Failure modes:
  - **One malformed OID fails every issuance under the profile.**
  - Malformed qualifier JSON written through the API or sync is swallowed.
  - A misspelled key, or a qualifier for an OID not listed, is silently ignored.
  - Any `critical: true` makes the whole extension critical.
- Proposal: one "Certificate Policies" table, one row per policy, with columns OID (dotted check),
  CPS URI (http/https), and user notice (≤ 200 chars). A single "mark extension critical"
  checkbox, and optional suggestions (anyPolicy, CA/B DV/OV/EV). It serializes to the same two
  fields.
- Server hardening: validate both at save.

### J5. Cert profile: CT Log IDs **[PROFILE]**
- UI: `profiles/CertProfileForm.tsx`; `CT_LOG_IDS_HINT`.
- Shape: a JSON array of internal CT-log **GUIDs** (`CtLogEntity.Id`), not RFC 6962 LogIDs. The
  label invites the wrong thing.
- Server: stored verbatim, merged across inheritance (`ProfileResolutionService`), parsed in
  `CertificateIssuanceService` (~983) as `List<Guid>`.
- Failure mode: the JsonException is caught by the outer catch, so **no CT submission at all** for
  the profile, contrary to the hint. It shows only as a warning log and audit entry.
- Catalog gap: there is no CT-log page in the console, and `GET /admin/ct-logs` is SystemOperator
  only.
- Proposal: a checkbox multi-select of logs (name, URL, enabled); empty means every enabled log.
  Needs a read endpoint profile editors can call (e.g. `GET /ct-logs/options` under CaAuditor).

### J6. Settings › LDAP Authentication: Group to Role Mappings
- UI: `Settings.tsx` (~1149-1152, super only).
- Shape: `{ "<LDAP group DN>": "<local group name>" }`.
- Server: `PUT /admin/config/ldap-auth` and `AdminLdapController`. Validated by
  `LdapGroupSyncService.ValidateMappingsAsync`: 400 on bad JSON, or when the target is a system or
  controlled group.
- Failure mode: a target group that doesn't exist passes and grants nothing.
- Problems: the placeholder uses the old role name `CaAdmin`, and a DN can map to only one group.
- Proposal: a key/value table. Left: DN, with syntax and duplicate checks. Right: a local-group
  select that excludes system and controlled groups, mirroring the server.

### J7. Request profile rules: Advanced (JSON)
- UI: `components/RequestProfileRulesEditor.tsx`.
- Server: typed DTOs, so a bad shape gets a 400. A client parse error already blocks Save.
- Proposal: keep it, reframed as Import/Export ("Copy as JSON", and "Paste JSON…" with a preview
  and Apply).

## List-as-text inputs

**Settings bug affecting L3, L4, L5, L10, L11 and L12:** `Settings.tsx` (~124-129) splits and
re-joins the list on every keystroke, so a trailing comma or newline vanishes as soon as it is
typed. A second item can only be added by pasting. A chip list removes the bug.

| # | Where | Server type and parser | Failure mode | Proposal |
|---|---|---|---|---|
| L1 **[PROFILE]** | `profiles/SshSigningProfileForm.tsx` | JSON-array string → `source-address=` (`AdminSshController`, `UserSshController`) | Bad CIDR → certs sshd rejects | Chip list, CIDR check |
| L2 **[PROFILE]** | `profiles/SshCertProfileForm.tsx` | JSON-array string → `ProfileRegex` | Invalid regex never matches; JS and .NET dialects differ | Chip list, compile check, test box |
| L3 | `Settings.tsx` Forbidden Algorithms | `List<string>`, exact match against signature algorithm names (`CertPolicyService`) | Placeholder `MD5, SHA1` matches nothing | Multi-select + free add |
| L4 | `Settings.tsx` Algorithm Sunset Rules | `List<string>` (`CertPolicyService` ~113-160) | Bad rules skipped with a log line | Row editor: algorithm + date |
| L5 | `Settings.tsx` Deprecated Algorithms | `List<string>` | Reports only | Chip list |
| L6 | `Settings.tsx` Warning Days | GET `warningDaysBeforeExpiry`; PUT `WarningDays: List<int>` | **UI uses `warningDays`, sends a string** | Numeric chip list; fix the property |
| L7 | `Settings.tsx` Admin Recipients | string split on `,` (`EmailService`) | No validation | Email chip list |
| L8 | `NotificationManagement.tsx` Override Recipients | string split (`NotificationService`) | Client-validated | Email chip list |
| L9 | `Settings.tsx` CORS Origins | string split at startup | Typo silently breaks CORS | Origin chip list |
| L10 | `Settings.tsx` mTLS paths | `List<string>` | Separators eaten | Chip lists |
| L11 | `Settings.tsx` IP Whitelist Exempt Paths | `List<string>` | Wrong prefix opens a path | Chip list (must start with `/`) |
| L12 | `Settings.tsx` Network Audit Exclude Paths | `List<string>` | Separators eaten | Chip list |
| L13 | `Whitelists.tsx`, `WhitelistDetail.tsx` CIDRs | `List<string>`, validated both sides | Fine | Chip list (low priority) |
| L14 | `SshCertificates.tsx` Principals / Hostnames | `List<string>` | Client-checked | Chip list (low priority) |
| L15 | `EnrollmentManagement.tsx` Subject / SAN Restriction | string; `EnrollmentNameRestriction.ParsePatterns` splits on `, ; space tab newline` | **Spaces split a DN value into an extra pattern that widens the token** (verify) | Typed row editor; quote values or reject spaces |
| L16 | `WebTlsManagement.tsx` SANs | `List<string>`, validated at build | Fine | SAN row editor from `CertificateRequestForm.tsx` |
| L17 | `CertificateReissueModal.tsx` SANs | `newSans: List<string>` | Fine | SAN row editor |
| L18 | setupui `WebTlsCertificate.tsx` SANs | `sans: string[]` | Fine | SAN row editor in `shared/common` |
| L19 | setupui `Features.tsx` | `apiCertSans` | Not rendered | Delete |

Related: `RoleDetail.tsx` "Resource Type" and "Resource ID" take a raw type string and GUID. A type
select plus a resource picker would be safer.

## Display-only JSON (lower priority)

| # | Where | Shown | Suggestion |
|---|---|---|---|
| D1 **[PROFILE]** | `SigningProfileDetail.tsx` | Name constraints, policy qualifiers as raw JSON | Read-only J1 rows and J3 table |
| D2 **[PROFILE]** | `CertProfileDetail.tsx` | CT log GUIDs | Resolve to names via the J5 catalog |
| D3 | `AuditLogs.tsx` drawer, `AuditLogDetail.tsx` | `detailsJson` as one mono string | Nested label/value rows |
| D4 | `Dashboard.tsx` (`parseJsonSafe`) | Flattened `k: v`; nested values render `[object Object]` | The D3 renderer |
| D5 | `AcmeManagement.tsx` audit drawer | `JSON.stringify(v, null, 2)` | The D3 renderer |
| D6 | `Ceremonies.tsx` CaCreation parameters | **Name constraints, cert profile and public base URL are not shown to approvers** | Show them (security-relevant: do before D3–D5) |
| D7 | publicui `AcmeDirectory.tsx` | ACME `meta` | Fine as is |

## Shared components to build first

All in `shared/common/src/components/`, so setupui can use them. Today the only primitives there are
`inputClass`, `labelClass`, `FieldHint` and `ToggleField`; there is no chip, list or key/value
editor in the repo.

1. **`validators.ts`** (S). Collect `looksLikeHostname`, `CIDR_REGEX` (duplicated in the two
   whitelist pages) and `EMAIL_REGEX`. Add checks for OID, https origin, path prefix, regex compile
   and `TYPE:value` general names.
2. **`ChipListInput`** (S–M). Value is `string[]`, with per-item validation, split on paste,
   deduplication, optional suggestions and a numeric mode. Covers about 14 fields and removes the
   Settings separator bug.
3. **`TypedEntryListEditor`** (M). Extracted from the SAN rows in `CertificateRequestForm.tsx`.
   Covers J1, J2, L15, L16, L17 and L18, including the two highest-risk fields.
4. **`RowTableEditor` / `KeyValueTable`** (M). Covers J3+J4, J6 and L4.
5. J5 needs no new component, only `CheckboxList` (already in `shared/common`; it replaced
   `MultiToggle`) plus a CT-log options endpoint.

Order:
1. Validators and chip list.
2. Typed entry editor.
3. J5 with its endpoint.
4. Row table.
5. J7 and D1–D7.

## Server hardening alongside

Structured controls only protect the console. The admin API and the YAML policy sync can still
write malformed values. Validate these at save and return 400; the parsers already exist but run at
issuance:
- `NameConstraintsPermitted/Excluded`
- `PolicyOids`
- `PolicyQualifiersJson`
- `CtLogIds`
- `SourceAddressRestrictions`
- `AllowedPrincipalPatterns`
- the CA-create name-constraint lists

## Step 1 results (2026-10-04)

Built: `shared/common/src/validators.ts` (now home of `looksLikeHostname`, `CIDR_REGEX`,
`EMAIL_REGEX`; `hostname.ts` re-exports), `shared/common/src/components/chipList.ts` (pure logic)
and `ChipListInput.tsx`. Invalid entries are kept as chips marked invalid, with their messages
listed under the field; pages block Save through `invalidItems()` or `onInvalidChange`.

| # | Done | Validator / note |
|---|---|---|
| L1 | ✓ | `validateIpOrCidr(…, { requireNetworkAddress: true })`; Save blocked. Server: `SshProfileFieldRules.ValidateSourceAddressRestrictions` at create and update (400). |
| L2 | ✓ | `validateRegex`, commas do not split (regexes use `{0,31}`); "Test a principal" box. Server: each pattern compiled as `ProfileRegex` builds it (`ProfileRegex.CompileError`, 400). |
| L3 | ✓ | Suggestions are the names the server produces (`SHA1withRSA`, …) plus free add; placeholder `SHA1withRSA`. |
| L4 | — | Left for step 4; newline-eating fixed with a textarea that keeps its own text (`LinesTextarea`). |
| L5 | ✓ | Suggestions `SHA1`, `MD5`, … plus free add. Server match fixed (see findings). |
| L6 | ✓ | Numeric chips, 1–3650, sorted descending; reads `warningDaysBeforeExpiry`, sends `warningDays: number[]` (`settingsLists.ts`, tested). Server: 1–3650 or 400. |
| L7 | ✓ | `validateEmail`; still stored comma-joined. Server: `MailAddress.TryCreate` per entry (400). |
| L8 | ✓ | `validateEmail`; Save disabled while invalid. Server: same check on the preference PUT. |
| L9 | ✓ | `validateOrigin` (https, http only for localhost / 127.0.0.1 / [::1], no path or trailing `/`). Server: same rules at save. |
| L10 | ✓ | `validatePathPrefix` and `validateAbsoluteFilePath`. |
| L11 | ✓ | `validatePathPrefix`. |
| L12 | ✓ | `validatePathPrefix`. |
| L13 | ✓ | `validateIpOrCidr` (host bits tolerated, as the whitelist matcher does); detail Save disabled with a reason. |
| L14 | ✓ | Chips marked when no profile pattern matches; the existing count/pattern check is kept. |

Findings that differed from, or went beyond, the inventory:
- **L6 was worse than "probably unsaveable".** GET returns `warningDaysBeforeExpiry`; the field read
  `warningDays`, so it always rendered empty and the card header showed a hard-coded
  `90,60,30,14,7` (the real default is `90,60,30,14,7,3,1`). Saving untouched sent no `WarningDays`,
  so only Enabled was written; typing any value sent a string, which cannot bind to `List<int>`, so
  `[ApiController]` returned 400. The marks could never be changed from the console (from reading
  the code; not reproduced live). The hint was also wrong: the job sorts the marks and fires every
  one crossed, not "the first match".
- **L5: the compliance scan never flagged SHA-1.** It substring-matches against BouncyCastle's
  `SigAlgName`, which is `SHA-1withRSA` (checked against BouncyCastle 2.7.0), so the shipped default
  `SHA1WithRSA` never matched. `ComplianceScanJob.MatchesDeprecatedAlgorithm` now ignores hyphens
  and blank entries. The old placeholder `RSA-1024` can never match a signature algorithm.
- **L3:** confirmed. Forbidden Algorithms is an exact, case-insensitive comparison with the CSR's
  signature algorithm as `CertificateUtil` names it. MD5 has no name there, so it can only be
  forbidden by OID (`1.2.840.113549.1.1.4`); the hint says so.
- **L9 was a startup risk, not only a CORS typo.** An origin the startup check rejects was saved by
  PUT and then threw `InvalidOperationException` at the next start. Both now share
  `ConfigInputRules.CorsOriginsError`; startup skips the bare-origin check so existing configs load.
  The old startup check compared `Uri.Host` with `::1`, but .NET returns `[::1]`, so
  `http://[::1]:port` was refused; it is now accepted.
- **L10:** the server ignores an empty Required Paths or Trusted CA Cert Paths list
  (`Count > 0` guard), so the last entry cannot be removed from the console. Not changed.
- **L13:** the client check is stricter than `CidrMatcher` for IPv4 shorthand (`10.1`) and leading
  zeros, which `IPAddress.Parse` accepts; a stored rule written that way shows as invalid on edit.

## Step 2 results (2026-10-04)

Built, all in `shared/common/src` so setupui can use them:
- `components/typedEntryList.ts`: the pure logic. Rows are `{ type, value }`; `parseTypedEntry`
  matches a type or alias in any case and returns the caller's canonical spelling;
  `entriesFromList` / `entriesToList` convert at the caller's boundary (blank rows dropped);
  `typedEntryError` / `hasTypedEntryProblems` (a blank row is never an error); `splitPastedEntries`
  and `insertPastedEntries` (lines or a JSON array of strings; commas never split, since a DN or
  URI may hold one); `sameEntryLists` compares in canonical spelling.
- `components/TypedEntryListEditor.tsx`: rows of a type select, a monospace value, a status icon
  and remove. Props: `value`, `onChange`, `types` (each `{ value, label, aliases?, validate?,
  placeholder?, example? }`), `offeredTypes` (a row keeps a type not offered, flagged),
  `defaultType`, `check` (`allowedTypes`), `validate` (off when the server validates), `rowStatus`
  (the caller's own valid/warning/error per row), `actions`, `onBlur`, `addLabel`, `emptyText`,
  `disabled`. Pasting several lines adds one row each; pasting `DNS:x` into an empty field sets the
  type. `TypedEntryListView` is the read-only rendering, marking entries the types would refuse.
- `generalNames.ts`: `NAME_CONSTRAINT_TYPES` and `validateNc*`, which mirror the server's new
  `NameConstraintRules`; `SAN_TYPES` (DNS, IP, Email with alias RFC822, URI, UPN) and
  `INFRA_SAN_TYPES` (DNS, IP) with `validateSan*`; the shared hint texts.
- `components/NameConstraintsEditor.tsx`: Permitted and Excluded sections, the hint, the line that
  constraints land only in CA certificates, and a warning when a non-DNS row is present (see
  below). `NameConstraintsView` renders stored constraints read-only.

| # | Done | Note |
|---|---|---|
| J1 | ✓ | Signing profile form; state is rows, body still the JSON-array string (null when empty), written in the server spelling (`EMAIL:`). Save blocked on an invalid row. |
| J2 | ✓ | Create CA; body still `List<string>`. Create blocked on an invalid row. |
| D6 | ✓ | Ceremony drawer shows the other subject parts, the CA cert profile (or what an unset one means; a root ignores it), the public base URL (or the fallback an unset one gets), and the name constraints through `NameConstraintsView`, "None" stated explicitly. |
| L15 | ✓ | Typed rows, "DNS domain" or "DN attribute" for the subject, domains only for SANs; server parser fixed (see below). The token drawer shows a stored restriction as the patterns the server now reads. |
| L16 | ✓ | Web TLS reissue: DNS and IP rows. |
| L17 | ✓ | Reissue modal: all five SAN types; rows are only validated (and only block) once the list differs from the certificate's. |
| L18 | ✓ | setupui Web TLS step: DNS and IP rows; Next blocked on an invalid row. |
| L19 | ✓ | `Features.tsx` deleted; nothing imported it. |
| — | ✓ | `CertificateRequestForm` uses the shared editor too, with its own checks off and the server's per-row results passed through `rowStatus`. |

Server hardening:
- `ModularCA.Shared/Utils/NameConstraintRules.cs` is now the one parser: `CertificateBuilderService.ParseSubtrees`
  delegates to it, and the save-time checks call it. 400 on any entry it refuses at signing
  profile create and update, CA create-root and create-intermediate (before the ceremony branch),
  and generic ceremony initiation (`RefuseCaCreationParametersAsync`). YAML policy sync skips such
  a profile with an error.
- Enrollment token create: 400 for a restriction `EnrollmentNameRestriction.RestrictionError`
  refuses (bad domain, wildcard, a DN pattern in the SAN restriction, over the column length).
- Web TLS reissue: 400 for a SAN that is not `DNS:` or `IP:`, which the infrastructure CSR builder
  used to drop without a word.

Name-constraint forms (what the server actually did, checked against BouncyCastle 2.7.0):
- **IP.** `new GeneralName(IPAddress, string)` took both `10.0.0.0/8` and `10.0.0.0/255.0.0.0`,
  with identical encodings, so both old hints were right. It also took a non-contiguous mask,
  host bits (`10.0.0.1/8`), leading zeros, and a bare address, which it encoded as a 4- or 16-byte
  value where RFC 5280 requires address plus mask. Now: both forms, contiguous masks, the network
  address, strict address syntax; a bare address is refused with the `/32` (or `/128`) suggestion.
- **Email.** `@example.com` is none of the three RFC 5280 forms (mailbox, host, `.domain`). The
  server stored it as written. OpenSSL reads it as the host `example.com`; Go's `crypto/x509`
  refuses to parse a certificate whose rfc822Name constraint has an `@` but is not a mailbox (from
  the source, not run). Now refused, naming `example.com` and `.example.com`.
- **URI.** J2's example `URI:https://example.com` could never match: a URI constraint names the
  host. Now refused unless it is a host or `.domain`.
- **DN.** The DN sanitizer splits on every comma before parsing, so a value with an escaped or
  quoted comma was, and is, refused; an attribute BouncyCastle does not know is refused.
- **Empty subtrees.** When every entry dropped, `ParseSubtrees` returned an empty array, not null,
  and BouncyCastle's `NameConstraints` constructor threw `ArgumentException` ("Minimum sequence size
  is 1"). No empty extension was ever emitted; the CA build failed instead, on the ceremony path
  after the approvals. Now an empty list means no subtree, and an invalid entry throws an
  `InvalidOperationException` naming it, rather than being dropped. A profile stored with a bad
  entry therefore fails CA-certificate issuance loudly instead of issuing a weaker constraint.
- **Non-DNS constraints.** `CertificateIssuanceService.ValidateNameConstraints` refuses every
  issuance from a CA whose certificate carries IP, Email, URI or DN constraints (enforcement is not
  implemented). Both editors and the ceremony view now say so when such a row is present.
- The cases both sides must agree on are in `tests/modularca.web.tests/src/common/name-constraint-cases.json`,
  read by `generalNames.test.ts` and `NameConstraintRulesTests`.

L15, confirmed and fixed. `ParsePatterns` split on `, ; space tab newline`, so `O=Acme Corp` became
`O=Acme` and `Corp`, and a CSR need match only one pattern. Traced through `SubjectSatisfies`:
`O=Acme` matched any subject with that exact RDN, and `Corp`, having no `=`, was a DNS pattern
every Common Name had to fall under, so `CN=anything.corp` passed. The subject the token was
written for (`O=Acme Corp`) failed, because the compare removed spaces (`O=AcmeCorp` against
`O=Acme`). The new rule, with no migration: split on line breaks and `;`, then on unescaped commas
(as before); a piece with `=` is one DN pattern with its spaces, cut only where whitespace is
followed by another attribute keyword BouncyCastle knows (so `O=Acme OU=Eng` is still two);
anything else is DNS names split on whitespace (as before; a DNS name has no spaces). Every stored
restriction without a spaced DN value reads as it did. The one shape that changes is a DN value
followed by a DNS name, `O=Acme example.com`, now one DN pattern: narrower, never wider. An
unescaped comma in a DN value (`O=Acme, Inc.`) still separates, as always; the console escapes it.
DN values now compare by attribute OID (`E` = `emailAddress`), case-insensitively, with whitespace
runs collapsed and escapes removed, and a multi-valued RDN is split on `+`. The console writes rows
joined with `; `. Split cases shared with the server: `tests/modularca.web.tests/src/adminui/enrollment-restriction-cases.json`.

Other findings:
- Web TLS reissue compared the console's host with the SAN lines still prefixed (`dns:host`), so
  the lock-out warning showed on every reissue. It now compares the names.
- The reissue modal's comment said an emptied SAN list reissues with no SANs. It does not:
  `CertificateIssuanceService.ApplySanOverrides` treats an empty override list as no override and
  keeps the original names. Not changed here (only the reissue path writes an empty override, so
  the fix looks local, but it changes what reissue does); the modal now says so when every row is
  removed.
- `CertificateRequestForm` matched the server's per-SAN results to rows by raw index, while the
  validate call omits blank rows, so a blank row shifted every result below it. Now mapped.
- Setup's Web TLS SANs go to the same infrastructure CSR builder (DNS and IP only); the wizard now
  restricts the rows, but bootstrap itself still drops other types silently.
- `SigningProfileDetail` (D1) still shows the raw JSON; `NameConstraintsView` is ready for it.

## Steps 3 and 4 results (2026-10-04)

Built, in `shared/common/src/components` so setupui can use them:
- `rowTable.ts`: the pure logic. Rows are records of cells (`string`, or `boolean` for a
  checkbox); columns are `{ key, label, kind: 'text' | 'select' | 'checkbox' | 'date', required?,
  validate?, warn?, placeholder?, options?, suggestions?, mono?, maxLength?, min?, max?, width?,
  hint? }`. `findRowProblems(rows, columns, { duplicateKey?, validateRow? })` returns per-cell and
  per-row problems (error or warning); a blank row is never a problem. Also `hasRowErrors`,
  `filledRows`, `addTableRow` / `removeTableRow` / `updateTableRow`, and for maps
  `keyValueRowsFromObject` / `keyValueRowsToObject`.
- `RowTableEditor.tsx`: a table with column headers on wide screens, one group of labelled fields
  per row on narrow ones (one DOM, explicit table roles). Props: `value`, `onChange`, `columns`,
  `newRow`, `checks`, `rowProblems` (the caller's own, e.g. a stored value the server no longer
  knows), `caption`, `rowLabel`, `addLabel`, `emptyText`, `actions`, `disabled`, `id`,
  `aria-describedby`. Messages sit under their cell or under the row; a select keeps a stored value
  it does not offer, marked "(not offered)"; text suggestions use a datalist. `KeyValueTable` is
  the two-column preset (a key text column with duplicate detection through `normalizeKey`, and a
  value select when `options` is given).
- `CheckboxList` gained an option `badge` and an `unknown` prop (label, formatting and tone for
  stored values no option offers).

| # | Done | Note |
|---|---|---|
| J5 | ✓ | Cert profile: "CT Logs" checklist (name, Enabled/Disabled badge, URL) under Every enabled log / Only these logs. Shown while CT is on, and also while stored ids name no log; those appear as "unknown log" chips to remove (Save blocked). Body still a JSON-array string: null for Every enabled log, except that a stored `[]` stays `[]`. Pure half: `profiles/ctLogChoices.ts`. |
| D2 | ✓ | Cert profile view and the resolved-profile panel show log names (disabled and unknown ones marked); raw ids only when the catalog cannot be read. |
| J3 + J4 | ✓ | Signing profile: one "Certificate Policies" table (OID with suggestions, CPS URI, user notice) plus "Mark the CertificatePolicies extension critical". Pure half: `profiles/certificatePolicies.ts`; component `profiles/CertificatePoliciesTable.tsx`. |
| D1 | part | Signing profile view: policies as a read-only table (suggestion labels, the critical flag), name constraints through `NameConstraintsView`. |
| J6 | ✓ | Settings › LDAP: key/value table, DN check and case-insensitive duplicate detection, a select of local groups. Pure half: `pages/ldapMappings.ts`; component in `pages/SettingsTables.tsx`. |
| L4 | ✓ | Settings › Certificate Policy: rows of algorithm (with suggestions, and a warning for a name the server never produces) and a date picker; `LinesTextarea` removed. Pure half: `pages/sunsetRules.ts`. |

New endpoint: `GET /api/v1/admin/ct-logs/options`, `[Authorize(Policy = "CaOperator")]` (cert.revoke
on any CA, the capability cert profile create and update demand), returning
`[{ id, name, url, enabled }]` by name. It lives in its own controller class
(`AdminCtLogOptionsController`, same route prefix), because on `AdminCtLogController` the
class-level SystemOperator policy would have stacked on it. Listed in the docsui endpoint data; the
existing CT log entries there said CaOperator and now say SystemOperator. It is allowlisted in
`SpaceFenceGuardTests` as an instance-wide catalog with no space binding. `GET /api/v1/admin/groups`
also returns `isControlled` per group, so the LDAP picker applies the server's rule; it is computed
for all groups in two queries (`ControlledTierResolver.ClassifyGroupsAsync`, tested equal to the
per-group `ClassifyGroupAsync`).

Server hardening (400 at save):
- Cert profile create and update: `CtLogIds` must be blank or a JSON array of GUIDs
  (`CtLogIdRules`), each naming an existing CT log.
- Signing profile create and update: `PolicyOids` blank or a JSON array of distinct OIDs that
  `DerObjectIdentifier` accepts; `PolicyQualifiersJson` blank or an object whose keys are listed
  OIDs, each value null or an object with only `cpsUri` (absolute http/https in printable ASCII,
  since it is written as an IA5String), `userNotice` (at most 200 characters, no control
  characters) and `critical` (boolean), keys case-sensitive as the builder reads them
  (`CertificatePolicyRules`). YAML policy sync skips a signing profile whose `policyOids` are
  refused, with an error.
- PUT `/admin/config/certificate-policy`: each sunset rule must be `ALG:YYYY-MM-DD`, split at the
  last colon, ALG one word without spaces or colons, the date a real calendar date
  (`ConfigInputRules.AlgorithmSunsetRuleError`).
- The LDAP target rule is now one method, `LdapGroupSyncService.IsRefusedMappingTarget`, used by
  validation and sync.

Shared cases (both suites read them): `src/common/certificate-policy-cases.json` (OIDs, CPS URIs,
notices), `src/adminui/sunset-rule-cases.json`, `src/adminui/ldap-mapping-cases.json`.

Round-trip decisions:
- **Critical.** The builder marks the extension critical when any qualifier entry has
  `critical: true`, even one for an OID not listed. The form reads exactly that as the checkbox,
  and writes `critical: true` on every listed policy when it is ticked (nothing when not).
  `critical: false` is no longer written, which reads the same.
- **Dropped junk, each with a notice above the table** (and in the view): qualifiers that are not a
  JSON object; an entry that is not an object; an entry for an OID not listed (its critical flag is
  kept, since the server honoured it); keys other than `cpsUri`, `userNotice`, `critical`
  (misspellings such as `CpsUri`); values of the wrong type. A duplicated OID is listed once. An
  invalid stored OID is kept as a row, marked, and blocks Save. The notices say the junk goes at the
  next Save; an otherwise untouched profile is not dirty.
- **Empty.** No policies save as `policyOids: "[]"` and `policyQualifiersJson: "{}"`, as the empty
  form already did. A comma-separated `policyOids`, as YAML sync may write, loads as rows and saves
  as JSON.
- **CT logs.** Every enabled log saves null, so an inheriting profile takes its parent's list
  (`MergeNullableString`). A stored `[]` overrides the parent's list with every enabled log, so it
  is kept as `[]`. Ids compare ignoring case and are written in the catalog's spelling.
- **LDAP mappings.** The setting is rewritten only once a row is edited. The server treats any
  change to the string as super-only, so an untouched card saved by a non-super must send it byte
  for byte. Rows keep their stored order; a mapping whose target is not text is dropped with a
  notice. "Stored unchanged" is judged against the config as last loaded.
- **Sunset rules.** Split at the last colon as the server splits them; a rule with no colon loads as
  an algorithm with the date missing (marked).

Findings that differed from, or went beyond, the plan:
- **YAML policy sync never writes `CtLogIds`** (nor `PolicyQualifiersJson`), so there was nothing
  to validate there for J5. It does write `PolicyOids`, now checked. A YAML change to `policyOids`
  keeps the profile's existing qualifiers, so qualifiers can outlive their OID that way; the
  console drops them at the next save.
- **A list of only disabled CT logs submits nothing.** `CtSubmissionService` filters the list to
  enabled logs and does not fall back to every enabled log. The picker warns when every ticked log
  is disabled.
- **CT under inheritance:** a blank child takes the parent's list, but `[]` on a child overrides it
  (`MergeNullableString` treats only null or empty string as unset). The JSON-array fields merged
  by `MergeJsonArray` treat `[]` as unset instead.
- **Qualifiers for unlisted OIDs still affected certificates:** their `critical` flag made the whole
  extension critical. Now refused at save; on load the console keeps the criticality and drops the
  entry.
- **A CPS URI with non-ASCII characters** was written as an IA5String with `?` for each such
  character (BouncyCastle does not validate it). Now refused.
- **BouncyCastle silently truncates a user notice over 200 characters** (`DisplayText`). Now refused.
- **Duplicate policy OIDs** were emitted as given; RFC 5280 allows each policy once. Now refused,
  and listed once on load.
- **LDAP: sync never grants an instance group**, though validation accepts one. The picker offers
  only groups in a space and warns on a stored instance-group target. `GET /admin/groups` could not
  tell a controlled group from a plain one, so `isControlled` was added rather than guessing from
  template names.
- **LDAP mapping keys compare ignoring case** at sync, so duplicate detection does too, and the hint
  says one LDAP group maps to one local group. The DN check is console-only: the server compares
  DNs as strings, so the hint says to write the DN as the directory reports it.
- **Sunset ALG grammar.** Besides `RSA-2048`, ALG matches the key algorithm alone (`RSA`,
  `Ed25519`, `ML-DSA-65`), `ECDSA-P-256` (curve names, not bit sizes), or the signature algorithm
  (`SHA1withRSA`). The old placeholder `SHA-256:2035-01-01` matches nothing; it is still accepted
  (the server cannot know every name), with a warning. The runtime check stays lenient
  (`DateTime.TryParse`), so a hand-written config.yaml still loads; only the API refuses.
- Sunset rules also warn in the 90 days before the date; the old hint said a rule does nothing until
  then.
- Not checked in a browser: the row editor's narrow layout and the pickers were verified by type
  checks, builds and unit tests only.

## Step 5 results (2026-10-04)

Built:
- `shared/common/src/components/structuredValueModel.ts`, the pure half. `buildValueTree(value,
  { maxDepth = 4, maxItems = 50, formatDate? })` returns a tree of display nodes: `object`
  (labelled entries), `list`, `table` (an array of objects whose values are all
  primitive, at most eight keys in all; missing cells show "—"), `text`, `empty` and `truncated`
  (a container past the depth limit, as compact JSON clipped to 400 characters). An object or
  array past `maxItems` counts the rest in `more`. `formatPrimitive` formats a primitive:
  - booleans as Yes/No;
  - null as "—" and an empty string as "(empty)";
  - ISO timestamps as a local date, with the raw value as the tooltip;
  - GUIDs, hex of 16 or more digits (plain or colon-separated) and id-like keys (`caId`,
    `sourceIp`, `serialNumber`, …) as `mono`.

  `humanizeKey` turns identifier keys into labels (`caId` → "CA ID") and leaves any other key
  verbatim (a DN, a header name). `parseJsonText` unwraps a double-encoded object once.
  `parseJsonContainer` returns the object or array a string holds, or undefined.
- `shared/common/src/components/StructuredValue.tsx`. Props: `value` (parsed), or `json` (text,
  parsed here; text that does not parse is shown as it is), `maxDepth`, `maxItems`, `rawToggle`
  (default true) and `className`. It renders objects as `<dl>`, lists as `<ul>`, and tables with
  column headers. A nested container is a native `<details>`: open at depth 1 when it has 12
  entries or fewer, closed deeper. "Show raw JSON" shows the original text. It renders text nodes
  only, with no `dangerouslySetInnerHTML`; a test asserts this against the source.
- `modularca.adminui/src/components/AuditFields.tsx`: every populated field of an audit row. Objects,
  and strings holding a JSON object or array, go through `StructuredValue` at full width (spanning
  both columns on the detail page). Other fields are `DetailField`s, as before.

| # | Done | Note |
|---|---|---|
| J7 | ✓ | The live textarea is gone. **Copy as JSON** writes the rules as the API stores them, indented (`rulesToJsonText`), shows "Copied", and falls back to a read-only, select-on-focus textarea when copying fails. **Paste JSON…** opens a dialog with a textarea, a shape check and a preview: the number of DN rules with their fields and requirements, the SAN types allowed, whether a SAN is required, and the per-type constraints. It also says when the paste is identical to the form, and lists warnings. Apply (disabled until the check passes) replaces the rules; Cancel, Escape or the backdrop discards the paste. Pure half: `checkRulesImport(text, current)` in `components/requestProfileRules.ts`. `RULES_JSON_REASON`, the `onErrorChange` / `onRulesErrorChange` plumbing and `validate`'s third parameter are removed, since the form can no longer hold unparseable rules. |
| D3 | ✓ | Audit drawer (and so every `AuditTable` drawer, record drawers included) and `AuditLogDetail`. |
| D4 | ✓ | Dashboard "Recent audit" modal: a full `StructuredValue` (the modal has the room), so `parseJsonSafe` is removed. |
| D5 | ✓ | ACME audit drawer, through `AuditFields`. The `identifiers` string column now shows as a type/value table. |
| D1 | ✓ | Checked: the signing profile view renders policies through `CertificatePoliciesView` and name constraints through `NameConstraintsView`. The list drawer and the Dashboard card show neither field, so nothing raw is left. |
| D2 | ✓ | Checked: the cert profile view and the resolved panel show CT log names. |

The paste check is stricter than `parseRules`, which stays tolerant for stored profiles.
- **Refused** (each would otherwise be changed silently):
  - text that is not JSON, or not an object;
  - an object with neither `subjectDnRules` nor `sanRules`;
  - a section of the wrong type, or a DN rule that is not an object;
  - a DN rule whose `field` is not text (`parseRules` would read it as CN);
  - a `requirement` that is not Required, Optional or Forbidden (`parseRules` would read it as
    Optional). Any letter case is accepted and respelled.
  - non-text `fixedValue`, `regex` or `defaultValue`;
  - a `maxLength` or `maxCount` that is not a whole number;
  - a non-boolean `required`.
- **Warned:**
  - keys outside the model (a whole profile object pasted, for instance; only the rules are
    taken);
  - a DN rule with no requirement (Optional);
  - a field or SAN type this editor does not list (kept);
  - a missing `allowedTypes` (DNS and IP);
  - a per-type rule for a type not allowed (dropped on save);
  - an empty DN rule list (the editor's one Required CN row).
- **A section left out keeps the current one,** so `{"sanRules": …}` alone changes only the SAN
  rules.
- **SAN types are respelled** in the editor's form (`dns` → `DNS`): the server matches SAN types
  ignoring case, but the editor's toggles do not.

Findings:
- **The old live textarea could weaken a profile without a word.** It ran every keystroke
  through `parseRules`, so `"requirement": "required"` (lower case) became Optional in the form
  and was saved that way. The server compares `Requirement` case-sensitively
  (`== "Required"` in both CSR controllers, a `switch` in `RequestProfileValidationService`), so
  through the API that value enforces nothing either.
- Dashboard's `parseJsonSafe` printed nested values as `[object Object]` and arrays of objects
  the same way. The audit drawers printed objects as single-line JSON. The ACME drawer printed
  `identifiers` (a JSON string column) as raw text.

Sweep for remaining JSON input. `JSON.parse` in the UIs reads only server data or stored
settings, except in three places:
- the J7 dialog;
- the typed-entry paste (`splitPastedEntries`, a JSON array of strings);
- the chip list's internal key.

No textarea or input has a JSON placeholder; the remaining textareas take a PEM, an SSH key, a
banner, a description or a reason. publicui `AcmeDirectory` (D7) still prints ACME `meta` as
JSON, as intended.

Remaining:
- **Server: request profile rules are not checked at save.** Create and update accept any
  `Requirement` string, any `Field`, and any SAN type name. A misspelled requirement enforces
  nothing. Validate against Required / Optional / Forbidden (400), as the console's paste check
  now does. C# was out of scope for this step.
- `RoleDetail.tsx` "Resource Type" / "Resource ID" (the related note under the list-as-text
  table) still take a raw type string and GUID. A type select plus a resource picker is a
  separate piece of work.
- Not checked in a browser: the paste dialog and the structured audit rendering were verified by
  type checks, builds and unit tests only.

## Fix now, independent of the refactor

- ~~Warning Days (L6) reads and writes the wrong property.~~ Fixed in step 1.
- ~~Settings list inputs eat their separators while typing.~~ Fixed in step 1 (L4 too).
- ~~The Forbidden Algorithms placeholder never matches.~~ Fixed in step 1.
- ~~Enrollment restrictions split on whitespace, which can widen a token (L15).~~ Fixed in step 2.
- ~~Malformed CT Log IDs silently disable CT submission (J5).~~ Refused at save in step 3.
- ~~The CA-creation ceremony drawer hides name constraints from approvers (D6).~~ Fixed in step 2.
- ~~The LDAP mapping placeholder still says `CaAdmin`.~~ Replaced by the mapping table in step 4.
- ~~Pasted request profile rules with a misspelled requirement silently became Optional (J7).~~
  Refused by the paste check in step 5.
- Request profile create and update accept any `Requirement` string; a misspelled one enforces
  nothing. Server-side, still open (see "Step 5 results").
