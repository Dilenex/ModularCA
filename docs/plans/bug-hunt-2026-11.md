# Bug hunt, November 2026: findings and the 0.4.3 / 0.4.4 split

Status: **the 0.4.3 group is fixed** on `0.4.3-dev` (2026-11-08), one commit each with tests:
F1 `0089e7e`, F2 `3a5d2eb`, F3 `2e15693`, F4 `f41135b`, F5 `162cc0c`, F6 `e1ca1ee`, F7 `ec901f2`,
X1 `09791ef`, X2 `16bc9d7`, X3 `7448530`, X4 `cabf2e8`, X5 `2fd35db`. X4 and X5 were confirmed in
the source before fixing. The 0.4.4 group is open.

Six read-only reviews of `0.4.3-dev` at `7bd74b9`
(`0.4.3-rc.1.2`), 2026-11-07, one per area: API; Core; Auth; Keystore, Signer and Ssh; Bootstrap,
Migrate and Database; the admin console with `shared/`. `ModularCA.Shared`, docsui, publicui and
setupui were not covered. Every High and Medium-High finding was confirmed by reading the source a
second time; findings marked *(reported)* rest on the review alone. Line numbers are a snapshot
and will drift.

The owner decided on 2026-11-07 that the first two groups go into 0.4.3 and the rest wait for 0.4.4.

## Fix in 0.4.3

| # | Finding | Where | Effect |
|---|---|---|---|
| F1 | Reissue acts on the certificate named in the body, not the route | `AdminIssuanceController` `{certId}/reissue`, `serial/{serial}/reissue`, `csr/{csrId}/reissue` | Authorization resolves the CA from the route; the reissue runs on the body's id. An operator on one CA can reissue another CA's certificates in the same space. `AdminRevocationController` had the same split and was fixed earlier. |
| F2 | A deactivated ACME account keeps working | `AcmeJwsAttribute` | Status is checked only on account update and key change, so a deactivated account can still order, finalize, answer challenges and revoke (RFC 8555 §7.3.6). |
| F3 | Reissue skips the key-compromise reuse block (CLM-007) | `CertificateIssuanceService` reissue | The refusal is a `ConfigurationValidationException`; the `catch (InvalidOperationException) { throw; }` meant to pass it on does not catch it, and the general catch logs "allowing reissue". An expired certificate revoked for KeyCompromise is reissued with the same key. |
| F4 | MSAE certificates carry the CSR's subject, not the Kerberos identity's | `RequestProfileEnforcement.ProtocolSubjectOverrides`, `EnrollmentPipeline` | The request row holds `CN=<principal>`, but issuance builds the subject from the CSR, and the override adds a CN only when the CSR has none. Subject-based mappings (`X509:<I><S>`, RADIUS, VPN) see whatever the client asked for. |
| F5 | WebAuthn-only login asks for user verification as "Preferred" | `AuthController` login, inline assertion options | Bypasses `RequireWebAuthnUserVerification`: a security key works without its PIN. |
| F6 | Editing the worn access badge widens the session without step-up | `AccountBadgesController` Update and Delete | Switching to a wider badge needs step-up; editing the worn badge (read live on every request) or deleting it does not. |
| F7 | New intermediate CA can be created under a parent the form no longer shows | `adminui` `CaManagement.tsx` parent re-check | The re-check runs on the candidate count only; after a scope switch to a subtree of the same size the old parent id is submitted. |
| X1 | A wrong code while setting up an authenticator signs the user out | `shared/authenticated` `createClient.ts`, `TotpController.VerifySetup` | The server answers 401; the client treats every 401 but step-up as the end of the session. |
| X2 | Key material written to a file before it is restricted | `Unlocker` `--output`; `BackupRestore` decrypted archive | The file exists at default permissions before the chmod; a local user who opens it in that window keeps the descriptor. |
| X3 | The migrate tool's temporary role password is on the `psql` command line | `ModularCA.Migrate/LocalPostgresAccess` | Readable from `/proc` by any local user while the migration runs; the role can take the app and audit roles. |
| X4 | User SSH signing does not tie the request profile to the signing CA *(reported)* | `UserSshController` `sign-user` | Another CA's request profile, without approval, can be paired with this CA's signing profile. |
| X5 | Unauthenticated input becomes Prometheus label values *(reported)* | OCSP, short-URL and SCEP controllers | Each new `caLabel` or SCEP `operation` value is a new time series kept for the life of the process. |

## Wait for 0.4.4

**HSM**
- ECDSA signatures from PKCS#11 are raw r‖s and are not converted to DER for certificates, CRLs and
  OCSP, so an EC CA on an HSM produces signatures nothing can verify. Move up if any EC HSM CA exists.
- RSA-PSS and Ed448 mechanisms are created without their required parameters.
- An HSM key is paired with its CA certificate by label alone; the public key is never compared.

**Issuance and policy**
- A cert profile with an empty EKU list escapes the signing profile's EKU allow-list.
- A held certificate cannot move straight to a permanent reason; it must be released first.
- Profile inheritance clamps against the parent's stored row, one level deep.
- Maximum validity is measured from now, so a backdated notBefore stretches the certificate.
- Creating an intermediate does not check the parent's pathLenConstraint.
- A multi-request OCSP query is answered in the first request's issuer scope.
- Check-then-act races: issuing the same request twice, quota overshoot, ceremony approve vs reject.

**Keystore**
- An admin-set scrypt N that is not a power of two breaks every keystore write.
- The scrypt bounds still allow a 4 GiB derivation.
- Restoring a keystore file skips the per-path lock and is not atomic.

**API and protocols**
- Infra integration profile listings ignore the API key's space scope.
- An EAB key can bind more than one account under a race.
- Infra revoke accepts numeric and undefined revocation reasons.
- ACME: a bad nonce is `malformed`, not `badNonce`; malformed JWS input returns 500.

**Auth**
- The default access badge applies only to password-only sign-in.
- DPoP: a proof with a future `iat` outlives its replay entry; the jti check is not atomic.
- The approval outlook evaluates other users through the caller's context (false audit rows, wrong
  count under a badge).
- With LDAP on, a refused bind still falls back to the local password hash.

**Bootstrap**
- CLI `--backup` stages into a predictable `/tmp` directory and only warns when it cannot restrict it.
- Restore replaces the live audit database without keeping a copy. Open question for the owner:
  should a restore fall under the rule that audit history survives unless deliberately wiped?

**Admin console**
- Bulk revoke on Certificates keeps a selection made in another space.
- Dashboard, Profiles and Distribution ignore a space-scope change.
- Protocol Configuration loads race and can save one CA's settings to another.
- The typed-filter debounce rewrites the URL from stale parameters.
- Several scope-keyed list loads have no cancellation.
- The "valid until" picker allows up to a day past the server's limit, and uses UTC dates.
- Group bulk delete asks for step-up once per group.

## Came up clean

JWT validation; refresh-token rotation and family revocation; passwords and lockout; step-up tokens;
mTLS hold and revoke ending sessions; keystore format and crypto; the signer seam's checks; SSH wire
format and option rules; the three audit drop sites; setup re-run protection; SQL quoting; serial
numbers; CRL numbering; ceremony quorum; the shared client's refresh single-flight; XSS.
