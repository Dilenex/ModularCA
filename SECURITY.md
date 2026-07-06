# Security Policy

ModularCA is a Certificate Authority. A vulnerability here can compromise the
trust of every certificate it issues, so we take security reports seriously and
ask that you do too.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, use one of the following private channels:

1. **GitHub Security Advisories (preferred).** Open a private report via the
   **"Security" tab → "Report a vulnerability"** on this repository. This keeps
   the discussion confidential until a fix is released.
2. **Email.** Send details to `ca-security@dilenex.com`. Provide an encrypted archive if
   the report contains sensitive material. We will reach out to retrieve the passphrase.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The component and version/commit affected (`ModularCA.API`, a specific
  protocol handler, the keystore, a frontend, etc.).
- Step-by-step reproduction instructions or a proof of concept.
- Any relevant configuration (which protocols are enabled, keystore backend,
  auth mode) — **redact all real keys, passwords, and certificates.**

## What to Expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity rating within 10 business days.
- We practice **coordinated disclosure**: we will work with you on a fix and a
  disclosure timeline, and credit you in the advisory unless you prefer to
  remain anonymous.

## Scope

Because this is PKI software, we are especially interested in reports involving:

- Authentication or authorization bypass (including tenant isolation,
  CA-scoped group/role enforcement, and step-up MFA).
- Certificate issuance, validation, path-building, or revocation flaws
  (CRL/OCSP, name constraints, EKU/key-usage, profile enforcement).
- Protocol-handler vulnerabilities (ACME, SCEP, EST, CMP, OCSP, TSA, SSH CA).
- Private-key exposure, keystore/HSM handling, or weaknesses in key generation,
  encryption, or the key-ceremony quorum.
- Audit-trail tampering or integrity bypass (the audit hash chain).
- Insecure-by-default configuration or backdoors.

## Out of Scope

- Findings that require an already-compromised host or database.
- Vulnerabilities in deliberately operator-enabled, clearly-documented insecure
  modes (e.g. dev mode, which refuses to run without an explicit opt-in flag).
- Reports from automated scanners without a demonstrated, exploitable impact.

## Supported Versions

ModularCA is pre-1.0. Until the first stable release, only the latest tagged
release and `main` receive security fixes.

| Version | Supported |
| ------- | --------- |
| `main` / latest release | ✅ |
| older pre-releases | ❌ |

## Safe Harbor

We consider good-faith security research that follows this policy to be
authorized. We will not pursue legal action against researchers who act in good
faith, avoid privacy violations and service disruption, and give us a reasonable
chance to remediate before disclosure.
