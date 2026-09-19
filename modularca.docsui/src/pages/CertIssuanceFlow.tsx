export default function CertIssuanceFlow() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Certificate Issuance Flow
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                ModularCA supports multiple certificate issuance paths: direct admin issuance, user request
                with approval, and automated protocol-based enrollment (ACME, EST, SCEP, CMP). All paths
                converge on profile validation and CA signing.
            </p>

            {/* Core Flow */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Core Issuance Pipeline</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  CSR Submission     Approval        Profile + Policy     Quota      Signing         Storage + CT
  +-----------+   +----------+   +----------------+   +--------+   +---------+   +-------------+
  |  Upload   |   | Manual / |   | Profile merge  |   | Tenant |   | CA Key  |   | DB Store +  |
  |  CSR or   |-->| Auto-    |-->| Name constrs.  |-->| + CA   |-->| Signs   |-->| CT Submit + |
  |  Generate |   | Approve  |   | Cert Policy    |   | Quota  |   | Cert    |   | Audit Log   |
  |  Key+CSR  |   |          |   | DN/SAN valid.  |   |        |   |         |   |             |
  +-----------+   +----------+   +----------------+   +--------+   +---------+   +-------------+
                       |                |                  |
                       |  Reject        |  Fail            |  Fail
                       v                v                  v
                  +---------+    +-----------+       +-----------+
                  | Request |    | Error     |       | 429 Quota |
                  | Denied  |    | Response  |       | Exceeded  |
                  +---------+    +-----------+       +-----------+
`}</pre>
                </div>
            </section>

            {/* Step-by-step */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Detailed Steps</h2>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">1. CSR Submission</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The process begins with a Certificate Signing Request (CSR). This can arrive through
                    several channels:
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>Admin UI:</strong> Direct issuance at /admin/certificates/issue</li>
                    <li><strong>User UI:</strong> Self-service request at /user/request</li>
                    <li><strong>REST API:</strong> POST /api/v1/admin/certificates/issue or POST /api/v1/user/requests</li>
                    <li><strong>ACME:</strong> Automated CSR via ACME finalize order</li>
                    <li><strong>EST:</strong> CSR via /est/simpleenroll</li>
                    <li><strong>SCEP:</strong> PKCS#7 wrapped CSR</li>
                    <li><strong>CMP:</strong> Certificate request message</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">2. Request Approval</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Depending on the issuance path and configuration, approval may be:
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>Automatic:</strong> Admin direct issuance and ACME-validated requests bypass manual approval</li>
                    <li><strong>Manual:</strong> User requests require admin review in the Certificate Requests page</li>
                    <li><strong>Policy-based:</strong> Auto-approve rules can be configured per profile or template</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">3. Profile Resolution and Validation</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The effective profile is resolved
                    by <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">ProfileResolutionService</code>,
                    which merges a child profile with its inherited parent. When inheritance is enabled, the
                    child can only impose equal or stricter constraints -- looser overrides are rejected during
                    inheritance validation. Three profile types participate: cert profiles (extensions, validity,
                    key constraints), request profiles (approval mode, DN rules, SAN rules), and signing profiles
                    (CA binding, algorithm restrictions).
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li>Key algorithm and size validated against both cert profile and signing profile</li>
                    <li>Requested validity period does not exceed profile maximum</li>
                    <li>Validity is clamped to the issuing CA's NotAfter minus 5-minute margin (with warning)</li>
                    <li>Minimum validity duration enforced post-clamp</li>
                    <li>Subject DN fields match allowed patterns and rules; subject/SAN overrides re-validated</li>
                    <li>SANs pass validation (DNS format, IP format, email format, wildcard rules)</li>
                    <li>Name constraints from the issuing CA certificate are enforced (RFC 5280 section 4.2.1.10)</li>
                    <li>Key usage and extended key usage are permitted by both profile and signing profile</li>
                    <li>Basic constraints are appropriate (not requesting CA:true on end-entity profile)</li>
                    <li>System-wide certificate policy rules evaluated
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">ICertPolicyService</code></li>
                    <li>Tenant quota and per-CA certificate limits checked
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">IQuotaService</code> (skipped for infrastructure certs)</li>
                    <li>Tenant enabled status verified -- disabled tenants cannot issue certificates</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">4. CA Signing</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The issuing CA's private key signs the certificate
                    via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">CertificateBuilderService</code>.
                    CA keys are resolved from the keystore (file-based or HSM) through
                    the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">IPrivateKeyHandle</code> abstraction.
                    The certificate includes:
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li>Subject from the validated CSR (with optional subject/SAN overrides applied)</li>
                    <li>Extensions from the effective profile (key usage, EKU, basic constraints)</li>
                    <li>Authority Information Access (AIA) pointing to OCSP and CA issuer</li>
                    <li>CRL Distribution Points</li>
                    <li>Subject Key Identifier and Authority Key Identifier</li>
                    <li>Certificate Policies OIDs and qualifier URLs</li>
                    <li>128-bit CSPRNG serial number (CA/BF BR compliant: 17 bytes with forced positive BigInteger)</li>
                    <li>RSA signature padding mode (PSS by default, configurable to PKCS#1 v1.5
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">CertPolicy.RsaSignaturePadding</code>)</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">5. Storage, CT Submission, and Audit</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The signed certificate is stored in the database with its full intermediate chain (leaf +
                    intermediates, root excluded). If Certificate Transparency is configured, the certificate is
                    submitted to CT logs asynchronously (fire-and-forget -- never blocks issuance). A unified
                    <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">CertificateIssued</code> audit
                    entry is created regardless of issuance path (admin UI, REST API, ACME, EST, SCEP, CMP),
                    providing a single source of truth. If the CSR included a server-generated private key, the
                    key is re-encrypted under the issuing CA's public key using HKDF-SHA256 / AES-256-GCM wrapping.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">6. Reissuance</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Certificate reissuance creates a new certificate with the same subject and SANs (or overrides)
                    while revoking the previous certificate with reason <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">Superseded</code>.
                    The revocation uses the full revocation pipeline (CRL trigger, audit, notifications). Reissuance
                    requires step-up MFA
                    (<code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">reissue-cert</code> operation).
                </p>
            </section>

            {/* Protocol Flows */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Protocol Enrollment Flows</h2>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">ACME (RFC 8555)</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  ACME Client                  ModularCA ACME Server
      |                              |
      |  POST /acme/new-account      |
      |----------------------------->|  Register account
      |  201 Account                 |
      |<-----------------------------|
      |                              |
      |  POST /acme/new-order        |
      |  { identifiers: [...] }      |
      |----------------------------->|  Create order + authorizations
      |  201 Order                   |
      |<-----------------------------|
      |                              |
      |  GET /acme/authz/{id}        |
      |----------------------------->|  Get challenges
      |  200 Authorization           |
      |<-----------------------------|
      |                              |
      |  POST /acme/challenge/{id}   |
      |----------------------------->|  Respond to challenge
      |                              |  (HTTP-01 / DNS-01 / TLS-ALPN-01)
      |  200 Challenge valid         |
      |<-----------------------------|
      |                              |
      |  POST /acme/order/{id}/      |
      |       finalize               |
      |  { csr: "..." }             |
      |----------------------------->|  Validate CSR, sign cert
      |  200 Order (valid)           |
      |<-----------------------------|
      |                              |
      |  POST /acme/cert/{id}        |
      |----------------------------->|  Download certificate
      |  200 PEM chain               |
      |<-----------------------------|
`}</pre>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">EST (RFC 7030)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Enrollment over Secure Transport uses TLS mutual authentication. The client authenticates
                    with an existing certificate (for renewal) or HTTP basic auth (for initial enrollment).
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    GET  /.well-known/est/cacerts&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-- Get CA certs<br />
                    POST /.well-known/est/simpleenroll&nbsp;&nbsp;-- Submit CSR (PKCS#10)<br />
                    POST /.well-known/est/simplereenroll -- Renew certificate<br />
                    POST /.well-known/est/serverkeygen&nbsp;&nbsp;-- Server-side key gen
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">SCEP (RFC 8894)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Simple Certificate Enrollment Protocol is used primarily by network devices. Requests
                    are wrapped in PKCS#7 CMS envelopes for confidentiality and authenticity.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    GET  /scep?operation=GetCACert<br />
                    GET  /scep?operation=GetCACaps<br />
                    POST /scep?operation=PKIOperation&nbsp;&nbsp;-- PKCS#7 CSR envelope
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">CMP (RFC 4210)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Certificate Management Protocol supports initialization requests, certificate requests,
                    key update requests, and revocation. Uses ASN.1-encoded PKI messages.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    POST /cmp&nbsp;&nbsp;-- PKIMessage (ir, cr, kur, rr)
                </div>
            </section>

            {/* Issuance Modes */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Issuance Modes</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    ModularCA supports three issuance modes, each suited to different deployment scenarios.
                    The approval behavior is configured per request profile.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">CSR-Based Issuance</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The user or admin uploads a PKCS#10 Certificate Signing Request generated externally.
                    The private key never leaves the requester's system.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li>Admin direct issuance via the Admin UI or REST API</li>
                    <li>User self-service request via the User UI or REST API</li>
                    <li>Protocol-based enrollment (ACME, EST, SCEP, CMP)</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Server-Side Key Generation</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When the client cannot generate a key pair (or chooses not to), ModularCA generates
                    the key pair on the server, creates a CSR internally, signs the certificate, and returns
                    both the certificate and the private key. The private key is stored encrypted in the database
                    using HKDF-SHA256 key wrapping (see Key Wrapping below).
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Client                           Server
    |                                |
    |  POST /api/v1/admin/           |
    |       certificates/            |
    |       issue-with-key           |
    |  { profile, subject, sans,     |
    |    keyAlgorithm, keySize }     |
    |------------------------------->|
    |                                |  Generate key pair
    |                                |  Create CSR internally
    |                                |  Validate against profile
    |                                |  Hold the key on the request
    |                                |  (Data Protection, not the keystore)
    |                                |
    |  200 { requestId, csr,         |
    |        keyHeld: true }         |
    |<-------------------------------|
    |                                |
    |   ... approve and issue from   |
    |       the Requests page ...    |
    |                                |
    |  POST /api/v1/admin/requests/  |
    |       {id}/pkcs12              |
    |  { password }  + step-up MFA   |
    |------------------------------->|
    |                                |  Build PKCS#12: certificate,
    |                                |  chain and key; delete the
    |                                |  held key in the same save
    |  200 application/x-pkcs12      |
    |<-------------------------------|
`}</pre>
                </div>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Security note:</span> The CA holds the generated key only
                        until the certificate is issued and the .pfx is downloaded once; a second download reports the
                        date the key left. The key still crosses the network in that file, so always use TLS, and prefer
                        client-side key generation with CSR upload where the client can do it.
                    </p>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mt-4 mb-2">Approval Modes</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Each request profile configures whether certificate requests require manual approval or
                    are auto-approved:
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>Auto-approval:</strong> The certificate is issued immediately when the request
                        passes profile validation. Used for admin direct issuance, ACME, and profiles marked
                        for automatic approval.</li>
                    <li><strong>Pending approval:</strong> The request enters a pending state and must be
                        reviewed and approved by an authorized administrator before issuance proceeds.
                        Configured per request profile for user-facing enrollment.</li>
                </ul>
            </section>

            {/* Post-Quantum Cryptography */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Post-Quantum Cryptography Support</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    ModularCA supports post-quantum cryptographic algorithms for certificate signing alongside
                    traditional algorithms, enabling a migration path toward quantum-resistant PKI.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">ML-DSA (NIST FIPS 204)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Module-Lattice-Based Digital Signature Algorithm, the NIST standard derived from CRYSTALS-Dilithium.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>ML-DSA-44</strong> — NIST security level 2 (roughly equivalent to AES-128)</li>
                    <li><strong>ML-DSA-65</strong> — NIST security level 3 (roughly equivalent to AES-192)</li>
                    <li><strong>ML-DSA-87</strong> — NIST security level 5 (roughly equivalent to AES-256)</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">SLH-DSA (NIST FIPS 205)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Stateless Hash-Based Digital Signature Algorithm, the NIST standard derived from SPHINCS+.
                    Available in SHA2 and SHAKE instantiations, each with Fast (F) and Small (S) parameter sets.
                </p>
                <div className="overflow-x-auto mb-4">
                    <table className="min-w-full text-sm text-gray-700 dark:text-gray-300">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-600">
                                <th className="text-left py-2 pr-4 font-semibold">Hash</th>
                                <th className="text-left py-2 pr-4 font-semibold">128-bit</th>
                                <th className="text-left py-2 pr-4 font-semibold">192-bit</th>
                                <th className="text-left py-2 font-semibold">256-bit</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-semibold">SHA2</td>
                                <td className="py-2 pr-4">SHA2-128F, SHA2-128S</td>
                                <td className="py-2 pr-4">SHA2-192F, SHA2-192S</td>
                                <td className="py-2">SHA2-256F, SHA2-256S</td>
                            </tr>
                            <tr>
                                <td className="py-2 pr-4 font-semibold">SHAKE</td>
                                <td className="py-2 pr-4">SHAKE-128F, SHAKE-128S</td>
                                <td className="py-2 pr-4">SHAKE-192F, SHAKE-192S</td>
                                <td className="py-2">SHAKE-256F, SHAKE-256S</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r mb-4">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Fast vs. Small:</span> The F (Fast) variants have
                        faster signing but larger signatures. The S (Small) variants produce smaller signatures
                        at the cost of slower signing. Choose based on your bandwidth vs. latency requirements.
                    </p>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Edwards Curves</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>Ed25519</strong> — Edwards curve over Curve25519 (128-bit security)</li>
                    <li><strong>Ed448</strong> — Edwards curve over Curve448-Goldilocks (224-bit security)</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Traditional Algorithms</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li><strong>RSA-2048, RSA-4096</strong> — RSA with PKCS#1 v1.5 or PSS padding</li>
                    <li><strong>ECDSA P-256</strong> — secp256r1 / prime256v1</li>
                    <li><strong>ECDSA P-384</strong> — secp384r1</li>
                    <li><strong>ECDSA P-521</strong> — secp521r1</li>
                    <li><strong>Ed25519</strong> — Edwards curve (also listed above)</li>
                </ul>
            </section>

            {/* ECDSA Named Curves */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">ECDSA Named Curves</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    ECDSA keys are encoded using named curve OIDs rather than explicit parameters. This
                    ensures compatibility with OpenSSL 3.x, which rejects EC keys with explicit parameters
                    by default.
                </p>
                <div className="overflow-x-auto mb-4">
                    <table className="min-w-full text-sm text-gray-700 dark:text-gray-300">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-600">
                                <th className="text-left py-2 pr-4 font-semibold">Curve</th>
                                <th className="text-left py-2 pr-4 font-semibold">OID</th>
                                <th className="text-left py-2 font-semibold">Aliases</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4">P-256</td>
                                <td className="py-2 pr-4 font-mono text-xs">1.2.840.10045.3.1.7</td>
                                <td className="py-2">secp256r1, prime256v1</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4">P-384</td>
                                <td className="py-2 pr-4 font-mono text-xs">1.3.132.0.34</td>
                                <td className="py-2">secp384r1</td>
                            </tr>
                            <tr>
                                <td className="py-2 pr-4">P-521</td>
                                <td className="py-2 pr-4 font-mono text-xs">1.3.132.0.35</td>
                                <td className="py-2">secp521r1</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Why named curves?</span> OpenSSL 3.x defaults to
                        rejecting EC keys that use explicit curve parameters (the full curve definition embedded
                        in the key). Using named curve OIDs keeps keys compact and interoperable across all
                        modern TLS stacks.
                    </p>
                </div>
            </section>

            {/* Key Wrapping */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Key Wrapping</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Private keys generated or stored by ModularCA are encrypted at rest using HKDF-SHA256
                    key wrapping with AES-256-GCM authenticated encryption.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Wrapping Process</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li>A 32-byte random salt is generated for HKDF key derivation</li>
                    <li>HKDF-SHA256 derives a 256-bit wrapping key from the master key and salt</li>
                    <li>A 12-byte random IV is generated for AES-256-GCM</li>
                    <li>The private key is encrypted with AES-256-GCM, producing ciphertext and a 16-byte authentication tag</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Storage Format</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  +------------------+----------+-----------------------------+
  |  HKDF Salt       |  IV      |  Ciphertext + GCM Auth Tag  |
  |  (32 bytes)      |  (12 B)  |  (variable length)          |
  +------------------+----------+-----------------------------+
`}</pre>
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The salt ensures each wrapped key uses a unique derived key even when the same master key
                    is used. The GCM authentication tag provides integrity verification, ensuring that
                    tampered ciphertext is detected during unwrapping.
                </p>
            </section>

            {/* Name Constraint Validation */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Name Constraint Validation</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When a CA certificate includes the Name Constraints extension (RFC 5280 section 4.2.1.10),
                    ModularCA validates all DNS Subject Alternative Names against the issuing CA's permitted
                    and excluded subtrees before signing the certificate.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-4">
                    <li>Each DNS SAN must fall within at least one permitted subtree (if any are defined)</li>
                    <li>No DNS SAN may fall within any excluded subtree</li>
                    <li>Validation is performed before the CA signing step in the issuance pipeline</li>
                    <li>Requests that violate name constraints are rejected with a descriptive error</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Example: CA has permitted subtree ".example.com"

    www.example.com      --> Allowed (within .example.com)
    api.example.com      --> Allowed (within .example.com)
    evil.example.org     --> Rejected (not within permitted subtree)
`}</pre>
                </div>
            </section>

            {/* Certificate Extension Builder */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Extension Builder</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    ModularCA builds X.509v3 extensions based on the effective profile. The following
                    extensions are included in issued certificates:
                </p>
                <div className="overflow-x-auto mb-4">
                    <table className="min-w-full text-sm text-gray-700 dark:text-gray-300">
                        <thead>
                            <tr className="border-b border-gray-300 dark:border-gray-600">
                                <th className="text-left py-2 pr-4 font-semibold">Extension</th>
                                <th className="text-left py-2 pr-4 font-semibold">Critical</th>
                                <th className="text-left py-2 font-semibold">Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">BasicConstraints</td>
                                <td className="py-2 pr-4">Yes</td>
                                <td className="py-2">Indicates whether the subject is a CA and the maximum path length</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">KeyUsage</td>
                                <td className="py-2 pr-4">Yes</td>
                                <td className="py-2">Permitted key operations (digitalSignature, keyEncipherment, etc.)</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">ExtendedKeyUsage</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">Purpose of the certificate (serverAuth, clientAuth, codeSigning, etc.)</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">SubjectKeyIdentifier</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">SHA-1 hash of the subject's public key, used for chain building</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">AuthorityKeyIdentifier</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">Identifies the issuing CA's public key for chain validation</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">SubjectAlternativeNames</td>
                                <td className="py-2 pr-4">No*</td>
                                <td className="py-2">DNS names, IP addresses, email addresses, URIs associated with the certificate</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">CRLDistributionPoints</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">URLs where the CA's CRL can be retrieved</td>
                            </tr>
                            <tr className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 pr-4 font-mono text-xs">AuthorityInfoAccess</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">OCSP responder URL and CA issuer certificate URL</td>
                            </tr>
                            <tr>
                                <td className="py-2 pr-4 font-mono text-xs">CertificatePolicies</td>
                                <td className="py-2 pr-4">No</td>
                                <td className="py-2">Policy OIDs and optional qualifier URLs for the certificate</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <p className="text-gray-700 dark:text-gray-300 text-sm mb-2">
                    <strong>*</strong> SAN is marked critical when the Subject DN is empty (per RFC 5280).
                </p>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        Extension values are controlled by the effective profile, which merges the system-level
                        profile with the CA-level override. The CA profile can only impose stricter constraints
                        than the system profile.
                    </p>
                </div>
            </section>
        </div>
    );
}
