export default function CaHierarchyDiagram() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                CA Hierarchy
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                ModularCA uses a tiered Certificate Authority hierarchy with a root CA at the top,
                optional intermediate CAs, and issuing CAs that sign end-entity certificates. A dedicated
                System Signing CA handles infrastructure certificates. SSH CAs operate alongside but
                independently of the X.509 hierarchy. Cross-certification is supported for trust bridging
                between separate PKI hierarchies.
            </p>

            {/* Hierarchy Diagram */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Hierarchy Structure</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
                        +------------------+
                        |    Root CA       |
                        |  (Trust Anchor)  |
                        +--------+---------+
                                 |
                +----------------+----------------+
                |                                 |
    +-----------+----------+         +-----------+----------+
    |  System Signing CA   |         |  Intermediate CA     |
    |  (Infrastructure)    |         |  (Space)             |
    +----------+-----------+         +----------+-----------+
               |                                |
    +----------+----------+          +----------+----------+
    |                     |          |                     |
+---+-----+    +----------+   +-----+------+    +---------+---+
| API TLS |    | OCSP     |   | Issuing CA |    | Issuing CA  |
| Cert    |    | Signing  |   | (Dept A)   |    | (Dept B)    |
+---------+    +----------+   +-----+------+    +------+------+
                                    |                  |
                              +-----+------+     +-----+------+
                              | End-Entity |     | End-Entity |
                              | Certs      |     | Certs      |
                              +------------+     +------------+
`}</pre>
                </div>
            </section>

            {/* Root CA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Root CA</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The root CA is the trust anchor for the entire PKI. Its self-signed certificate must be
                    distributed to all relying parties. The root CA key is used only to sign intermediate CA
                    certificates and should be used as infrequently as possible.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Created during initial setup (wizard step 3)</li>
                    <li>Self-signed certificate with CA:TRUE basic constraint</li>
                    <li>Key usage: keyCertSign, cRLSign</li>
                    <li>Long validity period (typically 10-20 years)</li>
                    <li>Private key stored in the configured keystore</li>
                    <li>Signs intermediate CA and System Signing CA certificates only</li>
                </ul>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Best practice:</span> In production deployments, consider
                        storing the root CA key in an HSM or air-gapped system. The keystore supports runtime
                        writes for intermediate CA creation.
                    </p>
                </div>
            </section>

            {/* Intermediate CA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Intermediate CAs</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Intermediate CAs sit between the root and issuing CAs. They add an extra layer of
                    hierarchy, allowing the root key to remain offline while intermediate keys handle
                    day-to-day signing.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Signed by the root CA or another intermediate CA</li>
                    <li>CA:TRUE with pathLenConstraint to limit chain depth</li>
                    <li>Can sign further intermediate CAs or issuing CAs</li>
                    <li>Medium validity period (typically 5-10 years)</li>
                    <li>Created via Admin UI at /admin/authorities/manage</li>
                </ul>
            </section>

            {/* Issuing CA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Issuing CAs</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Issuing CAs are the leaf CAs in the hierarchy. They directly sign end-entity certificates
                    for users and servers. Each issuing CA can be scoped to a specific department, use case,
                    or space.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Signed by an intermediate CA (or directly by root in simple deployments)</li>
                    <li>CA:TRUE with pathLenConstraint:0 (cannot sign further CA certificates)</li>
                    <li>Profiles are assigned to issuing CAs to control what certificates they can issue</li>
                    <li>Each issuing CA generates its own CRLs</li>
                    <li>Shorter validity period (typically 2-5 years)</li>
                </ul>
            </section>

            {/* System Signing CA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">System Signing CA</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The System Signing CA is a special intermediate CA created automatically during setup.
                    It is used exclusively for ModularCA's own infrastructure certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Automatically created during the bootstrap process</li>
                    <li>Signs the API server TLS certificate</li>
                    <li>Signs OCSP responder certificates</li>
                    <li>Signs internal service communication certificates</li>
                    <li>Not available for end-user certificate issuance</li>
                    <li>Managed internally -- not editable through the admin UI</li>
                </ul>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Note:</span> The System Signing CA is visible in the CA
                        hierarchy view but cannot be used as an issuer for certificate requests. It is reserved
                        for platform infrastructure.
                    </p>
                </div>
            </section>

            {/* SSH CA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">SSH CA Integration</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    SSH CAs operate alongside the X.509 hierarchy but use a separate key format. SSH CA keys
                    sign SSH certificates (not X.509 certificates).
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  X.509 Hierarchy                SSH Hierarchy
  +-----------+                  +------------------+
  |  Root CA  |                  |  SSH User CA     |
  +-----+-----+                  |  (ed25519/ecdsa) |
        |                        +--------+---------+
  +-----+-----+                           |
  | Issuing   |                  +--------+---------+
  | CAs       |                  | SSH User Certs   |
  +-----+-----+                  +------------------+
        |
  +-----+-----+                  +------------------+
  | End-Entity|                  |  SSH Host CA     |
  | Certs     |                  |  (ed25519/ecdsa) |
  +-----------+                  +--------+---------+
                                          |
                                 +--------+---------+
                                 | SSH Host Certs   |
                                 +------------------+
`}</pre>
                </div>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Separate CA keys for user certificates and host certificates</li>
                    <li>SSH CA keys are stored in the same keystore as X.509 keys</li>
                    <li>Key types: Ed25519 (recommended), ECDSA, RSA</li>
                    <li>Certificate types: user (for authentication) and host (for server identity)</li>
                    <li>Principals define which usernames or hostnames the certificate is valid for</li>
                    <li>Key Revocation Lists (KRL) for SSH certificate revocation</li>
                </ul>
            </section>

            {/* Cross-Certification */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Cross-Certification</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Cross-certification creates trust bridges between separate PKI hierarchies. A CA in one
                    hierarchy signs a certificate for a CA in another hierarchy, allowing relying parties that
                    trust the first hierarchy to also validate certificates from the second.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Supported via the key ceremony workflow (requires ceremony approvals)</li>
                    <li>The keystore supports runtime writes for cross-certification operations</li>
                    <li>Name constraints can be applied to limit the scope of cross-certified CAs</li>
                    <li>Cross-certified CA certificates appear in the hierarchy view alongside native CAs</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Hierarchy A                    Hierarchy B
  +-----------+                  +-----------+
  | Root CA A |                  | Root CA B |
  +-----+-----+                  +-----+-----+
        |                              |
  +-----+------+                 +-----+------+
  | Issuing A  |---cross-cert--->| Issuing B  |
  +-----+------+                 +-----+------+
        |                              |
  Relying parties       Certificates from B are now
  that trust A          trusted by A's trust chain
`}</pre>
                </div>
            </section>

            {/* Key Ceremony Workflow */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Key Ceremony Workflow</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Spaces with <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">RequireKeyCeremony = true</code> must
                    go through a multi-party approval workflow before creating new CAs. The number of required
                    approvals is configured
                    via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">CeremonyRequiredApprovals</code> on the space (the instance has its own).
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>CA creation endpoints auto-create a ceremony instead of creating the CA immediately</li>
                    <li>Each ceremony step requires step-up MFA (initiate, approve, reject, cancel, execute)</li>
                    <li>The ceremony is scoped to the space's admin group and its quorum requirements</li>
                    <li>Once the required number of approvals is reached, the ceremony can be executed</li>
                </ul>
            </section>

            {/* Trust Chain Building */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Trust Chain Building</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When a certificate is issued, ModularCA builds the full trust chain from the end-entity
                    certificate up to (but not including) the root CA. This chain is available for download
                    and is served via the AIA extension.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Chain download (PEM bundle):

  -----BEGIN CERTIFICATE-----        <-- End-entity certificate
  MIIBxTCCAWugAwIBAgIUP...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----        <-- Issuing CA certificate
  MIIBzDCCAXKgAwIBAgIUQ...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----        <-- Intermediate CA certificate
  MIIBxjCCAWygAwIBAgIUR...
  -----END CERTIFICATE-----

  (Root CA certificate is NOT included -- it must be
   pre-installed in the relying party's trust store)
`}</pre>
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                    The AIA (Authority Information Access) extension in each certificate points to the issuer's
                    certificate URL, allowing clients to dynamically fetch missing intermediate certificates.
                </p>
            </section>
        </div>
    );
}
