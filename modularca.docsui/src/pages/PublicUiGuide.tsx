export default function PublicUiGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Public UI Guide
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                The Public UI is served at <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">/public</code> and
                provides unauthenticated access to CA certificates, CRL downloads, certificate verification,
                and ACME directory information. No login is required. The top navigation bar has 5 items:
                Home, CA Certificates, CRL Downloads, Certificate Search, and ACME. A dark mode toggle is
                available in the header. The layout includes a responsive mobile menu.
            </p>

            {/* Landing */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Landing Page</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /public/
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The public landing page for the ModularCA deployment. Provides an overview of the CA
                    service and navigation to public resources.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Organization name and description</li>
                    <li>Quick links to CA certificates, CRLs, and certificate search</li>
                    <li>Links to the User UI login for self-service certificate requests</li>
                    <li>ACME directory URL for automated clients</li>
                </ul>
            </section>

            {/* CA Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">CA Certificates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /public/certificates
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Download CA certificates for trust store configuration. Relying parties use these to
                    validate certificates issued by the CAs in this deployment.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>List of all public CA certificates in the hierarchy</li>
                    <li>Download individual CA certificates in PEM or DER format</li>
                    <li>Download full CA chain bundle</li>
                    <li>View CA certificate details (subject, validity, key algorithm, fingerprint)</li>
                    <li>Copy fingerprints for out-of-band verification</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/public/ca<br />
                    GET /api/v1/public/ca/&#123;serial&#125;
                </div>
            </section>

            {/* CRL Downloads */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">CRL Downloads</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /public/crl
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Download Certificate Revocation Lists for offline revocation checking. Each CA publishes
                    its own CRL on a configured schedule.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>List of CRLs organized by issuing CA</li>
                    <li>Download CRL in DER or PEM format</li>
                    <li>View CRL metadata (this-update, next-update, entry count)</li>
                    <li>Direct download URLs for automated CRL fetching</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/public/crl/&#123;serial&#125;<br />
                    GET /api/v1/public/crl/&#123;serial&#125;
                </div>
            </section>

            {/* Certificate Search */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Search</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /public/search
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Public certificate search allowing anyone to verify whether a certificate was issued by
                    this CA and check its revocation status.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Search by serial number or thumbprint</li>
                    <li>View certificate status (active, revoked, expired)</li>
                    <li>View basic certificate details (subject, issuer, validity)</li>
                    <li>Download the certificate if found</li>
                </ul>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r mt-3">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Note:</span> The public search exposes limited certificate
                        details compared to the admin search. Subject DN and SAN values may be partially masked
                        depending on system configuration.
                    </p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mt-3">
                    GET /api/v1/public/info
                </div>
            </section>

            {/* ACME Directory */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">ACME Directory</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /public/acme
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Information page for ACME (Automatic Certificate Management Environment) clients.
                    Displays the ACME directory URL and configuration instructions for popular ACME clients.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>ACME directory URL for client configuration</li>
                    <li>Supported challenge types (HTTP-01, DNS-01, TLS-ALPN-01)</li>
                    <li>Configuration examples for certbot, acme.sh, and other clients</li>
                    <li>Terms of service link</li>
                    <li>External Account Binding (EAB) information if required</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /acme/directory
                </div>
            </section>
        </div>
    );
}
