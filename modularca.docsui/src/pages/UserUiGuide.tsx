export default function UserUiGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                User UI Guide
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                The User UI is served at <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">/user</code> and
                provides a self-service portal for end users to request, manage, and download their certificates.
                All routes require authentication with step-up MFA support (TOTP and WebAuthn) for
                sensitive operations. The sidebar navigation is organized into 5 sections: Overview,
                Certificates, SSH, CA Information, and My Account.
            </p>

            {/* Dashboard */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Dashboard</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/dashboard&nbsp;&nbsp;(also /user/)
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Personal overview showing the user's certificate inventory, pending requests, and expiring
                    certificates at a glance.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Summary cards for active certificates, pending requests, and upcoming expirations</li>
                    <li>Recent activity feed</li>
                    <li>Quick-action buttons for requesting a new certificate</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/me
                </div>
            </section>

            {/* Request Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Request Certificate</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/request
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Submit a certificate signing request. The request enters the approval workflow and will be
                    reviewed by an administrator (unless auto-approval is configured).
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Upload a PEM-encoded CSR file or paste CSR text</li>
                    <li>Select from available certificate templates or profiles</li>
                    <li>Fill in subject fields within allowed constraints</li>
                    <li>Add Subject Alternative Names</li>
                    <li>Choose key algorithm from the key generation dropdown, including post-quantum options</li>
                    <li>Track request after submission</li>
                </ul>
                <div className="border-l-4 border-purple-500 bg-purple-50 dark:bg-purple-900/20 p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-purple-800 dark:text-purple-300 mb-2">Post-Quantum Cryptography (PQC)</h3>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-2">
                        The key generation dropdown includes post-quantum algorithms alongside traditional options:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-2">
                        <li><strong>ML-DSA-44, ML-DSA-65, ML-DSA-87</strong> — FIPS 204 lattice-based digital signatures (formerly CRYSTALS-Dilithium)</li>
                        <li><strong>SLH-DSA-SHA2-128F</strong> — FIPS 205 stateless hash-based signatures (formerly SPHINCS+)</li>
                        <li><strong>Ed448</strong> — Edwards-curve signature with 224-bit security level</li>
                    </ul>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        PQC algorithms have fixed security levels, so the key size field is automatically hidden
                        when a PQC algorithm is selected.
                    </p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    POST /api/v1/user/requests<br />
                    GET /api/v1/user/request-profiles<br />
                    GET /api/v1/user/signing-profiles
                </div>
            </section>

            {/* My Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">My Certificates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/certificates
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    View all certificates issued to the current user. Supports filtering by status (all, active,
                    revoked, expired) to quickly locate specific certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>List of issued certificates with status indicators</li>
                    <li>Filter certificates by status: all, active, revoked, or expired</li>
                    <li>View certificate details (subject, SANs, validity, serial number)</li>
                    <li>Download certificate in PEM, DER, or full-chain format</li>
                    <li>Download PKCS#12 / PFX bundle with private key (if server-side key generation was used)</li>
                    <li>View certificate expiry dates</li>
                </ul>
                <div className="border-l-4 border-amber-500 bg-amber-50 dark:bg-amber-900/20 p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-amber-800 dark:text-amber-300 mb-2">MFA Step-Up on PFX Export</h3>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-2">
                        Downloading a PKCS#12 / PFX file (which contains the private key) requires MFA step-up
                        verification. Users must enter their TOTP code before the PFX file will download. This
                        protects against session hijacking — even if an attacker steals a session token, they
                        cannot extract private keys without the second factor.
                    </p>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        <strong>PFX export with private keys is only available in the User UI, not the Admin UI.</strong> This
                        is a deliberate security design decision ensuring that private key material is only ever
                        delivered directly to the certificate owner.
                    </p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/user/certificates<br />
                    GET /api/v1/user/certificates/&#123;serial&#125;/file
                </div>
            </section>

            {/* Request Status */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Request Status</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/requests
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Track the status of submitted certificate requests through the approval pipeline.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View all submitted requests with current status</li>
                    <li>Status states: pending, approved, issued, rejected, cancelled</li>
                    <li>Cancel pending requests</li>
                    <li>View rejection reasons</li>
                    <li>Download issued certificate once approved</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/user/requests<br />
                    POST /api/v1/user/requests
                </div>
            </section>

            {/* SSH Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">SSH Certificates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/ssh
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Request and manage personal SSH certificates for server access.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Submit an SSH public key for signing</li>
                    <li>View issued SSH certificates with principals and validity</li>
                    <li>Download signed SSH certificates</li>
                    <li>View SSH CA public key for trust configuration</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    POST /api/v1/user/ssh/sign-user<br />
                    GET /api/v1/user/ssh/certificates
                </div>
            </section>

            {/* Trusted CAs */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Trusted CAs</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/authorities
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    View information about the Certificate Authorities available in the deployment. Provides
                    CA certificates for trust configuration.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>List of available CAs the user can request certificates from</li>
                    <li>Download CA certificates for trust store installation</li>
                    <li>View CA certificate details and chain</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/user/authorities
                </div>
            </section>

            {/* My Security */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">My Security</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /user/security
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Personal security management for the logged-in user. Sensitive operations on this page
                    require MFA step-up verification to prevent unauthorized changes.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Change password (requires MFA step-up)</li>
                    <li>Enroll or manage TOTP authenticator app</li>
                    <li>Remove TOTP authenticator (requires MFA step-up)</li>
                    <li>Register WebAuthn/FIDO2 security keys</li>
                    <li>Remove WebAuthn security keys (requires MFA step-up)</li>
                    <li>Revoke mTLS credentials (requires MFA step-up)</li>
                    <li>View active sessions and revoke them</li>
                </ul>
                <div className="border-l-4 border-amber-500 bg-amber-50 dark:bg-amber-900/20 p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-amber-800 dark:text-amber-300 mb-2">MFA Step-Up on Security Operations</h3>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        Password changes, TOTP removal, WebAuthn key removal, and mTLS credential revocation
                        all require the user to re-verify with their TOTP code before the operation proceeds.
                        This prevents an attacker with a stolen session from locking the real user out or
                        downgrading their security posture.
                    </p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/me<br />
                    POST /api/v1/auth/change-password<br />
                    POST /api/v1/auth/totp/setup<br />
                    POST /api/v1/auth/webauthn/register
                </div>
            </section>

            {/* Auth routes note */}
            <section className="mb-10">
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <h3 className="text-lg font-semibold text-blue-800 dark:text-blue-300 mb-2">Authentication Routes</h3>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        The User UI includes the same authentication flow as the Admin UI:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mt-2">
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/login</code> — Login form, shared with the management console</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-setup</code> — First-time MFA enrollment</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-verify</code> — MFA challenge verification</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-callback</code> — WebAuthn callback handler</li>
                    </ul>
                </div>
            </section>
        </div>
    );
}
