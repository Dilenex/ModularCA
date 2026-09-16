export default function AdminUiGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Admin UI Guide
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                The Admin UI is served at <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">/admin</code> and
                provides full management access to the ModularCA platform. All routes require authentication and are
                wrapped in a <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">ProtectedRoute</code> with
                step-up MFA support for sensitive operations. All pages support a dark mode toggle for comfortable
                use in low-light environments.
            </p>

            {/* MFA Step-Up on Sensitive Operations */}
            <section className="mb-10">
                <div className="border-l-4 border-amber-500 bg-amber-50 dark:bg-amber-900/20 p-4 rounded-r">
                    <h2 className="text-2xl font-bold text-amber-800 dark:text-amber-300 mb-3">MFA Step-Up on Sensitive Operations</h2>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                        All destructive and sensitive operations in the Admin UI require MFA step-up verification.
                        When a user triggers a protected action, a TOTP modal appears prompting for a 6-digit
                        verification code before the operation proceeds. Step-up supports both TOTP codes and
                        WebAuthn/FIDO2 security keys. This applies even if the user already
                        authenticated with MFA at login.
                    </p>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Operations Requiring Step-Up</h3>
                    <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                        <li>Certificate revocation, hold, and unhold (via the Certificates page and Dashboard)</li>
                        <li>Certificate export (PEM with private key)</li>
                        <li>Profile deletion (certificate profiles, signing profiles, request profiles)</li>
                        <li>Protocol configuration updates</li>
                        <li>User management: create, update (disable/enable), reset password, reset MFA</li>
                        <li>Group membership changes (add or remove a user from a group)</li>
                        <li>Backup creation and restore</li>
                        <li>CA creation and updates</li>
                        <li>Key ceremony initiation and approval</li>
                        <li>Application restart and security configuration changes</li>
                    </ul>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        The step-up modal is enforced client-side and server-side. The backend rejects any
                        sensitive API call that does not include a valid, recent TOTP verification token.
                    </p>
                </div>
            </section>

            {/* Dark Mode */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Dark Mode</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    All Admin UI pages support a dark mode toggle. The preference is persisted in local storage and
                    applies immediately across every page. The toggle is accessible from the top navigation bar.
                    Dark mode is also respected by charts, code blocks, and the TOTP step-up modal.
                </p>
            </section>

            {/* Navigation Structure */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Navigation Structure</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The sidebar navigation is organized into 5 collapsible sections. Items are role-gated:
                    hidden links cannot be reached by typing the URL either, as the server enforces the same
                    role check.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm leading-relaxed">
                    <strong>Overview:</strong> Dashboard, System Health, My Security<br />
                    <strong>Certificates:</strong> All Certificates, Request Certificate, Pending Requests,
                        Search, Cert Inventory, Vulnerabilities, Compliance, Expiry Calendar<br />
                    <strong>CA Management:</strong> Authorities, Profiles, Templates, CRL Management,
                        Trust Anchors, Key Ceremonies, SSH CA, Protocol Config<br />
                    <strong>Access &amp; Identity:</strong> Users, Groups, Roles, Enrollment, ACME<br />
                    <strong>Administration:</strong> Tenants, Settings, Audit Logs, Notifications, Quotas,
                        Whitelists, Backup &amp; Restore, Web TLS Certificate
                </div>
            </section>

            {/* Dashboard */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Dashboard</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/dashboard&nbsp;&nbsp;(also /admin/)
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The landing page after login. Provides a system-wide overview of the ModularCA deployment
                    with real-time status information.
                </p>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Key Features</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>CA status cards showing each authority's health, key algorithm, and certificate count</li>
                    <li>Recently issued certificates with quick links to details</li>
                    <li>Pending request count with approve/reject shortcuts</li>
                    <li>Expiring certificate warnings for the next 30/60/90 days</li>
                    <li>System health summary (scheduler, database, OCSP responder)</li>
                    <li>Quick-action buttons for common tasks (issue certificate, create CA)</li>
                </ul>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Related API Endpoints</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/certificates?pageSize=10<br />
                    GET /api/v1/admin/authorities<br />
                    GET /api/v1/admin/requests<br />
                    GET /api/v1/admin/audit?pageSize=10
                </div>
            </section>

            {/* System Health */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">System Health</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/health
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Detailed system health monitoring with real-time metrics and background scheduler status.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Database connection pool metrics</li>
                    <li>Background scheduler status (CRL generation, OCSP updates, cleanup jobs)</li>
                    <li>Certificate counts by status (active, revoked, expired)</li>
                    <li>Uptime and version information</li>
                    <li>Memory and resource utilization</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/scheduler/health<br />
                    GET /api/v1/admin/certificates/health/summary
                </div>
            </section>

            {/* Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/certificates
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The main certificate inventory view. Lists all certificates across all CAs with filtering
                    and bulk operations.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Paginated certificate list with sortable columns</li>
                    <li>Filter by status (active, revoked, expired, pending)</li>
                    <li>Filter by issuing CA</li>
                    <li>Download individual certificates in PEM, DER, or full-chain format (PFX/private key export is only available in the User UI)</li>
                    <li>Revoke certificates with reason code selection (requires MFA step-up)</li>
                    <li>Hold and unhold certificates (requires MFA step-up)</li>
                    <li>Certificate detail view with parsed X.509 extensions: AIA, CDP, Basic Constraints, Key Usage, Extended Key Usage, SANs, Subject Key Identifier, Authority Key Identifier, and Certificate Policies</li>
                    <li>View subject, fingerprints, validity dates, and serial number</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/certificates<br />
                    GET /api/v1/admin/certificates/&#123;serial&#125;<br />
                    GET /api/v1/admin/ssh/certificates/&#123;id&#125;/download<br />
                    POST /api/v1/admin/certificates/&#123;certId&#125;/revoke
                </div>
            </section>

            {/* Request Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Request Certificate</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/certificates/request
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Direct certificate issuance for administrators. Supports both CSR-based and server-side key
                    generation workflows.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Upload a PEM-encoded CSR or paste CSR text</li>
                    <li>Server-side key generation with algorithm and key size selection</li>
                    <li>Select issuing CA and certificate profile</li>
                    <li>Edit subject DN fields (CN, O, OU, L, ST, C)</li>
                    <li>Add Subject Alternative Names (DNS, IP, email, URI)</li>
                    <li>Set custom validity period within profile limits</li>
                    <li>Preview effective certificate extensions before signing</li>
                </ul>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Post-Quantum Cryptography</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The key algorithm dropdown now includes NIST post-quantum signature algorithms alongside
                    classical algorithms. Supported PQC algorithms:
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li><strong>ML-DSA-44, ML-DSA-65, ML-DSA-87</strong> — NIST post-quantum digital signature (formerly CRYSTALS-Dilithium)</li>
                    <li><strong>SLH-DSA-SHA2-128F</strong> — NIST stateless hash-based signature (formerly SPHINCS+)</li>
                    <li><strong>Ed448</strong> — Edwards-curve Digital Signature Algorithm (448-bit)</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    POST /api/v1/admin/ssh/profiles/request<br />
                    POST /api/v1/admin/certificates/issue-with-key<br />
                    GET /api/v1/admin/cert-profiles<br />
                    GET /api/v1/admin/authorities
                </div>
            </section>

            {/* Certificate Search */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Search</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/certificates/search
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Advanced search across all certificates with multiple filter criteria.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Search by subject CN, serial number, or thumbprint</li>
                    <li>Filter by Subject Alternative Name (DNS, IP, email)</li>
                    <li>Date range filters for issuance and expiry</li>
                    <li>Filter by issuing CA and profile</li>
                    <li>Status filter (active, revoked, expired)</li>
                    <li>Export search results</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/certificates/tags/search
                </div>
            </section>

            {/* Expiry Calendar */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Expiry Calendar</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/certificates/expiry
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Visual calendar view showing upcoming certificate expirations. Helps plan renewals and
                    prevent outages from expired certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Monthly calendar with expiration counts per day</li>
                    <li>Color-coded urgency (red for imminent, yellow for upcoming)</li>
                    <li>Click a day to see the specific certificates expiring</li>
                    <li>Filter by CA or profile</li>
                    <li>Quick renew/reissue actions</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/certificates/health/summary
                </div>
            </section>

            {/* Certificate Requests */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Requests</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/certificates/requests
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage the certificate request lifecycle. Requests submitted by users through the User UI
                    or API appear here for approval.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Filter by status: pending, approved, issued, rejected, cancelled</li>
                    <li>Review CSR details and requested subject/SANs</li>
                    <li>Approve requests (triggers signing and issuance)</li>
                    <li>Reject requests with a reason message</li>
                    <li>Cancel pending requests</li>
                    <li>View request history and audit trail</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/requests<br />
                    POST /api/v1/admin/ceremonies/&#123;id&#125;/approve<br />
                    POST /api/v1/admin/ceremonies/&#123;id&#125;/reject<br />
                    POST /api/v1/admin/requests/&#123;id&#125;/cancel
                </div>
            </section>

            {/* CA Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">CA Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/authorities/manage
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage the CA hierarchy. Create, view, and configure Certificate Authorities including
                    root, intermediate, and issuing CAs.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Visual CA hierarchy tree</li>
                    <li>Create new root CA with key algorithm selection</li>
                    <li>Create intermediate CAs signed by an existing root or intermediate</li>
                    <li>View CA certificate details and chain</li>
                    <li>Download CA certificates</li>
                    <li>Enable/disable CAs</li>
                    <li>Configure CA-specific settings</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/authorities<br />
                    POST /api/v1/admin/authorities/create-root<br />
                    POST /api/v1/admin/authorities/create-intermediate<br />
                    GET /api/v1/admin/authorities/&#123;serial&#125;<br />
                    PUT /api/v1/admin/authorities/&#123;id&#125;
                </div>
            </section>

            {/* Protocol Config */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Protocol Configuration</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/authorities/protocols
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Configure certificate enrollment protocols per CA. Controls which protocols are enabled
                    and their specific settings.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Enable/disable ACME, EST, SCEP, and CMP per CA</li>
                    <li>Configure protocol-specific parameters (challenge types, encryption settings)</li>
                    <li>Set protocol endpoint URLs</li>
                    <li>View protocol health and usage statistics</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/protocol-configs/&#123;caId&#125;<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* CRL Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">CRL Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/crl
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage Certificate Revocation Lists for each CA. Configure automatic generation schedules
                    and trigger manual CRL generation.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View current CRL for each CA with next-update time</li>
                    <li>Configure CRL generation schedule (interval, overlap period)</li>
                    <li>Trigger immediate CRL regeneration</li>
                    <li>Download CRL in DER or PEM format</li>
                    <li>View CRL entries (revoked certificate list)</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/user/authorities/&#123;serial&#125;/crl<br />
                    POST /api/v1/admin/crl-schedules<br />
                    GET /api/v1/admin/ssh/certificates/&#123;id&#125;/download
                </div>
            </section>

            {/* Trust Anchors */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Trust Anchors</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/trust-anchors
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage trusted CA certificates for cross-certification and external trust relationships.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Import external CA certificates as trust anchors</li>
                    <li>View and manage the trust store</li>
                    <li>Configure trust anchor usage (TLS, signing verification)</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/trust-anchors<br />
                    POST /api/v1/admin/trust-anchors<br />
                    DELETE /api/v1/admin/trust-anchors/&#123;id&#125;
                </div>
            </section>

            {/* LDAP Publishers */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">LDAP Publishers</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/authorities/:caId/ldap
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Configure LDAP directory publishing for a specific CA. Certificates and CRLs can be
                    automatically published to LDAP directories for discovery by relying parties.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Configure LDAP server connection (host, port, bind DN, credentials)</li>
                    <li>Set publication base DN and attribute mappings</li>
                    <li>Enable/disable automatic publishing on certificate issuance</li>
                    <li>Test LDAP connectivity</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers<br />
                    POST /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers<br />
                    PUT /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers/&#123;id&#125;
                </div>
            </section>

            {/* Profile Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Profile Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/profiles
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Certificate profiles define the policy constraints and extensions applied during certificate
                    issuance. System profiles set a baseline; CA-level profiles can inherit and override with
                    stricter-only constraints.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Create and edit certificate profiles</li>
                    <li>Configure key usage, extended key usage, and basic constraints</li>
                    <li>Set allowed key algorithms and sizes</li>
                    <li>Define validity period limits</li>
                    <li>Configure subject DN rules and SAN validation</li>
                    <li>Profile inheritance: system profiles as baseline, CA profiles inherit and restrict</li>
                    <li>Assign profiles to specific CAs</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/cert-profiles<br />
                    POST /api/v1/admin/cert-profiles<br />
                    PUT /api/v1/admin/authorities/&#123;id&#125;<br />
                    GET /api/v1/admin/cert-profiles/&#123;id&#125;/resolved
                </div>
            </section>

            {/* Certificate Templates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Templates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/templates
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Pre-configured templates that combine a profile with default subject values, making it easy
                    for users to request certificates for common use cases.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Create templates with pre-filled subject fields and SAN patterns</li>
                    <li>Link templates to profiles and CAs</li>
                    <li>Set template visibility for user self-service</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/templates<br />
                    POST /api/v1/admin/templates<br />
                    PUT /api/v1/admin/templates/&#123;id&#125;
                </div>
            </section>

            {/* ACME Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">ACME Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/acme
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage ACME (Automatic Certificate Management Environment) accounts and orders.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View registered ACME accounts</li>
                    <li>Monitor active orders and authorizations</li>
                    <li>Revoke ACME-issued certificates</li>
                    <li>Configure ACME challenge types (HTTP-01, DNS-01, TLS-ALPN-01)</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/acme/eab-keys<br />
                    GET /api/v1/admin/audit/acme
                </div>
            </section>

            {/* SSH Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">SSH Certificates</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/ssh
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage SSH CA keys and SSH certificate issuance. Supports both user and host certificate types.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View and manage SSH CA signing keys</li>
                    <li>Issue SSH user and host certificates</li>
                    <li>Configure allowed principals and extensions</li>
                    <li>Set certificate validity periods</li>
                    <li>Manage Key Revocation Lists (KRL)</li>
                    <li>View issued SSH certificates</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/ssh/ca-keys<br />
                    POST /api/v1/integration/cert-manager/sign<br />
                    GET /api/v1/user/ssh/certificates<br />
                    GET /api/v1/admin/ssh/ca-keys/&#123;id&#125;/krl
                </div>
            </section>

            {/* Users */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Users</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/users
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    User account management. Create, view, enable, disable, and manage user accounts and their
                    group memberships.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>List all users with search and filter</li>
                    <li>Create new user accounts</li>
                    <li>Enable/disable user accounts</li>
                    <li>View and modify group assignments</li>
                    <li>Reset user passwords</li>
                    <li>View user MFA enrollment status</li>
                    <li>View user certificate and request history</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/users<br />
                    POST /api/v1/admin/users<br />
                    PUT /api/v1/admin/users/&#123;id&#125;<br />
                    DELETE /api/v1/admin/users/&#123;id&#125;
                </div>
            </section>

            {/* Group Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Group Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/groups
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    CA-scoped groups provide fine-grained authorization. Each CA automatically gets groups
                    generated from its label, and system groups provide global access. Users are assigned
                    to groups with a specific role level.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View all groups (system and CA-scoped)</li>
                    <li>Create custom groups</li>
                    <li>Manage group members and their role levels</li>
                    <li>View effective permissions for a group</li>
                    <li>Auto-generated groups per CA label</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/groups<br />
                    POST /api/v1/admin/groups<br />
                    PUT /api/v1/admin/groups/&#123;id&#125;<br />
                    POST /api/v1/admin/groups/&#123;id&#125;/members
                </div>
            </section>

            {/* Role Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Role Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/roles
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    View and manage the role definitions used in the CA-scoped authorization model. Roles
                    define the permission level assigned to users within groups.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View all role definitions (Administrator, Operator, Auditor, etc.)</li>
                    <li>See effective permissions for each role level</li>
                    <li>Understand role hierarchy and inheritance</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/roles
                </div>
            </section>

            {/* Enrollment Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Enrollment Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/enrollment
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Configure and manage certificate enrollment workflows including auto-enrollment policies.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Configure enrollment policies</li>
                    <li>Set auto-approval rules</li>
                    <li>Manage enrollment agents</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/enrollment-tokens<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* Key Ceremonies */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Key Ceremonies</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/ceremonies
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage key ceremony procedures for high-security CA key generation and signing operations.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Initiate key ceremonies for root CA creation</li>
                    <li>Multi-party authorization workflows</li>
                    <li>Ceremony audit logs and attestation records</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/ceremonies<br />
                    POST /api/v1/admin/ceremonies
                </div>
            </section>

            {/* Quota Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Quota Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/quotas
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Configure and monitor resource quotas per tenant, CA, or group.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Set certificate issuance limits</li>
                    <li>Configure rate limits per tenant</li>
                    <li>Monitor quota usage and remaining capacity</li>
                    <li>Alert thresholds for quota exhaustion</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/quotas<br />
                    PUT /api/v1/admin/quotas/&#123;groupId&#125;
                </div>
            </section>

            {/* Certificate Inventory (Intelligence) */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Certificate Inventory</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/intel/inventory
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Comprehensive certificate inventory analysis across the entire deployment.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Certificate counts by algorithm, key size, and profile</li>
                    <li>Issuance trends over time</li>
                    <li>Algorithm distribution analysis</li>
                    <li>Weak key detection</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/compliance
                </div>
            </section>

            {/* Vulnerabilities */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Vulnerabilities</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/intel/vulnerabilities
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Certificate vulnerability scanning results. Identifies certificates with weak algorithms,
                    short key lengths, or other security concerns.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Vulnerability scan results with severity ratings</li>
                    <li>Certificates using deprecated algorithms (SHA-1, RSA-1024)</li>
                    <li>Certificates with excessively long validity periods</li>
                    <li>Missing or incorrect extensions</li>
                    <li>Remediation recommendations</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/compliance
                </div>
            </section>

            {/* Compliance */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Compliance</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/intel/compliance
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Generate compliance reports and export data for auditing purposes.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Generate compliance reports against policy baselines</li>
                    <li>Export reports in CSV format</li>
                    <li>Certificate policy compliance checks</li>
                    <li>Historical compliance trend tracking</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/compliance<br />
                    POST /api/v1/admin/compliance/export/csv
                </div>
            </section>

            {/* Audit Logs */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Audit Logs</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/audit
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Comprehensive audit logging with separate tabs for different log categories.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>General audit tab: user actions, certificate operations, configuration changes</li>
                    <li>Network audit tab: API requests, protocol transactions</li>
                    <li>Protocol audit tab: ACME, EST, SCEP, CMP protocol-level events</li>
                    <li>Filter by user, action type, date range, and resource</li>
                    <li>Export audit logs</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/audit<br />
                    GET /api/v1/admin/audit/network<br />
                    GET /api/v1/admin/audit/est
                </div>
            </section>

            {/* Notification Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Notification Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/notifications
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Configure notification rules for certificate events such as expiry warnings, issuance
                    confirmations, and revocation alerts.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Create notification rules with event triggers</li>
                    <li>Configure email notification recipients</li>
                    <li>Set expiry warning thresholds (e.g., 30, 14, 7 days)</li>
                    <li>View notification delivery history</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/notifications<br />
                    POST /api/v1/admin/notifications/test<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* Tenant Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Tenant Management</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/tenants
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Multi-tenant management for organizations sharing a single ModularCA deployment. Each tenant
                    has isolated CAs, users, and quotas.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Create and manage tenants</li>
                    <li>Configure tenant-level quotas and limits</li>
                    <li>View tenant resource usage</li>
                    <li>Enable/disable tenants</li>
                    <li>System tenant vs. organization tenants</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/tenants<br />
                    POST /api/v1/admin/tenants<br />
                    PUT /api/v1/admin/tenants/&#123;id&#125;
                </div>
            </section>

            {/* Settings */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Settings</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/settings
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    System-wide configuration settings for the ModularCA platform.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>General settings: system name, public base URL</li>
                    <li>Security settings: password policy, session timeout, MFA requirements</li>
                    <li>Email/SMTP configuration</li>
                    <li>Logging level configuration</li>
                    <li>Rate limiting settings</li>
                    <li>OCSP responder configuration</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/config<br />
                    PUT /api/v1/admin/tenants/&#123;id&#125;/settings
                </div>
            </section>

            {/* Backup & Restore */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Backup &amp; Restore</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/backup
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage system backups and restore operations for disaster recovery.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Trigger manual backups</li>
                    <li>Configure backup schedules</li>
                    <li>View backup history</li>
                    <li>Restore from a previous backup</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    POST /api/v1/admin/backup<br />
                    GET /api/v1/admin/backup<br />
                    POST /api/v1/admin/backup/restore
                </div>
            </section>

            {/* Web TLS Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Web TLS Certificate</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/webtls
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage the TLS certificate used by the ModularCA management UI and API. Renew or
                    replace the certificate issued during initial setup, including support for post-quantum
                    key algorithms.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>View current Web TLS certificate details and expiry</li>
                    <li>Renew with the same or different key algorithm</li>
                    <li>Configure Subject Alternative Names (DNS, IP)</li>
                    <li>PQC key algorithm support (ML-DSA, SLH-DSA, Ed25519)</li>
                    <li>Automatic restart after certificate renewal</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/webtls<br />
                    POST /api/v1/admin/certificates/&#123;serial&#125;/renew
                </div>
            </section>

            {/* Whitelists */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Whitelists</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/whitelists
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Manage IP and domain whitelists for access control. Whitelists restrict which clients
                    can access specific services or enrollment endpoints.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Create and manage IP address whitelists</li>
                    <li>Configure domain-based access rules</li>
                    <li>Assign whitelists to specific CAs or protocols</li>
                    <li>View whitelist hit counts and activity</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/admin/whitelists<br />
                    POST /api/v1/admin/whitelists<br />
                    PUT /api/v1/admin/whitelists/&#123;id&#125;<br />
                    DELETE /api/v1/admin/whitelists/&#123;id&#125;
                </div>
            </section>

            {/* My Security */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">My Security</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-3">
                    Route: /admin/security
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Personal security settings for the currently logged-in administrator.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Change password</li>
                    <li>Enroll or manage TOTP authenticator</li>
                    <li>Register WebAuthn/FIDO2 security keys</li>
                    <li>View active sessions</li>
                    <li>Revoke sessions</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm">
                    GET /api/v1/me<br />
                    PUT /api/v1/account/password<br />
                    POST /api/v1/auth/mtls/enroll<br />
                    POST /api/v1/auth/webauthn/register
                </div>
            </section>

            {/* Auth routes note */}
            <section className="mb-10">
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <h3 className="text-lg font-semibold text-blue-800 dark:text-blue-300 mb-2">Authentication Routes</h3>
                    <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                        The Admin UI also includes unauthenticated routes for the login flow:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mt-2">
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/login</code> — Username/password login form, shared with the self-service portal</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-setup</code> — First-time MFA enrollment</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-verify</code> — MFA challenge verification</li>
                        <li><code className="text-sm bg-white dark:bg-gray-800 px-1.5 py-0.5 rounded">/mfa-callback</code> — WebAuthn callback handler</li>
                    </ul>
                </div>
            </section>
        </div>
    );
}
