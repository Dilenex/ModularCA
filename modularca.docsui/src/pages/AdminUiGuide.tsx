export default function AdminUiGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-2xl font-semibold text-ink mb-4">
                Admin UI Guide
            </h1>
            <p className="text-lg text-ink-muted leading-relaxed mb-8">
                The Admin UI is served at <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin</code> and
                provides full management access to the ModularCA platform. All routes require authentication and are
                wrapped in a <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">ProtectedRoute</code> with
                step-up MFA support for sensitive operations. All pages support a dark mode toggle for comfortable
                use in low-light environments.
            </p>

            {/* MFA Step-Up on Sensitive Operations */}
            <section className="mb-10">
                <div className="border-l-4 border-warn bg-warn-soft p-4 rounded-r">
                    <h2 className="text-2xl font-bold text-warn mb-3">MFA Step-Up on Sensitive Operations</h2>
                    <p className="text-ink leading-relaxed mb-3">
                        All destructive and sensitive operations in the Admin UI require MFA step-up verification.
                        When a user triggers a protected action, a TOTP modal appears prompting for a 6-digit
                        verification code before the operation proceeds. Step-up supports both TOTP codes and
                        WebAuthn/FIDO2 security keys. This applies even if the user already
                        authenticated with MFA at login.
                    </p>
                    <h3 className="text-lg font-semibold text-ink mb-2">Operations Requiring Step-Up</h3>
                    <ul className="list-disc list-inside space-y-1 text-ink mb-3">
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
                    <p className="text-ink leading-relaxed">
                        The step-up modal is enforced client-side and server-side. The backend rejects any
                        sensitive API call that does not include a valid, recent TOTP verification token.
                    </p>
                </div>
            </section>

            {/* Dark Mode */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Dark Mode</h2>
                <p className="text-ink leading-relaxed mb-3">
                    All Admin UI pages support a dark mode toggle. The preference is persisted in local storage and
                    applies immediately across every page. The toggle is accessible from the top navigation bar.
                    Dark mode is also respected by charts, code blocks, and the TOTP step-up modal.
                </p>
            </section>

            {/* Navigation Structure */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Navigation Structure</h2>
                <p className="text-ink leading-relaxed mb-3">
                    The sidebar navigation is organized into 5 collapsible sections. Items are role-gated:
                    hidden links cannot be reached by typing the URL either, as the server enforces the same
                    role check.
                </p>
                <div className="bg-sunken rounded p-4 data-mono leading-relaxed">
                    <strong>Overview:</strong> Dashboard, System Health, My Security<br />
                    <strong>Certificates:</strong> All Certificates, Request Certificate, Pending Requests,
                        Search, Cert Inventory, Vulnerabilities, Compliance, Expiry Calendar<br />
                    <strong>CA Management:</strong> Authorities, Profiles, Templates, CRL Management,
                        Trust Anchors, Key Ceremonies, Protocol Config<br />
                    <strong>Access &amp; Identity:</strong> Users, Groups, Roles, Enrollment, ACME<br />
                    <strong>Administration:</strong> Spaces, Settings, Audit Logs, Notifications, Quotas,
                        Whitelists, Backup &amp; Restore, Web TLS Certificate
                </div>
            </section>

            {/* Dashboard */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Dashboard</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/dashboard&nbsp;&nbsp;(also /admin/)
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    The landing page after login. Provides a system-wide overview of the ModularCA deployment
                    with real-time status information.
                </p>
                <h3 className="text-lg font-semibold text-ink mb-2">Key Features</h3>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>CA status cards showing each authority's health, key algorithm, and certificate count</li>
                    <li>Recently issued certificates with quick links to details</li>
                    <li>Pending request count with approve/reject shortcuts</li>
                    <li>Expiring certificate warnings for the next 30/60/90 days</li>
                    <li>System health summary (scheduler, database, OCSP responder)</li>
                    <li>Quick-action buttons for common tasks (issue certificate, create CA)</li>
                </ul>
                <h3 className="text-lg font-semibold text-ink mb-2">Clearing an expiry warning</h3>
                <p className="text-ink leading-relaxed mb-3">
                    A certificate that expires within 30 days, or expired in the last 30, with no replacement is listed
                    under Needs attention. A reissue or renewal clears it. When none is coming, there are two other ways,
                    and neither revokes the certificate or changes the CRL and OCSP answers:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">Dismiss</span>, on the dashboard row or the certificate&apos;s page,
                        silences the warning and the expiry e-mails. The certificate can still be renewed by hand, by
                        auto-renewal or by its client.</li>
                    <li><span className="font-semibold">Retire</span>, on the certificate&apos;s page, also stops every
                        renewal from it: the console, the user portal, auto-renewal and protocol renewals refuse it, and its
                        subject needs a new enrollment. Use it for a host or device that is gone.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    Both need cert.revoke on the issuing CA, are audited, and can be undone from the certificate&apos;s page.
                    Revoke a certificate only when it must stop being trusted, for example when its key may have leaked.
                </p>
                <h3 className="text-lg font-semibold text-ink mb-2">Related API Endpoints</h3>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/certificates?pageSize=10<br />
                    GET /api/v1/admin/authorities<br />
                    GET /api/v1/admin/requests<br />
                    GET /api/v1/admin/audit?pageSize=10
                </div>
            </section>

            {/* System Health */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">System Health</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/health
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Detailed system health monitoring with real-time metrics and background scheduler status.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Database connection pool metrics</li>
                    <li>Background scheduler status (CRL generation, OCSP updates, cleanup jobs)</li>
                    <li>Certificate counts by status (active, revoked, expired)</li>
                    <li>Uptime and version information</li>
                    <li>Memory and resource utilization</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The Health Checks card shows the readiness payload, <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/health/ready</code>,
                    which answers only a caller the SystemAuditor policy admits. Its signer entry says whether the signer has unlocked its
                    keystore, and, on an install with SSH CAs, how many SSH CA keys the signer holds
                    (<code className="text-sm bg-sunken px-1.5 py-0.5 rounded">checks.signer.sshKeys</code>):
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">total</code> and <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">held</code>: the card shows them as &ldquo;2 of 3 held by the signer&rdquo;</li>
                    <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">awaitingImport</code>: keys that are still key files on the node, each with <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">id</code>, <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">name</code>, <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">reasonCode</code> and <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">reason</code></li>
                    <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">notHeld</code>: keys recorded as the signer&apos;s for which the unlocked signer lists no key, with the same four fields</li>
                    <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">unknown</code>: how many keys could not be checked because the signer is locked or did not answer</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The reasons here are one fixed sentence per code and name no path; the SSH CA key&apos;s own page has the whole
                    reason, with the path. An SSH CA key that is not held never makes the node unhealthy: SSH is not a reason to
                    take a node that issues X.509 certificates out of service. <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">sshKeys</code> can
                    be null when the keys could not be read.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /health/ready<br />
                    GET /api/v1/admin/scheduler/health<br />
                    GET /api/v1/admin/certificates/health/summary
                </div>
            </section>

            {/* Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Certificates</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/certificates
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    The main certificate inventory view. Lists all certificates across all CAs with filtering
                    and bulk operations.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Paginated certificate list with sortable columns</li>
                    <li>Filter by status (active, revoked, expired, pending)</li>
                    <li>Filter by issuing CA</li>
                    <li>Download individual certificates in PEM, DER, or full-chain format (PFX/private key export is only available in the User UI)</li>
                    <li>Revoke certificates with reason code selection (requires MFA step-up)</li>
                    <li>Hold and unhold certificates (requires MFA step-up)</li>
                    <li>Certificate detail view with parsed X.509 extensions: AIA, CDP, Basic Constraints, Key Usage, Extended Key Usage, SANs, Subject Key Identifier, Authority Key Identifier, and Certificate Policies</li>
                    <li>View subject, fingerprints, validity dates, and serial number</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The page has two tabs, X.509 and SSH, for whoever can use both. The SSH tab
                    (<code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin/certificates?tab=SSH</code>) lists the SSH
                    certificates of every SSH CA key you may view, with the key as a column and as a filter, and has download,
                    revoke and &ldquo;Find by host log line&rdquo;. It is shown to whoever may view certificates on an SSH CA. See SSH below.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/certificates<br />
                    GET /api/v1/admin/certificates/&#123;serial&#125;<br />
                    GET /api/v1/admin/ssh/certificates<br />
                    GET /api/v1/admin/ssh/certificates/&#123;id&#125;/download<br />
                    POST /api/v1/admin/certificates/&#123;certId&#125;/revoke
                </div>
            </section>

            {/* Request Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Request Certificate</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/certificates/request
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Direct certificate issuance for administrators. Supports both CSR-based and server-side key
                    generation workflows.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Upload a PEM-encoded CSR or paste CSR text</li>
                    <li>Server-side key generation with algorithm and key size selection</li>
                    <li>Select issuing CA and certificate profile</li>
                    <li>Edit subject DN fields (CN, O, OU, L, ST, C)</li>
                    <li>Add Subject Alternative Names (DNS, IP, email, URI)</li>
                    <li>Set custom validity period within profile limits</li>
                    <li>Preview effective certificate extensions before signing</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The page has two tabs, X.509 and SSH, for whoever can use both. The SSH tab
                    (<code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin/certificates/request?tab=SSH</code>) signs an
                    SSH key for a user of the console, a service identity or a host. It is shown to whoever may sign on at
                    least one SSH CA. See &ldquo;Signing for a user, a service identity or a host&rdquo; under SSH below.
                </p>
                <h3 className="text-lg font-semibold text-ink mb-2">Post-Quantum Cryptography</h3>
                <p className="text-ink leading-relaxed mb-3">
                    The key algorithm dropdown now includes NIST post-quantum signature algorithms alongside
                    classical algorithms. Supported PQC algorithms:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><strong>ML-DSA-44, ML-DSA-65, ML-DSA-87</strong> — NIST post-quantum digital signature (formerly CRYSTALS-Dilithium)</li>
                    <li><strong>SLH-DSA-SHA2-128F</strong> — NIST stateless hash-based signature (formerly SPHINCS+)</li>
                    <li><strong>Ed448</strong> — Edwards-curve Digital Signature Algorithm (448-bit)</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    POST /api/v1/admin/ssh/profiles/request<br />
                    POST /api/v1/admin/certificates/issue-with-key<br />
                    GET /api/v1/admin/cert-profiles<br />
                    GET /api/v1/admin/authorities
                </div>
            </section>

            {/* Certificate Search */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Certificate Search</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/certificates/search
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Advanced search across all certificates with multiple filter criteria.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Search by subject CN, serial number, or thumbprint</li>
                    <li>Filter by Subject Alternative Name (DNS, IP, email)</li>
                    <li>Date range filters for issuance and expiry</li>
                    <li>Filter by issuing CA and profile</li>
                    <li>Status filter (active, revoked, expired)</li>
                    <li>Export search results</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/certificates/tags/search
                </div>
            </section>

            {/* Expiry Calendar */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Expiry Calendar</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/certificates/expiry
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Visual calendar view showing upcoming certificate expirations. Helps plan renewals and
                    prevent outages from expired certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Monthly calendar with expiration counts per day</li>
                    <li>Color-coded urgency (red for imminent, yellow for upcoming)</li>
                    <li>Click a day to see the specific certificates expiring</li>
                    <li>Filter by CA or profile</li>
                    <li>Quick renew/reissue actions</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/certificates/health/summary
                </div>
            </section>

            {/* Certificate Requests */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Certificate Requests</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/certificates/requests
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage the certificate request lifecycle. Requests submitted by users through the User UI
                    or API appear here for approval.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Filter by status: pending, approved, issued, rejected, cancelled</li>
                    <li>Review CSR details and requested subject/SANs</li>
                    <li>Approve requests (triggers signing and issuance)</li>
                    <li>Reject requests with a reason message</li>
                    <li>Cancel pending requests</li>
                    <li>View request history and audit trail</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/requests<br />
                    POST /api/v1/admin/ceremonies/&#123;id&#125;/approve<br />
                    POST /api/v1/admin/ceremonies/&#123;id&#125;/reject<br />
                    POST /api/v1/admin/requests/&#123;id&#125;/cancel
                </div>
            </section>

            {/* CA Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">CA Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/authorities/manage
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage the CA hierarchy. Create, view, and configure Certificate Authorities including
                    root, intermediate, and issuing CAs.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Visual CA hierarchy tree</li>
                    <li>Create new root CA with key algorithm selection</li>
                    <li>Create intermediate CAs signed by an existing root or intermediate</li>
                    <li>View CA certificate details and chain</li>
                    <li>Download CA certificates</li>
                    <li>Enable/disable CAs</li>
                    <li>Configure CA-specific settings</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The page has two tabs, X.509 and SSH, for whoever can use both. The SSH tab
                    (<code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin/authorities/manage?tab=SSH</code>) lists the SSH
                    CA keys and has the form for a new one. It is shown to whoever may list the SSH CA keys or generate one.
                    See SSH below.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/authorities<br />
                    POST /api/v1/admin/authorities/create-root<br />
                    POST /api/v1/admin/authorities/create-intermediate<br />
                    GET /api/v1/admin/authorities/&#123;serial&#125;<br />
                    PUT /api/v1/admin/authorities/&#123;id&#125;
                </div>
            </section>

            {/* Protocol Config */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Protocol Configuration</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/authorities/protocols
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Configure certificate enrollment protocols per CA. Controls which protocols are enabled
                    and their specific settings.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Enable/disable ACME, EST, SCEP, and CMP per CA</li>
                    <li>Configure protocol-specific parameters (challenge types, encryption settings)</li>
                    <li>Set protocol endpoint URLs</li>
                    <li>View protocol health and usage statistics</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/protocol-configs/&#123;caId&#125;<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* CRL Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">CRL Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/crl
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage Certificate Revocation Lists for each CA. Configure automatic generation schedules
                    and trigger manual CRL generation.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View current CRL for each CA with next-update time</li>
                    <li>Configure CRL generation schedule (interval, overlap period)</li>
                    <li>Trigger immediate CRL regeneration</li>
                    <li>Download CRL in DER or PEM format</li>
                    <li>View CRL entries (revoked certificate list)</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/user/authorities/&#123;serial&#125;/crl<br />
                    POST /api/v1/admin/crl-schedules<br />
                    GET /api/v1/admin/ssh/certificates/&#123;id&#125;/download
                </div>
            </section>

            {/* Trust Anchors */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Trust Anchors</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/trust-anchors
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage trusted CA certificates for cross-certification and external trust relationships.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Import external CA certificates as trust anchors</li>
                    <li>View and manage the trust store</li>
                    <li>Configure trust anchor usage (TLS, signing verification)</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/trust-anchors<br />
                    POST /api/v1/admin/trust-anchors<br />
                    DELETE /api/v1/admin/trust-anchors/&#123;id&#125;
                </div>
            </section>

            {/* LDAP Publishers */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">LDAP Publishers</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/authorities/:caId/ldap
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Configure LDAP directory publishing for a specific CA. Certificates and CRLs can be
                    automatically published to LDAP directories for discovery by relying parties.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Configure LDAP server connection (host, port, bind DN, credentials)</li>
                    <li>Set publication base DN and attribute mappings</li>
                    <li>Enable/disable automatic publishing on certificate issuance</li>
                    <li>Test LDAP connectivity</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers<br />
                    POST /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers<br />
                    PUT /api/v1/admin/authorities/&#123;caId&#125;/ldap-publishers/&#123;id&#125;
                </div>
            </section>

            {/* Profile Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Profile Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/profiles
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Certificate profiles define the policy constraints and extensions applied during certificate
                    issuance. System profiles set a baseline; CA-level profiles can inherit and override with
                    stricter-only constraints.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Create and edit certificate profiles</li>
                    <li>Configure key usage, extended key usage, and basic constraints</li>
                    <li>Set allowed key algorithms and sizes</li>
                    <li>Define validity period limits</li>
                    <li>Configure subject DN rules and SAN validation</li>
                    <li>Profile inheritance: system profiles as baseline, CA profiles inherit and restrict</li>
                    <li>Assign profiles to specific CAs</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/cert-profiles<br />
                    POST /api/v1/admin/cert-profiles<br />
                    PUT /api/v1/admin/authorities/&#123;id&#125;<br />
                    GET /api/v1/admin/cert-profiles/&#123;id&#125;/resolved
                </div>
            </section>

            {/* Certificate Templates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Certificate Templates</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/templates
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Pre-configured templates that combine a profile with default subject values, making it easy
                    for users to request certificates for common use cases.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Create templates with pre-filled subject fields and SAN patterns</li>
                    <li>Link templates to profiles and CAs</li>
                    <li>Set template visibility for user self-service</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/templates<br />
                    POST /api/v1/admin/templates<br />
                    PUT /api/v1/admin/templates/&#123;id&#125;
                </div>
            </section>

            {/* ACME Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">ACME Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/acme
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage ACME (Automatic Certificate Management Environment) accounts and orders.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View registered ACME accounts</li>
                    <li>Monitor active orders and authorizations</li>
                    <li>Revoke ACME-issued certificates</li>
                    <li>Configure ACME challenge types (HTTP-01, DNS-01, TLS-ALPN-01)</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/acme/eab-keys<br />
                    GET /api/v1/admin/audit/acme
                </div>
            </section>

            {/* SSH */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">SSH</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Routes: /admin/authorities/manage?tab=SSH, /admin/authorities/ssh/&#123;id&#125;,
                    /admin/certificates?tab=SSH, /admin/certificates/ssh/&#123;id&#125;, /admin/certificates/request?tab=SSH
                    (the old /admin/ssh paths redirect here until 0.5)
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage SSH CA keys and SSH certificate issuance. Supports both user and host certificate types.
                    SSH has no menu entry of its own. Each part is an SSH tab on the page for the same thing in X.509:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">Authorities, SSH tab:</span> the SSH CA keys, the form for a new key, and the plaintext notice. A key&apos;s own page, with its review date, storage, login names and revocation list, is under Authorities at <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin/authorities/ssh/&#123;id&#125;</code></li>
                    <li><span className="font-semibold">All Certificates, SSH tab:</span> the SSH certificates of every SSH CA key you may view, download and revoke, and &ldquo;Find by host log line&rdquo;. A certificate&apos;s own page is under Certificates at <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/admin/certificates/ssh/&#123;id&#125;</code></li>
                    <li><span className="font-semibold">Request Certificate, SSH tab:</span> Sign key, for a user, a service identity or a host</li>
                    <li><span className="font-semibold">Profiles:</span> the SSH Signing, SSH Cert and SSH Request tabs, as before</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    A tab is shown only to whoever can use it, and a page opens for whoever can use one of its tabs.
                    SSH CAs belong to the instance, not to a space: while the console&apos;s scope is set to a space, or to a
                    CA of a space, each SSH tab says so and shows nothing else.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View and manage SSH CA signing keys</li>
                    <li>Grant login names: who may get a certificate that logs in as which account</li>
                    <li>Sign a key for a user of the console, for a service identity, or for a host</li>
                    <li>Set certificate validity periods and extensions</li>
                    <li>Download Key Revocation Lists (KRL)</li>
                    <li>View and revoke issued SSH certificates, and find one from a host log line</li>
                </ul>

                <h3 className="text-lg font-semibold text-ink mb-2">Recommended setup</h3>
                <p className="text-ink leading-relaxed mb-3">
                    Create two SSH CA keys: one of type user and one of type host. The form asks for one type and creates a
                    key that signs that type only. The two public keys go to different places: servers trust the user CA
                    key, clients trust the host CA key. They need different lifetimes, and a leaked host CA key then cannot
                    mint logins. The API still accepts a key that signs both, for keys and scripts that already do.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">User certificates:</span> 12 hours by default and 24 hours at most. A new user key&apos;s longest certificate is pre-filled as 24 hours, and the seeded user request profile allows 12</li>
                    <li><span className="font-semibold">A sensitive login name</span> such as <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">root</code>: grant it with a longest certificate of 1 hour. See Login names below</li>
                    <li><span className="font-semibold">Host certificates:</span> 1 year. A new host key&apos;s longest certificate is pre-filled as 8760 hours. Each host certificate is signed by hand, so a year keeps that work reasonable. An expired host certificate does not lock anyone out: clients ask about the host key again, as they do for a host with no certificate</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    A certificate&apos;s lifetime is the smallest of what the SSH CA key, the three profiles and the login name
                    grants allow. Set it in one place:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">The SSH CA key</span> holds the hard ceiling. Nothing can issue a longer certificate from it</li>
                    <li><span className="font-semibold">The request profile</span> holds the everyday number, and decides which signing and certificate profiles a person may ask through and whether a request needs approval. Change this one to change how long people&apos;s certificates last</li>
                    <li><span className="font-semibold">The signing profile</span> names the SSH CA key and the extensions a certificate gets when the request asks for none. It is created with the key, at the key&apos;s ceiling. Leave its lifetime there</li>
                    <li><span className="font-semibold">The certificate profile</span> limits the login names or hostnames and the extensions a certificate may carry. Leave its lifetime at the ceiling too</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    A new install is seeded with two user certificate profiles. <span className="font-semibold">SSH User Cert - Standard</span> takes
                    any valid login name, at most three, and allows a terminal (permit-pty) and permit-user-rc; a request
                    through it that asks for agent, port or X11 forwarding is refused. <span className="font-semibold">SSH User Cert - Forwarding</span> is
                    the same with agent and port forwarding on every certificate. It is seeded but attached to no request
                    profile: add it to a request profile&apos;s certificate profiles for the people who need forwarding. Agent
                    forwarding lets a compromised server use the holder&apos;s access to other servers, which is why it is not the
                    default, and why the signing profile created with a user key now gives a terminal and nothing else.
                    An install that already had SSH profiles keeps them exactly as they are; only new installs and new keys
                    get these defaults.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    <span className="font-semibold">The type of a profile.</span> An SSH request profile and an SSH certificate profile each have a
                    Certificate type: User, Host or Either. A User profile is offered and accepted only for user certificates,
                    a Host profile only for host certificates, and an Either profile for both. A profile of the other type is
                    refused when a key is signed, with a message that says so. The five profiles a new install is seeded
                    with carry their type. On an upgrade the type is set on those five where they still have their seeded
                    names, and every other existing profile is Either, which is how it worked before. Set the type on your
                    own profiles under Profiles, so that a form for a user certificate no longer offers a host profile.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    <span className="font-semibold">The review date.</span> An SSH CA key does not expire. Each key has a Review by date: two years after it was
                    created for a key that signs user certificates, five years for a host-only key. Nothing stops working on
                    that date. The key keeps signing, its certificates stay valid and its revocation list is still served. From
                    90 days before the date, and after it, the key list and the key&apos;s page mark the key as due for review, and
                    the administrators are told once by the daily expiry notification, where e-mail is set up. Decide whether
                    the key should still be in use, then move the date in the Review section of the key&apos;s page. Moving it
                    takes the right to manage the SSH CA and is audited.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Where SSH CA keys are held</h3>
                <p className="text-ink leading-relaxed mb-3">
                    From 0.4.2 the signer holds every SSH CA key, in its SSH keystore
                    (<code className="text-sm bg-sunken px-1.5 py-0.5 rounded">keystores/ssh-ca.keystore</code>), and builds and signs every SSH
                    certificate itself. The node holds no SSH CA key and starts no OpenSSH program. A new SSH CA&apos;s key is
                    generated by the signer and never written to the node; the form says so. Where the instance requires key
                    ceremonies, the signer checks the approved ceremony itself before it generates the key.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    The SSH CA key list has a Storage column, and each key&apos;s page a Key storage section, with one of four states:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">Held by the signer:</span> the signer holds the key and signs with it</li>
                    <li><span className="font-semibold">Awaiting import:</span> the key is still a file on the node, from before 0.4.2. It signs nothing until it has been imported. The row and the key&apos;s page give the reason, the path the file is expected at, and what to do</li>
                    <li><span className="font-semibold">Not held:</span> the SSH CA is recorded as held by the signer, but the signer holds no key for it: its creation stopped before the key was committed, or the signer lost its SSH keystore. It signs nothing. Disable it and create a new one, or restore the signer&apos;s SSH keystore from a backup</li>
                    <li><span className="font-semibold">Unknown:</span> the signer is locked or did not answer, so it could not be asked</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The Sign key form does not sign, and gives the reason, while the selected SSH CA key is awaiting import or not held.
                    Certificates such a key has issued can still be revoked, and its KRL is still served. When signing or
                    creating a key is refused, the form shows the server&apos;s own reason: for example that the signer is locked,
                    that the signer must be upgraded first, or which rule of the certificate the signer refused.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">The plaintext notice</h3>
                <p className="text-ink leading-relaxed mb-3">
                    An install that had SSH CAs before 0.4.2 kept their private keys as plaintext files on the node. The SSH
                    tab of Authorities then shows a warning: the keys that were imported into the signer and when, where each file was and whether
                    it has been removed, and the backup archives and pre-restore snapshots in the backup directory that were
                    written before the last import and may still hold the keys. Rotating an SSH CA, which is a new SSH CA and
                    new trust lines on the servers, is the only remedy; this release tells you and leaves the decision to you.
                    Each administrator can dismiss the notice for their own account. It stays on the page of every SSH CA key
                    that was imported or is awaiting import, and it comes back when another key is imported.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Extensions are exact</h3>
                <p className="text-ink leading-relaxed mb-3">
                    A user certificate carries exactly the extensions its profiles and its request name: the signing
                    profile&apos;s default extensions, or the ones the request names instead, with the signing profile&apos;s force
                    command and source addresses and the cert profile&apos;s required extensions. None is added by default. Before
                    0.4.2 every user certificate also carried permit-X11-forwarding, permit-agent-forwarding,
                    permit-port-forwarding, permit-pty and permit-user-rc by default. A profile that names
                    only permit-pty now issues a certificate with permit-pty alone. The no-* names put nothing into a
                    certificate; each only withholds the permit-* of the same name. A host certificate carries no extensions.
                    A certificate needs at least one login name, or for a host one hostname: the signer refuses one with none.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Login names</h3>
                <p className="text-ink leading-relaxed mb-3">
                    A login name is an account a user certificate may log in as: what OpenSSH calls a principal. It is an
                    account on the hosts, such as <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">deploy</code>, or a role name
                    the hosts map to accounts. From 0.4.2 a certificate for a user carries only login names that user
                    holds on the SSH CA key that signs it, and a request that names anything else is refused. A user holds:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>their own username, while the key&apos;s switch &ldquo;Everyone who can request from this CA may log in as their own username&rdquo; is on. The username root is never counted, in any case: root always needs a grant;</li>
                    <li>each name granted on the key to them, until the grant ends;</li>
                    <li>each name granted on the key to a group, while they are a member of it.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    Each SSH CA key&apos;s page has a Login names section with that switch and the table of grants: the login
                    name, the user or group it is granted to, the longest certificate that may carry it, when the grant ends,
                    how many live certificates carry the name under it, and who granted it. Reading it takes the right to view
                    certificates on the SSH CA; changing it takes the right to manage the SSH CA, and every change asks for
                    step-up MFA.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">The own-username switch</span> is on for every key until it is turned off, and it is saved at once. Turn it off where console usernames are not accounts on the hosts. Turning it off revokes the live certificates that carried their holder&apos;s own username with no grant behind it. Bear in mind that whoever may create or rename a user decides that user&apos;s username, and so one login name on every key that leaves the switch on. Only root is kept out of that.</li>
                    <li><span className="font-semibold">+ Grant</span> takes several login names at once (type one, then Enter), one user or one group, an optional longest certificate in hours, an optional end date and an optional note. A name is 1 to 128 characters: first a letter, a digit or an underscore, then letters, digits and . _ @ + -. Upper and lower case are different names, as they are to sshd. A group must be an instance group, since an SSH CA belongs to the instance; a user must already have a role, a group or a grant on the SSH CA.</li>
                    <li><span className="font-semibold">A grant with an end</span> is for temporary access. No certificate under it is valid past the end, and a grant that ends within fourteen days is marked in the table. A grant that has ended gives nothing, but it still holds its place: granting the same name to the same user or group again is refused until the old grant is edited or removed. The form says so and offers the edit.</li>
                    <li><span className="font-semibold">Edit</span> changes the longest certificate, the end and the note. Lowering the limit revokes nothing; moving the end earlier revokes the certificates that would outlive it.</li>
                    <li><span className="font-semibold">Remove</span> asks first and says how many live certificates carry the name under the grant. They are revoked, unless their holder still has the name another way. The count that was revoked is shown afterwards. Grants are edited and removed one at a time, because each change is confirmed with step-up MFA.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    A user&apos;s page shows the same from the other side: every login name the user holds on each SSH CA you may
                    view and where it comes from, and the user&apos;s live SSH certificates with Revoke all. Only a name granted
                    to the user directly can be edited or removed there; one that comes from a group is changed on the group or
                    on the SSH CA. Revoke all reports how many certificates were revoked and how many were left because you may
                    not revoke on their SSH CA. A group&apos;s page lists the login names its members get, per SSH CA.
                    Disabling, renaming or deleting a user revokes every live SSH certificate issued for them; removing a
                    member from a group, or deleting the group, revokes the certificates that carried a name only through it.
                    A user who may no longer request from an SSH CA loses every live certificate they have on it, at once
                    when the right goes with a group, a role or a capability taken away in the console, and within 15
                    minutes otherwise.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    An SSH certificate profile&apos;s patterns are the outer limit on login names: a name outside them is refused
                    whoever asks. They grant nothing. Who may use which name is set on the SSH CA key.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Signing for a user, a service identity or a host</h3>
                <p className="text-ink leading-relaxed mb-3">
                    Sign key is the SSH tab of Request Certificate. Choose the SSH CA key to sign with, then answer the
                    form&apos;s first question, who the certificate is for. Only the request and certificate profiles of the
                    matching type, and those of type Either, are then offered.
                    The CA writes the name a certificate carries into host logs (its key id); the form shows it and
                    asks for none. Signing a user or a host certificate asks for step-up MFA, because whoever signs decides whose
                    name, or which host, a public key is certified as. The certificate is for one of:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">A user of this console.</span> Pick the user. Their login names on the chosen SSH CA key are listed to tick, each with where it comes from and its limit; nothing is typed. To give the user another name, grant it on the key first, so the grant is on record. The user must be allowed to request from the SSH CA themselves; for one who is not, the form says so and signs nothing. Hosts log the user&apos;s username, and the certificate is listed for that user, on the SSH tab of My Certificates in their own portal, not for you.</li>
                    <li><span className="font-semibold">A service identity with no account.</span> Give it a label of 1 to 64 letters, digits and . _ -. Hosts log it as <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">svc:label</code>, which no username can equal. Its login names are typed and checked against the certificate profile&apos;s patterns.</li>
                    <li><span className="font-semibold">A host.</span> A host certificate, which a server presents to the clients that connect to it. It takes the server&apos;s hostnames.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    For a host the CA writes the first hostname as the certificate&apos;s name in host logs.
                    &ldquo;Valid for&rdquo; starts at the most allowed: the smallest limit among the profiles, the SSH CA key and the
                    ticked login names, and never past the end of a grant. The form names the login name that sets the limit.
                    The certificate records both who it was issued to and who issued it; the tables and the certificate&apos;s
                    page show them as Issued to and Issued by. A certificate from before 0.4.2 shows &ldquo;Not recorded&rdquo; and
                    &ldquo;Issued before login names were recorded&rdquo; where the reason for a name is not known.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Shared accounts</h3>
                <p className="text-ink leading-relaxed mb-3">
                    Several people can log in to one account, such as <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">deploy</code>,
                    without sharing a key. Each person keeps their own key and gets their own certificate; the certificate
                    carries the shared account as a login name, and the host log names the person:
                </p>
                <div className="bg-sunken rounded p-4 data-mono mb-3 overflow-x-auto">
                    <pre className="text-ink">{`Oct  7 09:58:14 web01 sshd[21877]: Accepted publickey for deploy from 192.0.2.10 port 51122 ssh2: ED25519-CERT SHA256:[key] ID alice (serial 8841) CA ED25519 SHA256:[CA key]`}</pre>
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    The account is after <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">for</code>, the person after
                    <code className="text-sm bg-sunken px-1.5 py-0.5 rounded"> ID</code>, then the certificate&apos;s serial and the SSH CA
                    key&apos;s fingerprint. On each host, in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">sshd_config</code>:
                </p>
                <div className="bg-sunken rounded p-4 data-mono mb-3 overflow-x-auto">
                    <pre className="text-ink">{`TrustedUserCAKeys /etc/ssh/user_ca.pub
RevokedKeys /etc/ssh/revoked_keys.krl
# Only for the second way below:
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`}</pre>
                </div>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">TrustedUserCAKeys</span> names a file with the SSH CA key&apos;s public key, from Download Public Key on the key&apos;s page.</li>
                    <li><span className="font-semibold">A host can decide in two ways who gets into an account.</span> The first: the certificate lists the account. Grant the login name <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">deploy</code> to a group, and with no AuthorizedPrincipalsFile sshd lets a certificate into the account deploy when deploy is one of its login names. Every host that trusts the CA then accepts it. The second: the certificate lists a role, and the host maps it. Grant a role name such as <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">deployers</code>, and on each host that should let the role in, list it in the account&apos;s file, here <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/etc/ssh/auth_principals/deploy</code>, one name per line. Each host then decides which roles reach which account. With that file set, an account with no file, or one whose file lists none of the certificate&apos;s login names, lets no certificate in.</li>
                    <li><span className="font-semibold">RevokedKeys</span> names the SSH CA key&apos;s KRL, which each host has to fetch: the public URL is shown on the key&apos;s page and ends in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/ssh/ca-keys/&#123;id&#125;/krl</code>. sshd refuses every public-key login while the file it names cannot be read, so add this line only after the list has been copied there. &ldquo;Getting the revocation list to hosts&rdquo; below has the order. A certificate revoked in the console is refused by a host only once that host has the new list, so keep certificates short as well.</li>
                    <li><span className="font-semibold">sshd logs the login, not the session.</span> The line above is all sshd writes. A session that needs to know which certificate opened it, for example to record the person in a shell audit, sets <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">ExposeAuthInfo yes</code>; sshd then puts the path of a file in the session&apos;s <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">SSH_USER_AUTH</code>, and that file holds the certificate that was used.</li>
                </ul>

                <h3 className="text-lg font-semibold text-ink mb-2">Getting the revocation list to hosts</h3>
                <p className="text-ink leading-relaxed mb-3">
                    The CA revokes a certificate at once, but a host learns of it only when it has the new list, and
                    OpenSSH does not fetch it. Each SSH CA key&apos;s page has a Revocation list (KRL) section: the KRL URL,
                    the list&apos;s version and when a certificate of the key was last revoked. Copy the list to each host,
                    from Download KRL or the KRL URL, and again after each revocation. As root on the host:
                </p>
                <div className="bg-sunken rounded p-4 data-mono mb-3 overflow-x-auto">
                    <pre className="text-ink">{`# Put the list in place first, and check that it is a KRL.
install -m 0644 revoked_keys.krl /etc/ssh/revoked_keys.krl
ssh-keygen -Q -l -f /etc/ssh/revoked_keys.krl

# Only now, add this line to /etc/ssh/sshd_config:
#   RevokedKeys /etc/ssh/revoked_keys.krl
# then check the configuration and reload sshd (the unit is named sshd on some distributions).
sshd -t && systemctl reload ssh`}</pre>
                </div>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">The order matters.</span> Copy the list, then point RevokedKeys at the file, then reload sshd. Named before it exists, the file locks every public-key login out of the host. Keep a session open while you reload.</li>
                    <li><span className="font-semibold">A new list needs no reload.</span> sshd reads the file at each login. Replace it whole, for example by copying beside it and renaming over it, so a login never reads half a file.</li>
                    <li><span className="font-semibold">The list is binary.</span> It is OpenSSH&apos;s KRL format, not text. <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">ssh-keygen -Q -l -f</code> lists what it revokes, and <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">ssh-keygen -Q -f revoked_keys.krl id_ed25519-cert.pub</code> says whether a certificate is in it.</li>
                    <li><span className="font-semibold">One list per host.</span> RevokedKeys takes one file, so a host follows the list of one SSH CA key.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    A certificate&apos;s page shows when it was revoked. A certificate revoked before 0.4.2 has no time: it is
                    in the list, and it does not date it.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Finding a certificate from a host log line</h3>
                <p className="text-ink leading-relaxed mb-3">
                    On the SSH tab of All Certificates, above the table, is &ldquo;Find by host log line&rdquo;. Paste the line sshd wrote for a login. The
                    console reads it in your browser and shows what it read: the SSH CA, the serial, the name after ID and the
                    account that was logged in to. It then looks the certificate up by serial, name and CA fingerprint, on
                    the SSH CAs you may view. One match is shown at once, with who it was issued to and by and each login
                    name with why its holder had it; the one the line used is marked. No match, or one on each of several
                    SSH CAs, is said plainly. A line for a login with a plain public key or a password has no certificate in
                    it, and the console says so. Where the account in the line is not a login name of the certificate, the
                    host mapped the certificate to that account itself, with AuthorizedPrincipalsFile.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/ssh/ca-keys<br />
                    POST /api/v1/admin/ssh/ca-keys<br />
                    PUT /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/review-by<br />
                    GET /api/v1/admin/ssh/plaintext-notice<br />
                    POST /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/certificates/sign-user<br />
                    POST /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/certificates/sign-host<br />
                    GET /api/v1/admin/ssh/certificates<br />
                    GET /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/certificates<br />
                    GET /api/v1/admin/ssh/ca-keys/&#123;id&#125;/krl<br />
                    GET /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/login-names<br />
                    POST /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/login-names<br />
                    PUT /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/login-names/&#123;grantId&#125;<br />
                    DELETE /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/login-names/&#123;grantId&#125;<br />
                    PUT /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/login-names/own-username<br />
                    GET /api/v1/admin/ssh/ca-keys/&#123;caKeyId&#125;/users/&#123;userId&#125;/login-names<br />
                    GET /api/v1/admin/ssh/users/&#123;userId&#125;/login-names<br />
                    GET /api/v1/admin/ssh/groups/&#123;groupId&#125;/login-names<br />
                    GET /api/v1/admin/ssh/users/&#123;userId&#125;/certificates<br />
                    POST /api/v1/admin/ssh/users/&#123;userId&#125;/certificates/revoke<br />
                    GET /api/v1/admin/ssh/certificates/find<br />
                    GET /api/v1/admin/ssh/certificates/&#123;id&#125;
                </div>
            </section>

            {/* Users */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Users</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/users
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    User account management. Create, view, enable, disable, and manage user accounts and their
                    group memberships.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>List all users with search and filter</li>
                    <li>Create new user accounts</li>
                    <li>Enable/disable user accounts</li>
                    <li>View and modify group assignments</li>
                    <li>Reset user passwords</li>
                    <li>View user MFA enrollment status</li>
                    <li>View user certificate and request history</li>
                    <li>See the SSH login names a user holds and their live SSH certificates, grant a login name, and revoke all of the certificates</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    Disabling, renaming or deleting a user revokes every live SSH certificate issued for them. A rename
                    revokes them because hosts log the username the certificate was issued under, and that name would no
                    longer say who logged in. Taking away a user&apos;s right to request from an SSH CA revokes their
                    certificates on it. See Login names under SSH.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/users<br />
                    POST /api/v1/admin/users<br />
                    PUT /api/v1/admin/users/&#123;id&#125;<br />
                    DELETE /api/v1/admin/users/&#123;id&#125;
                </div>
            </section>

            {/* Group Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Group Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/groups
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    CA-scoped groups provide fine-grained authorization. Each CA automatically gets groups
                    generated from its label, and system groups provide global access. Users are assigned
                    to groups with a specific role level.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View all groups (system and CA-scoped)</li>
                    <li>Create custom groups</li>
                    <li>Manage group members and their role levels</li>
                    <li>View effective permissions for a group</li>
                    <li>Auto-generated groups per CA label</li>
                    <li>See and grant the SSH login names an instance group gives its members, per SSH CA</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/groups<br />
                    POST /api/v1/admin/groups<br />
                    PUT /api/v1/admin/groups/&#123;id&#125;<br />
                    POST /api/v1/admin/groups/&#123;id&#125;/members
                </div>
            </section>

            {/* Role Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Role Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/roles
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    View and manage the role definitions used in the CA-scoped authorization model. Roles
                    define the permission level assigned to users within groups.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View all role definitions (Administrator, Operator, Auditor, etc.)</li>
                    <li>See effective permissions for each role level</li>
                    <li>Understand role hierarchy and inheritance</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/roles
                </div>
            </section>

            {/* Enrollment Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Enrollment Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/enrollment
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Configure and manage certificate enrollment workflows including auto-enrollment policies.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Configure enrollment policies</li>
                    <li>Set auto-approval rules</li>
                    <li>Manage enrollment agents</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/enrollment-tokens<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* Key Ceremonies */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Key Ceremonies</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/ceremonies
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage key ceremony procedures for high-security CA key generation and signing operations.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Initiate key ceremonies for root CA creation</li>
                    <li>Multi-party authorization workflows</li>
                    <li>Ceremony audit logs and attestation records</li>
                </ul>
                <h3 className="text-lg font-semibold text-ink mb-2">With one administrator</h3>
                <p className="text-ink leading-relaxed mb-3">
                    Whoever starts a ceremony can never approve it, so a ceremony needs at least one other
                    account that can approve. When too few can, the action that would have opened the
                    ceremony is refused instead and nothing is started: &ldquo;You&apos;re the only
                    administrator who can approve this&rdquo; (code MCA-CFG-020), or &ldquo;This needs N
                    approvals and only M other administrators can approve&rdquo; (MCA-CFG-021). Service
                    identities and disabled or locked accounts do not count.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>The refusal appears where the action was taken, with links to the next step you are allowed to take</li>
                    <li>A system super-administrator can turn the requirement off: Settings, Security, Key Ceremonies for instance CAs, and the Key Ceremonies section of a space&apos;s page for that space</li>
                    <li>Or add a second administrator under Users, then try again</li>
                    <li>Both switches warn before you turn the requirement on while nobody else could approve; the warning does not block the save</li>
                    <li>A ceremony that was already pending and can no longer be approved says so in its drawer, where its initiator can cancel it</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/ceremonies<br />
                    POST /api/v1/admin/ceremonies<br />
                    GET /api/v1/admin/ceremonies/approvers
                </div>
            </section>

            {/* Quota Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Quota Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/quotas
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Configure and monitor certificate quotas per CA (on its admin group).
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Set certificate issuance limits</li>
                    <li>Configure pending-request limits per CA</li>
                    <li>Monitor quota usage and remaining capacity</li>
                    <li>Alert thresholds for quota exhaustion</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/quotas<br />
                    PUT /api/v1/admin/quotas/&#123;groupId&#125;
                </div>
            </section>

            {/* Certificate Inventory (Intelligence) */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Certificate Inventory</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/intel/inventory
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Comprehensive certificate inventory analysis across the entire deployment.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Certificate counts by algorithm, key size, and profile</li>
                    <li>Issuance trends over time</li>
                    <li>Algorithm distribution analysis</li>
                    <li>Weak key detection</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/compliance
                </div>
            </section>

            {/* Vulnerabilities */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Vulnerabilities</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/intel/vulnerabilities
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Certificate vulnerability scanning results. Identifies certificates with weak algorithms,
                    short key lengths, or other security concerns.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Vulnerability scan results with severity ratings</li>
                    <li>Certificates using deprecated algorithms (SHA-1, RSA-1024)</li>
                    <li>Certificates with excessively long validity periods</li>
                    <li>Missing or incorrect extensions</li>
                    <li>Remediation recommendations</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/compliance
                </div>
            </section>

            {/* Compliance */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Compliance</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/intel/compliance
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Generate compliance reports and export data for auditing purposes.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Generate compliance reports against policy baselines</li>
                    <li>Export reports in CSV format</li>
                    <li>Certificate policy compliance checks</li>
                    <li>Historical compliance trend tracking</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/compliance<br />
                    POST /api/v1/admin/compliance/export/csv
                </div>
            </section>

            {/* Audit Logs */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Audit Logs</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/audit
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Comprehensive audit logging with separate tabs for different log categories.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>General audit tab: user actions, certificate operations, configuration changes</li>
                    <li>Network audit tab: API requests, protocol transactions</li>
                    <li>Protocol audit tab: ACME, EST, SCEP, CMP protocol-level events</li>
                    <li>Filter by user, action type, date range, and resource</li>
                    <li>Export audit logs</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/audit<br />
                    GET /api/v1/admin/audit/network<br />
                    GET /api/v1/admin/audit/est
                </div>
            </section>

            {/* Notification Management */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Notification Management</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/notifications
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Configure notification rules for certificate events such as expiry warnings, issuance
                    confirmations, and revocation alerts.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Create notification rules with event triggers</li>
                    <li>Configure email notification recipients</li>
                    <li>Set expiry warning thresholds (e.g., 30, 14, 7 days)</li>
                    <li>View notification delivery history</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/notifications<br />
                    POST /api/v1/admin/notifications/test<br />
                    PUT /api/v1/admin/protocol-configs/&#123;caId&#125;/&#123;protocol&#125;
                </div>
            </section>

            {/* Spaces & Quotas */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Spaces &amp; Quotas</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/spaces, /admin/spaces/&#123;id&#125; (the old /admin/tenants paths redirect here until 0.5)
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Spaces delegate administration within one organisation. They share sign-in, backups, the
                    audit trail and instance administrators; for a separate customer, create a separate
                    instance. Each space holds its CAs, its ceilings and per-CA quotas.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Create and manage spaces. The Create Space dialog says what a space shares, and from the fifth space that a licence is recommended; creation always succeeds</li>
                    <li>Configure each space's validity ceiling and ceremony policy</li>
                    <li>View each space's CAs, users and per-CA quota usage</li>
                    <li>Enable/disable spaces</li>
                    <li>The instance (its own CAs, system groups and CA policy) beside the spaces</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/quotas/by-space<br />
                    POST /api/v1/admin/spaces<br />
                    PUT /api/v1/admin/spaces/&#123;id&#125;<br />
                    PUT /api/v1/admin/spaces/&#123;id&#125;/settings
                </div>
            </section>

            {/* Settings */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Settings</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/settings
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    System-wide configuration settings for the ModularCA platform.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>General settings: system name, public base URL</li>
                    <li>Security settings: password policy, session timeout, MFA requirements</li>
                    <li>Email/SMTP configuration</li>
                    <li>Logging level configuration</li>
                    <li>Rate limiting settings</li>
                    <li>OCSP responder configuration</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/config<br />
                    PUT /api/v1/admin/config/security
                </div>
            </section>

            {/* Backup & Restore */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Backup &amp; Restore</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/backup
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage system backups and restore operations for disaster recovery.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Trigger manual backups</li>
                    <li>Configure backup schedules</li>
                    <li>View backup history</li>
                    <li>Restore from a previous backup</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    An archive holds the application database, the audit database, the keystores and the configuration files.
                    SSH CA keys travel inside the signer&apos;s SSH keystore, <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">ssh-ca.keystore</code>,
                    which the signer exports with its other keystores. That file can be opened only with the application
                    database beside it, so keep the two together. Restoring an archive made before 0.4.2 brings back its SSH CA
                    key files, and the next start imports them into the signer; see Upgrading to 0.4.2 under Configuration
                    Lifecycle.
                </p>
                <div className="bg-sunken rounded p-4 data-mono">
                    POST /api/v1/admin/backup<br />
                    GET /api/v1/admin/backup<br />
                    POST /api/v1/admin/backup/restore
                </div>
            </section>

            {/* Web TLS Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Web TLS Certificate</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/webtls
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage the TLS certificate used by the ModularCA management UI and API. Renew or
                    replace the certificate issued during initial setup, including support for post-quantum
                    key algorithms.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View current Web TLS certificate details and expiry</li>
                    <li>Renew with the same or different key algorithm</li>
                    <li>Configure Subject Alternative Names (DNS, IP)</li>
                    <li>PQC key algorithm support (ML-DSA, SLH-DSA, Ed25519)</li>
                    <li>Automatic restart after certificate renewal</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/webtls<br />
                    POST /api/v1/admin/certificates/&#123;serial&#125;/renew
                </div>
            </section>

            {/* Whitelists */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Whitelists</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/whitelists
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Manage IP and domain whitelists for access control. Whitelists restrict which clients
                    can access specific services or enrollment endpoints.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Create and manage IP address whitelists</li>
                    <li>Configure domain-based access rules</li>
                    <li>Assign whitelists to specific CAs or protocols</li>
                    <li>View whitelist hit counts and activity</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/admin/whitelists<br />
                    POST /api/v1/admin/whitelists<br />
                    PUT /api/v1/admin/whitelists/&#123;id&#125;<br />
                    DELETE /api/v1/admin/whitelists/&#123;id&#125;
                </div>
            </section>

            {/* My Security */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">My Security</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /admin/security
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Personal security settings for the currently logged-in administrator.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Change password</li>
                    <li>Enroll or manage TOTP authenticator</li>
                    <li>Register WebAuthn/FIDO2 security keys</li>
                    <li>View active sessions</li>
                    <li>Revoke sessions</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/me<br />
                    PUT /api/v1/account/password<br />
                    POST /api/v1/auth/mtls/enroll<br />
                    POST /api/v1/auth/webauthn/register
                </div>
            </section>

            {/* Auth routes note */}
            <section className="mb-10">
                <div className="border-l-4 border-info bg-info-soft p-4 rounded-r">
                    <h3 className="text-lg font-semibold text-ink mb-2">Authentication Routes</h3>
                    <p className="text-ink leading-relaxed">
                        The Admin UI also includes unauthenticated routes for the login flow:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-ink mt-2">
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/login</code> — Username/password login form, shared with the self-service portal</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-setup</code> — First-time MFA enrollment</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-verify</code> — MFA challenge verification</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-callback</code> — WebAuthn callback handler</li>
                    </ul>
                </div>
            </section>
        </div>
    );
}
