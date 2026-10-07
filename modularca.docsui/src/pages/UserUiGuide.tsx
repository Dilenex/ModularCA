export default function UserUiGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-2xl font-semibold text-ink mb-4">
                User UI Guide
            </h1>
            <p className="text-lg text-ink-muted leading-relaxed mb-8">
                The User UI is served at <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/user</code> and
                provides a self-service portal for end users to request, manage, and download their certificates.
                All routes require authentication with step-up MFA support (TOTP and WebAuthn) for
                sensitive operations. The sidebar navigation is organized into 5 sections: Overview,
                Certificates, SSH, CA Information, and My Account.
            </p>

            {/* Dashboard */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Dashboard</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/dashboard&nbsp;&nbsp;(also /user/)
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Personal overview showing the user's certificate inventory, pending requests, and expiring
                    certificates at a glance.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Summary cards for active certificates, pending requests, and upcoming expirations</li>
                    <li>Recent activity feed</li>
                    <li>Quick-action buttons for requesting a new certificate</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/me
                </div>
            </section>

            {/* Request Certificate */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Request Certificate</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/request
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Submit a certificate signing request. The request enters the approval workflow and will be
                    reviewed by an administrator (unless auto-approval is configured).
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Upload a PEM-encoded CSR file or paste CSR text</li>
                    <li>Select from available certificate templates or profiles</li>
                    <li>Fill in subject fields within allowed constraints</li>
                    <li>Add Subject Alternative Names</li>
                    <li>Choose key algorithm from the key generation dropdown, including post-quantum options</li>
                    <li>Track request after submission</li>
                </ul>
                <div className="border-l-4 border-accent bg-accent-soft p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-accent-ink mb-2">Post-Quantum Cryptography (PQC)</h3>
                    <p className="text-ink leading-relaxed mb-2">
                        The key generation dropdown includes post-quantum algorithms alongside traditional options:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-ink mb-2">
                        <li><strong>ML-DSA-44, ML-DSA-65, ML-DSA-87</strong> — FIPS 204 lattice-based digital signatures (formerly CRYSTALS-Dilithium)</li>
                        <li><strong>SLH-DSA-SHA2-128F</strong> — FIPS 205 stateless hash-based signatures (formerly SPHINCS+)</li>
                        <li><strong>Ed448</strong> — Edwards-curve signature with 224-bit security level</li>
                    </ul>
                    <p className="text-ink leading-relaxed">
                        PQC algorithms have fixed security levels, so the key size field is automatically hidden
                        when a PQC algorithm is selected.
                    </p>
                </div>
                <div className="bg-sunken rounded p-4 data-mono">
                    POST /api/v1/user/requests<br />
                    GET /api/v1/user/request-profiles<br />
                    GET /api/v1/user/signing-profiles
                </div>
            </section>

            {/* My Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">My Certificates</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/certificates
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    View all certificates issued to the current user. Supports filtering by status (all, active,
                    revoked, expired) to quickly locate specific certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>List of issued certificates with status indicators</li>
                    <li>Filter certificates by status: all, active, revoked, or expired</li>
                    <li>View certificate details (subject, SANs, validity, serial number)</li>
                    <li>Download certificate in PEM, DER, or full-chain format</li>
                    <li>Download PKCS#12 / PFX bundle with private key (if server-side key generation was used)</li>
                    <li>View certificate expiry dates</li>
                </ul>
                <div className="border-l-4 border-warn bg-warn-soft p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-warn mb-2">MFA Step-Up on PFX Export</h3>
                    <p className="text-ink leading-relaxed mb-2">
                        Downloading a PKCS#12 / PFX file (which contains the private key) requires MFA step-up
                        verification. Users must enter their TOTP code before the PFX file will download. This
                        protects against session hijacking — even if an attacker steals a session token, they
                        cannot extract private keys without the second factor.
                    </p>
                    <p className="text-ink leading-relaxed">
                        <strong>PFX export with private keys is only available in the User UI, not the Admin UI.</strong> This
                        is a deliberate security design decision ensuring that private key material is only ever
                        delivered directly to the certificate owner.
                    </p>
                </div>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/user/certificates<br />
                    GET /api/v1/user/certificates/&#123;serial&#125;/file
                </div>
            </section>

            {/* Request Status */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Request Status</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/requests
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Track the status of submitted certificate requests through the approval pipeline.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>View all submitted requests with current status</li>
                    <li>Status states: pending, approved, issued, rejected, cancelled</li>
                    <li>Cancel pending requests</li>
                    <li>View rejection reasons</li>
                    <li>Download issued certificate once approved</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/user/requests<br />
                    POST /api/v1/user/requests
                </div>
            </section>

            {/* SSH Certificates */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">SSH Certificates</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/ssh
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Request, view and download your SSH certificates for server access.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Request a certificate for your own public key</li>
                    <li>View the SSH certificates issued for you, with their serial, SSH CA, login names and validity</li>
                    <li>Download a certificate again</li>
                </ul>

                <h3 className="text-lg font-semibold text-ink mb-2">Requesting a certificate</h3>
                <p className="text-ink leading-relaxed mb-3">
                    &ldquo;+ Request&rdquo; opens the form. It asks for three things:
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><span className="font-semibold">Your public key:</span> the contents of the .pub file of the key you use, for example <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">~/.ssh/id_ed25519.pub</code>. The private key never leaves your machine.</li>
                    <li><span className="font-semibold">Log in as:</span> the accounts the certificate lets you log in to, called login names (OpenSSH calls them principals). The list holds every login name you hold on the SSH CA and nothing else: your own username where the SSH CA allows it, and each name an administrator granted to you or to a group you are in. Each row says where the name comes from and how long a certificate carrying it may last. A name the chosen profile does not allow is shown but cannot be ticked. If you need an account that is not listed, ask an administrator of the SSH CA to grant it.</li>
                    <li><span className="font-semibold">Valid for:</span> it starts at the most allowed for the names you ticked. A name with a short limit shortens the whole certificate, and the form names it and says how long the certificate could last without it. No certificate outlives a grant that has an end; leave the field empty for one that ends when the grant does.</li>
                </ul>
                <p className="text-ink leading-relaxed mb-3">
                    The SSH CA is asked for only when you may request from more than one, and a profile only when there is
                    a real choice. &ldquo;Your name in host logs&rdquo; is your username. The CA writes it into the certificate and it
                    cannot be changed: every host records it with each login, whichever account you use. The form shows the
                    line a host will write, for example when alice logs in as root:
                </p>
                <div className="bg-sunken rounded p-4 data-mono mb-3 overflow-x-auto">
                    <pre className="text-ink">{`Accepted publickey for root from 192.0.2.10 port 51122 ssh2: ED25519-CERT SHA256:[key] ID alice (serial 8841) CA ED25519 SHA256:[CA key]`}</pre>
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    This is how a shared account works: several people may log in as
                    <code className="text-sm bg-sunken px-1.5 py-0.5 rounded"> deploy</code> or <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">root</code>,
                    each with their own key and their own certificate, and the host log still names the person.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    After signing, the certificate is shown once with Copy and Download. Save it beside the private key,
                    under the key file&apos;s name with <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">-cert.pub</code> added:
                    for <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">~/.ssh/id_ed25519</code> that is
                    <code className="text-sm bg-sunken px-1.5 py-0.5 rounded"> ~/.ssh/id_ed25519-cert.pub</code>. ssh then presents it by
                    itself. The certificate also appears in the list, where it can be downloaded again. A certificate an
                    administrator signs for you appears in your list too.
                </p>
                <p className="text-ink leading-relaxed mb-3">
                    If you hold no login name on an SSH CA, the form says so: an administrator of the SSH CA has to grant
                    one, or turn on logging in as your own username. Your certificates are revoked when a login name they
                    carry is taken from you, and all of them when your account is disabled or renamed.
                </p>

                <h3 className="text-lg font-semibold text-ink mb-2">Through the API</h3>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">GET /api/v1/user/ssh/request-options</code> answers what the form shows: the name the CA will write, and per SSH CA your login names and the profiles you can request with</li>
                    <li>A request names at least one login name in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">principals</code>, each one you hold; a name you do not hold is refused with 400, naming it</li>
                    <li>A request must not send <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">keyId</code>: the CA writes it, and a value other than your username is refused with 400</li>
                    <li>The certificate carries exactly the extensions the profiles and your request name. None is added by default, so a certificate that names no permit-pty opens no interactive shell. Ask your administrator to add the permits you need to the signing profile</li>
                    <li>When signing is unavailable the answer is 503 with the reason in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">error</code>: the signer is locked (try again shortly), or the SSH CA key is awaiting import into the signer (an administrator has to act)</li>
                    <li>When the certificate itself is refused the answer is 400, with the reason in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">error</code> or, for a login name or a validity that is not allowed, in <code className="text-sm bg-sunken px-1.5 py-0.5 rounded">detail</code></li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/user/ssh/request-options<br />
                    POST /api/v1/user/ssh/sign-user<br />
                    GET /api/v1/user/ssh/certificates<br />
                    GET /api/v1/user/ssh/certificates/&#123;id&#125;/download
                </div>
            </section>

            {/* Trusted CAs */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">Trusted CAs</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/authorities
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    View information about the Certificate Authorities available in the deployment. Provides
                    CA certificates for trust configuration.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>List of available CAs the user can request certificates from</li>
                    <li>Download CA certificates for trust store installation</li>
                    <li>View CA certificate details and chain</li>
                </ul>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/user/authorities
                </div>
            </section>

            {/* My Security */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-ink mb-3">My Security</h2>
                <div className="bg-sunken rounded p-4 data-mono mb-3">
                    Route: /user/security
                </div>
                <p className="text-ink leading-relaxed mb-3">
                    Personal security management for the logged-in user. Sensitive operations on this page
                    require MFA step-up verification to prevent unauthorized changes.
                </p>
                <ul className="list-disc list-inside space-y-1 text-ink mb-3">
                    <li>Change password (requires MFA step-up)</li>
                    <li>Enroll or manage TOTP authenticator app</li>
                    <li>Remove TOTP authenticator (requires MFA step-up)</li>
                    <li>Register WebAuthn/FIDO2 security keys</li>
                    <li>Remove WebAuthn security keys (requires MFA step-up)</li>
                    <li>Revoke mTLS credentials (requires MFA step-up)</li>
                    <li>View active sessions and revoke them</li>
                </ul>
                <div className="border-l-4 border-warn bg-warn-soft p-4 rounded-r mb-3">
                    <h3 className="text-lg font-semibold text-warn mb-2">MFA Step-Up on Security Operations</h3>
                    <p className="text-ink leading-relaxed">
                        Password changes, TOTP removal, WebAuthn key removal, and mTLS credential revocation
                        all require the user to re-verify with their TOTP code before the operation proceeds.
                        This prevents an attacker with a stolen session from locking the real user out or
                        downgrading their security posture.
                    </p>
                </div>
                <div className="bg-sunken rounded p-4 data-mono">
                    GET /api/v1/me<br />
                    POST /api/v1/auth/change-password<br />
                    POST /api/v1/auth/totp/setup<br />
                    POST /api/v1/auth/webauthn/register
                </div>
            </section>

            {/* Auth routes note */}
            <section className="mb-10">
                <div className="border-l-4 border-info bg-info-soft p-4 rounded-r">
                    <h3 className="text-lg font-semibold text-ink mb-2">Authentication Routes</h3>
                    <p className="text-ink leading-relaxed">
                        The User UI includes the same authentication flow as the Admin UI:
                    </p>
                    <ul className="list-disc list-inside space-y-1 text-ink mt-2">
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/login</code> — Login form, shared with the management console</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-setup</code> — First-time MFA enrollment</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-verify</code> — MFA challenge verification</li>
                        <li><code className="text-sm bg-sunken px-1.5 py-0.5 rounded">/mfa-callback</code> — WebAuthn callback handler</li>
                    </ul>
                </div>
            </section>
        </div>
    );
}
