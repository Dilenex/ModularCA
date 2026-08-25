export default function AuthFlowDiagram() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Authentication Flow
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                ModularCA uses a multi-layered authentication model combining password-based login (local or LDAP),
                multi-factor authentication (MFA via TOTP, WebAuthn, and mTLS), JWT tokens with refresh rotation,
                certificate-based login, and operation-scoped step-up MFA for sensitive actions. All auth endpoints
                are exposed at both <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">/auth/*</code> (canonical
                short URL) and <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">/api/v1/auth/*</code> (legacy path).
            </p>

            {/* Flow Diagram */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Authentication Sequence</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Client                        Server                      Database
    |                              |                            |
    |  POST /api/v1/auth/login     |                            |
    |  { username, password }      |                            |
    |----------------------------->|                            |
    |                              |  Verify credentials        |
    |                              |--------------------------->|
    |                              |<---------------------------|
    |                              |                            |
    |  200 { mfaRequired: true }   |                            |
    |<-----------------------------|                            |
    |                              |                            |
    |  POST /api/v1/auth/totp/     |                            |
    |       verify                 |                            |
    |  { token, code }             |                            |
    |----------------------------->|                            |
    |                              |  Validate TOTP/WebAuthn    |
    |                              |--------------------------->|
    |                              |<---------------------------|
    |                              |                            |
    |  200 { accessToken,          |                            |
    |        refreshToken }        |                            |
    |<-----------------------------|                            |
    |                              |                            |
    |  GET /api/v1/user/certificates       |                            |
    |  Authorization: Bearer {jwt} |                            |
    |----------------------------->|                            |
    |                              |  Validate JWT claims       |
    |  200 { certificates }        |                            |
    |<-----------------------------|                            |
    |                              |                            |
    |  --- Sensitive Operation (e.g. revoke) ---                |
    |                              |                            |
    |  POST /api/v1/user/          |                            |
    |  certificates/{serial}/revoke|                            |
    |  X-Step-Up-Token: {token}    |                            |
    |----------------------------->|                            |
    |                              |                            |
    |  403 { stepUpRequired: true }|                            |
    |<-----------------------------|                            |
    |                              |                            |
    |  POST /api/v1/auth/mfa/      |                            |
    |       verify-stepup/totp     |                            |
    |  { code }                    |                            |
    |----------------------------->|                            |
    |                              |  Validate MFA again        |
    |  200 { stepUpToken }         |                            |
    |<-----------------------------|                            |
    |                              |                            |
    |  POST /api/v1/user/          |                            |
    |  certificates/{serial}/revoke|                            |
    |  X-Step-Up-Token: {token}    |                            |
    |----------------------------->|                            |
    |  200 { success }             |                            |
    |<-----------------------------|                            |
`}</pre>
                </div>
            </section>

            {/* Authentication Methods */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Authentication Methods</h2>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 mt-4">Password Authentication (Local + LDAP)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The primary login factor. When LDAP is enabled, credentials are tried against the directory
                    first; on failure, the local password hash is checked. Local passwords are hashed using
                    PBKDF2-SHA256 with a minimum of 600,000 iterations (auto-rehashed from legacy 100k hashes on
                    successful login). The password policy requires a minimum of 16 characters with uppercase,
                    lowercase, digit, and special character requirements.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    POST /auth/login<br />
                    {`{ "username": "admin", "password": "..." }`}
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The login endpoint applies constant-time response budgets (configurable
                    via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.LoginResponseDelayMs</code>)
                    and dummy password hashing on every failure path so that user enumeration via timing
                    side-channels is infeasible. Input is shape-validated (unicode normalization, homoglyph
                    rejection) before the database is touched.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">TOTP (Time-based One-Time Password)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Software-based MFA using authenticator apps (Google Authenticator, Authy, etc.).
                    A shared secret is generated during enrollment and stored encrypted via ASP.NET Data
                    Protection. Login-flow TOTP verification uses a one-step drift tolerance; step-up
                    verification uses windowSize=0 (current code only) for tighter brute-force resistance.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    POST /auth/totp/setup&nbsp;&nbsp;(returns QR code + secret)<br />
                    POST /auth/totp/verify-setup&nbsp;&nbsp;(complete enrollment)<br />
                    POST /auth/totp/verify&nbsp;&nbsp;{`{ "code": "123456" }`}&nbsp;&nbsp;(login-flow verification)
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">WebAuthn / FIDO2</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Hardware security key or platform authenticator (Touch ID, Windows Hello). Uses
                    public-key cryptography -- the private key never leaves the authenticator device.
                    This is the strongest MFA option.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    POST /auth/webauthn/register-options&nbsp;&nbsp;(credential creation challenge)<br />
                    POST /auth/webauthn/register&nbsp;&nbsp;(complete registration)<br />
                    POST /auth/webauthn/assertion-options&nbsp;&nbsp;(login assertion challenge)<br />
                    POST /auth/webauthn/assertion&nbsp;&nbsp;(verify assertion, issue JWT)<br />
                    GET&nbsp;&nbsp;/auth/webauthn/credentials&nbsp;&nbsp;(list registered keys)<br />
                    DELETE /auth/webauthn/credentials/{'{id}'}
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    WebAuthn includes per-user brute-force protection: after reaching the configurable failure
                    threshold the MFA token is consumed and the user must restart the login flow. User verification
                    (PIN/biometric) can be enforced
                    via the DB-backed <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.RequireWebAuthnUserVerification</code> (tune via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">PUT /admin/security-policy</code>).
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Mutual TLS (mTLS) / Certificate Login</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Client certificate authentication via the dedicated <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/cert-login</code> endpoint.
                    The client presents a certificate during the TLS handshake. The server validates the
                    certificate thumbprint against enrolled mTLS credentials, then performs full chain
                    validation against the credential's signing CA (not just thumbprint equality). On success,
                    a JWT access token and refresh token are issued without requiring password or MFA.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    POST /auth/cert-login&nbsp;&nbsp;(no request body; client cert in TLS handshake)
                </div>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r mb-4">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Security:</span> Chain validation
                        uses <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">MtlsChainValidator.ValidateAgainstCredentialCaAsync</code> to
                        ensure the certificate chains to the exact CA it was enrolled under. OCSP revocation
                        checks can be enforced
                        via the DB-backed <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.RequireMtlsOcspCheck</code>.
                        Failed chain validation increments the failed login counter and can trigger account lockout.
                    </p>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Account Lockout</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    All login paths (password, LDAP, cert-login, pre-JWT password change) share the same
                    account lockout mechanism. Failed login attempts are tracked atomically in the database.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li><strong>Temporary lockout:</strong> When <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.LockoutMinutes &gt; 0</code>,
                        the account is locked for the configured duration after reaching <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.MaxFailedLoginAttempts</code></li>
                    <li><strong>Permanent lockout:</strong> When <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">LockoutMinutes = 0</code>,
                        the account is hard-locked and requires admin intervention</li>
                    <li><strong>Concurrent session limit:</strong> Configurable
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.MaxConcurrentSessions</code>;
                        excess sessions are revoked FIFO</li>
                    <li><strong>Tuning:</strong> These knobs live in the DB-backed <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy</code> table and are edited via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">PUT /api/v1/admin/security-policy</code> (step-up MFA required), not config.yaml</li>
                    <li>Account state (disabled, locked, temp-locked) is only revealed after successful
                        password verification to prevent user enumeration</li>
                    <li>Lockout events trigger notifications
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">INotificationService.NotifyAccountLockedAsync</code></li>
                </ul>
            </section>

            {/* JWT Claims */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">JWT Token Structure</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    After successful authentication (password + MFA), the server issues a signed JWT access
                    token and an opaque refresh token.
                </p>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Access Token Claims</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`{
  "sub": "user-uuid",              // User ID (NameIdentifier)
  "jti": "unique-token-id",        // JWT ID (used for revocation + step-up binding)
  "username": "admin",             // Username
  "email": "admin@example.com",    // Email address
  "tenant": "tenant-uuid",         // Current tenant context
  "groups": [                      // Group memberships (CA-scoped + system)
    { "id": "group-uuid", "role": "Admin" },
    { "id": "group-uuid", "role": "Operator" }
  ],
  "mfa_setup_required": true,      // Present when user has no TOTP/WebAuthn enrolled
  "source_ip": "192.168.1.100",    // IP address at token issuance
  "iat": 1712937600,               // Issued at
  "exp": 1712941200,               // Expires (configurable via JWT.ExpirationMinutes)
  "iss": "modularca",              // Issuer (configurable)
  "aud": "modularca-api"           // Audience (configurable)
}`}</pre>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Token Lifecycle</h3>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Token</th>
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Lifetime</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Storage</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Access Token (JWT)</td>
                            <td className="py-2 pr-4">Configurable (JWT.ExpirationMinutes)</td>
                            <td className="py-2">Memory (JavaScript variable)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Refresh Token</td>
                            <td className="py-2 pr-4">Configurable; capped by SecurityPolicy.MaxSessionLifetimeDays</td>
                            <td className="py-2">Stored SHA-256 hashed in DB; plaintext sent to client</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">MFA Session Token</td>
                            <td className="py-2 pr-4">Configurable (SecurityPolicy.MfaSessionTtlSeconds, 60-900s)</td>
                            <td className="py-2">Distributed cache (Redis/memory)</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4">Step-Up Token</td>
                            <td className="py-2 pr-4">Configurable (SecurityPolicy.StepUpTokenTtlSeconds, 30-300s)</td>
                            <td className="py-2">Distributed cache; single-use, session-bound via JWT jti</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            {/* Refresh Flow */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Refresh Token Flow</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When the access token expires, the client automatically uses the refresh token to obtain
                    a new access token without requiring the user to re-authenticate.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Client                        Server
    |                              |
    |  GET /api/v1/user/certificates       |
    |  Authorization: Bearer {expired-jwt}
    |----------------------------->|
    |  401 Unauthorized            |
    |<-----------------------------|
    |                              |
    |  POST /api/v1/auth/refresh   |
    |  Cookie: refresh={token}     |
    |----------------------------->|
    |                              |
    |  200 { accessToken,          |
    |        refreshToken }        |
    |<-----------------------------|
    |                              |
    |  GET /api/v1/user/certificates       |
    |  Authorization: Bearer {new-jwt}
    |----------------------------->|
    |  200 { certificates }        |
    |<-----------------------------|
`}</pre>
                </div>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r mb-4">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Security note:</span> Refresh tokens are rotated on
                        each use (rotation strategy). If a refresh token is reused, all tokens in that rotation
                        family are invalidated to mitigate token theft.
                    </p>
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Refresh Token Security</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li><strong>Stored hashed:</strong> Refresh tokens are stored as SHA-256 hashes; only the plaintext is sent to the client once</li>
                    <li><strong>Family tracking:</strong> Each rotation chain shares a <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">FamilyId</code>;
                        reuse of any revoked sibling revokes the entire family</li>
                    <li><strong>Absolute session cap:</strong> <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.MaxSessionLifetimeDays</code> limits
                        how long a rotation chain can extend from the original login</li>
                    <li><strong>Idle timeout:</strong> <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.SessionIdleTimeoutMinutes</code> revokes
                        tokens that have been inactive too long</li>
                    <li><strong>IP binding:</strong> Optional
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">Security.BindRefreshTokenToIp</code> -- rejects
                        refresh from a different IP (log-only mode available)</li>
                    <li><strong>Fingerprint binding:</strong> Optional
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">Security.BindRefreshTokenToFingerprint</code> -- User-Agent
                        hash binding</li>
                    <li><strong>Account status enforced on refresh:</strong> Locked, disabled, or temporarily locked users cannot refresh</li>
                </ul>
            </section>

            {/* Step-Up MFA */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Step-Up MFA</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Certain sensitive operations require additional MFA verification even when the user is
                    already authenticated. This is managed by the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">StepUpMfaProvider</code> context
                    in both the Admin and User UIs.
                </p>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Operations Requiring Step-Up (StepUpOps Registry)</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    All step-up operations are defined in a compile-time canonical registry
                    (<code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">StepUpOps</code>). The issuance
                    endpoint rejects any operation string not in this allow-list.
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-xs mb-4 overflow-x-auto">
                    <pre className="text-gray-700 dark:text-gray-300">{`Certificate:  revoke-cert, hold-cert, unhold-cert, reissue-cert, export-cert
User:         create-user, update-user, delete-user
Group:        add-group-member, remove-group-member
Password/MFA: reset-password, reset-mfa, change-password
Backup:       create-backup, restore-backup, set-backup-password, change-backup-encryption-mode
CA:           create-ca, update-ca, revoke-ca, create-ssh-ca, disable-ssh-ca
Profile:      update-signing-profile, delete-signing-profile, update-cert-profile,
              delete-cert-profile, update-request-profile, delete-request-profile
Whitelist:    create-whitelist, update-whitelist, delete-whitelist
Policy:       policy-sync, policy-import
Config:       update-protocol-config, update-config, restart
Ceremony:     initiate-ceremony, approve-ceremony, reject-ceremony,
              cancel-ceremony, execute-ceremony, disable-ceremony-requirement
MFA enroll:   totp-setup, totp-verify-setup, totp-remove,
              webauthn-register, webauthn-delete, mtls-enroll, mtls-delete`}</pre>
                </div>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                    The step-up token is short-lived (configurable, default 90s, max 300s) and scoped to
                    the current JWT session via the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">jti</code> claim.
                    It is passed via the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">X-MFA-Token</code> header
                    on the protected request.
                </p>
            </section>

            {/* MFA Step-Up Verification Flow */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">MFA Step-Up Verification Flow</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When an authenticated user initiates a sensitive operation (e.g., revoke certificate, delete
                    user, export PFX), the API challenges them with a step-up MFA verification. The UI handles
                    this transparently by intercepting the 403 response, prompting for MFA, obtaining a scoped
                    token, and retrying the original request.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Flow Steps</h3>
                <ol className="list-decimal list-inside space-y-2 text-gray-700 dark:text-gray-300 mb-6">
                    <li>User initiates a sensitive operation (e.g., revoke certificate, delete user, export PFX)</li>
                    <li>API returns HTTP 403 with <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{`{ requiresStepUp: true }`}</code></li>
                    <li>UI detects the response and opens the Step-Up MFA Modal</li>
                    <li>User enters 6-digit TOTP code (or taps security key)</li>
                    <li>UI calls <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/mfa/verify-stepup/totp</code> with <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{`{ code, operation, targetId }`}</code></li>
                    <li>API validates TOTP code and returns a scoped, single-use MFA token (configurable TTL, default 90s)</li>
                    <li>Token is cached as <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{`mfa-stepup:{userId}:{jti}:{operation}:{targetId}`}</code></li>
                    <li>UI retries the original request with <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">X-MFA-Token</code> header</li>
                    <li>API validates and consumes (single-use) the token, then processes the request</li>
                </ol>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Sequence Diagram</h3>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-6">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  User/UI                       API Server                    Cache (Redis)
    |                              |                              |
    |  1. Sensitive operation       |                              |
    |  POST /api/v1/user/            |                              |
    |  certificates/{serial}/revoke|                              |
    |  Authorization: Bearer {jwt} |                              |
    |----------------------------->|                              |
    |                              |  Check for X-MFA-Token       |
    |                              |  (none found)                |
    |  2. 403 Forbidden            |                              |
    |  { requiresStepUp: true }    |                              |
    |<-----------------------------|                              |
    |                              |                              |
    |  3. UI opens Step-Up         |                              |
    |     MFA Modal                |                              |
    |                              |                              |
    |  4. User enters TOTP code    |                              |
    |                              |                              |
    |  5. POST /auth/mfa/           |                              |
    |     verify-stepup/totp       |                              |
    |  { code: "123456",           |                              |
    |    operation: "revoke-cert", |                              |
    |    targetId: "{cert-id}" }   |                              |
    |----------------------------->|                              |
    |                              |  6. Validate TOTP code       |
    |                              |     Generate scoped token    |
    |                              |                              |
    |                              |  7. Cache token              |
    |                              |  mfa-stepup:{userId}:{jti}: |
    |                              |    revoke-cert:{cert-id}     |
    |                              |  TTL: 90s (configurable)     |
    |                              |----------------------------->|
    |                              |                              |
    |  200 { mfaToken: "tok_..." } |                              |
    |<-----------------------------|                              |
    |                              |                              |
    |  8. Retry original request   |                              |
    |  POST /api/v1/user/            |                              |
    |  certificates/{serial}/revoke|                              |
    |  Authorization: Bearer {jwt} |                              |
    |  X-MFA-Token: tok_...        |                              |
    |----------------------------->|                              |
    |                              |  9. Validate token           |
    |                              |  (scope + single-use check)  |
    |                              |----------------------------->|
    |                              |     Token found, valid       |
    |                              |<-----------------------------|
    |                              |                              |
    |                              |  Consume (delete) token      |
    |                              |----------------------------->|
    |                              |                              |
    |                              |  Process revocation          |
    |  200 { success: true }       |                              |
    |<-----------------------------|                              |
`}</pre>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Key Security Properties</h3>
                <ul className="list-disc list-inside space-y-2 text-gray-700 dark:text-gray-300 mb-4">
                    <li>
                        <span className="font-semibold">Operation-scoped:</span> A token issued
                        for <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">revoke-cert</code> cannot
                        be used for <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">delete-user</code>
                    </li>
                    <li>
                        <span className="font-semibold">Target-scoped:</span> A token for certificate ABC cannot be
                        used for certificate XYZ
                    </li>
                    <li>
                        <span className="font-semibold">Single-use:</span> The token is consumed (deleted from cache)
                        on successful validation and cannot be replayed
                    </li>
                    <li>
                        <span className="font-semibold">Session-bound:</span> When the JWT
                        includes a <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">jti</code> claim,
                        the step-up token is bound to that session and cannot be replayed from a different JWT
                    </li>
                    <li>
                        <span className="font-semibold">Short-lived:</span> Tokens expire after the configured TTL
                        (default 90s, max 300s) via cache TTL, even if unused
                    </li>
                    <li>
                        <span className="font-semibold">Timing-safe comparison:</span> Token validation
                        uses <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">CryptographicOperations.FixedTimeEquals</code> to
                        prevent timing side-channel attacks
                    </li>
                    <li>
                        <span className="font-semibold">Rate-limited:</span> Per-user sliding-window failure
                        counter (configurable
                        via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy.StepUpFailureThreshold</code> and <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">StepUpFailureWindowSeconds</code> — both DB-backed, edited via <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">PUT /admin/security-policy</code>).
                        When the threshold is reached, all step-up attempts return 429 until the window expires.
                    </li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Supported Verification Methods</h3>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Method</th>
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Endpoint</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Notes</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">TOTP</td>
                            <td className="py-2 pr-4"><code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/mfa/verify-stepup/totp</code></td>
                            <td className="py-2">6-digit code; windowSize=0 (no drift tolerance)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">WebAuthn (options)</td>
                            <td className="py-2 pr-4"><code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/mfa/verify-stepup/webauthn-options</code></td>
                            <td className="py-2">Returns assertion challenge for step-up</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">WebAuthn (verify)</td>
                            <td className="py-2 pr-4"><code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/mfa/verify-stepup/webauthn</code></td>
                            <td className="py-2">Hardware key or platform authenticator assertion</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4">mTLS</td>
                            <td className="py-2 pr-4"><code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">POST /auth/mfa/verify-stepup/mtls</code></td>
                            <td className="py-2">Restricted to MFA enrollment operations only (StepUpOps.AllowedViaMtls)</td>
                        </tr>
                    </tbody>
                </table>

                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Security note:</span> The cache
                        key <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">{`mfa-stepup:{userId}:{jti}:{operation}:{targetId}`}</code> ensures
                        that each token is bound to a specific user, JWT session, operation type, and target
                        resource. This prevents any form of token reuse across different contexts or sessions.
                        When the JWT has no <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">jti</code> claim
                        (legacy callers), the key falls back to userId-only scope.
                    </p>
                </div>
            </section>
        </div>
    );
}
