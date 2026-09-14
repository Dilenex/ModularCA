using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Services;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Utils;
using ModularCA.Auth.Models;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.API.Controllers.v1.Auth;

/// <summary>
/// mTLS client certificate endpoints for enrolling, listing, revoking, and verifying
/// mTLS credentials used as a multi-factor authentication method.
/// Certificates are signed by a CA configured per-group via <see cref="CaGroupEntity.MtlsSigningCaId"/>.
/// </summary>
[ApiController]
[Route("api/v1/auth/mtls")]
[Route("auth/mtls")]
public class MtlsController : ControllerBase
{
    private readonly ModularCADbContext _db;
    private readonly IDistributedCache _cache;
    private readonly IJwtTokenService _jwt;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuditService _audit;
    private readonly IKeystoreCertificates _keystore;
    private readonly SystemConfig _config;
    private readonly ISecurityPolicyService _securityPolicy;

    /// <summary>
    /// Initializes a new instance of the <see cref="MtlsController"/> class.
    /// </summary>
    public MtlsController(
        ModularCADbContext db,
        IDistributedCache cache,
        IJwtTokenService jwt,
        ICurrentUserService currentUser,
        IAuditService audit,
        IKeystoreCertificates keystore,
        SystemConfig config,
        ISecurityPolicyService securityPolicy)
    {
        _db = db;
        _cache = cache;
        _jwt = jwt;
        _currentUser = currentUser;
        _audit = audit;
        _keystore = keystore;
        _config = config;
        _securityPolicy = securityPolicy;
    }

    /// <summary>
    /// Returns the current mTLS authentication configuration — whether the auth
    /// subdomain is enabled and the full URL the login UI should redirect to for
    /// the browser certificate picker. mTLS login is now SNI-gated on the main
    /// HTTPS listener; there is no longer a separate port.
    /// </summary>
    [HttpGet("auth-info")]
    [AllowAnonymous]
    public IActionResult GetAuthInfo()
    {
        var hasSubdomain = !string.IsNullOrWhiteSpace(_config.Mtls.AuthSubdomain);

        // Build the full subdomain URL. If AuthSubdomain is a short prefix (e.g. "mtls")
        // rather than an FQDN (e.g. "mtls.ca.example.com"), prepend it to PublicDomain.
        string? subdomainUrl = null;
        if (hasSubdomain)
        {
            var raw = _config.Mtls.AuthSubdomain.Trim();
            var fqdn = raw.Contains('.')
                ? raw  // Already an FQDN like "mtls.ca.example.com"
                : !string.IsNullOrWhiteSpace(_config.Https.PublicDomain)
                    ? $"{raw}.{_config.Https.PublicDomain}"  // Build "mtls" + "ca.example.com"
                    : raw;  // No PublicDomain configured, use as-is
            subdomainUrl = $"https://{fqdn}";
        }

        return Ok(new
        {
            enabled = hasSubdomain,
            subdomain = subdomainUrl,
        });
    }

    /// <summary>
    /// Returns the list of CAs the authenticated user is allowed to obtain mTLS certificates from,
    /// based on group memberships where <see cref="CaGroupEntity.MtlsSigningCaId"/> is configured.
    /// </summary>
    [Authorize]
    [HttpGet("allowed-cas")]
    public async Task<IActionResult> GetAllowedCas()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var allowedCas = await GetUserAllowedMtlsCasAsync(userId.Value);

        return Ok(allowedCas.Select(ca => new
        {
            caId = ca.Id,
            caName = ca.Name,
            caLabel = ca.Label
        }));
    }

    /// <summary>
    /// Enrolls a new mTLS client certificate for the authenticated user.
    /// Generates an RSA-2048 keypair, issues a client certificate signed by the specified CA,
    /// and returns a PKCS#12 file containing the certificate and private key.
    /// The PKCS#12 password is returned in the X-Pkcs12-Password response header.
    /// Returns 401 when unauthenticated, 403 on MFA step-up or CA authorization failures,
    /// 404 when the user or the CA certificate does not exist, and 409 when the CA
    /// exists but its signing key is currently unavailable (keystore state prevents signing).
    /// </summary>
    [Authorize]
    [HttpPost("enroll")]
    public async Task<IActionResult> Enroll([FromBody] MtlsEnrollRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        // Enrolling a new mTLS credential is an MFA-equivalent
        // action — the resulting PKCS#12 becomes a valid login + step-up factor
        // for a year. Require step-up gate unless the user has no existing MFA
        // factor at all (bootstrap), mirroring TOTP `setup`/WebAuthn `register`.
        var hasTotpPrecheck = await _db.TotpSecrets.AnyAsync(t => t.UserId == userId.Value && t.IsVerified);
        var hasWebAuthnPrecheck = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var hasActiveMtlsPrecheck = await _db.MtlsCredentials.AnyAsync(c => c.UserId == userId.Value && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);
        if (hasTotpPrecheck || hasWebAuthnPrecheck || hasActiveMtlsPrecheck)
        {
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.MtlsEnroll))
                return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });
        }

        var user = await _db.Users.FindAsync(userId.Value);
        if (user == null)
            return NotFound(new { error = "User not found" });

        // Validate that the requested CA is in the user's allowed set
        var allowedCas = await GetUserAllowedMtlsCasAsync(userId.Value);
        var targetCa = allowedCas.FirstOrDefault(ca => ca.Id == request.CaId);
        if (targetCa == null)
            return StatusCode(403, new { error = "You are not authorized to enroll mTLS certificates from this CA" });

        // Load the CA certificate from the Certificates table
        var caCertEntity = await _db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == targetCa.CertificateId);
        if (caCertEntity == null || caCertEntity.RawCertificate == null)
            return NotFound(new { error = "CA certificate not found in certificate store" });

        var caCertParser = new X509CertificateParser();
        var caCert = caCertParser.ReadCertificate(caCertEntity.RawCertificate);

        // Resolve CA private key
        var caKeyHandle = _keystore.GetPrivateKeyFor(caCert);
        if (caKeyHandle == null)
            return Conflict(new { error = "CA private key is not currently available for signing" });

        // Generate RSA-2048 keypair for the client cert
        var keyGenParams = new Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters(
            BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100);
        var rsaKeyGen = new RsaKeyPairGenerator();
        rsaKeyGen.Init(keyGenParams);
        var clientKeyPair = rsaKeyGen.GenerateKeyPair();

        // Build the client certificate
        var now = DateTime.UtcNow;
        var validTo = now.AddYears(1);
        // Generate 128-bit random serial number (CA/BF BR §7.1 requires ≥64 bits from CSPRNG)
        var serialBytes = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(serialBytes);
        serialBytes[0] &= 0x7F; // Ensure positive (MSB = 0)
        var serialNumber = new BigInteger(1, serialBytes);
        var subjectDn = new X509Name($"CN={user.Username}, O=ModularCA mTLS");

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serialNumber);
        certGen.SetIssuerDN(caCert.SubjectDN);
        certGen.SetSubjectDN(subjectDn);
        certGen.SetNotBefore(now);
        certGen.SetNotAfter(validTo);
        certGen.SetPublicKey(clientKeyPair.Public);

        // BasicConstraints - leaf
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        // Subject Key Identifier
        var leafPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(clientKeyPair.Public);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(leafPubKeyInfo));

        // Authority Key Identifier
        var caPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey());
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPubKeyInfo));

        // Key Usage: Digital Signature
        certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));

        // Extended Key Usage: Client Authentication (1.3.6.1.5.5.7.3.2)
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
            new ExtendedKeyUsage(new[] { new DerObjectIdentifier("1.3.6.1.5.5.7.3.2") }));

        // Sign the certificate
        var sigAlgName = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey()));
        var signer = new PrivateKeyHandleSignatureFactory(sigAlgName, caKeyHandle);
        var clientCert = certGen.Generate(signer);

        // Compute thumbprint
        var sha256Hash = SHA256.HashData(clientCert.GetEncoded());
        var thumbprint = BitConverter.ToString(sha256Hash).Replace("-", "").ToUpperInvariant();
        var formattedSerial = CertificateUtil.FormatSerialNumber(clientCert.SerialNumber);

        // Save the certificate to the Certificates table
        var sha1Hash = SHA1.HashData(clientCert.GetEncoded());
        var sha1Thumbprint = BitConverter.ToString(sha1Hash).Replace("-", "").ToUpperInvariant();
        var thumbprintDict = new Dictionary<string, string>
        {
            { "SHA 1", sha1Thumbprint },
            { "SHA 256", thumbprint }
        };

        var certPem = CertificateUtil.ExportCertificateToPem(clientCert);

        var certInfoModel = new CertificateInfoModel
        {
            Pem = certPem,
            SubjectDN = clientCert.SubjectDN.ToString(),
            Issuer = clientCert.IssuerDN.ToString(),
            SerialNumber = formattedSerial,
            NotBefore = clientCert.NotBefore,
            NotAfter = clientCert.NotAfter,
            IsCA = false,
            Revoked = false,
            RevocationReason = string.Empty,
            Thumbprints = JsonSerializer.Serialize(thumbprintDict),
            KeyUsages = new List<string> { "DigitalSignature" },
            ExtendedKeyUsages = new List<string> { "1.3.6.1.5.5.7.3.2" },
            SubjectAlternativeNames = new List<string>()
        };

        var certEntity = new CertificateEntity
        {
            SerialNumber = certInfoModel.SerialNumber,
            SubjectDN = certInfoModel.SubjectDN,
            Pem = certInfoModel.Pem,
            Issuer = certInfoModel.Issuer,
            NotBefore = certInfoModel.NotBefore,
            NotAfter = certInfoModel.NotAfter,
            Thumbprints = certInfoModel.Thumbprints,
            IsCA = false,


            Revoked = false,
            RevocationReason = string.Empty,
            RawCertificate = clientCert.GetEncoded(),
            SubjectAlternativeNamesJson = "[]",
            KeyUsagesJson = JsonSerializer.Serialize(certInfoModel.KeyUsages),
            ExtendedKeyUsagesJson = JsonSerializer.Serialize(certInfoModel.ExtendedKeyUsages),
            // mTLS client cert is signed by caCertEntity (targetCa's cert).
            IssuerCertificateId = caCertEntity.CertificateId,
        };

        _db.Certificates.Add(certEntity);
        await _db.SaveChangesAsync();

        // Create the mTLS credential record
        var mtlsCredential = new MtlsCredentialEntity
        {
            UserId = userId.Value,
            CertificateId = certEntity.CertificateId,
            SigningCaId = targetCa.Id,
            Thumbprint = thumbprint,
            SerialNumber = formattedSerial,
            DeviceName = request.DeviceName,
            IssuedAt = now,
            ExpiresAt = validTo,
            IsRevoked = false
        };

        _db.MtlsCredentials.Add(mtlsCredential);

        // Mark MFA enrollment if this is the user's first MFA method
        if (user.MfaEnrolledAt == null)
        {
            user.MfaEnrolledAt = DateTime.UtcNow;
            _db.Users.Update(user);
        }

        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserUpdated,
            userId.Value,
            user.Username,
            details: new { Action = "MtlsEnrolled", DeviceName = request.DeviceName, CaId = request.CaId, SerialNumber = formattedSerial });

        // Build PKCS#12
        var pkcs12Password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        var pkcs12Store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(clientCert);
        var caCertEntry = new X509CertificateEntry(caCert);

        pkcs12Store.SetKeyEntry("mtls-client",
            new AsymmetricKeyEntry(clientKeyPair.Private),
            new[] { certEntry, caCertEntry });

        using var pkcs12Stream = new MemoryStream();
        pkcs12Store.Save(pkcs12Stream, pkcs12Password.ToCharArray(), new SecureRandom());
        var pkcs12Bytes = pkcs12Stream.ToArray();

        Response.Headers.Append("X-Pkcs12-Password", pkcs12Password);
        Response.Headers.Append("Access-Control-Expose-Headers", "X-Pkcs12-Password");

        return File(pkcs12Bytes, "application/x-pkcs12", $"mtls-{user.Username}.p12");
    }

    /// <summary>
    /// Lists all mTLS credentials for the authenticated user, including device name,
    /// serial number, issuance and expiration dates, revocation status, and signing CA name.
    /// </summary>
    [Authorize]
    [HttpGet("credentials")]
    public async Task<IActionResult> ListCredentials()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var credentials = await _db.MtlsCredentials
            .Where(c => c.UserId == userId.Value)
            .Include(c => c.SigningCa)
            .OrderByDescending(c => c.IssuedAt)
            .Select(c => new
            {
                id = c.Id,
                deviceName = c.DeviceName,
                serialNumber = c.SerialNumber,
                issuedAt = c.IssuedAt,
                expiresAt = c.ExpiresAt,
                isRevoked = c.IsRevoked,
                signingCaName = c.SigningCa.Name
            })
            .ToListAsync();

        return Ok(credentials);
    }

    /// <summary>
    /// Revokes an mTLS credential by ID. Requires step-up MFA verification via X-MFA-Token header.
    /// Cannot revoke the user's last remaining MFA method. Also revokes the underlying certificate.
    /// </summary>
    [Authorize]
    [HttpDelete("credentials/{id}")]
    public async Task<IActionResult> RevokeCredential(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        // Require step-up MFA verification
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.MtlsDelete, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var credential = await _db.MtlsCredentials.FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId.Value);
        if (credential == null)
            return NotFound(new { error = "mTLS credential not found" });

        if (credential.IsRevoked)
            return Conflict(new { error = "Credential is already revoked" });

        // Prevent removal of last MFA method
        var hasTotp = await _db.TotpSecrets.AnyAsync(t => t.UserId == userId.Value && t.IsVerified);
        var hasWebAuthn = await _db.Fido2Credentials.AnyAsync(c => c.UserId == userId.Value);
        var otherActiveMtls = await _db.MtlsCredentials.AnyAsync(c =>
            c.UserId == userId.Value && c.Id != id && !c.IsRevoked && c.ExpiresAt > DateTime.UtcNow);

        if (!hasTotp && !hasWebAuthn && !otherActiveMtls)
            return StatusCode(409, new { error = "Cannot revoke your only MFA method. Set up another MFA method first." });

        credential.IsRevoked = true;
        credential.RevokedAt = DateTime.UtcNow;

        // Also revoke the underlying certificate if it exists
        if (credential.CertificateId.HasValue)
        {
            var cert = await _db.Certificates.FindAsync(credential.CertificateId.Value);
            if (cert != null && !cert.Revoked)
            {
                cert.Revoked = true;
                cert.RevocationReason = "Superseded";
                cert.RevocationDate = DateTime.UtcNow;
            }
        }

        await _db.SaveChangesAsync();

        // Emit the dedicated MfaMtlsRemoved action type instead of
        // the generic UserUpdated, and capture the source IP. Keeps MFA revocation
        // detection queries consistent across TOTP/WebAuthn/mTLS.
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaMtlsRemoved,
            userId.Value,
            _currentUser.User?.Username,
            targetEntityType: "MtlsCredential",
            targetEntityId: id.ToString(),
            details: new { Action = "MtlsRevoked", CredentialId = id, SerialNumber = credential.SerialNumber },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "mTLS credential revoked successfully" });
    }

    /// <summary>
    /// Verifies mTLS during the login MFA flow. Reads the client certificate from the TLS connection,
    /// validates it against the user's stored mTLS credentials, and issues a full JWT on success.
    /// Accepts the temporary MFA token from the login endpoint (no JWT required).
    /// </summary>
    /// <remarks>
    /// <c>[AllowAnonymous]</c> is required, not optional. <c>StartModularCA</c> sets a
    /// <c>FallbackPolicy</c> of <c>RequireAuthenticatedUser</c>, so without it this endpoint
    /// answered 401 before the body ever ran — while its own summary promised "no JWT required",
    /// which is the whole point of an MFA-completion step. mTLS as a second factor was therefore
    /// unreachable. <c>TotpController.Verify</c> carries the identical summary AND the attribute;
    /// this is the sibling that was missed.
    /// </remarks>
    [AllowAnonymous]
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] MtlsMfaVerifyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.MfaToken))
            return BadRequest(new { error = "MFA token is required" });

        // Atomically consume: read AND remove in one operation to prevent TOCTOU race
        var cachedUserId = await _cache.GetStringAsync($"mfa:{request.MfaToken}");
        await _cache.RemoveAsync($"mfa:{request.MfaToken}"); // Remove IMMEDIATELY after read
        if (string.IsNullOrEmpty(cachedUserId) || !Guid.TryParse(cachedUserId, out var userId))
            return Unauthorized(new { error = "MFA token is invalid or expired" });

        var user = await _db.Users.FindAsync(userId);
        if (user == null)
            return Unauthorized(new { error = "User not found" });

        // Read client certificate from the TLS connection
        var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
        if (clientCert == null)
            return Unauthorized(new { error = "No client certificate presented. Ensure your browser or client is configured with the mTLS certificate." });

        // Compute SHA-256 thumbprint of the presented certificate
        var thumbprint = clientCert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);

        // Look up the credential for this user and thumbprint
        var credential = await _db.MtlsCredentials.FirstOrDefaultAsync(c =>
            c.UserId == userId
            && c.Thumbprint == thumbprint
            && !c.IsRevoked
            && c.ExpiresAt > DateTime.UtcNow);

        if (credential == null)
            return Unauthorized(new { error = "Client certificate does not match any active mTLS credential for this user" });

        // Validate the presented cert chains to the enrolled signing CA.
        // Thumbprint equality alone does not prove issuer binding.
        var chainOk = await MtlsChainValidator.ValidateAgainstCredentialCaAsync(
            _db, credential.SigningCaId, clientCert,
            requireRevocationCheck: (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck);
        if (!chainOk)
        {
            // Increment failed-login counter for the identified user.
            await _db.Users
                .Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
            await _db.Entry(user).ReloadAsync();
            var maxAttempts = (await _securityPolicy.GetAsync()).MaxFailedLoginAttempts;
            var lockoutMinutes = (await _securityPolicy.GetAsync()).LockoutMinutes;
            if (maxAttempts > 0 && user.FailedLoginAttempts >= maxAttempts)
            {
                if (lockoutMinutes > 0)
                    user.LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                else
                    user.IsLocked = true;
            }
            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserLoginFailed,
                user.Id, user.Username,
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(), success: false,
                details: new { reason = "cert_chain_validation_failed", thumbprint, signingCaId = credential.SigningCaId },
                errorMessage: "LoginFailed");
            return Unauthorized(new { error = "Client certificate failed chain validation" });
        }

        MetricsService.AuthMfaVerificationsTotal.WithLabels("mtls").Inc();

        // Emit the dedicated MfaMtlsVerified action
        // symmetric with MfaTotpVerified / MfaWebAuthnVerified so SIEM rules can
        // filter on a stable enum string instead of parsing the TwoFactor detail
        // out of UserLogin rows. UserLogin is still emitted further below so the
        // login-event stream stays intact for session-tracking queries.
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaMtlsVerified,
            user.Id, user.Username,
            targetEntityType: "MtlsCredential",
            targetEntityId: credential.Id.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            details: new { Thumbprint = thumbprint, SigningCaId = credential.SigningCaId, SerialNumber = credential.SerialNumber });

        // MFA is complete; issue the JWT.
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        // Re-check account state at issuance. The gate ran when the MFA token was minted, but
        // that was up to MfaSessionTtlSeconds ago (clamped to 900s) — long enough for an
        // administrator to disable or lock the account while its owner is part-way through MFA.
        if (AccountStateGate.IsBlocked(user, out var blockedAtIssue))
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserLoginFailed,
                user.Id, user.Username,
                sourceIp: sourceIp,
                details: new { Reason = blockedAtIssue, Flow = "mtls-verify" });
            return StatusCode(403, new { error = AccountStateGate.ClientMessage });
        }

        var groups = await _db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group)
            .Select(gm => gm.Group)
            .ToListAsync();
        // mTLS is the only factor here. For a member of a system group that is not enough:
        // Login computes the same flag and MfaEnrollmentMiddleware confines a token that
        // carries it to enrollment until a second factor exists. These certificate-primary
        // paths minted an unrestricted token instead, so an admin whose only factor was a
        // .p12 had full API access on one possession factor, and a restricted admin could
        // enrol a .p12 and certificate-login around the restriction.
        var mfaSetupRequired = groups.Any(g => g.IsSystemGroup);
        var mfaEnforcedForGroup = _config.WebAuthn.EnforceForGroups.Count > 0
            && groups.Any(g => _config.WebAuthn.EnforceForGroups.Contains(g.TemplateName ?? "Custom", StringComparer.OrdinalIgnoreCase));
        if (mfaEnforcedForGroup)
        {
            return StatusCode(403, new
            {
                error = "Multi-factor authentication is required for your group. Sign in with your password to enrol a second factor.",
                requiresMfaEnrollment = true
            });
        }
        var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupRequired);
        var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
        var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash);
        // Plaintext is returned to the client; DB stores the hash.
        var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

        user.LastLoginAt = DateTime.UtcNow;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;

        _db.RefreshTokens.Add(refreshToken);
        _db.Users.Update(user);
        await _db.SaveChangesAsync();

        // Enforce concurrent session limit
        if ((await _securityPolicy.GetAsync()).MaxConcurrentSessions > 0)
        {
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            if (activeTokens.Count > (await _securityPolicy.GetAsync()).MaxConcurrentSessions)
            {
                var tokensToRevoke = activeTokens.Skip((await _securityPolicy.GetAsync()).MaxConcurrentSessions);
                foreach (var old in tokensToRevoke)
                {
                    old.IsRevoked = true;
                    old.RevokedAt = DateTime.UtcNow;
                }
                await _db.SaveChangesAsync();
            }
        }

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserLogin,
            user.Id,
            user.Username,
            sourceIp: sourceIp,
            details: new { TwoFactor = "mTLS", Thumbprint = thumbprint });

        return Ok(new LoginResponse
        {
            Token = Token,
            ExpiresAt = ExpiresAt,
            RefreshToken = refreshPlaintext
        });
    }

    /// <summary>
    /// Cookie name for the cross-subdomain mTLS handoff cookie. Set by
    /// <see cref="PrepareRedirect"/> on the main origin with <c>Domain=</c> scoped to the
    /// shared parent of the main and mTLS hosts so the browser sends it to the auth
    /// subdomain on the subsequent navigation. Replaces the prior <c>?mfaToken=</c> query
    /// parameter, which leaked the token to referer headers, server logs, and browser
    /// history.
    /// </summary>
    private const string MfaHandoffCookie = "MfaMtlsHandoff";

    /// <summary>
    /// Sets a short-lived, HttpOnly, Secure cookie carrying the MFA token, scoped to the
    /// shared parent of the main and mTLS subdomains so the subsequent navigation to the
    /// mTLS subdomain's <see cref="VerifyRedirect"/> can read it. Operators call this from
    /// the main origin BEFORE navigating to the mTLS subdomain — the response sets the
    /// cookie and returns 200; the UI then does <c>window.location.href = subdomain URL</c>
    /// without any query parameter. Validates the MFA token exists in cache (without
    /// consuming it — <see cref="VerifyRedirect"/> does the consume).
    /// </summary>
    [HttpPost("prepare-redirect")]
    [AllowAnonymous]
    public async Task<IActionResult> PrepareRedirect([FromBody] MtlsPrepareRedirectRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.MfaToken))
            return BadRequest(new { error = "mfaToken is required" });

        // Validate (don't consume) — the actual consume happens in VerifyRedirect under the
        // mTLS-authenticated TLS handshake. This pre-check just rejects obviously stale
        // tokens early so the operator gets a clean error before the cert picker pops up.
        var cachedUserId = await _cache.GetStringAsync($"mfa:{request.MfaToken}");
        if (string.IsNullOrEmpty(cachedUserId))
            return Unauthorized(new { error = "MFA token is invalid or expired" });

        var cookieDomain = ComputeHandoffCookieDomain();
        var cookieMaxAge = TimeSpan.FromSeconds(60); // generous for the user to click through the cert picker

        Response.Cookies.Append(MfaHandoffCookie, request.MfaToken, new Microsoft.AspNetCore.Http.CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None, // cross-subdomain GET navigation
            Domain = cookieDomain,
            Path = "/",
            MaxAge = cookieMaxAge,
        });

        return Ok(new { ok = true });
    }

    /// <summary>
    /// Browser-navigation mTLS verification endpoint. Unlike the POST /verify endpoint (which
    /// uses fetch and can't trigger TLS renegotiation), this GET endpoint forces the browser
    /// to navigate here directly, triggering a fresh TLS handshake and the certificate picker.
    /// On success, redirects back to the admin UI with a one-time auth code in the query.
    /// <para>
    /// Reads the MFA token from the <see cref="MfaHandoffCookie"/> cookie set by
    /// <see cref="PrepareRedirect"/>; falls back to the legacy <c>?mfaToken=</c> query
    /// parameter only when the cookie is absent (test envs, manual deep links). The cookie
    /// path keeps the token out of referer headers, server logs, and browser history.
    /// </para>
    /// </summary>
    /// <remarks>
    /// <c>[AllowAnonymous]</c> for the same reason as <see cref="Verify"/>: the caller is
    /// part-way through login and holds only a temporary MFA token, so the global
    /// <c>RequireAuthenticatedUser</c> fallback made this endpoint answer 401 unconditionally.
    /// </remarks>
    [AllowAnonymous]
    [HttpGet("verify-redirect")]
    public async Task<IActionResult> VerifyRedirect()
    {
        var mainOrigin = ResolveMainOrigin();

        // Prefer the cookie set by PrepareRedirect; fall back to the query parameter so a
        // direct deep link (e.g. ops debugging) still works in environments without the
        // shared-parent-domain cookie scope.
        // Cookie only. A query-string fallback survived the introduction of the cookie handoff
        // and undid it: the SPA never sent the query form, but anyone holding a token from a
        // log line could.
        var mfaToken = Request.Cookies[MfaHandoffCookie];

        // Always clear the handoff cookie on the way through so a refresh of this URL
        // doesn't accidentally re-attempt with a stale token.
        if (Request.Cookies.ContainsKey(MfaHandoffCookie))
        {
            var clearDomain = ComputeHandoffCookieDomain();
            Response.Cookies.Delete(MfaHandoffCookie, new Microsoft.AspNetCore.Http.CookieOptions
            {
                Domain = clearDomain,
                Path = "/",
                Secure = true,
                SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None,
            });
        }

        // Try to read the client cert
        var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
        if (clientCert == null)
        {
            // No client cert presented — browser didn't have one or issuing CA isn't trusted.
            return Redirect($"{mainOrigin}/admin/login?error=no_certificate");
        }

        if (string.IsNullOrWhiteSpace(mfaToken))
            return Redirect($"{mainOrigin}/admin/login?error=mfa_token_missing");

        // Atomically consume: read AND remove in one operation to prevent TOCTOU race
        var cachedUserId = await _cache.GetStringAsync($"mfa:{mfaToken}");
        await _cache.RemoveAsync($"mfa:{mfaToken}"); // Remove IMMEDIATELY after read
        if (string.IsNullOrEmpty(cachedUserId) || !Guid.TryParse(cachedUserId, out var userId))
            return Redirect($"{mainOrigin}/admin/login?error=mfa_expired");

        var user = await _db.Users.FindAsync(userId);
        if (user == null)
            return Redirect($"{mainOrigin}/admin/login?error=user_not_found");

        // clientCert was already obtained above (non-null if we reached here)
        var thumbprint = clientCert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);

        var credential = await _db.MtlsCredentials.FirstOrDefaultAsync(c =>
            c.UserId == userId
            && c.Thumbprint == thumbprint
            && !c.IsRevoked
            && c.ExpiresAt > DateTime.UtcNow);

        if (credential == null)
            return Redirect($"{mainOrigin}/admin/login?error=cert_not_matched");

        // Full chain validation against the enrolled signing CA.
        var chainOkRedirect = await MtlsChainValidator.ValidateAgainstCredentialCaAsync(
            _db, credential.SigningCaId, clientCert,
            requireRevocationCheck: (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck);
        if (!chainOkRedirect)
        {
            // Apply the failed-login counter for cert chain failures too.
            await _db.Users.Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
            return Redirect($"{mainOrigin}/admin/login?error=cert_chain_invalid");
        }

        // Dedicated MfaMtlsVerified emission (see /verify).
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaMtlsVerified,
            user.Id, user.Username,
            targetEntityType: "MtlsCredential",
            targetEntityId: credential.Id.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            details: new { Thumbprint = thumbprint, SigningCaId = credential.SigningCaId, SerialNumber = credential.SerialNumber, Flow = "verify-redirect" });

        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        // Re-check account state at issuance. The gate ran when the MFA token was minted, but
        // that was up to MfaSessionTtlSeconds ago (clamped to 900s) — long enough for an
        // administrator to disable or lock the account while its owner is part-way through MFA.
        if (AccountStateGate.IsBlocked(user, out var blockedAtIssue))
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserLoginFailed,
                user.Id, user.Username,
                sourceIp: sourceIp,
                details: new { Reason = blockedAtIssue, Flow = "mtls-verify-redirect" });
            return Redirect($"{mainOrigin}/admin/login?error=account_locked");
        }

        var groups = await _db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group)
            .Select(gm => gm.Group)
            .ToListAsync();
        // mTLS is the only factor here. For a member of a system group that is not enough:
        // Login computes the same flag and MfaEnrollmentMiddleware confines a token that
        // carries it to enrollment until a second factor exists. These certificate-primary
        // paths minted an unrestricted token instead, so an admin whose only factor was a
        // .p12 had full API access on one possession factor, and a restricted admin could
        // enrol a .p12 and certificate-login around the restriction.
        var mfaSetupRequired = groups.Any(g => g.IsSystemGroup);
        var mfaEnforcedForGroup = _config.WebAuthn.EnforceForGroups.Count > 0
            && groups.Any(g => _config.WebAuthn.EnforceForGroups.Contains(g.TemplateName ?? "Custom", StringComparer.OrdinalIgnoreCase));
        if (mfaEnforcedForGroup)
        {
            return StatusCode(403, new
            {
                error = "Multi-factor authentication is required for your group. Sign in with your password to enrol a second factor.",
                requiresMfaEnrollment = true
            });
        }
        var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupRequired);
        var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
        var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash);
        var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

        user.LastLoginAt = DateTime.UtcNow;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;

        _db.RefreshTokens.Add(refreshToken);
        _db.Users.Update(user);
        await _db.SaveChangesAsync();

        // Enforce concurrent session limit
        if ((await _securityPolicy.GetAsync()).MaxConcurrentSessions > 0)
        {
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            if (activeTokens.Count > (await _securityPolicy.GetAsync()).MaxConcurrentSessions)
            {
                var tokensToRevoke = activeTokens.Skip((await _securityPolicy.GetAsync()).MaxConcurrentSessions);
                foreach (var old in tokensToRevoke)
                {
                    old.IsRevoked = true;
                    old.RevokedAt = DateTime.UtcNow;
                }
                await _db.SaveChangesAsync();
            }
        }

        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserLogin,
            user.Id,
            user.Username,
            sourceIp: sourceIp,
            details: new { TwoFactor = "mTLS", Thumbprint = thumbprint });

        // Generate one-time authorization code instead of putting tokens in URL fragment
        var authCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await _cache.SetStringAsync($"mtls-code:{authCode}",
            JsonSerializer.Serialize(new { Token, ExpiresAt = ExpiresAt.ToString("O"), RefreshToken = refreshPlaintext }),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30) });
        return Redirect($"{mainOrigin}/admin/mfa-callback?code={authCode}");
    }

    /// <summary>
    /// Primary mTLS login endpoint. Reads the client certificate from the TLS connection,
    /// looks up the thumbprint in MtlsCredentials, finds the user, and either issues a full
    /// JWT (if no other MFA methods) or redirects to MFA verification.
    /// </summary>
    [HttpGet("login-redirect")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginRedirect()
    {
        var mainOrigin = ResolveMainOrigin();

        // Try to read the client cert
        var clientCert = await HttpContext.Connection.GetClientCertificateAsync();
        if (clientCert == null)
            return Redirect($"{mainOrigin}/admin/login?error=no_certificate");

        // Compute SHA-256 thumbprint of the presented certificate
        var thumbprint = clientCert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);

        // Look up the credential by thumbprint (any user)
        var credential = await _db.MtlsCredentials.FirstOrDefaultAsync(c =>
            c.Thumbprint == thumbprint
            && !c.IsRevoked
            && c.ExpiresAt > DateTime.UtcNow);

        var user = credential != null ? await _db.Users.FindAsync(credential.UserId) : null;
        if (credential == null || user == null)
            return Redirect($"{mainOrigin}/admin/login?error=auth_failed");

        // Validate chain against the enrolled signing CA.
        var chainOkLogin = await MtlsChainValidator.ValidateAgainstCredentialCaAsync(
            _db, credential.SigningCaId, clientCert,
            requireRevocationCheck: (await _securityPolicy.GetAsync()).RequireMtlsOcspCheck);
        if (!chainOkLogin)
        {
            await _db.Users.Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, u => u.FailedLoginAttempts + 1));
            return Redirect($"{mainOrigin}/admin/login?error=cert_chain_invalid");
        }

        // Account-state gate. This is a PRIMARY login path — nothing ran AuthController.Login
        // first — so without this a disabled or locked user holding a valid mTLS credential
        // logged in normally, and the code below then cleared their lockout as a side effect.
        //
        // Placed AFTER chain validation so the outcome cannot be used to enumerate account
        // state: a caller who cannot present a certificate chaining to the enrolled CA is turned
        // away before reaching this point.
        if (AccountStateGate.IsBlocked(user, out var blockedReason))
        {
            await _audit.LogAsync(
                Shared.Enums.AuditActionType.UserLoginFailed,
                user.Id, user.Username,
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                details: new { Reason = blockedReason, Flow = "login-redirect", Thumbprint = thumbprint });
            return Redirect($"{mainOrigin}/admin/login?error=account_locked");
        }

        // Check if user has other MFA methods (TOTP or WebAuthn)
        var hasTotp = await _db.TotpSecrets.AnyAsync(t => t.UserId == user.Id && t.IsVerified);
        var hasWebAuthn = await _db.Fido2Credentials.AnyAsync(c => c.UserId == user.Id);

        if (hasTotp || hasWebAuthn)
        {
            // User has additional MFA methods — issue temporary MFA token and redirect to MFA verify.
            // TTL driven by SecurityPolicyEntity.MfaSessionTtlSeconds (DB-backed).
            var mfaToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var mfaSessionTtl = Math.Clamp((await _securityPolicy.GetAsync()).MfaSessionTtlSeconds, 60, 900);
            await _cache.SetStringAsync($"mfa:{mfaToken}", user.Id.ToString(),
                new Microsoft.Extensions.Caching.Distributed.DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(mfaSessionTtl)
                });

            // Handed back through a one-time code, exactly as the full-login branch below hands
            // back its tokens. This used to redirect to /admin/mfa-verify?mfaToken=..., which put
            // the MFA session secret in browser history, proxy logs and same-origin referers, and
            // the page it landed on reads only navigation state, so the flow also did not work.
            var mfaMethods = new List<string>();
            if (hasTotp) mfaMethods.Add("totp");
            if (hasWebAuthn) mfaMethods.Add("webauthn");
            var mfaAuthCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await _cache.SetStringAsync($"mtls-code:{mfaAuthCode}",
                JsonSerializer.Serialize(new { RequiresMfa = true, MfaToken = mfaToken, AvailableMethods = mfaMethods }),
                new Microsoft.Extensions.Caching.Distributed.DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30) });
            return Redirect($"{mainOrigin}/admin/mfa-callback?code={mfaAuthCode}");
        }

        // No other MFA — mTLS is the sole factor. Issue full JWT.
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var groups = await _db.CaGroupMembers
            .Where(gm => gm.UserId == user.Id)
            .Include(gm => gm.Group)
            .Select(gm => gm.Group)
            .ToListAsync();
        // mTLS is the only factor here. For a member of a system group that is not enough:
        // Login computes the same flag and MfaEnrollmentMiddleware confines a token that
        // carries it to enrollment until a second factor exists. These certificate-primary
        // paths minted an unrestricted token instead, so an admin whose only factor was a
        // .p12 had full API access on one possession factor, and a restricted admin could
        // enrol a .p12 and certificate-login around the restriction.
        var mfaSetupRequired = groups.Any(g => g.IsSystemGroup);
        var mfaEnforcedForGroup = _config.WebAuthn.EnforceForGroups.Count > 0
            && groups.Any(g => _config.WebAuthn.EnforceForGroups.Contains(g.TemplateName ?? "Custom", StringComparer.OrdinalIgnoreCase));
        if (mfaEnforcedForGroup)
        {
            return StatusCode(403, new
            {
                error = "Multi-factor authentication is required for your group. Sign in with your password to enrol a second factor.",
                requiresMfaEnrollment = true
            });
        }
        var (Token, ExpiresAt) = _jwt.GenerateToken(user, groups, sourceIp, mfaSetupRequired: mfaSetupRequired);
        var userAgentHash = ModularCA.Auth.Utils.FingerprintUtil.ComputeUserAgentHash(Request.Headers.UserAgent.ToString());
        var refreshToken = _jwt.GenerateRefreshToken(user.Id, sourceIp, userAgentHash);
        var refreshPlaintext = refreshToken.PlaintextTokenForClient ?? refreshToken.Token;

        user.LastLoginAt = DateTime.UtcNow;
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;

        _db.RefreshTokens.Add(refreshToken);
        _db.Users.Update(user);
        await _db.SaveChangesAsync();

        // Enforce concurrent session limit
        if ((await _securityPolicy.GetAsync()).MaxConcurrentSessions > 0)
        {
            var activeTokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            if (activeTokens.Count > (await _securityPolicy.GetAsync()).MaxConcurrentSessions)
            {
                var tokensToRevoke = activeTokens.Skip((await _securityPolicy.GetAsync()).MaxConcurrentSessions);
                foreach (var old in tokensToRevoke)
                {
                    old.IsRevoked = true;
                    old.RevokedAt = DateTime.UtcNow;
                }
                await _db.SaveChangesAsync();
            }
        }

        MetricsService.AuthMfaVerificationsTotal.WithLabels("mtls").Inc();
        // Dedicated MfaMtlsVerified emission (see /verify).
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.MfaMtlsVerified,
            user.Id, user.Username,
            targetEntityType: "MtlsCredential",
            targetEntityId: credential.Id.ToString(),
            sourceIp: sourceIp,
            details: new { Thumbprint = thumbprint, SigningCaId = credential.SigningCaId, SerialNumber = credential.SerialNumber, Flow = "login-redirect" });
        await _audit.LogAsync(
            Shared.Enums.AuditActionType.UserLogin,
            user.Id,
            user.Username,
            sourceIp: sourceIp,
            details: new { TwoFactor = "mTLS-LoginRedirect", Thumbprint = thumbprint });

        // Generate one-time authorization code instead of putting tokens in URL fragment
        var authCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await _cache.SetStringAsync($"mtls-code:{authCode}",
            JsonSerializer.Serialize(new { Token, ExpiresAt = ExpiresAt.ToString("O"), RefreshToken = refreshPlaintext }),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30) });
        return Redirect($"{mainOrigin}/admin/mfa-callback?code={authCode}");
    }

    /// <summary>
    /// Exchanges a one-time authorization code (issued by verify-redirect or login-redirect)
    /// for the associated JWT tokens. The code is single-use and expires after 30 seconds.
    /// </summary>
    [HttpPost("exchange")]
    [AllowAnonymous]
    public async Task<IActionResult> ExchangeCode([FromBody] MtlsCodeExchangeRequest request)
    {
        // Validate code format before any cache lookup (Finding 5: code format validation)
        if (string.IsNullOrWhiteSpace(request.Code) || request.Code.Length != 64)
            return Unauthorized(new { error = "Invalid or expired authorization code" });

        var cached = await _cache.GetStringAsync($"mtls-code:{request.Code}");
        // Single-use: remove immediately after reading regardless of validity (Finding 4)
        await _cache.RemoveAsync($"mtls-code:{request.Code}");
        if (string.IsNullOrEmpty(cached))
            return Unauthorized(new { error = "Invalid or expired authorization code" });

        try
        {
            var data = JsonSerializer.Deserialize<JsonElement>(cached);

            // A certificate that identified a user who also has TOTP or WebAuthn does not get
            // tokens here; it gets the MFA session to finish on the main origin.
            if (data.TryGetProperty("RequiresMfa", out var requiresMfa) && requiresMfa.GetBoolean())
            {
                var methods = data.GetProperty("AvailableMethods").EnumerateArray()
                    .Select(m => m.GetString() ?? string.Empty)
                    .Where(m => m.Length > 0)
                    .ToList();
                return Ok(new
                {
                    requiresMfa = true,
                    mfaToken = data.GetProperty("MfaToken").GetString(),
                    method = methods.Count == 1 ? methods[0] : null,
                    availableMethods = methods
                });
            }

            return Ok(new
            {
                token = data.GetProperty("Token").GetString(),
                expiresAt = data.GetProperty("ExpiresAt").GetString(),
                refreshToken = data.GetProperty("RefreshToken").GetString()
            });
        }
        catch (JsonException)
        {
            return Unauthorized(new { error = "Invalid or expired authorization code" });
        }
    }

    /// <summary>
    /// Resolves the main application origin URL for redirect purposes.
    /// Handles PublicDomain, auth subdomain, and auth port scenarios to always
    /// redirect back to the primary origin rather than the mTLS auth origin.
    /// </summary>
    private string ResolveMainOrigin()
    {
        // If PublicDomain is configured, use it
        if (!string.IsNullOrWhiteSpace(_config.Https.PublicDomain))
            return _config.Https.GetPublicHttpsBaseUrl();

        var host = Request.Host.Host;
        var localPort = HttpContext.Connection.LocalPort;

        // If on the auth subdomain, strip the mtls prefix to get the main host.
        // AuthSubdomain may be a short prefix ("mtls") or FQDN ("mtls.ca.example.com").
        if (!string.IsNullOrWhiteSpace(_config.Mtls.AuthSubdomain))
        {
            var raw = _config.Mtls.AuthSubdomain.Trim();
            var authFqdn = raw.Contains('.')
                ? raw
                : !string.IsNullOrWhiteSpace(_config.Https.PublicDomain)
                    ? $"{raw}.{_config.Https.PublicDomain}"
                    : raw;

            if (string.Equals(host, authFqdn, StringComparison.OrdinalIgnoreCase))
            {
                // "mtls.ca.example.com" → "ca.example.com"
                var idx = host.IndexOf('.');
                if (idx >= 0)
                    host = host[(idx + 1)..];
            }
        }

        // mTLS login is now SNI-gated on the main HTTPS listener, so the local
        // port is always the main port. No separate auth-port remapping needed.
        return localPort == 443 ? $"https://{host}" : $"https://{host}:{localPort}";
    }

    /// <summary>
    /// Computes the cookie <c>Domain</c> attribute for <see cref="MfaHandoffCookie"/>: the
    /// longest dot-aligned suffix shared between <c>Https.PublicDomain</c> and the resolved
    /// mTLS auth FQDN. For the typical setup where <c>AuthSubdomain</c> is a short prefix
    /// (e.g. <c>"mtls"</c>) joined to <c>PublicDomain</c> (e.g. <c>"ca.example.com"</c>),
    /// this returns <c>"ca.example.com"</c> so the cookie is sent to both
    /// <c>ca.example.com</c> and <c>mtls.ca.example.com</c>. Returns <c>null</c> when no
    /// safe shared suffix exists (e.g. raw IP, single-label host, or unconfigured
    /// PublicDomain) — caller should not set the Domain attribute in that case, which
    /// scopes the cookie to the request host only and effectively disables cross-subdomain
    /// handoff in that environment (the legacy query-string fallback covers it).
    /// </summary>
    private string? ComputeHandoffCookieDomain()
    {
        var publicDomain = _config.Https.PublicDomain;
        if (string.IsNullOrWhiteSpace(publicDomain))
            return null;

        var rawSubdomain = _config.Mtls.AuthSubdomain?.Trim();
        if (string.IsNullOrWhiteSpace(rawSubdomain))
            return null;

        var mtlsFqdn = rawSubdomain.Contains('.')
            ? rawSubdomain
            : $"{rawSubdomain}.{publicDomain}";

        var publicParts = publicDomain.Split('.');
        var mtlsParts = mtlsFqdn.Split('.');
        var sharedLen = 0;
        for (int i = 1; i <= Math.Min(publicParts.Length, mtlsParts.Length); i++)
        {
            if (string.Equals(publicParts[publicParts.Length - i], mtlsParts[mtlsParts.Length - i],
                    StringComparison.OrdinalIgnoreCase))
            {
                sharedLen = i;
            }
            else break;
        }

        // Refuse to scope a cookie to a TLD or a single-label host — that would be
        // overbroad. Two labels is the practical floor (e.g. "example.com").
        if (sharedLen < 2)
            return null;

        return string.Join(".", publicParts.TakeLast(sharedLen));
    }

    /// <summary>
    /// Queries the user's group memberships and returns the distinct set of CAs that are configured
    /// for mTLS signing across those groups.
    /// </summary>
    private async Task<List<CertificateAuthorityEntity>> GetUserAllowedMtlsCasAsync(Guid userId)
    {
        var cas = await _db.CaGroupMembers
            .Where(gm => gm.UserId == userId)
            .Include(gm => gm.Group)
                .ThenInclude(g => g.MtlsSigningCa)
            .Where(gm => gm.Group.MtlsSigningCaId != null)
            .Select(gm => gm.Group.MtlsSigningCa!)
            .Distinct()
            .ToListAsync();

        return cas;
    }
}

/// <summary>
/// Request body for mTLS enrollment.
/// </summary>
public class MtlsEnrollRequest
{
    /// <summary>The CA to use for signing the mTLS client certificate.</summary>
    public Guid CaId { get; set; }

    /// <summary>Optional friendly name for the credential (e.g. "Work Laptop").</summary>
    public string? DeviceName { get; set; }
}

/// <summary>
/// Request body for mTLS MFA verification during the login flow (uses MFA token, no JWT required).
/// </summary>
public class MtlsMfaVerifyRequest
{
    /// <summary>The temporary MFA token issued by the login endpoint after successful password verification.</summary>
    public string MfaToken { get; set; } = string.Empty;
}

/// <summary>
/// Request body for exchanging a one-time mTLS authorization code for JWT tokens.
/// </summary>
public class MtlsCodeExchangeRequest
{
    /// <summary>The one-time authorization code received from the mTLS redirect.</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Request body for setting the cross-subdomain MFA handoff cookie before redirecting the
/// browser to the mTLS auth subdomain.
/// </summary>
public class MtlsPrepareRedirectRequest
{
    /// <summary>The temporary MFA token issued by the login endpoint.</summary>
    public string MfaToken { get; set; } = string.Empty;
}
