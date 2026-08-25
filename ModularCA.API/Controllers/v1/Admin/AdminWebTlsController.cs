using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for inspecting and reissuing the running Web TLS certificate that fronts
/// the management API. Reissue operations are validated against the seeded "Web TLS (Internal)"
/// request profile, hot-reload is performed via <see cref="ApiCertificateProvider"/>, and the
/// reissue endpoint is gated behind the same <c>reissue-cert</c> step-up MFA operation that
/// the generic certificate reissue endpoints use. Read operations are open to any caller that
/// satisfies the <c>SystemAdmin</c> policy.
/// </summary>
[ApiController]
[Route("api/v1/admin/webtls")]
[Authorize(Policy = "SystemAdmin")]
public class AdminWebTlsController(
    ModularCADbContext db,
    ICertificateIssuanceService issuance,
    ICsrService csrService,
    ICertificateRevocationService revocation,
    ApiCertificateProvider certProvider,
    IDistributedCache cache,
    ICurrentUserService currentUser,
    IAuditService audit,
    SystemConfig config,
    EnvVarConfigOverlay envOverlay) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly ICertificateIssuanceService _issuance = issuance;
    private readonly ICsrService _csrService = csrService;
    private readonly ICertificateRevocationService _revocation = revocation;
    private readonly ApiCertificateProvider _certProvider = certProvider;
    private readonly IDistributedCache _cache = cache;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly SystemConfig _config = config;

    /// <summary>
    /// Returns the current Web TLS certificate's parsed details for the admin UI to pre-populate
    /// a reissue form. The response is built primarily from the in-memory <see cref="X509Certificate2"/>
    /// held by <see cref="ApiCertificateProvider"/>; when a matching <see cref="CertificateEntity"/>
    /// row exists in the database the <c>SubjectAlternativeNamesJson</c> column is preferred over
    /// the X509 SAN extension so the response stays in sync with the canonical issuance record.
    /// No step-up MFA is required because this endpoint is strictly read-only.
    /// </summary>
    /// <returns>200 OK with a <see cref="WebTlsCertStatusResponse"/>, or 404 if no Web TLS cert
    /// is currently loaded into the provider (e.g., bootstrap incomplete).</returns>
    [HttpGet]
    public async Task<IActionResult> GetStatus()
    {
        var current = _certProvider.GetCertificate();
        if (current == null)
            return NotFound(new { error = "Web TLS certificate not loaded." });

        var normalizedSerial = NormalizeSerial(current.SerialNumber);

        // Attempt to find the matching DB row — optional, the response stays usable without it.
        var dbCert = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(normalizedSerial);

        var dnComponents = ParseSubjectDnInline(current.Subject);

        // Prefer the persisted SAN list (canonical issuance record) when available; otherwise
        // fall back to parsing the X509 SAN extension off the in-memory certificate.
        var sans = ExtractSans(current, dbCert);

        var nowUtc = DateTime.UtcNow;
        var notAfterUtc = current.NotAfter.ToUniversalTime();
        var daysUntilExpiry = Math.Round((notAfterUtc - nowUtc).TotalDays, 1);

        // Resolve signing profile + key params from the CSR record
        Guid? signingProfileId = null;
        string? signingProfileName = null;
        string? keyAlgorithm = null;
        string? keySize = null;
        if (dbCert != null)
        {
            var csr = await _db.CertificateRequests
                .AsNoTracking()
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.IssuedCertificateId == dbCert.CertificateId);
            signingProfileId = csr?.SigningProfileId;
            signingProfileName = csr?.SigningProfile?.Name;
            keyAlgorithm = csr?.KeyAlgorithm;
            keySize = csr?.KeySize;
        }

        var response = new WebTlsCertStatusResponse
        {
            SerialNumber = normalizedSerial,
            CommonName = dnComponents.GetValueOrDefault("CN"),
            Organization = dnComponents.GetValueOrDefault("O"),
            OrganizationalUnit = dnComponents.GetValueOrDefault("OU"),
            Locality = dnComponents.GetValueOrDefault("L"),
            // .NET's X509Certificate2.Subject emits state as "S=", BouncyCastle uses "ST=".
            // Accept either form so the reissue form populates correctly regardless of who
            // issued the running cert.
            State = dnComponents.GetValueOrDefault("ST") ?? dnComponents.GetValueOrDefault("S"),
            Country = dnComponents.GetValueOrDefault("C"),
            Sans = sans,
            NotBefore = current.NotBefore.ToUniversalTime(),
            NotAfter = notAfterUtc,
            DaysUntilExpiry = daysUntilExpiry,
            IsExpired = notAfterUtc < nowUtc,
            HttpsPort = _config.Https?.Port ?? 8443,
            SigningProfileId = signingProfileId,
            SigningProfileName = signingProfileName,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize
        };

        return Ok(response);
    }

    /// <summary>
    /// Reissues the running Web TLS certificate with operator-supplied subject-DN and SAN
    /// overrides. The override fields are merged into a new subject DN string, validated against
    /// the seeded "Web TLS (Internal)" request profile (when present), and forwarded to
    /// <see cref="ICertificateIssuanceService.ReissueCertificateAsync"/>. On success the database
    /// is updated; the running server is NOT hot-swapped in this implementation — the admin must
    /// restart the API for the new certificate to take effect (see remarks below). Requires step-up
    /// MFA verification via the <c>X-MFA-Token</c> header, scoped to the <c>reissue-cert</c>
    /// operation with target <c>webtls</c>. Emits a
    /// <see cref="AuditActionType.CertificateReissued"/> record on both the success and failure
    /// branches so SIEM can correlate Web TLS reissue attempts regardless of outcome.
    /// </summary>
    /// <remarks>
    /// True hot-reload (rebuilding <c>config/api-tls.pfx</c> and calling <c>SetCertificate</c>)
    /// requires decrypting the new certificate's private key from <see cref="CertificateEntity.EncryptedPrivateKey"/>
    /// and re-wrapping it into a PKCS#12 store with the configured password — see
    /// <c>ModularCA.Core/Services/SchedulerJobs/TlsRenewalJob.cs</c> around line 360 for the
    /// reference pattern. To avoid partial-state bugs (DB updated but in-memory cert stale) this
    /// endpoint deliberately leaves the running cert untouched and instructs the operator to restart.
    /// TODO: revisit once the keystore decryption helper is broken out into a reusable service.
    /// </remarks>
    /// <param name="request">Override fields for the reissued certificate.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <returns>200 OK with the new serial number and validity window, 400 on validation
    /// failure, 403 if step-up MFA is missing or invalid, 404 if no Web TLS cert is loaded,
    /// or 500 if the running cert has no database record (cannot be reissued).</returns>
    [HttpPost("reissue")]
    public async Task<IActionResult> ReissueWebTls(
        [FromBody] ReissueWebTlsRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null)
            return Unauthorized();

        var userId = _currentUser.User.Id;
        var username = _currentUser.User.Username;

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ReissueCert, "webtls"))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var current = _certProvider.GetCertificate();
        if (current == null)
            return NotFound(new { error = "Web TLS certificate not loaded." });

        var normalizedSerial = NormalizeSerial(current.SerialNumber);
        var currentCertEntity = await _db.Certificates
            .ResolveBySerialOrNullAsync(normalizedSerial);

        if (currentCertEntity == null)
        {
            Serilog.Log.Warning("Web TLS reissue: cert serial lookup failed. Raw={RawSerial}, Normalized={NormalizedSerial}",
                current.SerialNumber, normalizedSerial);
            return StatusCode(500, new
            {
                error = "Current Web TLS cert has no database record — cannot reissue via the generic service. Bootstrap or re-run setup."
            });
        }

        // Build subject DN from the request fields
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(request.CommonName)) parts.Add($"CN={request.CommonName}");
        if (!string.IsNullOrWhiteSpace(request.OrganizationalUnit)) parts.Add($"OU={request.OrganizationalUnit}");
        if (!string.IsNullOrWhiteSpace(request.Organization)) parts.Add($"O={request.Organization}");
        if (!string.IsNullOrWhiteSpace(request.Locality)) parts.Add($"L={request.Locality}");
        if (!string.IsNullOrWhiteSpace(request.State)) parts.Add($"ST={request.State}");
        if (!string.IsNullOrWhiteSpace(request.Country)) parts.Add($"C={request.Country}");
        var newSubjectDn = parts.Count > 0 ? string.Join(",", parts) : current.Subject;

        // Resolve the Web TLS cert profile and signing profile from the current cert's CSR
        var currentCsr = await _db.CertificateRequests
            .Include(c => c.CertProfile)
            .Include(c => c.SigningProfile)
            .FirstOrDefaultAsync(c => c.IssuedCertificateId == currentCertEntity.CertificateId);

        if (currentCsr?.CertProfileId == null || currentCsr?.SigningProfileId == null)
            return BadRequest(new { error = "Cannot determine cert/signing profile for reissue. The original CSR record is missing." });

        // Use requested signing profile or fall back to the current cert's profile
        var signingProfileId = request.SigningProfileId ?? currentCsr.SigningProfileId.Value;
        var signingProfile = await _db.SigningProfiles
            .AsNoTracking()
            .FirstOrDefaultAsync(sp => sp.Id == signingProfileId);
        if (signingProfile == null)
            return BadRequest(new { error = $"Signing profile {signingProfileId} not found." });

        var sans = request.Sans ?? new List<string>();
        var validityDays = request.ValidityDays ?? 397;
        var keyAlgorithm = request.KeyAlgorithm ?? "ECDSA";
        var keySize = request.KeySize > 0 ? request.KeySize : 256;

        try
        {
            // Generate a fresh CSR + key pair through the infrastructure pipeline
            var (csrId, keyPair) = await _csrService.GenerateInfrastructureCsrAsync(
                newSubjectDn, keyAlgorithm, keySize,
                currentCsr.CertProfileId.Value, signingProfileId,
                sans);

            // Issue the cert through the standard pipeline
            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddDays(validityDays);
            var result = await _issuance.IssueCertificateAsync(csrId, notBefore, notAfter);

            // Parse the issued cert for PFX export
            var issuedCert = ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(result.Pem);
            var newSerial = ModularCA.Shared.Utils.CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber);
            var newValidTo = issuedCert.NotAfter;

            // Resolve CA cert for chain
            var caCertEntity = await _db.Certificates
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId);
            Org.BouncyCastle.X509.X509Certificate? caCert = null;
            if (caCertEntity != null)
                caCert = ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(caCertEntity.Pem);

            // Build PFX from the in-memory key pair (not from DB — infra certs don't store encrypted keys)
            var pfxPassword = Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
            var pfxPath = Path.Combine(AppContext.BaseDirectory, "config", "api-tls.pfx");

            // Backup existing PFX
            if (System.IO.File.Exists(pfxPath))
            {
                try { System.IO.File.Copy(pfxPath, pfxPath + ".bak", overwrite: true); }
                catch (Exception backupEx) { Serilog.Log.Warning(backupEx, "Web TLS reissue: failed to backup previous PFX"); }
            }

            var pfxStore = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();
            var chainEntries = caCert != null
                ? new[] { new Org.BouncyCastle.Pkcs.X509CertificateEntry(issuedCert), new Org.BouncyCastle.Pkcs.X509CertificateEntry(caCert) }
                : new[] { new Org.BouncyCastle.Pkcs.X509CertificateEntry(issuedCert) };
            pfxStore.SetKeyEntry("api-tls",
                new Org.BouncyCastle.Pkcs.AsymmetricKeyEntry(keyPair.Private),
                chainEntries);

            using (var fs = System.IO.File.Create(pfxPath))
            {
                pfxStore.Save(fs, pfxPassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
            }
            ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(pfxPath);

            // Update config with new PFX password
            _config.Https.CertificatePassword = pfxPassword;
            _config.Https.CertificatePath = "config/api-tls.pfx";
            PersistConfig();

            // Hot-swap the running cert
            var newX509 = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, pfxPassword,
                X509KeyStorageFlags.MachineKeySet);
            _certProvider.SetCertificate(newX509);

            Serilog.Log.Information(
                "Web TLS certificate reissued and hot-swapped. SN={Serial}, ValidTo={ValidTo:O}",
                newSerial, newValidTo);

            // Revoke the previous cert as Superseded now that the replacement is live.
            // Unlike the generic ReissueCertificateAsync flow (which auto-revokes), the Web TLS
            // path issues a fresh CSR + keypair via GenerateInfrastructureCsrAsync + IssueCertificateAsync
            // because the algorithm/size can change and the in-memory keypair is needed to build the
            // PFX. That bypasses the auto-revoke, so we trigger it explicitly here. Wrapped in
            // try/catch because a CRL-regen failure shouldn't roll back a successful hot-swap —
            // the new cert is already live; the old one will be picked up on the next CRL pass.
            bool oldRevoked = false;
            try
            {
                if (!currentCertEntity.Revoked)
                {
                    await _revocation.RevokeCertificateAsync(
                        currentCertEntity.CertificateId, null, RevocationReason.Superseded);
                    oldRevoked = true;
                }
            }
            catch (Exception revokeEx)
            {
                Serilog.Log.Warning(revokeEx,
                    "Web TLS reissue: failed to revoke superseded cert SN={Serial}. Replacement is live.",
                    normalizedSerial);
            }

            await _audit.LogAsync(
                AuditActionType.CertificateReissued,
                userId, username,
                targetEntityType: "WebTls",
                targetEntityId: currentCertEntity.CertificateId.ToString(),
                details: new
                {
                    PreviousSerial = normalizedSerial,
                    NewSerial = newSerial,
                    NewSubjectDn = newSubjectDn,
                    NewSans = sans,
                    NewValidTo = newValidTo,
                    HotReloaded = true,
                    PreviousRevoked = oldRevoked
                },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(new
            {
                message = "Web TLS certificate reissued and loaded. New TLS connections will use the updated certificate. You may need to close and reopen your browser to see the change.",
                previousSerialNumber = normalizedSerial,
                newSerialNumber = newSerial,
                validTo = newValidTo,
                restartRequired = false
            });
        }
        catch (InvalidOperationException ex)
        {
            // A Web TLS reissue failure is a security-
            // relevant event because the running TLS chain remains the previous (potentially
            // expiring) cert. Emit the same CertificateReissued action type with success=false
            // so SIEM can correlate failures against the success path. Audit emission is
            // wrapped so it cannot mask the original 400 response.
            try
            {
                await _audit.LogAsync(
                    AuditActionType.CertificateReissued,
                    userId, username,
                    targetEntityType: "WebTls",
                    targetEntityId: currentCertEntity.CertificateId.ToString(),
                    details: new
                    {
                        PreviousSerial = normalizedSerial,
                        AttemptedNewSubjectDn = newSubjectDn,
                        AttemptedSans = sans,
                        HotReloaded = false,
                    },
                    sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                    success: false,
                    errorMessage: ex.Message);
            }
            catch (Exception auditEx)
            {
                Serilog.Log.Warning(auditEx, "Audit emission for failed Web TLS reissue failed");
            }

            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Normalizes a certificate serial number to uppercase hex with no delimiters so equality
    /// comparisons between the in-memory <see cref="X509Certificate2.SerialNumber"/> and the
    /// stored <see cref="CertificateEntity.SerialNumber"/> are consistent across both sources.
    /// </summary>
    /// <summary>
    /// Normalizes a certificate serial number to match the DB format produced by
    /// BouncyCastle's <c>BigInteger.ToString(16).ToUpperInvariant()</c> — uppercase hex,
    /// no delimiters, no leading zeros.
    /// <para>
    /// Delegates to <see cref="ModularCA.Shared.Utils.CertificateUtil.NormalizeSerialForLookup"/>.
    /// This logic was private here while EST re-enrollment compared serials without it, so a
    /// revoked client certificate whose serial had a leading zero nibble was never matched.
    /// One copy now.
    /// </para>
    /// </summary>
    private static string NormalizeSerial(string? serial)
        => ModularCA.Shared.Utils.CertificateUtil.NormalizeSerialForLookup(serial);

    /// <summary>
    /// Minimal subject DN parser duplicated from <c>RequestProfileValidationService.ParseSubjectDn</c>
    /// (which is internal to the Core assembly and not reachable from this project). Splits on
    /// top-level commas and assigns each <c>KEY=value</c> fragment into a case-insensitive
    /// dictionary. Quoted values containing commas are preserved.
    /// </summary>
    private static Dictionary<string, string> ParseSubjectDnInline(string dn)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(dn))
            return result;

        var components = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;

        foreach (var c in dn)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                current.Append(c);
            }
            else if (c == ',' && !inQuotes)
            {
                var part = current.ToString().Trim();
                if (!string.IsNullOrEmpty(part))
                    components.Add(part);
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        var lastPart = current.ToString().Trim();
        if (!string.IsNullOrEmpty(lastPart))
            components.Add(lastPart);

        foreach (var component in components)
        {
            var eqIndex = component.IndexOf('=');
            if (eqIndex <= 0)
                continue;

            var key = component[..eqIndex].Trim().ToUpperInvariant();
            var value = component[(eqIndex + 1)..].Trim();

            if (value.Length >= 2 && value.StartsWith('"') && value.EndsWith('"'))
                value = value[1..^1];

            result[key] = value;
        }

        return result;
    }

    /// <summary>
    /// Extracts the SAN list for the response payload. When a database record exists and has a
    /// non-empty <c>SubjectAlternativeNamesJson</c> column we use that (canonical issuance record).
    /// Otherwise we fall back to parsing the X509 SAN extension off the in-memory certificate so
    /// callers always get something usable. Entries are normalized to <c>DNS:</c> / <c>IP:</c>
    /// prefix casing.
    /// </summary>
    private static List<string> ExtractSans(X509Certificate2 cert, CertificateEntity? dbCert)
    {
        // Prefer the persisted JSON list when present.
        if (dbCert != null && !string.IsNullOrWhiteSpace(dbCert.SubjectAlternativeNamesJson))
        {
            try
            {
                var parsed = JsonSerializer.Deserialize<List<string>>(dbCert.SubjectAlternativeNamesJson);
                if (parsed != null && parsed.Count > 0)
                    return parsed.Select(NormalizeSanPrefix).ToList();
            }
            catch (JsonException ex)
            {
                Serilog.Log.Warning(ex, "Web TLS status: failed to deserialize SubjectAlternativeNamesJson — falling back to X509 extension");
            }
        }

        // Fall back to the X509 SAN extension on the in-memory cert.
        var sans = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension sanExt)
            {
                foreach (var dns in sanExt.EnumerateDnsNames())
                    sans.Add($"DNS:{dns}");
                foreach (var ip in sanExt.EnumerateIPAddresses())
                    sans.Add($"IP:{ip}");
                break;
            }
        }
        return sans;
    }

    /// <summary>
    /// Persists the in-memory config to config.yaml after PFX password update.
    /// </summary>
    private void PersistConfig()
    {
        // Secrets that came from the environment must be nulled before serialization, or this
        // write persists them in cleartext to config.yaml. WithSecretsProtected covers
        // JWT.Secret, both DB passwords, LdapAuth.BindPassword, the Email secrets,
        // IntegrationApi.ApiKey, CertManager.ApiKey and Hsm.Pin. Writing the whole SystemConfig
        // without it -- as this did -- meant a Web TLS reissue could drop the JWT SIGNING KEY on
        // disk, where anyone able to read the file can mint admin tokens. WebTlsProvisioningService
        // performs the same operation and always used the overlay; this path did not.
        try
        {
            envOverlay.WithSecretsProtected(_config, () =>
            {
                var serializer = new YamlDotNet.Serialization.SerializerBuilder()
                    .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.PascalCaseNamingConvention.Instance)
                    .Build();
                var yaml = serializer.Serialize(_config);
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                System.IO.File.WriteAllText(configPath, yaml);
            });
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Web TLS reissue: failed to persist config.yaml with new PFX password");
        }
    }

    /// <summary>
    /// Normalizes the SAN prefix to canonical uppercase form (<c>DNS:</c>, <c>IP:</c>, etc.) so
    /// the response is consistent regardless of how the entries were persisted.
    /// </summary>
    private static string NormalizeSanPrefix(string entry)
    {
        var colonIdx = entry.IndexOf(':');
        if (colonIdx <= 0)
            return entry;
        var prefix = entry[..colonIdx].Trim().ToUpperInvariant();
        var value = entry[(colonIdx + 1)..].Trim();

        // Convert ASN.1 hex-encoded IP addresses (e.g., "#0a646918") to human-readable form
        if (prefix == "IP" && value.StartsWith('#') && (value.Length == 9 || value.Length == 33))
        {
            try
            {
                var hexBytes = Convert.FromHexString(value[1..]);
                var ip = new System.Net.IPAddress(hexBytes);
                value = ip.ToString();
            }
            catch { /* leave as-is if parsing fails */ }
        }

        return $"{prefix}:{value}";
    }
}

/// <summary>
/// Read-only response describing the currently-running Web TLS certificate. Used by the admin
/// UI to pre-populate the reissue form so operators can edit individual fields without having
/// to re-enter the full subject DN and SAN list.
/// </summary>
public class WebTlsCertStatusResponse
{
    /// <summary>Normalized uppercase-hex serial number with no delimiters.</summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>Common Name (CN) parsed from the subject DN, if present.</summary>
    public string? CommonName { get; set; }

    /// <summary>Organization (O) parsed from the subject DN, if present.</summary>
    public string? Organization { get; set; }

    /// <summary>Organizational Unit (OU) parsed from the subject DN, if present.</summary>
    public string? OrganizationalUnit { get; set; }

    /// <summary>Locality (L) parsed from the subject DN, if present.</summary>
    public string? Locality { get; set; }

    /// <summary>State or Province (ST) parsed from the subject DN, if present.</summary>
    public string? State { get; set; }

    /// <summary>Country (C) parsed from the subject DN, if present.</summary>
    public string? Country { get; set; }

    /// <summary>The list of SANs as <c>DNS:host</c> or <c>IP:address</c> entries.</summary>
    public List<string> Sans { get; set; } = new();

    /// <summary>Certificate validity start (UTC).</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>Certificate validity end (UTC).</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>Days remaining until expiry, rounded to one decimal place. Negative if expired.</summary>
    public double DaysUntilExpiry { get; set; }

    /// <summary>True when the certificate's <c>NotAfter</c> is in the past.</summary>
    public bool IsExpired { get; set; }

    /// <summary>The HTTPS listen port the management API serves on (read from <see cref="HttpsConfig.Port"/>).</summary>
    public int HttpsPort { get; set; }

    /// <summary>The signing profile ID currently used for this cert.</summary>
    public Guid? SigningProfileId { get; set; }

    /// <summary>The signing profile name currently used for this cert.</summary>
    public string? SigningProfileName { get; set; }

    /// <summary>The key algorithm used for the current cert (e.g., ECDSA, RSA).</summary>
    public string? KeyAlgorithm { get; set; }

    /// <summary>The key size or curve label (e.g., "2048", "P-384") used for the current cert.</summary>
    public string? KeySize { get; set; }
}

/// <summary>
/// Request body for the Web TLS reissue endpoint. All subject-DN component fields are optional;
/// fields left null/blank are omitted from the override DN and the original CSR's stored values
/// remain in effect for that component.
/// </summary>
public class ReissueWebTlsRequest
{
    /// <summary>New Common Name (CN) for the reissued certificate.</summary>
    public string? CommonName { get; set; }

    /// <summary>New Organization (O) for the reissued certificate.</summary>
    public string? Organization { get; set; }

    /// <summary>New Organizational Unit (OU) for the reissued certificate.</summary>
    public string? OrganizationalUnit { get; set; }

    /// <summary>New Locality (L) for the reissued certificate.</summary>
    public string? Locality { get; set; }

    /// <summary>New State or Province (ST) for the reissued certificate.</summary>
    public string? State { get; set; }

    /// <summary>New Country (C) for the reissued certificate.</summary>
    public string? Country { get; set; }

    /// <summary>
    /// New SAN list as <c>DNS:host</c> or <c>IP:address</c> entries. Validated against the
    /// "Web TLS (Internal)" request profile's SAN rules before issuance.
    /// </summary>
    public List<string>? Sans { get; set; }

    /// <summary>
    /// Optional explicit validity period in days. When null the cert profile's
    /// <c>MaxValidityPeriod</c> applies inside the issuance service.
    /// </summary>
    public int? ValidityDays { get; set; }

    /// <summary>
    /// Signing profile ID to use for the reissued cert. When null, the current cert's
    /// signing profile is reused. Allows switching the issuing CA.
    /// </summary>
    public Guid? SigningProfileId { get; set; }

    /// <summary>Key algorithm for the new key pair (e.g., "ECDSA", "RSA"). Default: ECDSA.</summary>
    public string KeyAlgorithm { get; set; } = "ECDSA";

    /// <summary>Key size in bits (e.g., 256, 384 for ECDSA; 2048, 4096 for RSA). Default: 256.</summary>
    public int KeySize { get; set; } = 256;
}
