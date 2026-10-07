using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Security.Cryptography.X509Certificates;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Core.Services;

/// <summary>
/// Stage 2 of the two-stage bootstrap: issues the web TLS certificate through the standard
/// CSR → profile validation → CertificateIssuanceService pipeline on first runtime start.
/// Registered as an IHostedService only when <see cref="NeedsProvisioning"/> says so:
/// <c>Https.Mode = "Pending"</c>, or <c>"SelfIssued"</c> with the PFX gone, which is a restore
/// onto a new host, since no backup carries the PFX. The replacement then takes the subject,
/// names and lifetime of the last Web TLS certificate in the database.
/// After successful issuance, updates config.yaml to <c>Mode = "SelfIssued"</c> and
/// hot-swaps the cert into <see cref="ApiCertificateProvider"/>.
/// </summary>
public class WebTlsProvisioningService(
    IServiceScopeFactory scopeFactory,
    SystemConfig config,
    ApiCertificateProvider certProvider,
    EnvVarConfigOverlay envOverlay,
    ILogger<WebTlsProvisioningService> logger,
    TimeProvider? timeProvider = null) : IHostedService
{
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Whether the Web TLS certificate has to be issued at start: the mode is Pending, or it is
    /// SelfIssued and <c>config/api-tls.pfx</c> under <paramref name="baseDirectory"/> is missing
    /// or does not open with the configured password (a file left by another installation).
    /// </summary>
    public static bool NeedsProvisioning(HttpsConfig https, string baseDirectory)
    {
        var mode = https.Mode?.Trim();
        if (string.Equals(mode, "Pending", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.Equals(mode, "SelfIssued", StringComparison.OrdinalIgnoreCase))
            return false;

        var pfxPath = Path.Combine(baseDirectory, "config", "api-tls.pfx");
        if (!File.Exists(pfxPath))
            return true;
        try
        {
            using var probe = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, https.CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    /// <summary>
    /// When <see cref="NeedsProvisioning"/>, issues the Web TLS certificate under the signing
    /// profile <see cref="ResolveSigningProfileAsync"/> picks, writes the PFX, switches the config
    /// to SelfIssued and hot-swaps the certificate. The subject and SANs (DNS and IP only,
    /// <see cref="EnsureDnsOrIpSans"/>) are the pending ones; without those, the last Web TLS
    /// certificate's; without one, the public name. A failure is logged and the temporary
    /// certificate stays.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!NeedsProvisioning(config.Https, AppContext.BaseDirectory))
            return;
        var replacing = !string.Equals(config.Https.Mode?.Trim(), "Pending", StringComparison.OrdinalIgnoreCase);

        logger.LogInformation(replacing
            ? "The Web TLS certificate file is missing (it is in no backup): issuing a replacement via the standard pipeline..."
            : "Stage 2 TLS provisioning: issuing web TLS certificate via standard pipeline...");

        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
            var csrService = scope.ServiceProvider.GetRequiredService<ICsrService>();
            var issuanceService = scope.ServiceProvider.GetRequiredService<ICertificateIssuanceService>();
            var audit = scope.ServiceProvider.GetService<IAuditService>();

            // Resolve the Web TLS cert profile and a signing profile linked to it
            var certProfile = await db.CertProfiles
                .FirstOrDefaultAsync(cp => cp.Name == "Web TLS Certificate Profile", cancellationToken);
            if (certProfile == null)
                throw new InvalidOperationException("Web TLS Certificate Profile not found. Run bootstrap to seed profiles.");

            var signingProfile = await ResolveSigningProfileAsync(db, certProfile.Id, cancellationToken)
                ?? throw new InvalidOperationException(
                    "No enabled instance CA (or CA of the instance's primary space) has a signing profile linked to the "
                    + "Web TLS Certificate Profile.");

            // Subject, SANs and lifetime: the pending ones, else the last Web TLS certificate's.
            var previous = replacing
                ? await db.Certificates.AsNoTracking()
                    .Where(c => c.CertProfileId == certProfile.Id && !c.IsCA)
                    .OrderByDescending(c => c.NotBefore)
                    .FirstOrDefaultAsync(cancellationToken)
                : null;
            List<string> previousSans = previous == null ? [] : [.. UpnSanEncoding.DeserializeStoredSans(previous.SubjectAlternativeNamesJson)];
            var publicName = string.IsNullOrWhiteSpace(config.Https.PublicDomain) ? "localhost" : config.Https.PublicDomain.Trim();
            var subjectDn = config.Https.PendingSubjectDn ?? previous?.SubjectDN ?? $"CN={publicName}";
            var sans = config.Https.PendingSans
                ?? (previousSans.Count > 0
                    ? previousSans
                    : new List<string> { System.Net.IPAddress.TryParse(publicName, out _) ? $"IP:{publicName}" : $"DNS:{publicName}" });
            EnsureDnsOrIpSans(sans);
            var validityDays = config.Https.PendingValidityDays
                ?? (previous == null ? 365 : Math.Max(1, (int)Math.Round((previous.NotAfter - previous.NotBefore).TotalDays)));
            var keyAlgorithm = config.Https.PendingKeyAlgorithm ?? "ECDSA";
            var keySize = config.Https.PendingKeySize ?? 256;

            // Generate CSR via the infrastructure pipeline
            var (csrId, keyPair) = await csrService.GenerateInfrastructureCsrAsync(
                subjectDn, keyAlgorithm, keySize, certProfile.Id, signingProfile.Id, sans);

            // Issue the cert through the standard pipeline
            var notBefore = _timeProvider.GetUtcNow().UtcDateTime;
            var notAfter = notBefore.AddDays(validityDays);
            // Named argument because the space validity-ceiling enforcement mode now sits ahead of
            // the token. The default — always shorten — is the right one here: this runs
            // unattended, there is nobody to read a refusal, and the Web TLS certificate this
            // provisions is what the admin UI itself is served over.
            var result = await issuanceService.IssueCertificateAsync(csrId, notBefore, notAfter, cancellationToken: cancellationToken);

            if (result.Warnings.Count > 0)
            {
                foreach (var w in result.Warnings)
                    logger.LogWarning("TLS provisioning warning: {Warning}", w);
            }

            // Parse the issued cert for PFX export
            var issuedCert = CertificateUtil.ParseFromPem(result.Pem);

            // Resolve the CA cert for the chain
            var caCertEntity = await db.Certificates
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId, cancellationToken);
            Org.BouncyCastle.X509.X509Certificate? caCert = null;
            if (caCertEntity != null)
                caCert = CertificateUtil.ParseFromPem(caCertEntity.Pem);

            // Generate PFX password and export. Use the same atomic write pattern as
            // TlsRenewalJob: write to .new, load-test, then atomic Move into place. A
            // crash mid-write would otherwise truncate api-tls.pfx and the next process
            // start would fail to bind HTTPS.
            var pfxPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var pfxPath = Path.Combine(AppContext.BaseDirectory, "config", "api-tls.pfx");
            var pfxTempPath = pfxPath + ".new";

            var pfxStore = new Pkcs12StoreBuilder().Build();
            var chainEntries = caCert != null
                ? new[] { new X509CertificateEntry(issuedCert), new X509CertificateEntry(caCert) }
                : new[] { new X509CertificateEntry(issuedCert) };
            pfxStore.SetKeyEntry("api-tls",
                new AsymmetricKeyEntry(keyPair.Private),
                chainEntries);

            X509Certificate2 x509;
            try
            {
                using (var fs = new FileStream(pfxTempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    pfxStore.Save(fs, pfxPassword.ToCharArray(), new SecureRandom());
                }
                FileSecurityUtil.SetOwnerOnly(pfxTempPath);

                // Load-test BEFORE committing. If the password or PKCS#12 structure is
                // wrong we discover it now while the original PFX (if any) is still intact.
                x509 = X509CertificateLoader.LoadPkcs12FromFile(pfxTempPath, pfxPassword,
                    X509KeyStorageFlags.MachineKeySet);

                // Atomic commit: replace the live PFX with the load-tested temp file.
                File.Move(pfxTempPath, pfxPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(pfxTempPath))
                {
                    try { File.Delete(pfxTempPath); }
                    catch (Exception cleanupEx)
                    {
                        logger.LogWarning(cleanupEx, "Stage 2 TLS provisioning: failed to clean up {TempPath}", pfxTempPath);
                    }
                }
            }

            // Update config: Mode=SelfIssued, store password, clear pending fields
            config.Https.Mode = "SelfIssued";
            config.Https.CertificatePassword = pfxPassword;
            config.Https.CertificatePath = "config/api-tls.pfx";
            config.Https.PendingSubjectDn = null;
            config.Https.PendingSans = null;
            config.Https.PendingValidityDays = null;
            config.Https.PendingKeyAlgorithm = null;
            config.Https.PendingKeySize = null;
            PersistConfig();

            // Hot-swap into the cert provider using the already-loaded cert from above.
            certProvider.SetCertificate(x509);

            logger.LogInformation(
                "Web TLS certificate provisioned successfully via standard pipeline. " +
                "SN={Serial}, Subject={Subject}, NotAfter={NotAfter:O}",
                CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
                issuedCert.SubjectDN, issuedCert.NotAfter);

            if (audit != null)
            {
                await audit.LogAsync(
                    Shared.Enums.AuditActionType.TlsCertificateRenewed,
                    actorUserId: null, actorUsername: "system",
                    targetEntityType: "Certificate",
                    targetEntityId: CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
                    details: new
                    {
                        Action = replacing ? "ReplacedMissingCertificateFile" : "Stage2Provisioning",
                        Subject = issuedCert.SubjectDN.ToString(),
                        issuedCert.NotAfter,
                        Replaces = previous?.SerialNumber,
                    });
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Stage 2 TLS provisioning failed. The temporary self-signed certificate remains active. " +
                "Fix the issue and restart the application.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// The signing profile the instance's Web TLS certificate is issued under: one linked to
    /// <paramref name="webTlsCertProfileId"/> whose issuer is the current certificate of an
    /// enabled, undeleted X.509 CA other than the system signing CA, and that CA is an instance CA
    /// or a CA of the instance's primary space (the undeletable space bootstrap creates, which
    /// holds the bootstrap root). A CA of any other space is never chosen: space signing profiles
    /// are linked to instance-wide cert profiles, the Web TLS one included, and a delegated space
    /// must not issue the instance's own TLS identity. Instance CAs come first, then the primary
    /// space's; within each, the oldest signing profile, then the lowest id, so the choice does not
    /// depend on row order. Null when there is none.
    /// </summary>
    internal static async Task<Shared.Entities.SigningProfileEntity?> ResolveSigningProfileAsync(
        ModularCADbContext db, Guid webTlsCertProfileId, CancellationToken cancellationToken = default)
    {
        var candidates = await (
            from link in db.AllowedCertProfileSigningProfiles
            where link.CertProfileId == webTlsCertProfileId
            join profile in db.SigningProfiles on link.SigningProfileId equals profile.Id
            join ca in db.CertificateAuthorities on profile.IssuerId equals ca.CertificateId
            where ca.IsEnabled && !ca.IsDeleted && !ca.IsSshCa
                && (ca.Label == null || ca.Label.ToLower() != "system-signing-ca")
                && (ca.SpaceId == null
                    || db.Spaces.Any(s => s.Id == ca.SpaceId && !s.CanBeDeleted && !s.IsDeleted && s.IsEnabled))
            select new { Profile = profile, Instance = ca.SpaceId == null })
            .ToListAsync(cancellationToken);

        return candidates
            .OrderByDescending(c => c.Instance)
            .ThenBy(c => c.Profile.CreatedAt)
            .ThenBy(c => c.Profile.Id)
            .Select(c => c.Profile)
            .FirstOrDefault();
    }

    /// <summary>
    /// Refuses a Web TLS SAN that is not <c>DNS:name</c> or <c>IP:address</c>: the Web TLS
    /// certificate carries only those, as setup and the Web TLS reissue endpoint already require.
    /// The infrastructure CSR builder itself takes every SAN type, so the restriction is kept here.
    /// </summary>
    /// <exception cref="InvalidOperationException">An entry has another type, or none.</exception>
    internal static void EnsureDnsOrIpSans(IEnumerable<string> sans)
    {
        foreach (var san in sans)
        {
            if (string.IsNullOrWhiteSpace(san))
                continue;
            var colon = san.IndexOf(':');
            var type = colon > 0 ? san[..colon].Trim() : string.Empty;
            if (!type.Equals("DNS", StringComparison.OrdinalIgnoreCase) && !type.Equals("IP", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"Web TLS certificate SAN '{san}' is not supported; the Web TLS certificate carries only DNS:name and IP:address names.");
        }
    }

    /// <summary>
    /// Persists the in-memory <see cref="SystemConfig"/> to <c>config.yaml</c>. Uses
    /// <see cref="EnvVarConfigOverlay.WithSecretsProtected"/> so env-sourced secrets are
    /// nulled for the YAML write and restored in-memory afterward. Without this, Stage 2
    /// TLS provisioning would leak env-sourced JWT secrets, DB passwords, etc. into
    /// <c>config.yaml</c> on first runtime boot. Written through
    /// <see cref="ModularCA.Shared.Utils.ConfigYamlWriter"/>, which leaves out the <c>DB</c>
    /// section and keeps the file's owner, group and mode.
    /// </summary>
    private void PersistConfig()
    {
        envOverlay.WithSecretsProtected(config, () =>
        {
            try
            {
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                ModularCA.Shared.Utils.ConfigYamlWriter.Write(configPath, config);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to persist config.yaml after TLS provisioning. " +
                    "In-memory config updated; restart will re-enter Pending mode.");
            }
        });
    }
}
