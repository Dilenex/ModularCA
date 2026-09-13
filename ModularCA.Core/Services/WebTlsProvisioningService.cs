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
/// Registered as an IHostedService only when <c>Https.Mode = "Pending"</c>.
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

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!string.Equals(config.Https.Mode?.Trim(), "Pending", StringComparison.OrdinalIgnoreCase))
            return;

        logger.LogInformation("Stage 2 TLS provisioning: issuing web TLS certificate via standard pipeline...");

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

            var signingProfileLink = await db.AllowedCertProfileSigningProfiles
                .Include(l => l.SigningProfile)
                .FirstOrDefaultAsync(l => l.CertProfileId == certProfile.Id, cancellationToken);
            if (signingProfileLink?.SigningProfile == null)
                throw new InvalidOperationException("No signing profile linked to Web TLS Certificate Profile.");

            var signingProfile = signingProfileLink.SigningProfile;

            // Build subject DN and SANs from pending config
            var subjectDn = config.Https.PendingSubjectDn ?? "CN=localhost";
            var sans = config.Https.PendingSans ?? new List<string> { "DNS:localhost", "IP:127.0.0.1" };
            var validityDays = config.Https.PendingValidityDays ?? 365;
            var keyAlgorithm = config.Https.PendingKeyAlgorithm ?? "ECDSA";
            var keySize = config.Https.PendingKeySize ?? 256;

            // Generate CSR via the infrastructure pipeline
            var (csrId, keyPair) = await csrService.GenerateInfrastructureCsrAsync(
                subjectDn, keyAlgorithm, keySize, certProfile.Id, signingProfile.Id, sans);

            // Issue the cert through the standard pipeline
            var notBefore = _timeProvider.GetUtcNow().UtcDateTime;
            var notAfter = notBefore.AddDays(validityDays);
            // Named argument because the tenant validity-ceiling enforcement mode now sits ahead of
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
                    details: new { Action = "Stage2Provisioning", Subject = issuedCert.SubjectDN.ToString(), issuedCert.NotAfter });
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
    /// Persists the in-memory <see cref="SystemConfig"/> to <c>config.yaml</c>. Uses
    /// <see cref="EnvVarConfigOverlay.WithSecretsProtected"/> so env-sourced secrets are
    /// nulled for the YAML write and restored in-memory afterward. Without this, Stage 2
    /// TLS provisioning would leak env-sourced JWT secrets, DB passwords, etc. into
    /// <c>config.yaml</c> on first runtime boot.
    /// </summary>
    private void PersistConfig()
    {
        envOverlay.WithSecretsProtected(config, () =>
        {
            try
            {
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(PascalCaseNamingConvention.Instance)
                    .Build();
                var yaml = serializer.Serialize(config);
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                File.WriteAllText(configPath, yaml);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to persist config.yaml after TLS provisioning. " +
                    "In-memory config updated; restart will re-enter Pending mode.");
            }
        });
    }
}
