using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Handles certificate revocation, hold/unhold, and reissuance using the database and keystore.
    /// After every successful state change this service synchronously (but
    /// best-effort) triggers a full CRL regeneration so revocations become visible to CRL-based
    /// validators without waiting for the next scheduled CRL export. Failures in the CRL regen
    /// are logged but don't fail the revoke — the alternative (either fully sync with an HTTP
    /// stall or fully async via an outbox) is worse in this pass.
    /// </summary>
    public class CertificateRevocationService : ICertificateRevocationService
    {
        private readonly ModularCADbContext _db;
        private readonly IKeystoreCertificates _keystore;
        private readonly ICertificateStore _certStore;
        private readonly INotificationService _notifications;
        private readonly ICrlService _crlService;
        private readonly ILogger<CertificateRevocationService> _logger;

        public CertificateRevocationService(
            ModularCADbContext db,
            IKeystoreCertificates keystore,
            ICertificateStore certStore,
            INotificationService notifications,
            ICrlService crlService,
            ILogger<CertificateRevocationService> logger)
        {
            _db = db;
            _keystore = keystore;
            _certStore = certStore;
            _notifications = notifications;
            _crlService = crlService;
            _logger = logger;
        }

        /// <summary>
        /// Permanently revokes a certificate by ID or serial number with the specified reason.
        /// Throws if the certificate is already revoked (idempotency guard).
        /// Triggers a full CRL regeneration after persistence and an
        /// opportunistic delta CRL regen if a delta config exists.
        /// </summary>
        public async Task<RevocationResult> RevokeCertificateAsync(
            Guid? certificateId,
            string? certificateSerialNumber,
            RevocationReason reason,
            DateTime? invalidityDate = null)
        {
            var certEntity = await ResolveCertificateEntityAsync(certificateId, certificateSerialNumber);

            if (certEntity.Revoked)
                throw new InvalidOperationException($"Certificate is already revoked (reason: {certEntity.RevocationReason}).");

            var now = DateTime.UtcNow;
            certEntity.Revoked = true;
            certEntity.RevocationReason = reason.ToString();
            certEntity.RevocationDate = now;
            if (invalidityDate.HasValue)
                certEntity.InvalidityDate = invalidityDate.Value.ToUniversalTime();
            await _db.SaveChangesAsync();

            MetricsService.CertsRevoked.WithLabels(certEntity.Issuer ?? "unknown", reason.ToString()).Inc();

            try { await NotifyRevocationAsync(certEntity.SubjectDN, certEntity.SerialNumber, reason.ToString()); }
            catch (Exception notifyEx) { _logger.LogWarning(notifyEx, "Revocation notification failed for cert {CertId}", certEntity.SerialNumber); }

            var crlNumber = await TryRegenerateCrlAsync(certEntity);

            return new RevocationResult(
                certEntity.CertificateId,
                certEntity.SerialNumber,
                "Revoked",
                reason,
                now,
                crlNumber);
        }

        /// <summary>
        /// Places a certificate on hold. Idempotent — repeating on an already-held
        /// cert returns the current state without bumping <c>RevocationDate</c>.
        /// </summary>
        public async Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            var certEntity = await ResolveCertificateEntityAsync(certificateId, certificateSerialNumber);

            // Idempotent — already-held is a no-op.
            if (certEntity.Revoked && certEntity.RevocationReason == nameof(RevocationReason.CertificateHold))
            {
                return new RevocationResult(
                    certEntity.CertificateId,
                    certEntity.SerialNumber,
                    "OnHold",
                    RevocationReason.CertificateHold,
                    certEntity.RevocationDate ?? DateTime.UtcNow,
                    null);
            }

            if (certEntity.Revoked && certEntity.RevocationReason != nameof(RevocationReason.CertificateHold))
                throw new InvalidOperationException("Certificate is already permanently revoked and cannot be placed on hold.");

            var now = DateTime.UtcNow;
            certEntity.Revoked = true;
            certEntity.RevocationReason = nameof(RevocationReason.CertificateHold);
            certEntity.RevocationDate = now;
            await _db.SaveChangesAsync();

            var crlNumber = await TryRegenerateCrlAsync(certEntity);
            return new RevocationResult(
                certEntity.CertificateId,
                certEntity.SerialNumber,
                "OnHold",
                RevocationReason.CertificateHold,
                now,
                crlNumber);
        }

        public async Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            var certEntity = await ResolveCertificateEntityAsync(certificateId, certificateSerialNumber);

            if (!certEntity.Revoked)
                throw new InvalidOperationException("Certificate is not revoked or on hold.");

            if (certEntity.RevocationReason != nameof(RevocationReason.CertificateHold))
                throw new InvalidOperationException("Certificate is permanently revoked (reason: " +
                    certEntity.RevocationReason + "). Only certificates on hold can be reinstated.");

            var now = DateTime.UtcNow;
            certEntity.Revoked = false;
            certEntity.RevocationReason = null;
            certEntity.RevocationDate = null;
            certEntity.InvalidityDate = null;
            await _db.SaveChangesAsync();

            var crlNumber = await TryRegenerateCrlAsync(certEntity);
            return new RevocationResult(
                certEntity.CertificateId,
                certEntity.SerialNumber,
                "Good",
                null,
                now,
                crlNumber);
        }

        /// <summary>
        /// Deprecated stub — use <see cref="CertificateIssuanceService.ReissueCertificateAsync"/> instead.
        /// </summary>
        [Obsolete("Use CertificateIssuanceService.ReissueCertificateAsync instead")]
        public Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter)
        {
            throw new InvalidOperationException("Use CertificateIssuanceService.ReissueCertificateAsync for certificate reissuance.");
        }

        /// <summary>
        /// Best-effort synchronous CRL regeneration. Resolves the CA from
        /// <see cref="CertificateEntity.IssuerCertificateId"/> when set, otherwise falls back to
        /// the signing profile linkage / issuer DN. Returns the new CRL number (or null when the
        /// CA could not be resolved or the regen failed) so callers can surface it in responses.
        /// Failures are logged but do not bubble up — the primary revoke write is already
        /// committed by the time this runs.
        /// </summary>
        private async Task<long?> TryRegenerateCrlAsync(CertificateEntity cert)
        {
            try
            {
                var caId = await ResolveIssuerCaIdAsync(cert);
                if (caId == null)
                {
                    _logger.LogWarning(
                        "Could not resolve issuing CA for cert {CertId} / serial {Serial}; skipping CRL regeneration.",
                        cert.CertificateId, cert.SerialNumber);
                    return null;
                }

                await _crlService.GenerateCrlAsync(caId.Value);

                // If a delta config exists, regen the delta too.
                var hasDelta = await _db.CrlConfigurations
                    .AnyAsync(c => c.CaCertificateId == caId.Value && c.IsDelta);
                if (hasDelta)
                {
                    try { await _crlService.GenerateDeltaCrlAsync(caId.Value); }
                    catch (Exception dex) { _logger.LogWarning(dex, "Delta CRL regen failed for CA {CaId}", caId.Value); }
                }

                var latest = await _db.Crls
                    .AsNoTracking()
                    .Where(c => !c.IsDelta && c.Task != null && c.Task.CaCertificateId == caId.Value)
                    .OrderByDescending(c => c.CrlNumber)
                    .Select(c => (long?)c.CrlNumber)
                    .FirstOrDefaultAsync();
                return latest;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Post-revocation CRL regeneration failed for cert {CertId} / serial {Serial}; CRL will be refreshed on next scheduled run.",
                    cert.CertificateId, cert.SerialNumber);
                return null;
            }
        }

        /// <summary>
        /// Resolves the issuing CA's certificate ID for the supplied cert. Prefers the direct
        /// <see cref="CertificateEntity.IssuerCertificateId"/> FK; falls back to the signing
        /// profile linkage when the FK is null (legacy rows); last resort is matching by issuer
        /// DN string.
        /// </summary>
        private async Task<Guid?> ResolveIssuerCaIdAsync(CertificateEntity cert)
        {
            if (cert.IssuerCertificateId != null)
                return cert.IssuerCertificateId;

            if (cert.SigningProfileId != null)
            {
                var profileLink = await _db.CaProtocolConfigs
                    .AsNoTracking()
                    .Include(pc => pc.Ca)
                    .FirstOrDefaultAsync(pc => pc.SigningProfileId == cert.SigningProfileId);
                if (profileLink?.Ca?.CertificateId != null)
                    return profileLink.Ca.CertificateId;
            }

            if (!string.IsNullOrWhiteSpace(cert.Issuer))
            {
                var caCert = await _db.Certificates
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.IsCA && c.SubjectDN == cert.Issuer);
                if (caCert != null)
                    return caCert.CertificateId;
            }

            return null;
        }

        /// <summary>
        /// Sends a fire-and-forget revocation notification to administrators.
        /// Errors are logged but do not propagate to the caller.
        /// </summary>
        private async Task NotifyRevocationAsync(string subjectDN, string serial, string reason)
        {
            try
            {
                await _notifications.NotifyCertRevokedAsync(subjectDN, serial, reason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send revocation notification for certificate {Serial}", serial);
            }
        }

        /// <summary>
        /// Resolves the certificate a revocation operation targets, preferring the primary key.
        /// <para>
        /// A serial number does NOT identify a certificate on its own. X.509 requires serials to be
        /// unique only within an issuer, and the schema models exactly that: the unique index on
        /// <c>Certificates</c> is <c>(SerialNumber, Issuer)</c>, not <c>SerialNumber</c>. So a
        /// bare <c>FirstOrDefault(c =&gt; c.SerialNumber == s)</c> asks the database for "any row
        /// with this serial" and silently accepts whichever one it returns first — a choice with
        /// no defined ordering, which the engine may answer differently between two calls in the
        /// same request.
        /// </para>
        /// <para>
        /// For a mutation that revokes a certificate that is not an acceptable failure mode, so a
        /// serial matching more than one row is rejected outright rather than resolved by guess.
        /// Callers that can supply <paramref name="certificateId"/> should always do so; the serial
        /// overload exists for protocol paths that only ever see a serial on the wire.
        /// </para>
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// No certificate matches, or the serial is ambiguous across issuers.
        /// </exception>
        private async Task<CertificateEntity> ResolveCertificateEntityAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            if (certificateId.HasValue)
            {
                return await _db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == certificateId.Value)
                    ?? throw new InvalidOperationException("Certificate not found.");
            }

            if (string.IsNullOrWhiteSpace(certificateSerialNumber))
                throw new InvalidOperationException("Certificate not found: neither an ID nor a serial number was supplied.");

            var resolution = await _db.Certificates.ResolveBySerialAsync(certificateSerialNumber);

            if (resolution.Outcome == SerialResolution.NotFound)
                throw new InvalidOperationException("Certificate not found.");

            if (resolution.Outcome == SerialResolution.Ambiguous)
            {
                _logger.LogError(
                    "Refusing to act on serial {Serial}: it matches more than one certificate (issuers differ). "
                    + "Re-issue the request against the certificate ID.", certificateSerialNumber);
                throw new InvalidOperationException(
                    $"Serial number '{certificateSerialNumber}' matches more than one certificate. "
                    + "Serials are unique only per issuer — retry using the certificate ID.");
            }

            return resolution.Certificate!;
        }
    }
}
