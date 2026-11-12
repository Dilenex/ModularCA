using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
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
    /// <para>
    /// Revoking or holding a certificate that is an mTLS sign-in credential also ends every session
    /// of the accounts holding it (<see cref="UserSessionTermination"/>), in the same save.
    /// </para>
    /// <para>
    /// Every operation refuses a missing certificate with <see cref="ResourceNotFoundException"/>
    /// (404) and an ambiguous serial with <see cref="ResourceConflictException"/> (409,
    /// <see cref="ErrorCodes.CertificateSerialAmbiguous"/>); see <see cref="ResolveCertificateEntityAsync"/>.
    /// </para>
    /// </summary>
    public class CertificateRevocationService : ICertificateRevocationService
    {
        private readonly ModularCADbContext _db;
        private readonly IKeystoreCertificates _keystore;
        private readonly ICertificateStore _certStore;
        private readonly INotificationService _notifications;
        private readonly ICrlService _crlService;
        private readonly ILogger<CertificateRevocationService> _logger;
        private readonly IDistributedCache? _cache;
        private readonly IAuditService? _audit;

        /// <summary>
        /// Creates the service. <paramref name="cache"/> drops the cached security stamp of an
        /// account whose sessions a revocation ends, and <paramref name="audit"/> records the ending;
        /// without them the stamp check catches up when its cache entry lapses and the ending is
        /// only logged.
        /// </summary>
        public CertificateRevocationService(
            ModularCADbContext db,
            IKeystoreCertificates keystore,
            ICertificateStore certStore,
            INotificationService notifications,
            ICrlService crlService,
            ILogger<CertificateRevocationService> logger,
            IDistributedCache? cache = null,
            IAuditService? audit = null)
        {
            _db = db;
            _keystore = keystore;
            _certStore = certStore;
            _notifications = notifications;
            _crlService = crlService;
            _logger = logger;
            _cache = cache;
            _audit = audit;
        }

        /// <summary>
        /// Permanently revokes a certificate by ID or serial number with the specified reason.
        /// Throws <see cref="CertificateRevocationStateException"/> (409) if the certificate is
        /// already permanently revoked, or is on hold and <paramref name="reason"/> is
        /// <see cref="RevocationReason.CertificateHold"/> again.
        /// <para>
        /// A certificate on hold may be revoked permanently without being released first, as
        /// RFC 5280 §5.3.1 allows: the entry's reason becomes <paramref name="reason"/> and its
        /// revocation date becomes now, the moment the CA processed the permanent revocation. The
        /// date moves so the change reaches the next delta CRL, which carries the entries revoked
        /// after its base (RFC 5280 §5.2.4), and OCSP reports the new reason and time. Unless the
        /// caller gives an <paramref name="invalidityDate"/> (or one is already stored), the hold's
        /// own date becomes the invalidity date, so the CRL entry still says the certificate has
        /// not been trusted since it was suspended. The result's
        /// <see cref="RevocationResult.PreviousReason"/> is <see cref="RevocationReason.CertificateHold"/>.
        /// </para>
        /// Any mTLS sign-in credential issued as the certificate is revoked in the same save, and
        /// every session of the accounts holding one is ended.
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

            var wasOnHold = RevocationStatus.IsOnHold(certEntity.Revoked, certEntity.RevocationReason);
            if (certEntity.Revoked && !wasOnHold)
                throw new CertificateRevocationStateException(
                    $"Certificate is already revoked (reason: {certEntity.RevocationReason}).", certEntity.RevocationReason);
            if (wasOnHold && reason == RevocationReason.CertificateHold)
                throw new CertificateRevocationStateException(
                    "Certificate is already on hold. Revoke it with a permanent reason, or release the hold.", certEntity.RevocationReason);

            var now = DateTime.UtcNow;
            var holdDate = wasOnHold ? certEntity.RevocationDate : null;
            certEntity.Revoked = true;
            certEntity.RevocationReason = reason.ToString();
            certEntity.RevocationDate = now;
            if (invalidityDate.HasValue)
                certEntity.InvalidityDate = invalidityDate.Value.ToUniversalTime();
            else if (holdDate.HasValue && certEntity.InvalidityDate == null)
                certEntity.InvalidityDate = holdDate.Value;
            var holders = await MtlsCredentialStatus.HoldersOfCertificateAsync(_db, certEntity.CertificateId);
            var ended = await UserSessionTermination.EndAllSessionsAsync(_db, holders, now);
            var mtlsRevoked = await MtlsCredentialStatus.MarkRevokedForCertificateAsync(_db, certEntity.CertificateId, now);
            await _db.SaveChangesAsync();
            if (mtlsRevoked > 0)
                _logger.LogInformation("Revoking certificate {CertId} also revoked {Count} mTLS sign-in credential(s) issued as it.",
                    certEntity.CertificateId, mtlsRevoked);
            await RecordEndedSessionsAsync(certEntity, ended, "mtls_certificate_revoked");

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
                crlNumber,
                wasOnHold ? RevocationReason.CertificateHold : null);
        }

        /// <summary>
        /// Places a certificate on hold. Idempotent — repeating on an already-held
        /// cert returns the current state without bumping <c>RevocationDate</c>. A permanently
        /// revoked certificate throws <see cref="CertificateRevocationStateException"/> (409).
        /// An mTLS sign-in credential issued as the certificate stays unrevoked, so a release
        /// restores it, but every session of the accounts holding one is ended in the same save.
        /// </summary>
        public async Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            var certEntity = await ResolveCertificateEntityAsync(certificateId, certificateSerialNumber);

            // Idempotent — already-held is a no-op.
            if (RevocationStatus.IsOnHold(certEntity.Revoked, certEntity.RevocationReason))
            {
                return new RevocationResult(
                    certEntity.CertificateId,
                    certEntity.SerialNumber,
                    "OnHold",
                    RevocationReason.CertificateHold,
                    certEntity.RevocationDate ?? DateTime.UtcNow,
                    null);
            }

            if (RevocationStatus.IsPermanentlyRevoked(certEntity.Revoked, certEntity.RevocationReason))
                throw new CertificateRevocationStateException(
                    "Certificate is already permanently revoked and cannot be placed on hold.", certEntity.RevocationReason);

            var now = DateTime.UtcNow;
            certEntity.Revoked = true;
            certEntity.RevocationReason = nameof(RevocationReason.CertificateHold);
            certEntity.RevocationDate = now;
            var holders = await MtlsCredentialStatus.HoldersOfCertificateAsync(_db, certEntity.CertificateId);
            var ended = await UserSessionTermination.EndAllSessionsAsync(_db, holders, now);
            await _db.SaveChangesAsync();
            await RecordEndedSessionsAsync(certEntity, ended, "mtls_certificate_on_hold");

            var crlNumber = await TryRegenerateCrlAsync(certEntity);
            return new RevocationResult(
                certEntity.CertificateId,
                certEntity.SerialNumber,
                "OnHold",
                RevocationReason.CertificateHold,
                now,
                crlNumber);
        }

        /// <summary>
        /// Releases a certificate from hold, so it is good again. A certificate that is not
        /// revoked, or is revoked permanently, throws <see cref="CertificateRevocationStateException"/> (409).
        /// </summary>
        public async Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            var certEntity = await ResolveCertificateEntityAsync(certificateId, certificateSerialNumber);

            if (!certEntity.Revoked)
                throw new CertificateRevocationStateException("Certificate is not revoked or on hold.", null);

            if (!RevocationStatus.IsOnHold(certEntity.Revoked, certEntity.RevocationReason))
                throw new CertificateRevocationStateException("Certificate is permanently revoked (reason: " +
                    certEntity.RevocationReason + "). Only certificates on hold can be reinstated.", certEntity.RevocationReason);

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
        /// After the save that ended them, drops the cached stamps of the accounts whose sessions a
        /// revocation or hold of <paramref name="cert"/> ended, and logs and audits each. Failures
        /// are logged and do not fail the revocation, which is already committed; a stale cached
        /// stamp lapses within the stamp cache's lifetime.
        /// </summary>
        private async Task RecordEndedSessionsAsync(CertificateEntity cert, IReadOnlyList<EndedSessions> ended, string reason)
        {
            if (ended.Count == 0)
                return;

            try { await UserSessionTermination.InvalidateStampCacheAsync(_cache, ended.Select(e => e.UserId)); }
            catch (Exception ex) { _logger.LogWarning(ex, "Could not drop cached security stamps after certificate {CertId} ended sessions", cert.CertificateId); }

            foreach (var e in ended)
            {
                _logger.LogInformation(
                    "Certificate {CertId} ({Reason}) was an mTLS sign-in credential of user {UserId}; ended all of that user's sessions ({Count} refresh token(s) revoked).",
                    cert.CertificateId, reason, e.UserId, e.RefreshTokensRevoked);
                if (_audit == null)
                    continue;
                try
                {
                    await _audit.LogAsync(AuditActionType.UserSessionsEnded, null, null,
                        targetEntityType: "User", targetEntityId: e.UserId.ToString(),
                        details: new { reason, username = e.Username, certificateId = cert.CertificateId, serialNumber = cert.SerialNumber, refreshTokensRevoked = e.RefreshTokensRevoked });
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not audit the sessions ended for user {UserId}", e.UserId);
                }
            }
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
        /// profile's issuer when the FK is null (legacy rows); last resort is the CA certificates
        /// with the issuer DN: one is taken as it is, and several (a renewed CA's old and new
        /// certificates share the DN) are narrowed by key (<see cref="ResolveByKeyAsync"/>).
        /// </summary>
        private async Task<Guid?> ResolveIssuerCaIdAsync(CertificateEntity cert)
        {
            if (cert.IssuerCertificateId != null)
                return cert.IssuerCertificateId;

            if (cert.SigningProfileId != null)
            {
                var issuerId = await _db.SigningProfiles
                    .AsNoTracking()
                    .Where(sp => sp.Id == cert.SigningProfileId)
                    .Select(sp => sp.IssuerId)
                    .FirstOrDefaultAsync();
                if (issuerId != null)
                    return issuerId;
            }

            if (!string.IsNullOrWhiteSpace(cert.Issuer))
            {
                var caCerts = await _db.Certificates
                    .AsNoTracking()
                    .Where(c => c.IsCA && c.SubjectDN == cert.Issuer)
                    .Select(c => new { c.CertificateId, c.Pem })
                    .ToListAsync();
                if (caCerts.Count == 1)
                    return caCerts[0].CertificateId;
                if (caCerts.Count > 1)
                    return await ResolveByKeyAsync(cert, caCerts.Select(c => (c.CertificateId, c.Pem)).ToList());
            }

            return null;
        }

        /// <summary>
        /// Picks the issuer of <paramref name="cert"/> among CA certificates sharing its issuer DN:
        /// those whose key verifies its signature. One such certificate is the issuer. Several
        /// (a CA renewed on the same key) must all belong to one CA
        /// (<see cref="IssuerChainResolver.OwnerOf(ModularCADbContext, Guid)"/>), whose current
        /// certificate is preferred when it carries that key, since its CRL covers every same-key
        /// certificate; otherwise the newest of them. Null when no candidate signed it, the signers
        /// belong to different CAs, or the certificate cannot be parsed.
        /// </summary>
        private async Task<Guid?> ResolveByKeyAsync(CertificateEntity cert, List<(Guid Id, string Pem)> candidates)
        {
            Org.BouncyCastle.X509.X509Certificate leaf;
            try
            {
                leaf = cert.RawCertificate is { Length: > 0 } raw
                    ? new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(raw)
                    : ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(cert.Pem);
            }
            catch
            {
                return null;
            }

            var signers = new List<(Guid Id, DateTime NotBefore)>();
            foreach (var (id, pem) in candidates)
            {
                try
                {
                    var issuer = ModularCA.Shared.Utils.CertificateUtil.ParseFromPem(pem);
                    leaf.Verify(issuer.GetPublicKey());
                    signers.Add((id, issuer.NotBefore));
                }
                catch
                {
                    // Not this key, or not a parsable certificate.
                }
            }
            if (signers.Count == 0)
                return null;
            if (signers.Count == 1)
                return signers[0].Id;

            var owners = signers.Select(s => IssuerChainResolver.OwnerOf(_db, s.Id)?.CaId).Distinct().ToList();
            if (owners.Count != 1 || owners[0] is not Guid caId)
                return null;

            var currentId = await _db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.Id == caId)
                .Select(ca => ca.CertificateId)
                .FirstOrDefaultAsync();
            if (currentId is Guid current && signers.Any(s => s.Id == current))
                return current;
            return signers.OrderByDescending(s => s.NotBefore).First().Id;
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
        /// <para>
        /// The refusals belong to the <see cref="RequestValidationException"/> family, so a path
        /// without its own catch answers them through <c>RequestValidationMiddleware</c> instead of
        /// the global handler's 500. They used to be bare <see cref="InvalidOperationException"/>s.
        /// </para>
        /// </summary>
        /// <exception cref="ResourceNotFoundException">
        /// No certificate matches (404, <see cref="ErrorCodes.ResourceNotFound"/>).
        /// </exception>
        /// <exception cref="ResourceConflictException">
        /// The serial matches certificates of more than one issuer (409,
        /// <see cref="ErrorCodes.CertificateSerialAmbiguous"/>).
        /// </exception>
        /// <exception cref="InvalidRequestException">
        /// Neither an ID nor a serial number was supplied (400, <see cref="ErrorCodes.RequestInvalid"/>).
        /// </exception>
        private async Task<CertificateEntity> ResolveCertificateEntityAsync(Guid? certificateId, string? certificateSerialNumber)
        {
            if (certificateId.HasValue)
            {
                return await _db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == certificateId.Value)
                    ?? throw new ResourceNotFoundException("Certificate", "Certificate not found.", certificateId.Value.ToString());
            }

            if (string.IsNullOrWhiteSpace(certificateSerialNumber))
                throw new InvalidRequestException("Neither a certificate ID nor a serial number was supplied.");

            var resolution = await _db.Certificates.ResolveBySerialAsync(certificateSerialNumber);

            if (resolution.Outcome == SerialResolution.NotFound)
                throw new ResourceNotFoundException("Certificate", "Certificate not found.", certificateSerialNumber);

            if (resolution.Outcome == SerialResolution.Ambiguous)
            {
                _logger.LogError(
                    "Refusing to act on serial {Serial}: it matches more than one certificate (issuers differ). "
                    + "Re-issue the request against the certificate ID.", certificateSerialNumber);
                throw new ResourceConflictException(
                    $"Serial number '{certificateSerialNumber}' matches more than one certificate. "
                    + "Serials are unique only per issuer — retry using the certificate ID.",
                    ErrorCodes.CertificateSerialAmbiguous);
            }

            return resolution.Certificate!;
        }
    }
}
