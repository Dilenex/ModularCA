using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Interfaces
{
    /// <summary>
    /// Result of a successful revoke/hold/unhold call — returned to the controller so the API
    /// response can surface the post-action cert state plus the newly issued CRL number without
    /// a second round-trip. <see cref="PreviousReason"/> is <see cref="RevocationReason.CertificateHold"/>
    /// when a revoke turned a hold into a permanent revocation, and null otherwise.
    /// </summary>
    public sealed record RevocationResult(
        Guid CertificateId,
        string SerialNumber,
        string NewStatus,
        RevocationReason? Reason,
        DateTime EffectiveAt,
        long? CrlNumber,
        RevocationReason? PreviousReason = null);

    /// <summary>
    /// Handles certificate revocation, hold, unhold, and reissuance operations.
    /// </summary>
    public interface ICertificateRevocationService
    {
        /// <summary>
        /// Revokes a certificate by ID or serial with a strongly-typed
        /// <see cref="RevocationReason"/>. On success the post-state (and any new CRL number
        /// produced by the synchronous best-effort CRL regen) is returned via
        /// <see cref="RevocationResult"/>. A certificate on hold may be revoked permanently without
        /// being released first (RFC 5280 §5.3.1); a permanently revoked one, or a held one asked
        /// for <see cref="RevocationReason.CertificateHold"/> again, throws
        /// <see cref="ModularCA.Shared.Errors.CertificateRevocationStateException"/> (409).
        /// <para>
        /// Here and on hold and release, a certificate that cannot be found throws
        /// <see cref="ModularCA.Shared.Errors.ResourceNotFoundException"/> (404,
        /// <see cref="ModularCA.Shared.Errors.ErrorCodes.ResourceNotFound"/>), and a serial that
        /// matches certificates of more than one issuer throws
        /// <see cref="ModularCA.Shared.Errors.ResourceConflictException"/> (409,
        /// <see cref="ModularCA.Shared.Errors.ErrorCodes.CertificateSerialAmbiguous"/>).
        /// </para>
        /// </summary>
        Task<RevocationResult> RevokeCertificateAsync(
            Guid? certificateId,
            string? certificateSerialNumber,
            RevocationReason reason,
            DateTime? invalidityDate = null);

        /// <summary>
        /// Deprecated — use <c>ICertificateIssuanceService.ReissueCertificateAsync</c> instead.
        /// This stub throws <see cref="InvalidOperationException"/> at runtime.
        /// </summary>
        [Obsolete("Use CertificateIssuanceService.ReissueCertificateAsync instead")]
        Task ReissueCertificateAsync(Guid certificateId, DateTime notBefore, DateTime notAfter);

        /// <summary>
        /// Places a certificate on hold (CRL reason code 6 — certificateHold).
        /// A held certificate appears on the CRL but can be reinstated later.
        /// Idempotent — repeating on an already-held cert is a no-op. A permanently revoked
        /// certificate cannot be placed on hold: that throws
        /// <see cref="ModularCA.Shared.Errors.CertificateRevocationStateException"/> (409). A missing
        /// or ambiguous certificate is refused as on <see cref="RevokeCertificateAsync"/>.
        /// </summary>
        Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber);

        /// <summary>
        /// Removes a certificate from hold, reinstating it to good status.
        /// The certificate will be removed from subsequent CRLs. A certificate that is not on
        /// hold throws <see cref="ModularCA.Shared.Errors.CertificateRevocationStateException"/> (409).
        /// A missing or ambiguous certificate is refused as on <see cref="RevokeCertificateAsync"/>.
        /// </summary>
        Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber);
    }
}
