using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Interfaces
{
    /// <summary>
    /// Result of a successful revoke/hold/unhold call — returned to the controller so the API
    /// response can surface the post-action cert state plus the newly issued CRL number without
    /// a second round-trip. <see cref="PreviousReason"/> is <see cref="RevocationReason.CertificateHold"/>
    /// when a revoke turned a hold into a permanent revocation, and null otherwise.
    /// <see cref="AlsoSerialNumbers"/> lists the other certificates the same action reached: for a
    /// CA certificate, every other certificate that CA has over the same key, which is revoked,
    /// held or released with it. Empty for any other certificate.
    /// </summary>
    public sealed record RevocationResult(
        Guid CertificateId,
        string SerialNumber,
        string NewStatus,
        RevocationReason? Reason,
        DateTime EffectiveAt,
        long? CrlNumber,
        RevocationReason? PreviousReason = null)
    {
        /// <summary>Serials of the other certificates of the same CA and key that the action also changed.</summary>
        public IReadOnlyList<string> AlsoSerialNumbers { get; init; } = [];
    }

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

        /// <summary>
        /// <see cref="RevokeCertificateAsync(Guid?, string?, RevocationReason, DateTime?)"/> on behalf of
        /// <paramref name="actor"/>. Revoking a CA certificate also revokes every other certificate
        /// that CA has over the same key; the audit row the service writes for each of those names
        /// this actor and carries the same address and ceremony as the caller's own row for the
        /// certificate it named. The default ignores the actor, for an implementation that audits nothing.
        /// </summary>
        Task<RevocationResult> RevokeCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationReason reason,
            DateTime? invalidityDate, RevocationActor actor)
            => RevokeCertificateAsync(certificateId, certificateSerialNumber, reason, invalidityDate);

        /// <summary><see cref="HoldCertificateAsync(Guid?, string?)"/> on behalf of <paramref name="actor"/>, who is named on the audit row of each other certificate the hold reaches.</summary>
        Task<RevocationResult> HoldCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationActor actor)
            => HoldCertificateAsync(certificateId, certificateSerialNumber);

        /// <summary><see cref="UnholdCertificateAsync(Guid?, string?)"/> on behalf of <paramref name="actor"/>, who is named on the audit row of each other certificate the release reaches.</summary>
        Task<RevocationResult> UnholdCertificateAsync(Guid? certificateId, string? certificateSerialNumber, RevocationActor actor)
            => UnholdCertificateAsync(certificateId, certificateSerialNumber);
    }

    /// <summary>
    /// Who asked for a revocation, a hold or a release, and from where: what the audit row of
    /// every certificate the action reaches says, so that a row never names "system" for
    /// something a person did.
    /// </summary>
    /// <param name="UserId">The account.</param>
    /// <param name="Username">Its name.</param>
    /// <param name="SourceIp">The address the request came from.</param>
    /// <param name="CeremonyId">The key ceremony the action executes, when there is one.</param>
    public sealed record RevocationActor(Guid? UserId, string? Username, string? SourceIp = null, Guid? CeremonyId = null);
}
