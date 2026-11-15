using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The signer's judgement of a renewed CA certificate
/// (<see cref="SigningPurpose.CaCertificateRenewal"/>,
/// <c>docs/architecture/ca-certificate-renewal.md</c>).
/// </summary>
public sealed partial class InProcessSigningService
{
    /// <summary>
    /// The extensions a renewed certificate may carry differently from the one it renews, and
    /// only when its issuer is another CA: they say where the issuer is found, and the issuer's
    /// own certificate may have been renewed since.
    /// </summary>
    private static readonly HashSet<string> IssuerLocatorExtensions = new(StringComparer.Ordinal)
    {
        X509Extensions.AuthorityKeyIdentifier.Id,
        X509Extensions.CrlDistributionPoints.Id,
        X509Extensions.AuthorityInfoAccess.Id,
    };

    /// <summary>How far ahead of the signer's clock a renewed certificate may start.</summary>
    private static readonly TimeSpan RenewalStartSkew = TimeSpan.FromMinutes(10);

    /// <summary>
    /// What a CA key signs under <see cref="SigningPurpose.CaCertificateRenewal"/>: a new
    /// certificate for an existing CA over the key that CA already has, and nothing else. The
    /// key and the context have passed <see cref="JudgeSign"/>, so the context names the CA
    /// whose key signs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The CA being renewed is found from the certificate itself: it is the one CA of this
    /// instance, not deleted, whose current certificate carries the subject public key. The
    /// signer must hold that key. A subject key that is no CA's, or that the signer does not
    /// hold, is <see cref="SigningRefusalReason.EvidenceRequired"/>: this is what keeps a
    /// renewal from certifying a key from outside the signer.
    /// </para>
    /// <para>
    /// The certificate must then repeat the current one: the same subject, byte for byte
    /// (<see cref="SigningRefusalReason.EvidenceRequired"/>); <c>cA=TRUE</c>; a path length that
    /// is not wider than the current one and, for an intermediate, still below its parent's;
    /// every extension of the current certificate with the same criticality and value, and no
    /// other, except that an intermediate's authority key identifier, CRL distribution points
    /// and authority information access may differ; a serial other than the current one; and a
    /// validity that ends after the signer's clock, starts no later than a few minutes after it
    /// and, for an intermediate, lies within the parent certificate's. Those are
    /// <see cref="SigningRefusalReason.PurposeNotPermitted"/>.
    /// </para>
    /// <para>
    /// Who signs is held to the hierarchy: a CA renews itself only when its current certificate
    /// is self-issued, and otherwise the signing CA must be the parent the CA row names and the
    /// key that signed the current certificate (<see cref="SigningRefusalReason.CaMismatch"/>,
    /// <see cref="SigningRefusalReason.EvidenceRequired"/>).
    /// </para>
    /// <para>
    /// Last, the ceremony (<see cref="JudgeRenewalCeremonyAsync"/>): where the scope of the CA
    /// being renewed requires a key ceremony, the context must name an approved
    /// <c>RenewCaCertificate</c> ceremony for that CA, and the certificate must end exactly when
    /// that ceremony says.
    /// </para>
    /// </remarks>
    private async Task<SigningRefusedException?> JudgeCaCertificateRenewalAsync(
        CachedOwner owner, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken)
    {
        var tbs = SignedDataTypes.TbsCertificate(data);
        if (tbs == null)
            return Untyped(SigningPurpose.CaCertificateRenewal, "a DER TBSCertificate");
        var refusal = JudgeCertificateShape(tbs, algorithm, out var shape);
        if (refusal != null)
            return refusal;
        if (!shape!.IsCa)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "A renewal signs a CA certificate only; this certificate does not assert cA=TRUE.");
        if (!tbs.Issuer.Equivalent(owner.Certificate.SubjectDN, true))
            return new SigningRefusedException(SigningRefusalReason.IssuerMismatch,
                $"The certificate names issuer '{tbs.Issuer}', not '{owner.Certificate.SubjectDN}', the CA whose key would sign it.");

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();

        // The CA being renewed: the one whose current certificate carries the subject key.
        var candidates = await (from ca in db.CertificateAuthorities.AsNoTracking()
                                join cert in db.Certificates.AsNoTracking() on ca.CertificateId equals cert.CertificateId
                                where !ca.IsSshCa
                                select new { Ca = ca, Row = cert }).ToListAsync(cancellationToken);
        CertificateAuthorityEntity? renewed = null;
        X509Certificate? current = null;
        foreach (var candidate in candidates)
        {
            var parsed = TryParse(candidate.Row);
            if (parsed == null)
                continue;
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(parsed.GetPublicKey()).GetDerEncoded();
            if (!spki.AsSpan().SequenceEqual(shape.SubjectPublicKeyInfo))
                continue;
            if (renewed != null)
                return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                    $"More than one CA of this instance ({renewed.Id}, {candidate.Ca.Id}) has the subject key of this certificate; the signer cannot tell which is being renewed.");
            (renewed, current) = (candidate.Ca, parsed);
        }
        if (renewed == null || current == null)
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                "A CA certificate is renewed only over the key of an existing CA of this instance; the subject key of this certificate is the key of no CA's current certificate.");
        if (_keystore.GetPrivateKeyFor(current) == null)
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                $"The signer does not hold the key of CA {renewed.Id}; it renews a CA certificate only over a key it holds.");

        if (!tbs.Subject.GetEncoded(Asn1Encodable.Der).AsSpan().SequenceEqual(current.SubjectDN.GetEncoded(Asn1Encodable.Der)))
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                $"A renewal keeps the CA's subject: the certificate names '{tbs.Subject}', and CA {renewed.Id} is '{current.SubjectDN}'.");

        var selfIssued = current.IssuerDN.Equivalent(current.SubjectDN, true);
        var selfRenewal = renewed.Id == owner.CaId;
        if (selfRenewal && !selfIssued)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"CA {renewed.Id} is not a root: its certificate was issued by '{current.IssuerDN}', and only that CA's key renews it.");
        if (!selfRenewal)
        {
            if (selfIssued)
                return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                    $"CA {renewed.Id} is a root; a root's certificate is renewed by its own key, not by CA {owner.CaId}.");
            if (renewed.ParentCaId != owner.CaId)
                return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                    $"CA {owner.CaId} is not the parent of CA {renewed.Id}; a CA certificate is renewed by the parent that issued it.");
        }
        try
        {
            current.Verify(owner.Certificate.GetPublicKey());
        }
        catch (Exception ex) when (ex is GeneralSecurityException or InvalidOperationException or ArgumentException)
        {
            return new SigningRefusedException(SigningRefusalReason.EvidenceRequired,
                $"The current certificate of CA {renewed.Id} was not signed by the key of CA {owner.CaId}; a renewal is signed by the key that signed the certificate it renews.");
        }

        // Path length: never wider than the current certificate's, and below the parent's.
        var currentPathLength = current.GetBasicConstraints();
        if (currentPathLength >= 0 && currentPathLength != int.MaxValue
            && (shape.PathLength == null || shape.PathLength.CompareTo(Org.BouncyCastle.Math.BigInteger.ValueOf(currentPathLength)) > 0))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"A renewal does not widen the path length: CA {renewed.Id} has {currentPathLength}, and the certificate carries {(shape.PathLength == null ? "none" : shape.PathLength.ToString())}.");
        if (!selfRenewal)
        {
            var issuerPathLength = owner.Certificate.GetBasicConstraints();
            if (issuerPathLength >= 0 && issuerPathLength != int.MaxValue
                && (issuerPathLength == 0 || shape.PathLength == null || shape.PathLength.IntValue >= issuerPathLength))
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"CA {owner.CaId} has a path length of {issuerPathLength}; a CA certificate it signs must carry a path length below it.");
        }

        if (JudgeRenewedExtensions(tbs.Extensions, current.CertificateStructure.TbsCertificate.Extensions, selfRenewal, renewed.Id) is { } extensionRefusal)
            return extensionRefusal;

        if (tbs.SerialNumber.Value.Equals(current.SerialNumber))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                "A renewed certificate has a serial of its own; this one repeats the serial of the certificate it renews.");

        var now = DateTime.UtcNow;
        var notBefore = tbs.StartDate.ToDateTime().ToUniversalTime();
        var notAfter = tbs.EndDate.ToDateTime().ToUniversalTime();
        if (notAfter <= notBefore || notAfter <= now)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The renewed certificate would be valid from {notBefore:O} to {notAfter:O}, which is no validity at {now:O}.");
        if (notBefore > now + RenewalStartSkew)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The renewed certificate would start at {notBefore:O}, after the signer's clock ({now:O}); a renewal starts now.");
        if (!selfRenewal)
        {
            var parentNotBefore = owner.Certificate.NotBefore.ToUniversalTime();
            var parentNotAfter = owner.Certificate.NotAfter.ToUniversalTime();
            if (notBefore < parentNotBefore || notAfter > parentNotAfter)
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"The renewed certificate would be valid from {notBefore:O} to {notAfter:O}, outside its parent's validity ({parentNotBefore:O} to {parentNotAfter:O}).");
        }

        return await JudgeRenewalCeremonyAsync(db, renewed, notAfter, context, cancellationToken);
    }

    /// <summary>
    /// Holds a renewed certificate's extensions to those of the certificate it renews: each of
    /// the current ones present with the same criticality and value, and none added. With
    /// <paramref name="selfRenewal"/> false the three extensions that locate the issuer
    /// (<see cref="IssuerLocatorExtensions"/>) are not compared and may be added or left out.
    /// </summary>
    private static SigningRefusedException? JudgeRenewedExtensions(X509Extensions? offered, X509Extensions? current, bool selfRenewal, Guid renewedCaId)
    {
        bool Compared(DerObjectIdentifier oid) => selfRenewal || !IssuerLocatorExtensions.Contains(oid.Id);

        var currentOids = current?.GetExtensionOids() ?? [];
        var offeredOids = offered?.GetExtensionOids() ?? [];
        foreach (var oid in currentOids)
        {
            if (!Compared(oid))
                continue;
            var was = current!.GetExtension(oid);
            var now = offered?.GetExtension(oid);
            if (now == null)
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"A renewal carries every extension of the certificate it renews: extension {oid.Id} of CA {renewedCaId} is missing.");
            if (now.IsCritical != was.IsCritical || !now.Value.GetOctets().AsSpan().SequenceEqual(was.Value.GetOctets()))
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"A renewal changes the validity and the serial only: extension {oid.Id} differs from the one CA {renewedCaId} has.");
        }
        foreach (var oid in offeredOids)
        {
            if (Compared(oid) && (current == null || current.GetExtension(oid) == null))
                return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                    $"A renewal adds no extension: {oid.Id} is not in the certificate CA {renewedCaId} has.");
        }
        return null;
    }

    /// <summary>
    /// The ceremony a renewal runs under. A ceremony the context names must exist, be approved
    /// and unexpired, be a <c>RenewCaCertificate</c> ceremony of the scope of the CA being
    /// renewed, target that CA, and have agreed to exactly <paramref name="notAfter"/>; anything
    /// else is <see cref="SigningRefusalReason.CeremonyNotApproved"/>. With none named, the
    /// scope's policy decides (<see cref="JudgeCeremonyRequirementAsync"/>): a scope that requires
    /// a key ceremony gets no renewal without one.
    /// </summary>
    private static async Task<SigningRefusedException?> JudgeRenewalCeremonyAsync(
        ModularCADbContext db, CertificateAuthorityEntity renewed, DateTime notAfter, SigningContext context, CancellationToken cancellationToken)
    {
        if (context.CeremonyId is not Guid ceremonyId)
            return await JudgeCeremonyRequirementAsync(db, renewed.SpaceId, cancellationToken);

        var ceremony = await db.KeyCeremonies.AsNoTracking().FirstOrDefaultAsync(c => c.Id == ceremonyId, cancellationToken);
        if (ceremony == null)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"No ceremony {ceremonyId} exists; the signer renews a CA certificate under a ceremony it can verify.");
        if (!string.Equals(ceremony.Status, "Approved", StringComparison.Ordinal))
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} is {ceremony.Status}, not Approved.");
        if (ceremony.ExpiresAt <= DateTime.UtcNow)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} expired at {ceremony.ExpiresAt:O}; its approval no longer stands.");
        if (!string.Equals(ceremony.OperationType, RenewCaCertificateCeremonyParameters.OperationType, StringComparison.Ordinal))
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} is a {ceremony.OperationType} ceremony; a CA certificate is renewed only under a {RenewCaCertificateCeremonyParameters.OperationType} ceremony.");
        if (ceremony.SpaceId != renewed.SpaceId)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} was approved for {DescribeScope(ceremony.SpaceId)}, not {DescribeScope(renewed.SpaceId)}.");
        if (!Guid.TryParse(ceremony.TargetEntityId, out var target) || target != renewed.Id)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} does not target CA {renewed.Id}.");

        RenewCaCertificateCeremonyParameters? parameters;
        try
        {
            parameters = CeremonyParametersJson.Read<RenewCaCertificateCeremonyParameters>(ceremony.ParametersJson);
        }
        catch (System.Text.Json.JsonException)
        {
            parameters = null;
        }
        if (parameters == null || parameters.CaId != renewed.Id)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} carries no readable renewal of CA {renewed.Id}.");
        if (parameters.CurrentCertificateId != renewed.CertificateId)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} was approved to renew certificate {parameters.CurrentCertificateId}, which is no longer the current certificate of CA {renewed.Id}.");
        var approved = DateTime.SpecifyKind(parameters.NotAfter, DateTimeKind.Utc);
        if (Math.Abs((approved - notAfter).TotalSeconds) >= 1)
            return new SigningRefusedException(SigningRefusalReason.CeremonyNotApproved,
                $"Ceremony {ceremonyId} approved a certificate valid until {approved:O}; this one would be valid until {notAfter:O}.");
        return null;
    }
}
