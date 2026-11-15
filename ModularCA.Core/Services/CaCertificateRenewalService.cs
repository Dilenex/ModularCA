using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services;

/// <summary>What a renewal of a CA's certificate would do, worked out before anything is signed.</summary>
/// <param name="Ca">The CA whose certificate is renewed.</param>
/// <param name="CurrentRow">Its current certificate row.</param>
/// <param name="Current">That certificate, parsed.</param>
/// <param name="IsRoot">Whether the CA signs its own certificate.</param>
/// <param name="Parent">The CA that signs the new certificate of an intermediate; null for a root.</param>
/// <param name="ParentRow">The parent's current certificate row.</param>
/// <param name="ParentCertificate">That certificate, parsed.</param>
/// <param name="NotAfter">The end of validity the new certificate will carry, UTC, to the second.</param>
/// <param name="ShortenedToParent">Whether the validity asked for ran past the parent's certificate and was shortened to it.</param>
public sealed record CaRenewalPlan(
    CertificateAuthorityEntity Ca, CertificateEntity CurrentRow, X509Certificate Current, bool IsRoot,
    CertificateAuthorityEntity? Parent, CertificateEntity? ParentRow, X509Certificate? ParentCertificate,
    DateTime NotAfter, bool ShortenedToParent);

/// <summary>A renewal that was made.</summary>
/// <param name="Ca">The CA, now naming the new certificate.</param>
/// <param name="Previous">The certificate it had before; still valid, still served, not revoked.</param>
/// <param name="Renewed">The new certificate row.</param>
/// <param name="Certificate">The new certificate.</param>
public sealed record CaRenewalResult(CertificateAuthorityEntity Ca, CertificateEntity Previous, CertificateEntity Renewed, X509Certificate Certificate);

/// <summary>
/// Renews a CA's certificate over the key it already has
/// (<c>docs/architecture/ca-certificate-renewal.md</c>): the same key, the same subject and the
/// same extensions, a new serial and a new validity. A root signs its own new certificate; an
/// intermediate's is signed by its parent CA of this instance. The signer signs it as an
/// operation of its own (<see cref="SigningPurpose.CaCertificateRenewal"/>) and checks all of
/// that itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>What changes.</b> The CA row names the new certificate, which is from then on the issuer
/// certificate of everything the CA signs. What belongs to the CA's key and was kept under the
/// old certificate's id moves to the new one in the same transaction: the signing profiles that
/// issue from it, its CRL schedules (so the CRL number continues and one CRL covers both
/// certificates), and its service URLs. Both certificates are recorded in <c>CaCertificates</c>.
/// </para>
/// <para>
/// <b>What does not.</b> The earlier certificate stays as it is: valid until it expires, served
/// at its serial, and not revoked. The certificates issued under it keep naming it as their
/// issuer and stay on the CA's CRL and in its OCSP answers, which are found through the key.
/// The CA's children, its delegated OCSP, timestamp and CMP certificates and the keystore files
/// are not touched.
/// </para>
/// <para>
/// <b>Not built.</b> A new key, a changed subject, a certificate signed by a CA outside this
/// instance, cross-certificates and renewal on a schedule.
/// </para>
/// <para>
/// <b>The system signing CA</b> is renewed by the same call. <see cref="RenewAsync"/> takes the
/// CA, the end of validity and the ceremony, and nothing of a request, so a scheduled trigger
/// can call it as the controller does; none is registered.
/// </para>
/// </remarks>
public sealed class CaCertificateRenewalService(
    ModularCADbContext db,
    ISigningService signer,
    IKeystoreCertificates keystore,
    ICaServiceUrlService caServiceUrls,
    ICrlService crlService,
    ILogger<CaCertificateRenewalService> logger,
    ModularCA.Shared.Modes.IInstanceModeGate? modeGate = null)
{
    private const string SignerCaller = nameof(CaCertificateRenewalService);

    /// <summary>The longest validity a renewal may ask for, in years.</summary>
    public const int MaxValidityYears = 50;

    /// <summary>
    /// Works out the renewal of CA <paramref name="caId"/> for <paramref name="validityYears"/>
    /// from <paramref name="now"/>, and refuses what cannot be renewed.
    /// </summary>
    /// <exception cref="ResourceNotFoundException">No such X.509 CA.</exception>
    /// <exception cref="ConfigurationValidationException">
    /// The validity is not from 1 to <see cref="MaxValidityYears"/> years; the CA is the system
    /// signing CA, has no certificate or a revoked one; it is an intermediate whose issuer is
    /// not a CA of this instance, or whose parent is disabled, revoked or outside its validity;
    /// or the new certificate would not end after the current one (for an intermediate, because
    /// its parent's certificate ends first: renew the parent before it).
    /// </exception>
    /// <param name="caId">The CA.</param>
    /// <param name="validityYears">The validity asked for, in years from <paramref name="now"/>.</param>
    /// <param name="now">The instant the renewal is worked out at.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="mayNameParentIn">
    /// Whether whoever reads a refusal may see a CA of the space given (null for an instance CA):
    /// the caller's space fence. A refusal names the parent CA only when it admits the parent's
    /// space; null, the default, never names it. The dates in a refusal stay: they bound the
    /// renewed certificate itself, whose own end the answer carries.
    /// </param>
    public async Task<CaRenewalPlan> PlanAsync(Guid caId, int validityYears, DateTime now, CancellationToken ct = default,
        Func<Guid?, bool>? mayNameParentIn = null)
    {
        if (validityYears is < 1 or > MaxValidityYears)
            throw new ConfigurationValidationException($"The validity of a renewed CA certificate is from 1 to {MaxValidityYears} years; {validityYears} was asked for.");
        var requested = Seconds(now.AddYears(validityYears));
        var plan = await LoadAsync(caId, requested, now, mayNameParentIn, ct);
        if (plan.ShortenedToParent)
            logger.LogInformation("Renewal of CA {CaId}: the validity asked for runs past the parent's certificate and is shortened to {NotAfter:O}.", caId, plan.NotAfter);
        return plan;
    }

    /// <summary>
    /// Renews the certificate of CA <paramref name="caId"/> so that it ends at
    /// <paramref name="notAfter"/>, as <see cref="PlanAsync"/> worked it out (and, under a
    /// ceremony, as the ceremony's parameters record it).
    /// </summary>
    /// <param name="caId">The CA.</param>
    /// <param name="notAfter">The end of validity of the new certificate, UTC.</param>
    /// <param name="ceremonyId">The approved <c>RenewCaCertificate</c> ceremony this executes, when the CA's scope requires one; the signer verifies it.</param>
    /// <param name="actor">Who asked, for the CA's certificate history.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="mayNameParentIn">As for <see cref="PlanAsync"/>: whether a refusal may name the parent CA, by the parent's space; null never names it.</param>
    /// <exception cref="SigningRefusedException">The signer refused: the key, the certificate offered or the ceremony is not what a renewal needs.</exception>
    public async Task<CaRenewalResult> RenewAsync(Guid caId, DateTime notAfter, Guid? ceremonyId, string? actor, CancellationToken ct = default,
        Func<Guid?, bool>? mayNameParentIn = null)
    {
        ModularCA.Shared.Modes.InstanceModeGate.ThrowIfRefused(modeGate, ModularCA.Shared.Modes.ModeOperation.Frozen, "Renewing a CA certificate");

        var now = DateTime.UtcNow;
        var plan = await LoadAsync(caId, Seconds(DateTime.SpecifyKind(notAfter, DateTimeKind.Utc)), now, mayNameParentIn, ct);
        if (plan.ShortenedToParent)
            throw new ConfigurationValidationException(
                $"The renewed certificate would end at {notAfter:yyyy-MM-dd}, after the certificate of its {ParentPhrase(plan.Parent!, mayNameParentIn)} ({plan.ParentCertificate!.NotAfter:yyyy-MM-dd}). Renew the parent first, or ask for a shorter validity.");

        var ca = plan.Ca;
        var signingCa = plan.Parent ?? ca;
        var signingRow = plan.ParentRow ?? plan.CurrentRow;
        var signingCertificate = plan.ParentCertificate ?? plan.Current;

        var keys = await signer.ListKeysAsync(SigningContext.ForCa(SignerCaller, SigningPurpose.Certificate, signingCa.Id, signingCa.SpaceId), ct);
        if (!X509SignerKeys.Holds(keys, signingRow.CertificateId))
            throw new ConfigurationValidationException(
                $"The signer does not hold the key of {(plan.Parent == null ? $"CA '{signingCa.Name}'" : $"the {ParentPhrase(plan.Parent, mayNameParentIn)}")}, which signs the renewed certificate.", ErrorCodes.IssuingCaKeyUnavailable);

        // The new certificate: everything of the current one but the serial and the validity.
        var serialBytes = new byte[17];
        RandomNumberGenerator.Fill(serialBytes.AsSpan(1));
        var serial = new BigInteger(1, serialBytes);
        var notBefore = Seconds(CertificateValidityUtil.DefaultNotBefore());
        if (!plan.IsRoot && notBefore < signingCertificate.NotBefore.ToUniversalTime())
            notBefore = signingCertificate.NotBefore.ToUniversalTime();

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(serial);
        generator.SetIssuerDN(signingCertificate.SubjectDN);
        generator.SetSubjectDN(plan.Current.SubjectDN);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(plan.NotAfter);
        generator.SetPublicKey(plan.Current.GetPublicKey());

        // Where the issuer is found may have moved since the certificate was issued; for an
        // intermediate those two extensions are written from the parent's URLs as they are now.
        var parentUrls = plan.IsRoot ? null : await caServiceUrls.ResolveForCaAsync(signingRow.CertificateId);
        var rewriteLocators = parentUrls != null && (parentUrls.CdpUrls.Count > 0 || parentUrls.OcspUrls.Count > 0 || parentUrls.CaIssuerUrls.Count > 0);
        var extensions = plan.Current.CertificateStructure.TbsCertificate.Extensions;
        if (extensions != null)
        {
            foreach (var oid in extensions.GetExtensionOids())
            {
                if (rewriteLocators && (oid.Equals(X509Extensions.CrlDistributionPoints) || oid.Equals(X509Extensions.AuthorityInfoAccess)))
                    continue;
                var extension = extensions.GetExtension(oid);
                generator.AddExtension(oid, extension.IsCritical, Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(extension.Value.GetOctets()));
            }
        }
        if (rewriteLocators)
            CaCreationService.AddCdpAndAiaFromResolved(generator, parentUrls!);

        var caKey = SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signingCertificate.GetPublicKey()).GetDerEncoded());
        var context = SigningContext.ForCa(SignerCaller, SigningPurpose.CaCertificateRenewal, signingCa.Id, signingCa.SpaceId) with
        {
            CeremonyId = ceremonyId,
            Issuance = new IssuanceOrigin(
                Answers: new IssuanceAnswers(ModularCA.Journal.AnswersKind.None, ceremonyId?.ToString("D")),
                Replaces: new IssuanceReplaces(plan.Current.SerialNumber.ToByteArrayUnsigned(), caKey),
                Belongs: ca.SpaceId is Guid space ? new IssuanceBelongs(Space: space.ToString("D")) : null,
                Protocol: "CaRenewal"),
        };
        var algorithm = SignatureAlgorithm.FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(signingCertificate.GetPublicKey()));
        var renewed = generator.Generate(new SigningServiceSignatureFactory(signer, new KeyRef(signingRow.CertificateId), algorithm, context));
        renewed.Verify(signingCertificate.GetPublicKey());

        // Signed. From here the database is brought to it in one transaction.
        var previous = plan.CurrentRow;
        var row = CaCreationService.BuildCaCertEntity(renewed, plan.ParentRow?.CertificateId);
        row.CertificateId = Guid.NewGuid();
        if (plan.IsRoot)
            row.IssuerCertificateId = row.CertificateId;
        row.KeyUsagesJson = previous.KeyUsagesJson;
        row.ExtendedKeyUsagesJson = previous.ExtendedKeyUsagesJson;
        row.SubjectAlternativeNamesJson = previous.SubjectAlternativeNamesJson;
        row.SigningProfileId = previous.SigningProfileId;
        row.CertProfileId = previous.CertProfileId;
        row.CreatedAt = now;

        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            var tracked = await db.CertificateAuthorities.FirstAsync(c => c.Id == ca.Id, ct);
            if (tracked.CertificateId != previous.CertificateId)
                throw new ResourceConflictException($"CA '{ca.Name}' was given another certificate while this renewal ran; nothing was changed.");
            db.Certificates.Add(row);
            await db.SaveChangesAsync(ct);

            tracked.CertificateId = row.CertificateId;
            foreach (var profile in await db.SigningProfiles.Where(p => p.IssuerId == previous.CertificateId).ToListAsync(ct))
                profile.IssuerId = row.CertificateId;
            foreach (var schedule in await db.CrlConfigurations.Where(c => c.CaCertificateId == previous.CertificateId).ToListAsync(ct))
                schedule.CaCertificateId = row.CertificateId;
            foreach (var urls in await db.CaServiceUrls.Where(u => u.CaCertificateId == previous.CertificateId).ToListAsync(ct))
                urls.CaCertificateId = row.CertificateId;

            // The earlier certificate is a CA's own and has been replaced: its expiry is no longer
            // something to warn about in the certificate list.
            var earlier = await db.Certificates.FirstAsync(c => c.CertificateId == previous.CertificateId, ct);
            earlier.ExpiryWarningDismissedAt ??= now;
            earlier.ExpiryWarningDismissedBy ??= "CA certificate renewed";

            var keyId = Convert.ToHexStringLower(SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(renewed.GetPublicKey()).GetDerEncoded()));
            var history = await db.CaCertificates.FirstOrDefaultAsync(h => h.CertificateId == previous.CertificateId, ct);
            if (history == null)
            {
                history = new CaCertificateEntity
                {
                    CertificateAuthorityId = ca.Id,
                    CertificateId = previous.CertificateId,
                    KeyId = keyId,
                    Origin = CaCertificateEntity.OriginInitial,
                    ActivatedAt = previous.CreatedAt == default ? previous.NotBefore : previous.CreatedAt,
                };
                db.CaCertificates.Add(history);
            }
            history.SupersededAt = now;
            db.CaCertificates.Add(new CaCertificateEntity
            {
                CertificateAuthorityId = ca.Id,
                CertificateId = row.CertificateId,
                KeyId = keyId,
                Origin = CaCertificateEntity.OriginRenewal,
                ActivatedAt = now,
                CeremonyId = ceremonyId,
                Actor = actor,
            });
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        // The node's view of its CAs learns the new certificate at once.
        keystore.RegisterRenewedCaCertificate(renewed);
        logger.LogInformation("CA '{Name}' ({CaId}): certificate renewed over the same key. Serial {Old} is superseded by {New}, valid until {NotAfter:O}.",
            ca.Name, ca.Id, previous.SerialNumber, row.SerialNumber, plan.NotAfter);

        try
        {
            // Not needed for correctness: the CRL in force names the same issuer and key. It
            // shows at once that the CA signs under its new certificate.
            await crlService.GenerateCrlAsync(row.CertificateId, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "CA '{Name}': the CRL could not be generated right after the renewal; the scheduler generates the next one.", ca.Name);
        }

        return new CaRenewalResult(await db.CertificateAuthorities.AsNoTracking().FirstAsync(c => c.Id == ca.Id, ct), previous, row, renewed);
    }

    /// <summary>
    /// "parent CA 'Name'" for a reader who may see <paramref name="parent"/>, and "parent CA" for
    /// one who may not: a refusal does not carry a CA's name across the space fence.
    /// </summary>
    private static string ParentPhrase(CertificateAuthorityEntity parent, Func<Guid?, bool>? mayNameParentIn)
        => mayNameParentIn?.Invoke(parent.SpaceId) == true ? $"parent CA '{parent.Name}'" : "parent CA";

    /// <summary>
    /// Loads the CA, its certificate and its parent, refuses what cannot be renewed, and bounds
    /// <paramref name="requested"/> by the parent's certificate. A refusal names the parent only
    /// where <paramref name="mayNameParentIn"/> admits its space.
    /// </summary>
    private async Task<CaRenewalPlan> LoadAsync(Guid caId, DateTime requested, DateTime now, Func<Guid?, bool>? mayNameParentIn, CancellationToken ct)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking().Include(c => c.Certificate).FirstOrDefaultAsync(c => c.Id == caId && !c.IsSshCa, ct)
            ?? throw new ResourceNotFoundException("Certificate authority", $"No X.509 certificate authority {caId} exists.", caId.ToString());
        // The system signing CA is renewed like any root. What depends on it depends on its key:
        // the keystore pins and signatures, the instance identifier, the hub's systemKey, the
        // journal's checkpoint key block and the wrapped settings are all read by public key.
        var currentRow = ca.Certificate
            ?? throw new ConfigurationValidationException($"CA '{ca.Name}' has no certificate to renew.");
        if (currentRow.Revoked)
            throw new ConfigurationValidationException($"The certificate of CA '{ca.Name}' is revoked. A revoked CA certificate is not renewed: its key is no longer trusted.");
        var current = Parse(currentRow);
        var selfIssued = current.IssuerDN.Equivalent(current.SubjectDN, true);

        if (ca.ParentCaId == null)
        {
            if (!selfIssued)
                throw new ConfigurationValidationException(
                    $"The certificate of CA '{ca.Name}' was issued by '{current.IssuerDN}', which is not a CA of this instance. Renewal by an outside CA is not built: this version has no way to send a request out and take a certificate back.");
            return EnsureExtends(new CaRenewalPlan(ca, currentRow, current, true, null, null, null, requested, false), mayNameParentIn);
        }

        var parent = await db.CertificateAuthorities.AsNoTracking().Include(c => c.Certificate).FirstOrDefaultAsync(c => c.Id == ca.ParentCaId, ct);
        if (parent?.Certificate == null)
            throw new ConfigurationValidationException($"The parent CA of '{ca.Name}' no longer exists, so nothing can sign its renewed certificate.");
        if (!parent.IsEnabled)
            throw new ConfigurationValidationException($"The {ParentPhrase(parent, mayNameParentIn)} is disabled and cannot sign a renewed certificate.", ErrorCodes.IssuingCaDisabled);
        var parentCertificate = Parse(parent.Certificate);
        // The guard names the parent by its subject DN, which the child's own certificate carries as its issuer.
        await IssuingCaGuard.EnsureUsableAsync(db, parent.Certificate, parentCertificate, requireAuthority: true, now, ct);

        var parentEnd = parentCertificate.NotAfter.ToUniversalTime();
        var shortened = requested > parentEnd;
        return EnsureExtends(new CaRenewalPlan(ca, currentRow, current, false, parent, parent.Certificate, parentCertificate, shortened ? parentEnd : requested, shortened), mayNameParentIn);
    }

    /// <summary>A renewal that would not end after the current certificate is refused: it renews nothing. The refusal names the parent only where <paramref name="mayNameParentIn"/> admits its space.</summary>
    private static CaRenewalPlan EnsureExtends(CaRenewalPlan plan, Func<Guid?, bool>? mayNameParentIn)
    {
        var currentEnd = plan.Current.NotAfter.ToUniversalTime();
        if (plan.NotAfter > currentEnd)
            return plan;
        throw new ConfigurationValidationException(plan.ShortenedToParent
            ? $"The certificate of the {ParentPhrase(plan.Parent!, mayNameParentIn)} ends on {plan.ParentCertificate!.NotAfter:yyyy-MM-dd}, so a renewed certificate of '{plan.Ca.Name}' could not end later than the current one ({currentEnd:yyyy-MM-dd}). Renew the parent's certificate first."
            : $"The renewed certificate would end on {plan.NotAfter:yyyy-MM-dd}, which is not after the current one ({currentEnd:yyyy-MM-dd}). Ask for a longer validity.");
    }

    private static X509Certificate Parse(CertificateEntity row)
        => row.RawCertificate is { Length: > 0 } ? new X509Certificate(row.RawCertificate) : CertificateUtil.ParseFromPem(row.Pem);

    /// <summary>The instant without its fraction of a second: a certificate's validity carries none.</summary>
    private static DateTime Seconds(DateTime value)
    {
        var utc = value.ToUniversalTime();
        return new DateTime(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerSecond), DateTimeKind.Utc);
    }
}
