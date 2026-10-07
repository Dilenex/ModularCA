using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Ocsp;

/// <summary>
/// The checks a delegated OCSP responder certificate must pass before the responder will sign
/// with it, as one pure function. <see cref="OcspResponderService"/> applies it to answer a
/// request; <see cref="OcspResponderReadiness"/> applies it to tell an operator beforehand.
/// </summary>
public static class OcspResponderRules
{
    private static readonly DerObjectIdentifier IdKpOcspSigning = new("1.3.6.1.5.5.7.3.9");
    private const string IdPkixOcspNoCheck = "1.3.6.1.5.5.7.48.1.5";

    /// <summary>True when the certificate carries id-pkix-ocsp-nocheck, critical or not.</summary>
    public static bool HasNoCheck(X509Certificate responder) =>
        responder.GetCriticalExtensionOids()?.Contains(IdPkixOcspNoCheck) == true
        || responder.GetNonCriticalExtensionOids()?.Contains(IdPkixOcspNoCheck) == true;

    /// <summary>
    /// Why <paramref name="responder"/> cannot sign OCSP responses, in words an operator can act
    /// on, or null when it can. Checks the id-kp-OCSPSigning extended key usage (RFC 6960
    /// section 4.2.2.2), id-pkix-ocsp-nocheck when <paramref name="requireNoCheck"/> is set, and
    /// the validity window against <paramref name="nowUtc"/>.
    /// </summary>
    public static string? Problem(X509Certificate responder, bool requireNoCheck, DateTime nowUtc)
    {
        var eku = responder.GetExtendedKeyUsage();
        if (eku == null || !eku.Contains(IdKpOcspSigning))
            return "The responder certificate does not carry the OCSP signing extended key usage.";

        if (requireNoCheck && !HasNoCheck(responder))
            return "The responder certificate lacks the OCSP no-check extension, which the security policy requires.";

        if (nowUtc < responder.NotBefore.ToUniversalTime())
            return $"The responder certificate is not valid until {responder.NotBefore.ToUniversalTime():yyyy-MM-dd HH:mm} UTC.";
        if (nowUtc > responder.NotAfter.ToUniversalTime())
            return $"The responder certificate expired on {responder.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm} UTC.";

        return null;
    }
}

/// <summary>How one CA answers OCSP, and what stops it when it cannot.</summary>
/// <param name="CaId">The certificate authority.</param>
/// <param name="Mode">
/// <c>delegated</c>: a responder certificate signs. <c>direct</c>: the CA key signs, because the
/// security policy allows it and no responder is set. <c>none</c>: no responder and direct
/// signing is off. <c>off</c>: OCSP is not served for this CA, so nothing is expected of it.
/// </param>
/// <param name="Problem">Why every OCSP request for this CA is answered "unauthorized"; null when it is answered.</param>
/// <param name="ResponderSerial">Serial number of the responder certificate the CA points at; null when it has none or the row is gone.</param>
/// <param name="ResponderSubject">Subject of that certificate.</param>
/// <param name="ResponderNotAfter">When that certificate expires.</param>
public sealed record OcspResponderState(Guid CaId, string Mode, string? Problem,
    string? ResponderSerial = null, string? ResponderSubject = null, DateTime? ResponderNotAfter = null);

/// <summary>Reports, per CA, whether its OCSP responder can be used.</summary>
public interface IOcspResponderReadiness
{
    /// <summary>
    /// Assesses the given CAs, or every enabled X.509 CA when <paramref name="caIds"/> is null.
    /// A CA that is disabled, deleted, an SSH CA, or without a certificate is left out.
    /// </summary>
    Task<IReadOnlyDictionary<Guid, OcspResponderState>> AssessAsync(IReadOnlyCollection<Guid>? caIds = null, CancellationToken ct = default);
}

/// <summary>
/// Reads the same rows and applies the same certificate rules as the responder, without asking
/// the signer anything, so it is cheap enough to run for every CA on a page load. It therefore
/// does not see a responder key the signer has lost; the keystore checks report that.
/// </summary>
public sealed class OcspResponderReadiness(
    ModularCADbContext db,
    ISecurityPolicyService securityPolicy,
    IFeatureFlagService featureFlags) : IOcspResponderReadiness
{
    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<Guid, OcspResponderState>> AssessAsync(IReadOnlyCollection<Guid>? caIds = null, CancellationToken ct = default)
    {
        var query = db.CertificateAuthorities.AsNoTracking()
            .Where(ca => ca.IsEnabled && !ca.IsDeleted && !ca.IsSshCa && ca.CertificateId != null);
        if (caIds != null)
            query = query.Where(ca => caIds.Contains(ca.Id));

        var cas = await query
            .Select(ca => new
            {
                ca.Id,
                ca.OcspResponderCertificateId,
                CaRevoked = ca.Certificate != null && ca.Certificate.Revoked,
                CaNotAfter = ca.Certificate != null ? ca.Certificate.NotAfter : (DateTime?)null,
            })
            .ToListAsync(ct);

        var states = new Dictionary<Guid, OcspResponderState>();
        if (cas.Count == 0)
            return states;

        var now = DateTime.UtcNow;
        var served = featureFlags.IsEnabled(ProtocolCompatibility.FeatureFlagName("OCSP"));
        var ids = cas.Select(c => c.Id).ToList();
        var switchedOff = (await db.CaProtocolConfigs.AsNoTracking()
                .Where(pc => pc.Protocol == "OCSP" && !pc.IsEnabled && ids.Contains(pc.CaId))
                .Select(pc => pc.CaId)
                .ToListAsync(ct))
            .ToHashSet();

        var responderIds = cas.Where(c => c.OcspResponderCertificateId != null)
            .Select(c => c.OcspResponderCertificateId!.Value).ToList();
        var responders = (await db.Certificates.AsNoTracking()
                .Where(c => responderIds.Contains(c.CertificateId))
                .Select(c => new { c.CertificateId, c.Revoked, c.Pem, c.SerialNumber, c.SubjectDN, c.NotAfter })
                .ToListAsync(ct))
            .ToDictionary(c => c.CertificateId);

        var policy = await securityPolicy.GetAsync();

        foreach (var ca in cas)
        {
            // A CA that answers nothing for its own reasons has no responder problem to report.
            if (!served || switchedOff.Contains(ca.Id) || ca.CaRevoked || ca.CaNotAfter < now)
            {
                states[ca.Id] = new OcspResponderState(ca.Id, "off", null);
                continue;
            }

            if (ca.OcspResponderCertificateId == null)
            {
                states[ca.Id] = policy.AllowCaDirectSigning
                    ? new OcspResponderState(ca.Id, "direct", null)
                    : new OcspResponderState(ca.Id, "none", "This CA has no OCSP responder certificate.");
                continue;
            }

            string? problem;
            if (!responders.TryGetValue(ca.OcspResponderCertificateId.Value, out var row))
                problem = "The responder certificate this CA points at no longer exists.";
            else if (row.Revoked)
                problem = "The responder certificate this CA points at is revoked.";
            else
            {
                try
                {
                    problem = OcspResponderRules.Problem(CertificateUtil.ParseFromPem(row.Pem), policy.RequireNoCheckExtension, now);
                }
                catch (Exception)
                {
                    problem = "The responder certificate this CA points at cannot be read.";
                }
            }
            states[ca.Id] = new OcspResponderState(ca.Id, "delegated", problem, row?.SerialNumber, row?.SubjectDN, row?.NotAfter);
        }

        return states;
    }
}
