using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Issuance;

namespace ModularCA.Shared.Utils;

/// <summary>
/// What the tenant validity ceiling did to a request.
/// </summary>
/// <remarks>
/// Deliberately not in <c>Shared/Enums</c>: this never crosses the wire, and the shared-type
/// generator would otherwise publish it to the SPAs as a contract nothing consumes.
/// </remarks>
public enum ValidityCeilingOutcome
{
    /// <summary>Within the ceiling, exempt from it, or the tenant has none. Issue as asked.</summary>
    Unchanged = 0,

    /// <summary>Over the ceiling; issue with a shortened expiry and raise <c>MCA-ISS-004</c>.</summary>
    Shortened = 1,

    /// <summary>Over the ceiling, and this caller is refused rather than shortened: <c>MCA-ISS-005</c>.</summary>
    Refused = 2,
}

/// <summary>The outcome of applying a tenant validity ceiling, and the expiry that follows from it.</summary>
/// <param name="Outcome">What the ceiling did.</param>
/// <param name="NotAfter">
/// The expiry to use. Equal to the requested one for <see cref="ValidityCeilingOutcome.Unchanged"/>,
/// shortened to the ceiling for <see cref="ValidityCeilingOutcome.Shortened"/>, and meaningless for
/// <see cref="ValidityCeilingOutcome.Refused"/> because no certificate is issued.
/// </param>
public readonly record struct ValidityCeilingDecision(ValidityCeilingOutcome Outcome, DateTime NotAfter);

/// <summary>
/// Validity-window helpers shared by every issuance path.
/// <para>
/// Certificates are validated by relying parties whose clocks are not the CA's clock. A
/// certificate stamped <c>notBefore = exactly now</c> is therefore invalid on any verifier
/// running even slightly behind — which is why real CAs backdate. Without it, the CA is asserting
/// a precision about wall-clock time that nothing in a distributed system can honour.
/// </para>
/// <para>
/// This was observed rather than theorised: a host whose clock had drifted an hour (never
/// NTP-synced, running off the CMOS clock after a power cut) produced a root CA stamped an hour
/// in the future. Once the clock was corrected the CA could not issue anything at all — every
/// request failed with "Certificate NotBefore precedes issuing CA NotBefore" until real time
/// caught up. A backdated <c>notBefore</c> absorbs ordinary skew; the clamp below absorbs the
/// rest.
/// </para>
/// </summary>
public static class CertificateValidityUtil
{
    /// <summary>
    /// How far before "now" a freshly issued certificate's <c>notBefore</c> is placed.
    /// <para>
    /// Five minutes matches the margin this codebase already applies to the upper bound when
    /// clamping against the issuing CA's <c>notAfter</c>, so both ends of the window now use the
    /// same skew allowance. Long enough to cover ordinary NTP drift and VM clock jitter, short
    /// enough that it does not meaningfully extend the certificate's life.
    /// </para>
    /// </summary>
    public static readonly TimeSpan SkewAllowance = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The <c>notBefore</c> to use when the caller has not specified one: now, less
    /// <see cref="SkewAllowance"/>.
    /// </summary>
    public static DateTime DefaultNotBefore() => DateTime.UtcNow - SkewAllowance;

    /// <summary>
    /// Tags a validity timestamp as UTC, converting a local one and treating an unspecified one as
    /// already-UTC per the application's convention.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because of a defect that put a future <c>notBefore</c> into production
    /// certificates. BouncyCastle's <c>SetNotBefore</c> / <c>SetNotAfter</c> call
    /// <see cref="DateTime.ToUniversalTime"/> on the value they are given, and for
    /// <see cref="DateTimeKind.Unspecified"/> that assumes <em>local</em> time and adds the host's
    /// UTC offset. Measured on a UTC-7 host:
    /// </para>
    /// <code>
    /// Kind=Utc          09:00 -> notBefore 09:00   correct
    /// Kind=Local        02:00 -> notBefore 09:00   correct
    /// Kind=Unspecified  09:00 -> notBefore 16:00   shifted by the host offset
    /// </code>
    /// <para>
    /// Requested validity windows are persisted on the certificate request and read back by EF,
    /// which returns MySQL <c>datetime</c> columns as <see cref="DateTimeKind.Unspecified"/>. So a
    /// window that was correct when submitted became "now plus the server's UTC offset" at
    /// issuance — six hours on the affected host — and every relying party rejected the
    /// certificate until that time passed.
    /// </para>
    /// <para>
    /// The same convention is already applied on the JSON boundary by
    /// <c>UtcDateTimeJsonConverter</c>; this is its counterpart for values that reach the
    /// certificate builder from the database instead.
    /// </para>
    /// </remarks>
    public static DateTime AsUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };

    /// <inheritdoc cref="AsUtc(DateTime)"/>
    public static DateTime? AsUtc(DateTime? value) => value.HasValue ? AsUtc(value.Value) : null;

    /// <summary>
    /// Raises <paramref name="notBefore"/> to <paramref name="issuerNotBefore"/> when it would
    /// otherwise precede it, since a certificate cannot be valid before its issuer.
    /// <para>
    /// Backdating and this clamp are a pair. Backdating alone would break issuance from any CA
    /// whose own <c>notBefore</c> was not backdated — including every CA created before this
    /// change — because the leaf would start five minutes before its issuer. Returning the
    /// issuer's value is the correct answer rather than a workaround: it is the earliest instant
    /// at which the leaf could legitimately be valid.
    /// </para>
    /// </summary>
    /// <param name="notBefore">The proposed certificate start time.</param>
    /// <param name="issuerNotBefore">The issuing CA certificate's start time.</param>
    /// <param name="wasClamped">True when the value was raised.</param>
    public static DateTime ClampToIssuer(DateTime notBefore, DateTime issuerNotBefore, out bool wasClamped)
    {
        wasClamped = notBefore < issuerNotBefore;
        return wasClamped ? issuerNotBefore : notBefore;
    }

    /// <summary>
    /// Shortens <paramref name="notAfter"/> to at most <paramref name="maxValidityDays"/> measured
    /// from <paramref name="notBefore"/>.
    /// <para>
    /// This is the tenant validity ceiling, and it replaced a single global setting that defaulted
    /// to 825 days — the CA/Browser Forum baseline for publicly trusted TLS, applied to every leaf
    /// in the installation whether or not it was a public web certificate. A private CA issuing
    /// five-year device identities was refused by a number that only ever meant anything to public
    /// web PKI, and the only way to permit it was to relax the limit for everyone at once.
    /// </para>
    /// <para>
    /// It shortens rather than refuses. Every enrollment protocol derives its requested expiry from
    /// the certificate profile without any knowledge of the tenant, so refusing would fail every
    /// ACME, EST and CMP enrollment whose profile out-reaches its tenant, over a condition the
    /// enrolling client can neither see nor fix. Callers report the change through the
    /// <c>MCA-ISS-004</c> diagnostic, which is what keeps "shortened" from meaning "silently
    /// different".
    /// </para>
    /// </summary>
    /// <param name="notAfter">The proposed certificate expiry.</param>
    /// <param name="notBefore">The certificate start, which the ceiling is measured from.</param>
    /// <param name="maxValidityDays">The tenant's ceiling in days; 0 or less means unlimited.</param>
    /// <param name="wasClamped">True when the value was shortened.</param>
    /// <returns>The expiry to use, never later than <paramref name="notAfter"/>.</returns>
    public static DateTime ClampToValidityCeiling(
        DateTime notAfter, DateTime notBefore, int maxValidityDays, out bool wasClamped)
    {
        // 0 is unlimited, matching the tenant quota fields beside it. A negative value cannot be
        // set through the API, and is read as unlimited rather than as a ceiling of zero because
        // the alternative failure mode is a tenant that can issue nothing at all.
        if (maxValidityDays <= 0)
        {
            wasClamped = false;
            return notAfter;
        }

        var ceiling = notBefore.AddDays(maxValidityDays);
        wasClamped = notAfter > ceiling;
        return wasClamped ? ceiling : notAfter;
    }

    /// <summary>
    /// The whole tenant-ceiling decision in one place: the three exemptions, the caller's
    /// enforcement mode, the tenant's configured behaviour, and the clamp itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It lives here rather than inside <c>CertificateIssuanceService</c> for the same reason
    /// <see cref="ClampToValidityCeiling"/> does: the interesting part is a set of conditions whose
    /// interaction is easy to get subtly wrong, and it is only directly testable if it needs no
    /// database, no keystore and no CSR. What is left at the call site — logging the message,
    /// attaching the diagnostic, throwing the typed exception — is plumbing.
    /// </para>
    /// <para>
    /// <b>Exemptions are checked first and are absolute.</b> An infrastructure certificate (TSA,
    /// OCSP, Web TLS) or a CA certificate is never shortened and never refused, whatever the tenant
    /// says. The CA exemption is the important one: silently reissuing a ten-year intermediate as a
    /// two-year one takes down everything beneath it, years later, long after anyone connects the
    /// outage to a tenant setting. Before this it was exempt only by accident — CA creation happens
    /// to route through an infrastructure CSR helper — so the caller now asserts it in its own
    /// right.
    /// </para>
    /// <para>
    /// <b>Refusal needs both halves.</b> The tenant set to <see cref="ValidityCeilingBehavior.Refuse"/>
    /// AND the caller passing <see cref="ValidityCeilingEnforcement.HonourTenantPolicy"/>. Either
    /// alone shortens. That is what keeps a tenant setting from failing ACME, EST, SCEP and CMP
    /// enrollments and scheduled renewals, none of which can see the ceiling or change their
    /// request.
    /// </para>
    /// </remarks>
    /// <param name="notAfter">The requested expiry.</param>
    /// <param name="notBefore">The certificate start, which the ceiling is measured from.</param>
    /// <param name="maxValidityDays">The tenant's ceiling in days; 0 or less means unlimited.</param>
    /// <param name="behavior">The tenant's configured behaviour when the ceiling is exceeded.</param>
    /// <param name="enforcement">Whether this caller may be refused rather than shortened.</param>
    /// <param name="isInfrastructureCert">True for a TSA/OCSP/Web TLS certificate; exempt.</param>
    /// <param name="isCaCertificate">True when the issuance produces a CA certificate; exempt.</param>
    /// <returns>What to do, and the expiry that follows from it.</returns>
    public static ValidityCeilingDecision DecideValidityCeiling(
        DateTime notAfter,
        DateTime notBefore,
        int maxValidityDays,
        ValidityCeilingBehavior behavior,
        ValidityCeilingEnforcement enforcement,
        bool isInfrastructureCert,
        bool isCaCertificate)
    {
        if (isInfrastructureCert || isCaCertificate)
            return new ValidityCeilingDecision(ValidityCeilingOutcome.Unchanged, notAfter);

        var clamped = ClampToValidityCeiling(notAfter, notBefore, maxValidityDays, out var wasClamped);
        if (!wasClamped)
            return new ValidityCeilingDecision(ValidityCeilingOutcome.Unchanged, notAfter);

        if (behavior == ValidityCeilingBehavior.Refuse
            && enforcement == ValidityCeilingEnforcement.HonourTenantPolicy)
        {
            return new ValidityCeilingDecision(ValidityCeilingOutcome.Refused, notAfter);
        }

        return new ValidityCeilingDecision(ValidityCeilingOutcome.Shortened, clamped);
    }

    /// <summary>
    /// Works out the longest validity a request could actually receive, and which of the three
    /// layers that can shorten it would be the one to do so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the pre-flight half of the clamps above: the same three limits, evaluated before
    /// the operator submits rather than after. Nothing told them about any ceiling until the
    /// certificate came back shorter than they asked for — by which point the certificate exists,
    /// carries a serial, and has to be revoked and reissued to fix. Being told "capped by tenant
    /// 'Acme Corp'" while the form is still open costs nothing.
    /// </para>
    /// <para>
    /// Narrowest wins. Ties go to the widest-scoped layer that produced the value — the profile
    /// before the tenant, the tenant before the CA — because a layer only displaces another when
    /// it is <em>strictly</em> narrower. Reporting "capped by the issuing CA" for a date the
    /// profile would have produced anyway sends the operator to renew a CA that is not the
    /// problem.
    /// </para>
    /// <para>
    /// The cert profile is the baseline rather than an optional layer, matching what issuance
    /// does: every path defaults <c>ValidityPeriodMax</c> to <c>P1Y</c> when unset
    /// (<c>Iso8601ParserUtil.ParseIso8601(profile.ValidityPeriodMax ?? "P1Y")</c>), so there is no
    /// configuration in which this layer is absent.
    /// </para>
    /// <para>
    /// The arithmetic deliberately mirrors the three enforcement sites rather than simplifying
    /// them into one rule, because they genuinely differ: the profile ceiling is measured from
    /// <em>now</em> (<c>IssuanceValidationService.NotBeyondMaximumDate</c> and the <c>timeMax</c>
    /// default both do), the tenant ceiling from <em>notBefore</em>
    /// (<see cref="ClampToValidityCeiling"/>), and the CA ceiling is its <c>notAfter</c> less the
    /// skew margin. A pre-flight that used one rule for all three would promise dates issuance
    /// then clamps, which is worse than promising nothing.
    /// </para>
    /// </remarks>
    /// <param name="notBefore">The certificate start the request would carry.</param>
    /// <param name="now">Current UTC time, from which the cert profile's maximum is measured.</param>
    /// <param name="certProfileMax">The cert profile's <c>ValidityPeriodMax</c>, already parsed and defaulted.</param>
    /// <param name="tenantMaxValidityDays">The tenant's ceiling in days; 0 or less means unlimited.</param>
    /// <param name="issuingCaNotAfter">The issuing CA certificate's expiry, or null when it is unknown.</param>
    /// <returns>The effective ceiling and the layer that set it.</returns>
    public static ValidityCeilingResolution ResolveCeiling(
        DateTime notBefore,
        DateTime now,
        TimeSpan certProfileMax,
        int tenantMaxValidityDays,
        DateTime? issuingCaNotAfter)
    {
        var profileCeiling = now + certProfileMax;
        DateTime? tenantCeiling = tenantMaxValidityDays > 0 ? notBefore.AddDays(tenantMaxValidityDays) : null;
        // The same 5-minute margin the issuing-CA clamp applies, so the number shown here is the
        // number issuance will honour rather than five minutes more than it.
        DateTime? caCeiling = issuingCaNotAfter.HasValue ? issuingCaNotAfter.Value - SkewAllowance : null;

        var effective = profileCeiling;
        var boundBy = ValidityCeilingSource.CertProfile;
        if (tenantCeiling.HasValue && tenantCeiling.Value < effective)
        {
            effective = tenantCeiling.Value;
            boundBy = ValidityCeilingSource.Tenant;
        }
        if (caCeiling.HasValue && caCeiling.Value < effective)
        {
            effective = caCeiling.Value;
            boundBy = ValidityCeilingSource.IssuingCa;
        }

        // Floor, and never below zero: an already-expired issuing CA yields a negative span, and
        // "-40 days" in a form field reads as a bug rather than as "this CA cannot issue".
        var days = (int)Math.Floor((effective - notBefore).TotalDays);
        if (days < 0) days = 0;

        return new ValidityCeilingResolution(
            notBefore, effective, days, boundBy, profileCeiling, tenantCeiling, caCeiling);
    }
}
