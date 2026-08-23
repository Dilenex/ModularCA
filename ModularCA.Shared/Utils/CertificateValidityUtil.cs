namespace ModularCA.Shared.Utils;

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
}
