namespace ModularCA.Shared.Enrollment;

/// <summary>
/// What an enrollment protocol can do, as a flag set the console and the readiness checks can
/// read rather than infer.
/// </summary>
/// <remarks>
/// Declared by the protocol itself through <see cref="IEnrollmentProtocol.Capabilities"/>, so a
/// protocol page says what a protocol supports without a lookup table that drifts away from the
/// implementation it describes.
/// </remarks>
[Flags]
public enum EnrollmentCapabilities
{
    /// <summary>The protocol supports nothing; the zero value, never a declared capability.</summary>
    None = 0,

    /// <summary>First issuance for a caller that does not already hold a certificate from this CA.</summary>
    Enroll = 1 << 0,

    /// <summary>
    /// Re-enrollment, where the caller's existing certificate is the credential — EST's
    /// <c>/simplereenroll</c>, SCEP's renewal signed by the certificate being replaced.
    /// </summary>
    ReEnroll = 1 << 1,

    /// <summary>
    /// Renewal as a distinct operation carrying evidence of the certificate being renewed, so the
    /// new request is linked to the old certificate — MSAE's CMC renewal, CMP's <c>kur</c>.
    /// </summary>
    Renew = 1 << 2,

    /// <summary>The client may ask after a request taken under submission, by its identifier.</summary>
    Poll = 1 << 3,

    /// <summary>The client may fetch the certificate for a request that has since been approved.</summary>
    Collect = 1 << 4,

    /// <summary>The protocol carries a revocation request.</summary>
    Revoke = 1 << 5,

    /// <summary>The server generates the key pair and returns it with the certificate.</summary>
    ServerKeyGeneration = 1 << 6,
}
