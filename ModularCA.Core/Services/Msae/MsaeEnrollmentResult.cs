namespace ModularCA.Core.Services.Msae;

/// <summary>
/// The outcome of an MSAE enrollment: the certificate, or a request left waiting for approval.
/// </summary>
/// <param name="Pkcs7">The issued certificate and its chain as a certs-only PKCS#7 (DER), or null while pending.</param>
/// <param name="PendingRequestId">The request an approver owns, or null when issued.</param>
public sealed record MsaeEnrollmentResult(byte[]? Pkcs7, Guid? PendingRequestId)
{
    /// <summary>True when the request awaits approval and the client must poll with the request id.</summary>
    public bool IsPending => PendingRequestId != null;

    /// <summary>An issued certificate.</summary>
    public static MsaeEnrollmentResult Issued(byte[] pkcs7) => new(pkcs7, null);

    /// <summary>A request taken under submission.</summary>
    public static MsaeEnrollmentResult Pending(Guid requestId) => new(null, requestId);
}

/// <summary>What a client learns when it asks after a request it submitted earlier.</summary>
public enum MsaeRequestState
{
    /// <summary>Still waiting for approval, or approved and not yet issued.</summary>
    Pending,
    /// <summary>Issued; the certificate is in <see cref="MsaeStatusResult.Pkcs7"/>.</summary>
    Issued,
    /// <summary>Rejected or cancelled by an operator; the client should stop asking.</summary>
    Denied,
}

/// <summary>The answer to a status query.</summary>
/// <param name="State">Where the request stands.</param>
/// <param name="Pkcs7">The certificate and chain when <see cref="MsaeRequestState.Issued"/>.</param>
/// <param name="Reason">Why, when <see cref="MsaeRequestState.Denied"/>.</param>
public sealed record MsaeStatusResult(MsaeRequestState State, byte[]? Pkcs7 = null, string? Reason = null);
