using ModularCA.Shared.Enums;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Reads a certificate's stored revocation state (its <c>Revoked</c> flag and
/// <c>RevocationReason</c> name). A certificate on hold is revoked with reason
/// <see cref="RevocationReason.CertificateHold"/> and may still be released or revoked
/// permanently (RFC 5280 §5.3.1); any other revoked certificate is revoked permanently and can
/// change no further. The revocation service enforces the rules; the endpoints use this to decide
/// what to tell the caller before they call it.
/// </summary>
public static class RevocationStatus
{
    /// <summary>True when the certificate is on hold.</summary>
    /// <param name="revoked">The certificate's <c>Revoked</c> flag.</param>
    /// <param name="reason">Its stored <c>RevocationReason</c> name.</param>
    public static bool IsOnHold(bool revoked, string? reason)
        => revoked && reason == nameof(RevocationReason.CertificateHold);

    /// <summary>True when the certificate is revoked permanently: revoked, and not on hold.</summary>
    /// <param name="revoked">The certificate's <c>Revoked</c> flag.</param>
    /// <param name="reason">Its stored <c>RevocationReason</c> name.</param>
    public static bool IsPermanentlyRevoked(bool revoked, string? reason)
        => revoked && !IsOnHold(revoked, reason);
}
