using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Signer.Identity;

/// <summary>
/// The pin each side of the signer channel holds for the other: SHA-256 over the DER-encoded
/// SubjectPublicKeyInfo of the peer's certificate, as lower-case hex, which is the form the
/// keystore already pins its signing CA in. There is no trust-store lookup on either side; a
/// peer whose public key is not the pinned one is refused at the handshake whatever chain it
/// presents.
/// </summary>
public static class SpkiPin
{
    private const string Prefix = "sha256:";

    /// <summary>Computes the pin of <paramref name="certificate"/>: 64 lower-case hex characters.</summary>
    public static string Compute(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexStringLower(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));
    }

    /// <summary>
    /// Brings a configured pin to the form <see cref="Compute"/> produces: an optional
    /// <c>sha256:</c> prefix, colons and whitespace are dropped, the case is lowered. Returns
    /// null for a value that is not 32 hex bytes, which is a pin that matches nothing.
    /// </summary>
    public static string? Normalize(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return null;
        var value = configured.Trim();
        if (value.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            value = value[Prefix.Length..];
        value = value.Replace(":", string.Empty).Replace(" ", string.Empty).ToLowerInvariant();
        if (value.Length != 64) return null;
        foreach (var c in value)
        {
            if (!Uri.IsHexDigit(c)) return null;
        }
        return value;
    }

    /// <summary>
    /// Whether <paramref name="certificate"/> carries the pinned public key. A null certificate,
    /// or a pin that does not normalise, matches nothing. The comparison is constant-time.
    /// </summary>
    public static bool Matches(X509Certificate2? certificate, string? pin)
    {
        if (certificate == null) return false;
        var expected = Normalize(pin);
        if (expected == null) return false;
        var actual = Compute(certificate);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(actual), Convert.FromHexString(expected));
    }
}
