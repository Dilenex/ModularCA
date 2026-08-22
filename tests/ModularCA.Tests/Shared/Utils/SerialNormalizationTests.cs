using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the equivalence between the two serial-number spellings this codebase holds.
/// <para>
/// The Certificates table stores <see cref="CertificateUtil.FormatSerialNumber"/>, which is
/// BouncyCastle's <c>BigInteger.ToString(16)</c> — minimal hex, no leading zeros. .NET's
/// <c>X509Certificate2.SerialNumber</c> renders the DER integer octets at fixed width. The two
/// disagree whenever the leading nibble is zero, which is about one serial in sixteen. EST
/// re-enrollment compared them directly, and because a miss there reads as "not revoked", a
/// revoked client certificate could renew itself.
/// </para>
/// </summary>
public class SerialNormalizationTests
{
    /// <summary>
    /// Builds a real certificate with a leading-zero serial and shows the two representations
    /// genuinely differ — the premise of the bug, demonstrated rather than assumed.
    /// </summary>
    [Fact]
    public void DotNet_and_stored_representations_differ_on_a_leading_zero_serial()
    {
        // 0x0A... — high nibble zero.
        var serialBytes = new byte[] { 0x0A, 0x1B, 0x2C, 0x3D };

        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=serial-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.Create(
            req.SubjectName,
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            serialBytes);

        var stored = CertificateUtil.FormatSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serialBytes));

        Assert.Equal("A1B2C3D", stored);
        Assert.NotEqual(stored, cert.SerialNumber);                              // the bug
        Assert.Equal(stored, CertificateUtil.NormalizeSerialForLookup(cert.SerialNumber));  // the fix
    }

    [Theory]
    [InlineData("0A1B2C", "A1B2C")]
    [InlineData("A1B2C", "A1B2C")]
    [InlineData("0a1b2c", "A1B2C")]
    [InlineData("0A:1B:2C", "A1B2C")]
    [InlineData("0A-1B-2C", "A1B2C")]
    [InlineData("000001", "1")]
    [InlineData("00", "0")]      // an all-zero serial must not normalize to an empty string
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Normalizes_to_the_stored_form(string? input, string expected)
        => Assert.Equal(expected, CertificateUtil.NormalizeSerialForLookup(input));
}
