using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins the empty-allow-list semantic on the CSR ingestion path.
/// <para>
/// <c>AllowedAlgorithms</c>, <c>AllowedKeySizes</c> and <c>AllowedSignatureAlgorithms</c> mean
/// "unrestricted" when empty — that is how <c>IssuanceValidationService</c> reads all three, and
/// it is what the admin UI now states on screen. <c>CsrService.IsValidKeyParameters</c> did not
/// apply it: an empty list rejected every CSR, so a profile with an empty list could not be
/// submitted against at all while issuance would have accepted anything. The two paths disagreed
/// about the same three columns, and the UI asserted the issuance reading.
/// </para>
/// </summary>
public class CsrKeyParameterCeilingTests
{
    private static SigningProfileEntity Signing(string allowedAlgorithms)
        => new() { Name = "test", AllowedAlgorithms = allowedAlgorithms };

    private static CertProfileEntity Cert(string allowedKeySizes, string allowedSignatureAlgorithms)
        => new()
        {
            Name = "test",
            AllowedKeySizes = allowedKeySizes,
            AllowedSignatureAlgorithms = allowedSignatureAlgorithms,
        };

    /// <summary>
    /// Empty lists stop restricting, rather than rejecting everything. They do not permit
    /// literally anything: KeyAlgorithmPolicy.IsAllowed and the algorithm/size compatibility
    /// checks still run at every call site, so the floor becomes policy rather than the profile.
    /// </summary>
    [Fact]
    public void Empty_allow_lists_stop_restricting_key_parameters()
    {
        var ok = CsrService.IsValidKeyParameters(
            "RSA", "4096", "SHA256WITHRSA",
            Signing("[]"), Cert("[]", "[]"));

        Assert.True(ok);
    }

    /// <summary>A populated list still restricts — the change must not disable the check.</summary>
    [Theory]
    [InlineData("ECDSA", "4096", "SHA256WITHRSA", "Key algorithm")]
    [InlineData("RSA", "1024", "SHA256WITHRSA", "Key size")]
    [InlineData("RSA", "4096", "MD5WITHRSA", "Signature algorithm")]
    public void A_populated_allow_list_still_rejects_a_value_outside_it(
        string algorithm, string keySize, string signatureAlgorithm, string expectedField)
    {
        var ex = Assert.Throws<ProfileValidationException>(() => CsrService.IsValidKeyParameters(
            algorithm, keySize, signatureAlgorithm,
            Signing("[\"RSA\"]"),
            Cert("[\"2048\",\"4096\"]", "[\"SHA256WITHRSA\"]")));

        Assert.Contains(expectedField, ex.Message);
    }

    /// <summary>A value inside every populated list is accepted.</summary>
    [Fact]
    public void A_value_inside_every_populated_list_is_accepted()
    {
        var ok = CsrService.IsValidKeyParameters(
            "RSA", "4096", "SHA256WITHRSA",
            Signing("[\"RSA\"]"),
            Cert("[\"2048\",\"4096\"]", "[\"SHA256WITHRSA\"]"));

        Assert.True(ok);
    }

    /// <summary>
    /// One empty list must not relax the others — the guard is per-list, not all-or-nothing.
    /// </summary>
    [Fact]
    public void An_empty_list_does_not_relax_a_populated_sibling()
    {
        var ex = Assert.Throws<ProfileValidationException>(() => CsrService.IsValidKeyParameters(
            "ECDSA", "384", "SHA384WITHECDSA",
            Signing("[\"RSA\"]"),
            Cert("[]", "[]")));

        Assert.Contains("Key algorithm", ex.Message);
    }

    /// <summary>
    /// A JSON <c>null</c> deserialises to a null list and is refused outright, rather than
    /// falling through the new Count checks as though it were unrestricted. Genuinely malformed
    /// JSON is a separate case: CsrService deserialises these three columns without options or a
    /// try/catch, so it throws JsonException rather than returning false.
    /// </summary>
    [Fact]
    public void A_json_null_list_is_rejected_rather_than_treated_as_unrestricted()
    {
        var ok = CsrService.IsValidKeyParameters(
            "RSA", "4096", "SHA256WITHRSA",
            Signing("null"), Cert("[]", "[]"));

        Assert.False(ok);
    }
}
