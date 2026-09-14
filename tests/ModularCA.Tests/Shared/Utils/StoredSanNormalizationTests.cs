using System.Text.Json;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the read-time repair of Subject Alternative Names stored in BouncyCastle's raw rendering.
/// </summary>
/// <remarks>
/// A certificate issued before <see cref="UpnSanEncoding.Describe"/> handled otherName kept a UPN
/// SAN in its <c>SubjectAlternativeNamesJson</c> column as <c>Other:[oid, [CONTEXT 0]value]</c>.
/// The value is baked into the row, so it still displayed that way in the user and admin UIs long
/// after the parser was fixed. These pin the recovery to the clean <c>UPN:value</c> form and that
/// it never touches a string it should not.
/// </remarks>
public class StoredSanNormalizationTests
{
    [Fact]
    public void The_exact_legacy_UPN_rendering_becomes_a_clean_UPN()
    {
        // The string from the bug report.
        const string legacy = "Other:[1.3.6.1.4.1.311.20.2.3, [CONTEXT 0]testuser@local.private]";
        Assert.Equal("UPN:testuser@local.private", UpnSanEncoding.NormalizeStoredSan(legacy));
    }

    [Fact]
    public void Nested_or_spaced_tag_markers_are_stripped_from_the_value()
    {
        Assert.Equal("UPN:a@b", UpnSanEncoding.NormalizeStoredSan("Other:[1.3.6.1.4.1.311.20.2.3, [CONTEXT 0][CONTEXT 0]a@b]"));
        Assert.Equal("UPN:a@b", UpnSanEncoding.NormalizeStoredSan("Other:[1.3.6.1.4.1.311.20.2.3,  [CONTEXT 0] a@b]"));
    }

    [Fact]
    public void A_non_UPN_otherName_becomes_a_clean_OTHER_form_not_a_sequence_dump()
    {
        var result = UpnSanEncoding.NormalizeStoredSan("Other:[1.2.3.4.5, [CONTEXT 0]something]");
        Assert.Equal("OTHER:1.2.3.4.5:something", result);
    }

    [Theory]
    [InlineData("DNS:example.com")]
    [InlineData("IP:10.0.0.1")]
    [InlineData("EMAIL:user@example.com")]
    [InlineData("URI:https://example.com")]
    [InlineData("UPN:already@clean")]
    // A DirectoryName SAN carries commas in its own value; the repair must not touch it, which is
    // only safe because the "Other:[" guard runs first. Without that guard this string would be
    // split on its first comma and rewritten.
    [InlineData("DN:CN=Service Account,O=Acme,C=US")]
    [InlineData("OTHER:1.2.3.4.5:already-normalized")]
    public void Already_clean_sans_are_returned_unchanged(string clean)
    {
        // The common case: every SAN a current certificate writes. Must be a no-op.
        Assert.Equal(clean, UpnSanEncoding.NormalizeStoredSan(clean));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void Null_and_empty_are_tolerated(string? input, string expected)
    {
        Assert.Equal(expected, UpnSanEncoding.NormalizeStoredSan(input));
    }

    [Fact]
    public void A_malformed_other_rendering_is_left_alone_rather_than_mangled()
    {
        // No comma to split on: not a shape we understand, so do not guess.
        const string weird = "Other:[no-comma-here]";
        Assert.Equal(weird, UpnSanEncoding.NormalizeStoredSan(weird));
    }

    [Fact]
    public void DeserializeStoredSans_repairs_a_mixed_list_from_json()
    {
        var json = JsonSerializer.Serialize(new[]
        {
            "DNS:host.example",
            "Other:[1.3.6.1.4.1.311.20.2.3, [CONTEXT 0]svc@corp.local]",
        });
        Assert.Equal(new List<string> { "DNS:host.example", "UPN:svc@corp.local" },
            UpnSanEncoding.DeserializeStoredSans(json));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    public void DeserializeStoredSans_returns_empty_for_absent_or_bad_json(string? json)
    {
        Assert.Empty(UpnSanEncoding.DeserializeStoredSans(json));
    }
}
