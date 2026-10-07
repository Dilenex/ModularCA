using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="SshProfileFieldRules"/>, the save-time checks AdminSshProfileController runs on
/// the SSH profile fields stored as JSON-array strings. Before them, a malformed value was stored
/// and only failed at signing: a bad source address produced certificates sshd rejects, a bad
/// pattern refused every principal, and non-array text threw for every request.
/// </summary>
public class SshProfileFieldRulesTests
{
    [Theory]
    [InlineData("[]")]
    [InlineData("[\"10.0.0.0/8\"]")]
    [InlineData("[\"10.0.0.0/8\",\"192.168.1.5\",\"2001:db8::/32\",\"::1\",\"0.0.0.0/0\"]")]
    public void Accepts_addresses_and_networks(string json)
        => Assert.Null(SshProfileFieldRules.ValidateSourceAddressRestrictions(json));

    [Fact]
    public void Treats_an_absent_field_as_unchanged()
    {
        Assert.Null(SshProfileFieldRules.ValidateSourceAddressRestrictions(null));
        Assert.Null(SshProfileFieldRules.ValidateAllowedPrincipalPatterns(null));
    }

    [Theory]
    [InlineData("[\"10.0.0.1/8\"]", "bits set")]
    [InlineData("[\"2001:db8::1/32\"]", "bits set")]
    [InlineData("[\"10.0.0.0/33\"]", "prefix length")]
    [InlineData("[\"10.0.0.0/\"]", "prefix length")]
    [InlineData("[\"10.1\"]", "not an IPv4")]
    [InlineData("[\"010.0.0.1\"]", "not an IPv4")]
    [InlineData("[\"office\"]", "not an IPv4")]
    [InlineData("[\"fe80::1%eth0\"]", "not an IPv4")]
    [InlineData("[\"\"]", "empty")]
    [InlineData("10.0.0.0/8", "JSON array")]
    [InlineData("", "JSON array")]
    [InlineData("[null]", "JSON array")]
    [InlineData("{\"a\":1}", "JSON array")]
    public void Refuses_entries_sshd_would_reject(string json, string expected)
    {
        var error = SshProfileFieldRules.ValidateSourceAddressRestrictions(json);
        Assert.NotNull(error);
        Assert.Contains(expected, error);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("[\"^[a-z_][a-z0-9_-]{0,31}$\",\"^admin$\"]")]
    [InlineData("[\"^(?=ops-)[a-z-]+$\"]")]
    public void Accepts_patterns_that_compile(string json)
        => Assert.Null(SshProfileFieldRules.ValidateAllowedPrincipalPatterns(json));

    [Theory]
    [InlineData("[\"^(admin\"]")]
    [InlineData("[\"[z-a]\"]")]
    [InlineData("[\"\"]")]
    [InlineData("^admin$")]
    public void Refuses_patterns_that_do_not_compile_or_are_not_an_array(string json)
    {
        var error = SshProfileFieldRules.ValidateAllowedPrincipalPatterns(json);
        Assert.NotNull(error);
        Assert.StartsWith("AllowedPrincipalPatterns", error);
    }

    [Fact]
    public void CompileError_names_the_pattern_and_passes_good_ones()
    {
        Assert.Null(ProfileRegex.CompileError(@"^\d{3}$"));
        Assert.Contains("(unclosed", ProfileRegex.CompileError("(unclosed"));
        Assert.NotNull(ProfileRegex.CompileError(""));
    }
}
