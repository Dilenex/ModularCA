using System.Text.Json;
using ModularCA.Core.Services;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="NameConstraintRules"/>: the one parser for name-constraint subtrees, run by
/// the certificate builder and by the save-time checks on signing profiles, CA creation and CA
/// ceremonies. The accept/refuse table is shared with the console's checks
/// (<c>shared/common/src/generalNames.ts</c>) through a JSON file both suites read.
/// </summary>
public class NameConstraintRulesTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static IEnumerable<object[]> Cases(string key)
    {
        var path = Path.Combine(RepoRoot(), "tests", "modularca.web.tests", "src", "common", "name-constraint-cases.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty(key).EnumerateArray().Select(e => new object[] { e.GetString()! }).ToList();
    }

    public static IEnumerable<object[]> Accepted => Cases("accept");
    public static IEnumerable<object[]> Refused => Cases("reject");

    [Theory]
    [MemberData(nameof(Accepted))]
    public void Accepts_the_shared_valid_cases(string entry)
    {
        Assert.Null(NameConstraintRules.EntryError(entry));
        Assert.True(NameConstraintRules.TryParse(entry, out var subtree, out _));
        Assert.NotNull(subtree);
    }

    [Theory]
    [MemberData(nameof(Refused))]
    public void Refuses_the_shared_invalid_cases(string entry)
    {
        Assert.NotNull(NameConstraintRules.EntryError(entry));
    }

    [Theory]
    [InlineData("IP:10.0.0.0/8", "0A000000FF000000")]
    [InlineData("IP:10.0.0.0/255.0.0.0", "0A000000FF000000")]
    [InlineData("IP:192.168.1.0/24", "C0A80100FFFFFF00")]
    [InlineData("IP:2001:db8::/32", "20010DB8000000000000000000000000FFFFFFFF000000000000000000000000")]
    public void Prefix_and_netmask_forms_encode_the_same_address_and_mask(string entry, string hex)
    {
        Assert.True(NameConstraintRules.TryParse(entry, out var subtree, out _));
        var octets = ((Asn1OctetString)subtree!.Base.Name).GetOctets();
        Assert.Equal(hex, Convert.ToHexString(octets));
    }

    [Fact]
    public void An_email_constraint_with_a_leading_at_sign_is_refused_with_the_forms_that_work()
    {
        var error = NameConstraintRules.EntryError("EMAIL:@example.com");
        Assert.NotNull(error);
        Assert.Contains("example.com", error);
        Assert.Contains(".example.com", error);
    }

    [Fact]
    public void Json_error_names_the_field_and_rejects_non_arrays()
    {
        Assert.Null(NameConstraintRules.JsonError(null, "F"));
        Assert.Null(NameConstraintRules.JsonError("  ", "F"));
        Assert.Null(NameConstraintRules.JsonError("[]", "F"));
        Assert.Null(NameConstraintRules.JsonError("[\"DNS:example.com\",\"IP:10.0.0.0/8\"]", "F"));
        Assert.StartsWith("F:", NameConstraintRules.JsonError("[\"DNS:example.com\",\"example.org\"]", "F"));
        Assert.Contains("JSON array", NameConstraintRules.JsonError("DNS:example.com", "F"));
        Assert.Contains("JSON array", NameConstraintRules.JsonError("{\"a\":1}", "F"));
        Assert.NotNull(NameConstraintRules.JsonError("[null]", "F"));
    }

    [Fact]
    public void List_error_reports_the_first_bad_entry()
    {
        Assert.Null(NameConstraintRules.ListError(null, "F"));
        Assert.Null(NameConstraintRules.ListError([], "F"));
        var error = NameConstraintRules.ListError(["DNS:example.com", "IP:10.0.0.1", "URI:https://x"], "F");
        Assert.NotNull(error);
        Assert.Contains("10.0.0.1", error);
    }

    [Fact]
    public void An_empty_array_builds_no_extension()
    {
        Assert.Null(NameConstraintRules.ParseJson("[]"));
        Assert.Null(CertificateBuilderService.BuildNameConstraints("[]", null));
        Assert.Null(CertificateBuilderService.BuildNameConstraints(null, "  "));
    }

    /// <summary>
    /// The builder used to drop unreadable entries; when all of them dropped, BouncyCastle was
    /// handed an empty subtree list and threw ArgumentException ("Minimum sequence size is 1"),
    /// failing the CA build with an error that pointed nowhere near the cause. It also passed a
    /// bare IP through as a 4-byte constraint. Both are now refused, by name.
    /// </summary>
    [Theory]
    [InlineData("[\"example.com\"]")]
    [InlineData("[\"FOO:bar\"]")]
    [InlineData("[\"IP:10.0.0.1\"]")]
    [InlineData("[\"DNS:example.com\",\"Email:@example.com\"]")]
    public void The_builder_refuses_an_entry_it_used_to_drop_or_misencode(string permitted)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => CertificateBuilderService.BuildNameConstraints(permitted, null));
        Assert.Contains("Invalid name constraint", ex.Message);
    }

    [Fact]
    public void Only_the_halves_that_have_entries_are_emitted()
    {
        var nc = CertificateBuilderService.BuildNameConstraints("[\"DNS:.example.com\",\"IP:10.0.0.0/8\"]", null);
        Assert.NotNull(nc);
        var seq = (Asn1Sequence)nc!.ToAsn1Object();
        var tagged = Asn1TaggedObject.GetInstance(Assert.Single(seq));
        Assert.Equal(0, tagged.TagNo);
        Assert.Equal(2, Asn1Sequence.GetInstance(tagged, false).Count);
    }
}
