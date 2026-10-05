using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Covers <see cref="CertificatePolicyRules"/>, the save-time checks on a signing profile's
/// PolicyOids and PolicyQualifiersJson, and <see cref="CtLogIdRules"/>. The per-value cases are
/// shared with the console (<c>certificatePolicies.ts</c>) through certificate-policy-cases.json.
/// </summary>
public class CertificatePolicyRulesTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static IEnumerable<object[]> Cases(string group, string key)
    {
        var path = Path.Combine(RepoRoot(), "tests", "modularca.web.tests", "src", "common", "certificate-policy-cases.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty(group).GetProperty(key).EnumerateArray().Select(e => new object[] { e.GetString()! }).ToList();
    }

    public static IEnumerable<object[]> AcceptedOids => Cases("oid", "accept");
    public static IEnumerable<object[]> RefusedOids => Cases("oid", "reject");
    public static IEnumerable<object[]> AcceptedCpsUris => Cases("cpsUri", "accept");
    public static IEnumerable<object[]> RefusedCpsUris => Cases("cpsUri", "reject");
    public static IEnumerable<object[]> AcceptedNotices => Cases("userNotice", "accept");
    public static IEnumerable<object[]> RefusedNotices => Cases("userNotice", "reject");

    [Theory, MemberData(nameof(AcceptedOids))]
    public void Accepts_the_shared_valid_oids(string oid) => Assert.Null(CertificatePolicyRules.OidError(oid));

    [Theory, MemberData(nameof(RefusedOids))]
    public void Refuses_the_shared_invalid_oids(string oid) => Assert.NotNull(CertificatePolicyRules.OidError(oid));

    [Theory, MemberData(nameof(AcceptedCpsUris))]
    public void Accepts_the_shared_valid_cps_uris(string uri) => Assert.Null(CertificatePolicyRules.CpsUriError(uri));

    [Theory, MemberData(nameof(RefusedCpsUris))]
    public void Refuses_the_shared_invalid_cps_uris(string uri) => Assert.NotNull(CertificatePolicyRules.CpsUriError(uri));

    [Theory, MemberData(nameof(AcceptedNotices))]
    public void Accepts_the_shared_valid_notices(string text) => Assert.Null(CertificatePolicyRules.UserNoticeError(text));

    [Theory, MemberData(nameof(RefusedNotices))]
    public void Refuses_the_shared_invalid_notices(string text) => Assert.NotNull(CertificatePolicyRules.UserNoticeError(text));

    [Fact]
    public void A_user_notice_is_at_most_200_characters()
    {
        Assert.Null(CertificatePolicyRules.UserNoticeError(new string('x', 200)));
        Assert.Contains("200", CertificatePolicyRules.UserNoticeError(new string('x', 201)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("[]")]
    [InlineData("[\"2.23.140.1.2.1\",\"1.3.6.1.4.1.66874.1.1\"]")]
    public void Accepts_blank_or_a_json_array_of_distinct_oids(string? json)
        => Assert.Null(CertificatePolicyRules.PolicyOidsError(json));

    [Theory]
    [InlineData("2.23.140.1.2.1", "JSON array")]
    [InlineData("[\"2.23.140.1.2.1\",\"bogus\"]", "bogus")]
    [InlineData("[\"2.23.140.1.2.1\",\"2.23.140.1.2.1\"]", "more than once")]
    [InlineData("[\"\"]", "empty")]
    [InlineData("[null]", "empty")]
    [InlineData("{\"a\":1}", "JSON array")]
    public void Refuses_policy_oids_the_builder_cannot_encode(string json, string expected)
    {
        var error = CertificatePolicyRules.PolicyOidsError(json);
        Assert.NotNull(error);
        Assert.Contains(expected, error);
    }

    private const string Oids = "[\"2.23.140.1.2.1\",\"2.23.140.1.2.2\"]";

    [Theory]
    [InlineData(null)]
    [InlineData("{}")]
    [InlineData("{\"2.23.140.1.2.1\":{\"cpsUri\":\"https://example.com/cps\",\"userNotice\":\"See the CPS.\",\"critical\":true}}")]
    [InlineData("{\"2.23.140.1.2.1\":{},\"2.23.140.1.2.2\":null}")]
    [InlineData("{\"2.23.140.1.2.1\":{\"cpsUri\":null,\"userNotice\":null,\"critical\":false}}")]
    public void Accepts_qualifiers_of_the_shape_the_builder_reads(string? json)
        => Assert.Null(CertificatePolicyRules.PolicyQualifiersError(json, Oids));

    [Theory]
    [InlineData("[]", "JSON object")]
    [InlineData("{", "JSON object")]
    [InlineData("{\"1.2.3.4\":{\"cpsUri\":\"https://example.com/cps\"}}", "does not list")]
    [InlineData("{\"bogus\":{}}", "bogus")]
    [InlineData("{\"2.23.140.1.2.1\":{\"CpsUri\":\"https://example.com/cps\"}}", "not a recognised key")]
    [InlineData("{\"2.23.140.1.2.1\":{\"cpsUri\":\"ftp://example.com/cps\"}}", "http")]
    [InlineData("{\"2.23.140.1.2.1\":{\"cpsUri\":5}}", "string")]
    [InlineData("{\"2.23.140.1.2.1\":{\"critical\":\"yes\"}}", "true or false")]
    [InlineData("{\"2.23.140.1.2.1\":\"https://example.com/cps\"}", "object")]
    public void Refuses_qualifiers_the_builder_would_ignore(string json, string expected)
    {
        var error = CertificatePolicyRules.PolicyQualifiersError(json, Oids);
        Assert.NotNull(error);
        Assert.Contains(expected, error);
    }

    [Fact]
    public void A_user_notice_over_200_characters_is_refused_inside_the_qualifiers()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object> { ["2.23.140.1.2.1"] = new { userNotice = new string('x', 201) } });
        Assert.Contains("200", CertificatePolicyRules.PolicyQualifiersError(json, Oids));
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData(" ", 0)]
    [InlineData("[]", 0)]
    [InlineData("[\"3f2504e0-4f89-11d3-9a0c-0305e82c3301\",\"3F2504E0-4F89-11D3-9A0C-0305E82C3302\"]", 2)]
    public void Ct_log_ids_parse_as_a_json_array_of_guids(string? json, int count)
    {
        Assert.True(CtLogIdRules.TryParse(json, out var ids, out var error));
        Assert.Null(error);
        Assert.Equal(count, ids.Count);
    }

    [Theory]
    [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    [InlineData("[\"log-a\"]")]
    [InlineData("[null]")]
    [InlineData("{}")]
    public void Malformed_ct_log_ids_are_refused_rather_than_disabling_ct(string json)
    {
        Assert.False(CtLogIdRules.TryParse(json, out _, out var error));
        Assert.Contains("JSON array", error);
    }

    [Fact]
    public async Task Policy_sync_skips_a_signing_profile_whose_policy_oids_would_not_build()
    {
        using var db = InMemoryDbContextFactory.Create();
        var sync = new PolicySyncService(db, NullLogger<PolicySyncService>.Instance);
        const string yaml = """
            profiles:
              - name: Good
                policyOids: '["2.23.140.1.2.1"]'
              - name: Bad
                policyOids: '["2.23.140.1.2.1","not-an-oid"]'
            """;

        var result = await sync.SyncFromYamlAsync(yaml, "signing");

        Assert.Equal(1, result.Created);
        Assert.Contains(result.Errors, e => e.Contains("'Bad' not synced") && e.Contains("not-an-oid"));
        Assert.Equal(new[] { "Good" }, db.SigningProfiles.Select(p => p.Name).ToArray());
    }
}
