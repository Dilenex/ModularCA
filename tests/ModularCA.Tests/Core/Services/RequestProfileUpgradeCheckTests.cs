using System.Text.Json;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.RequestProfiles;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The <c>--upgrade-check</c> note about request profiles: certificates the protocols issued are
/// replayed against the request profile each protocol uses now, with the rules issuance applies,
/// and the ones a request would no longer get are listed.
/// </summary>
public sealed class RequestProfileUpgradeCheckTests
{
    private static readonly DateTime Issued = new(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>The SAN rules of a profile as bootstrap writes them: camel-case keys, which were not read before 0.4.2.</summary>
    private static string SeededSanRules(string[] allowedTypes, bool required)
        => JsonSerializer.Serialize(new
        {
            allowedTypes,
            required,
            rules = allowedTypes.ToDictionary(t => t, _ => (object)new { regex = (string?)null, maxCount = 10 }),
        });

    private static RequestProfileEntity Profile(string name, string sanRules, params SubjectDnFieldRule[] subject) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        SubjectDnRules = JsonSerializer.Serialize(subject),
        SanRules = sanRules,
    };

    private static ProtocolIssuance Issuance(string protocol, RequestProfileEntity? profile, string subject, params string[] sans)
        => new(protocol, "issuing-ca", profile?.Id, subject, JsonSerializer.Serialize(sans), Issued);

    private static readonly SubjectDnFieldRule CommonNameRequired = new() { Field = "CN", Requirement = "Required", MaxLength = 64 };

    [Fact]
    public void A_seeded_san_rule_that_was_never_read_now_refuses_and_the_note_names_protocol_ca_profile_and_reason()
    {
        var est = Profile("Enterprise Server (EST)", SeededSanRules(["DNS", "IP"], required: true), CommonNameRequired);
        var cmp = Profile("Enterprise User (CMP)", SeededSanRules(["Email"], required: false), CommonNameRequired);

        var note = RequestProfileUpgradeCheck.Note([est, cmp],
        [
            Issuance("EST", est, "CN=printer1", "DNS:printer1"),
            Issuance("EST", est, "CN=printer2"),
            Issuance("CMP", cmp, "CN=alice", "DNS:alice.example.test"),
            Issuance("CMP", cmp, "CN=bob", "Email:bob@example.test"),
        ]);

        Assert.NotNull(note);
        Assert.Contains("4 certificate(s) issued through enrollment protocols in the last 90 days were checked", note);
        Assert.Contains("2 would be refused if requested again:", note);
        Assert.Contains("EST on 'issuing-ca', request profile 'Enterprise Server (EST)': 1 certificate(s), the latest issued 2026-10-01", note);
        Assert.Contains("'CN=printer2':", note);
        Assert.Contains("CMP on 'issuing-ca', request profile 'Enterprise User (CMP)': 1 certificate(s)", note);
        Assert.Contains("'CN=alice': SAN type 'DNS' is not allowed", note);
        Assert.DoesNotContain("printer1", note);
        Assert.DoesNotContain("CN=bob", note);
        Assert.Contains("change the client or the request profile", note);
    }

    [Fact]
    public void When_nothing_would_be_refused_the_note_says_so_and_without_any_profile_there_is_no_note()
    {
        var acme = Profile("Web Server (ACME)", SeededSanRules(["DNS", "IP"], required: true),
            new SubjectDnFieldRule { Field = "CN", Requirement = "Required", Regex = @"^[a-z0-9.-]+$", MaxLength = 64 });

        var note = RequestProfileUpgradeCheck.Note([acme], [Issuance("ACME", acme, "CN=pve1.example.test", "DNS:pve1.example.test")]);
        Assert.Equal("1 certificate(s) issued through enrollment protocols in the last 90 days were checked against the request profile "
            + "each protocol uses on its CA now, with the rules issuance applies from this release; none would be refused.", note);

        Assert.Null(RequestProfileUpgradeCheck.Note([acme], [Issuance("ACME", null, "CN=pve1.example.test", "DNS:pve1.example.test")]));
        Assert.Null(RequestProfileUpgradeCheck.Note([], [Issuance("ACME", acme, "CN=pve1.example.test", "DNS:pve1.example.test")]));
        Assert.Null(RequestProfileUpgradeCheck.Note([acme], []));
    }

    [Fact]
    public void An_acme_request_without_a_subject_takes_its_first_dns_name_as_common_name_as_finalize_does()
    {
        var acme = Profile("Web Server (ACME)", SeededSanRules(["DNS", "IP"], required: true), CommonNameRequired);
        var effective = ProfileResolutionService.ForLoadedRows(Microsoft.Extensions.Logging.Abstractions.NullLogger<ProfileResolutionService>.Instance)
            .ResolveLoaded(acme, null);

        Assert.Null(RequestProfileUpgradeCheck.WhyRefused(effective, Issuance("ACME", acme, "", "DNS:host.example.test")));
        Assert.Contains("'CN' is required", RequestProfileUpgradeCheck.WhyRefused(effective, Issuance("EST", acme, "", "DNS:host.example.test")));
    }

    [Fact]
    public void A_fixed_value_is_supplied_by_the_server_and_does_not_count_against_the_request()
    {
        var profile = Profile("Fixed organisation", SeededSanRules(["DNS"], required: false),
            CommonNameRequired, new SubjectDnFieldRule { Field = "O", Requirement = "Required", FixedValue = "Acme" });

        Assert.Contains("none would be refused", RequestProfileUpgradeCheck.Note([profile], [Issuance("SCEP", profile, "CN=device,O=Somebody Else")]));
    }

    [Fact]
    public void An_inheriting_profile_is_judged_with_the_rules_it_inherits()
    {
        var parent = Profile("Servers", SeededSanRules(["DNS"], required: true), CommonNameRequired);
        var child = Profile("Servers for one CA", "{}", CommonNameRequired);
        child.InheritsFromId = parent.Id;
        child.InheritanceEnabled = true;

        var note = RequestProfileUpgradeCheck.Note([child, parent], [Issuance("EST", child, "CN=host")]);

        Assert.Contains("request profile 'Servers for one CA': 1 certificate(s)", note);
    }

    [Fact]
    public void Names_that_cannot_be_read_are_reported_as_such_and_examples_are_capped()
    {
        var profile = Profile("Servers", SeededSanRules(["DNS"], required: true), CommonNameRequired);
        var issued = Enumerable.Range(1, 5).Select(i => Issuance("EST", profile, $"CN=host{i}")).ToList();
        issued.Add(new ProtocolIssuance("EST", "issuing-ca", profile.Id, "CN=broken", "not json", Issued));

        var note = RequestProfileUpgradeCheck.Note([profile], issued)!;

        Assert.Contains("6 would be refused", note);
        Assert.Contains("and 3 more", note);
        Assert.Equal(3, note.Split('\n').Count(l => l.TrimStart().StartsWith("'CN=", StringComparison.Ordinal)));
        Assert.Contains("its recorded names cannot be read", RequestProfileUpgradeCheck.WhyRefused(
            ProfileResolutionService.ForLoadedRows(Microsoft.Extensions.Logging.Abstractions.NullLogger<ProfileResolutionService>.Instance).ResolveLoaded(profile, null),
            issued[^1]));
    }
}
