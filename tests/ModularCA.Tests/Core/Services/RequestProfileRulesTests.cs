using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Request profile rules are checked when saved and compared ignoring case when enforced. A rule
/// saved as "required" enforced nothing, a per-type SAN rule keyed "Email" was never found for an
/// EMAIL: name, and an unknown requirement, field or SAN type was stored without a word.
/// </summary>
public sealed class RequestProfileRulesTests
{
    [Fact]
    public void Normalize_rewrites_case_variants_in_the_stored_spelling()
    {
        var dn = new List<SubjectDnFieldRule>
        {
            new() { Field = "cn", Requirement = "required" },
            new() { Field = "emailAddress", Requirement = " FORBIDDEN " },
        };
        var san = new SanRules { AllowedTypes = ["dns", "EMAIL", "rfc822"], Rules = new() { ["email"] = new SanTypeRule { Regex = "@acme" } } };

        Assert.Null(RequestProfileRules.Normalize(dn, san));
        Assert.Equal(["CN", "E"], dn.Select(r => r.Field));
        Assert.Equal(["Required", "Forbidden"], dn.Select(r => r.Requirement));
        Assert.Equal(["DNS", "Email"], san.AllowedTypes);
        Assert.Equal(["Email"], san.Rules.Keys);
    }

    [Theory]
    [InlineData("Mandatory", "CN", "DNS", "requirement 'Mandatory' is not one of Required, Optional, Forbidden")]
    [InlineData("Required", "CNN", "DNS", "field 'CNN' is not one of CN, O, OU")]
    [InlineData("Required", "CN", "DSN", "'DSN' is not one of DNS, IP, Email, URI, UPN")]
    public void Normalize_names_a_bad_value_and_the_allowed_ones(string requirement, string field, string sanType, string message)
    {
        var dn = new List<SubjectDnFieldRule> { new() { Field = field, Requirement = requirement } };
        var san = new SanRules { AllowedTypes = [sanType] };
        Assert.Contains(message, RequestProfileRules.Normalize(dn, san));
        Assert.Equal(requirement, dn[0].Requirement);
    }

    [Fact]
    public void Normalize_refuses_a_san_type_ruled_twice_and_a_negative_count()
    {
        Assert.Contains("more than once", RequestProfileRules.Normalize(null,
            new SanRules { Rules = new() { ["DNS"] = new SanTypeRule(), ["dns"] = new SanTypeRule() } }));
        Assert.Contains("must not be negative", RequestProfileRules.Normalize(null,
            new SanRules { Rules = new() { ["DNS"] = new SanTypeRule { MaxCount = -1 } } }));
    }

    /// <summary>Rows already stored in the wrong case are enforced as written, not skipped.</summary>
    [Fact]
    public async Task Stored_rules_in_another_case_are_enforced()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = new RequestProfileEntity
        {
            Name = "legacy",
            SubjectDnRules = "[{\"Field\":\"O\",\"Requirement\":\"required\"},{\"Field\":\"OU\",\"Requirement\":\"forbidden\"}]",
            SanRules = "{\"AllowedTypes\":[\"DNS\",\"Email\"],\"Rules\":{\"Email\":{\"Regex\":\"@acme\\\\.test$\",\"MaxCount\":1}}}",
            AllowedCertProfileIds = "[]",
        };
        db.RequestProfiles.Add(profile);
        db.SaveChanges();
        var service = new RequestProfileValidationService(db, new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance));

        Assert.Contains("'O' is required", (await service.ValidateAsync(profile.Id, "CN=x", null)).Error);
        Assert.Contains("'OU' is not allowed", (await service.ValidateAsync(profile.Id, "CN=x,O=Acme,OU=y", null)).Error);
        Assert.Contains("does not match", (await service.ValidateAsync(profile.Id, "CN=x,O=Acme", "[\"EMAIL:a@evil.test\"]")).Error);
        Assert.Contains("Too many", (await service.ValidateAsync(profile.Id, "CN=x,O=Acme", "[\"EMAIL:a@acme.test\",\"Email:b@acme.test\"]")).Error);
        Assert.True((await service.ValidateAsync(profile.Id, "CN=x,O=Acme", "[\"EMAIL:a@acme.test\"]")).IsValid);
    }

    [Fact]
    public async Task Create_and_update_refuse_a_bad_rule_and_store_case_variants_canonically()
    {
        var w = new World();
        var user = w.Users["space admin"];
        CreateRequestProfileRequest Body(string requirement, params string[] sanTypes) => new()
        {
            Name = $"rp-{Guid.NewGuid():N}",
            CertificateAuthorityId = w.A.CaId,
            SubjectDnRules = [new() { Field = "cn", Requirement = requirement }],
            SanRules = new SanRules { AllowedTypes = sanTypes.ToList() },
        };
        Call Create(CreateRequestProfileRequest r) => Send("POST", "Admin.AdminRequestProfileController", "Create", "/api/v1/admin/request-profiles", ("request", r));

        var (status, body) = await SendAsync(w, user, Create(Body("Mandatory", "DNS")), skipPolicy: true);
        Assert.Equal(400, status);
        Assert.Contains("Required, Optional, Forbidden", body);
        Assert.Equal(400, (await SendAsync(w, user, Create(Body("Required", "DSN")), skipPolicy: true)).Status);

        var good = Body("required", "dns");
        Assert.Equal(201, (await SendAsync(w, user, Create(good), skipPolicy: true)).Status);
        var stored = w.Db.RequestProfiles.Single(p => p.Name == good.Name);
        Assert.Contains("\"Requirement\":\"Required\"", stored.SubjectDnRules);
        Assert.Contains("\"Field\":\"CN\"", stored.SubjectDnRules);
        Assert.Contains("[\"DNS\"]", stored.SanRules);

        var update = new UpdateRequestProfileRequest { Name = good.Name, CertificateAuthorityId = w.A.CaId, SubjectDnRules = [new() { Field = "CN", Requirement = "Sometimes" }] };
        var (updateStatus, _) = await SendAsync(w, user, Send("PUT", "Admin.AdminRequestProfileController", "Update", $"/api/v1/admin/request-profiles/{stored.Id}",
            ("id", stored.Id), ("request", update), ("mfaToken", w.StepUp(user, ModularCA.Shared.Enums.StepUpOps.UpdateRequestProfile, stored.Id))), skipPolicy: true);
        Assert.Equal(400, updateStatus);
    }

    [Fact]
    public async Task Policy_sync_refuses_a_bad_rule_and_stores_good_ones_canonically()
    {
        using var db = InMemoryDbContextFactory.Create();
        var sync = new PolicySyncService(db, NullLogger<PolicySyncService>.Instance);
        const string yaml = """
            profiles:
              - name: bad
                subjectDnRules: '[{"field":"CN","requirement":"Mandatory"}]'
              - name: good
                subjectDnRules: '[{"field":"cn","requirement":"required"}]'
                sanRules: '{"allowedTypes":["dns","email"]}'
            """;

        var result = await sync.SyncFromYamlAsync(yaml, "request");

        Assert.Equal(1, result.Created);
        Assert.Contains(result.Errors, e => e.Contains("'bad'") && e.Contains("Mandatory"));
        var good = Assert.Single(db.RequestProfiles);
        Assert.Contains("\"Requirement\":\"Required\"", good.SubjectDnRules);
        Assert.Contains("[\"DNS\",\"Email\"]", good.SanRules);

        Assert.Equal(1, (await sync.SyncFromYamlAsync(yaml, "request")).Unchanged);
    }
}
