using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// What the review of 0.4.2-dev.1.10 found: approval held at issuance whatever the route, renewals
/// and reissues that keep the request profile and what it settled, a CA-scoped request profile that
/// cannot be looser than its parent, and infrastructure profiles judged after inheritance, guarded
/// on policy sync, and listed without naming CAs the caller cannot see.
/// </summary>
public sealed class ReviewFixTests
{
    private const string OcspSigning = "1.3.6.1.5.5.7.3.9";

    private static RequestProfileEnforcement Enforcement(ModularCADbContext db)
        => new(db, new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance));

    private static string Rules(params SubjectDnFieldRule[] rules) => JsonSerializer.Serialize(rules);

    private static List<SubjectDnFieldRule> ReadRules(string json)
        => JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(json, SafeJsonOptions.Stored)!;

    // ---- approval ---------------------------------------------------------------------------

    [Fact]
    public async Task A_request_under_a_profile_that_requires_approval_starts_pending_approval_and_is_not_issued_until_approved()
    {
        using var db = InMemoryDbContextFactory.Create();
        var gated = new RequestProfileEntity { Name = "Gated", RequireApproval = true, RequiredApprovalCount = 2 };
        var open = new RequestProfileEntity { Name = "Open" };
        db.RequestProfiles.AddRange(gated, open);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);

        Assert.Equal("PendingApproval", await enforcement.InitialStatusAsync(gated.Id));
        Assert.Equal("Pending", await enforcement.InitialStatusAsync(open.Id));
        Assert.Equal("Pending", await enforcement.InitialStatusAsync(null));
        Assert.Equal("Pending", await enforcement.InitialStatusAsync(Guid.NewGuid()));

        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(() =>
            enforcement.EnsureApprovedAsync(new CertRequestEntity { RequestProfileId = gated.Id, Status = "Pending" }));
        Assert.Equal(ErrorCodes.RequestProfileRefused, refused.Code);
        Assert.Contains("'Gated' requires approval", refused.Message);
        await Assert.ThrowsAsync<ConfigurationValidationException>(() =>
            enforcement.EnsureApprovedAsync(new CertRequestEntity { RequestProfileId = gated.Id, Status = "PartiallyApproved" }));

        await enforcement.EnsureApprovedAsync(new CertRequestEntity { RequestProfileId = gated.Id, Status = "Approved" });
        await enforcement.EnsureApprovedAsync(new CertRequestEntity { RequestProfileId = open.Id, Status = "Pending" });
        await enforcement.EnsureApprovedAsync(new CertRequestEntity { Status = "Pending" });
    }

    [Fact]
    public async Task A_child_that_turns_approval_off_still_requires_it_when_its_parent_does()
    {
        using var db = InMemoryDbContextFactory.Create();
        var parent = new RequestProfileEntity { Name = "Parent", RequireApproval = true };
        var child = new RequestProfileEntity { Name = "Child", RequireApproval = false, InheritsFromId = parent.Id, InheritanceEnabled = true };
        db.RequestProfiles.AddRange(parent, child);
        await db.SaveChangesAsync();

        Assert.Equal("PendingApproval", await Enforcement(db).InitialStatusAsync(child.Id));
    }

    // ---- renewals and reissues --------------------------------------------------------------

    [Fact]
    public void A_renewal_that_reuses_the_csr_carries_the_profile_and_what_it_settled()
    {
        var profileId = Guid.NewGuid();
        var original = new CertRequestEntity
        {
            RequestProfileId = profileId,
            SubjectOverrides = """{"O":"Acme"}""",
            SanOverrides = """[{"type":"DNS","value":"host.example.test"}]""",
            AdditionalExtensions = "[]",
        };

        var sameKey = new CertRequestEntity();
        CertificateRequestLineage.CarryForward(original, sameKey, reusesCsr: true);
        Assert.Equal(profileId, sameKey.RequestProfileId);
        Assert.Equal(original.SubjectOverrides, sameKey.SubjectOverrides);
        Assert.Equal(original.SanOverrides, sameKey.SanOverrides);
        Assert.Equal(original.AdditionalExtensions, sameKey.AdditionalExtensions);

        var newKey = new CertRequestEntity();
        CertificateRequestLineage.CarryForward(original, newKey, reusesCsr: false);
        Assert.Equal(profileId, newKey.RequestProfileId);
        Assert.Null(newKey.SubjectOverrides);
        Assert.Null(newKey.SanOverrides);

        var orphan = new CertRequestEntity();
        CertificateRequestLineage.CarryForward(null, orphan, reusesCsr: true);
        Assert.Null(orphan.RequestProfileId);
    }

    [Fact]
    public void The_request_a_certificate_came_from_is_the_original_and_not_an_old_reissue_link_row()
    {
        var certificateId = Guid.NewGuid();
        var profileId = Guid.NewGuid();
        var original = new CertRequestEntity { IssuedCertificateId = certificateId, RequestProfileId = profileId, SubmittedAt = new DateTime(2026, 9, 1) };
        var oldLinkRow = new CertRequestEntity { IssuedCertificateId = certificateId, SubmittedAt = new DateTime(2026, 8, 1) };
        var newLinkRow = new CertRequestEntity { IssuedCertificateId = certificateId, RequestProfileId = profileId, SubmittedAt = new DateTime(2026, 10, 1) };
        var other = new CertRequestEntity { IssuedCertificateId = Guid.NewGuid(), RequestProfileId = profileId, SubmittedAt = new DateTime(2026, 1, 1) };

        var rows = new[] { newLinkRow, oldLinkRow, other, original }.AsQueryable();

        Assert.Same(original, rows.ThatIssued(certificateId).First());
        Assert.Equal(3, rows.ThatIssued(certificateId).Count());
    }

    // ---- request profile inheritance --------------------------------------------------------

    [Fact]
    public void A_child_s_subject_rules_are_merged_with_the_parent_s_and_never_looser()
    {
        var parent = Rules(
            new SubjectDnFieldRule { Field = "CN", Requirement = "Required", Regex = "^[a-z.]+$", MaxLength = 64 },
            new SubjectDnFieldRule { Field = "O", Requirement = "Required", FixedValue = "Acme" },
            new SubjectDnFieldRule { Field = "OU", Requirement = "Forbidden" });
        var child = Rules(
            new SubjectDnFieldRule { Field = "CN", Requirement = "Optional", Regex = ".*", MaxLength = 32 },
            new SubjectDnFieldRule { Field = "o", Requirement = "Optional", FixedValue = "Evil" },
            new SubjectDnFieldRule { Field = "L", Requirement = "Required", DefaultValue = "Bonn" });

        var merged = ReadRules(RequestProfileInheritance.MergeSubjectRules(child, parent));

        var cn = merged.Single(r => r.Field == "CN");
        Assert.Equal("Required", cn.Requirement);
        Assert.Equal("^[a-z.]+$", cn.Regex);
        Assert.Equal(32, cn.MaxLength);
        Assert.Equal("Acme", merged.Single(r => r.Field == "O").FixedValue);
        Assert.Equal("Forbidden", merged.Single(r => r.Field == "OU").Requirement);
        Assert.Equal("Required", merged.Single(r => r.Field == "L").Requirement);

        Assert.Equal(parent, RequestProfileInheritance.MergeSubjectRules("[]", parent));
        Assert.Equal(child, RequestProfileInheritance.MergeSubjectRules(child, "[]"));
    }

    [Fact]
    public void A_child_s_san_rules_allow_only_what_both_allow_and_the_console_s_default_does_not_drop_the_parent_s()
    {
        var parent = JsonSerializer.Serialize(new
        {
            allowedTypes = new[] { "Email" },
            required = true,
            rules = new Dictionary<string, object> { ["Email"] = new { regex = (string?)null, maxCount = 3 } },
        });
        var consoleDefault = JsonSerializer.Serialize(new SanRules());

        var merged = RequestProfileValidationService.ReadSanRules(RequestProfileInheritance.MergeSanRules(consoleDefault, parent))!;
        Assert.Empty(merged.AllowedTypes);
        Assert.True(merged.Required);

        var child = JsonSerializer.Serialize(new SanRules
        {
            AllowedTypes = ["RFC822", "DNS"],
            Rules = new() { ["Email"] = new SanTypeRule { MaxCount = 1, Regex = "@acme\\.test$" } },
        });
        merged = RequestProfileValidationService.ReadSanRules(RequestProfileInheritance.MergeSanRules(child, parent))!;
        Assert.Equal(["Email"], merged.AllowedTypes);
        Assert.True(merged.Required);
        Assert.True(RequestProfileRules.TryGetSanRule(merged, "Email", out var email));
        Assert.Equal(1, email.MaxCount);
        Assert.Equal("@acme\\.test$", email.Regex);

        Assert.Equal(parent, RequestProfileInheritance.MergeSanRules("{}", parent));
    }

    [Fact]
    public async Task A_child_s_default_certificate_profile_must_be_one_the_parent_designates()
    {
        using var db = InMemoryDbContextFactory.Create();
        var allowed = Guid.NewGuid();
        var elsewhere = Guid.NewGuid();
        var parent = new RequestProfileEntity { Name = "Parent", DefaultCertProfileId = allowed };
        var loose = new RequestProfileEntity { Name = "Loose", DefaultCertProfileId = elsewhere, InheritsFromId = parent.Id, InheritanceEnabled = true };
        var fine = new RequestProfileEntity { Name = "Fine", DefaultCertProfileId = allowed, InheritsFromId = parent.Id, InheritanceEnabled = true };
        db.RequestProfiles.AddRange(parent, loose, fine);
        await db.SaveChangesAsync();
        var resolver = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);

        Assert.Equal(allowed, (await resolver.ResolveRequestProfileAsync(loose.Id)).DefaultCertProfileId);
        Assert.Equal(allowed, (await resolver.ResolveRequestProfileAsync(fine.Id)).DefaultCertProfileId);
    }

    // ---- infrastructure profiles ------------------------------------------------------------

    private static CertProfileEntity Profile(string name, string ekus = "[]", Guid? inheritsFrom = null) => new()
    {
        Name = name,
        KeyUsages = "[\"Digital Signature\"]",
        ExtendedKeyUsages = ekus,
        AllowedKeySizes = "[]",
        AllowedSignatureAlgorithms = "[]",
        InheritsFromId = inheritsFrom,
        InheritanceEnabled = inheritsFrom != null,
    };

    private static UpdateCertProfileRequest RequestFor(CertProfileEntity p) => new()
    {
        Name = p.Name,
        Description = p.Description,
        IsCaProfile = p.IsCaProfile,
        KeyUsages = p.KeyUsages,
        ExtendedKeyUsages = p.ExtendedKeyUsages,
        AllowedKeyAlgorithms = p.AllowedKeyAlgorithms,
        AllowedKeySizes = p.AllowedKeySizes,
        AllowedSignatureAlgorithms = p.AllowedSignatureAlgorithms,
        CertificateAuthorityId = p.CertificateAuthorityId,
        InheritsFromId = p.InheritsFromId,
        InheritanceEnabled = p.InheritanceEnabled,
    };

    [Fact]
    public void A_profile_is_judged_by_the_usages_it_has_after_inheritance()
    {
        var serverOnly = Profile("Server only", "[\"1.3.6.1.5.5.7.3.1\"]");
        var child = Profile("Responder", $"[\"{OcspSigning}\"]", inheritsFrom: serverOnly.Id);

        Assert.Null(InfrastructureCertProfiles.WhyUnsuitable(child, InfrastructureCertProfiles.OcspResponder));
        Assert.Contains("OCSP signing", InfrastructureCertProfiles.WhyUnsuitable(child, InfrastructureCertProfiles.OcspResponder, serverOnly));
    }

    [Fact]
    public async Task A_profile_cannot_start_inheriting_or_strip_a_parent_so_that_a_ca_s_responder_loses_its_usage()
    {
        using var db = InMemoryDbContextFactory.Create();
        var serverOnly = Profile("Server only", "[\"1.3.6.1.5.5.7.3.1\"]");
        var responder = Profile("Responder", $"[\"{OcspSigning}\"]");
        db.CertProfiles.AddRange(serverOnly, responder);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Name = "Issuing CA", OcspResponderCertProfileId = responder.Id });
        await db.SaveChangesAsync();
        var service = new CertProfileService(db);

        var inheriting = RequestFor(responder);
        inheriting.InheritsFromId = serverOnly.Id;
        inheriting.InheritanceEnabled = true;
        var refused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(responder.Id, inheriting));
        Assert.Contains("Issuing CA issues its OCSP Responder certificate from it", refused.Message);

        var parent = Profile("Parent", $"[\"{OcspSigning}\",\"1.3.6.1.5.5.7.3.1\"]");
        var child = Profile("Child responder", $"[\"{OcspSigning}\"]", inheritsFrom: parent.Id);
        db.CertProfiles.AddRange(parent, child);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Name = "Second CA", OcspResponderCertProfileId = child.Id });
        await db.SaveChangesAsync();
        var stripped = RequestFor(parent);
        stripped.ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.1\"]";
        refused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.UpdateAsync(parent.Id, stripped));
        Assert.Contains("inherits its usages from 'Parent'", refused.Message);
        Assert.Contains("Second CA", refused.Message);
    }

    [Fact]
    public async Task Policy_sync_does_not_strip_a_usage_or_change_the_kind_of_a_name_bound_profile()
    {
        using var db = InMemoryDbContextFactory.Create();
        var tsa = Profile(SystemCertProfiles.Tsa, "[\"1.3.6.1.5.5.7.3.8\"]");
        db.CertProfiles.Add(tsa);
        await db.SaveChangesAsync();
        var sync = new PolicySyncService(db, NullLogger<PolicySyncService>.Instance);

        var result = await sync.SyncFromYamlAsync($"""
            profiles:
              - name: {SystemCertProfiles.Tsa}
                keyUsages: '["Digital Signature"]'
                extendedKeyUsages: '[]'
            """, "cert");
        Assert.Equal(0, result.Updated);
        Assert.Contains(result.Errors, e => e.Contains("was not updated") && e.Contains("time stamping"));

        result = await sync.SyncFromYamlAsync($"""
            profiles:
              - name: {SystemCertProfiles.Tsa}
                isCaProfile: true
                keyUsages: '["Key Certificate Signing"]'
                extendedKeyUsages: '["1.3.6.1.5.5.7.3.8"]'
            """, "cert");
        Assert.Equal(0, result.Updated);
        Assert.Contains(result.Errors, e => e.Contains("cannot change between a CA and an end-entity profile"));

        var stored = await db.CertProfiles.FindAsync(tsa.Id);
        Assert.False(stored!.IsCaProfile);
        Assert.Contains("1.3.6.1.5.5.7.3.8", stored.ExtendedKeyUsages);
    }

    [Fact]
    public async Task A_profile_s_uses_by_cas_the_caller_cannot_see_are_counted_not_named()
    {
        using var db = InMemoryDbContextFactory.Create();
        var shared = Profile("Shared responder", $"[\"{OcspSigning}\"]");
        var mine = Guid.NewGuid();
        var theirs = Guid.NewGuid();
        db.CertProfiles.Add(shared);
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Name = "My CA", SpaceId = mine, OcspResponderCertProfileId = shared.Id },
            new CertificateAuthorityEntity { Name = "Payroll Issuing", SpaceId = theirs, OcspResponderCertProfileId = shared.Id, TsaCertProfileId = shared.Id });
        await db.SaveChangesAsync();
        var service = new CertProfileService(db);

        var uses = (await service.GetByIdAsync(shared.Id, space => space == mine))!.InfrastructureUses;
        Assert.Equal(["My CA: OCSP Responder", "2 uses by CAs outside your scope"], uses);
        Assert.DoesNotContain(uses, u => u.Contains("Payroll"));

        Assert.Equal(3, (await service.GetByIdAsync(shared.Id))!.InfrastructureUses.Count);
        Assert.Contains("2 uses by CAs outside your scope", (await service.GetAllAsync(space => space == mine)).Single().InfrastructureUses);
    }
}
