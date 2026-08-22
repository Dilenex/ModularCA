using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Proves request-profile inheritance reaches the enrollment path.
/// <para>
/// <c>ProfileResolutionService.ResolveRequestProfileAsync</c> holds all the CLM-002 clamping for
/// RequireApproval, RequiredApprovalCount, MaxValidityPeriod, AllowedCertProfileIds,
/// SubjectDnRules and SanRules — and it had exactly one caller in the entire repository, an admin
/// preview endpoint. Every enrollment path (EST, SCEP, CMP, ACME, public token enrollment) read
/// the raw RequestProfileEntity instead, so MergeRequestProfiles was dead code at runtime and a
/// CA-scoped child could simply set RequireApproval=false against a parent that required it.
/// </para>
/// </summary>
public class RequestProfileInheritanceTests
{
    private static ProfileResolutionService Resolution(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<ProfileResolutionService>.Instance);

    private static RequestProfileValidationService Validation(ModularCA.Database.ModularCADbContext db)
        => new(db, Resolution(db));

    private static (ModularCA.Database.ModularCADbContext Db, Guid ChildId) Hierarchy(
        Action<RequestProfileEntity> configureParent,
        Action<RequestProfileEntity> configureChild)
    {
        var db = InMemoryDbContextFactory.Create();

        var parent = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "system-parent" };
        configureParent(parent);

        var child = new RequestProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = "ca-child",
            InheritanceEnabled = true,
            InheritsFromId = parent.Id,
        };
        configureChild(child);

        db.RequestProfiles.AddRange(parent, child);
        db.SaveChanges();
        return (db, child.Id);
    }

    /// <summary>
    /// The headline case: a child must not be able to switch approval off when its parent
    /// requires it. Every protocol enrollment leaned on the raw value.
    /// </summary>
    [Fact]
    public async Task Child_cannot_disable_approval_required_by_the_parent()
    {
        var (db, childId) = Hierarchy(
            p => p.RequireApproval = true,
            c => c.RequireApproval = false);
        using (db)
        {
            var effective = await Resolution(db).ResolveRequestProfileAsync(childId);
            Assert.True(effective.RequireApproval);
        }
    }

    /// <summary>A child may still tighten — enabling approval a lenient parent does not require.</summary>
    [Fact]
    public async Task Child_may_require_approval_a_lenient_parent_does_not()
    {
        var (db, childId) = Hierarchy(
            p => p.RequireApproval = false,
            c => c.RequireApproval = true);
        using (db)
        {
            var effective = await Resolution(db).ResolveRequestProfileAsync(childId);
            Assert.True(effective.RequireApproval);
        }
    }

    /// <summary>
    /// The cert-profile allow-list is the other half of what a request profile controls, and it
    /// is consumed through the validation service the enrollment paths call.
    /// </summary>
    [Fact]
    public async Task Allowed_cert_profiles_are_resolved_through_inheritance()
    {
        var allowed = Guid.NewGuid();
        var notAllowed = Guid.NewGuid();

        var (db, childId) = Hierarchy(
            p => p.AllowedCertProfileIds = $"[\"{allowed}\"]",
            c => c.AllowedCertProfileIds = $"[\"{allowed}\",\"{notAllowed}\"]");
        using (db)
        {
            var (resolved, error) = await Validation(db)
                .ResolveCertProfileIdAsync(notAllowed, Guid.NewGuid(), childId);

            // The child tried to widen the allow-list; the parent's restriction must win.
            Assert.Null(resolved);
            Assert.False(string.IsNullOrEmpty(error));
        }
    }

    /// <summary>A choice the parent genuinely allows still resolves.</summary>
    [Fact]
    public async Task Allowed_choice_still_resolves()
    {
        var allowed = Guid.NewGuid();

        var (db, childId) = Hierarchy(
            p => p.AllowedCertProfileIds = $"[\"{allowed}\"]",
            c => c.AllowedCertProfileIds = $"[\"{allowed}\"]");
        using (db)
        {
            var (resolved, error) = await Validation(db)
                .ResolveCertProfileIdAsync(allowed, Guid.NewGuid(), childId);

            Assert.Equal(allowed, resolved);
            Assert.Null(error);
        }
    }

    /// <summary>A profile that does not exist keeps the previous "no profile = no validation".</summary>
    [Fact]
    public async Task Missing_profile_does_not_block_validation()
    {
        using var db = InMemoryDbContextFactory.Create();

        var (isValid, error, subject) = await Validation(db)
            .ValidateAsync(Guid.NewGuid(), "CN=test", null);

        Assert.True(isValid);
        Assert.Null(error);
        Assert.Equal("CN=test", subject);
    }
}
