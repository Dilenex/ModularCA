using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the "stricter only" guarantee of cert-profile inheritance on the path issuance
/// actually uses.
/// <para>
/// <c>ValidateCertProfileInheritanceAsync</c> already checked the subset rule, but it is only
/// reachable from an admin preview endpoint — issuance calls <c>ResolveCertProfileAsync</c>, and
/// that path had three ways to end up less restrictive than the parent: KeyUsages and
/// ExtendedKeyUsages bypassed the clamp entirely, the IsCaProfile clamp was inverted in both
/// directions, and clamping a fully-disjoint list produced an empty one, which every consumer
/// reads as "no restriction configured" rather than "nothing permitted".
/// </para>
/// </summary>
public class CertProfileInheritanceTests
{
    private static ProfileResolutionService Service(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<ProfileResolutionService>.Instance);

    /// <summary>Wires a child profile to a parent with inheritance enabled.</summary>
    private static (ModularCA.Database.ModularCADbContext Db, Guid ChildId) Hierarchy(
        Action<CertProfileEntity> configureParent,
        Action<CertProfileEntity> configureChild)
    {
        var db = InMemoryDbContextFactory.Create();

        var parent = new CertProfileEntity { Id = Guid.NewGuid(), Name = "system-parent" };
        configureParent(parent);

        var child = new CertProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = "ca-child",
            InheritanceEnabled = true,
            InheritsFromId = parent.Id,
        };
        configureChild(child);

        db.CertProfiles.AddRange(parent, child);
        db.SaveChanges();
        return (db, child.Id);
    }

    // ── IsCaProfile ──────────────────────────────────────────────────────────

    /// <summary>
    /// The escalation the clamp missed entirely: a leaf-only parent must not allow a child to
    /// declare itself a CA profile, which would have CertificateBuilderService emit
    /// basicConstraints cA=TRUE plus keyCertSign|cRLSign.
    /// </summary>
    [Fact]
    public async Task Child_cannot_become_a_CA_profile_under_a_leaf_parent()
    {
        var (db, childId) = Hierarchy(
            p => p.IsCaProfile = false,
            c => c.IsCaProfile = true);
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.False(effective.IsCaProfile);
        }
    }

    /// <summary>
    /// The other half, and why this was inverted rather than merely missing: narrowing a CA
    /// profile to a leaf profile is exactly what the inheritance model is for. The old clamp
    /// forced it back to true, silently turning a leaf-issuing profile into one that stamps
    /// cA=TRUE.
    /// </summary>
    [Fact]
    public async Task Child_may_narrow_a_CA_parent_to_a_leaf_profile()
    {
        var (db, childId) = Hierarchy(
            p => p.IsCaProfile = true,
            c => c.IsCaProfile = false);
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.False(effective.IsCaProfile);
        }
    }

    // ── KeyUsages / ExtendedKeyUsages ────────────────────────────────────────

    /// <summary>A child must not add an EKU the parent never permitted.</summary>
    [Fact]
    public async Task Child_cannot_widen_extended_key_usages()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"serverAuth\"]",
            c => c.ExtendedKeyUsages = "[\"serverAuth\",\"codeSigning\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"serverAuth\"]", effective.ExtendedKeyUsages);
        }
    }

    /// <summary>
    /// The same for KeyUsage bits — this is the one that decides whether a certificate can sign
    /// other certificates.
    /// </summary>
    [Fact]
    public async Task Child_cannot_widen_key_usages()
    {
        var (db, childId) = Hierarchy(
            p => p.KeyUsages = "[\"digitalSignature\"]",
            c => c.KeyUsages = "[\"digitalSignature\",\"keyCertSign\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"digitalSignature\"]", effective.KeyUsages);
        }
    }

    /// <summary>Narrowing still works — a child may drop usages the parent allows.</summary>
    [Fact]
    public async Task Child_may_narrow_extended_key_usages()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"serverAuth\",\"clientAuth\"]",
            c => c.ExtendedKeyUsages = "[\"clientAuth\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"clientAuth\"]", effective.ExtendedKeyUsages);
        }
    }

    /// <summary>An empty child list still inherits the parent's, which is the merge semantics.</summary>
    [Fact]
    public async Task Empty_child_list_inherits_the_parent_list()
    {
        var (db, childId) = Hierarchy(
            p => p.ExtendedKeyUsages = "[\"serverAuth\"]",
            c => c.ExtendedKeyUsages = "[]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"serverAuth\"]", effective.ExtendedKeyUsages);
        }
    }

    // ── Disjoint clamp ───────────────────────────────────────────────────────

    /// <summary>
    /// The subtlest of the three. Parent allows only 4096, child asks for only 2048, so the
    /// intersection is empty — and an empty list is read downstream as "no restriction"
    /// (IssuanceValidationService gates on <c>validKeySizes?.Count &gt; 0</c>). The clamp
    /// therefore turned a restriction into its opposite, permitting key sizes neither profile
    /// ever listed. The effective value must fall back to the parent's list.
    /// </summary>
    [Fact]
    public async Task Disjoint_child_list_falls_back_to_the_parent_not_to_empty()
    {
        var (db, childId) = Hierarchy(
            p => p.AllowedKeySizes = "[\"4096\"]",
            c => c.AllowedKeySizes = "[\"2048\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);

            Assert.Equal("[\"4096\"]", effective.AllowedKeySizes);
            Assert.DoesNotContain("2048", effective.AllowedKeySizes);
        }
    }

    /// <summary>Same failure shape on the algorithm list.</summary>
    [Fact]
    public async Task Disjoint_algorithm_list_falls_back_to_the_parent()
    {
        var (db, childId) = Hierarchy(
            p => p.AllowedKeyAlgorithms = "[\"ECDSA\"]",
            c => c.AllowedKeyAlgorithms = "[\"RSA\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"ECDSA\"]", effective.AllowedKeyAlgorithms);
        }
    }

    /// <summary>A parent with no restriction still imposes none — the clamp is not a floor.</summary>
    [Fact]
    public async Task Unrestricted_parent_leaves_the_child_list_alone()
    {
        var (db, childId) = Hierarchy(
            p => p.AllowedKeySizes = "[]",
            c => c.AllowedKeySizes = "[\"2048\"]");
        using (db)
        {
            var effective = await Service(db).ResolveCertProfileAsync(childId);
            Assert.Equal("[\"2048\"]", effective.AllowedKeySizes);
        }
    }
}
