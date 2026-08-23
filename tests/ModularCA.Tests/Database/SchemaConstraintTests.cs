using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Pins schema decisions that are invisible at runtime until the day they matter.
/// <para>
/// These assert against EF's model metadata rather than a live database, so they run in the unit
/// suite and fail the moment someone changes an index or a delete behaviour — which is the point.
/// A cascade rule is not something you notice in review or in normal use; you notice it when a
/// delete takes six years of CRL history with it.
/// </para>
/// </summary>
public class SchemaConstraintTests
{
    private static IModel Model()
    {
        using var db = InMemoryDbContextFactory.Create();
        return db.Model;
    }

    private static IEntityType Entity<T>() => Model().FindEntityType(typeof(T))
        ?? throw new InvalidOperationException($"{typeof(T).Name} is not in the model");

    private static IEnumerable<string[]> UniqueIndexes<T>() =>
        Entity<T>().GetIndexes()
            .Where(i => i.IsUnique)
            .Select(i => i.Properties.Select(p => p.Name).ToArray());

    private static bool HasUniqueIndexOver<T>(params string[] columns) =>
        UniqueIndexes<T>().Any(cols => cols.SequenceEqual(columns));

    // ── Serial numbers are unique per issuer, not globally ─────────────────────

    [Fact]
    public void TrustAnchor_serials_are_unique_per_issuer()
    {
        // A serial is only unique within the CA that assigned it — X.509 makes no cross-issuer
        // guarantee, and a self-signed root is very often serial 1. A global unique index meant
        // importing two unrelated roots failed with a constraint violation that reads like a
        // duplicate import.
        Assert.True(HasUniqueIndexOver<TrustAnchorEntity>(nameof(TrustAnchorEntity.SerialNumber), nameof(TrustAnchorEntity.Issuer)),
            "TrustAnchors must be unique over (SerialNumber, Issuer)");

        Assert.False(HasUniqueIndexOver<TrustAnchorEntity>(nameof(TrustAnchorEntity.SerialNumber)),
            "a globally unique SerialNumber index must not exist — that is the defect");
    }

    [Fact]
    public void Certificates_already_scoped_serials_to_the_issuer()
    {
        // The sibling that got it right. Asserted so the two cannot drift apart again.
        Assert.True(HasUniqueIndexOver<CertificateEntity>(nameof(CertificateEntity.SerialNumber), nameof(CertificateEntity.Issuer)));
    }

    // ── CRL history is not collateral damage ───────────────────────────────────

    [Fact]
    public void Deleting_a_ca_certificate_cannot_cascade_into_crl_history()
    {
        // Both of these were Cascade by EF convention (required FK, no explicit configuration).
        // Deleting one CA certificate removed its CrlConfigurations, which removed every Crl
        // generated under them — and CrlConfiguration carries LastCrlNumber, so recreating it
        // restarts a counter RFC 5280 §5.2.3 requires to increase monotonically.
        var configToCert = Entity<CrlConfigurationEntity>().GetForeignKeys()
            .Single(fk => fk.PrincipalEntityType.ClrType == typeof(CertificateEntity));
        Assert.Equal(DeleteBehavior.Restrict, configToCert.DeleteBehavior);

        var crlToConfig = Entity<CrlEntity>().GetForeignKeys()
            .Single(fk => fk.PrincipalEntityType.ClrType == typeof(CrlConfigurationEntity));
        Assert.Equal(DeleteBehavior.Restrict, crlToConfig.DeleteBehavior);
    }

    // ── Tenant scoping ─────────────────────────────────────────────────────────

    [Fact]
    public void Ca_names_and_labels_are_both_scoped_to_the_tenant()
    {
        // Label was already composite; Name beside it was left global, so two tenants could each
        // have an "issuing-ca" label but not both name a CA "Issuing CA". A global unique name is
        // also a cross-tenant oracle: you learn a name is taken by failing to take it.
        Assert.True(HasUniqueIndexOver<CertificateAuthorityEntity>(nameof(CertificateAuthorityEntity.TenantId), nameof(CertificateAuthorityEntity.Name)));
        Assert.True(HasUniqueIndexOver<CertificateAuthorityEntity>(nameof(CertificateAuthorityEntity.TenantId), nameof(CertificateAuthorityEntity.Label)));

        Assert.False(HasUniqueIndexOver<CertificateAuthorityEntity>(nameof(CertificateAuthorityEntity.Name)),
            "a globally unique CA Name index must not exist");
    }

    [Fact]
    public void Profiles_groups_and_roles_are_still_globally_unique_on_purpose()
    {
        // These three carry a TenantId and "should" be per-tenant, but the CODE resolves them by
        // bare name — CaCreationService looks up "Main CA Certificate Profile", bootstrap looks
        // up "system-super", RoleAssignmentHelper looks up a role template. The unique index is
        // what makes those lookups deterministic.
        //
        // This test exists so relaxing the index is a deliberate act with a failing test attached,
        // not a tidy-up. Doing it without first making those lookups tenant-aware would trade an
        // inconvenience for a cross-tenant resolution bug. If you are here because this test
        // failed: fix the lookups, then change this.
        Assert.True(HasUniqueIndexOver<CertProfileEntity>(nameof(CertProfileEntity.Name)));
        Assert.True(HasUniqueIndexOver<CaGroupEntity>(nameof(CaGroupEntity.Name)));
        Assert.True(HasUniqueIndexOver<RoleEntity>(nameof(RoleEntity.Name)));
    }
}
