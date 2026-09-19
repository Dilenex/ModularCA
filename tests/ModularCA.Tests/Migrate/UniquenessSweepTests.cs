using ModularCA.Migrate;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// The shape of the case-collision sweep, pinned by the four constraints that got it wrong.
/// <para>
/// The first version checked one column at a time. Run against a real 0.3.0 database it refused
/// the migration four times over — for four certificates sharing an issuer, three CRLs sharing an
/// issuer name, six protocol rows across several CAs, and two Kerberos keys of the same encryption
/// type. Every one of those is a composite key doing exactly what it is for, and the operator was
/// told to go and repair data that was never broken.
/// </para>
/// <para>
/// So the unit of the sweep is the whole key, and these tests assert that for the constraints that
/// exposed it.
/// </para>
/// </summary>
public class UniquenessSweepTests
{
    private static IReadOnlyList<ModelIntrospection.UniquenessCheck> Checks() =>
        ModelIntrospection.UniquenessChecks(ModelIntrospection.DestinationModel()).ToList();

    private static ModelIntrospection.UniquenessCheck For(string table, string foldingColumn) =>
        Assert.Single(Checks(), c => c.Table == table && c.FoldsCase.Contains(foldingColumn));

    [Theory]
    [InlineData("Certificates", "Issuer", "SerialNumber")]
    [InlineData("Crls", "IssuerName", "CrlNumber")]
    [InlineData("CaProtocolConfigs", "Protocol", "CaId")]
    [InlineData("KerberosRealmKeys", "EncryptionType", "RealmId")]
    public void A_folding_column_is_swept_with_the_rest_of_its_key(
        string table, string folding, string companion)
    {
        // The four from the live run. Each is unique only in combination, so a sweep that looks at
        // the folding column alone reports normal data as a collision.
        var check = For(table, folding);

        Assert.Contains(folding, check.Columns);
        Assert.Contains(companion, check.Columns);
        Assert.True(check.Columns.Count > 1,
            $"{table}.{folding} is part of a composite key and must be swept as one");
    }

    [Fact]
    public void A_single_column_key_is_still_swept_on_its_own()
    {
        // The other half: where the constraint really is one column, the whole key is that column,
        // and a duplicate really is a collision.
        var check = For("Users", "Username");

        Assert.Equal(["Username"], check.Columns);
        Assert.Equal(["Username"], check.FoldsCase);
    }

    [Fact]
    public void Constraints_that_cannot_fold_are_not_swept_at_all()
    {
        // A key of integers and identifiers cannot gain a collision from case, and sweeping it
        // would be a full table scan bought for nothing. Refresh tokens are the case-sensitive
        // text counterpart: deliberately exact, so equally not a candidate.
        var checks = Checks();

        Assert.DoesNotContain(checks, c => c.FoldsCase.Count == 0);
        Assert.DoesNotContain(checks, c => c.Table == "RefreshTokens");
    }

    [Fact]
    public void Every_swept_key_names_only_columns_that_fold_as_folding()
    {
        // FoldsCase drives whether a column is compared lowered or exactly, so a name that is not
        // in Columns would silently produce a query grouping on something else.
        foreach (var check in Checks())
        {
            Assert.NotEmpty(check.FoldsCase);
            foreach (var folding in check.FoldsCase)
                Assert.Contains(folding, check.Columns);
        }
    }

    [Fact]
    public void The_scheduler_lease_primary_key_is_swept()
    {
        // A text primary key is a uniqueness constraint declared through a different API, and the
        // sweep has to see it for the same reason the classification does.
        var check = For("SchedulerLeases", "Name");

        Assert.Equal(["Name"], check.Columns);
    }

    [Fact]
    public void The_supported_source_schema_is_the_sources_last_migration_not_the_destinations()
    {
        // The other half of the same live failure. InitialCreate is what 0.3.1 generates FOR
        // PostgreSQL; a 0.3.0 MariaDB database ends at the last of its thirty-odd migrations, and
        // comparing against the wrong one told a correct database to upgrade to the version it was
        // already on.
        Assert.StartsWith("20260918", Preflight.SupportedSourceMigration);
        Assert.EndsWith("LinkScepTransactionToRequest", Preflight.SupportedSourceMigration);
        Assert.DoesNotContain("InitialCreate", Preflight.SupportedSourceMigration);
    }

    [Fact]
    public void The_classification_and_the_sweep_agree_on_which_columns_fold()
    {
        // Two readings of TextCaseSensitivity: one that lists columns, one that groups them into
        // keys. Every folding column in a sweep must be one the registry actually named, or the
        // sweep is testing a rule the database does not have.
        var model = ModelIntrospection.DestinationModel();
        var classified = ModelIntrospection.CaseInsensitiveColumns(model)
            .Select(c => (c.Table, c.Column))
            .ToHashSet();

        foreach (var check in ModelIntrospection.UniquenessChecks(model))
            foreach (var folding in check.FoldsCase)
                Assert.Contains((check.Table, folding), classified);
    }

    [Fact]
    public void Entities_behind_the_four_live_failures_are_still_in_the_model()
    {
        // Guards the table-name literals above against a rename that would turn every assertion
        // into a silent pass.
        var model = ModelIntrospection.DestinationModel();

        Assert.NotNull(model.FindEntityType(typeof(CertificateEntity)));
        Assert.NotNull(model.FindEntityType(typeof(CrlEntity)));
        Assert.NotNull(model.FindEntityType(typeof(CaProtocolConfigEntity)));
        Assert.NotNull(model.FindEntityType(typeof(KerberosRealmKeyEntity)));
    }
}
