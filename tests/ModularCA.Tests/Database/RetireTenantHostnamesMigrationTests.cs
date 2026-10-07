using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The 0.4.0 S2 migration refuses while a tenant hostname remains, naming how many, before it
/// drops anything, and drops only the <c>TenantHostnames</c> table.
/// </summary>
public class RetireTenantHostnamesMigrationTests
{
    private static (string Id, Migration Migration) Load()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var assembly = db.GetService<IMigrationsAssembly>();
        var (id, type) = Assert.Single(assembly.Migrations, m => m.Key.EndsWith("_RetireTenantHostnames", StringComparison.Ordinal));
        return (id, assembly.CreateMigration(type, db.Database.ProviderName!));
    }

    [Fact]
    public void Up_starts_with_the_precondition_and_then_drops_only_the_table()
    {
        var (_, migration) = Load();
        var up = migration.UpOperations;

        Assert.Equal(2, up.Count);
        var precondition = Assert.IsType<SqlOperation>(up[0]);
        Assert.Equal(
            MigrationPreconditions.BuildSql(
                "EXISTS (SELECT 1 FROM \"TenantHostnames\")",
                "This instance has {0} tenant hostname(s), which 0.4.0 no longer serves. Before upgrading, remove them "
                + "with a 0.3.x or 0.4.0-S1 build, or move those names to the instance's public domain or to a reverse proxy.",
                "(SELECT count(*) FROM \"TenantHostnames\")"),
            precondition.Sql);
        Assert.StartsWith("DO $$ BEGIN IF (EXISTS (SELECT 1 FROM \"TenantHostnames\")) THEN RAISE EXCEPTION USING MESSAGE = "
            + "concat('This instance has ', ((SELECT count(*) FROM \"TenantHostnames\"))::text, ' tenant hostname(s)", precondition.Sql);
        Assert.EndsWith("reverse proxy.'); END IF; END $$;", precondition.Sql);
        Assert.False(precondition.SuppressTransaction);

        var drop = Assert.IsType<DropTableOperation>(up[1]);
        Assert.Equal("TenantHostnames", drop.Name);
    }

    [Fact]
    public void Down_recreates_the_table_empty()
    {
        var (_, migration) = Load();
        var create = Assert.IsType<CreateTableOperation>(migration.DownOperations[0]);
        Assert.Equal("TenantHostnames", create.Name);
        Assert.Contains(create.Columns, c => c.Name == "NodeUpstream");
        Assert.DoesNotContain(migration.DownOperations, o => o is SqlOperation or InsertDataOperation);
    }

    [Fact]
    public void It_is_the_first_migration_after_the_frozen_baseline()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var ids = db.GetService<IMigrationsAssembly>().Migrations.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.Equal("20260919181506_InitialCreate", ids[0]);
        Assert.EndsWith("_RetireTenantHostnames", ids[1]);
    }

    [Fact]
    public void A_precondition_message_can_name_values_the_database_computes()
    {
        var sql = MigrationPreconditions.BuildSql("true", "{1} of {0}; 100% sure it's {1}", "a", "(SELECT 2)");
        Assert.Equal("DO $$ BEGIN IF (true) THEN RAISE EXCEPTION USING MESSAGE = "
            + "concat(((SELECT 2))::text, ' of ', (a)::text, '; 100% sure it''s ', ((SELECT 2))::text); END IF; END $$;", sql);

        Assert.Equal("DO $$ BEGIN IF (true) THEN RAISE EXCEPTION USING MESSAGE = concat('%', ((SELECT 5))::text, '% of rows'); END IF; END $$;",
            MigrationPreconditions.BuildSql("true", "%{0}% of rows", "(SELECT 5)"));
        Assert.Equal("DO $$ BEGIN IF (true) THEN RAISE EXCEPTION USING MESSAGE = concat((a)::text, '%', (b)::text); END IF; END $$;",
            MigrationPreconditions.BuildSql("true", "{0}%{1}", "a", "b"));
        Assert.Equal("DO $$ BEGIN IF (true) THEN RAISE EXCEPTION 'Tenant''s 100%% done'; END IF; END $$;",
            MigrationPreconditions.BuildSql("true", "Tenant's 100% done"));

        Assert.Throws<ArgumentException>(() => MigrationPreconditions.BuildSql("true", "{0} and {1}", "a"));
        Assert.Throws<ArgumentException>(() => MigrationPreconditions.BuildSql("true", "{0}", "$$"));
    }
}
