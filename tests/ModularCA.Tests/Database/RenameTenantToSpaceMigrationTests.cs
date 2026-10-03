using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using ModularCA.Database.Migrations;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The shape of the 0.4.0 S6 migration, checked without a database: it renames in place and
/// copies nothing. Only rename operations and SQL, never a drop or a create; the primary key,
/// check constraints and foreign keys renamed with <c>RENAME CONSTRAINT</c>; the stored-JSON
/// precondition first; the data steps after the renames; a post-check last; no suppressed
/// transaction, and no way back. The PostgreSQL harness runs it for real.
/// </summary>
public class RenameTenantToSpaceMigrationTests
{
    private static Migration Migration()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var assembly = db.GetService<IMigrationsAssembly>();
        var (_, type) = assembly.Migrations.Single(m => m.Key.EndsWith("_RenameTenantToSpace", StringComparison.Ordinal));
        return assembly.CreateMigration(type, db.Database.ProviderName!);
    }

    private static List<string> Sql(IEnumerable<MigrationOperation> ops) => ops.OfType<SqlOperation>().Select(s => s.Sql).ToList();

    [Fact]
    public void It_contains_only_renames_and_sql()
    {
        var ops = Migration().UpOperations.ToList();
        Assert.All(ops, o => Assert.True(
            o is RenameTableOperation or RenameColumnOperation or RenameIndexOperation or SqlOperation,
            $"{o.GetType().Name} is neither a rename nor SQL."));
        Assert.DoesNotContain(ops, o => o is SqlOperation { SuppressTransaction: true });
        Assert.All(Sql(ops), sql => Assert.DoesNotMatch(@"(?i)\b(DROP|CREATE|TRUNCATE|DELETE|INSERT)\b",
            System.Text.RegularExpressions.Regex.Replace(sql, "'(?:[^']|'')*'", "''")));
    }

    [Fact]
    public void It_renames_the_table_the_eleven_columns_and_their_indexes()
    {
        var ops = Migration().UpOperations.ToList();

        var table = Assert.Single(ops.OfType<RenameTableOperation>());
        Assert.Equal(("Tenants", "Spaces"), (table.Name, table.NewName));

        var columns = ops.OfType<RenameColumnOperation>().Select(c => $"{c.Table}.{c.Name}>{c.NewName}").Order(StringComparer.Ordinal).ToList();
        Assert.Equal(new[]
        {
            "CaGroups.TenantId>SpaceId", "CertProfiles.TenantId>SpaceId", "CertificateAuthorities.TenantId>SpaceId",
            "EnrollmentTokens.TenantId>SpaceId", "KerberosRealms.TenantId>SpaceId", "KeyCeremonies.TenantId>SpaceId",
            "RoleAssignments.TenantId>SpaceId", "Roles.TenantId>SpaceId", "SignerAudit.TenantId>SpaceId",
            "UserCapabilityGrants.TenantId>SpaceId", "Users.ServiceScopeTenantId>ServiceScopeSpaceId",
        }.Order(StringComparer.Ordinal), columns);

        var indexes = ops.OfType<RenameIndexOperation>().Select(i => $"{i.Name}>{i.NewName}").Order(StringComparer.Ordinal).ToList();
        Assert.Equal(new[]
        {
            "IX_CaGroups_TenantId>IX_CaGroups_SpaceId",
            "IX_CertProfiles_TenantId>IX_CertProfiles_SpaceId",
            "IX_CertificateAuthorities_TenantId>IX_CertificateAuthorities_SpaceId",
            "IX_KerberosRealms_TenantId>IX_KerberosRealms_SpaceId",
            "IX_RoleAssignments_TenantId_CertificateAuthorityId>IX_RoleAssignments_SpaceId_CertificateAuthorityId",
            "IX_Roles_TenantId>IX_Roles_SpaceId",
            "IX_Tenants_IsDeleted>IX_Spaces_IsDeleted",
            "IX_Tenants_Name>IX_Spaces_Name",
            "IX_Tenants_Slug>IX_Spaces_Slug",
            "IX_UserCapabilityGrants_TenantId_CertificateAuthorityId>IX_UserCapabilityGrants_SpaceId_CertificateAuthorityId",
            "IX_Users_ServiceScopeTenantId>IX_Users_ServiceScopeSpaceId",
        }.Order(StringComparer.Ordinal), indexes);
    }

    [Fact]
    public void The_key_constraints_are_renamed_in_place()
    {
        var sql = Sql(Migration().UpOperations);
        var renames = sql.Where(s => s.StartsWith("ALTER TABLE", StringComparison.Ordinal) && s.Contains("RENAME CONSTRAINT")).ToList();
        Assert.Single(sql, s => s.StartsWith("DO $$", StringComparison.Ordinal) && s.Contains("contype = 'n' AND left(conname, 8) = 'Tenants_'"));
        Assert.Equal(
        [
            """ALTER TABLE "Spaces" RENAME CONSTRAINT "PK_Tenants" TO "PK_Spaces";""",
            """ALTER TABLE "Spaces" RENAME CONSTRAINT "CK_Tenants_Name_Length" TO "CK_Spaces_Name_Length";""",
            """ALTER TABLE "Spaces" RENAME CONSTRAINT "CK_Tenants_Slug_Length" TO "CK_Spaces_Slug_Length";""",
            """ALTER TABLE "CertificateAuthorities" RENAME CONSTRAINT "FK_CertificateAuthorities_Tenants_TenantId" TO "FK_CertificateAuthorities_Spaces_SpaceId";""",
            """ALTER TABLE "KerberosRealms" RENAME CONSTRAINT "FK_KerberosRealms_Tenants_TenantId" TO "FK_KerberosRealms_Spaces_SpaceId";""",
            """ALTER TABLE "RoleAssignments" RENAME CONSTRAINT "FK_RoleAssignments_Tenants_TenantId" TO "FK_RoleAssignments_Spaces_SpaceId";""",
            """ALTER TABLE "Roles" RENAME CONSTRAINT "FK_Roles_Tenants_TenantId" TO "FK_Roles_Spaces_SpaceId";""",
            """ALTER TABLE "UserCapabilityGrants" RENAME CONSTRAINT "FK_UserCapabilityGrants_Tenants_TenantId" TO "FK_UserCapabilityGrants_Spaces_SpaceId";""",
        ], renames);
    }

    [Fact]
    public void The_json_precondition_comes_first_and_the_data_steps_follow_the_renames()
    {
        var ops = Migration().UpOperations.ToList();

        var p1 = Assert.IsType<SqlOperation>(ops[0]).Sql;
        Assert.StartsWith("DO $$", p1);
        Assert.Contains("j := t::jsonb;", p1);
        Assert.Contains("EXCEPTION WHEN data_exception", p1);
        Assert.Contains("jsonb_typeof(j) <> 'object'", p1);
        Assert.Contains("RAISE EXCEPTION", p1);

        var lastRename = ops.FindLastIndex(o => o is RenameTableOperation or RenameColumnOperation or RenameIndexOperation
            || (o is SqlOperation s && s.Sql.Contains("RENAME CONSTRAINT")));
        var p2 = ops.FindIndex(o => o is SqlOperation s && s.Sql.Contains("space-<slug>-*"));
        var nul = ops.FindIndex(o => o is SqlOperation s && s.Sql.Contains("""UPDATE "KeyCeremonies" SET "ParametersJson" = regexp_replace("""));
        var keys = ops.FindIndex(o => o is SqlOperation s && s.Sql.Contains("jsonb_object_agg"));
        var operation = ops.FindIndex(o => o is SqlOperation s && s.Sql.Contains("""SET "OperationType" = 'SpacePolicyChange' WHERE "OperationType" = 'TenantPolicyChange'"""));
        var groups = ops.FindIndex(o => o is SqlOperation s && s.Sql.StartsWith("""UPDATE "CaGroups" g SET "Name" = r.new_name""", StringComparison.Ordinal));
        Assert.True(lastRename < p2 && p2 < nul && nul == keys - 1 && keys < operation && operation < groups && groups == ops.Count - 2,
            $"order: renames end {lastRename}, P2 {p2}, NUL {nul}, keys {keys}, operation type {operation}, groups {groups}, count {ops.Count}");

        var post = Assert.IsType<SqlOperation>(ops[^1]).Sql;
        Assert.StartsWith("""DO $$ BEGIN IF (CASE WHEN EXISTS (SELECT 1 FROM "KeyCeremonies" WHERE "ParametersJson" ~ '(^|[^\\])((\\\\)*)\\u0000') THEN true ELSE """, post);
        Assert.Contains("'tenantid', 'mintedtiertenantid'", post);
        Assert.Contains("'TenantPolicyChange'", post);
    }

    [Fact]
    public void The_nul_escape_regex_is_exactly_what_postgresql_should_receive()
    {
        const string once = """regexp_replace(t, '(^|[^\\])((\\\\)*)\\u0000', '\1\2\\ufffd', 'g')""";
        Assert.Equal(once, RenameTenantToSpace.NeutraliseNulOnce("t"));
        Assert.Equal(@"\" + "ufffd", RenameTenantToSpace.ReplacementEscape);

        var ops = Migration().UpOperations.ToList();
        var p1 = Assert.IsType<SqlOperation>(ops[0]).Sql.ReplaceLineEndings("\n");
        Assert.Contains($"""
                    LOOP
                        n := {once};
                        EXIT WHEN n = t;
                        t := n;
                    END LOOP;
                    BEGIN
                        j := t::jsonb;
            """.ReplaceLineEndings("\n"), p1);
        Assert.DoesNotContain("""r."ParametersJson"::jsonb""", p1);

        var nul = Sql(ops).Single(s => s.Contains("""UPDATE "KeyCeremonies" SET "ParametersJson" = regexp_replace("""));
        Assert.Equal("""
            DO $$
            BEGIN
                LOOP
                    UPDATE "KeyCeremonies" SET "ParametersJson" = regexp_replace("ParametersJson", '(^|[^\\])((\\\\)*)\\u0000', '\1\2\\ufffd', 'g')
                    WHERE "ParametersJson" ~ '(^|[^\\])((\\\\)*)\\u0000';
                    EXIT WHEN NOT FOUND;
                END LOOP;
            END $$;
            """.ReplaceLineEndings("\n"), nul.ReplaceLineEndings("\n"));
    }

    /// <summary>The rule the SQL applies, run in .NET: only an escape after an even run of backslashes is a NUL.</summary>
    [Theory]
    [InlineData(@"a\u0000b", @"a|b")]
    [InlineData(@"\u0000", @"|")]
    [InlineData(@"\\u0000", @"\\u0000")]
    [InlineData(@"\\\u0000", @"\\|")]
    [InlineData(@"\\\\u0000", @"\\\\u0000")]
    [InlineData(@"\u0000\u0000", @"||")]
    [InlineData(@"x\u0000\u0000\u0000y", @"x|||y")]
    [InlineData(@"\\\u0000\\u0000\u0000", @"\\|\\u0000|")]
    [InlineData(@"\u00001 \" + "u0041 " + @"\n", @"|1 \" + "u0041 " + @"\n")]
    public void Only_an_unescaped_nul_escape_is_replaced(string json, string expected)
    {
        Assert.Equal(expected.Replace("|", RenameTenantToSpace.ReplacementEscape), RenameTenantToSpace.NeutraliseNul(json));
    }

    [Fact]
    public void A_name_with_nul_written_by_the_serializer_reads_back_with_the_replacement_character()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { FirstName = "Bob\0\0", LastName = @"O\u0000Neil" });
        Assert.Contains(@"Bob\u0000\u0000", json);

        var read = System.Text.Json.JsonDocument.Parse(RenameTenantToSpace.NeutraliseNul(json)).RootElement;
        Assert.Equal("Bob" + (char)0xFFFD + (char)0xFFFD, read.GetProperty("FirstName").GetString());
        Assert.Equal(@"O\u0000Neil", read.GetProperty("LastName").GetString());
    }

    [Fact]
    public void Every_legacy_key_and_casing_is_renamed_in_every_status()
    {
        var keys = Sql(Migration().UpOperations).Single(s => s.Contains("jsonb_object_agg"));
        Assert.Contains("""WHEN 'tenantid' THEN CASE WHEN e.key ~ '^[a-z]' THEN 'spaceId' ELSE 'SpaceId' END""", keys);
        Assert.Contains("""WHEN 'mintedtiertenantid' THEN CASE WHEN e.key ~ '^[a-z]' THEN 'mintedTierSpaceId' ELSE 'MintedTierSpaceId' END""", keys);
        Assert.DoesNotContain("Status", keys);
    }

    [Fact]
    public void Groups_are_renamed_as_new_spaces_name_them()
    {
        var sql = Sql(Migration().UpOperations);
        var groups = sql.Single(s => s.StartsWith("""UPDATE "CaGroups" g SET "Name" = r.new_name""", StringComparison.Ordinal));
        Assert.Contains("""'space-' || s."Slug"::text || '-' || x.suffix""", groups);
        Assert.Contains("""lower(g."Name"::text) = lower('org-' || s."Slug"::text || '-' || x.suffix)""", groups);
        Assert.Contains("(VALUES ('admin'), ('operator'), ('auditor'), ('user'))", groups);
        Assert.Contains("""g."CertificateAuthorityId" IS NULL""", groups);
        Assert.Contains("""regexp_replace(g."DisplayName", '^(Org|Organisation|Organization) ', 'Space ')""", groups);

        var p2 = sql.Single(s => s.Contains("space-<slug>-*"));
        Assert.Contains("""length(r.new_name) > 200 OR length(r.new_display) > 300 OR EXISTS (SELECT 1 FROM "CaGroups" o WHERE lower(o."Name"::text) = lower(r.new_name))""", p2);
    }

    [Fact]
    public void Down_refuses()
    {
        var ex = Assert.Throws<NotSupportedException>(() => Migration().DownOperations.ToList());
        Assert.Contains("restore the pre-upgrade dump", ex.Message);
    }
}
