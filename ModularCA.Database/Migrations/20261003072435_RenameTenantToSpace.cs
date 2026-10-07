using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0 S6: "tenant" becomes "space" in the application schema. Renames the <c>Tenants</c>
    /// table, its primary key, check constraints and indexes, the eleven tenant columns, their
    /// indexes and the five foreign keys, in place: catalog changes only, no data is copied. Then,
    /// in the same transaction, replaces each JSON <c>\u0000</c> escape in stored ceremony
    /// parameters with U+FFFD, since jsonb rejects it, and renames the stored ceremony parameter keys (<c>TenantId</c>,
    /// <c>MintedTierTenantId</c>, <c>tenantId</c>) to their space names in every ceremony, the
    /// <c>TenantPolicyChange</c> operation type to <c>SpacePolicyChange</c>, and each space's
    /// <c>org-&lt;slug&gt;-*</c> groups to <c>space-&lt;slug&gt;-*</c>, as new spaces name them.
    /// Refuses (P1) while stored parameters naming a tenant are not a JSON object with one scope
    /// key each, and (P2) while a group's new name is taken or too long. The audit database is not
    /// touched. Not reversible: Down throws.
    /// </summary>
    public partial class RenameTenantToSpace : Migration
    {
        private const string MentionsTenant = """strpos(lower(k."ParametersJson"), 'tenantid') > 0""";

        private const string HasLegacyKey =
            """CASE WHEN """ + MentionsTenant + """ THEN EXISTS (SELECT 1 FROM jsonb_object_keys(k."ParametersJson"::jsonb) jk WHERE lower(jk) IN ('tenantid', 'mintedtiertenantid')) ELSE false END""";

        private const string RenamedGroups =
            """
            SELECT g."Id", g."Name", 'space-' || s."Slug"::text || '-' || x.suffix AS new_name,
                   regexp_replace(g."DisplayName", '^(Org|Organisation|Organization) ', 'Space ') AS new_display
            FROM "CaGroups" g
            JOIN "Spaces" s ON s."Id" = g."SpaceId"
            CROSS JOIN (VALUES ('admin'), ('operator'), ('auditor'), ('user')) AS x(suffix)
            WHERE g."CertificateAuthorityId" IS NULL
              AND lower(g."Name"::text) = lower('org-' || s."Slug"::text || '-' || x.suffix)
            """;

        /// <summary>
        /// A JSON <c>\u0000</c> escape, which jsonb rejects (22P05): one preceded by an even run of
        /// backslashes. The same text is a PostgreSQL ARE and a .NET regex.
        /// </summary>
        public const string NulEscapePattern = @"(^|[^\\])((\\\\)*)\\u0000";

        /// <summary>The JSON escape for U+FFFD, which replaces each <see cref="NulEscapePattern"/> match.</summary>
        public const string ReplacementEscape = @"\" + "ufffd";

        /// <summary>The PostgreSQL replacement for <see cref="NulEscapePattern"/>: prefix, run, then <see cref="ReplacementEscape"/>.</summary>
        public const string NulEscapeReplacement = @"\1\2\" + ReplacementEscape;

        /// <summary>
        /// One SQL pass replacing each <c>\u0000</c> escape in <paramref name="text"/> with
        /// U+FFFD. Adjacent escapes overlap, so the migration repeats it until nothing changes.
        /// </summary>
        public static string NeutraliseNulOnce(string text) =>
            $"regexp_replace({text}, '{NulEscapePattern}', '{NulEscapeReplacement}', 'g')";

        /// <summary>The same rule in .NET, repeated until nothing changes, for tests.</summary>
        public static string NeutraliseNul(string json)
        {
            for (var next = Pass(json); next != json; next = Pass(json))
                json = next;
            return json;

            static string Pass(string s) => System.Text.RegularExpressions.Regex.Replace(s, NulEscapePattern, "$1$2" + ReplacementEscape);
        }

        private const string BlockedGroups =
            """SELECT r."Name", r.new_name FROM (""" + RenamedGroups + """) r WHERE length(r.new_name) > 200 OR length(r.new_display) > 300 OR EXISTS (SELECT 1 FROM "CaGroups" o WHERE lower(o."Name"::text) = lower(r.new_name))""";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // P1
            migrationBuilder.Sql(
                $"""
                DO $$
                DECLARE
                    r record;
                    t text;
                    n text;
                    j jsonb;
                    bad text := '';
                BEGIN
                    FOR r IN SELECT k."Id", k."Status", k."ParametersJson" FROM "KeyCeremonies" k
                             WHERE strpos(lower(k."ParametersJson"), 'tenantid') > 0 ORDER BY k."Id"
                    LOOP
                        t := r."ParametersJson";
                        LOOP
                            n := {NeutraliseNulOnce("t")};
                            EXIT WHEN n = t;
                            t := n;
                        END LOOP;
                        BEGIN
                            j := t::jsonb;
                        EXCEPTION WHEN data_exception THEN
                            j := NULL;
                        END;
                        IF j IS NULL OR jsonb_typeof(j) <> 'object'
                           OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('tenantid', 'spaceid')) > 1
                           OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('mintedtiertenantid', 'mintedtierspaceid')) > 1 THEN
                            bad := bad || CASE WHEN bad = '' THEN '' ELSE ', ' END || r."Id"::text || ' (' || r."Status" || ')';
                        END IF;
                    END LOOP;
                    IF bad <> '' THEN
                        RAISE EXCEPTION USING MESSAGE = 'The stored parameters of these key ceremonies could not be read as a JSON object '
                            || 'with one tenant key each: ' || bad || '. 0.4.0 renames those keys in place and cannot rename these. '
                            || 'Cancel an open one, or let it expire, and open it again after the upgrade; and contact support with '
                            || 'these ceremony ids, because each blocks the upgrade whatever its status.';
                    END IF;
                END $$;
                """);

            // 1
            migrationBuilder.RenameTable(
                name: "Tenants",
                newName: "Spaces");

            migrationBuilder.Sql("""ALTER TABLE "Spaces" RENAME CONSTRAINT "PK_Tenants" TO "PK_Spaces";""");
            migrationBuilder.Sql("""ALTER TABLE "Spaces" RENAME CONSTRAINT "CK_Tenants_Name_Length" TO "CK_Spaces_Name_Length";""");
            migrationBuilder.Sql("""ALTER TABLE "Spaces" RENAME CONSTRAINT "CK_Tenants_Slug_Length" TO "CK_Spaces_Slug_Length";""");

            // PostgreSQL 18 records NOT NULL as named constraints (Tenants_Name_not_null); earlier releases have none.
            migrationBuilder.Sql(
                """
                DO $$
                DECLARE c record;
                BEGIN
                    FOR c IN SELECT conname FROM pg_catalog.pg_constraint
                             WHERE conrelid = '"Spaces"'::regclass AND contype = 'n' AND left(conname, 8) = 'Tenants_'
                    LOOP
                        EXECUTE format('ALTER TABLE "Spaces" RENAME CONSTRAINT %I TO %I', c.conname, 'Spaces' || substr(c.conname, 8));
                    END LOOP;
                END $$;
                """);

            migrationBuilder.RenameIndex(
                name: "IX_Tenants_Slug",
                table: "Spaces",
                newName: "IX_Spaces_Slug");

            migrationBuilder.RenameIndex(
                name: "IX_Tenants_Name",
                table: "Spaces",
                newName: "IX_Spaces_Name");

            migrationBuilder.RenameIndex(
                name: "IX_Tenants_IsDeleted",
                table: "Spaces",
                newName: "IX_Spaces_IsDeleted");

            // 2
            migrationBuilder.RenameColumn(
                name: "ServiceScopeTenantId",
                table: "Users",
                newName: "ServiceScopeSpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_Users_ServiceScopeTenantId",
                table: "Users",
                newName: "IX_Users_ServiceScopeSpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "UserCapabilityGrants",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_UserCapabilityGrants_TenantId_CertificateAuthorityId",
                table: "UserCapabilityGrants",
                newName: "IX_UserCapabilityGrants_SpaceId_CertificateAuthorityId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "SignerAudit",
                newName: "SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "Roles",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_Roles_TenantId",
                table: "Roles",
                newName: "IX_Roles_SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "RoleAssignments",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_RoleAssignments_TenantId_CertificateAuthorityId",
                table: "RoleAssignments",
                newName: "IX_RoleAssignments_SpaceId_CertificateAuthorityId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "KeyCeremonies",
                newName: "SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "KerberosRealms",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_KerberosRealms_TenantId",
                table: "KerberosRealms",
                newName: "IX_KerberosRealms_SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "EnrollmentTokens",
                newName: "SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "CertProfiles",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_CertProfiles_TenantId",
                table: "CertProfiles",
                newName: "IX_CertProfiles_SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "CertificateAuthorities",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_CertificateAuthorities_TenantId",
                table: "CertificateAuthorities",
                newName: "IX_CertificateAuthorities_SpaceId");

            migrationBuilder.RenameColumn(
                name: "TenantId",
                table: "CaGroups",
                newName: "SpaceId");

            migrationBuilder.RenameIndex(
                name: "IX_CaGroups_TenantId",
                table: "CaGroups",
                newName: "IX_CaGroups_SpaceId");

            // 3
            migrationBuilder.Sql("""ALTER TABLE "CertificateAuthorities" RENAME CONSTRAINT "FK_CertificateAuthorities_Tenants_TenantId" TO "FK_CertificateAuthorities_Spaces_SpaceId";""");
            migrationBuilder.Sql("""ALTER TABLE "KerberosRealms" RENAME CONSTRAINT "FK_KerberosRealms_Tenants_TenantId" TO "FK_KerberosRealms_Spaces_SpaceId";""");
            migrationBuilder.Sql("""ALTER TABLE "RoleAssignments" RENAME CONSTRAINT "FK_RoleAssignments_Tenants_TenantId" TO "FK_RoleAssignments_Spaces_SpaceId";""");
            migrationBuilder.Sql("""ALTER TABLE "Roles" RENAME CONSTRAINT "FK_Roles_Tenants_TenantId" TO "FK_Roles_Spaces_SpaceId";""");
            migrationBuilder.Sql("""ALTER TABLE "UserCapabilityGrants" RENAME CONSTRAINT "FK_UserCapabilityGrants_Tenants_TenantId" TO "FK_UserCapabilityGrants_Spaces_SpaceId";""");

            // P2
            migrationBuilder.FailIf(
                $"EXISTS ({BlockedGroups})",
                "This instance has {0} space group(s) that cannot take their 0.4.0 name: {1}. 0.4.0 renames each space's "
                + "org-<slug>-admin, -operator, -auditor and -user groups to space-<slug>-*, as new spaces name them; the new "
                + "name must be free and at most 200 characters, and the display name at most 300. Rename or delete the group "
                + "holding each new name before upgrading.",
                $"(SELECT count(*) FROM ({BlockedGroups}) b)",
                $"""(SELECT string_agg(b."Name"::text || ' -> ' || b.new_name, ', ' ORDER BY b.new_name) FROM ({BlockedGroups}) b)""");

            // 4
            migrationBuilder.Sql(
                $"""
                DO $$
                BEGIN
                    LOOP
                        UPDATE "KeyCeremonies" SET "ParametersJson" = {NeutraliseNulOnce("\"ParametersJson\"")}
                        WHERE "ParametersJson" ~ '{NulEscapePattern}';
                        EXIT WHEN NOT FOUND;
                    END LOOP;
                END $$;
                """);

            migrationBuilder.Sql(
                """
                UPDATE "KeyCeremonies" k
                SET "ParametersJson" = (
                    SELECT jsonb_object_agg(
                        CASE lower(e.key)
                            WHEN 'tenantid' THEN CASE WHEN e.key ~ '^[a-z]' THEN 'spaceId' ELSE 'SpaceId' END
                            WHEN 'mintedtiertenantid' THEN CASE WHEN e.key ~ '^[a-z]' THEN 'mintedTierSpaceId' ELSE 'MintedTierSpaceId' END
                            ELSE e.key
                        END,
                        e.value)
                    FROM jsonb_each(k."ParametersJson"::jsonb) e)::text
                WHERE
                """ + " " + HasLegacyKey + ";");

            migrationBuilder.Sql("""UPDATE "KeyCeremonies" SET "OperationType" = 'SpacePolicyChange' WHERE "OperationType" = 'TenantPolicyChange';""");

            // 5
            migrationBuilder.Sql(
                """UPDATE "CaGroups" g SET "Name" = r.new_name, "DisplayName" = r.new_display FROM (""" + RenamedGroups + """) r WHERE g."Id" = r."Id";""");

            // 6
            migrationBuilder.FailIf(
                $"""CASE WHEN EXISTS (SELECT 1 FROM "KeyCeremonies" WHERE "ParametersJson" ~ '{NulEscapePattern}') THEN true ELSE EXISTS (SELECT 1 FROM "KeyCeremonies" k WHERE {HasLegacyKey}) OR EXISTS (SELECT 1 FROM "KeyCeremonies" WHERE "OperationType" = 'TenantPolicyChange') END""",
                @"RenameTenantToSpace left a \u0000 escape or a tenant key in stored ceremony parameters, or a TenantPolicyChange "
                + "ceremony, after renaming them; nothing was changed. Report this with the migration log.");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("RenameTenantToSpace cannot be reversed; restore the pre-upgrade dump.");
        }
    }
}
