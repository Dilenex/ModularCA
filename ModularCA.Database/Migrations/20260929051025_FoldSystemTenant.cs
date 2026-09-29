using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0 S3: the system tenant is folded into the instance. Refuses (P1-P9) when a row would
    /// widen privilege, bypass a ceremony, or be lost; then copies the system tenant's CA policy to
    /// <c>SecurityPolicy</c> as it is, deletes its tenant-wide <c>org-system-*</c> groups, gives
    /// every row that named it a null tenant (instance scope), makes the tenant foreign keys
    /// RESTRICT, deletes the tenant, and drops <c>Tenants.IsSystemTenant</c>. It also adds
    /// <c>SignerAudit.EffectiveScope</c>, so new signer rows tell the instance from no stated
    /// scope; existing rows keep it null. A database with no
    /// tenants at all (a fresh install, seeded after the schema) passes and changes no data.
    /// Not reversible: Down throws.
    /// </summary>
    public partial class FoldSystemTenant : Migration
    {
        private const string Sys = """(SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")""";

        private const string OrgSystemGroups =
            """SELECT g."Id" FROM "CaGroups" g WHERE g."TenantId" = """ + Sys + """ AND NOT g."IsSystemGroup" AND g."CertificateAuthorityId" IS NULL""";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // P1
            migrationBuilder.FailIf(
                """(SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") > 1 OR ((SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") = 0 AND EXISTS (SELECT 1 FROM "Tenants"))""",
                "This instance has {0} system tenant(s), counting soft-deleted ones; 0.4.0 folds exactly one into the instance. "
                + "The database is not in a state any release produced: restore the pre-upgrade dump and contact support.",
                """(SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant")""");

            // P2
            migrationBuilder.FailIf(
                """(SELECT count(*) FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted") > 1""",
                "This instance has {0} organisation tenants ({1}); 0.4.0 folds the system tenant into an instance with one "
                + "organisation, whatever Features.AllowMultipleOrganizations says. Move all but one organisation to its own "
                + "instance before upgrading.",
                """(SELECT count(*) FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted")""",
                """(SELECT string_agg("Name", ', ' ORDER BY "Name") FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted")""");

            // P3
            migrationBuilder.FailIf(
                """(SELECT count(*) FROM "SecurityPolicy") > 1""",
                "This instance has {0} SecurityPolicy rows; there must be one, which receives the system tenant's CA policy. "
                + "Delete the extra rows, keeping the one the console shows, before upgrading.",
                """(SELECT count(*) FROM "SecurityPolicy")""");

            // P4
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "KeyCeremonies" WHERE "Status" IN ('Pending', 'Approved') AND ("TenantId" = """ + Sys + """ OR strpos(lower("ParametersJson"), """ + Sys + """::text) > 0))""",
                "This instance has {0} open ceremony(ies) that name the system tenant: {1}. Their parameters would name a tenant "
                + "that no longer exists. Before upgrading, execute or cancel each one with the current build.",
                """(SELECT count(*) FROM "KeyCeremonies" WHERE "Status" IN ('Pending', 'Approved') AND ("TenantId" = """ + Sys + """ OR strpos(lower("ParametersJson"), """ + Sys + """::text) > 0))""",
                """(SELECT string_agg("Id"::text || ' (' || "OperationType" || ', ' || "Status" || ')', ', ') FROM "KeyCeremonies" WHERE "Status" IN ('Pending', 'Approved') AND ("TenantId" = """ + Sys + """ OR strpos(lower("ParametersJson"), """ + Sys + """::text) > 0))""");

            // P5
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "UserCapabilityGrants" WHERE "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL) OR EXISTS (SELECT 1 FROM "RoleAssignments" WHERE "GroupId" IS NULL AND "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL)""",
                "This instance has {0} capability(ies) and {1} role assignment(s) held by users directly across the whole "
                + "system tenant. With the tenant gone they would apply to the whole instance, which is wider than they were "
                + "given. Before upgrading, remove them, or give them again at system scope on purpose.",
                """(SELECT count(*) FROM "UserCapabilityGrants" WHERE "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL)""",
                """(SELECT count(*) FROM "RoleAssignments" WHERE "GroupId" IS NULL AND "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL)""");

            // P6
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "Users" WHERE "ServiceScopeTenantId" = """ + Sys + """ AND "ServiceScopeCaId" IS NULL)""",
                "This instance has {0} service identity(ies) scoped to the whole system tenant ({1}). With the tenant gone they "
                + "would be scoped to the whole instance. Before upgrading, delete them, or scope them to a CA.",
                """(SELECT count(*) FROM "Users" WHERE "ServiceScopeTenantId" = """ + Sys + """ AND "ServiceScopeCaId" IS NULL)""",
                """(SELECT string_agg("Username", ', ' ORDER BY "Username") FROM "Users" WHERE "ServiceScopeTenantId" = """ + Sys + """ AND "ServiceScopeCaId" IS NULL)""");

            // P7
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "CaGroupMembers" WHERE "GroupId" IN (""" + OrgSystemGroups + """)) OR EXISTS (SELECT 1 FROM "AccessBadgeSources" WHERE "SourceId" IN (""" + OrgSystemGroups + """))""",
                "The system tenant's tenant-wide groups ({0}) have {1} member(s) and {2} access badge source(s). 0.4.0 deletes "
                + "these groups: org-system-admin held every capability across the system tenant, which would otherwise become "
                + "the whole instance. Before upgrading, move each member to the system group that fits (system-admin, "
                + "system-operator, system-auditor) or to a CA's group, and edit the badges that name these groups.",
                """(SELECT string_agg(g."Name", ', ' ORDER BY g."Name") FROM "CaGroups" g WHERE g."Id" IN (""" + OrgSystemGroups + """))""",
                """(SELECT count(*) FROM "CaGroupMembers" WHERE "GroupId" IN (""" + OrgSystemGroups + """))""",
                """(SELECT count(*) FROM "AccessBadgeSources" WHERE "SourceId" IN (""" + OrgSystemGroups + """))""");

            // P8
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "CaGroups" g WHERE NOT EXISTS (SELECT 1 FROM "Tenants" t WHERE t."Id" = g."TenantId")) OR EXISTS (SELECT 1 FROM "CaGroups" g JOIN "CertificateAuthorities" ca ON ca."Id" = g."CertificateAuthorityId" WHERE g."TenantId" <> ca."TenantId" AND (g."TenantId" = """ + Sys + """ OR ca."TenantId" = """ + Sys + """))""",
                "This instance has group(s) whose tenant does not exist or, for a CA's group, differs from its CA's, next to the "
                + "system tenant: {0}. Folding the tenant would move them to the wrong scope. Correct each group's tenant "
                + "before upgrading.",
                """(SELECT string_agg(g."Name", ', ' ORDER BY g."Name") FROM "CaGroups" g LEFT JOIN "CertificateAuthorities" ca ON ca."Id" = g."CertificateAuthorityId" WHERE NOT EXISTS (SELECT 1 FROM "Tenants" t WHERE t."Id" = g."TenantId") OR (g."TenantId" <> ca."TenantId" AND (g."TenantId" = """ + Sys + """ OR ca."TenantId" = """ + Sys + """)))""");

            // P9
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "CertProfiles" WHERE "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile")""",
                "This instance has {0} certificate profile(s) on the system tenant that are bound to no CA ({1}). With the "
                + "tenant gone they would be offered to every CA created afterwards. Before upgrading, bind each to a CA or "
                + "delete it.",
                """(SELECT count(*) FROM "CertProfiles" WHERE "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile")""",
                """(SELECT string_agg("Name", ', ' ORDER BY "Name") FROM "CertProfiles" WHERE "TenantId" = """ + Sys + """ AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile")""");

            // 1
            migrationBuilder.AlterColumn<Guid>(
                name: "TenantId",
                table: "CertificateAuthorities",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AlterColumn<Guid>(
                name: "TenantId",
                table: "CaGroups",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AlterColumn<Guid>(
                name: "TenantId",
                table: "KerberosRealms",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<bool>(
                name: "RequireKeyCeremony",
                table: "SecurityPolicy",
                type: "boolean",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<int>(
                name: "CeremonyRequiredApprovals",
                table: "SecurityPolicy",
                type: "integer",
                nullable: false,
                defaultValue: 2);

            migrationBuilder.AddColumn<int>(
                name: "MaxValidityDays",
                table: "SecurityPolicy",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "ValidityCeilingBehavior",
                table: "SecurityPolicy",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "UserCeremonyRequiredApprovals",
                table: "SecurityPolicy",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "EffectiveScope",
                table: "SignerAudit",
                type: "character varying(16)",
                maxLength: 16,
                nullable: true);

            // 2
            migrationBuilder.Sql(
                """
                INSERT INTO "SecurityPolicy" (
                    "Id", "MaxFailedLoginAttempts", "LockoutMinutes", "SessionIdleTimeoutMinutes", "MaxConcurrentSessions",
                    "MaxSessionLifetimeDays", "LoginResponseDelayMs", "LoginBanner", "LoginBannerTitle",
                    "AllowSystemSuperSelfApproval", "RequireMtlsOcspCheck", "StepUpTokenTtlSeconds", "MfaSessionTtlSeconds",
                    "WebAuthnChallengeTtlSeconds", "RequireWebAuthnUserVerification", "StepUpFailureThreshold",
                    "StepUpFailureWindowSeconds", "AllowCaDirectSigning", "RequireNoCheckExtension", "RequireSignedRequests",
                    "DefaultGoodResponseTtlMinutes", "DefaultRevokedResponseTtlMinutes", "MaxSingleRequestsPerRequest",
                    "KeystoreScryptN", "KeystoreScryptR", "KeystoreScryptP", "UserQuorum", "RequireKeyCeremony",
                    "CeremonyRequiredApprovals", "MaxValidityDays", "ValidityCeilingBehavior", "UserCeremonyRequiredApprovals",
                    "UpdatedAt")
                SELECT gen_random_uuid(), 5, 15, 30, 3,
                    14, 500, NULL, NULL,
                    false, false, 90, 300,
                    120, true, 5,
                    300, false, false, false,
                    60, 15, 4,
                    65536, 8, 1, 1, true,
                    2, 0, 0, NULL,
                    now()
                WHERE NOT EXISTS (SELECT 1 FROM "SecurityPolicy")
                  AND EXISTS (SELECT 1 FROM "Tenants" WHERE "IsSystemTenant");
                """);

            // 3
            migrationBuilder.Sql(
                """
                UPDATE "SecurityPolicy" p SET
                    "RequireKeyCeremony" = t."RequireKeyCeremony",
                    "CeremonyRequiredApprovals" = t."CeremonyRequiredApprovals",
                    "MaxValidityDays" = t."MaxValidityDays",
                    "ValidityCeilingBehavior" = t."ValidityCeilingBehavior",
                    "UserCeremonyRequiredApprovals" = t."UserCeremonyRequiredApprovals"
                FROM "Tenants" t
                WHERE t."IsSystemTenant";
                """);

            // 4
            migrationBuilder.Sql("""DELETE FROM "CaGroups" WHERE "Id" IN (""" + OrgSystemGroups + """);""");

            // 5
            foreach (var table in new[] { "CertificateAuthorities", "CaGroups", "KerberosRealms", "Roles", "RoleAssignments", "UserCapabilityGrants", "CertProfiles", "EnrollmentTokens", "KeyCeremonies" })
                migrationBuilder.Sql($"""UPDATE "{table}" SET "TenantId" = NULL WHERE "TenantId" = {Sys};""");
            migrationBuilder.Sql($"""UPDATE "Users" SET "ServiceScopeTenantId" = NULL WHERE "ServiceScopeTenantId" = {Sys};""");

            // 6
            migrationBuilder.DropForeignKey(
                name: "FK_KerberosRealms_Tenants_TenantId",
                table: "KerberosRealms");

            migrationBuilder.DropForeignKey(
                name: "FK_RoleAssignments_Tenants_TenantId",
                table: "RoleAssignments");

            migrationBuilder.DropForeignKey(
                name: "FK_Roles_Tenants_TenantId",
                table: "Roles");

            migrationBuilder.DropForeignKey(
                name: "FK_UserCapabilityGrants_Tenants_TenantId",
                table: "UserCapabilityGrants");

            migrationBuilder.AddForeignKey(
                name: "FK_KerberosRealms_Tenants_TenantId",
                table: "KerberosRealms",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_RoleAssignments_Tenants_TenantId",
                table: "RoleAssignments",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_Roles_Tenants_TenantId",
                table: "Roles",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_UserCapabilityGrants_Tenants_TenantId",
                table: "UserCapabilityGrants",
                column: "TenantId",
                principalTable: "Tenants",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            // 7
            migrationBuilder.FailIf(
                """EXISTS (SELECT 1 FROM "CaGroups" WHERE "TenantId" = """ + Sys + """) OR EXISTS (SELECT 1 FROM "CertProfiles" WHERE "TenantId" = """ + Sys + """) OR EXISTS (SELECT 1 FROM "EnrollmentTokens" WHERE "TenantId" = """ + Sys + """) OR EXISTS (SELECT 1 FROM "KeyCeremonies" WHERE "TenantId" = """ + Sys + """) OR EXISTS (SELECT 1 FROM "Users" WHERE "ServiceScopeTenantId" = """ + Sys + """)""",
                "FoldSystemTenant left rows naming the system tenant after moving them to the instance; nothing was changed. "
                + "Report this with the migration log.");

            // 8
            migrationBuilder.Sql("""DELETE FROM "Tenants" WHERE "IsSystemTenant";""");

            // 9
            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_Label_Instance",
                table: "CertificateAuthorities",
                column: "Label",
                unique: true,
                filter: "\"TenantId\" IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_Name_Instance",
                table: "CertificateAuthorities",
                column: "Name",
                unique: true,
                filter: "\"TenantId\" IS NULL");

            // 10
            migrationBuilder.DropColumn(
                name: "IsSystemTenant",
                table: "Tenants");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("FoldSystemTenant cannot be reversed; restore the pre-upgrade dump.");
        }
    }
}
