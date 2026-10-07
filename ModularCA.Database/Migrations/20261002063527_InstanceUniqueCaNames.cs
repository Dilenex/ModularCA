using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0 S4: CA labels and names are unique across the instance, soft-deleted CAs included,
    /// because a label is the path of the CRL, OCSP, AIA and enrolment URLs of every certificate its
    /// CA issued. Refuses (P1-P3) while two CAs share a label, a label up to case, or a name, and
    /// while an enabled protocol configuration (P4) or certificate template (P5) of a live X.509 CA
    /// names a signing profile that does not issue from that CA's current certificate, which 0.4.0
    /// resolution refuses. Label is citext, so P1 compares it as text (exact duplicates) and P2
    /// reports the case-only ones; Name is citext and P3 compares it as its unique index will. Then
    /// replaces the per-tenant and instance-only unique indexes with plain ones, adds a raw-SQL
    /// unique index on <c>lower("Label")</c> (outside the EF model) so case cannot be raced past
    /// the application check, and drops the tenant quota columns, whatever they hold. Not
    /// reversible: Down throws.
    /// </summary>
    public partial class InstanceUniqueCaNames : Migration
    {
        private const string Rename =
            " Rename all but one of each before upgrading. Prefer the SSH CA or a CA that has issued nothing, because renaming an X.509 CA changes the URLs baked into its certificates.";

        /// <summary>
        /// The FailIf arguments refusing two CAs whose <paramref name="key"/> (a SQL expression
        /// over <c>ca</c>) is equal: the condition, the duplicate-group count and the listing of
        /// every duplicate row as its <paramref name="shown"/> column, its space (or the instance)
        /// and whether it is deleted.
        /// </summary>
        private static (string Condition, string Count, string Listing) Duplicates(string key, string shown)
        {
            var groups = $"""SELECT {key} AS k FROM "CertificateAuthorities" ca WHERE ca."{shown}" IS NOT NULL GROUP BY {key} HAVING count(*) > 1""";
            return (
                $"EXISTS ({groups})",
                $"(SELECT count(*) FROM ({groups}) d)",
                $"""(SELECT string_agg(ca."{shown}" || ' (' || coalesce(t."Name", 'instance') || CASE WHEN ca."IsDeleted" THEN ', deleted' ELSE '' END || ')', ', ' ORDER BY {key}, ca."{shown}", t."Name") FROM "CertificateAuthorities" ca LEFT JOIN "Tenants" t ON t."Id" = ca."TenantId" WHERE {key} IN (SELECT d.k FROM ({groups}) d))""");
        }

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // P1
            var p1 = Duplicates("""ca."Label"::text""", "Label");
            migrationBuilder.FailIf(p1.Condition,
                "This instance has {0} CA label(s) used by more than one CA, counting soft-deleted CAs: {1}. From 0.4.0 a label "
                + "names one CA across the instance; it is the path of its CRL, OCSP, AIA and enrolment URLs." + Rename,
                p1.Count, p1.Listing);

            // P2
            var p2 = Duplicates("""lower(ca."Label")""", "Label");
            migrationBuilder.FailIf(p2.Condition,
                "This instance has {0} CA label(s) that differ from another CA's label only in case, counting soft-deleted CAs: {1}. "
                + "From 0.4.0 a label names one CA across the instance, compared without regard to case; it is the path of its "
                + "CRL, OCSP, AIA and enrolment URLs." + Rename,
                p2.Count, p2.Listing);

            // P3
            var p3 = Duplicates("""ca."Name" """, "Name");
            migrationBuilder.FailIf(p3.Condition,
                "This instance has {0} CA name(s) used by more than one CA, counting soft-deleted CAs: {1}. From 0.4.0 a CA name "
                + "is unique across the instance. Rename all but one of each before upgrading; a CA's name is a display name, "
                + "and renaming it changes no certificate.",
                p3.Count, p3.Listing);

            // P4
            const string misissuing = """FROM "CaProtocolConfigs" pc JOIN "CertificateAuthorities" ca ON ca."Id" = pc."CaId" JOIN "SigningProfiles" sp ON sp."Id" = pc."SigningProfileId" WHERE pc."IsEnabled" AND NOT ca."IsDeleted" AND NOT ca."IsSshCa" AND (sp."IssuerId" IS NULL OR sp."IssuerId" <> ca."CertificateId")""";
            migrationBuilder.FailIf($"EXISTS (SELECT 1 {misissuing})",
                "This instance has {0} enabled protocol configuration(s) whose signing profile does not issue from the "
                + "configuration's CA: {1}. From 0.4.0 a CA's EST, CMP, SCEP, ACME, XCEP and MSAE endpoints refuse such a "
                + "configuration, so every request to them would fail. In the 0.3.x console, open Protocol Config for each CA "
                + "listed and point the protocol at that CA's own signing profile, or disable the protocol, then upgrade.",
                $"(SELECT count(*) {misissuing})",
                $"""(SELECT string_agg(coalesce(ca."Label", ca."Name") || ' ' || pc."Protocol" || ' uses ''' || sp."Name" || '''', ', ' ORDER BY coalesce(ca."Label", ca."Name"), pc."Protocol") {misissuing})""");

            // P5
            const string misissuingTemplates = """FROM "CertificateTemplates" ct JOIN "CertificateAuthorities" ca ON ca."Id" = ct."CaId" JOIN "SigningProfiles" sp ON sp."Id" = ct."SigningProfileId" WHERE ct."IsEnabled" AND NOT ca."IsDeleted" AND NOT ca."IsSshCa" AND (sp."IssuerId" IS NULL OR sp."IssuerId" <> ca."CertificateId")""";
            migrationBuilder.FailIf($"EXISTS (SELECT 1 {misissuingTemplates})",
                "This instance has {0} enabled certificate template(s) whose signing profile does not issue from the "
                + "template's CA: {1}. From 0.4.0 MSAE refuses such a template. In the 0.3.x console, open Certificate "
                + "Templates (/admin/templates) and point each template listed at its CA's own signing profile, or disable "
                + "it, then upgrade.",
                $"(SELECT count(*) {misissuingTemplates})",
                $"""(SELECT string_agg('''' || ct."Name" || ''' on ' || coalesce(ca."Label", ca."Name") || ' uses ''' || sp."Name" || '''', ', ' ORDER BY ct."Name") {misissuingTemplates})""");

            // Raw SQL, outside the EF model, which cannot express an expression index.
            migrationBuilder.Sql("CREATE UNIQUE INDEX \"IX_CertificateAuthorities_LabelLower\" ON \"CertificateAuthorities\" (lower(\"Label\"))");

            // 1
            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_Label",
                table: "CertificateAuthorities",
                column: "Label",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_Name",
                table: "CertificateAuthorities",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_TenantId",
                table: "CertificateAuthorities",
                column: "TenantId");

            // 2
            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_Label_Instance",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_Name_Instance",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_TenantId_Label",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_TenantId_Name",
                table: "CertificateAuthorities");

            // 3
            migrationBuilder.DropColumn(
                name: "MaxCertificateAuthorities",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "MaxCertificatesTotal",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "MaxUsers",
                table: "Tenants");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("InstanceUniqueCaNames cannot be reversed; restore the pre-upgrade dump.");
        }
    }
}
