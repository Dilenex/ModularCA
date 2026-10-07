using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0: an ACME account is bound to the CA it registered at, by id, and refused at every
    /// other CA. Adds <c>AcmeAccounts.CertificateAuthorityId</c> and fills it in place: an account
    /// that registered under a label gets the CA with that label (ignoring case, soft-deleted CAs
    /// included, since labels are unique over all rows); one that registered on the label-less
    /// routes gets the CA those routes resolve to today, as <c>CaResolverService.DefaultCandidates</c>
    /// orders them: enabled, not SSH, not deleted, no <c>system-</c> label, the default first, then
    /// by name and id. An account whose label names no CA stays unbound, and no CA accepts it; its
    /// client registers again. Nothing to refuse, so no precondition.
    /// </summary>
    public partial class BindAcmeAccountsToCa : Migration
    {
        /// <summary>The CA the label-less routes resolve to, as <c>CaResolverService.DefaultCandidates</c> picks it.</summary>
        private const string DefaultCa =
            """SELECT c."Id" FROM "CertificateAuthorities" c WHERE c."IsEnabled" AND NOT c."IsSshCa" AND NOT c."IsDeleted" AND (c."Label" IS NULL OR lower(c."Label"::text) NOT LIKE 'system-%') ORDER BY c."IsDefault" DESC, c."Name", c."Id" LIMIT 1""";

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CertificateAuthorityId",
                table: "AcmeAccounts",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql(
                """UPDATE "AcmeAccounts" a SET "CertificateAuthorityId" = c."Id" FROM "CertificateAuthorities" c WHERE a."CaLabel" IS NOT NULL AND btrim(a."CaLabel") <> '' AND c."Label" IS NOT NULL AND lower(c."Label"::text) = lower(btrim(a."CaLabel"))""");

            migrationBuilder.Sql(
                $"""UPDATE "AcmeAccounts" SET "CertificateAuthorityId" = ({DefaultCa}) WHERE "CertificateAuthorityId" IS NULL AND ("CaLabel" IS NULL OR btrim("CaLabel") = '')""");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_CertificateAuthorityId",
                table: "AcmeAccounts",
                column: "CertificateAuthorityId");

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeAccounts_CertificateAuthorities_CertificateAuthorityId",
                table: "AcmeAccounts",
                column: "CertificateAuthorityId",
                principalTable: "CertificateAuthorities",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AcmeAccounts_CertificateAuthorities_CertificateAuthorityId",
                table: "AcmeAccounts");

            migrationBuilder.DropIndex(
                name: "IX_AcmeAccounts_CertificateAuthorityId",
                table: "AcmeAccounts");

            migrationBuilder.DropColumn(
                name: "CertificateAuthorityId",
                table: "AcmeAccounts");
        }
    }
}
