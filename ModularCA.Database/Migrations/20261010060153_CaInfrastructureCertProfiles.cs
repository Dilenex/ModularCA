using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: a CA can name the certificate profile its timestamp signer, its OCSP responder and
    /// its CMP signer are issued under. Three nullable columns on <c>CertificateAuthorities</c>,
    /// each a reference to <c>CertProfiles</c> that refuses the profile's deletion. They are
    /// left null on every existing CA, which reads as the seeded default profile, the one every
    /// CA used before. Columns only; no row changes and nothing to refuse.
    /// </summary>
    public partial class CaInfrastructureCertProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CmpSignerCertProfileId",
                table: "CertificateAuthorities",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "OcspResponderCertProfileId",
                table: "CertificateAuthorities",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TsaCertProfileId",
                table: "CertificateAuthorities",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_CmpSignerCertProfileId",
                table: "CertificateAuthorities",
                column: "CmpSignerCertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_OcspResponderCertProfileId",
                table: "CertificateAuthorities",
                column: "OcspResponderCertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_TsaCertProfileId",
                table: "CertificateAuthorities",
                column: "TsaCertProfileId");

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_CmpSignerCertProfileId",
                table: "CertificateAuthorities",
                column: "CmpSignerCertProfileId",
                principalTable: "CertProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_OcspResponderCertProfil~",
                table: "CertificateAuthorities",
                column: "OcspResponderCertProfileId",
                principalTable: "CertProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_TsaCertProfileId",
                table: "CertificateAuthorities",
                column: "TsaCertProfileId",
                principalTable: "CertProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_CmpSignerCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_OcspResponderCertProfil~",
                table: "CertificateAuthorities");

            migrationBuilder.DropForeignKey(
                name: "FK_CertificateAuthorities_CertProfiles_TsaCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_CmpSignerCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_OcspResponderCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_TsaCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropColumn(
                name: "CmpSignerCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropColumn(
                name: "OcspResponderCertProfileId",
                table: "CertificateAuthorities");

            migrationBuilder.DropColumn(
                name: "TsaCertProfileId",
                table: "CertificateAuthorities");
        }
    }
}
