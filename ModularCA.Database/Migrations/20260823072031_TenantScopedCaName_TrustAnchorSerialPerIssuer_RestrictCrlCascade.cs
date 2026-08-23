using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class TenantScopedCaName_TrustAnchorSerialPerIssuer_RestrictCrlCascade : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CrlConfigurations_Certificates_CaCertificateId",
                table: "CrlConfigurations");

            migrationBuilder.DropForeignKey(
                name: "FK_Crls_CrlConfigurations_TaskId",
                table: "Crls");

            migrationBuilder.DropIndex(
                name: "IX_TrustAnchors_SerialNumber",
                table: "TrustAnchors");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_Name",
                table: "CertificateAuthorities");

            migrationBuilder.CreateIndex(
                name: "IX_TrustAnchors_SerialNumber_Issuer",
                table: "TrustAnchors",
                columns: new[] { "SerialNumber", "Issuer" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_TenantId_Name",
                table: "CertificateAuthorities",
                columns: new[] { "TenantId", "Name" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_CrlConfigurations_Certificates_CaCertificateId",
                table: "CrlConfigurations",
                column: "CaCertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_Crls_CrlConfigurations_TaskId",
                table: "Crls",
                column: "TaskId",
                principalTable: "CrlConfigurations",
                principalColumn: "TaskId",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CrlConfigurations_Certificates_CaCertificateId",
                table: "CrlConfigurations");

            migrationBuilder.DropForeignKey(
                name: "FK_Crls_CrlConfigurations_TaskId",
                table: "Crls");

            migrationBuilder.DropIndex(
                name: "IX_TrustAnchors_SerialNumber_Issuer",
                table: "TrustAnchors");

            migrationBuilder.DropIndex(
                name: "IX_CertificateAuthorities_TenantId_Name",
                table: "CertificateAuthorities");

            migrationBuilder.CreateIndex(
                name: "IX_TrustAnchors_SerialNumber",
                table: "TrustAnchors",
                column: "SerialNumber",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_Name",
                table: "CertificateAuthorities",
                column: "Name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_CrlConfigurations_Certificates_CaCertificateId",
                table: "CrlConfigurations",
                column: "CaCertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Crls_CrlConfigurations_TaskId",
                table: "Crls",
                column: "TaskId",
                principalTable: "CrlConfigurations",
                principalColumn: "TaskId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
