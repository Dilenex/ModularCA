using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddMsaeTemplateFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "MsaeMachineType",
                table: "CertificateTemplates",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "MsaeMajorVersion",
                table: "CertificateTemplates",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "MsaeMinorVersion",
                table: "CertificateTemplates",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "MsaeTemplateOid",
                table: "CertificateTemplates",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_MsaeTemplateOid",
                table: "CertificateTemplates",
                column: "MsaeTemplateOid",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CertificateTemplates_MsaeTemplateOid",
                table: "CertificateTemplates");

            migrationBuilder.DropColumn(
                name: "MsaeMachineType",
                table: "CertificateTemplates");

            migrationBuilder.DropColumn(
                name: "MsaeMajorVersion",
                table: "CertificateTemplates");

            migrationBuilder.DropColumn(
                name: "MsaeMinorVersion",
                table: "CertificateTemplates");

            migrationBuilder.DropColumn(
                name: "MsaeTemplateOid",
                table: "CertificateTemplates");
        }
    }
}
