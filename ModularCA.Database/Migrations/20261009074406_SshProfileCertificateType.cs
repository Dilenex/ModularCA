using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: a certificate type on SSH request profiles and SSH certificate profiles.
    /// <c>SshRequestProfiles.CertificateType</c> and <c>SshCertProfiles.CertificateType</c> are
    /// added: <c>user</c>, <c>host</c>, or null for either. The type is set only on the five
    /// profiles a new install seeds, found by their exact names, letter case included. Every
    /// other profile stays null and works as it did. No other column of any row changes. Two
    /// columns and a backfill; nothing to refuse.
    /// </summary>
    public partial class SshProfileCertificateType : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CertificateType",
                table: "SshRequestProfiles",
                type: "character varying(10)",
                maxLength: 10,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CertificateType",
                table: "SshCertProfiles",
                type: "character varying(10)",
                maxLength: 10,
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE "SshCertProfiles" SET "CertificateType" = 'user'
                    WHERE "Name"::text IN ('SSH User Cert - Standard', 'SSH User Cert - Forwarding');
                UPDATE "SshCertProfiles" SET "CertificateType" = 'host'
                    WHERE "Name"::text = 'SSH Host Cert - Standard';
                UPDATE "SshRequestProfiles" SET "CertificateType" = 'user'
                    WHERE "Name"::text = 'SSH User Request - Default';
                UPDATE "SshRequestProfiles" SET "CertificateType" = 'host'
                    WHERE "Name"::text = 'SSH Host Request - Default';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CertificateType",
                table: "SshRequestProfiles");

            migrationBuilder.DropColumn(
                name: "CertificateType",
                table: "SshCertProfiles");
        }
    }
}
