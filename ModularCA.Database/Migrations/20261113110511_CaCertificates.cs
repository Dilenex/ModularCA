using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.5: the certificates a CA has had over time
    /// (<c>docs/architecture/ca-certificate-renewal.md</c>). Renewing a CA's certificate over
    /// its key gives the CA a second certificate; a row here says which CA each belongs to, over
    /// which key, and how and when it became the CA's. The table starts empty and nothing is
    /// changed in any other table: a CA that was never renewed has no row, and its certificate
    /// is the one its own row names, as before.
    /// </summary>
    public partial class CaCertificates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CaCertificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    KeyId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Origin = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    ActivatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SupersededAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CeremonyId = table.Column<Guid>(type: "uuid", nullable: true),
                    Actor = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaCertificates_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_CertificateAuthorityId",
                table: "CaCertificates",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_CertificateId",
                table: "CaCertificates",
                column: "CertificateId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CaCertificates");
        }
    }
}
