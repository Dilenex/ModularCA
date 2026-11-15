using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.5: revocation of what the database does not hold
    /// (<c>docs/architecture/rollback-continuity.md</c>, section 5). Adds the table of revoked
    /// serials with no certificate row (tombstones), which the CRL lists and OCSP answers from,
    /// and three nullable columns on <c>Certificates</c> that mark a row as adopted from outside:
    /// when, by whom and why. Additive only: no existing row changes, and an empty database is
    /// left empty.
    /// </summary>
    public partial class RevokedSerialTombstones : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "AdoptedAt",
                table: "Certificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AdoptedBy",
                table: "Certificates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AdoptionNote",
                table: "Certificates",
                type: "character varying(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "RevokedSerialTombstones",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CaCertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: false),
                    IssuerDN = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    SerialNumber = table.Column<string>(type: "citext", maxLength: 64, nullable: false),
                    RevocationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RevocationReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    InvalidityDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ListedUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Note = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedByUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RevokedSerialTombstones", x => x.Id);
                    table.CheckConstraint("CK_RevokedSerialTombstones_SerialNumber_Length", "length(\"SerialNumber\") <= 64");
                    table.ForeignKey(
                        name: "FK_RevokedSerialTombstones_Certificates_CaCertificateId",
                        column: x => x.CaCertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RevokedSerialTombstones_CaCertificateId_SerialNumber",
                table: "RevokedSerialTombstones",
                columns: new[] { "CaCertificateId", "SerialNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RevokedSerialTombstones_CertificateAuthorityId",
                table: "RevokedSerialTombstones",
                column: "CertificateAuthorityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RevokedSerialTombstones");

            migrationBuilder.DropColumn(
                name: "AdoptedAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "AdoptedBy",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "AdoptionNote",
                table: "Certificates");
        }
    }
}
