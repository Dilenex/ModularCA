using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: a certificate can be retired (no renewal or reissue from it, no expiry warning) or
    /// have its expiry warning dismissed. Nullable columns only; every existing certificate is
    /// neither.
    /// </summary>
    public partial class CertificateRetireAndDismiss : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiryWarningDismissedAt",
                table: "Certificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExpiryWarningDismissedBy",
                table: "Certificates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "RetiredAt",
                table: "Certificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RetiredBy",
                table: "Certificates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RetiredReason",
                table: "Certificates",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExpiryWarningDismissedAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "ExpiryWarningDismissedBy",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "RetiredAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "RetiredBy",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "RetiredReason",
                table: "Certificates");
        }
    }
}
