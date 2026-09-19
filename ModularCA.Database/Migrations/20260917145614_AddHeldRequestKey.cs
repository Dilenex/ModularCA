using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddHeldRequestKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "HeldKeyDeliveredAt",
                table: "CertificateRequests",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "HeldPrivateKey",
                table: "CertificateRequests",
                type: "longblob",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HeldPrivateKeyAlgorithm",
                table: "CertificateRequests",
                type: "varchar(64)",
                maxLength: 64,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HeldKeyDeliveredAt",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "HeldPrivateKey",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "HeldPrivateKeyAlgorithm",
                table: "CertificateRequests");
        }
    }
}
