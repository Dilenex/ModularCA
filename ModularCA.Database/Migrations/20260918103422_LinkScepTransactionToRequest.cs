using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class LinkScepTransactionToRequest : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CertRequestId",
                table: "ScepTransactions",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.CreateIndex(
                name: "IX_ScepTransactions_CertRequestId",
                table: "ScepTransactions",
                column: "CertRequestId");

            migrationBuilder.AddForeignKey(
                name: "FK_ScepTransactions_CertificateRequests_CertRequestId",
                table: "ScepTransactions",
                column: "CertRequestId",
                principalTable: "CertificateRequests",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ScepTransactions_CertificateRequests_CertRequestId",
                table: "ScepTransactions");

            migrationBuilder.DropIndex(
                name: "IX_ScepTransactions_CertRequestId",
                table: "ScepTransactions");

            migrationBuilder.DropColumn(
                name: "CertRequestId",
                table: "ScepTransactions");
        }
    }
}
