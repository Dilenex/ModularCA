using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddServiceIdentities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Users",
                type: "varchar(500)",
                maxLength: 500,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<bool>(
                name: "IsServiceIdentity",
                table: "Users",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "ServiceScopeCaId",
                table: "Users",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<Guid>(
                name: "ServiceScopeTenantId",
                table: "Users",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsServiceIdentity",
                table: "Users",
                column: "IsServiceIdentity");

            migrationBuilder.CreateIndex(
                name: "IX_Users_ServiceScopeCaId",
                table: "Users",
                column: "ServiceScopeCaId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_ServiceScopeTenantId",
                table: "Users",
                column: "ServiceScopeTenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_IsServiceIdentity",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_ServiceScopeCaId",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_ServiceScopeTenantId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "IsServiceIdentity",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ServiceScopeCaId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ServiceScopeTenantId",
                table: "Users");
        }
    }
}
