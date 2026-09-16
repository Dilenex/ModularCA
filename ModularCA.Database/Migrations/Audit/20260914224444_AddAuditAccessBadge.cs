using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations.Audit
{
    /// <inheritdoc />
    public partial class AddAuditAccessBadge : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "AccessBadgeId",
                table: "AuditLogs",
                type: "char(36)",
                nullable: true,
                collation: "ascii_general_ci");

            migrationBuilder.AddColumn<string>(
                name: "AccessBadgeName",
                table: "AuditLogs",
                type: "varchar(100)",
                maxLength: 100,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AccessBadgeId",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "AccessBadgeName",
                table: "AuditLogs");
        }
    }
}
