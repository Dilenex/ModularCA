using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations.Audit
{
    /// <inheritdoc />
    public partial class AuditRecordSpace : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "SpaceId",
                table: "AuditLogs",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SpaceId",
                table: "AuditLogs");
        }
    }
}
