using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddTenantValidityCeilingBehavior : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // defaultValue 0 is ValidityCeilingBehavior.Shorten, so every existing tenant keeps the
            // behaviour it already had. Upgrading must not start refusing issuance that worked
            // yesterday.
            migrationBuilder.AddColumn<int>(
                name: "ValidityCeilingBehavior",
                table: "Tenants",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ValidityCeilingBehavior",
                table: "Tenants");
        }
    }
}
