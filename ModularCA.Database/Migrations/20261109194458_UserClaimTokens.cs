using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.4: one-time account claims. One row per account at most, holding the SHA-256 of a claim
    /// token, when it expires and what issued it; <c>POST /api/v1/auth/claim</c> sets the account's
    /// password with the token once and deletes the row. The headless bootstrap writes one when
    /// bootstrap.yaml gives <c>Administration.ClaimTokenSha256</c>, and <c>--issue-claim-token</c>
    /// writes one on the host. Table creation only; nothing to refuse, and no existing account is
    /// changed.
    /// </summary>
    public partial class UserClaimTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserClaimTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenHash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IssuedBy = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserClaimTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserClaimTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserClaimTokens_UserId",
                table: "UserClaimTokens",
                column: "UserId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserClaimTokens");
        }
    }
}
