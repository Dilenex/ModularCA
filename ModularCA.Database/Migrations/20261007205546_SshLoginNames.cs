using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: SSH login names. The table of login names granted on an SSH CA key to a user or
    /// to a group (exactly one, by a check constraint; once per key, name and target);
    /// <c>SshCaKeys.AllowOwnUsername</c>, true on every existing key; and on
    /// <c>SshCertificates</c> who the certificate is for (<c>SubjectUserId</c>) and why that
    /// subject held each login name (<c>LoginNameGrounds</c>). The subject is filled in only for
    /// a user certificate whose key id is exactly its issuer's username; no other row is
    /// changed and no certificate is revoked. A table, three columns and a backfill; nothing to refuse.
    /// </summary>
    public partial class SshLoginNames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "LoginNameGrounds",
                table: "SshCertificates",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SubjectUserId",
                table: "SshCertificates",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowOwnUsername",
                table: "SshCaKeys",
                type: "boolean",
                nullable: false,
                defaultValue: true);

            migrationBuilder.CreateTable(
                name: "SshLoginNameGrants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SshCaKeyId = table.Column<Guid>(type: "uuid", nullable: false),
                    LoginName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    GroupId = table.Column<Guid>(type: "uuid", nullable: true),
                    MaxValidityHours = table.Column<int>(type: "integer", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Note = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    GrantedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    GrantedByUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshLoginNameGrants", x => x.Id);
                    table.CheckConstraint("CK_SshLoginNameGrants_ExactlyOneTarget", "(\"UserId\" IS NULL) <> (\"GroupId\" IS NULL)");
                    table.ForeignKey(
                        name: "FK_SshLoginNameGrants_CaGroups_GroupId",
                        column: x => x.GroupId,
                        principalTable: "CaGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SshLoginNameGrants_SshCaKeys_SshCaKeyId",
                        column: x => x.SshCaKeyId,
                        principalTable: "SshCaKeys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SshLoginNameGrants_Users_GrantedByUserId",
                        column: x => x.GrantedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_SshLoginNameGrants_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificates_SubjectUserId",
                table: "SshCertificates",
                column: "SubjectUserId");

            migrationBuilder.CreateIndex(
                name: "IX_SshLoginNameGrants_GrantedByUserId",
                table: "SshLoginNameGrants",
                column: "GrantedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_SshLoginNameGrants_GroupId",
                table: "SshLoginNameGrants",
                column: "GroupId");

            migrationBuilder.CreateIndex(
                name: "IX_SshLoginNameGrants_SshCaKeyId_LoginName_GroupId",
                table: "SshLoginNameGrants",
                columns: new[] { "SshCaKeyId", "LoginName", "GroupId" },
                unique: true,
                filter: "\"GroupId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_SshLoginNameGrants_SshCaKeyId_LoginName_UserId",
                table: "SshLoginNameGrants",
                columns: new[] { "SshCaKeyId", "LoginName", "UserId" },
                unique: true,
                filter: "\"UserId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_SshLoginNameGrants_UserId",
                table: "SshLoginNameGrants",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_SshCertificates_Users_SubjectUserId",
                table: "SshCertificates",
                column: "SubjectUserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.Sql(
                """
                UPDATE "SshCertificates" c SET "SubjectUserId" = c."IssuedByUserId"
                FROM "Users" u
                WHERE u."Id" = c."IssuedByUserId" AND c."CertificateType" = 'user' AND c."KeyId" = u."Username"::text;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SshCertificates_Users_SubjectUserId",
                table: "SshCertificates");

            migrationBuilder.DropTable(
                name: "SshLoginNameGrants");

            migrationBuilder.DropIndex(
                name: "IX_SshCertificates_SubjectUserId",
                table: "SshCertificates");

            migrationBuilder.DropColumn(
                name: "LoginNameGrounds",
                table: "SshCertificates");

            migrationBuilder.DropColumn(
                name: "SubjectUserId",
                table: "SshCertificates");

            migrationBuilder.DropColumn(
                name: "AllowOwnUsername",
                table: "SshCaKeys");
        }
    }
}
