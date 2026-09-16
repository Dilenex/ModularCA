using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class AddKerberosRealms : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "MsaeAllowKerberos",
                table: "CaProtocolConfigs",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "MsaeAllowUsernameToken",
                table: "CaProtocolConfigs",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "KerberosRealms",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    TenantId = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    Realm = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    DnsDomain = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ServicePrincipal = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    EnrollmentUserId = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    AllowMachines = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    AllowUsers = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Notes = table.Column<string>(type: "varchar(1000)", maxLength: 1000, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KerberosRealms", x => x.Id);
                    table.ForeignKey(
                        name: "FK_KerberosRealms_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_KerberosRealms_Users_EnrollmentUserId",
                        column: x => x.EnrollmentUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "KerberosRealmKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    RealmId = table.Column<Guid>(type: "char(36)", nullable: false, collation: "ascii_general_ci"),
                    Kvno = table.Column<int>(type: "int", nullable: false),
                    EncryptionType = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ProtectedKey = table.Column<string>(type: "varchar(1024)", maxLength: 1024, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Source = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RetireAfter = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KerberosRealmKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_KerberosRealmKeys_KerberosRealms_RealmId",
                        column: x => x.RealmId,
                        principalTable: "KerberosRealms",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealmKeys_RealmId_Kvno_EncryptionType",
                table: "KerberosRealmKeys",
                columns: new[] { "RealmId", "Kvno", "EncryptionType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_EnrollmentUserId",
                table: "KerberosRealms",
                column: "EnrollmentUserId");

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_Realm",
                table: "KerberosRealms",
                column: "Realm",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_TenantId",
                table: "KerberosRealms",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KerberosRealmKeys");

            migrationBuilder.DropTable(
                name: "KerberosRealms");

            migrationBuilder.DropColumn(
                name: "MsaeAllowKerberos",
                table: "CaProtocolConfigs");

            migrationBuilder.DropColumn(
                name: "MsaeAllowUsernameToken",
                table: "CaProtocolConfigs");
        }
    }
}
