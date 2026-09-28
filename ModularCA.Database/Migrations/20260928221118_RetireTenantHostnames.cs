using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0 S2: tenant hostnames are retired. Refuses while any row remains, so no name an
    /// operator configured disappears silently; then drops the table. Down recreates it empty.
    /// </summary>
    public partial class RetireTenantHostnames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.FailIf(
                "EXISTS (SELECT 1 FROM \"TenantHostnames\")",
                "This instance has {0} tenant hostname(s), which 0.4.0 no longer serves. Before upgrading, remove them "
                + "with a 0.3.x or 0.4.0-S1 build, or move those names to the instance's public domain or to a reverse proxy.",
                "(SELECT count(*) FROM \"TenantHostnames\")");

            migrationBuilder.DropTable(
                name: "TenantHostnames");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TenantHostnames",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    IssuingCaId = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Hostname = table.Column<string>(type: "citext", maxLength: 255, nullable: false),
                    NodeUpstream = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Notes = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantHostnames", x => x.Id);
                    table.CheckConstraint("CK_TenantHostnames_Hostname_Length", "length(\"Hostname\") <= 255");
                    table.ForeignKey(
                        name: "FK_TenantHostnames_CertificateAuthorities_IssuingCaId",
                        column: x => x.IssuingCaId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TenantHostnames_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_TenantHostnames_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_CertificateId",
                table: "TenantHostnames",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_Hostname",
                table: "TenantHostnames",
                column: "Hostname",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_IssuingCaId",
                table: "TenantHostnames",
                column: "IssuingCaId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_TenantId",
                table: "TenantHostnames",
                column: "TenantId");
        }
    }
}
