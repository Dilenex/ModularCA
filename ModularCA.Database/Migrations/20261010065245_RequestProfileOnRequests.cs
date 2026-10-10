using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: a certificate request records the request profile it was made under.
    /// <c>CertificateRequests.RequestProfileId</c> is added, nullable, as a reference to
    /// <c>RequestProfiles</c> that is cleared when the profile is deleted. It is left null on
    /// every existing request, which reads as made under no profile, so nothing already
    /// submitted is held to a rule it was not submitted under. A column; nothing to refuse.
    /// </summary>
    public partial class RequestProfileOnRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "RequestProfileId",
                table: "CertificateRequests",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_RequestProfileId",
                table: "CertificateRequests",
                column: "RequestProfileId");

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateRequests_RequestProfiles_RequestProfileId",
                table: "CertificateRequests",
                column: "RequestProfileId",
                principalTable: "RequestProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CertificateRequests_RequestProfiles_RequestProfileId",
                table: "CertificateRequests");

            migrationBuilder.DropIndex(
                name: "IX_CertificateRequests_RequestProfileId",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "RequestProfileId",
                table: "CertificateRequests");
        }
    }
}
