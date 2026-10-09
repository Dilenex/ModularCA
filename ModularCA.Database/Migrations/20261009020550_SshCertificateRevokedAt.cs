using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: when an SSH certificate was revoked. <c>SshCertificates.RevokedAt</c> is added
    /// empty: a certificate revoked before this keeps no time, since none was recorded, and no
    /// row is otherwise changed. A partial index over the revoked rows of each SSH CA key
    /// serves the count and the newest revocation that a KRL's version, generation time and
    /// ETag are read from on every poll. A column and an index; nothing to refuse.
    /// </summary>
    public partial class SshCertificateRevokedAt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RevokedAt",
                table: "SshCertificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificates_SshCaKeyId_RevokedAt",
                table: "SshCertificates",
                columns: new[] { "SshCaKeyId", "RevokedAt" },
                filter: "\"IsRevoked\"");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SshCertificates_SshCaKeyId_RevokedAt",
                table: "SshCertificates");

            migrationBuilder.DropColumn(
                name: "RevokedAt",
                table: "SshCertificates");
        }
    }
}
