using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: what the signer was asked to certify when it signs an SSH certificate.
    /// <c>SignerAudit.Summary</c> holds the type, serial, key id, validity and the number of
    /// principals of a <c>SignSsh</c> decision, allowed or refused. The column is nullable and
    /// has no default: every row written before it, and every row of another operation, has
    /// none. One added column; nothing to backfill and nothing to refuse.
    /// </summary>
    public partial class SignerAuditSummary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Summary",
                table: "SignerAudit",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Summary",
                table: "SignerAudit");
        }
    }
}
