using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations.Audit
{
    /// <inheritdoc />
    public partial class RenameCertVulnerabilitiesToComplianceFindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The audit user (modularca_audit) is intentionally NOT granted DROP, so the audit
            // schema survives --reset --force. MySQL's RENAME TABLE / ALTER TABLE ... RENAME both
            // require the DROP privilege on the source table, so a normal rename fails here with
            // "command denied ... CertVulnerabilities". Instead we copy the table next to the
            // original using only CREATE + SELECT + INSERT (all granted), then leave the old
            // CertVulnerabilities table in place untouched.
            //
            // CREATE TABLE ... LIKE reproduces the structure exactly (columns, charset/collation,
            // and the implicit PRIMARY key — the audit copy has no secondary indexes). INSERT IGNORE
            // copies existing rows so the active table keeps full audit history and the migration is
            // safe to re-run if a prior attempt half-completed (DDL auto-commits in MySQL).
            migrationBuilder.Sql(
                "CREATE TABLE IF NOT EXISTS `CertComplianceFindings` LIKE `CertVulnerabilities`;");
            migrationBuilder.Sql(
                "INSERT IGNORE INTO `CertComplianceFindings` SELECT * FROM `CertVulnerabilities`;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // No-op: the original CertVulnerabilities table was never removed (the audit user lacks
            // DROP), so reverting simply means the app stops writing to CertComplianceFindings. We
            // cannot drop the copied table from this connection for the same reason.
        }
    }
}
