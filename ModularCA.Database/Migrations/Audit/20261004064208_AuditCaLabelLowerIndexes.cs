using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations.Audit
{
    /// <summary>
    /// Indexes <c>lower("CaLabel")</c> on the protocol audit tables, the predicate
    /// <c>CaLabelRules.LabelReferencesAsync</c> uses (<c>CaLabel.ToLower() == label</c>) to decide
    /// whether a CA's label is referenced and so locked. The plain <c>CaLabel</c> indexes cannot
    /// serve it. Expression indexes are not part of the EF model, so the snapshot is unchanged.
    /// </summary>
    public partial class AuditCaLabelLowerIndexes : Migration
    {
        private static readonly string[] Tables = ["AuditEst", "AuditScep", "AuditCmp", "AuditMsae", "AuditAcme"];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            foreach (var table in Tables)
                migrationBuilder.Sql($"""CREATE INDEX IF NOT EXISTS "IX_{table}_CaLabel_lower" ON "{table}" (lower("CaLabel"));""");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach (var table in Tables)
                migrationBuilder.Sql($"""DROP INDEX IF EXISTS "IX_{table}_CaLabel_lower";""");
        }
    }
}
