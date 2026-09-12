using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Drops <c>RequestProfiles.MaxValidityPeriod</c>, which duplicated
    /// <c>CertProfiles.ValidityPeriodMax</c> and was enforced nowhere.
    /// </summary>
    /// <remarks>
    /// The column was seeded with real values, surfaced in the admin UI as an editable field,
    /// carried through inheritance resolution and clamped against parent profiles — and then
    /// read by no issuance code path. Operators could type a ceiling into it and nothing applied
    /// it. Validity is a property of the certificate, so the certificate profile is where the
    /// ceiling belongs, and that one is enforced.
    ///
    /// No effective policy is lost. The cert profile ceiling was always the operative one, and
    /// across every seeded profile it is equal to or tighter than the value this column held.
    /// </remarks>
    public partial class DropRequestProfileMaxValidityPeriod : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MaxValidityPeriod",
                table: "RequestProfiles");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MaxValidityPeriod",
                table: "RequestProfiles",
                type: "varchar(50)",
                maxLength: 50,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
