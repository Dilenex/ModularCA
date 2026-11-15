using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.5: the storage for two tighter defaults, written so that an installed instance keeps
    /// every setting it has. Nothing is refused and no value an administrator set is lost.
    /// <list type="number">
    /// <item><c>SecurityPolicy.MaxSessionLifetimeDays</c> becomes <c>MaxSessionLifetimeHours</c>,
    /// and the stored value is multiplied by 24, so the 14 days an install has still means 14 days
    /// (336 hours) and 0 still means no maximum. Only a new install gets the new default of 12
    /// hours, from the entity when bootstrap seeds the row.</item>
    /// <item><c>PasswordPolicy.UseBundledBlocklist</c> is added, false for the existing row: an
    /// install that did not check the bundled blocklist before does not start to. Its own
    /// dictionary, when one is set, is checked as before.</item>
    /// <item>An installed instance (one with users) that has no <c>PasswordPolicy</c> row gets one
    /// holding the defaults it has been running on (12 characters, the four character classes, 90
    /// days), because the fallback for a missing row is the entity's defaults and those are now
    /// the NIST SP 800-63B preset. A fresh database gets no row here; bootstrap seeds the new
    /// defaults.</item>
    /// </list>
    /// </summary>
    public partial class TighterDefaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "MaxSessionLifetimeDays",
                table: "SecurityPolicy",
                newName: "MaxSessionLifetimeHours");

            // Days to hours, capped at what the column can hold (89 million days and up).
            migrationBuilder.Sql(
                """
                UPDATE "SecurityPolicy"
                SET "MaxSessionLifetimeHours" = LEAST("MaxSessionLifetimeHours"::bigint * 24, 2147483647)::integer;
                """);

            migrationBuilder.AddColumn<bool>(
                name: "UseBundledBlocklist",
                table: "PasswordPolicy",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.Sql(
                """
                INSERT INTO "PasswordPolicy" (
                    "Id", "MinLength", "MaxLength", "RequireUppercase", "RequireLowercase", "RequireDigit", "RequireSymbol",
                    "MinUppercase", "MinLowercase", "MinDigits", "MinSpecial", "MaxAgeDays", "HistoryCount",
                    "UseBundledBlocklist", "DictionaryPath", "DictionaryIsHashed", "UpdatedAt")
                SELECT gen_random_uuid(), 12, 128, true, true, true, true,
                    0, 0, 0, 0, 90, 0,
                    false, NULL, false, now()
                WHERE NOT EXISTS (SELECT 1 FROM "PasswordPolicy")
                  AND EXISTS (SELECT 1 FROM "Users");
                """);
        }

        /// <summary>
        /// Drops <c>UseBundledBlocklist</c> and turns the maximum session lifetime back into days,
        /// rounded up so that a maximum under a day (the 12 hours of a new install) becomes one
        /// day and not 0, which would mean no maximum. A password policy row added by <c>Up</c>
        /// stays: it holds what the older build's defaults were.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UseBundledBlocklist",
                table: "PasswordPolicy");

            migrationBuilder.Sql(
                """
                UPDATE "SecurityPolicy"
                SET "MaxSessionLifetimeHours" = CASE WHEN "MaxSessionLifetimeHours" <= 0 THEN "MaxSessionLifetimeHours"
                                                     ELSE ("MaxSessionLifetimeHours" + 23) / 24 END;
                """);

            migrationBuilder.RenameColumn(
                name: "MaxSessionLifetimeHours",
                table: "SecurityPolicy",
                newName: "MaxSessionLifetimeDays");
        }
    }
}
