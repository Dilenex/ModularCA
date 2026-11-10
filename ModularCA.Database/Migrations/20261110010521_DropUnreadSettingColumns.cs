using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.4: drops two setting columns nothing has read since 0.4.4 stopped exposing them:
    /// <c>CaProtocolConfigs.OcspSignResponses</c> (OCSP responses are always signed, as RFC 6960
    /// requires) and <c>NotificationPreferences.DaysBeforeExpiry</c> (no notification sender ever
    /// used it; certificate expiry email follows each certificate's expiry warning and
    /// <c>CertExpiryNotification.WarningDaysBeforeExpiry</c>). Column drops only; nothing to
    /// refuse, and the values they held are lost. Down puts the columns back with the defaults the
    /// entities had (signed responses on, no days).
    /// </summary>
    public partial class DropUnreadSettingColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DaysBeforeExpiry",
                table: "NotificationPreferences");

            migrationBuilder.DropColumn(
                name: "OcspSignResponses",
                table: "CaProtocolConfigs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "DaysBeforeExpiry",
                table: "NotificationPreferences",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "OcspSignResponses",
                table: "CaProtocolConfigs",
                type: "boolean",
                nullable: false,
                defaultValue: true);
        }
    }
}
