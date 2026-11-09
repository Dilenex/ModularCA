using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.3: profile-driven certificate expiry warnings. Each certificate stores when its soft
    /// warning and its alert start (<c>ExpiryWarningAt</c>, <c>ExpiryAlertAt</c>, indexed on the
    /// first), and a certificate profile may set both levels (a percent of the lifetime and an
    /// optional longest window), never warn, and override its parent's settings.
    /// <para>
    /// Every existing certificate is given its instants from the rule as first released, written
    /// here as constants: an end-entity certificate warns when 30 % of its lifetime remains and
    /// alerts at 10 %; a CA certificate warns 30 days and alerts 7 days before it expires; neither
    /// before it became valid. The arithmetic is in seconds: an interval in days would follow the
    /// session time zone across a daylight-saving change and move an instant by an hour. No
    /// profile sets anything yet, so nothing else applies. Then the
    /// instance's <c>Web TLS Certificate Profile</c>, which the console's own certificate is
    /// issued and renewed from by <c>TlsRenewalJob</c>, is set to never warn, and its certificates
    /// get both instants at their expiry. Last, the stored value of the retired
    /// <c>ComplianceScan.ExpiringWithinDays</c> setting is removed, so no start reports it as
    /// unknown.
    /// </para>
    /// </summary>
    public partial class ProfileExpiryWarnings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExpiryAlertMaxWindow",
                table: "CertProfiles",
                type: "character varying(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ExpiryAlertPercent",
                table: "CertProfiles",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ExpiryNeverWarn",
                table: "CertProfiles",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ExpiryWarningMaxWindow",
                table: "CertProfiles",
                type: "character varying(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ExpiryWarningOverridesParent",
                table: "CertProfiles",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "ExpiryWarningPercent",
                table: "CertProfiles",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiryAlertAt",
                table: "Certificates",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiryWarningAt",
                table: "Certificates",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.Sql(
                """
                UPDATE "Certificates"
                SET "ExpiryWarningAt" = "NotAfter" - make_interval(secs => CASE WHEN "IsCA"
                        THEN LEAST(2592000, GREATEST(EXTRACT(EPOCH FROM ("NotAfter" - "NotBefore"))::double precision, 0))
                        ELSE GREATEST(EXTRACT(EPOCH FROM ("NotAfter" - "NotBefore"))::double precision, 0) * 0.3 END),
                    "ExpiryAlertAt" = "NotAfter" - make_interval(secs => CASE WHEN "IsCA"
                        THEN LEAST(604800, GREATEST(EXTRACT(EPOCH FROM ("NotAfter" - "NotBefore"))::double precision, 0))
                        ELSE GREATEST(EXTRACT(EPOCH FROM ("NotAfter" - "NotBefore"))::double precision, 0) * 0.1 END);
                """);

            migrationBuilder.Sql(
                """
                WITH web_tls AS (
                    UPDATE "CertProfiles"
                    SET "ExpiryNeverWarn" = true, "UpdatedAt" = now()
                    WHERE "Name" = 'Web TLS Certificate Profile'
                      AND "SpaceId" IS NULL AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile"
                    RETURNING "Id"
                )
                UPDATE "Certificates" c
                SET "ExpiryWarningAt" = c."NotAfter", "ExpiryAlertAt" = c."NotAfter"
                FROM web_tls
                WHERE c."CertProfileId" = web_tls."Id";
                """);

            migrationBuilder.Sql(
                """
                DELETE FROM "Settings" WHERE "Key" = 'ComplianceScan_ExpiringWithinDays';
                """);

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_ExpiryWarningAt",
                table: "Certificates",
                column: "ExpiryWarningAt");
        }

        /// <summary>
        /// Drops the expiry warning columns and their index. The stored
        /// <c>ComplianceScan_ExpiringWithinDays</c> value that <see cref="Up"/> deleted was not kept
        /// anywhere, so it is not restored: after a rollback to 0.4.2 the setting is back at its
        /// default, 30 days, until it is set again.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_ExpiryWarningAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "ExpiryAlertMaxWindow",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryAlertPercent",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryNeverWarn",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryWarningMaxWindow",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryWarningOverridesParent",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryWarningPercent",
                table: "CertProfiles");

            migrationBuilder.DropColumn(
                name: "ExpiryAlertAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "ExpiryWarningAt",
                table: "Certificates");
        }
    }
}
