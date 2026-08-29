using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Adds the two extended key usages a Windows smart-card logon deployment needs to the
    /// <c>OIDOptions</c> catalog.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>BootstrapProfileSeeder.LoadOidsToDb</c> returns early when the table already has rows,
    /// so an install that was bootstrapped before these entries existed never picks them up — the
    /// seeder is a first-run operation, not a reconciliation. Without a catalog row, issuance
    /// silently drops the usage (<c>IssuanceValidationService</c> resolves against this table and
    /// discards what it cannot find), and the profile validator refuses the profile outright.
    /// </para>
    /// <list type="bullet">
    /// <item><b>smartcardLogon</b> (<c>1.3.6.1.4.1.311.20.2.2</c>) — the EKU Windows requires on
    /// the certificate presented by the card. Present in the built-in defaults, so most installs
    /// already have it; included here because an install seeded from a hand-written
    /// <c>config/OIDSeed.yaml</c> may not.</item>
    /// <item><b>kdcAuthentication</b> (<c>1.3.6.1.5.2.3.5</c>, RFC 4556 id-pkinit-KPKdc) — required
    /// on the <em>domain controller's</em> certificate, not the card's. A deployment with no AD CS
    /// has to issue that certificate from somewhere, and until now this CA could not: the usage
    /// was in neither the catalog nor the validator's hardcoded allow-list. Smart-card logon
    /// against a DC with no KDC certificate fails with KDC_ERR_PADATA_TYPE_NOSUPP, which looks
    /// like a client-side problem and is not.</item>
    /// </list>
    /// <para>
    /// Idempotent: <c>OID</c> is the primary key and the upsert is a no-op on an existing row, so
    /// an install that already has either entry keeps it, including a non-default one an operator
    /// added by hand.
    /// </para>
    /// </remarks>
    public partial class SeedSmartCardAndKdcEkus : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                INSERT INTO `OIDOptions` (`OID`, `FriendlyName`, `IsDefaultEntry`, `KeyUsage`, `AddedOn`)
                VALUES ('1.3.6.1.4.1.311.20.2.2', 'smartcardLogon', 1, 'Extended', UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE `OID` = `OID`;");

            migrationBuilder.Sql(@"
                INSERT INTO `OIDOptions` (`OID`, `FriendlyName`, `IsDefaultEntry`, `KeyUsage`, `AddedOn`)
                VALUES ('1.3.6.1.5.2.3.5', 'kdcAuthentication', 1, 'Extended', UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE `OID` = `OID`;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberately empty. Removing a catalog row is not the inverse of adding one: any
            // profile that has since referenced either OID would silently lose that usage at
            // issuance, because IssuanceValidationService drops what it cannot resolve. Two extra
            // rows in a reference table cost nothing; a certificate quietly issued without its
            // Smart Card Logon EKU costs a logon failure nobody can explain.
        }
    }
}
