using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Backfills the default OID catalog, repairing installations left unable to issue anything.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What went wrong.</b> <c>BootstrapProfileSeeder.LoadOidsToDb</c> used to return early when
    /// <c>OIDOptions</c> held any row at all. On a fresh install, migrations run before bootstrap
    /// seeds — so <c>20260829080000_SeedSmartCardAndKdcEkus</c>, itself written to work around that
    /// same early return on <em>upgrades</em>, inserted two Extended rows into an empty table, and
    /// the seeder then saw a non-empty catalog and skipped everything. The workaround for the guard
    /// tripped the guard.
    /// </para>
    /// <para>
    /// The observed end state on an affected install is the entire catalog:
    /// </para>
    /// <code>
    /// 1.3.6.1.4.1.311.20.2.2  smartcardLogon     Extended
    /// 1.3.6.1.5.2.3.5         kdcAuthentication  Extended
    /// </code>
    /// <para>
    /// No standard key usages and no <c>serverAuth</c>, which means no certificate of any kind can
    /// be issued: <c>IssuanceValidationService</c> resolves a profile's usages against this table,
    /// resolves none, and refuses with <c>MCA-POL-000</c> rather than emitting a certificate with no
    /// KeyUsage extension — which RFC 5280 leaves unrestricted for every usage. The refusal is
    /// right; its wording sends the reader to the profile's spelling, and the profile is fine.
    /// </para>
    /// <para>
    /// Every install bootstrapped after 2026-08-29 is affected, and the damage is not limited to
    /// enrollment: bootstrap seeds its own profiles through the same resolver, so the CA's own
    /// certificates were built from empty usage lists too.
    /// </para>
    /// <para>
    /// <b>The general fix</b> is in the seeder, which now reconciles Standard and Extended
    /// independently and can no longer be satisfied by a partially populated table. This migration
    /// repairs the databases that already exist, where a first-run seeder will never execute again.
    /// </para>
    /// <para>
    /// Idempotent, deliberately: <c>OID</c> is the primary key and the upsert is a no-op on an
    /// existing row. An entry an operator renamed keeps their name — reverting it to the shipped
    /// default during an upgrade they did not ask for would be its own defect — and the two rows
    /// from the 2026-08-29 migration are left exactly as they are.
    /// </para>
    /// </remarks>
    public partial class BackfillOidCatalog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Values mirror the built-in defaults in YamlOIDLoader. Standard usages are keyed by
            // their KeyUsage bit position under 2.5.29.15 rather than a registered arc, which is
            // this catalog's existing convention and what the resolver already matches against.
            migrationBuilder.Sql(@"
                INSERT INTO `OIDOptions` (`OID`, `FriendlyName`, `IsDefaultEntry`, `KeyUsage`, `AddedOn`)
                VALUES
                    ('2.5.29.15.0', 'digitalSignature',  1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.1', 'nonRepudiation',    1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.2', 'keyEncipherment',   1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.3', 'dataEncipherment',  1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.4', 'keyAgreement',      1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.5', 'keyCertSign',       1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.6', 'crlSign',           1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.7', 'encipherOnly',      1, 'Standard', UTC_TIMESTAMP()),
                    ('2.5.29.15.8', 'decipherOnly',      1, 'Standard', UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE `OID` = `OID`;");

            migrationBuilder.Sql(@"
                INSERT INTO `OIDOptions` (`OID`, `FriendlyName`, `IsDefaultEntry`, `KeyUsage`, `AddedOn`)
                VALUES
                    ('1.3.6.1.5.5.7.3.1', 'serverAuth',      1, 'Extended', UTC_TIMESTAMP()),
                    ('1.3.6.1.5.5.7.3.2', 'clientAuth',      1, 'Extended', UTC_TIMESTAMP()),
                    ('1.3.6.1.5.5.7.3.3', 'codeSigning',     1, 'Extended', UTC_TIMESTAMP()),
                    ('1.3.6.1.5.5.7.3.4', 'emailProtection', 1, 'Extended', UTC_TIMESTAMP()),
                    ('1.3.6.1.5.5.7.3.8', 'timeStamping',    1, 'Extended', UTC_TIMESTAMP()),
                    ('1.3.6.1.5.5.7.3.9', 'OCSPSigning',     1, 'Extended', UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE `OID` = `OID`;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberately empty. Removing these returns the installation to a state where no
            // certificate can be issued at all, and a down-migration that breaks the CA is worse
            // than one leaving fifteen correct catalog rows behind. They are also no longer
            // distinguishable from rows an operator added themselves.
        }
    }
}
