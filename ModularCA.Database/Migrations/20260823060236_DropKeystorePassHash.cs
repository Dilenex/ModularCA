using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Removes <c>Keystores.PassHash</c>, which held <c>Base64(SHA256(master passphrase))</c> —
    /// unsalted and single-round.
    /// <para>
    /// It was written once at bootstrap and read by nothing, anywhere. That made it pure
    /// downside: a standing offline-cracking target on the one secret that unwraps every CA
    /// private key in the install, sitting in the same database an attacker would already need
    /// to reach for most other purposes. Deleting the column is the whole mitigation; there is
    /// no replacement, because nothing needed the value.
    /// </para>
    /// <para>
    /// The passphrase still reaches this table, but only inside <c>Passblob</c>, AES-GCM
    /// encrypted under the wrapping KEK.
    /// </para>
    /// </summary>
    public partial class DropKeystorePassHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // EF flags this as possible data loss. It is intentional and the point of the
            // migration: the column's contents are a weak hash of a secret nothing consumes.
            migrationBuilder.DropColumn(
                name: "PassHash",
                table: "Keystores");
        }

        /// <summary>
        /// Recreates the column for schema symmetry only. Existing rows get the implicit empty
        /// default and nothing repopulates them, which is harmless precisely because no code
        /// path ever read this value.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PassHash",
                table: "Keystores",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
