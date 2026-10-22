using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: where each SSH CA key is held. <c>SshCaKeys.KeyStorage</c> is <c>Signer</c> for a
    /// new row; every row that has a key file path, which is every row written before this, is
    /// set to <c>LegacyFile</c>, so the signer imports its key once and nothing treats it as
    /// held until then. <c>PrivateKeyPath</c> becomes nullable, for rows whose key the signer
    /// holds. A column, a backfill and a relaxed constraint; nothing to refuse.
    /// </summary>
    public partial class SshKeyStorage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "PrivateKeyPath",
                table: "SshCaKeys",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(500)",
                oldMaxLength: 500);

            migrationBuilder.AddColumn<string>(
                name: "KeyStorage",
                table: "SshCaKeys",
                type: "character varying(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Signer");

            migrationBuilder.Sql(
                """UPDATE "SshCaKeys" SET "KeyStorage" = 'LegacyFile' WHERE "PrivateKeyPath" IS NOT NULL AND "PrivateKeyPath" <> '';""");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "KeyStorage",
                table: "SshCaKeys");

            migrationBuilder.Sql("""UPDATE "SshCaKeys" SET "PrivateKeyPath" = '' WHERE "PrivateKeyPath" IS NULL;""");

            migrationBuilder.AlterColumn<string>(
                name: "PrivateKeyPath",
                table: "SshCaKeys",
                type: "character varying(500)",
                maxLength: 500,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "character varying(500)",
                oldMaxLength: 500,
                oldNullable: true);
        }
    }
}
