using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.4: a per-user password source. <c>Users.PasswordSource</c> holds where an account's
    /// sign-in password is checked: <c>Inherit</c> (the instance LDAP setting), <c>Local</c> (the
    /// local hash only) or <c>Directory</c> (LDAP only). Every existing account gets the column
    /// default, <c>Inherit</c>, which is the rule every account followed before, so nothing signs in
    /// differently until an account is learned (its first accepted LDAP bind makes it
    /// <c>Directory</c>) or an administrator sets it. The bootstrap administrator of an existing
    /// install is not changed; only a new install creates it as <c>Local</c>.
    /// </summary>
    public partial class UserPasswordSource : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PasswordSource",
                table: "Users",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "Inherit");
        }

        /// <summary>
        /// Drops the column. Every account then follows the instance LDAP setting again, as
        /// <c>Inherit</c> does: a <c>Local</c> account loses password sign-in through an LDAP outage,
        /// and a <c>Directory</c> account's local hash is consulted again when the directory has no
        /// entry for it.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordSource",
                table: "Users");
        }
    }
}
