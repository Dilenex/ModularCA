using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Repairs SSH request profiles whose CA scope was stored as a CA <em>certificate</em> id
    /// instead of the CA row id.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A certificate authority has two identifiers, and the admin UI's CA picker returned the
    /// wrong one: every such <c>&lt;select&gt;</c> was written <c>value={a.certificateId || a.id}</c>.
    /// That is correct for a signing profile's issuer and for a CRL schedule, which genuinely key
    /// on the certificate, and wrong for anything named <c>CertificateAuthorityId</c>, which is a
    /// reference to the <c>CertificateAuthorities</c> row.
    /// </para>
    /// <para>
    /// <c>CertProfiles</c> and <c>RequestProfiles</c> carry a real foreign key, so those writes
    /// were rejected and the scope simply could not be set — visibly broken, and nothing to
    /// repair. <c>SshRequestProfiles</c> has no such constraint, so the wrong id was accepted
    /// silently and the profile ended up scoped to a CA that does not exist: it matches no
    /// CA-scoped query and appears unscoped without saying so.
    /// </para>
    /// <para>
    /// The rewrite is deliberately narrow. A row is touched only when its current value matches no
    /// CA row AND does match some CA's certificate id, which is exactly the signature of this
    /// defect; a correctly scoped row matches a CA row and is left alone.
    /// </para>
    /// </remarks>
    public partial class RepairSshRequestProfileCaScope : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                UPDATE `SshRequestProfiles` AS p
                JOIN `CertificateAuthorities` AS byCert
                     ON byCert.`CertificateId` = p.`CertificateAuthorityId`
                LEFT JOIN `CertificateAuthorities` AS byRow
                     ON byRow.`Id` = p.`CertificateAuthorityId`
                SET p.`CertificateAuthorityId` = byCert.`Id`
                WHERE p.`CertificateAuthorityId` IS NOT NULL
                  AND byRow.`Id` IS NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberately empty. The previous values were wrong — they pointed at rows that do
            // not exist in the table the column references. Restoring them would only reinstate a
            // scope that silently matches nothing.
        }
    }
}
