using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Seeds the <c>Public</c> whitelist rule so the relying-party portal is reachable by the
    /// people it exists for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>/public/*</c> and <c>/api/v1/public/info</c> had no scope of their own, so they fell
    /// through to the <c>System</c> rule — RFC1918 and loopback — and answered 403 to every caller
    /// outside the network. That is the opposite of what the portal is for: someone fetching the CA
    /// certificate has no trust in this CA yet, which is the reason for the visit, and
    /// <c>HttpSchemeEnforcementMiddleware</c> already allow-lists <c>/public</c> over plain HTTP on
    /// exactly that reasoning.
    /// </para>
    /// <para>
    /// It stayed invisible because a reverse proxy was making every caller look internal. Once the
    /// proxy was configured to forward the real client address, the whitelist began judging
    /// correctly and the portal started refusing the internet — the fix revealing the gap rather
    /// than causing it.
    /// </para>
    /// <para>
    /// This covers the portal and the info endpoint its footer reads, and nothing else. CRL, CA,
    /// OCSP and TSA under <c>/api/v1/public/</c> are matched earlier in <c>DerivePathBucket</c> and
    /// keep their own per-protocol rules, so an operator can publish OCSP while keeping the portal
    /// internal, or the reverse.
    /// </para>
    /// <para>
    /// Seeded open, which is unlike every other scope and is the point: this is the one surface
    /// whose audience is external. An air-gapped or internal-only deployment should tighten it —
    /// possible precisely because this is a rule rather than a path exemption, so it is visible in
    /// the admin Whitelists page, editable without a restart, and recorded in
    /// <c>AuditNetwork.Blocked</c> when it denies.
    /// </para>
    /// <para>
    /// Idempotent via the unique index on <c>(Scope, CertificateAuthorityId, Protocol)</c>: an
    /// install that already has a Public rule, including one an operator narrowed by hand, keeps it.
    /// </para>
    /// </remarks>
    public partial class SeedPublicPortalWhitelist : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Scope is persisted as a string column, so this is the enum name rather than its
            // ordinal — which also means appending to the enum cannot renumber anything.
            migrationBuilder.Sql(@"
                INSERT INTO `Whitelists`
                    (`Id`, `Name`, `Description`, `Scope`, `CertificateAuthorityId`, `Protocol`,
                     `Cidrs`, `IsEnabled`, `IsSystemDefault`, `CreatedAt`, `UpdatedAt`)
                SELECT
                    UUID(),
                    'Public Portal',
                    'The relying-party portal (/public) and the public info endpoint its footer reads. Open by default because the people it serves are outside the network by definition. Protocol endpoints under /api/v1/public/ keep their own per-protocol rules. Tighten this on an air-gapped or internal-only deployment.',
                    'Public',
                    NULL,
                    NULL,
                    '[""0.0.0.0/0"",""::/0""]',
                    1,
                    1,
                    UTC_TIMESTAMP(),
                    UTC_TIMESTAMP()
                FROM DUAL
                WHERE NOT EXISTS (
                    SELECT 1 FROM `Whitelists`
                    WHERE `Scope` = 'Public'
                      AND `CertificateAuthorityId` IS NULL
                      AND `Protocol` IS NULL
                );");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Only the untouched system default is removed. A rule an operator edited — narrowed to
            // their own ranges, or disabled — is theirs, and a down-migration silently discarding
            // that decision would be worse than leaving a row behind.
            migrationBuilder.Sql(@"
                DELETE FROM `Whitelists`
                WHERE `Scope` = 'Public'
                  AND `CertificateAuthorityId` IS NULL
                  AND `Protocol` IS NULL
                  AND `IsSystemDefault` = 1
                  AND `Cidrs` = '[""0.0.0.0/0"",""::/0""]';");
        }
    }
}
