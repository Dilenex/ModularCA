using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.4: the built-in Operator role gains <c>profile.use</c>, so an operator can approve and
    /// issue with the profiles of the CAs and spaces it operates. The role already held
    /// <c>cert.approve</c>, <c>cert.revoke</c> and <c>cert.reissue</c>, but approval and issuance
    /// also ask for <c>profile.use</c> on the signing and certificate profile, which it lacked.
    /// <para>
    /// A new install gets the capability from <c>Capabilities.OperatorTemplate</c>. This adds it
    /// to an existing one, in the two places a template's capabilities are kept: the built-in
    /// role named <c>Operator</c>, and the direct grants of every group made from the Operator
    /// template. A row is added only where no unrestricted <c>profile.use</c> is there already,
    /// so running it twice changes nothing. Custom roles and groups made from no template are
    /// left alone, and so is a grant that names one profile. An empty database is left empty.
    /// </para>
    /// <para>
    /// The capability name and the template name are frozen copies of
    /// <c>Capabilities.ProfileUse</c> and the built-in role's name as first released.
    /// </para>
    /// </summary>
    public partial class OperatorRoleUsesProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                INSERT INTO "RoleCapabilities" ("Id", "RoleId", "Capability")
                SELECT gen_random_uuid(), r."Id", 'profile.use'
                FROM "Roles" r
                WHERE r."Name" = 'Operator' AND r."IsBuiltIn"
                  AND NOT EXISTS (
                      SELECT 1 FROM "RoleCapabilities" c
                      WHERE c."RoleId" = r."Id" AND c."Capability" = 'profile.use'
                        AND c."ResourceType" IS NULL AND c."ResourceId" IS NULL);

                INSERT INTO "CapabilityGrants" ("Id", "GroupId", "Capability", "GrantedAt")
                SELECT gen_random_uuid(), g."Id", 'profile.use', now()
                FROM "CaGroups" g
                WHERE g."TemplateName" = 'Operator'
                  AND NOT EXISTS (
                      SELECT 1 FROM "CapabilityGrants" c
                      WHERE c."GroupId" = g."Id" AND c."Capability" = 'profile.use'
                        AND c."ResourceType" IS NULL AND c."ResourceId" IS NULL);
                """);
        }

        /// <summary>
        /// Nothing: the rows this added cannot be told from ones an administrator granted since,
        /// and removing a capability is an administrator's decision.
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
        }
    }
}
