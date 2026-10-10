using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: four purpose-specific end-entity certificate profiles for an install that predates
    /// them (<c>TLS Server</c>, <c>Device Client</c>, <c>User Authentication and Email</c>,
    /// <c>Code Signing</c>), and a default certificate profile on each seeded request profile.
    /// <para>
    /// Rows are added only where <c>Main Certificate Profile</c> exists, so an empty database is
    /// left empty for bootstrap, which seeds the same profiles itself. A profile is added only
    /// when none has its name in any letter case (names are unique without regard to case), and is linked to every signing profile the main profile is linked
    /// to. A request profile gets a default only when it is one of the six seeded ones, bound to
    /// no CA, with no default and no allowed list of its own, and only from a profile this
    /// migration added (the web TLS request profile from the existing
    /// <c>Web TLS Certificate Profile</c>). No protocol configuration is touched. Nothing is
    /// overwritten and nothing is refused.
    /// </para>
    /// <para>
    /// The values are a frozen copy of <c>ModularCA.Shared.Utils.StandardCertProfiles</c> as
    /// first released.
    /// </para>
    /// </summary>
    public partial class StandardCertProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                WITH added AS (
                    INSERT INTO "CertProfiles" (
                        "Id", "Name", "Description", "IsCaProfile", "KeyUsages", "ExtendedKeyUsages",
                        "ValidityPeriodMin", "ValidityPeriodMax",
                        "AllowedKeyAlgorithms", "AllowedKeySizes", "AllowedSignatureAlgorithms",
                        "CreatedAt", "Revision", "UpdatedAt", "CanBeDeleted", "ProfileHash",
                        "CtEnabled", "AllowWildcard", "InheritanceEnabled")
                    SELECT gen_random_uuid(), v.name, v.description, false, v.key_usages, v.extended_key_usages,
                        'P1D', v.validity_max,
                        '["RSA","ECDSA","Ed25519","Ed448","ML-DSA-44","ML-DSA-65","ML-DSA-87","SLH-DSA-SHA2-128F"]',
                        '["2048","3072","4096","7680","8192","P-256","P-384","P-521"]',
                        '["SHA256withRSA","SHA384withRSA","SHA512withRSA","SHA256withRSAandMGF1","SHA384withRSAandMGF1","SHA512withRSAandMGF1","SHA256withECDSA","SHA384withECDSA","SHA512withECDSA","Ed25519","Ed448","ML-DSA-44","ML-DSA-65","ML-DSA-87","SLH-DSA-SHA2-128F"]',
                        now(), 0, now(), true, '',
                        false, false, false
                    FROM (VALUES
                        ('TLS Server', 'TLS server certificates. Server authentication only.',
                            '["digitalSignature","keyEncipherment"]', '["1.3.6.1.5.5.7.3.1"]', 'P397D'),
                        ('Device Client', 'Device certificates that authenticate as a TLS client.',
                            '["digitalSignature","keyEncipherment"]', '["1.3.6.1.5.5.7.3.2"]', 'P2Y'),
                        ('User Authentication and Email', 'User certificates for sign-in and for signed or encrypted mail.',
                            '["digitalSignature","keyEncipherment"]', '["1.3.6.1.5.5.7.3.2","1.3.6.1.5.5.7.3.4"]', 'P1Y'),
                        ('Code Signing', 'Code signing certificates. Digital signature only.',
                            '["digitalSignature"]', '["1.3.6.1.5.5.7.3.3"]', 'P1Y')
                    ) AS v(name, description, key_usages, extended_key_usages, validity_max)
                    WHERE EXISTS (SELECT 1 FROM "CertProfiles" m WHERE m."Name" = 'Main Certificate Profile')
                      AND NOT EXISTS (SELECT 1 FROM "CertProfiles" p WHERE lower(p."Name"::text) = lower(v.name))
                    RETURNING "Id", "Name"
                ), linked AS (
                    INSERT INTO "AllowedCertProfileSigningProfiles" ("Id", "CertProfileId", "SigningProfileId")
                    SELECT gen_random_uuid(), a."Id", l."SigningProfileId"
                    FROM added a
                    CROSS JOIN (
                        SELECT DISTINCT l."SigningProfileId"
                        FROM "AllowedCertProfileSigningProfiles" l
                        JOIN "CertProfiles" m ON m."Id" = l."CertProfileId"
                        WHERE m."Name" = 'Main Certificate Profile'
                    ) l
                    RETURNING 1
                )
                UPDATE "RequestProfiles" r
                SET "DefaultCertProfileId" = a."Id", "UpdatedAt" = now()
                FROM added a
                JOIN (VALUES
                    ('Web Server (ACME)', 'TLS Server'),
                    ('Enterprise Server (EST)', 'TLS Server'),
                    ('MDM Device (SCEP)', 'Device Client'),
                    ('Enterprise User (CMP)', 'User Authentication and Email'),
                    ('Code Signing', 'Code Signing')
                ) AS d(request_profile, cert_profile) ON d.cert_profile = a."Name"
                WHERE r."Name" = d.request_profile
                  AND r."CertificateAuthorityId" IS NULL
                  AND r."DefaultCertProfileId" IS NULL
                  AND btrim(coalesce(r."AllowedCertProfileIds", '')) IN ('', '[]');
                """);

            migrationBuilder.Sql(
                """
                UPDATE "RequestProfiles" r
                SET "DefaultCertProfileId" = c."Id", "UpdatedAt" = now()
                FROM "CertProfiles" c
                WHERE c."Name" = 'Web TLS Certificate Profile'
                  AND NOT c."IsCaProfile"
                  AND r."Name" = 'Web TLS (Internal)'
                  AND r."CertificateAuthorityId" IS NULL
                  AND r."DefaultCertProfileId" IS NULL
                  AND btrim(coalesce(r."AllowedCertProfileIds", '')) IN ('', '[]');
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
        }
    }
}
