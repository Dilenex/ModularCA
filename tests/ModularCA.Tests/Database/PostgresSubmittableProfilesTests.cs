using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// <see cref="SubmittableProfiles"/> and <see cref="BodyTargetAuthorization.AllowedSigningProfileIdsAsync"/>
/// against a real PostgreSQL database migrated to the latest migration: the queries behind the
/// self-service profile lists translate, and a requester of one CA gets that CA's signing profile
/// and not its sibling's. The rule itself is covered on the in-memory provider by
/// <c>SelfServiceProfileListTests</c>. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresSubmittableProfilesTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_requester_gets_the_signing_profiles_of_their_ca_on_postgres() =>
        OnPostgresAsync(async db =>
        {
            var tag = Guid.NewGuid().ToString("N")[..8];
            var space = new SpaceEntity { Id = Guid.NewGuid(), Name = $"S {tag}", Slug = $"s-{tag}" };
            db.Spaces.Add(space);

            (CertificateAuthorityEntity Ca, SigningProfileEntity Signing) Ca(string name)
            {
                var id = Guid.NewGuid();
                db.Certificates.Add(new CertificateEntity
                {
                    CertificateId = id, SerialNumber = id.ToString("N")[..16], SubjectDN = $"CN={name} {tag}", Issuer = $"CN={name} {tag}",
                    Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----", NotBefore = DateTime.UtcNow.AddDays(-1),
                    NotAfter = DateTime.UtcNow.AddYears(1), IsCA = true, IssuerCertificateId = id,
                });
                var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{name} {tag}", Label = $"{name}-{tag}", SpaceId = space.Id, CertificateId = id, Type = "Root", IsEnabled = true };
                var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"{name}-signing-{tag}", IssuerId = id };
                db.CertificateAuthorities.Add(ca);
                db.SigningProfiles.Add(signing);
                return (ca, signing);
            }

            var one = Ca("one");
            var two = Ca("two");
            var unbound = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"unbound-signing-{tag}" };
            db.SigningProfiles.Add(unbound);
            await db.SaveChangesAsync();

            Guid User(string name, Guid? caId, bool system, params string[] capabilities)
            {
                var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"{name}-{tag}", DisplayName = name, SpaceId = system ? null : space.Id, CertificateAuthorityId = caId, IsSystemGroup = system };
                db.CaGroups.Add(group);
                foreach (var capability in capabilities)
                    db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = capability });
                var id = Guid.NewGuid();
                db.Users.Add(new UserEntity { Id = id, Username = $"{name}-{tag}", Email = $"{name}-{tag}@example.test" });
                db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = id });
                return id;
            }

            var requester = User("requester", one.Ca.Id, false, Capabilities.RequesterTemplate);
            var auditor = User("auditor", one.Ca.Id, false, Capabilities.AuditorTemplate);
            var admin = User("admin", null, true, Capabilities.AdministratorTemplate);
            await db.SaveChangesAsync();

            var auth = new CaGroupAuthorizationService(db, NullLogger<CaGroupAuthorizationService>.Instance);
            async Task<SubmittableProfiles> For(Guid user)
                => await SubmittableProfiles.ForAsync(auth, db, (await auth.GetFenceAsync(user)).For(Capabilities.CertRequest), user);

            var mine = await For(requester);
            Assert.Equal(new[] { one.Signing.Id }, mine.SigningProfiles.Select(s => s.Id));
            Assert.Equal(one.Ca.Id, mine.SigningProfiles[0].CaId);
            Assert.True(mine.AdmitsRequestProfile(null));
            Assert.True(mine.AdmitsRequestProfile(one.Ca.Id));
            Assert.False(mine.AdmitsRequestProfile(two.Ca.Id));
            Assert.True(mine.AdmitsCertProfile(null, space.Id, one.Ca.Id));
            Assert.False(mine.AdmitsCertProfile(null, space.Id, two.Ca.Id));

            Assert.Empty((await For(auditor)).SigningProfiles);
            Assert.Equal(
                new[] { one.Signing.Id, two.Signing.Id, unbound.Id }.Order(),
                (await For(admin)).SigningProfiles.Select(s => s.Id).Order());
        });

    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_subm");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await scenario(db);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await using var admin = new NpgsqlConnection(server);
            await admin.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)", admin);
            await drop.ExecuteNonQueryAsync();
        }
    }
}
