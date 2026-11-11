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
/// <see cref="UserAdministrationAccess"/> against a real PostgreSQL database migrated to the
/// latest migration: the footprint queries translate and name the scopes an account holds
/// anything in, and the refusal follows them. The decision itself is covered on the in-memory
/// provider by <c>ScopedUserAdministrationTests</c>; this proves the queries run on the provider
/// production uses. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresUserAdministrationScopeTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_footprint_and_the_refusal_run_on_postgres() =>
        OnPostgresAsync(async db =>
        {
            var tag = Guid.NewGuid().ToString("N")[..8];
            var spaceA = new SpaceEntity { Id = Guid.NewGuid(), Name = $"A {tag}", Slug = $"a-{tag}" };
            var spaceB = new SpaceEntity { Id = Guid.NewGuid(), Name = $"B {tag}", Slug = $"b-{tag}" };
            db.Spaces.AddRange(spaceA, spaceB);

            CaGroupEntity Group(string name, Guid? spaceId, bool system, params string[] capabilities)
            {
                var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"{name}-{tag}", DisplayName = name, SpaceId = spaceId, IsSystemGroup = system };
                db.CaGroups.Add(group);
                foreach (var capability in capabilities)
                    db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = group.Id, Capability = capability });
                return group;
            }
            Guid User(string name, params CaGroupEntity[] groups)
            {
                var id = Guid.NewGuid();
                db.Users.Add(new UserEntity { Id = id, Username = $"{name}-{tag}", Email = $"{name}-{tag}@example.test" });
                foreach (var group in groups)
                    db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = id });
                return id;
            }

            var adminsA = Group("space-a-admins", spaceA.Id, false, Capabilities.UserManage, Capabilities.GroupManage, Capabilities.GroupView);
            var requestersA = Group("space-a-requesters", spaceA.Id, false, Capabilities.CertRequest);
            var requestersB = Group("space-b-requesters", spaceB.Id, false, Capabilities.CertRequest);
            var systemAuditors = Group("system-auditors", null, true, Capabilities.AuditView);
            var systemAdmins = Group("system-admins", null, true, Capabilities.SystemManage, Capabilities.UserManage);

            var spaceAdmin = User("space-admin", adminsA);
            var systemAdmin = User("system-admin", systemAdmins);
            var ungrouped = User("ungrouped");
            var inA = User("in-a", requestersA);
            var inBoth = User("in-both", requestersA, requestersB);
            var auditor = User("auditor", systemAuditors);
            var granted = User("granted", requestersA);
            db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = granted, Capability = Capabilities.CertView, SpaceId = spaceB.Id });
            var withRole = User("with-role", requestersA);
            var role = new RoleEntity { Name = $"viewer-{tag}" };
            db.Roles.Add(role);
            db.RoleCapabilities.Add(new RoleCapabilityEntity { RoleId = role.Id, Capability = Capabilities.CertView });
            db.RoleAssignments.Add(new RoleAssignmentEntity { RoleId = role.Id, UserId = withRole });
            await db.SaveChangesAsync();

            Assert.True((await UserAdministrationAccess.FootprintAsync(db, ungrouped)).IsEmpty);
            var a = await UserAdministrationAccess.FootprintAsync(db, inA);
            Assert.False(a.Instance);
            Assert.Equal(new[] { spaceA.Id }, a.SpaceIds);
            Assert.Empty(a.CaIds);
            var both = await UserAdministrationAccess.FootprintAsync(db, inBoth);
            Assert.Equal(new[] { spaceA.Id, spaceB.Id }.OrderBy(id => id), both.SpaceIds.OrderBy(id => id));
            Assert.True((await UserAdministrationAccess.FootprintAsync(db, auditor)).Instance);
            Assert.Contains(spaceB.Id, (await UserAdministrationAccess.FootprintAsync(db, granted)).SpaceIds);
            Assert.True((await UserAdministrationAccess.FootprintAsync(db, withRole)).Instance);

            var auth = new CaGroupAuthorizationService(db, NullLogger<CaGroupAuthorizationService>.Instance);
            var controlled = new ControlledUserCeremonyService(db, null!, null!, NullLogger<ControlledUserCeremonyService>.Instance);
            Task<string?> Refusal(Guid caller, Guid target, bool systemOnly = false)
                => UserAdministrationAccess.RefusalAsync(db, auth, controlled, caller, target, systemOnly);

            Assert.Null(await Refusal(spaceAdmin, inA));
            Assert.NotNull(await Refusal(spaceAdmin, inA, systemOnly: true));
            Assert.NotNull(await Refusal(spaceAdmin, inBoth));
            Assert.NotNull(await Refusal(spaceAdmin, auditor));
            Assert.NotNull(await Refusal(spaceAdmin, granted));
            Assert.NotNull(await Refusal(spaceAdmin, withRole));
            Assert.NotNull(await Refusal(spaceAdmin, ungrouped));
            foreach (var target in new[] { inA, inBoth, auditor, granted, withRole, ungrouped })
                Assert.Null(await Refusal(systemAdmin, target, systemOnly: true));

            Assert.True(await UserAdministrationAccess.HoldsAtSomeScopeAsync(auth, spaceAdmin, Capabilities.UserManage));
            Assert.False(await UserAdministrationAccess.HoldsAtSomeScopeAsync(auth, inA, Capabilities.UserManage));
            Assert.Equal(new[] { $"space:{spaceA.Id}" }, await UserAdministrationAccess.ScopesToPinAsync(db, auth, controlled, spaceAdmin, inA));
            Assert.Null(await UserAdministrationAccess.ScopesToPinAsync(db, auth, controlled, systemAdmin, inA));
            Assert.False(await UserAdministrationAccess.HoldsOutsideAsync(db, inA, [$"space:{spaceA.Id}"]));
            Assert.True(await UserAdministrationAccess.HoldsOutsideAsync(db, inBoth, [$"space:{spaceA.Id}"]));
        });

    /// <summary>
    /// Deleting an account on the provider that enforces the foreign keys. An account named by a
    /// request and an approval, which the database will not let go of, is retained and stripped;
    /// one holding only access to a certificate, whose key restricts too, is removed outright; and
    /// the retained account's username stays taken at the database, not only in the service.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task Deleting_an_account_with_history_runs_on_postgres() =>
        OnPostgresAsync(async db =>
        {
            var tag = Guid.NewGuid().ToString("N")[..8];
            var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"requesters-{tag}", DisplayName = "requesters" };
            db.CaGroups.Add(group);
            UserEntity Account(string name)
            {
                var user = new UserEntity { Id = Guid.NewGuid(), Username = $"{name}-{tag}", Email = $"{name}-{tag}@example.test", PasswordHash = "a-hash" };
                db.Users.Add(user);
                db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = group.Id, UserId = user.Id });
                return user;
            }
            var busy = Account("busy");
            var reader = Account("reader");
            var certificate = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = tag, SubjectDN = "CN=leaf", Issuer = "CN=ca", Pem = "x" };
            db.Certificates.Add(certificate);
            var request = new CertRequestEntity { Id = Guid.NewGuid(), Subject = "CN=leaf", CSR = "-", RequestorUserId = busy.Id };
            db.CertificateRequests.Add(request);
            db.CsrApprovals.Add(new CsrApprovalEntity { CertRequestId = request.Id, ApproverId = busy.Id, ApproverUsername = busy.Username, Decision = "Approved" });
            db.RefreshTokens.Add(new RefreshTokenEntity { UserId = busy.Id, Token = $"session-{tag}", ExpiresAt = DateTime.UtcNow.AddDays(1) });
            db.CertificateAccessLists.AddRange(
                new CertificateAccessListEntity { Id = Guid.NewGuid(), CertificateId = certificate.CertificateId, UserId = busy.Id },
                new CertificateAccessListEntity { Id = Guid.NewGuid(), CertificateId = certificate.CertificateId, UserId = reader.Id });
            await db.SaveChangesAsync();

            var users = new ModularCA.Auth.Services.UserManagementService(db, NullLogger<ModularCA.Auth.Services.UserManagementService>.Instance,
                new ModularCA.Shared.Models.Config.SystemConfig(), null!, new ModularCA.Tests.Auth.ControlledUserBypassGuardTests.AllowAllPasswords());

            Assert.NotNull(await users.RetainedHistoryAsync(busy.Id));
            Assert.True(await users.DeleteUser(busy.Id));
            Assert.Null(await users.RetainedHistoryAsync(reader.Id));
            Assert.True(await users.DeleteUser(reader.Id));
            db.ChangeTracker.Clear();

            Assert.False(await db.Users.AnyAsync(u => u.Id == busy.Id || u.Id == reader.Id));
            Assert.False(await db.Users.IgnoreQueryFilters().AnyAsync(u => u.Id == reader.Id));
            var kept = await db.Users.IgnoreQueryFilters().SingleAsync(u => u.Id == busy.Id);
            Assert.True(kept.IsDeleted);
            Assert.False(kept.IsActive);
            Assert.Equal(string.Empty, kept.PasswordHash);
            Assert.Equal(ModularCA.Auth.Services.UserManagementService.TombstoneEmail(busy.Id), kept.Email);
            Assert.False(await db.CaGroupMembers.AnyAsync(m => m.UserId == busy.Id));
            Assert.False(await db.RefreshTokens.AnyAsync(r => r.UserId == busy.Id));
            Assert.False(await db.CertificateAccessLists.AnyAsync());
            Assert.Equal(busy.Id, (await db.CertificateRequests.SingleAsync(r => r.Id == request.Id)).RequestorUserId);
            Assert.Equal(busy.Id, (await db.CsrApprovals.SingleAsync(x => x.CertRequestId == request.Id)).ApproverId);

            var again = await users.CreateUser(new ModularCA.Shared.Models.Management.CreateUserRequest
                { Username = busy.Username, Email = $"other-{tag}@example.test", Password = "Chosen-Passw0rd!" });
            Assert.False(again.Success);
            Assert.Contains("deleted account", again.Error);
            db.Users.Add(new UserEntity { Id = Guid.NewGuid(), Username = busy.Username, Email = $"direct-{tag}@example.test" });
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        });

    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_uadm");
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
