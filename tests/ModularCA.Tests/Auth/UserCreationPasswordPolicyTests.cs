using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins that an administrator creating an account cannot bypass the password policy.
/// </summary>
/// <remarks>
/// Every other path that sets a password ran it through the policy: setup, the bootstrap seeder,
/// self-service change, the forced change at login, and the admin password update. Creation
/// hashed whatever it was given, so an operator could be created with the password "a" and no
/// forced rotation, holding whatever groups the request named.
/// </remarks>
public class UserCreationPasswordPolicyTests
{
    private sealed class NoTenantContext : ITenantContext
    {
        public bool IsSystemAdmin => true;
        public bool HasContext => false;
        public IReadOnlySet<Guid> AccessibleTenantIds => new HashSet<Guid>();
        public Guid? UserId => null;
        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin) { }
    }

    /// <summary>Rejects every password containing the letter x; accepts the rest.</summary>
    private sealed class StubPolicy : IPasswordPolicyService
    {
        public List<string> Checked { get; } = [];

        public Task<PasswordPolicyEntity> GetPolicyAsync() => Task.FromResult(new PasswordPolicyEntity());

        public Task<(bool IsValid, List<string> Errors)> ValidateAsync(string password)
        {
            Checked.Add(password);
            return Task.FromResult(password.Contains('x')
                ? (false, new List<string> { "contains the forbidden letter" })
                : (true, new List<string>()));
        }

        public Task<(bool IsValid, List<string> Errors)> ValidateAsync(Guid userId, string password) => ValidateAsync(password);

        public Task RecordPasswordHistoryAsync(Guid userId, string newPasswordHash) => Task.CompletedTask;
    }

    private static ModularCADbContext BuildContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(
                Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options, new NoTenantContext());
    }

    private static (UserManagementService Service, StubPolicy Policy) BuildService(ModularCADbContext db)
    {
        var policy = new StubPolicy();
        return (new UserManagementService(db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!, policy), policy);
    }

    private static CreateUserRequest Request(string password) => new()
    {
        Username = "operator1",
        Email = "operator1@example.test",
        Password = password,
        FirstName = "Op",
        LastName = "Erator",
        GroupIds = [],
    };

    [Fact]
    public async Task A_password_the_policy_rejects_blocks_creation_and_names_the_reason()
    {
        using var db = BuildContext(nameof(A_password_the_policy_rejects_blocks_creation_and_names_the_reason));
        var (service, policy) = BuildService(db);

        var (success, error) = await service.CreateUser(Request("xylophone"));

        Assert.False(success);
        Assert.Contains("forbidden letter", error);
        Assert.Equal(["xylophone"], policy.Checked);
        // Nothing half-provisioned: the refusal happens before the account exists.
        Assert.False(await db.Users.AnyAsync(u => u.Username == "operator1"));
    }

    [Fact]
    public async Task A_password_the_policy_accepts_creates_the_account()
    {
        using var db = BuildContext(nameof(A_password_the_policy_accepts_creates_the_account));
        var (service, policy) = BuildService(db);

        var (success, error) = await service.CreateUser(Request("Correct-Horse-Battery"));

        Assert.True(success, error);
        Assert.Single(policy.Checked);
        Assert.True(await db.Users.AnyAsync(u => u.Username == "operator1"));
    }
}
