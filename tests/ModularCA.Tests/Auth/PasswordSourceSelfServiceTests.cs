using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A Directory account's password lives in the directory, so the account cannot set a local one
/// that would never be used: the self-service change explains that instead of asking for step-up,
/// and the service refuses it on any path that reaches it.
/// </summary>
public sealed class PasswordSourceSelfServiceTests
{
    private const string OldPassword = "Old-Local-Passw0rd!xyz";
    private const string NewPassword = "New-Local-Passw0rd!xyz";

    private sealed class CurrentUserStub(UserEntity user) : ICurrentUserService
    {
        public Guid? UserId => user.Id;
        public UserEntity? User => user;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static (ModularCA.Database.ModularCADbContext Db, UserEntity User) World(PasswordSource source)
    {
        var db = InMemoryDbContextFactory.Create();
        var user = new UserEntity
        {
            Username = "rita", Email = "rita@example.test", PasswordHash = PasswordUtil.HashPassword(OldPassword),
            PasswordSource = source,
        };
        db.Users.Add(user);
        db.SaveChanges();
        return (db, user);
    }

    private static UserManagementService Users(ModularCA.Database.ModularCADbContext db)
        => new(db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!,
            new ControlledUserBypassGuardTests.AllowAllPasswords());

    private static async Task<IActionResult> ChangeOwnPasswordAsync(ModularCA.Database.ModularCADbContext db, UserEntity user, RecordingAuditService audit)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Account.AccountManagerController");
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var controller = Activator.CreateInstance(type, Users(db), new CurrentUserStub(user), audit, cache, db)!;
        type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!.SetValue(controller, new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", user.Id.ToString()) }, "test")),
            },
        });
        var request = new UpdatePasswordRequest { OldPassword = OldPassword, NewPassword = NewPassword, ConfirmNewPassword = NewPassword };
        return await (Task<IActionResult>)type.GetMethod("ChangePassword")!.Invoke(controller, new object?[] { request, null })!;
    }

    [Fact]
    public async Task A_directory_account_is_told_its_password_lives_in_the_directory_before_any_step_up()
    {
        var (db, user) = World(PasswordSource.Directory);
        var audit = new RecordingAuditService();
        var hash = user.PasswordHash;

        var result = Assert.IsType<ConflictObjectResult>(await ChangeOwnPasswordAsync(db, user, audit));

        Assert.Contains("directory", result.Value!.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(hash, db.Users.Single().PasswordHash);
        Assert.Contains(audit.Entries, e => e.Action == AuditActionType.UserPasswordChanged);
    }

    [Theory]
    [InlineData(PasswordSource.Inherit)]
    [InlineData(PasswordSource.Local)]
    public async Task Any_other_account_still_goes_through_step_up(PasswordSource source)
    {
        var (db, user) = World(source);

        var result = Assert.IsType<ObjectResult>(await ChangeOwnPasswordAsync(db, user, new RecordingAuditService()));

        Assert.Equal(403, result.StatusCode);
        Assert.Contains("requiresStepUp", System.Text.Json.JsonSerializer.Serialize(result.Value));
    }

    [Fact]
    public async Task The_service_refuses_a_local_password_for_a_directory_account_without_counting_a_failure()
    {
        var (db, user) = World(PasswordSource.Directory);
        var hash = user.PasswordHash;

        var changed = await Users(db).UpdateUserPassword(user.Id,
            new UpdatePasswordRequest { OldPassword = OldPassword, NewPassword = NewPassword, ConfirmNewPassword = NewPassword });

        Assert.False(changed);
        Assert.Equal(hash, db.Users.Single().PasswordHash);
        Assert.Equal(0, db.Users.Single().FailedLoginAttempts);
    }

    [Fact]
    public async Task The_service_refuses_an_admin_reset_of_a_directory_account()
    {
        var (db, user) = World(PasswordSource.Directory);
        var hash = user.PasswordHash;

        await Assert.ThrowsAsync<InvalidOperationException>(() => Users(db).ResetUserPassword(user.Id));
        Assert.Equal(hash, db.Users.Single().PasswordHash);
    }
}
