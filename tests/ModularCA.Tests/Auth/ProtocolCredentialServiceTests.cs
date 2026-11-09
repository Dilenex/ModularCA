using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins the rules that make password authentication over a machine protocol safe.
/// </summary>
/// <remarks>
/// EST's HTTP Basic authentication is the most brute-forceable surface this product exposes: no
/// MFA, no CAPTCHA, no interactive delay, and clients that retry by design. What stops it being a
/// password-grinding oracle is that it runs the interactive login's rules rather than a second,
/// looser copy of them. These tests are what keeps that true — a well-meaning simplification here
/// (skip the lockout, answer "no such user" early) reads as tidier code and silently removes the
/// protection.
/// </remarks>
public class ProtocolCredentialServiceTests
{
    /// <summary>Captures audit calls so outcomes can be asserted without a database.</summary>
    private sealed class RecordingAudit : IAuditService
    {
        public List<(string Action, string? Username, bool Success, object? Details)> Entries { get; } = [];

        public Task LogAsync(
            string actionType, Guid? actorUserId, string? actorUsername,
            string? targetEntityType = null, string? targetEntityId = null, object? details = null,
            string? sourceIp = null, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            Entries.Add((actionType, actorUsername, success, details));
            return Task.CompletedTask;
        }
    }

    private sealed class StubLdap(LdapBindOutcome outcome) : ILdapAuthService
    {
        public int Calls { get; private set; }

        public Task<LdapBindOutcome> AuthenticateAsync(string username, string password)
        {
            Calls++;
            return Task.FromResult(outcome);
        }

        public Task<List<string>?> GetUserGroupsAsync(string username) => Task.FromResult<List<string>?>(new List<string>());
    }

    private sealed class StubPolicy(int maxAttempts, int lockoutMinutes) : ISecurityPolicyService
    {
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(new SecurityPolicyEntity
        {
            MaxFailedLoginAttempts = maxAttempts,
            LockoutMinutes = lockoutMinutes,
        });

        public void InvalidateCache() { }
    }

    /// <summary>A throwaway relational database for a single test.</summary>
    /// <remarks>
    /// SQLite rather than the in-memory provider, because this service increments the failed-attempt
    /// counter with <c>ExecuteUpdateAsync</c> — an atomic UPDATE chosen so that two concurrent failed
    /// attempts cannot lose one another's increment, which is exactly the shape an EST client's
    /// mechanical retries produce. The in-memory provider cannot execute that statement at all, so
    /// testing through it would have meant weakening the production write to suit the test.
    /// </remarks>
    private sealed class TestDb : IDisposable
    {
        private readonly SqliteConnection _connection;

        public ModularCADbContext Context { get; }

        public TestDb()
        {
            // The schema lives for as long as the connection does, so it is held open here rather
            // than left to the context.
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();
            Context = new ModularCADbContext(
                new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);
            Context.Database.EnsureCreated();
        }

        public void Dispose()
        {
            Context.Dispose();
            _connection.Dispose();
        }
    }

    private static UserEntity AddUser(
        ModularCADbContext db, string username, string password,
        bool active = true, bool locked = false, int failedAttempts = 0, DateTime? lockoutEnd = null,
        bool mustChange = false, DateTime? passwordExpires = null, bool neverExpires = false,
        PasswordSource source = PasswordSource.Inherit)
    {
        var user = new UserEntity
        {
            Username = username,
            PasswordHash = PasswordUtil.HashPassword(password),
            IsActive = active,
            IsLocked = locked,
            FailedLoginAttempts = failedAttempts,
            LockoutEndUtc = lockoutEnd,
            PasswordChangeOnNextLogon = mustChange,
            PasswordExpirationDate = passwordExpires,
            PasswordNeverExpires = neverExpires,
            PasswordSource = source,
        };
        db.Users.Add(user);
        db.SaveChanges();
        db.ChangeTracker.Clear();
        return user;
    }

    private static (ProtocolCredentialService Service, RecordingAudit Audit, StubLdap Ldap) Build(
        ModularCADbContext db, bool ldapEnabled = false, bool ldapSucceeds = false,
        int maxAttempts = 3, int lockoutMinutes = 15, LdapBindOutcome? ldapOutcome = null)
    {
        var audit = new RecordingAudit();
        var ldap = new StubLdap(ldapOutcome ?? (ldapSucceeds ? LdapBindOutcome.Succeeded : LdapBindOutcome.Refused));
        var config = new SystemConfig();
        config.LdapAuth.Enabled = ldapEnabled;
        var service = new ProtocolCredentialService(
            db, audit, config, ldap, new StubPolicy(maxAttempts, lockoutMinutes));
        return (service, audit, ldap);
    }

    [Fact]
    public async Task Correct_credentials_verify_and_audit_a_successful_login()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db);

        var result = await service.VerifyAsync("device1", "Correct-Horse-1", "EST", "10.0.0.5");

        Assert.Equal("device1", result);
        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.UserLogin, entry.Action);
        Assert.True(entry.Success);
    }

    [Fact]
    public async Task A_wrong_password_is_refused_and_audited()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync("device1", "wrong", "EST", null));

        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.UserLoginFailed, entry.Action);
        Assert.False(entry.Success);
    }

    [Fact]
    public async Task An_unknown_username_is_refused_and_audited_by_the_name_that_was_tried()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync("no-such-device", "anything", "EST", "10.0.0.9"));

        // The attempted name is recorded even though no user id exists, so a spray against invented
        // names shows up in the trail rather than vanishing.
        var entry = Assert.Single(audit.Entries);
        Assert.Equal("no-such-device", entry.Username);
        Assert.False(entry.Success);
    }

    [Theory]
    [InlineData("", "password")]
    [InlineData("   ", "password")]
    [InlineData("device1", "")]
    public async Task Empty_credentials_are_refused_without_reaching_the_database(string username, string password)
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync(username, password, "EST", null));
        Assert.Empty(audit.Entries);
    }

    [Fact]
    public async Task Failed_attempts_accumulate_and_lock_the_account_at_the_policy_limit()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1");
        var (service, _, _) = Build(db, maxAttempts: 3, lockoutMinutes: 15);

        for (var i = 0; i < 3; i++)
            Assert.Null(await service.VerifyAsync("device1", "wrong", "EST", null));

        db.ChangeTracker.Clear();
        var stored = await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id);
        Assert.Equal(3, stored.FailedLoginAttempts);
        Assert.NotNull(stored.LockoutEndUtc);
        Assert.True(stored.LockoutEndUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task A_locked_account_is_refused_even_with_the_correct_password()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", lockoutEnd: DateTime.UtcNow.AddMinutes(10));
        var (service, audit, _) = Build(db);

        // This is the whole point of sharing the counter with interactive login: an attacker who
        // has locked the account at the login page cannot walk around it via EST.
        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.False(Assert.Single(audit.Entries).Success);
    }

    [Fact]
    public async Task A_disabled_account_is_refused_even_with_the_correct_password()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", active: false);
        var (service, _, _) = Build(db);

        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
    }

    [Fact]
    public async Task A_hard_locked_account_is_refused_even_with_the_correct_password()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", locked: true);
        var (service, _, _) = Build(db);

        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
    }

    [Fact]
    public async Task Account_state_is_not_revealed_to_a_caller_who_has_not_proved_the_password()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "disabled-device", "Correct-Horse-1", active: false);
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync("disabled-device", "wrong", "EST", null));

        // A wrong password against a disabled account must be indistinguishable from a wrong
        // password against a live one. Reporting "account_disabled" here turns the endpoint into an
        // account enumerator for anyone willing to try one password per name.
        var details = Assert.Single(audit.Entries).Details?.ToString();
        Assert.Contains("invalid_password", details);
        Assert.DoesNotContain("account_disabled", details);
    }

    [Fact]
    public async Task An_elapsed_temporary_lockout_clears_itself_on_the_next_attempt()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1",
            failedAttempts: 5, lockoutEnd: DateTime.UtcNow.AddMinutes(-1));
        var (service, _, _) = Build(db);

        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));

        db.ChangeTracker.Clear();
        var stored = await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id);
        Assert.Equal(0, stored.FailedLoginAttempts);
        Assert.Null(stored.LockoutEndUtc);
    }

    [Fact]
    public async Task A_successful_verification_resets_the_failure_counter()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1", failedAttempts: 2);
        var (service, _, _) = Build(db);

        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));

        db.ChangeTracker.Clear();
        var stored = await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id);
        Assert.Equal(0, stored.FailedLoginAttempts);
    }

    [Fact]
    public async Task Ldap_is_consulted_first_when_enabled_and_a_directory_success_needs_no_local_hash()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "a-stale-local-password");
        var (service, audit, ldap) = Build(db, ldapEnabled: true, ldapSucceeds: true);

        // The directory password is not the local one. An environment that moved authentication to
        // LDAP expects the directory to be authoritative.
        Assert.Equal("device1", await service.VerifyAsync("device1", "the-directory-password", "EST", null));
        Assert.Equal(1, ldap.Calls);
        Assert.Contains("ldap", Assert.Single(audit.Entries, e => e.Action == AuditActionType.UserLogin).Details?.ToString());
    }

    [Fact]
    public async Task An_inherit_account_the_directory_accepts_over_est_becomes_a_directory_account()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.Succeeded);

        Assert.Equal("device1", await service.VerifyAsync("device1", "the-directory-password", "EST", null));

        db.ChangeTracker.Clear();
        Assert.Equal(PasswordSource.Directory, (await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id)).PasswordSource);
        var learned = Assert.Single(audit.Entries, e => e.Action == AuditActionType.UserPasswordSourceLearned);
        Assert.Contains("EST", learned.Details?.ToString());

        // Its directory entry is deleted next: the matching local hash no longer answers.
        var (afterDeletion, _, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.UserNotFound);
        Assert.Null(await afterDeletion.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
    }

    [Fact]
    public async Task An_account_answered_by_the_local_hash_is_not_learned()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.UserNotFound);

        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));

        db.ChangeTracker.Clear();
        Assert.Equal(PasswordSource.Inherit, (await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id)).PasswordSource);
        Assert.DoesNotContain(audit.Entries, e => e.Action == AuditActionType.UserPasswordSourceLearned);
    }

    [Fact]
    public async Task A_refused_ldap_bind_does_not_fall_back_to_the_local_hash()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, ldap) = Build(db, ldapEnabled: true, ldapSucceeds: false);

        // The directory refused the bind, so it is authoritative for this account: the local hash
        // may be a stale password the directory has since rotated or disabled.
        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Equal(1, ldap.Calls);
        Assert.Contains("invalid_password", Assert.Single(audit.Entries).Details?.ToString());
    }

    [Fact]
    public async Task An_account_the_directory_does_not_know_still_verifies_against_the_local_hash()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, ldap) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.UserNotFound);

        // A local-only account, such as the bootstrap administrator, keeps working with LDAP on.
        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Equal(1, ldap.Calls);
        Assert.Contains("password", Assert.Single(audit.Entries).Details?.ToString());
    }

    [Fact]
    public async Task An_unreachable_directory_refuses_without_the_local_hash_or_a_failed_attempt()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.Unavailable);

        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Contains("directory_unavailable", Assert.Single(audit.Entries).Details?.ToString());

        // The password was never checked, so an outage does not walk accounts toward lockout.
        db.ChangeTracker.Clear();
        Assert.Equal(0, (await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id)).FailedLoginAttempts);
    }

    [Theory]
    [InlineData(LdapBindOutcome.Refused)]
    [InlineData(LdapBindOutcome.Unavailable)]
    public async Task A_local_account_verifies_against_the_local_hash_without_asking_the_directory(LdapBindOutcome outcome)
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", source: PasswordSource.Local);
        var (service, audit, ldap) = Build(db, ldapEnabled: true, ldapOutcome: outcome);

        // A local account keeps working through a directory outage and in direct-bind mode.
        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Equal(0, ldap.Calls);
        Assert.Contains("password", Assert.Single(audit.Entries).Details?.ToString());
    }

    [Fact]
    public async Task A_directory_account_verifies_when_the_directory_accepts_the_bind()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "a-stale-local-password", source: PasswordSource.Directory);
        var (service, _, ldap) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.Succeeded);

        Assert.Equal("device1", await service.VerifyAsync("device1", "the-directory-password", "EST", null));
        Assert.Equal(1, ldap.Calls);
    }

    [Fact]
    public async Task A_directory_account_the_directory_no_longer_knows_is_refused_and_counted()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1", source: PasswordSource.Directory);
        var (service, audit, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.UserNotFound);

        // Its directory entry was deleted: the local hash, though it matches, is not consulted.
        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Contains("not_in_directory", Assert.Single(audit.Entries).Details?.ToString());
        db.ChangeTracker.Clear();
        Assert.Equal(1, (await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id)).FailedLoginAttempts);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_directory_account_is_refused_without_a_failed_attempt_when_the_directory_cannot_answer(bool ldapEnabled)
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        var user = AddUser(db, "device1", "Correct-Horse-1", source: PasswordSource.Directory);
        var (service, audit, _) = Build(db, ldapEnabled: ldapEnabled, ldapOutcome: LdapBindOutcome.Unavailable);

        // Unreachable, or LDAP sign-in turned off: either way there is no answer, and the local hash
        // is not an answer for a directory account.
        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Contains("directory_unavailable", Assert.Single(audit.Entries).Details?.ToString());
        db.ChangeTracker.Clear();
        Assert.Equal(0, (await db.Users.AsNoTracking().FirstAsync(u => u.Id == user.Id)).FailedLoginAttempts);
    }

    [Fact]
    public async Task A_password_the_directory_accepted_is_not_held_to_the_local_password_flags()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "stale-local", mustChange: true, passwordExpires: DateTime.UtcNow.AddDays(-1),
            source: PasswordSource.Directory);
        var (service, _, _) = Build(db, ldapEnabled: true, ldapOutcome: LdapBindOutcome.Succeeded);

        // The forced change and expiry concern the local password, which a directory account has
        // no use for and cannot set.
        Assert.Equal("device1", await service.VerifyAsync("device1", "the-directory-password", "EST", null));
    }

    [Fact]
    public async Task Ldap_is_not_consulted_when_disabled()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, _, ldap) = Build(db, ldapEnabled: false);

        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Equal(0, ldap.Calls);
    }

    [Fact]
    public async Task A_password_the_account_must_change_is_refused_even_when_correct()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Temp-Password-1", mustChange: true);
        var (service, audit, _) = Build(db);

        // The temporary password an administrator hands out at reset time. Interactive login
        // forces a change; a protocol client cannot complete that, so it must be refused, or the
        // temporary password is a working EST credential until the user gets around to it.
        Assert.Null(await service.VerifyAsync("device1", "Temp-Password-1", "EST", null));
        Assert.Contains("password_change_required", Assert.Single(audit.Entries).Details?.ToString());
    }

    [Fact]
    public async Task An_expired_password_is_refused_even_when_correct()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", passwordExpires: DateTime.UtcNow.AddDays(-1));
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
        Assert.Contains("password_expired", Assert.Single(audit.Entries).Details?.ToString());
    }

    [Fact]
    public async Task A_never_expiring_password_ignores_the_expiration_date()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1", passwordExpires: DateTime.UtcNow.AddDays(-1), neverExpires: true);
        var (service, _, _) = Build(db);

        Assert.Equal("device1", await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null));
    }

    [Fact]
    public async Task Password_state_is_not_revealed_to_a_caller_who_has_not_proved_the_password()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Temp-Password-1", mustChange: true);
        var (service, audit, _) = Build(db);

        Assert.Null(await service.VerifyAsync("device1", "wrong", "EST", null));

        var details = Assert.Single(audit.Entries).Details?.ToString();
        Assert.Contains("invalid_password", details);
        Assert.DoesNotContain("password_change_required", details);
    }

    [Fact]
    public async Task The_protocol_name_is_carried_into_the_audit_record()
    {
        using var fixture = new TestDb();
        var db = fixture.Context;
        AddUser(db, "device1", "Correct-Horse-1");
        var (service, audit, _) = Build(db);

        await service.VerifyAsync("device1", "Correct-Horse-1", "EST", null);

        // Without this an auditor reading the trail cannot tell an unattended EST enrollment from
        // someone signing in at the console.
        Assert.Contains("EST", Assert.Single(audit.Entries).Details?.ToString());
    }
}
