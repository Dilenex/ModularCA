using ModularCA.Auth.Utils;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Covers <see cref="AccountStateGate"/>, the single decision on whether an account may be
/// issued a session.
/// <para>
/// It exists because the answer used to be decided independently at every JWT issuance point and
/// they disagreed. <c>AuthController.Login</c> and the refresh path checked all three flags;
/// every MFA-completion path checked none; and <c>MtlsController.LoginRedirect</c> — a primary
/// login path with no upstream gate at all — issued a full JWT to a disabled user and then
/// cleared their lockout on the way out.
/// </para>
/// </summary>
public class AccountStateGateTests
{
    private static UserEntity User(bool active = true, bool locked = false, DateTime? lockoutEnd = null) => new()
    {
        Id = Guid.NewGuid(),
        Username = "subject",
        PasswordHash = string.Empty,
        IsActive = active,
        IsLocked = locked,
        LockoutEndUtc = lockoutEnd,
    };

    [Fact]
    public void Healthy_account_is_not_blocked()
    {
        Assert.False(AccountStateGate.IsBlocked(User(), out var reason));
        Assert.Equal(string.Empty, reason);
    }

    [Fact]
    public void Disabled_account_is_blocked()
    {
        Assert.True(AccountStateGate.IsBlocked(User(active: false), out var reason));
        Assert.Contains("disabled", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Hard_locked_account_is_blocked()
    {
        Assert.True(AccountStateGate.IsBlocked(User(locked: true), out var reason));
        Assert.Contains("locked by an administrator", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Account_inside_a_temporary_lockout_is_blocked()
    {
        var user = User(lockoutEnd: DateTime.UtcNow.AddMinutes(5));

        Assert.True(AccountStateGate.IsBlocked(user, out var reason));
        Assert.Contains("temporarily locked", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Account_whose_temporary_lockout_has_elapsed_is_not_blocked()
    {
        // An expired LockoutEndUtc is a stale timestamp, not an active lockout. Treating it as
        // one would lock users out permanently after a single burst of failed logins, since
        // nothing clears the column until the next successful login.
        var user = User(lockoutEnd: DateTime.UtcNow.AddMinutes(-1));

        Assert.False(AccountStateGate.IsBlocked(user, out _));
    }

    [Fact]
    public void Disabled_takes_precedence_over_a_stale_lockout()
    {
        // Ordering matters for the audit trail: the operator wants "disabled", not a lockout
        // timestamp that happens to also be set.
        var user = User(active: false, lockoutEnd: DateTime.UtcNow.AddMinutes(-1));

        Assert.True(AccountStateGate.IsBlocked(user, out var reason));
        Assert.Contains("disabled", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Audit_reasons_are_distinct_per_cause()
    {
        // The reason string is for the audit log, so it has to tell the three causes apart —
        // an operator reading a failed login needs to know whether they are looking at a
        // disabled account or a lockout that will clear on its own.
        //
        // The message returned to the CALLER is the single shared AccountStateGate.ClientMessage
        // constant, which is why it cannot vary by cause and why that is not asserted here:
        // saying which state an account is in would be an enumeration oracle, and a constant
        // cannot leak it.
        AccountStateGate.IsBlocked(User(active: false), out var disabled);
        AccountStateGate.IsBlocked(User(locked: true), out var hardLocked);
        AccountStateGate.IsBlocked(User(lockoutEnd: DateTime.UtcNow.AddMinutes(5)), out var tempLocked);

        Assert.Equal(3, new HashSet<string>(new[] { disabled, hardLocked, tempLocked }).Count);
        Assert.All(new[] { disabled, hardLocked, tempLocked }, r => Assert.False(string.IsNullOrWhiteSpace(r)));
    }

    [Fact]
    public void Null_user_throws_rather_than_defaulting_to_allowed()
    {
        // Fail closed. A null here is a caller bug, and silently returning "not blocked" would
        // turn it into an authentication bypass.
        Assert.Throws<ArgumentNullException>(() => AccountStateGate.IsBlocked(null!, out _));
    }
}
