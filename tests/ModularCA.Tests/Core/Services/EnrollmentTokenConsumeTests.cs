using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers <c>EnrollmentTokenService.ValidateAndConsumeAsync</c> — the gate the SCEP
/// challenge-password path relies on, via <c>EnrollmentAuthorizationService</c>.
/// <para>
/// <b>Coverage limit, stated plainly.</b> The atomic-consume half of this work is NOT exercised
/// here. <c>TryConsumeUseAsync</c> issues a single <c>UPDATE ... WHERE UsesRemaining &gt; 0</c>
/// through <c>ExecuteUpdateAsync</c>, which the EF in-memory provider does not implement, and the
/// SQLite provider cannot be added because it pulls <c>SQLitePCLRaw.lib.e_sqlite3</c>, which has a
/// known high-severity advisory that this repo's build correctly treats as an error. Weakening
/// that gate to test a concurrency fix would be a poor trade.
/// </para>
/// <para>
/// So what IS covered here is every path that returns BEFORE the consume — which is where the
/// name-restriction bugs lived — plus the unlimited-token short circuit, which is the one branch
/// of the consume that never touches the database. The atomicity itself rests on the single
/// conditional UPDATE, which is a property of the statement rather than of the surrounding code.
/// </para>
/// </summary>
public class EnrollmentTokenConsumeTests
{
    private static EnrollmentTokenEntity Token(
        string token = "tok",
        int maxUses = 1,
        int usesRemaining = 1,
        string? subjectRestriction = null,
        string? sanRestriction = null,
        string? protocol = null,
        bool revoked = false,
        DateTime? expiresAt = null) => new()
        {
            Token = token,
            MaxUses = maxUses,
            UsesRemaining = usesRemaining,
            SubjectRestriction = subjectRestriction,
            SANRestriction = sanRestriction,
            Protocol = protocol,
            IsRevoked = revoked,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddHours(1),
            CreatedAt = DateTime.UtcNow,
        };

    private static async Task<(bool ok, string? error)> ValidateAsync(
        EnrollmentTokenEntity token, string? subject, string? protocol = "SCEP", IEnumerable<string>? sans = null)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.EnrollmentTokens.Add(token);
        await db.SaveChangesAsync();

        var service = new EnrollmentTokenService(db);
        return await service.ValidateAndConsumeAsync(token.Token, subject, protocol, sans);
    }

    // ── The bug this shares with the public enrollment path ────────────────────

    [Fact]
    public async Task Empty_subject_no_longer_bypasses_the_subject_restriction()
    {
        // The check was `restriction set && subject non-empty && !subject.Contains(...)`, so an
        // empty subject short-circuited to allowed. A SAN-only CSR has exactly that shape.
        //
        // This matters more here than on the public QR path: for SCEP challenge-password
        // enrollment this is the ONLY name check in the request.
        var (ok, error) = await ValidateAsync(Token(subjectRestriction: "example.com"), subject: "");

        Assert.False(ok);
        Assert.Contains("no subject", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Substring_lookalike_domain_is_rejected()
    {
        var (ok, _) = await ValidateAsync(
            Token(subjectRestriction: "example.com"), subject: "CN=evil-example.com.attacker.net");

        Assert.False(ok);
    }

    [Fact]
    public async Task Matching_subject_is_accepted()
    {
        // Deliberately an unlimited token (MaxUses = 0). A limited one would reach
        // TryConsumeUseAsync and its ExecuteUpdateAsync, which the in-memory provider cannot
        // run — the coverage limit described on this class. Using an unlimited token isolates
        // the assertion that actually matters here: a compliant subject is not rejected.
        var (ok, error) = await ValidateAsync(
            Token(maxUses: 0, usesRemaining: 0, subjectRestriction: "example.com"),
            subject: "CN=host.example.com");

        Assert.True(ok, error);
    }

    [Fact]
    public async Task San_restriction_is_enforced_when_sans_are_supplied()
    {
        // SANRestriction was previously read by nothing at all on any path.
        var (ok, error) = await ValidateAsync(
            Token(subjectRestriction: "example.com", sanRestriction: "example.com"),
            subject: "CN=host.example.com",
            sans: new[] { "DNS:host.example.com", "DNS:evil.attacker.net" });

        Assert.False(ok);
        Assert.Contains("evil.attacker.net", error!);
    }

    // ── Pre-existing gates still hold ──────────────────────────────────────────

    [Fact]
    public async Task Unknown_token_is_rejected()
    {
        using var db = InMemoryDbContextFactory.Create();
        var service = new EnrollmentTokenService(db);

        var (ok, error) = await service.ValidateAndConsumeAsync("no-such-token", "CN=x", "SCEP");

        Assert.False(ok);
        Assert.Contains("Invalid", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Expired_token_is_rejected()
    {
        var (ok, error) = await ValidateAsync(
            Token(expiresAt: DateTime.UtcNow.AddMinutes(-1)), subject: "CN=x");

        Assert.False(ok);
        Assert.Contains("expired", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Exhausted_token_is_rejected_before_any_other_work()
    {
        // Guarded by the pre-check, so it never reaches ExecuteUpdateAsync — which is also why
        // this one is runnable on the in-memory provider.
        var (ok, error) = await ValidateAsync(Token(maxUses: 1, usesRemaining: 0), subject: "CN=x");

        Assert.False(ok);
        Assert.Contains("maximum number of times", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Protocol_restricted_token_rejects_another_protocol()
    {
        var (ok, error) = await ValidateAsync(Token(protocol: "EST"), subject: "CN=x", protocol: "SCEP");

        Assert.False(ok);
        Assert.Contains("restricted to protocol", error!, StringComparison.OrdinalIgnoreCase);
    }

    // ── The one consume branch reachable without a relational provider ─────────

    [Fact]
    public async Task Unlimited_tokens_are_never_consumed()
    {
        // MaxUses <= 0 means unlimited. TryConsumeUseAsync short-circuits before issuing any
        // UPDATE, which is both correct and the reason this branch is testable here. If that
        // guard were removed, an unlimited token would decrement toward a negative
        // UsesRemaining and this test would fail on the in-memory provider's lack of
        // ExecuteUpdateAsync — a blunt signal, but a signal.
        using var db = InMemoryDbContextFactory.Create();
        var token = Token(maxUses: 0, usesRemaining: 0);
        db.EnrollmentTokens.Add(token);
        await db.SaveChangesAsync();

        var consumed = await EnrollmentTokenService.TryConsumeUseAsync(db, token);

        Assert.True(consumed);
        Assert.Equal(0, token.UsesRemaining);
    }
}
