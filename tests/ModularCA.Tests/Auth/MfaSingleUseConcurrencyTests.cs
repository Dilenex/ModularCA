using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// TOTP and WebAuthn second factors are single-use under concurrency. The verify endpoints read
/// the pending-MFA token, checked the proof, and only then removed the token, so concurrent
/// requests all passed the read and each issued a session; a TOTP code's replay check was a read
/// of <c>LastUsedTimeStep</c> that concurrent requests also all passed. Each proof is now claimed
/// through <see cref="IReplayGuard"/>, and of N parallel verifications exactly one succeeds.
/// </summary>
public sealed class MfaSingleUseConcurrencyTests
{
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    private const int Parallel = 8;

    private sealed class NoDpop : IDpopProofService
    {
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new()
        {
            SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0, MaxConcurrentSessions = 0,
            RequireWebAuthnUserVerification = false, StepUpFailureThreshold = 100,
        };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    /// <summary>
    /// A cache whose reads wait until <see cref="Release"/> once <see cref="Armed"/>, so every
    /// request is inside its first read of the pending-MFA token before any of them goes on.
    /// </summary>
    private sealed class GatedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Armed;
        public int Reads;
        public void Release() => _gate.TrySetResult();
        public byte[]? Get(string key) => _inner.Get(key);
        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            if (Volatile.Read(ref Armed))
            {
                Interlocked.Increment(ref Reads);
                await _gate.Task;
            }
            return await _inner.GetAsync(key, token);
        }
        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => _inner.SetAsync(key, value, options, token);
    }

    private sealed class World
    {
        private readonly string _dbName = $"mfa-single-use-{Guid.NewGuid():N}";
        public Guid UserId { get; } = Guid.NewGuid();
        public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(16);
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        public ConcurrentAudit Audit { get; } = new();
        public GatedCache Cache { get; } = new();
        public IReplayGuard Guard { get; init; } = new InProcessReplayGuard();
        public IDataProtectionProvider DataProtection { get; } = new EphemeralDataProtectionProvider();
        public IFido2? Fido2 { get; init; }

        public World()
        {
            using var db = Db();
            db.Users.Add(new UserEntity { Id = UserId, Username = "mira", Email = "mira@example.test", IsActive = true, SecurityStamp = "s" });
            db.TotpSecrets.Add(new TotpSecretEntity
            {
                UserId = UserId, IsVerified = true,
                EncryptedSecretKey = DataProtection.CreateProtector("TotpSecret").Protect(Secret),
            });
            db.Fido2Credentials.Add(new Fido2CredentialEntity { UserId = UserId, CredentialId = CredentialId, PublicKey = [1], SignCount = 0 });
            db.SaveChanges();
        }

        public ModularCADbContext Db() => InMemoryDbContextFactory.Create(_dbName);

        public async Task<string> PendingAsync()
        {
            var token = Guid.NewGuid().ToString("N");
            await PendingMfaToken.StoreAsync(Cache, token, UserId, PendingMfaToken.Password, TimeSpan.FromMinutes(5));
            return token;
        }

        /// <summary>Builds <paramref name="controllerName"/> over a fresh context, with the services the sign-in paths read.</summary>
        public (object Controller, Type Type, ModularCADbContext Db) Controller(string controllerName, Stream? body = null)
        {
            var db = Db();
            var type = ApiAssembly.TypeNamed(controllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object?[] { db, Cache, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), DataProtection, Guard, Fido2, new CurrentUserStub(UserId) };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => a != null && p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            var services = new ServiceCollection()
                .AddSingleton<IDpopProofService>(new NoDpop())
                .AddSingleton(new AccessBadgeService(db))
                .BuildServiceProvider();
            var http = new DefaultHttpContext { RequestServices = services };
            http.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("sub", UserId.ToString()), new System.Security.Claims.Claim("jti", "session-1")], "test"));
            if (body != null) http.Request.Body = body;
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });
            return (controller, type, db);
        }

        /// <summary>Completes a password-first sign-in of <paramref name="mfaToken"/> with <paramref name="code"/>.</summary>
        public async Task<IActionResult> TotpVerifyAsync(string mfaToken, string code)
        {
            var (controller, type, db) = Controller(TotpControllerName);
            using var _ = db;
            var method = type.GetMethods().Single(m => m.Name == "Verify" && m.GetParameters().Length == 1);
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("MfaToken")!.SetValue(request, mfaToken);
            request.GetType().GetProperty("Code")!.SetValue(request, code);
            return await (Task<IActionResult>)method.Invoke(controller, [request])!;
        }

        /// <summary>Asks for a step-up token for <c>totp-remove</c> with <paramref name="code"/>.</summary>
        public async Task<IActionResult> StepUpTotpAsync(string code)
        {
            var (controller, type, db) = Controller(StepUpControllerName);
            using var _ = db;
            var method = type.GetMethod("VerifyStepUpTotp")!;
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("Code")!.SetValue(request, code);
            request.GetType().GetProperty("Operation")!.SetValue(request, ModularCA.Shared.Enums.StepUpOps.TotpRemove);
            return await (Task<IActionResult>)method.Invoke(controller, [request])!;
        }

        /// <summary>Posts <paramref name="assertion"/> for <paramref name="mfaToken"/> to the sign-in assertion endpoint.</summary>
        public async Task<IActionResult> WebAuthnVerifyAsync(string mfaToken, AuthenticatorAssertionRawResponse assertion)
        {
            var json = JsonSerializer.Serialize(new { mfaToken, assertionResponse = assertion }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var (controller, type, db) = Controller(WebAuthnControllerName, new MemoryStream(Encoding.UTF8.GetBytes(json)));
            using var _ = db;
            return await (Task<IActionResult>)type.GetMethod("VerifyAssertion")!.Invoke(controller, [])!;
        }

        /// <summary>
        /// Runs <paramref name="call"/> <see cref="Parallel"/> times at once: every call is held in
        /// its first cache read until all of them are there, so they overlap through the checks.
        /// </summary>
        public async Task<IActionResult[]> AllAtOnceAsync(Func<int, Task<IActionResult>> call)
        {
            Volatile.Write(ref Cache.Armed, true);
            var calls = Enumerable.Range(0, Parallel).Select(i => Task.Run(() => call(i))).ToArray();
            while (Volatile.Read(ref Cache.Reads) < Parallel)
                await Task.Delay(5);
            Cache.Release();
            return await Task.WhenAll(calls);
        }

        public int RefreshTokenCount()
        {
            using var db = Db();
            return db.RefreshTokens.AsNoTracking().Count(t => t.UserId == UserId);
        }
    }

    /// <summary>Records audit rows from concurrent requests: action and error message.</summary>
    private sealed class ConcurrentAudit : IAuditService
    {
        public System.Collections.Concurrent.ConcurrentQueue<(string Action, string? ErrorMessage)> Entries { get; } = new();

        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            Entries.Enqueue((actionType, errorMessage));
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// A guard that lets every WebAuthn challenge claim through and claims everything else
    /// normally, so a test can show the pending-MFA token's consume deciding on its own.
    /// </summary>
    private sealed class ChallengeBlindGuard : IReplayGuard
    {
        private readonly InProcessReplayGuard _inner = new();
        public Task<bool> TryClaimAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
            => key.StartsWith("webauthn:challenge:", StringComparison.Ordinal) ? Task.FromResult(true) : _inner.TryClaimAsync(key, lifetime, ct);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "mira" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private const string TotpControllerName = "ModularCA.API.Controllers.v1.Auth.TotpController";
    private const string StepUpControllerName = "ModularCA.API.Controllers.v1.Auth.MfaStepUpController";
    private const string WebAuthnControllerName = "ModularCA.API.Controllers.v1.Auth.WebAuthnController";

    /// <summary>The RFC 6238 code for <see cref="Secret"/> at the current time step plus <paramref name="offset"/>.</summary>
    private static string Code(int offset = 0)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var key = new byte[Secret.Length * 5 / 8];
        int buffer = 0, bits = 0, index = 0;
        foreach (var c in Secret)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(c);
            bits += 5;
            if (bits >= 8) { bits -= 8; key[index++] = (byte)(buffer >> bits); }
        }
        var step = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 + offset);
        if (BitConverter.IsLittleEndian) Array.Reverse(step);
        // RFC 6238 TOTP is defined over HMAC-SHA1, as in the controller.
        var hash = HMACSHA1.HashData(key, step);
        var o = hash[^1] & 0x0F;
        var code = ((hash[o] & 0x7F) << 24 | hash[o + 1] << 16 | hash[o + 2] << 8 | hash[o + 3]) % 1_000_000;
        return code.ToString("D6");
    }

    // ── TOTP ─────────────────────────────────────────────────────────────

    /// <summary>
    /// One pending-MFA token, completed by parallel requests with different valid codes (the
    /// current step and the next, both inside the window): the token's consume decides, and
    /// exactly one session is issued.
    /// </summary>
    [Fact]
    public async Task Parallel_totp_verifications_of_one_token_issue_exactly_one_session()
    {
        var w = new World();
        var token = await w.PendingAsync();

        var results = await w.AllAtOnceAsync(i => w.TotpVerifyAsync(token, Code(i % 2)));

        Assert.Single(results, r => r is OkObjectResult);
        // Every other request is refused (401, or 429 once the failure counter trips) and issues nothing.
        Assert.All(results.Where(r => r is not OkObjectResult), r => Assert.True(r is ObjectResult { StatusCode: 401 or 429 }, r.GetType().Name));
        Assert.Equal(1, w.RefreshTokenCount());
    }

    /// <summary>
    /// One TOTP code presented by parallel requests, each with its own pending-MFA token: the
    /// code's time step is claimed once, and exactly one session is issued.
    /// </summary>
    [Fact]
    public async Task Parallel_totp_verifications_of_one_code_issue_exactly_one_session()
    {
        var w = new World();
        var tokens = new string[Parallel];
        for (var i = 0; i < Parallel; i++) tokens[i] = await w.PendingAsync();
        var code = Code();

        var results = await w.AllAtOnceAsync(i => w.TotpVerifyAsync(tokens[i], code));

        Assert.Single(results, r => r is OkObjectResult);
        Assert.Equal(1, w.RefreshTokenCount());
        // Every request that lost is refused. Which check stops it depends on timing: one that
        // reaches the time-step claim after the winner made it is "TOTP code already used"; one
        // that reads the winner's stored LastUsedTimeStep first fails the code check itself
        // ("Invalid TOTP code"); and once five failures are counted, a later one is refused with
        // 429 before its code is looked at, with no failed-TOTP row. So the number of rows varies,
        // from one up to every request that lost.
        Assert.Equal(Parallel - 1, results.Count(r => r is not OkObjectResult));
        var refusals = w.Audit.Entries.Where(e => e.Action == ModularCA.Shared.Enums.AuditActionType.MfaTotpFailed).ToList();
        Assert.InRange(refusals.Count, 1, Parallel - 1);
        Assert.All(refusals, e => Assert.Contains(e.ErrorMessage, new[] { "TOTP code already used", "Invalid TOTP code" }));
    }

    /// <summary>A code used to sign in cannot be used again within its time step, on a new sign-in or for step-up.</summary>
    [Fact]
    public async Task A_used_totp_code_cannot_be_replayed_within_its_time_step()
    {
        var w = new World();
        var code = Code();
        Assert.IsType<OkObjectResult>(await w.TotpVerifyAsync(await w.PendingAsync(), code));

        Assert.IsType<UnauthorizedObjectResult>(await w.TotpVerifyAsync(await w.PendingAsync(), code));
        Assert.IsType<UnauthorizedObjectResult>(await w.StepUpTotpAsync(code));
    }

    /// <summary>
    /// The claim holds even where the database read cannot: a step already claimed (by a
    /// concurrent request on another node, whose LastUsedTimeStep write has not landed) refuses
    /// the code although the stored step still allows it.
    /// </summary>
    [Fact]
    public async Task A_claimed_time_step_is_refused_before_its_database_record_lands()
    {
        var w = new World();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = Code();
        for (var s = step - 1; s <= step + 1; s++)
            Assert.True(await MfaSingleUse.TryClaimTotpStepAsync(w.Guard, w.UserId, s));

        Assert.IsType<UnauthorizedObjectResult>(await w.TotpVerifyAsync(await w.PendingAsync(), code));
        Assert.IsType<UnauthorizedObjectResult>(await w.StepUpTotpAsync(code));
        Assert.Equal(0, w.RefreshTokenCount());
    }

    /// <summary>Parallel step-up requests with one TOTP code: exactly one step-up token is issued.</summary>
    [Fact]
    public async Task Parallel_totp_step_ups_with_one_code_issue_exactly_one_token()
    {
        var w = new World();
        var code = Code();

        // The step-up path reads no pending-MFA token from the cache, so start them together
        // without the gate.
        var results = await Task.WhenAll(Enumerable.Range(0, Parallel).Select(_ => Task.Run(() => w.StepUpTotpAsync(code))));

        Assert.Single(results, r => r is OkObjectResult);
    }

    // ── WebAuthn ─────────────────────────────────────────────────────────

    /// <summary>
    /// IFido2 whose assertion verification succeeds for any response, standing in for an
    /// authenticator: the property under test is what the controller does after a verification
    /// passes, which a replayed assertion does on every concurrent request.
    /// </summary>
    private sealed class AcceptingFido2 : IFido2
    {
        private readonly Fido2 _real = new(new Fido2Configuration
        {
            ServerDomain = "ca.example.test",
            ServerName = "ModularCA",
            Origins = new HashSet<string> { "https://ca.example.test" },
        });

        public AssertionOptions GetAssertionOptions(GetAssertionOptionsParams getAssertionOptionsParams) => _real.GetAssertionOptions(getAssertionOptionsParams);

        public Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams, CancellationToken cancellationToken = default)
            => Task.FromResult(new VerifyAssertionResult
            {
                CredentialId = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(makeAssertionParams.AssertionResponse.Id),
                SignCount = 0,
            });

        public Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams, CancellationToken cancellationToken = default)
            => _real.MakeNewCredentialAsync(makeNewCredentialParams, cancellationToken);

        public CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams requestNewCredentialParams) => _real.RequestNewCredential(requestNewCredentialParams);
    }

    /// <summary>Caches assertion options for the user, as <c>assertion-options</c> does, and returns their challenge.</summary>
    private static async Task<byte[]> CacheAssertionOptionsAsync(World w)
    {
        var options = w.Fido2!.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [new PublicKeyCredentialDescriptor(w.CredentialId)],
            UserVerification = UserVerificationRequirement.Preferred,
        });
        await w.Cache.SetStringAsync($"webauthn:assert:{w.UserId}", options.ToJson());
        return options.Challenge;
    }

    private static AuthenticatorAssertionRawResponse Assertion(World w) => new()
    {
        Id = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(w.CredentialId),
        RawId = w.CredentialId,
        Type = PublicKeyCredentialType.PublicKey,
        Response = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = [1],
            Signature = [1],
            ClientDataJson = [1],
        },
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
    };

    /// <summary>
    /// One signed assertion replayed by parallel requests, each completing its own pending-MFA
    /// token: the challenge is claimed once, and exactly one session is issued.
    /// </summary>
    [Fact]
    public async Task Parallel_webauthn_assertions_over_one_challenge_issue_exactly_one_session()
    {
        var w = new World { Fido2 = new AcceptingFido2() };
        var tokens = new string[Parallel];
        for (var i = 0; i < Parallel; i++) tokens[i] = await w.PendingAsync();
        await CacheAssertionOptionsAsync(w);
        var assertion = Assertion(w);

        var results = await w.AllAtOnceAsync(i => w.WebAuthnVerifyAsync(tokens[i], assertion));

        Assert.Single(results, r => r is OkObjectResult);
        // Every other request is refused and issues nothing: 401 at a claim, or 400 when the winner
        // has already removed the assertion options it answered.
        Assert.All(results.Where(r => r is not OkObjectResult), r => Assert.True(r is ObjectResult { StatusCode: 400 or 401 }, r.GetType().Name));
        Assert.Equal(1, w.RefreshTokenCount());
    }

    /// <summary>
    /// One pending-MFA token completed by parallel requests whose challenge claims all pass (as
    /// if each answered its own challenge): the token's consume decides, and exactly one session
    /// is issued.
    /// </summary>
    [Fact]
    public async Task Parallel_webauthn_assertions_for_one_token_issue_exactly_one_session()
    {
        var w = new World { Fido2 = new AcceptingFido2(), Guard = new ChallengeBlindGuard() };
        var token = await w.PendingAsync();
        await CacheAssertionOptionsAsync(w);
        var assertion = Assertion(w);

        var results = await w.AllAtOnceAsync(_ => w.WebAuthnVerifyAsync(token, assertion));

        Assert.Single(results, r => r is OkObjectResult);
        Assert.Equal(1, w.RefreshTokenCount());
    }

    /// <summary>A challenge already answered is refused on a later request, even with a fresh pending-MFA token.</summary>
    [Fact]
    public async Task An_answered_webauthn_challenge_cannot_be_replayed()
    {
        var w = new World { Fido2 = new AcceptingFido2() };
        var challenge = await CacheAssertionOptionsAsync(w);
        Assert.True(await MfaSingleUse.TryClaimWebAuthnChallengeAsync(w.Guard, challenge));

        var result = await w.WebAuthnVerifyAsync(await w.PendingAsync(), Assertion(w));

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(0, w.RefreshTokenCount());
    }
}
