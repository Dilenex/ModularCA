using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
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
/// A user's default access badge narrows every new session, not only a password-only one: a
/// password sign-in completed with TOTP starts wearing it too. The certificate paths are covered in
/// <see cref="MtlsRevokedCertificateTests"/>.
/// </summary>
public sealed class DefaultBadgeSignInTests
{
    private const string TotpControllerName = "ModularCA.API.Controllers.v1.Auth.TotpController";
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    private sealed class NoDpop : IDpopProofService
    {
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new() { SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0, MaxConcurrentSessions = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public Guid BadgeId { get; } = Guid.NewGuid();
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public IDataProtectionProvider DataProtection { get; } = new EphemeralDataProtectionProvider();

        public World()
        {
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            db.Users.Add(new UserEntity { Id = UserId, Username = "tara", Email = "tara@example.test", IsActive = true, SecurityStamp = "s" });
            db.TotpSecrets.Add(new TotpSecretEntity
            {
                UserId = UserId, IsVerified = true,
                EncryptedSecretKey = DataProtection.CreateProtector("TotpSecret").Protect(Secret),
            });
            db.AccessBadges.Add(new AccessBadgeEntity { Id = BadgeId, UserId = UserId, Name = "Narrow", IsDefault = true });
            db.SaveChanges();
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        /// <summary>Completes a password-first sign-in with the current TOTP code.</summary>
        public async Task<IActionResult> TotpVerifyAsync()
        {
            var mfaToken = Guid.NewGuid().ToString("N");
            await PendingMfaToken.StoreAsync(Cache, mfaToken, UserId, PendingMfaToken.Password, TimeSpan.FromMinutes(5));

            using var db = Db();
            var type = ApiAssembly.TypeNamed(TotpControllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[] { db, Cache, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), DataProtection };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());
            var services = new ServiceCollection()
                .AddSingleton<IDpopProofService>(new NoDpop())
                .AddSingleton(new AccessBadgeService(db))
                .BuildServiceProvider();
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = new DefaultHttpContext { RequestServices = services } });

            var method = type.GetMethods().Single(m => m.Name == "Verify" && m.GetParameters().Length == 1);
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            request.GetType().GetProperty("MfaToken")!.SetValue(request, mfaToken);
            request.GetType().GetProperty("Code")!.SetValue(request, CurrentCode());
            return await (Task<IActionResult>)method.Invoke(controller, new[] { request })!;
        }

        public List<RefreshTokenEntity> RefreshTokens()
        {
            using var db = Db();
            return db.RefreshTokens.AsNoTracking().Where(t => t.UserId == UserId).ToList();
        }
    }

    /// <summary>The RFC 6238 code for <see cref="Secret"/> at the current time step.</summary>
    private static string CurrentCode()
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
        var step = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        if (BitConverter.IsLittleEndian) Array.Reverse(step);
        // RFC 6238 TOTP is defined over HMAC-SHA1, as in the controller.
        var hash = HMACSHA1.HashData(key, step);
        var offset = hash[^1] & 0x0F;
        var code = ((hash[offset] & 0x7F) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3]) % 1_000_000;
        return code.ToString("D6");
    }

    [Fact]
    public async Task A_sign_in_completed_with_totp_starts_wearing_the_default_badge()
    {
        using var w = new World();

        var ok = Assert.IsType<OkObjectResult>(await w.TotpVerifyAsync());

        var token = (string)ok.Value!.GetType().GetProperty("Token")!.GetValue(ok.Value)!;
        Assert.Equal(w.BadgeId.ToString(), new JwtSecurityTokenHandler().ReadJwtToken(token)
            .Claims.SingleOrDefault(c => c.Type == AccessBadgeContext.BadgeClaim)?.Value);
        Assert.Equal(w.BadgeId, Assert.Single(w.RefreshTokens()).AccessBadgeId);
    }
}
