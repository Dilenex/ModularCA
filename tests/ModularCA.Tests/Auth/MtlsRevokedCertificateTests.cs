using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// A client certificate revoked through the ordinary revocation service no longer signs in or
/// passes step-up on any mTLS path, a certificate on hold is refused until released, a credential
/// whose certificate record is gone is refused, and a redirect sign-in's session is bound to the
/// DPoP key that proves possession at the code exchange. Revoking or holding the certificate, or
/// revoking the credential from the account page, ends every session of its holder. Real
/// certificates and chain validation, SQLite, and the real controllers.
/// </summary>
public sealed class MtlsRevokedCertificateTests
{
    private const string AuthControllerName = "ModularCA.API.Controllers.v1.Auth.AuthController";
    private const string MtlsControllerName = "ModularCA.API.Controllers.v1.Auth.MtlsController";
    private const string StepUpControllerName = "ModularCA.API.Controllers.v1.Auth.MfaStepUpController";

    private sealed class FixedDpop : IDpopProofService
    {
        public string? Jkt { get; set; }
        public Task<string?> GetValidatedJktAsync(HttpContext context, CancellationToken ct = default) => Task.FromResult(Jkt);
    }

    private sealed class FixedPolicy : ISecurityPolicyService
    {
        private readonly SecurityPolicyEntity _policy = new() { SessionIdleTimeoutMinutes = 0, MaxSessionLifetimeDays = 0, LoginResponseDelayMs = 0, MaxConcurrentSessions = 0 };
        public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);
        public void InvalidateCache() { }
    }

    private sealed class CurrentUserStub(Guid id) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "maya" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public Guid CaId { get; } = Guid.NewGuid();
        public Guid LeafCertificateId { get; } = Guid.NewGuid();
        public Guid CredentialId { get; } = Guid.NewGuid();
        public X509Certificate2 Leaf { get; }
        public SystemConfig Config { get; } = new()
        {
            JWT = new JwtConfig { Secret = new string('k', 64) },
            Security = new SecurityConfig { BindRefreshTokenToIp = false, BindRefreshTokenToFingerprint = false },
        };
        public FixedDpop Dpop { get; } = new();
        public RecordingAuditService Audit { get; } = new();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public Guid OtherUserId { get; } = Guid.NewGuid();

        /// <summary>The <c>MfaMtlsHandoff</c> cookie the next controller call carries, when set.</summary>
        public string? HandoffCookie { get; set; }

        public World(bool linkCertificate = true)
        {
            Config.Https.PublicDomain = "ca.example.test";
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();

            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=Mtls Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));

            using var leafKey = RSA.Create(2048);
            var leafRequest = new CertificateRequest("CN=maya, O=ModularCA mTLS", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
            using var leaf = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
            Leaf = X509CertificateLoader.LoadCertificate(leaf.RawData);

            var caCertId = Guid.NewGuid();
            db.Users.Add(new UserEntity { Id = UserId, Username = "maya", Email = "maya@example.test", IsActive = true, SecurityStamp = "s" });
            db.Users.Add(new UserEntity { Id = OtherUserId, Username = "noor", Email = "noor@example.test", IsActive = true, SecurityStamp = "o" });
            db.Certificates.Add(Row(caCertId, ca, "01", isCa: true));
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = CaId, Name = "Mtls Test CA", Label = "mtls-test", CertificateId = caCertId });
            db.Certificates.Add(Row(LeafCertificateId, Leaf, "02", isCa: false, issuerId: caCertId));
            db.MtlsCredentials.Add(new MtlsCredentialEntity
            {
                Id = CredentialId,
                UserId = UserId,
                CertificateId = linkCertificate ? LeafCertificateId : null,
                SigningCaId = CaId,
                Thumbprint = Leaf.GetCertHashString(HashAlgorithmName.SHA256),
                SerialNumber = "02",
                IssuedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddYears(1),
            });
            db.SaveChanges();
        }

        private static CertificateEntity Row(Guid id, X509Certificate2 cert, string serial, bool isCa, Guid? issuerId = null) => new()
        {
            CertificateId = id,
            SerialNumber = serial,
            SubjectDN = cert.Subject,
            Issuer = cert.Issuer,
            Pem = cert.ExportCertificatePem(),
            RawCertificate = cert.RawData,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            Thumbprints = "{}",
            IsCA = isCa,
            IssuerCertificateId = issuerId,
            SubjectAlternativeNamesJson = "[]",
            KeyUsagesJson = "[]",
            ExtendedKeyUsagesJson = "[]",
        };

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose()
        {
            Leaf.Dispose();
            _connection.Dispose();
        }

        /// <summary>Revokes the client certificate through the ordinary revocation service.</summary>
        public async Task RevokeAsync(RevocationReason reason = RevocationReason.KeyCompromise)
        {
            using var db = Db();
            await NewRevocationService(db).RevokeCertificateAsync(LeafCertificateId, null, reason);
        }

        /// <summary>Places the client certificate on hold, or releases it, through the revocation service.</summary>
        public async Task HoldAsync(bool hold)
        {
            using var db = Db();
            var svc = NewRevocationService(db);
            if (hold) await svc.HoldCertificateAsync(LeafCertificateId, null);
            else await svc.UnholdCertificateAsync(LeafCertificateId, null);
        }

        // The keystore, store, notifier and CRL service are not reached on these paths except for
        // the best-effort notification and CRL regeneration, which swallow their own failures.
        private CertificateRevocationService NewRevocationService(ModularCADbContext db)
            => new(db, null!, null!, null!, null!, NullLogger<CertificateRevocationService>.Instance, Cache, Audit);

        /// <summary>
        /// Two live sessions for the certificate's holder and one for another account, and the
        /// holder's stamp in the stamp cache, as the token check leaves it.
        /// </summary>
        public void SeedSessions()
        {
            using var db = Db();
            foreach (var (user, token) in new[] { (UserId, "a"), (UserId, "b"), (OtherUserId, "c") })
                db.RefreshTokens.Add(new RefreshTokenEntity { UserId = user, Token = token, ExpiresAt = DateTime.UtcNow.AddDays(1) });
            db.SaveChanges();
            Cache.SetString(UserSessionTermination.StampCacheKey(UserId), "s|g");
        }

        public string Stamp(Guid userId)
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == userId).SecurityStamp;
        }

        public bool StampCached => Cache.GetString(UserSessionTermination.StampCacheKey(UserId)) != null;

        public List<RefreshTokenEntity> RefreshTokensOf(Guid userId)
        {
            using var db = Db();
            return db.RefreshTokens.AsNoTracking().Where(t => t.UserId == userId).ToList();
        }

        /// <summary>Whether a <c>UserSessionsEnded</c> record for the holder carries <paramref name="reason"/>.</summary>
        public bool AuditedSessionsEnded(string reason)
            => Audit.Entries.Any(e => e.Action == AuditActionType.UserSessionsEnded && e.TargetId == UserId.ToString()
                && JsonSerializer.Serialize(e.Details).Contains($"\"{reason}\""));

        /// <summary>Gives the holder a verified authenticator app, so the certificate is not their only factor.</summary>
        public void AddVerifiedTotp()
        {
            using var db = Db();
            db.TotpSecrets.Add(new TotpSecretEntity { UserId = UserId, EncryptedSecretKey = "x", IsVerified = true });
            db.SaveChanges();
        }

        /// <summary>Invokes <paramref name="action"/> on a fresh controller with the client certificate on the connection.</summary>
        public async Task<IActionResult> InvokeAsync(string controllerName, string action, params object?[] args)
        {
            using var db = Db();
            var type = ApiAssembly.TypeNamed(controllerName);
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            var available = new object[]
            {
                db, new JwtTokenService(Config), Audit, Config, new FixedPolicy(), Cache,
                new CurrentUserStub(UserId), new EphemeralDataProtectionProvider(),
            };
            var controller = ctor.Invoke(ctor.GetParameters()
                .Select(p => available.FirstOrDefault(a => p.ParameterType.IsInstanceOfType(a)))
                .ToArray());

            var services = new ServiceCollection().AddSingleton<IDpopProofService>(Dpop).BuildServiceProvider();
            var http = new DefaultHttpContext
            {
                RequestServices = services,
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", UserId.ToString()) }, "test")),
            };
            if (HandoffCookie != null)
                http.Request.Headers.Cookie = $"MfaMtlsHandoff={HandoffCookie}";
            http.Connection.ClientCertificate = Leaf;
            http.Request.Host = new HostString("ca.example.test");
            type.GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext { HttpContext = http });

            var method = type.GetMethods().Single(m => m.Name == action && m.GetParameters().Length == args.Length);
            return await (Task<IActionResult>)method.Invoke(controller, args)!;
        }

        public async Task<IActionResult> CertLoginAsync() => await InvokeAsync(AuthControllerName, "CertLogin");

        public async Task<IActionResult> LoginRedirectAsync() => await InvokeAsync(MtlsControllerName, "LoginRedirect");

        public async Task<IActionResult> MtlsVerifyAsync()
        {
            var token = Guid.NewGuid().ToString("N");
            await PendingMfaToken.StoreAsync(Cache, token, UserId, PendingMfaToken.Password, TimeSpan.FromMinutes(5));
            return await InvokeAsync(MtlsControllerName, "Verify", Request(MtlsControllerName, "Verify", ("MfaToken", token)));
        }

        public async Task<IActionResult> VerifyRedirectAsync()
        {
            var token = Guid.NewGuid().ToString("N");
            await PendingMfaToken.StoreAsync(Cache, token, UserId, PendingMfaToken.Password, TimeSpan.FromMinutes(5));
            HandoffCookie = token;
            try { return await InvokeAsync(MtlsControllerName, "VerifyRedirect"); }
            finally { HandoffCookie = null; }
        }

        /// <summary>Revokes the credential from the account page, with a valid step-up token.</summary>
        public async Task<IActionResult> RevokeCredentialAsync()
        {
            var stepUp = Guid.NewGuid().ToString("N");
            Cache.SetString($"mfa-stepup:{UserId}:{StepUpOps.MtlsDelete}:{CredentialId}", stepUp);
            return await InvokeAsync(MtlsControllerName, "RevokeCredential", CredentialId, stepUp);
        }

        public async Task<IActionResult> StepUpAsync()
            => await InvokeAsync(StepUpControllerName, "VerifyStepUpMtls",
                Request(StepUpControllerName, "VerifyStepUpMtls", ("Operation", StepUpOps.TotpSetup)));

        public async Task<IActionResult> ExchangeAsync(string code)
            => await InvokeAsync(MtlsControllerName, "ExchangeCode", Request(MtlsControllerName, "ExchangeCode", ("Code", code)));

        private static object Request(string controllerName, string action, params (string Name, object Value)[] values)
        {
            var method = ApiAssembly.TypeNamed(controllerName).GetMethods().Single(m => m.Name == action && m.GetParameters().Length == 1);
            var request = Activator.CreateInstance(method.GetParameters()[0].ParameterType)!;
            foreach (var (name, value) in values)
                request.GetType().GetProperty(name)!.SetValue(request, value);
            return request;
        }

        public List<RefreshTokenEntity> RefreshTokens()
        {
            using var db = Db();
            return db.RefreshTokens.AsNoTracking().Where(t => t.UserId == UserId).ToList();
        }

        public MtlsCredentialEntity Credential()
        {
            using var db = Db();
            return db.MtlsCredentials.AsNoTracking().Single(c => c.Id == CredentialId);
        }

        public bool CountsAsActiveFactor()
        {
            using var db = Db();
            return db.MtlsCredentials.Where(MtlsCredentialStatus.Usable(DateTime.UtcNow)).Any(c => c.UserId == UserId);
        }

        /// <summary>Revokes the client certificate's row only, leaving the credential row unrevoked.</summary>
        public void RevokeCertificateRowOnly()
        {
            using var db = Db();
            var cert = db.Certificates.Single(c => c.CertificateId == LeafCertificateId);
            cert.Revoked = true;
            cert.RevocationReason = nameof(RevocationReason.KeyCompromise);
            cert.RevocationDate = DateTime.UtcNow;
            db.SaveChanges();
        }

        /// <summary>The account's MFA marker as a controlled-user ceremony pins it.</summary>
        public async Task<string> MfaMarkerAsync()
        {
            using var db = Db();
            return Assert.Single(await ModularCA.Auth.Authorization.ControlledCredentials.SnapshotAsync(db, [UserId])).MfaMarker;
        }

        /// <summary>The <c>mtls</c> part of <c>GET /api/v1/account/mfa</c>, as JSON.</summary>
        public async Task<JsonElement> MfaStatusMtlsAsync()
        {
            var ok = Assert.IsType<OkObjectResult>(await InvokeAsync("ModularCA.API.Controllers.v1.Account.AccountManagerController", "GetMfaStatus"));
            return JsonSerializer.SerializeToElement(ok.Value).GetProperty("mtls");
        }

        /// <summary>Whether a failed sign-in or step-up was audited with <paramref name="reason"/>.</summary>
        public bool AuditedRefusal(string reason) => AuditedRefusals(reason) > 0;

        /// <summary>How many failed sign-ins and step-ups were audited with <paramref name="reason"/>.</summary>
        public int AuditedRefusals(string reason)
            => Audit.Entries.Count(e => (e.Action == AuditActionType.UserLoginFailed || e.Action == AuditActionType.MfaStepUpFailed)
                && JsonSerializer.Serialize(e.Details).Contains($"\"{reason}\""));
    }

    private static string Location(IActionResult result) => Assert.IsType<RedirectResult>(result).Url;

    [Fact]
    public async Task An_unrevoked_certificate_signs_in_on_every_path()
    {
        using var w = new World();

        Assert.IsType<OkObjectResult>(await w.CertLoginAsync());
        Assert.Contains("/mfa-callback?code=", Location(await w.LoginRedirectAsync()));
        Assert.IsType<OkObjectResult>(await w.MtlsVerifyAsync());
        Assert.IsType<OkObjectResult>(await w.StepUpAsync());
        Assert.True(w.CountsAsActiveFactor());
    }

    [Fact]
    public async Task A_certificate_revoked_through_the_revocation_service_no_longer_signs_in_or_steps_up()
    {
        using var w = new World();
        await w.RevokeAsync();

        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.Contains("error=cert_revoked", Location(await w.LoginRedirectAsync()));
        Assert.Contains("error=cert_revoked", Location(await w.VerifyRedirectAsync()));
        Assert.IsType<UnauthorizedObjectResult>(await w.MtlsVerifyAsync());
        Assert.IsType<UnauthorizedObjectResult>(await w.StepUpAsync());

        Assert.Empty(w.RefreshTokens());
        Assert.False(w.CountsAsActiveFactor());
        // Belt and braces: the permanent revocation also revoked the credential row.
        Assert.True(w.Credential().IsRevoked);
        // The revoked credential row is still recognised, so each refusal says why.
        Assert.Equal(5, w.AuditedRefusals("mtls_certificate_revoked"));
        Assert.Equal(0, w.AuditedRefusals("cert_thumbprint_unknown"));
    }

    [Fact]
    public async Task A_credential_revoked_on_its_own_is_refused_as_not_enrolled()
    {
        using var w = new World();
        using (var db = w.Db())
        {
            db.MtlsCredentials.Single(c => c.Id == w.CredentialId).IsRevoked = true;
            db.SaveChanges();
        }

        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.Contains("error=auth_failed", Location(await w.LoginRedirectAsync()));
        Assert.True(w.AuditedRefusal("cert_thumbprint_unknown"));
        Assert.False(w.AuditedRefusal("mtls_certificate_revoked"));
    }

    [Fact]
    public async Task Revoking_the_certificate_ends_every_session_of_its_holder()
    {
        using var w = new World();
        w.SeedSessions();

        await w.RevokeAsync();

        Assert.All(w.RefreshTokensOf(w.UserId), t => { Assert.True(t.IsRevoked); Assert.NotNull(t.RevokedAt); });
        Assert.NotEqual("s", w.Stamp(w.UserId));
        Assert.False(w.StampCached);
        Assert.True(w.AuditedSessionsEnded("mtls_certificate_revoked"));

        Assert.False(Assert.Single(w.RefreshTokensOf(w.OtherUserId)).IsRevoked);
        Assert.Equal("o", w.Stamp(w.OtherUserId));
    }

    [Fact]
    public async Task Holding_the_certificate_ends_every_session_and_a_release_restores_sign_in()
    {
        using var w = new World();
        w.SeedSessions();

        await w.HoldAsync(hold: true);

        Assert.All(w.RefreshTokensOf(w.UserId), t => Assert.True(t.IsRevoked));
        Assert.NotEqual("s", w.Stamp(w.UserId));
        Assert.False(w.StampCached);
        Assert.True(w.AuditedSessionsEnded("mtls_certificate_on_hold"));
        Assert.False(w.Credential().IsRevoked);
        Assert.False(Assert.Single(w.RefreshTokensOf(w.OtherUserId)).IsRevoked);

        await w.HoldAsync(hold: false);
        Assert.IsType<OkObjectResult>(await w.CertLoginAsync());
    }

    [Fact]
    public async Task Revoking_the_credential_from_the_account_page_ends_every_session()
    {
        using var w = new World();
        w.AddVerifiedTotp();
        w.SeedSessions();

        Assert.IsType<OkObjectResult>(await w.RevokeCredentialAsync());

        Assert.True(w.Credential().IsRevoked);
        Assert.All(w.RefreshTokensOf(w.UserId), t => Assert.True(t.IsRevoked));
        Assert.NotEqual("s", w.Stamp(w.UserId));
        Assert.False(w.StampCached);
        Assert.True(w.AuditedSessionsEnded("mtls_credential_revoked"));
        Assert.False(Assert.Single(w.RefreshTokensOf(w.OtherUserId)).IsRevoked);

        // Its certificate was revoked with it, so presenting it again is refused as revoked.
        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.True(w.AuditedRefusal("mtls_certificate_revoked"));
    }

    [Fact]
    public async Task A_revoked_certificate_whose_credential_row_was_left_unrevoked_is_refused_and_audited()
    {
        using var w = new World();
        // A revocation path that touches only the certificate row (as several did): the credential
        // stays unrevoked, and the certificate's own status must still stop it.
        using (var db = w.Db())
        {
            var cert = db.Certificates.Single(c => c.CertificateId == w.LeafCertificateId);
            cert.Revoked = true;
            cert.RevocationReason = nameof(RevocationReason.KeyCompromise);
            cert.RevocationDate = DateTime.UtcNow;
            db.SaveChanges();
        }

        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.Contains("error=cert_revoked", Location(await w.LoginRedirectAsync()));
        Assert.IsType<UnauthorizedObjectResult>(await w.MtlsVerifyAsync());
        Assert.IsType<UnauthorizedObjectResult>(await w.StepUpAsync());

        Assert.Empty(w.RefreshTokens());
        Assert.True(w.AuditedRefusal("mtls_certificate_revoked"));
        Assert.Equal(4, w.Audit.Entries.Count(e => JsonSerializer.Serialize(e.Details).Contains("\"mtls_certificate_revoked\"")));
    }

    [Fact]
    public async Task A_certificate_on_hold_is_refused_until_it_is_released()
    {
        using var w = new World();
        await w.HoldAsync(hold: true);

        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.False(w.Credential().IsRevoked);

        await w.HoldAsync(hold: false);
        Assert.IsType<OkObjectResult>(await w.CertLoginAsync());
    }

    [Fact]
    public async Task A_credential_whose_certificate_record_is_gone_is_refused()
    {
        using var w = new World(linkCertificate: false);

        Assert.IsType<UnauthorizedObjectResult>(await w.CertLoginAsync());
        Assert.True(w.AuditedRefusal("mtls_certificate_record_missing"));
        Assert.False(w.CountsAsActiveFactor());
    }

    [Fact]
    public async Task A_credential_whose_certificate_is_revoked_does_not_count_in_the_controlled_user_mfa_marker()
    {
        using var w = new World();
        var withCredential = await w.MfaMarkerAsync();

        w.RevokeCertificateRowOnly();
        var afterRevocation = await w.MfaMarkerAsync();
        Assert.NotEqual(withCredential, afterRevocation);

        using (var db = w.Db())
        {
            db.MtlsCredentials.Remove(db.MtlsCredentials.Single(c => c.Id == w.CredentialId));
            db.SaveChanges();
        }
        Assert.Equal(afterRevocation, await w.MfaMarkerAsync());
    }

    [Fact]
    public async Task The_account_mfa_listing_leaves_out_a_credential_whose_certificate_is_revoked()
    {
        using var w = new World();
        var before = await w.MfaStatusMtlsAsync();
        Assert.True(before.GetProperty("enrolled").GetBoolean());
        Assert.Equal(1, before.GetProperty("credentials").GetArrayLength());

        w.RevokeCertificateRowOnly();
        var after = await w.MfaStatusMtlsAsync();
        Assert.False(after.GetProperty("enrolled").GetBoolean());
        Assert.Equal(0, after.GetProperty("credentials").GetArrayLength());
    }

    [Fact]
    public async Task The_account_mfa_listing_leaves_out_a_credential_whose_certificate_is_on_hold()
    {
        using var w = new World();
        await w.HoldAsync(hold: true);
        Assert.False((await w.MfaStatusMtlsAsync()).GetProperty("enrolled").GetBoolean());

        await w.HoldAsync(hold: false);
        Assert.True((await w.MfaStatusMtlsAsync()).GetProperty("enrolled").GetBoolean());
    }

    [Fact]
    public async Task The_code_exchange_binds_a_redirect_sign_in_to_the_proving_key()
    {
        using var w = new World();
        var location = Location(await w.LoginRedirectAsync());
        var code = location[(location.IndexOf("code=", StringComparison.Ordinal) + 5)..];
        Assert.Null(Assert.Single(w.RefreshTokens()).CnfJkt);

        w.Dpop.Jkt = "jkt-of-this-browser";
        Assert.IsType<OkObjectResult>(await w.ExchangeAsync(code));

        Assert.Equal("jkt-of-this-browser", Assert.Single(w.RefreshTokens()).CnfJkt);
    }

    [Fact]
    public async Task The_mtls_verify_endpoint_binds_its_session_to_the_proving_key()
    {
        using var w = new World();
        w.Dpop.Jkt = "jkt-of-this-client";

        Assert.IsType<OkObjectResult>(await w.MtlsVerifyAsync());

        Assert.Equal("jkt-of-this-client", Assert.Single(w.RefreshTokens()).CnfJkt);
    }
}
