using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Acme;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// Drives <c>AcmeAccountController.NewAccount</c> at a CA that requires external account binding,
/// for the EAB single-use tests here and on PostgreSQL.
/// </summary>
internal static class AcmeEabHarness
{
    public const string Domain = "ca.example";

    /// <summary>Ignores every audit row; these tests assert on the database.</summary>
    private sealed class NoAudit : IProtocolAuditService
    {
        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null) => Task.CompletedTask;
        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null) => throw new NotSupportedException();
        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null) => throw new NotSupportedException();
        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null) => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null) => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null) => throw new NotSupportedException();
    }

    /// <summary>An enabled instance CA labelled <c>strict</c> whose ACME requires EAB.</summary>
    public static async Task<CertificateAuthorityEntity> SeedCaAsync(ModularCADbContext db)
    {
        var ca = new CertificateAuthorityEntity { Name = "Strict CA", Label = "strict", IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { CaId = ca.Id, Protocol = "ACME", IsEnabled = true, AcmeRequireEab = true });
        await db.SaveChangesAsync();
        return ca;
    }

    /// <summary>An unused EAB key named <paramref name="keyId"/> in the store; returns its HMAC key.</summary>
    public static async Task<byte[]> SeedEabKeyAsync(ModularCADbContext db, string keyId)
    {
        var hmac = RandomNumberGenerator.GetBytes(32);
        db.AcmeEabKeys.Add(new AcmeEabKeyEntity { KeyId = keyId, HmacKey = B64(hmac) });
        await db.SaveChangesAsync();
        return hmac;
    }

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A fresh P-256 account key as a JWK and its RFC 7638 thumbprint.</summary>
    public static (string Jwk, string Thumbprint) NewKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = key.ExportParameters(false);
        var jwk = $$"""{"crv":"P-256","kty":"EC","x":"{{B64(p.Q.X!)}}","y":"{{B64(p.Q.Y!)}}"}""";
        return (jwk, new AcmeJwsService(null!, null!).ComputeThumbprint(jwk));
    }

    /// <summary>A valid external account binding of <paramref name="jwk"/> made with EAB key <paramref name="keyId"/>.</summary>
    public static JsonElement Binding(byte[] hmac, string keyId, string jwk)
    {
        var protectedB64 = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { alg = "HS256", kid = keyId, url = $"https://{Domain}/acme/strict/new-account" })));
        var payloadB64 = B64(Encoding.UTF8.GetBytes(jwk));
        var signature = B64(HMACSHA256.HashData(hmac, Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}")));
        return JsonSerializer.SerializeToElement(new { @protected = protectedB64, payload = payloadB64, signature });
    }

    /// <summary>
    /// Posts new-account to <paramref name="ca"/> as the JWS filter would hand it over: signed by
    /// <paramref name="jwk"/> (an existing account's when <paramref name="accountId"/> is set) and
    /// carrying <paramref name="binding"/>. <paramref name="jws"/> replaces the real JWS service.
    /// </summary>
    public static async Task<ObjectResult> NewAccountAsync(ModularCADbContext db, CertificateAuthorityEntity ca, string jwk, string thumbprint,
        JsonElement binding, Guid? accountId = null, IAcmeJwsService? jws = null)
    {
        var config = new SystemConfig();
        config.Https.PublicDomain = Domain;
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Acme.AcmeAccountController");
        var controller = Activator.CreateInstance(type, new AcmeAccountService(db), jws ?? new AcmeJwsService(null!, null!), db, config,
            new RecordingAuditService(), new NoAudit())!;
        var http = new DefaultHttpContext();
        http.Request.RouteValues["caLabel"] = ca.Label;
        http.Items["AcmeJws"] = new AcmeJwsPayload
        {
            AccountId = accountId,
            Jwk = JsonDocument.Parse(jwk).RootElement.Clone(),
            JwkThumbprint = thumbprint,
            Payload = JsonSerializer.Serialize(new { termsOfServiceAgreed = true, externalAccountBinding = binding }),
        };
        http.Items[(string)ApiAssembly.TypeNamed("ModularCA.API.Filters.AcmeJwsActionFilter").GetField("AddressedCaItem")!.GetValue(null)!] = ca;
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });
        return Assert.IsAssignableFrom<ObjectResult>(await (Task<IActionResult>)type.GetMethod("NewAccount")!.Invoke(controller, null)!);
    }
}

/// <summary>
/// An EAB key binds one ACME account. New-account checked that the key was unused, created the
/// account, and then marked the key used with an unconditional write that swallowed every error,
/// so two requests presenting the same key at once both passed the check and both got an account,
/// the second overwriting the record of the first. The key is now claimed with a conditional
/// UPDATE before the account is created, and a request whose claim affects no row is refused.
/// SQLite rather than the in-memory provider, which cannot execute ExecuteUpdate; the concurrent
/// version against PostgreSQL is <c>PostgresAcmeEabTests</c>.
/// </summary>
public sealed class AcmeEabSingleUseTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public AcmeEabSingleUseTests()
    {
        _connection.Open();
        using var db = Context();
        db.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private ModularCADbContext Context() =>
        new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

    /// <summary>
    /// The real JWS service, which on its <paramref name="raceOnCall"/>th thumbprint, inside the
    /// EAB check after the key was read as unused, lets <paramref name="competitor"/> run: another
    /// request binding the same key in between this request's check and its write.
    /// </summary>
    private sealed class RacingJws(int raceOnCall, Func<Task> competitor) : IAcmeJwsService
    {
        private readonly AcmeJwsService _inner = new(null!, null!);
        private int _calls;

        public Task<AcmeJwsPayload> ParseAndVerifyAsync(string rawBody, string requestUrl) => throw new NotSupportedException();
        public void VerifySignature(string protectedB64, string payloadB64, string signatureB64, string jwkJson) => throw new NotSupportedException();

        public string ComputeThumbprint(string jwkJson)
        {
            if (++_calls == raceOnCall)
                competitor().GetAwaiter().GetResult();
            return _inner.ComputeThumbprint(jwkJson);
        }
    }

    /// <summary>Another request's account, bound with EAB key <paramref name="keyId"/>, written through its own context.</summary>
    private async Task<Guid> CompetitorBindsAsync(Guid caId, string keyId)
    {
        await using var other = Context();
        var (jwk, thumb) = AcmeEabHarness.NewKey();
        var account = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumb, CertificateAuthorityId = caId };
        other.AcmeAccounts.Add(account);
        var key = await other.AcmeEabKeys.SingleAsync(k => k.KeyId == keyId);
        key.IsUsed = true;
        key.UsedAt = DateTime.UtcNow;
        key.UsedByAccountId = account.Id;
        await other.SaveChangesAsync();
        return account.Id;
    }

    /// <summary>
    /// The finding: a request that read the key as unused, while another request bound it before
    /// this one wrote, is refused with <c>unauthorized</c>; no second account is created and the key
    /// still names the first.
    /// </summary>
    [Fact]
    public async Task A_new_account_whose_eab_key_was_bound_meanwhile_is_refused()
    {
        await using var db = Context();
        var ca = await AcmeEabHarness.SeedCaAsync(db);
        var hmac = await AcmeEabHarness.SeedEabKeyAsync(db, "eab-1");
        var (jwk, thumb) = AcmeEabHarness.NewKey();
        Guid? winner = null;
        // Thumbprint 1 is the new account key's; 2 is the EAB check's, after it read the key.
        var racing = new RacingJws(2, async () => winner = await CompetitorBindsAsync(ca.Id, "eab-1"));

        var result = await AcmeEabHarness.NewAccountAsync(db, ca, jwk, thumb, AcmeEabHarness.Binding(hmac, "eab-1", jwk), jws: racing);

        Assert.Equal(403, result.StatusCode);
        Assert.Equal("urn:ietf:params:acme:error:unauthorized", Assert.IsType<AcmeErrorResponse>(result.Value).Type);
        await using var read = Context();
        Assert.Equal(winner, (await read.AcmeAccounts.SingleAsync()).Id);
        Assert.Equal(winner, (await read.AcmeEabKeys.SingleAsync()).UsedByAccountId);
    }

    /// <summary>
    /// The same race on the path that binds an account the upgrade left unbound: the account stays
    /// unbound and the key still names the other request's account.
    /// </summary>
    [Fact]
    public async Task Binding_an_unbound_account_with_an_eab_key_bound_meanwhile_is_refused()
    {
        await using var db = Context();
        var ca = await AcmeEabHarness.SeedCaAsync(db);
        var hmac = await AcmeEabHarness.SeedEabKeyAsync(db, "eab-1");
        var (jwk, thumb) = AcmeEabHarness.NewKey();
        var unbound = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumb, CaLabel = "gone" };
        db.AcmeAccounts.Add(unbound);
        await db.SaveChangesAsync();
        Guid? winner = null;
        // Thumbprint 1 is the EAB check's, after it read the key.
        var racing = new RacingJws(1, async () => winner = await CompetitorBindsAsync(ca.Id, "eab-1"));

        var result = await AcmeEabHarness.NewAccountAsync(db, ca, jwk, thumb, AcmeEabHarness.Binding(hmac, "eab-1", jwk), unbound.Id, racing);

        Assert.Equal(403, result.StatusCode);
        Assert.Equal("urn:ietf:params:acme:error:unauthorized", Assert.IsType<AcmeErrorResponse>(result.Value).Type);
        await using var read = Context();
        Assert.Null((await read.AcmeAccounts.SingleAsync(a => a.Id == unbound.Id)).CertificateAuthorityId);
        Assert.Equal(winner, (await read.AcmeEabKeys.SingleAsync()).UsedByAccountId);
    }

    /// <summary>Without a competitor the key binds the new account, and a second account with the same key is refused.</summary>
    [Fact]
    public async Task An_eab_key_binds_the_first_account_and_refuses_the_next()
    {
        await using var db = Context();
        var ca = await AcmeEabHarness.SeedCaAsync(db);
        var hmac = await AcmeEabHarness.SeedEabKeyAsync(db, "eab-1");
        var (jwk, thumb) = AcmeEabHarness.NewKey();
        var (jwk2, thumb2) = AcmeEabHarness.NewKey();

        var first = await AcmeEabHarness.NewAccountAsync(db, ca, jwk, thumb, AcmeEabHarness.Binding(hmac, "eab-1", jwk));
        var second = await AcmeEabHarness.NewAccountAsync(db, ca, jwk2, thumb2, AcmeEabHarness.Binding(hmac, "eab-1", jwk2));

        Assert.Equal(201, first.StatusCode);
        Assert.Equal(403, second.StatusCode);
        await using var read = Context();
        var account = await read.AcmeAccounts.SingleAsync();
        Assert.Equal(thumb, account.JwkThumbprint);
        var key = await read.AcmeEabKeys.SingleAsync();
        Assert.True(key.IsUsed);
        Assert.NotNull(key.UsedAt);
        Assert.Equal(account.Id, key.UsedByAccountId);
    }
}
