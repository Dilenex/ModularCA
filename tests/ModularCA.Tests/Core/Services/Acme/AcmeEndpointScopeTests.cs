using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Core.Services.Acme;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// What the ACME endpoints do with the CA <c>AcmeJwsActionFilter</c> hands them: new-account and
/// new-order refuse a CA that does not serve ACME, as the directory does; new-account binds an
/// account the upgrade left unbound, under the CA's EAB policy; and the account's audit rows carry
/// the bound CA's label, id and space.
/// </summary>
public class AcmeEndpointScopeTests
{
    private const string Domain = "ca.example";

    /// <summary>Records ACME protocol rows and audit rows with their CA scope.</summary>
    private sealed class Recorder : IProtocolAuditService, IAuditService
    {
        public List<(string Operation, string? CaLabel, Guid? CaId, Guid? SpaceId)> Rows { get; } = [];

        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
        {
            Rows.Add((operation, caLabel, certificateAuthorityId, spaceId));
            return Task.CompletedTask;
        }

        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            var label = details?.GetType().GetProperty("CaLabel")?.GetValue(details) as string;
            Rows.Add((actionType, label, certificateAuthorityId, spaceId));
            return Task.CompletedTask;
        }

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }

    /// <summary>A rate limiter that never limits, so a refusal is the endpoint's own.</summary>
    private sealed class Unlimited : IAcmeAccountRateLimiter
    {
        public Task<bool> TryRecordNewOrderAsync(Guid accountId) => Task.FromResult(true);
        public Task<bool> TryRecordFinalizeAsync(Guid accountId) => Task.FromResult(true);
        public Task<bool> TryRecordFailedValidationAsync(Guid accountId) => Task.FromResult(true);
    }

    /// <summary>An order service whose finalize succeeds without issuing, for the finalize audit rows.</summary>
    private sealed class FinalizingOrders(Guid accountId) : IAcmeOrderService
    {
        public Task<AcmeOrderDto> FinalizeAsync(Guid orderId, string csrBase64Url, string baseUrl, CertificateAuthorityEntity addressedCa)
            => Task.FromResult(new AcmeOrderDto { Id = orderId, Status = "valid" });
        public Task<Guid?> GetAccountIdForOrderAsync(Guid orderId) => Task.FromResult<Guid?>(accountId);
        public Task<string?> GetIssuedCertificateSerialForOrderAsync(Guid orderId) => Task.FromResult<string?>("01");
        public Task<AcmeOrderDto> CreateAsync(Guid accountId, CreateAcmeOrderRequest request, string baseUrl, CertificateAuthorityEntity ca) => throw new NotSupportedException();
        public Task<AcmeOrderDto?> GetByIdAsync(Guid orderId, string baseUrl) => throw new NotSupportedException();
        public Task<List<AcmeOrderDto>> GetByAccountAsync(Guid accountId, string baseUrl) => throw new NotSupportedException();
        public Task<string?> DownloadCertificateAsync(Guid orderId) => throw new NotSupportedException();
        public Task<Guid?> GetAccountIdForCertificateSerialAsync(string serialNumber, byte[]? presentedDer = null) => throw new NotSupportedException();
        public Task ExpireStaleOrdersAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<bool> HasStaleOrdersAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class World
    {
        public required ModularCADbContext Db { get; init; }
        public required CertificateAuthorityEntity Open { get; init; }
        public required CertificateAuthorityEntity Strict { get; init; }
        public Recorder Audit { get; } = new();
    }

    /// <summary>
    /// <c>open</c>, the default, serves ACME without EAB; <c>strict</c> requires EAB; <c>off</c>
    /// has ACME switched off, <c>bare</c> has no ACME row, <c>ops-ssh</c> is an SSH CA and
    /// <c>system-signing-ca</c> is reserved, each with an enabled ACME row where it has one.
    /// </summary>
    private static World Seed()
    {
        var db = InMemoryDbContextFactory.Create();
        CertificateAuthorityEntity Ca(string label, bool isDefault = false, bool ssh = false) => new()
        {
            Id = Guid.NewGuid(), Name = label, Label = label, IsDefault = isDefault, IsSshCa = ssh, IsEnabled = true, SpaceId = Guid.NewGuid(),
        };
        var open = Ca("open", isDefault: true);
        var strict = Ca("strict");
        var off = Ca("off");
        var bare = Ca("bare");
        var ssh = Ca("ops-ssh", ssh: true);
        var system = Ca("system-signing-ca");
        db.CertificateAuthorities.AddRange(open, strict, off, bare, ssh, system);
        db.CaProtocolConfigs.AddRange(
            new CaProtocolConfigEntity { CaId = open.Id, Protocol = "ACME", IsEnabled = true },
            new CaProtocolConfigEntity { CaId = strict.Id, Protocol = "ACME", IsEnabled = true, AcmeRequireEab = true },
            new CaProtocolConfigEntity { CaId = off.Id, Protocol = "ACME", IsEnabled = false },
            new CaProtocolConfigEntity { CaId = ssh.Id, Protocol = "ACME", IsEnabled = true },
            new CaProtocolConfigEntity { CaId = system.Id, Protocol = "ACME", IsEnabled = true });
        db.SaveChanges();
        return new World { Db = db, Open = open, Strict = strict };
    }

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A fresh P-256 account key as a JWK and its RFC 7638 thumbprint.</summary>
    private static (string Jwk, string Thumbprint) NewKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = key.ExportParameters(false);
        var jwk = $$"""{"crv":"P-256","kty":"EC","x":"{{B64(p.Q.X!)}}","y":"{{B64(p.Q.Y!)}}"}""";
        return (jwk, new AcmeJwsService(null!, null!).ComputeThumbprint(jwk));
    }

    /// <summary>An unused EAB key in the store and a valid binding of <paramref name="jwk"/> made with it.</summary>
    private static JsonElement Eab(ModularCADbContext db, string jwk, string keyId)
    {
        var hmac = RandomNumberGenerator.GetBytes(32);
        db.AcmeEabKeys.Add(new AcmeEabKeyEntity { KeyId = keyId, HmacKey = B64(hmac) });
        db.SaveChanges();
        var protectedB64 = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { alg = "HS256", kid = keyId, url = $"https://{Domain}/acme/strict/new-account" })));
        var payloadB64 = B64(Encoding.UTF8.GetBytes(jwk));
        var signature = B64(HMACSHA256.HashData(hmac, Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}")));
        return JsonSerializer.SerializeToElement(new { @protected = protectedB64, payload = payloadB64, signature });
    }

    /// <summary>
    /// Runs <paramref name="action"/> on the named ACME controller as the filter would hand it
    /// the request: <paramref name="jws"/> parsed and <paramref name="ca"/> addressed.
    /// </summary>
    private static async Task<IActionResult> InvokeAsync(World w, string controller, string action, AcmeJwsPayload jws,
        CertificateAuthorityEntity ca, Action<SpaceIsolationMatrixTests.Resolver>? configure = null, params object[] args)
    {
        var services = new SpaceIsolationMatrixTests.Resolver(w.Db);
        var config = new SystemConfig();
        config.Https.PublicDomain = Domain;
        services.Add(typeof(SystemConfig), config);
        services.Add(typeof(IProtocolAuditService), w.Audit);
        services.Add(typeof(IAuditService), w.Audit);
        services.Add(typeof(IAcmeJwsService), new AcmeJwsService(null!, null!));
        services.Add(typeof(IAcmeAccountService), new AcmeAccountService(w.Db));
        services.Add(typeof(IAcmeAccountRateLimiter), new Unlimited());
        configure?.Invoke(services);

        var type = ApiAssembly.TypeNamed($"ModularCA.API.Controllers.v1.Acme.{controller}");
        var instance = ActivatorUtilities.CreateInstance(services, type);
        var http = new DefaultHttpContext { RequestServices = services };
        http.Items["AcmeJws"] = jws;
        http.Items[(string)ApiAssembly.TypeNamed("ModularCA.API.Filters.AcmeJwsActionFilter").GetField("AddressedCaItem")!.GetValue(null)!] = ca;
        type.GetProperty("ControllerContext")!.SetValue(instance, new ControllerContext { HttpContext = http });
        return await (Task<IActionResult>)type.GetMethod(action)!.Invoke(instance, args)!;
    }

    private static int? StatusOf(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    private static async Task<AcmeAccountEntity> UnboundAccountAsync(World w, string jwk, string thumbprint)
    {
        var account = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumbprint, CaLabel = "gone" };
        w.Db.AcmeAccounts.Add(account);
        await w.Db.SaveChangesAsync();
        return account;
    }

    private static AcmeJwsPayload NewAccountJws(Guid? accountId, string jwk, string thumbprint, object payload) => new()
    {
        AccountId = accountId,
        Jwk = JsonDocument.Parse(jwk).RootElement.Clone(),
        JwkThumbprint = thumbprint,
        Payload = JsonSerializer.Serialize(payload),
    };

    /// <summary>
    /// The finding: an account the upgrade could not bind (its label named no CA) could never be
    /// used again, its key being taken. New-account with that key now binds it to the CA addressed,
    /// here the default on the label-less routes, which needs no EAB.
    /// </summary>
    [Fact]
    public async Task New_account_with_an_unbound_key_binds_it_to_the_addressed_ca()
    {
        var w = Seed();
        var (jwk, thumb) = NewKey();
        var account = await UnboundAccountAsync(w, jwk, thumb);

        var result = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(account.Id, jwk, thumb, new { termsOfServiceAgreed = true }), w.Open);

        Assert.Equal(200, StatusOf(result));
        var stored = await w.Db.AcmeAccounts.AsNoTracking().SingleAsync();
        Assert.Equal(w.Open.Id, stored.CertificateAuthorityId);
        Assert.Equal("open", stored.CaLabel);
        var row = Assert.Single(w.Audit.Rows, r => r.Operation == "AccountBound");
        Assert.Equal((w.Open.Label, w.Open.Id, w.Open.SpaceId), (row.CaLabel, row.CaId, row.SpaceId));
    }

    /// <summary>
    /// At a CA that requires EAB the binding needs a valid EAB, as a new account would: without
    /// one the account stays unbound; with one it is bound and the EAB key is spent on it.
    /// </summary>
    [Fact]
    public async Task Binding_an_unbound_key_at_an_eab_ca_needs_a_valid_eab()
    {
        var w = Seed();
        var (jwk, thumb) = NewKey();
        var account = await UnboundAccountAsync(w, jwk, thumb);

        var refused = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(account.Id, jwk, thumb, new { termsOfServiceAgreed = true }), w.Strict);
        Assert.Equal(400, StatusOf(refused));
        Assert.Equal("urn:ietf:params:acme:error:externalAccountRequired",
            Assert.IsType<AcmeErrorResponse>(Assert.IsType<ObjectResult>(refused).Value).Type);
        Assert.Null((await w.Db.AcmeAccounts.AsNoTracking().SingleAsync()).CertificateAuthorityId);

        var eab = Eab(w.Db, jwk, "eab-1");
        var bound = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(account.Id, jwk, thumb, new { termsOfServiceAgreed = true, externalAccountBinding = eab }), w.Strict);

        Assert.Equal(200, StatusOf(bound));
        Assert.Equal(w.Strict.Id, (await w.Db.AcmeAccounts.AsNoTracking().SingleAsync()).CertificateAuthorityId);
        var key = await w.Db.AcmeEabKeys.AsNoTracking().SingleAsync();
        Assert.True(key.IsUsed);
        Assert.Equal(account.Id, key.UsedByAccountId);
    }

    /// <summary>A bound account's new-account lookup leaves its binding alone.</summary>
    [Fact]
    public async Task New_account_with_a_bound_key_does_not_rebind_it()
    {
        var w = Seed();
        var (jwk, thumb) = NewKey();
        var account = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumb, CertificateAuthorityId = w.Open.Id };
        w.Db.AcmeAccounts.Add(account);
        await w.Db.SaveChangesAsync();

        var result = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(account.Id, jwk, thumb, new { termsOfServiceAgreed = true }), w.Open);

        Assert.Equal(200, StatusOf(result));
        Assert.DoesNotContain(w.Audit.Rows, r => r.Operation == "AccountBound");
    }

    /// <summary>
    /// The finding: new-account and new-order checked nothing about the CA, so posting to the
    /// endpoints of a CA whose directory is refused (ACME off, no ACME row, SSH, <c>system-</c>)
    /// registered accounts and placed orders there. Both refuse it now, as the directory does.
    /// </summary>
    [Theory]
    [InlineData("off")]
    [InlineData("bare")]
    [InlineData("ops-ssh")]
    [InlineData("system-signing-ca")]
    public async Task New_account_and_new_order_refuse_a_ca_that_does_not_serve_acme(string label)
    {
        var w = Seed();
        var ca = await w.Db.CertificateAuthorities.AsNoTracking().SingleAsync(c => c.Label == label);
        var (jwk, thumb) = NewKey();

        var account = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(null, jwk, thumb, new { termsOfServiceAgreed = true }), ca);
        Assert.Equal(403, StatusOf(account));
        Assert.Empty(await w.Db.AcmeAccounts.ToListAsync());

        var bound = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumb, CertificateAuthorityId = ca.Id };
        w.Db.AcmeAccounts.Add(bound);
        await w.Db.SaveChangesAsync();
        var order = await InvokeAsync(w, "AcmeOrderController", "NewOrder", new AcmeJwsPayload
        {
            AccountId = bound.Id,
            Payload = JsonSerializer.Serialize(new { identifiers = new[] { new { type = "dns", value = "device.example.com" } } }),
        }, ca);
        Assert.Equal(403, StatusOf(order));
        Assert.Empty(await w.Db.AcmeOrders.ToListAsync());
    }

    /// <summary>A CA that serves ACME still takes new accounts and orders.</summary>
    [Fact]
    public async Task New_account_and_new_order_proceed_at_a_ca_that_serves_acme()
    {
        var w = Seed();
        var (jwk, thumb) = NewKey();

        var created = await InvokeAsync(w, "AcmeAccountController", "NewAccount",
            NewAccountJws(null, jwk, thumb, new { termsOfServiceAgreed = true }), w.Open);
        Assert.Equal(201, StatusOf(created));
        var account = await w.Db.AcmeAccounts.AsNoTracking().SingleAsync();
        Assert.Equal(w.Open.Id, account.CertificateAuthorityId);

        var order = await InvokeAsync(w, "AcmeOrderController", "NewOrder", new AcmeJwsPayload
        {
            AccountId = account.Id,
            Payload = JsonSerializer.Serialize(new { identifiers = new[] { new { type = "dns", value = "device.example.com" } } }),
        }, w.Open);
        Assert.Equal(201, StatusOf(order));
        Assert.Equal("open", (await w.Db.AcmeOrders.AsNoTracking().SingleAsync()).CaLabel);
    }

    /// <summary>
    /// The finding: <c>AcmeAccountDeactivated</c> carried the route label (null on the label-less
    /// routes) and no CA id or space. It carries the bound CA's now.
    /// </summary>
    [Fact]
    public async Task A_deactivation_is_audited_under_the_accounts_ca()
    {
        var w = Seed();
        var (jwk, thumb) = NewKey();
        var account = new AcmeAccountEntity { JwkJson = jwk, JwkThumbprint = thumb, CertificateAuthorityId = w.Strict.Id };
        w.Db.AcmeAccounts.Add(account);
        await w.Db.SaveChangesAsync();

        var result = await InvokeAsync(w, "AcmeAccountController", "UpdateAccount",
            new AcmeJwsPayload { AccountId = account.Id, Payload = """{"status":"deactivated"}""" }, w.Strict, null, account.Id);

        Assert.IsType<OkObjectResult>(result);
        var row = Assert.Single(w.Audit.Rows, r => r.Operation == "AcmeAccountDeactivated");
        Assert.Equal(("strict", w.Strict.Id, w.Strict.SpaceId), (row.CaLabel, row.CaId, row.SpaceId));
    }

    /// <summary>
    /// The finding: <c>AcmeOrderFinalized</c> took its label from the route, null on the
    /// label-less routes, and carried no CA id or space; <c>OrderFinalized</c> took the route label
    /// too. Both carry the bound CA's now.
    /// </summary>
    [Fact]
    public async Task A_finalize_is_audited_under_the_accounts_ca()
    {
        var w = Seed();
        var accountId = Guid.NewGuid();

        var result = await InvokeAsync(w, "AcmeOrderController", "FinalizeOrder",
            new AcmeJwsPayload { AccountId = accountId, Payload = """{"csr":"AAAA"}""" }, w.Strict,
            s => s.Add(typeof(IAcmeOrderService), new FinalizingOrders(accountId)), Guid.NewGuid());

        Assert.IsType<OkObjectResult>(result);
        foreach (var operation in new[] { "OrderFinalized", "AcmeOrderFinalized" })
        {
            var row = Assert.Single(w.Audit.Rows, r => r.Operation == operation);
            Assert.Equal(("strict", w.Strict.Id, w.Strict.SpaceId), (row.CaLabel, row.CaId, row.SpaceId));
        }
    }

    /// <summary>
    /// The finding: challenge validation rows carried the order's label only. They carry the
    /// label, id and space of the CA the order's account is bound to.
    /// </summary>
    [Fact]
    public async Task A_challenge_outcome_is_audited_under_the_accounts_ca()
    {
        var w = Seed();
        var account = new AcmeAccountEntity { JwkJson = "{}", JwkThumbprint = "t", CertificateAuthorityId = w.Strict.Id };
        var order = new AcmeOrderEntity { AccountId = account.Id, CaLabel = null };
        var authz = new AcmeAuthorizationEntity { OrderId = order.Id, Order = order, IdentifierType = "dns", IdentifierValue = "device.example.com" };
        var challenge = new AcmeChallengeEntity { AuthorizationId = authz.Id, Authorization = authz, Type = "dns-01", Token = "x", Status = "Valid" };
        w.Db.AcmeAccounts.Add(account);
        await w.Db.SaveChangesAsync();

        var service = new AcmeChallengeService(w.Db, null!, null!, null!, w.Audit, new SystemConfig());
        await (Task)typeof(AcmeChallengeService).GetMethod("LogChallengeOutcomeAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(service, [challenge, "ChallengeDns01"])!;

        var row = Assert.Single(w.Audit.Rows);
        Assert.Equal(("strict", w.Strict.Id, w.Strict.SpaceId), (row.CaLabel, row.CaId, row.SpaceId));
    }
}
