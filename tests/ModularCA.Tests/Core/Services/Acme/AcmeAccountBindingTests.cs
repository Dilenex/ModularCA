using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using ModularCA.Core.Services;
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
/// An ACME account is bound to the CA it registered at. Its CA label used to be stored at
/// new-account and read by nothing, so an account registered at a CA without external account
/// binding could place and finalize orders at a CA that requires it. The JWS filter now refuses
/// every account-authenticated request at any other CA. On the label-less routes a request signed
/// by an account addresses the account's own CA, so changing the default CA does not lock out the
/// clients registered there; only a new registration goes to the default.
/// </summary>
public class AcmeAccountBindingTests
{
    private sealed class Fixture
    {
        public required ModularCADbContext Db { get; init; }
        public required CertificateAuthorityEntity OpenCa { get; init; }
        public required CertificateAuthorityEntity EabCa { get; init; }
    }

    /// <summary>
    /// Two CAs: <c>open</c>, the default, whose ACME needs no EAB, and <c>strict</c>, whose ACME
    /// requires it.
    /// </summary>
    private static Fixture Seed()
    {
        var db = InMemoryDbContextFactory.Create();
        var open = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Open CA", Label = "open", IsDefault = true };
        var strict = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Strict CA", Label = "strict" };
        db.CertificateAuthorities.AddRange(open, strict);
        db.CaProtocolConfigs.AddRange(
            new CaProtocolConfigEntity { CaId = open.Id, Protocol = "ACME" },
            new CaProtocolConfigEntity { CaId = strict.Id, Protocol = "ACME", AcmeRequireEab = true });
        db.SaveChanges();
        return new Fixture { Db = db, OpenCa = open, EabCa = strict };
    }

    private sealed class FixedJws(Guid? accountId) : IAcmeJwsService
    {
        public Task<AcmeJwsPayload> ParseAndVerifyAsync(string rawBody, string requestUrl)
            => Task.FromResult(new AcmeJwsPayload { AccountId = accountId, Kid = $"https://ca.example/acme/account/{accountId}" });
        public string ComputeThumbprint(string jwkJson) => "thumb";
        public void VerifySignature(string protectedB64, string payloadB64, string signatureB64, string jwkJson) { }
    }

    private sealed class Nonces : IAcmeNonceService
    {
        public Task<string> GenerateAsync() => Task.FromResult("nonce");
        public Task<bool> ConsumeAsync(string nonce) => Task.FromResult(true);
        public Task CleanupExpiredAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> HasExpiredNoncesAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
    }

    /// <summary>
    /// Runs the real <c>AcmeJwsActionFilter</c> for a kid-signed request by
    /// <paramref name="accountId"/> on the route with <paramref name="routeLabel"/> (null for
    /// the label-less routes), as new-account when <paramref name="newAccount"/>. Returns the
    /// refusal, or null with the CA the action would see.
    /// </summary>
    private static async Task<(ObjectResult? Refusal, CertificateAuthorityEntity? Addressed)> RunFilterAsync(
        ModularCADbContext db, Guid? accountId, string? routeLabel, bool newAccount = false)
    {
        var config = new SystemConfig();
        config.Https.PublicDomain = "ca.example";
        var type = ApiAssembly.TypeNamed("ModularCA.API.Filters.AcmeJwsActionFilter");
        var filter = (IAsyncActionFilter)Activator.CreateInstance(type,
            new FixedJws(accountId), new Nonces(), new AcmeAccountService(db), new CaResolverService(db), config, newAccount, false)!;

        var http = new DefaultHttpContext();
        http.Request.ContentType = "application/jose+json";
        if (routeLabel != null)
            http.Request.RouteValues["caLabel"] = routeLabel;
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var executing = new ActionExecutingContext(action, new List<IFilterMetadata>(), new Dictionary<string, object?>(), controller: new object());
        var ran = false;
        await filter.OnActionExecutionAsync(executing, () =>
        {
            ran = true;
            return Task.FromResult(new ActionExecutedContext(action, new List<IFilterMetadata>(), new object()));
        });

        if (!ran)
            return (Assert.IsType<ObjectResult>(executing.Result), null);
        Assert.Null(executing.Result);
        return (null, http.Items[type.GetField("AddressedCaItem")!.GetValue(null)!] as CertificateAuthorityEntity);
    }

    private static async Task<Guid> AccountAtAsync(ModularCADbContext db, Guid? caId)
    {
        var account = new AcmeAccountEntity { JwkJson = "{}", JwkThumbprint = Guid.NewGuid().ToString("N"), CertificateAuthorityId = caId };
        db.AcmeAccounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    /// <summary>
    /// The finding: an account registered at the CA without EAB is refused at the CA that
    /// requires it, with <c>unauthorized</c>, whichever route names that CA.
    /// </summary>
    [Theory]
    [InlineData("strict")]
    [InlineData("STRICT")]
    public async Task An_account_is_refused_at_a_ca_it_did_not_register_at(string routeLabel)
    {
        var f = Seed();
        var account = await AccountAtAsync(f.Db, f.OpenCa.Id);

        var (refusal, _) = await RunFilterAsync(f.Db, account, routeLabel);

        Assert.NotNull(refusal);
        Assert.Equal(403, refusal!.StatusCode);
        Assert.Equal("urn:ietf:params:acme:error:unauthorized", Assert.IsType<AcmeErrorResponse>(refusal.Value).Type);
    }

    /// <summary>
    /// The same account works at its own CA, by label or on the label-less routes while that CA is
    /// the default, and the action sees that CA.
    /// </summary>
    [Theory]
    [InlineData("open")]
    [InlineData(null)]
    public async Task An_account_is_accepted_at_its_own_ca(string? routeLabel)
    {
        var f = Seed();
        var account = await AccountAtAsync(f.Db, f.OpenCa.Id);

        var (refusal, addressed) = await RunFilterAsync(f.Db, account, routeLabel);

        Assert.Null(refusal);
        Assert.Equal(f.OpenCa.Id, addressed?.Id);
    }

    /// <summary>
    /// On the label-less routes an account's request addresses the CA it is bound to, not the
    /// default: an account bound to a CA that is not the default works there, and once the default
    /// moves, an account bound to the old default keeps its CA. Before, both were refused, so
    /// changing the default broke every label-less client at its next renewal.
    /// </summary>
    [Fact]
    public async Task An_existing_account_keeps_its_ca_on_the_label_less_routes_when_the_default_changes()
    {
        var f = Seed();
        var strictAccount = await AccountAtAsync(f.Db, f.EabCa.Id);
        var (refusal, addressed) = await RunFilterAsync(f.Db, strictAccount, null);
        Assert.Null(refusal);
        Assert.Equal(f.EabCa.Id, addressed?.Id);

        var openAccount = await AccountAtAsync(f.Db, f.OpenCa.Id);
        f.OpenCa.IsDefault = false;
        f.EabCa.IsDefault = true;
        await f.Db.SaveChangesAsync();

        (refusal, addressed) = await RunFilterAsync(f.Db, openAccount, null);
        Assert.Null(refusal);
        Assert.Equal(f.OpenCa.Id, addressed?.Id);
        Assert.Equal(f.EabCa.Id, (await RunFilterAsync(f.Db, strictAccount, null)).Addressed?.Id);
    }

    /// <summary>
    /// A new registration, a key with no account, goes to the current default on the label-less
    /// routes, and moves with it.
    /// </summary>
    [Fact]
    public async Task A_new_account_on_the_label_less_routes_goes_to_the_default_ca()
    {
        var f = Seed();
        Assert.Equal(f.OpenCa.Id, (await RunFilterAsync(f.Db, null, null, newAccount: true)).Addressed?.Id);

        f.OpenCa.IsDefault = false;
        f.EabCa.IsDefault = true;
        await f.Db.SaveChangesAsync();
        Assert.Equal(f.EabCa.Id, (await RunFilterAsync(f.Db, null, null, newAccount: true)).Addressed?.Id);
    }

    /// <summary>
    /// An account the upgrade could not bind is refused everywhere but new-account, and an
    /// unknown CA is refused.
    /// </summary>
    [Theory]
    [InlineData("open", false)]
    [InlineData(null, false)]
    [InlineData("no-such-ca", true)]
    public async Task An_unbound_account_or_an_unknown_ca_is_refused(string? routeLabel, bool boundAccount)
    {
        var f = Seed();
        var account = await AccountAtAsync(f.Db, boundAccount ? f.OpenCa.Id : null);

        Assert.NotNull((await RunFilterAsync(f.Db, account, routeLabel)).Refusal);
    }

    /// <summary>
    /// New-account with an unbound account's key reaches the action, addressing the route's CA
    /// (the default on the label-less routes), so the action can bind it there. Before, the filter
    /// refused it, and the account's key could never be used again.
    /// </summary>
    [Theory]
    [InlineData("strict")]
    [InlineData(null)]
    public async Task New_account_with_an_unbound_key_addresses_the_routes_ca(string? routeLabel)
    {
        var f = Seed();
        var account = await AccountAtAsync(f.Db, null);

        var (refusal, addressed) = await RunFilterAsync(f.Db, account, routeLabel, newAccount: true);

        Assert.Null(refusal);
        Assert.Equal(routeLabel == null ? f.OpenCa.Id : f.EabCa.Id, addressed?.Id);
    }

    /// <summary>A bound account is still refused on another CA's labelled route at new-account.</summary>
    [Fact]
    public async Task New_account_with_a_bound_key_is_refused_at_another_cas_label()
    {
        var f = Seed();
        var account = await AccountAtAsync(f.Db, f.OpenCa.Id);

        Assert.NotNull((await RunFilterAsync(f.Db, account, "strict", newAccount: true)).Refusal);
        Assert.Equal(f.OpenCa.Id, (await RunFilterAsync(f.Db, account, null, newAccount: true)).Addressed?.Id);
    }

    /// <summary>
    /// The default CA every label-less resolver uses: enabled, not SSH, no <c>system-</c> label,
    /// the default first, then by name, so several defaults (as the 0.4.0 fold can leave)
    /// resolve to the same CA however the rows are stored. Before, the order was the
    /// default flag alone, and the first-stored default won.
    /// </summary>
    [Fact]
    public async Task The_default_ca_is_resolved_deterministically()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "SSH CA", Label = "ssh", IsSshCa = true, IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Disabled CA", Label = "disabled", IsEnabled = false, IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Zulu CA", Label = "zulu", IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Alpha CA", Label = "alpha", IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Aardvark CA", Label = "aardvark" });
        await db.SaveChangesAsync();

        Assert.Equal("alpha", (await new CaResolverService(db).ResolveCaEntityAsync(null))?.Label);
        Assert.Equal("alpha", (await CaResolverService.FindAddressedCaAsync(db, null))?.Label);

        var warning = await DefaultCaCheck.WarningAsync(db);
        Assert.NotNull(warning);
        Assert.Contains("zulu", warning);
        Assert.Contains("go to alpha", warning);
        Assert.Contains("new ACME registrations", warning);
        Assert.Contains("Existing ACME accounts keep using the CA they registered at", warning);
    }

    /// <summary>One default CA, or none, is not worth a startup warning.</summary>
    [Fact]
    public async Task One_default_ca_gives_no_warning()
    {
        var f = Seed();
        Assert.Null(await DefaultCaCheck.WarningAsync(f.Db));
    }
}
