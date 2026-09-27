using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real <c>AdminCertificateController</c> chain, file and health-summary endpoints over
/// an in-memory root, intermediate and leaf, loaded by reflection as <see cref="ProtocolConfigEndpointTests"/> does.
/// </summary>
public sealed class AdminCertificateChainEndpointTests
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminCertificateController";

    private static readonly Guid Operator = Guid.NewGuid();

    private sealed record Pki(CertificateEntity Root, CertificateEntity Intermediate, CertificateEntity Leaf,
        SigningProfileEntity Profile, CertificateAuthorityEntity RootCa, CertificateAuthorityEntity IntCa);

    private static CertificateEntity Entity(X509Certificate2 cert, bool isCa, Guid? signingProfileId = null) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = cert.SerialNumber,
        Pem = cert.ExportCertificatePem(),
        SubjectDN = cert.Subject,
        Issuer = cert.Issuer,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
        IsCA = isCa,
        SigningProfileId = signingProfileId,
    };

    private static X509Certificate2 CaCert(string cn, X509Certificate2? issuer, byte[] serial)
    {
        var from = DateTimeOffset.UtcNow.AddDays(-1);
        var to = DateTimeOffset.UtcNow.AddYears(1);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return issuer == null
            ? req.CreateSelfSigned(from, to)
            : req.Create(issuer, from, to, serial).CopyWithPrivateKey(key);
    }

    private static Pki SeedPki(ModularCADbContext db, string name = "Chain", Guid? tenantId = null)
    {
        var from = DateTimeOffset.UtcNow.AddDays(-1);
        var to = DateTimeOffset.UtcNow.AddYears(1);

        using var root = CaCert($"CN={name} Root", null, [0]);
        using var intermediate = CaCert($"CN={name} Intermediate", root, [1, 2]);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest($"CN={name.ToLowerInvariant()}-leaf.example", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafReq.Create(intermediate, from, to, new byte[] { 3, 4 });

        var rootEntity = Entity(root, isCa: true);
        var intEntity = Entity(intermediate, isCa: true);
        var profile = new SigningProfileEntity { Name = name, IssuerId = intEntity.CertificateId };
        var leafEntity = Entity(leaf, isCa: false, profile.Id);
        leafEntity.IssuerCertificateId = intEntity.CertificateId;
        var tenant = tenantId ?? Guid.NewGuid();
        var rootCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{name} Root", Label = $"{name.ToLowerInvariant()}-root", TenantId = tenant, CertificateId = rootEntity.CertificateId };
        var intCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{name} Int", Label = $"{name.ToLowerInvariant()}-int", TenantId = tenant, CertificateId = intEntity.CertificateId, ParentCaId = rootCa.Id };

        db.Certificates.AddRange(rootEntity, intEntity, leafEntity);
        db.SigningProfiles.Add(profile);
        db.CertificateAuthorities.AddRange(rootCa, intCa);
        db.SaveChanges();
        return new Pki(rootEntity, intEntity, leafEntity, profile, rootCa, intCa);
    }

    private static object NewController(ModularCADbContext db, ICertificateAccessEvaluator access,
        ICertHealthScoreService? health = null, ICaGroupAuthorizationService? groupAuth = null)
    {
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed(ControllerName),
            new CertificateStore(db),
            new CurrentUserStub(Operator),
            access,
            db,
            null,
            new RecordingAlertService(),
            health,
            new RecordingAuditService(),
            groupAuth)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static object NewController(ModularCADbContext db, bool canView) => NewController(db, new AccessStub(_ => canView));

    private static async Task<IActionResult> InvokeAsync(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static Task<IActionResult> ChainAsync(object controller, string serial) => InvokeAsync(controller, "GetCertificateChain", serial);

    private static string Bundle(IActionResult result)
        => Encoding.UTF8.GetString(Assert.IsType<FileContentResult>(result).FileContents);

    [Fact]
    public async Task A_leaf_chain_carries_the_leaf_and_intermediate_but_not_the_root()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);

        var bundle = Bundle(await ChainAsync(NewController(db, canView: true), pki.Leaf.SerialNumber));

        Assert.StartsWith(pki.Leaf.Pem.Trim(), bundle);
        Assert.Contains(pki.Intermediate.Pem.Trim(), bundle);
        Assert.DoesNotContain(pki.Root.Pem.Trim(), bundle);
    }

    [Fact]
    public async Task A_ca_certificate_chain_is_served_rather_than_hidden()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);

        var bundle = Bundle(await ChainAsync(NewController(db, canView: true), pki.Intermediate.SerialNumber));

        Assert.StartsWith(pki.Intermediate.Pem.Trim(), bundle);
        Assert.Contains(pki.Root.Pem.Trim(), bundle);
    }

    [Fact]
    public async Task A_certificate_the_caller_cannot_view_is_not_found()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);

        Assert.IsType<NotFoundResult>(await ChainAsync(NewController(db, canView: false), pki.Leaf.SerialNumber));
    }

    [Fact]
    public async Task A_leaf_keeps_its_real_issuer_after_the_profile_is_repointed_at_a_renewed_intermediate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);
        using var renewed = CaCert("CN=Chain Intermediate", null, [9]);
        var renewedEntity = Entity(renewed, isCa: true);
        renewedEntity.IssuerCertificateId = pki.Root.CertificateId;
        db.Certificates.Add(renewedEntity);
        pki.Leaf.IssuerCertificateId = pki.Intermediate.CertificateId;
        pki.Intermediate.IssuerCertificateId = pki.Root.CertificateId;
        pki.Profile.IssuerId = renewedEntity.CertificateId;
        pki.IntCa.CertificateId = renewedEntity.CertificateId;
        db.SaveChanges();

        var bundle = Bundle(await ChainAsync(NewController(db, canView: true), pki.Leaf.SerialNumber));

        Assert.StartsWith(pki.Leaf.Pem.Trim(), bundle);
        Assert.Contains(pki.Intermediate.Pem.Trim(), bundle);
        Assert.DoesNotContain(renewedEntity.Pem.Trim(), bundle);
        Assert.DoesNotContain(pki.Root.Pem.Trim(), bundle);
    }

    [Fact]
    public async Task A_caller_who_can_view_the_leaf_but_not_the_intermediate_still_gets_the_intermediate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);
        var access = new AccessStub(id => id == pki.Leaf.CertificateId);

        var bundle = Bundle(await ChainAsync(NewController(db, access), pki.Leaf.SerialNumber));

        Assert.Equal(pki.Leaf.Pem.Trim() + "\n" + pki.Intermediate.Pem.Trim() + "\n", bundle);
    }

    [Fact]
    public async Task The_admin_file_download_serves_a_ca_certificate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var pki = SeedPki(db);

        var file = Assert.IsType<FileContentResult>(await InvokeAsync(NewController(db, canView: true), "GetCertificate", pki.Intermediate.SerialNumber));

        Assert.Equal("application/pkix-cert", file.ContentType);
        using var x509 = X509CertificateLoader.LoadCertificate(file.FileContents);
        Assert.Equal(pki.Intermediate.SubjectDN, x509.Subject);
    }

    [Fact]
    public async Task The_health_summary_only_scores_certificates_of_the_callers_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = SeedPki(db, "Mine");
        var theirs = SeedPki(db, "Theirs");
        var health = new HealthStub();
        var controller = NewController(db, new AccessStub(_ => true), health, new GroupAuthStub([mine.IntCa.Id]));

        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "GetHealthSummary", null, null));
        Assert.Equal(new[] { mine.Leaf.CertificateId }, health.Scored);

        health.Scored.Clear();
        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "GetHealthSummary", null, theirs.IntCa.TenantId));
        Assert.Empty(health.Scored);

        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "GetHealthSummary", theirs.IntCa.Id, null));
        Assert.Empty(health.Scored);
    }

    private static CertificateEntity AddLeaf(ModularCADbContext db, string cn, Guid? issuerCertificateId, Guid? signingProfileId = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest(cn, key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var entity = Entity(cert, isCa: false, signingProfileId);
        entity.IssuerCertificateId = issuerCertificateId;
        db.Certificates.Add(entity);
        db.SaveChanges();
        return entity;
    }

    private static async Task<List<Guid>> ListAsync(object controller, Guid? caId = null, Guid? tenantId = null)
    {
        var ok = Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "ListCertificates",
            null, null, null, null, caId, tenantId, null, null, null, null, null, null, null, null, 1, 100));
        var items = (IEnumerable<ModularCA.Shared.Models.CertificateInfoModel>)ok.Value!.GetType().GetProperty("items")!.GetValue(ok.Value)!;
        return items.Select(i => i.CertificateId).ToList();
    }

    [Fact]
    public async Task A_certificate_with_an_issuer_but_no_signing_profile_is_scoped_to_its_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = SeedPki(db, "Mine");
        var mtls = AddLeaf(db, "CN=mtls-client", mine.Intermediate.CertificateId);
        var health = new HealthStub();
        var controller = NewController(db, new AccessStub(_ => true), health, new GroupAuthStub([mine.IntCa.Id]));

        Assert.Contains(mtls.CertificateId, await ListAsync(controller, caId: mine.IntCa.Id));
        Assert.Contains(mtls.CertificateId, await ListAsync(controller, tenantId: mine.IntCa.TenantId));

        Assert.IsType<OkObjectResult>(await InvokeAsync(controller, "GetHealthSummary", mine.IntCa.Id, null));
        Assert.Contains(mtls.CertificateId, health.Scored);
    }

    [Fact]
    public async Task A_leaf_stays_under_its_real_issuing_ca_after_its_profile_is_repointed()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = SeedPki(db, "Mine");
        var other = SeedPki(db, "Other");
        mine.Profile.IssuerId = other.Intermediate.CertificateId;
        db.SaveChanges();

        var system = NewController(db, new AccessStub(_ => true), null, new GroupAuthStub([], system: true));
        Assert.Contains(mine.Leaf.CertificateId, await ListAsync(system, caId: mine.IntCa.Id));
        Assert.DoesNotContain(mine.Leaf.CertificateId, await ListAsync(system, caId: other.IntCa.Id));

        var otherOnly = NewController(db, new AccessStub(_ => true), null, new GroupAuthStub([other.IntCa.Id]));
        Assert.Equal(new[] { other.Leaf.CertificateId }, await ListAsync(otherOnly));
    }

    [Fact]
    public async Task A_ca_scoped_caller_lists_exactly_the_certificates_CanViewCertificate_allows()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = SeedPki(db, "Mine");
        var theirs = SeedPki(db, "Theirs");
        var myMtls = AddLeaf(db, "CN=my-mtls", mine.Intermediate.CertificateId);
        var theirMtls = AddLeaf(db, "CN=their-mtls", theirs.Intermediate.CertificateId);
        var superseded = AddLeaf(db, "CN=superseded-int", null);
        var underSuperseded = AddLeaf(db, "CN=under-superseded", superseded.CertificateId, mine.Profile.Id);
        var legacy = AddLeaf(db, "CN=legacy", null, mine.Profile.Id);
        db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
        {
            UserId = Operator, Capability = ModularCA.Shared.Authorization.Capabilities.CertView, CertificateAuthorityId = mine.IntCa.Id,
        });
        db.SaveChanges();

        var evaluator = new ModularCA.Auth.Implementations.CertificateAccessEvaluator(db);
        var groupAuth = new CaGroupAuthorizationService(db, Microsoft.Extensions.Logging.Abstractions.NullLogger<CaGroupAuthorizationService>.Instance);
        var controller = NewController(db, evaluator, null, groupAuth);

        var listed = await ListAsync(controller);
        Assert.Equal(new[] { mine.Leaf.CertificateId, myMtls.CertificateId }.OrderBy(g => g), listed.OrderBy(g => g));
        foreach (var c in new[] { mine.Leaf, theirs.Leaf, myMtls, theirMtls, superseded, underSuperseded, legacy })
            Assert.Equal(evaluator.CanViewCertificate(Operator, c.CertificateId), listed.Contains(c.CertificateId));

        Assert.Empty(await ListAsync(controller, caId: theirs.IntCa.Id));
        Assert.Empty(await ListAsync(controller, tenantId: theirs.IntCa.TenantId));
    }

    [Fact]
    public async Task Certificates_issued_under_a_superseded_ca_certificate_stay_in_that_cas_scope()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = SeedPki(db, "Mine");
        var theirs = SeedPki(db, "Theirs");
        mine.Intermediate.IssuerCertificateId = mine.Root.CertificateId;
        using var renewed = CaCert("CN=Mine Intermediate", null, [7]);
        var renewedEntity = Entity(renewed, isCa: true);
        renewedEntity.Issuer = mine.Intermediate.Issuer;
        renewedEntity.IssuerCertificateId = mine.Root.CertificateId;
        db.Certificates.Add(renewedEntity);
        mine.IntCa.CertificateId = renewedEntity.CertificateId;
        mine.Profile.IssuerId = renewedEntity.CertificateId;
        var afterRenewal = AddLeaf(db, "CN=after-renewal", renewedEntity.CertificateId, mine.Profile.Id);
        db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
        {
            UserId = Operator, Capability = ModularCA.Shared.Authorization.Capabilities.CertView, CertificateAuthorityId = mine.IntCa.Id,
        });
        db.SaveChanges();

        var evaluator = new ModularCA.Auth.Implementations.CertificateAccessEvaluator(db);
        var groupAuth = new CaGroupAuthorizationService(db, Microsoft.Extensions.Logging.Abstractions.NullLogger<CaGroupAuthorizationService>.Instance);
        var controller = NewController(db, evaluator, null, groupAuth);

        Assert.True(evaluator.CanViewCertificate(Operator, mine.Leaf.CertificateId));
        var expected = new[] { mine.Leaf.CertificateId, afterRenewal.CertificateId }.OrderBy(g => g);
        Assert.Equal(expected, (await ListAsync(controller)).OrderBy(g => g));
        Assert.Equal(expected, (await ListAsync(controller, caId: mine.IntCa.Id)).OrderBy(g => g));
        Assert.Equal(expected, (await ListAsync(controller, tenantId: mine.IntCa.TenantId)).OrderBy(g => g));
        Assert.False(evaluator.CanViewCertificate(Operator, theirs.Leaf.CertificateId));

        var system = NewController(db, new AccessStub(_ => true), null, new GroupAuthStub([], system: true));
        Assert.DoesNotContain(mine.Leaf.CertificateId, await ListAsync(system, caId: theirs.IntCa.Id));
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class AccessStub(Func<Guid, bool> canView) : ICertificateAccessEvaluator
    {
        public bool CanViewCertificate(Guid userId, Guid certificateId) => canView(certificateId);
        public bool CanManageCertificate(Guid userId, Guid certificateId) => false;
    }

    private sealed class HealthStub : ICertHealthScoreService
    {
        public List<Guid> Scored { get; } = [];
        public Task<CertHealthScore> CalculateScoreAsync(Guid certificateId) => throw new NotSupportedException();
        public Task<List<CertHealthScore>> CalculateBulkScoresAsync(List<Guid> certificateIds)
        {
            Scored.AddRange(certificateIds);
            return Task.FromResult(certificateIds.Select(id => new CertHealthScore { CertificateId = id, Score = 95, Grade = "A" }).ToList());
        }
    }

    private sealed class GroupAuthStub(List<Guid> caIds, bool system = false) : ICaGroupAuthorizationService
    {
        public Task<bool> HasSystemCapabilityAsync(Guid userId, string capability) => Task.FromResult(system);
        public Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability) => Task.FromResult(caIds);
        public Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability, Guid? tenantId) => Task.FromResult(caIds);
        public Task<bool> HasCaCapabilityAsync(Guid userId, Guid caId, string capability) => throw new NotSupportedException();
        public Task<bool> HasTenantCapabilityAsync(Guid userId, Guid tenantId, string capability) => throw new NotSupportedException();
        public Task<List<Guid>> GetTenantIdsWithCapabilityAsync(Guid userId, string capability) => throw new NotSupportedException();
        public Task<bool> IsSystemAdminAsync(Guid userId) => throw new NotSupportedException();
        public Task<List<CaGroupEntity>> GetUserGroupsAsync(Guid userId) => throw new NotSupportedException();
        public Task<EffectiveCapabilities> GetEffectiveCapabilitiesAsync(Guid userId) => throw new NotSupportedException();
        public Task<bool> HasResourceCapabilityAsync(Guid userId, string capability, string resourceType, Guid resourceId) => throw new NotSupportedException();
        public Task<(List<Guid> ResourceIds, bool HasWildcard)> GetGrantedResourceIdsAsync(Guid userId, string capabilityPrefix, string resourceType) => throw new NotSupportedException();
    }
}
