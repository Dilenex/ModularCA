using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives <c>AdminCertificateController.GetLifecycleSummary</c> and the list's <c>replaced</c>
/// filter over in-memory rows: scope, the replacement rule both ways, and counts that do not
/// depend on the list's paging. The same scenarios run against PostgreSQL in
/// <c>PostgresLifecycleQueryTests</c>.
/// </summary>
public sealed class CertificateLifecycleSummaryTests
{
    [Fact]
    public async Task Another_spaces_certificates_are_not_counted()
    {
        using var db = InMemoryDbContextFactory.Create();
        await CertificateLifecycleScenarios.Another_spaces_certificates_are_not_counted(db);
    }

    [Fact]
    public async Task A_reissue_link_or_flag_marks_the_predecessor_replaced()
    {
        using var db = InMemoryDbContextFactory.Create();
        await CertificateLifecycleScenarios.A_reissue_link_or_flag_marks_the_predecessor_replaced(db);
    }

    [Fact]
    public async Task A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case()
    {
        using var db = InMemoryDbContextFactory.Create();
        await CertificateLifecycleScenarios.A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case(db);
    }

    [Fact]
    public async Task Counts_do_not_depend_on_the_list_page()
    {
        using var db = InMemoryDbContextFactory.Create();
        await CertificateLifecycleScenarios.Counts_do_not_depend_on_the_list_page(db);
    }

    [Fact]
    public void San_set_key_ignores_order_case_and_duplicates()
    {
        Assert.Equal(
            CertificateLifecycle.SanSetKey("[\"DNS:B.example\",\"DNS:a.example\",\"dns:a.example\"]"),
            CertificateLifecycle.SanSetKey("[\"DNS:a.example\",\"DNS:b.example\"]"));
        Assert.NotEqual(CertificateLifecycle.SanSetKey("[\"DNS:a.example\"]"), CertificateLifecycle.SanSetKey("[\"DNS:b.example\"]"));
    }
}

/// <summary>
/// The lifecycle summary and <c>replaced</c> filter scenarios, provider-neutral: each seeds its
/// rows into the context it is given and drives the controller over it.
/// </summary>
internal static class CertificateLifecycleScenarios
{
    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminCertificateController";
    private static readonly Guid Operator = Guid.NewGuid();

    private sealed record Ca(CertificateAuthorityEntity Entity, CertificateEntity Cert);

    private static Ca SeedCa(ModularCADbContext db, string name, Guid? spaceId = null)
    {
        var cert = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N")[..16], SubjectDN = $"CN={name} CA",
            Issuer = $"CN={name} CA", IsCA = true, NotBefore = DateTime.UtcNow.AddYears(-1), NotAfter = DateTime.UtcNow.AddYears(5),
        };
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = $"{name} CA", Label = name.ToLowerInvariant(), SpaceId = spaceId ?? Guid.NewGuid(),
            CertificateId = cert.CertificateId,
        };
        // PostgreSQL enforces the CA's foreign key to its space; the in-memory provider does not.
        var space = ca.SpaceId!.Value;
        if (db.Database.IsRelational() && !db.Spaces.Any(s => s.Id == space))
            db.Spaces.Add(new SpaceEntity { Id = space, Name = $"{name} space", Slug = $"{name.ToLowerInvariant()}-{space:N}"[..20] });
        db.Certificates.Add(cert);
        db.CertificateAuthorities.Add(ca);
        db.SaveChanges();
        return new Ca(ca, cert);
    }

    private static CertificateEntity Leaf(ModularCADbContext db, Ca ca, string cn, double notBeforeDays, double notAfterDays,
        string[]? sans = null, bool revoked = false, bool reissued = false)
    {
        var leaf = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N")[..20],
            SubjectDN = $"CN={cn}",
            Issuer = ca.Cert.SubjectDN,
            IssuerCertificateId = ca.Cert.CertificateId,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(sans ?? [$"DNS:{cn}"]),
            NotBefore = DateTime.UtcNow.AddDays(notBeforeDays),
            NotAfter = DateTime.UtcNow.AddDays(notAfterDays),
            Revoked = revoked,
            IsReissued = reissued,
        };
        db.Certificates.Add(leaf);
        db.SaveChanges();
        return leaf;
    }

    private static object NewController(ModularCADbContext db, ICaGroupAuthorizationService groupAuth)
    {
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed(ControllerName),
            new CertificateStore(db), new CurrentUserStub(Operator), new AccessStub(), db, null,
            new RecordingAlertService(), null, new RecordingAuditService(), groupAuth)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static async Task<CertificateLifecycleSummaryModel> SummaryAsync(object controller, Guid? caId = null, Guid? spaceId = null)
    {
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("GetLifecycleSummary")!.Invoke(controller, [caId, spaceId])!;
        return Assert.IsType<CertificateLifecycleSummaryModel>(Assert.IsType<OkObjectResult>(result).Value);
    }

    private static async Task<(int Total, List<CertificateInfoModel> Items)> ListAsync(object controller, string? status, string? replaced,
        int page = 1, int pageSize = 100)
    {
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("ListCertificates")!.Invoke(controller,
            [null, null, null, null, null, null, null, status, null, null, null, null, null, null, page, pageSize, replaced])!;
        var value = Assert.IsType<OkObjectResult>(result).Value!;
        var total = (int)value.GetType().GetProperty("total")!.GetValue(value)!;
        var items = ((IEnumerable<CertificateInfoModel>)value.GetType().GetProperty("items")!.GetValue(value)!).ToList();
        return (total, items);
    }

    /// <summary>The scenario behind <c>CertificateLifecycleSummaryTests.Another_spaces_certificates_are_not_counted</c>, on any provider.</summary>
    internal static async Task Another_spaces_certificates_are_not_counted(ModularCADbContext db)
    {
        var mine = SeedCa(db, "Mine");
        var theirs = SeedCa(db, "Theirs");
        Leaf(db, mine, "mine-expired.example", -60, -2);
        Leaf(db, mine, "mine-active.example", -10, 200);
        Leaf(db, theirs, "theirs-expired.example", -60, -3);
        Leaf(db, theirs, "theirs-soon.example", -60, 3);

        var scoped = NewController(db, new GroupAuthStub([mine.Entity.Id]));
        var summary = await SummaryAsync(scoped);
        Assert.Equal(2, summary.Total);
        Assert.Equal(1, summary.Expired);
        Assert.Equal(0, summary.ExpiringWithin30Days);
        Assert.Equal(new[] { "mine-expired.example" }, summary.Attention.Select(a => a.CommonName));
        Assert.Equal("mine", Assert.Single(summary.Attention).CaLabel);
        Assert.Equal(mine.Entity.Id, Assert.Single(summary.ByCa).CaId);

        var named = await SummaryAsync(scoped, spaceId: theirs.Entity.SpaceId);
        Assert.Equal(0, named.Total);
        Assert.Empty(named.Attention);

        var system = NewController(db, new GroupAuthStub([], system: true));
        var mineOnly = await SummaryAsync(system, spaceId: mine.Entity.SpaceId);
        Assert.Equal(2, mineOnly.Total);
        Assert.DoesNotContain(mineOnly.Attention, a => a.CommonName.StartsWith("theirs"));
        Assert.Equal(4, (await SummaryAsync(system)).Total);
    }

    /// <summary>The scenario behind <c>CertificateLifecycleSummaryTests.A_reissue_link_or_flag_marks_the_predecessor_replaced</c>, on any provider.</summary>
    internal static async Task A_reissue_link_or_flag_marks_the_predecessor_replaced(ModularCADbContext db)
    {
        var ca = SeedCa(db, "Link");
        var predecessor = Leaf(db, ca, "old.example", -100, -5);
        var successor = Leaf(db, ca, "renamed.example", -6, 300);
        db.CertificateRequests.Add(new CertRequestEntity
        {
            Subject = successor.SubjectDN, Status = "Issued", IssuedCertificateId = successor.CertificateId,
            RenewalOfCertificateId = predecessor.CertificateId,
        });
        var flagged = Leaf(db, ca, "flagged.example", -100, -4, reissued: true);
        var orphan = Leaf(db, ca, "orphan.example", -100, -3);
        db.SaveChanges();

        var controller = NewController(db, new GroupAuthStub([], system: true));
        var summary = await SummaryAsync(controller);
        Assert.Equal(3, summary.Expired);
        Assert.Equal(2, summary.ExpiredReplaced);
        Assert.Equal(1, summary.ExpiredNotReplaced);
        Assert.Equal(1, summary.RecentlyExpiredNotReplaced);
        Assert.Equal(orphan.CertificateId, Assert.Single(summary.Attention).CertificateId);

        var (_, items) = await ListAsync(controller, "expired", null);
        var listed = items.Single(i => i.CertificateId == predecessor.CertificateId);
        Assert.True(listed.Replaced);
        Assert.Equal(successor.SerialNumber, listed.ReplacedBySerial);
        var flaggedItem = items.Single(i => i.CertificateId == flagged.CertificateId);
        Assert.True(flaggedItem.Replaced);
        Assert.Null(flaggedItem.ReplacedBySerial);
        Assert.False(items.Single(i => i.CertificateId == orphan.CertificateId).Replaced);
    }

    /// <summary>The scenario behind <c>CertificateLifecycleSummaryTests.A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case</c>, on any provider.</summary>
    internal static async Task A_newer_valid_certificate_with_the_same_subject_and_san_set_replaces_regardless_of_order_and_case(ModularCADbContext db)
    {
        var ca = SeedCa(db, "Match");
        var other = SeedCa(db, "Other");
        var replaced = Leaf(db, ca, "www.example", -100, -2, ["DNS:www.example", "DNS:api.example"]);
        var successor = Leaf(db, ca, "www.example", -10, 80, ["dns:API.example", "DNS:www.example"]);
        var differentSans = Leaf(db, ca, "mail.example", -100, -2, ["DNS:mail.example"]);
        Leaf(db, ca, "mail.example", -10, 80, ["DNS:mail.example", "DNS:smtp.example"]);
        var revokedSuccessor = Leaf(db, ca, "vpn.example", -100, -2);
        Leaf(db, ca, "vpn.example", -10, 80, revoked: true);
        var otherCa = Leaf(db, ca, "db.example", -100, -2);
        Leaf(db, other, "db.example", -10, 80);
        var expiredSuccessor = Leaf(db, ca, "ftp.example", -100, -20);
        Leaf(db, ca, "ftp.example", -30, -1);

        var controller = NewController(db, new GroupAuthStub([], system: true));
        var (_, items) = await ListAsync(controller, "expired", null);
        string? By(CertificateEntity c) => items.Single(i => i.CertificateId == c.CertificateId) is { Replaced: true } i ? i.ReplacedBySerial : null;

        Assert.Equal(successor.SerialNumber, By(replaced));
        Assert.Null(By(differentSans));
        Assert.Null(By(revokedSuccessor));
        Assert.Null(By(otherCa));
        Assert.Null(By(expiredSuccessor));

        var (yesTotal, yes) = await ListAsync(controller, "expired", "yes");
        Assert.Equal(1, yesTotal);
        Assert.Equal(replaced.CertificateId, Assert.Single(yes).CertificateId);
        var (noTotal, no) = await ListAsync(controller, "expired", "no");
        Assert.Equal(5, noTotal);
        Assert.DoesNotContain(no, i => i.CertificateId == replaced.CertificateId);

        var summary = await SummaryAsync(controller);
        Assert.Equal(1, summary.ExpiredReplaced);
        Assert.Equal(noTotal, summary.ExpiredNotReplaced);
    }

    /// <summary>The scenario behind <c>CertificateLifecycleSummaryTests.Counts_do_not_depend_on_the_list_page</c>, on any provider.</summary>
    internal static async Task Counts_do_not_depend_on_the_list_page(ModularCADbContext db)
    {
        var ca = SeedCa(db, "Paged");
        for (var i = 0; i < 30; i++) Leaf(db, ca, $"expired-{i}.example", -100, -1 - i * 0.5);
        for (var i = 0; i < 12; i++) Leaf(db, ca, $"soon-{i}.example", -60, 1 + i * 2);
        for (var i = 0; i < 8; i++) Leaf(db, ca, $"fine-{i}.example", -10, 200);
        Leaf(db, ca, "ancient.example", -400, -200);

        var controller = NewController(db, new GroupAuthStub([], system: true));
        var (_, firstPage) = await ListAsync(controller, null, null, page: 1, pageSize: 5);
        Assert.Equal(5, firstPage.Count);

        var summary = await SummaryAsync(controller);
        Assert.Equal(51, summary.Total);
        Assert.Equal(31, summary.Expired);
        Assert.Equal(20, summary.Active);
        Assert.Equal(4, summary.ExpiringWithin7Days);
        Assert.Equal(12, summary.ExpiringWithin30Days);
        Assert.Equal(1, summary.ExpiredUnchecked);
        Assert.Equal(30, summary.ExpiredNotReplaced);
        Assert.Equal(30, summary.RecentlyExpiredNotReplaced);
        Assert.Equal(42, summary.AttentionTotal);
        Assert.Equal(20, summary.Attention.Count);
        Assert.Equal("expired-0.example", summary.Attention[0].CommonName);
        Assert.All(summary.Attention, a => Assert.Equal("expired", a.State));
        Assert.Equal(51, Assert.Single(summary.ByCa).Total);

        var (expiredTotal, _) = await ListAsync(controller, "expired", null, pageSize: 5);
        Assert.Equal(summary.Expired, expiredTotal);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class AccessStub : ICertificateAccessEvaluator
    {
        public bool CanViewCertificate(Guid userId, Guid certificateId) => true;
        public bool CanManageCertificate(Guid userId, Guid certificateId) => false;
    }

    private sealed class GroupAuthStub(List<Guid> caIds, bool system = false) : ICaGroupAuthorizationService
    {
        public Task<bool> HasSystemCapabilityAsync(Guid userId, string capability) => Task.FromResult(system);
        public Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability) => Task.FromResult(caIds);
        public Task<List<Guid>> GetAccessibleCaIdsAsync(Guid userId, string capability, Guid? spaceId) => Task.FromResult(caIds);
        public Task<bool> HasCaCapabilityAsync(Guid userId, Guid caId, string capability) => throw new NotSupportedException();
        public Task<bool> HasSpaceCapabilityAsync(Guid userId, Guid spaceId, string capability) => throw new NotSupportedException();
        public Task<List<Guid>> GetSpaceIdsWithCapabilityAsync(Guid userId, string capability) => throw new NotSupportedException();
        public Task<bool> IsSystemAdminAsync(Guid userId) => throw new NotSupportedException();
        public Task<List<CaGroupEntity>> GetUserGroupsAsync(Guid userId) => throw new NotSupportedException();
        public Task<SpaceFence> GetFenceAsync(Guid userId) => throw new NotSupportedException();
        public Task<EffectiveCapabilities> GetEffectiveCapabilitiesAsync(Guid userId) => throw new NotSupportedException();
        public Task<bool> HasResourceCapabilityAsync(Guid userId, string capability, string resourceType, Guid resourceId) => throw new NotSupportedException();
        public Task<(List<Guid> ResourceIds, bool HasWildcard)> GetGrantedResourceIdsAsync(Guid userId, string capabilityPrefix, string resourceType) => throw new NotSupportedException();
    }
}
