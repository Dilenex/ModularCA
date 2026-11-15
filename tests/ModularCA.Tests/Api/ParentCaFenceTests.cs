using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Auth.Authorization;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A viewer whose space fence does not admit a CA's parent learns nothing that identifies the
/// parent: no id, name or label, nothing of its certificate, and no notice text that names it.
/// Driven through the real <c>AdminCaController</c> (the hierarchy feed and the CA list) and
/// <see cref="CaLifecycleService"/>. A viewer who may see the parent still gets all of it.
/// </summary>
public sealed class ParentCaFenceTests
{
    private const string ParentName = "Corporate Trust Anchor";
    private const string ParentLabel = "corp-anchor";
    private static readonly DateTime ParentEnd = new(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime ChildEnd = new(2035, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private sealed class Flags : IFeatureFlagService
    {
        public bool IsEnabled(string flagName) => true;
        public string? GetValue(string flagName) => null;
        public (bool Enabled, string? Value)? Get(string flagName) => (true, null);
        public void InvalidateCache() { }
    }

    /// <summary>An instance CA (no space) that issued an intermediate in a space; the child's certificate ends five years after its parent's.</summary>
    private sealed class World : IDisposable
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public Guid SpaceId { get; } = Guid.NewGuid();
        public CertificateAuthorityEntity Parent { get; }
        public CertificateAuthorityEntity Child { get; }

        public World(DateTime? parentEnd = null)
        {
            Db.Spaces.Add(new SpaceEntity { Id = SpaceId, Name = "Engineering", Slug = "engineering", IsEnabled = true });
            // The CA's name and label are deliberately not its subject: the subject is public (it
            // is the issuer in the child's own certificate), the name and label are the instance's.
            var parentMaterial = TestCaMaterial.CreateCa("CN=Anchor Subject");
            var childMaterial = TestCaMaterial.CreateCa("CN=Engineering Issuing");
            var parentRow = Row(parentMaterial.Certificate, null);
            parentRow.NotAfter = parentEnd ?? ParentEnd;
            var childRow = Row(parentMaterial.Issue(BigInteger.ValueOf(5), childMaterial.SubjectDn, childMaterial.KeyPair.Public, isCa: true), parentRow.CertificateId);
            childRow.NotAfter = ChildEnd;
            (childRow.ExpiryWarningAt, childRow.ExpiryAlertAt) = (ChildEnd.AddDays(-30), ChildEnd.AddDays(-7));
            Parent = new CertificateAuthorityEntity
            {
                Id = Guid.NewGuid(), Name = ParentName, Label = ParentLabel, Type = "Root", SpaceId = null,
                CertificateId = parentRow.CertificateId, Certificate = parentRow, IsEnabled = true,
            };
            Child = new CertificateAuthorityEntity
            {
                Id = Guid.NewGuid(), Name = "Engineering Issuing", Label = "eng-issuing", Type = "Intermediate", SpaceId = SpaceId,
                ParentCaId = Parent.Id, CertificateId = childRow.CertificateId, Certificate = childRow, IsEnabled = true,
            };
            Db.Certificates.AddRange(parentRow, childRow);
            Db.CertificateAuthorities.AddRange(Parent, Child);
            Db.SaveChanges();
            Db.ChangeTracker.Clear();
        }

        /// <summary>A viewer who holds cert.view in the child's space only.</summary>
        public SpaceFence Fenced => SpaceFence.Of([SpaceId], instanceScope: false);

        /// <summary>A viewer who holds cert.view at system scope.</summary>
        public static SpaceFence Unfenced => SpaceFence.Of([], instanceScope: true, systemCapabilities: [Capabilities.CertView]);

        /// <summary>The camel-cased JSON of what <paramref name="action"/> of the real controller answers under <paramref name="fence"/>.</summary>
        public async Task<string> GetAsync(string action, SpaceFence fence)
        {
            var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminCaController");
            var flags = new Flags();
            var controller = (ControllerBase)Activator.CreateInstance(
                type, null, null, Db, null, null, null, null, null, null, flags,
                new ModularCA.Core.Services.Ocsp.OcspResponderReadiness(Db, new StubSecurityPolicyService(), flags))!;
            var services = new ServiceCollection();
            services.AddSingleton(new CaLifecycleService(Db, new SystemConfig()));
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Guid.NewGuid().ToString())], "test")),
                RequestServices = services.BuildServiceProvider(),
            };
            SpaceFence.Store(http, fence);
            controller.ControllerContext = new ControllerContext { HttpContext = http };

            var result = await (Task<IActionResult>)type.GetMethod(action, BindingFlags.Instance | BindingFlags.Public)!.Invoke(controller, null)!;
            return JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        public void Dispose() => Db.Dispose();
    }

    private static CertificateEntity Row(Org.BouncyCastle.X509.X509Certificate cert, Guid? issuerRow)
    {
        var id = Guid.NewGuid();
        var (warning, alert) = ExpiryWarningRule.Compute(cert.NotBefore, cert.NotAfter, true, null);
        return new CertificateEntity
        {
            CertificateId = id,
            SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE"),
            RawCertificate = cert.GetEncoded(),
            NotBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            ExpiryWarningAt = warning.ToUniversalTime(),
            ExpiryAlertAt = alert.ToUniversalTime(),
            IssuerCertificateId = issuerRow ?? id,
        };
    }

    private static int Words(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;

    /// <summary>Fails when <paramref name="json"/> carries anything that identifies the parent CA, or the end of its certificate.</summary>
    private static void AssertNothingOfTheParent(string json, World world)
    {
        Assert.DoesNotContain(ParentName, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ParentLabel, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(world.Parent.Id.ToString("D"), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(world.Parent.Id.ToString("N"), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(world.Parent.CertificateId!.Value.ToString("D"), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("2030-01-01", json);
    }

    // ── The hierarchy feed ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_fenced_viewer_gets_no_name_label_or_id_of_the_parent_in_the_hierarchy_feed()
    {
        using var world = new World();

        var json = await world.GetAsync("GetHierarchy", world.Fenced);

        AssertNothingOfTheParent(json, world);
        var child = Assert.Single(JsonDocument.Parse(json).RootElement.EnumerateArray().ToList());
        Assert.Equal(world.Child.Id, child.GetProperty("id").GetGuid());
        Assert.Equal(JsonValueKind.Null, child.GetProperty("parentCaId").ValueKind);
        Assert.True(child.GetProperty("parentHidden").GetBoolean());
        Assert.False(child.GetProperty("isRoot").GetBoolean());
        var period = child.GetProperty("cryptoperiod");
        Assert.Equal(JsonValueKind.Null, period.GetProperty("parentName").ValueKind);
        Assert.Equal(JsonValueKind.Null, period.GetProperty("parentCertificateNotAfter").ValueKind);
    }

    [Fact]
    public async Task A_fenced_viewer_is_still_told_the_certificate_outlives_its_parents_in_words_that_name_no_parent()
    {
        using var world = new World();

        var json = await world.GetAsync("GetHierarchy", world.Fenced);

        var child = JsonDocument.Parse(json).RootElement.EnumerateArray().Single();
        var outlives = child.GetProperty("keyAdvisories").EnumerateArray().Single(a => a.GetProperty("reason").GetString() == CaCryptoperiod.OutlivesParent);
        var message = outlives.GetProperty("message").GetString()!;
        Assert.Equal(
            "This certificate is valid until 2035-01-01, but its parent's certificate expires earlier. Ask an administrator of the parent CA to renew it.",
            message);
        Assert.Equal(22, Words(message));
        Assert.Equal(CaKeyAdvisory.Notice, outlives.GetProperty("severity").GetString());
        foreach (var advisory in child.GetProperty("keyAdvisories").EnumerateArray())
        {
            Assert.DoesNotContain(ParentName, advisory.GetProperty("message").GetString()!, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(ParentName, advisory.GetProperty("title").GetString() ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.True(Words(advisory.GetProperty("message").GetString()!) <= 40);
        }
    }

    [Fact]
    public async Task A_fenced_viewer_is_told_a_hidden_parents_certificate_has_expired_without_its_date()
    {
        using var world = new World(parentEnd: new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc));

        var json = await world.GetAsync("GetHierarchy", world.Fenced);

        Assert.DoesNotContain("2025-06-01", json);
        Assert.DoesNotContain(ParentName, json, StringComparison.OrdinalIgnoreCase);
        var outlives = JsonDocument.Parse(json).RootElement.EnumerateArray().Single()
            .GetProperty("keyAdvisories").EnumerateArray().Single(a => a.GetProperty("reason").GetString() == CaCryptoperiod.OutlivesParent);
        Assert.Equal(
            "This certificate is valid until 2035-01-01, but its parent's certificate has expired. Ask an administrator of the parent CA to renew it.",
            outlives.GetProperty("message").GetString());
        Assert.Equal(CaKeyAdvisory.Critical, outlives.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task An_unfenced_viewer_still_gets_the_parents_id_name_and_expiry()
    {
        using var world = new World();

        var json = await world.GetAsync("GetHierarchy", World.Unfenced);

        var parent = Assert.Single(JsonDocument.Parse(json).RootElement.EnumerateArray().ToList());
        Assert.Equal(ParentName, parent.GetProperty("name").GetString());
        Assert.Equal(ParentLabel, parent.GetProperty("label").GetString());
        var child = Assert.Single(parent.GetProperty("children").EnumerateArray().ToList());
        Assert.Equal(world.Parent.Id, child.GetProperty("parentCaId").GetGuid());
        Assert.False(child.GetProperty("parentHidden").GetBoolean());
        var period = child.GetProperty("cryptoperiod");
        Assert.Equal(ParentName, period.GetProperty("parentName").GetString());
        Assert.Equal(ParentEnd, period.GetProperty("parentCertificateNotAfter").GetDateTime().ToUniversalTime());
        var outlives = child.GetProperty("keyAdvisories").EnumerateArray().Single(a => a.GetProperty("reason").GetString() == CaCryptoperiod.OutlivesParent);
        Assert.Equal(
            $"This certificate is valid until 2035-01-01, but the certificate of its parent '{ParentName}' expires on 2030-01-01. Renew the parent's certificate before then.",
            outlives.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_viewer_whose_fence_admits_the_parents_space_but_not_the_list_still_gets_it_named()
    {
        // The parent is soft-deleted: no list returns it to anyone, but the viewer may see instance CAs.
        using var world = new World();
        var parent = world.Db.CertificateAuthorities.Single(ca => ca.Id == world.Parent.Id);
        parent.IsDeleted = true;
        world.Db.SaveChanges();
        world.Db.ChangeTracker.Clear();

        var json = await world.GetAsync("GetHierarchy", SpaceFence.Of([world.SpaceId], instanceScope: true));

        var child = Assert.Single(JsonDocument.Parse(json).RootElement.EnumerateArray().ToList());
        Assert.Equal(world.Parent.Id, child.GetProperty("parentCaId").GetGuid());
        Assert.False(child.GetProperty("parentHidden").GetBoolean());
        Assert.Equal(ParentName, child.GetProperty("cryptoperiod").GetProperty("parentName").GetString());
    }

    // ── The CA list ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_ca_list_gives_a_fenced_viewer_no_parent_id_and_an_unfenced_one_the_id()
    {
        using var world = new World();

        var fenced = await world.GetAsync("GetCertificateAuthorities", world.Fenced);
        var open = await world.GetAsync("GetCertificateAuthorities", World.Unfenced);

        AssertNothingOfTheParent(fenced, world);
        var row = Assert.Single(JsonDocument.Parse(fenced).RootElement.EnumerateArray().ToList());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("parentCaId").ValueKind);
        Assert.True(row.GetProperty("parentHidden").GetBoolean());

        var rows = JsonDocument.Parse(open).RootElement.EnumerateArray().ToList();
        var child = rows.Single(r => r.GetProperty("id").GetGuid() == world.Child.Id);
        Assert.Equal(world.Parent.Id, child.GetProperty("parentCaId").GetGuid());
        Assert.False(child.GetProperty("parentHidden").GetBoolean());
        Assert.False(rows.Single(r => r.GetProperty("id").GetGuid() == world.Parent.Id).GetProperty("parentHidden").GetBoolean());
    }

    // ── The lifetime facts themselves ───────────────────────────────────────────────────────

    [Fact]
    public async Task The_lifetime_facts_withhold_a_parent_that_was_not_asked_about_unless_the_caller_says_the_reader_may_see_it()
    {
        using var world = new World();
        var service = new CaLifecycleService(world.Db, new SystemConfig());
        var child = world.Db.CertificateAuthorities.Single(ca => ca.Id == world.Child.Id);
        world.Db.Entry(child).Reference(ca => ca.Certificate).Load();
        var now = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // Nothing said about the reader: the default leaks nothing.
        var byDefault = (await service.DescribeAsync([child], now))[child.Id];
        // A fence that admits the child's space only, and one that admits every space.
        var fenced = (await service.DescribeAsync([child], now, default, world.Fenced.Allows))[child.Id];
        var open = (await service.DescribeAsync([child], now, default, World.Unfenced.For(Capabilities.CertView).Allows))[child.Id];

        foreach (var report in new[] { byDefault, fenced })
        {
            Assert.Null(report.Facts.ParentName);
            Assert.Null(report.Facts.ParentCertificateNotAfter);
            Assert.Equal(CaWithheldParent.EndsFirst, report.Facts.WithheldParent);
            Assert.DoesNotContain(report.Advisories, a => a.Message.Contains(ParentName, StringComparison.OrdinalIgnoreCase) || a.Message.Contains("2030-01-01"));
            Assert.Contains(report.Advisories, a => a.Reason == CaCryptoperiod.OutlivesParent);
        }
        Assert.Equal(ParentName, open.Facts.ParentName);
        Assert.Equal(ParentEnd, open.Facts.ParentCertificateNotAfter);
        Assert.Null(open.Facts.WithheldParent);
        Assert.Contains(ParentName, open.Advisories.Single(a => a.Reason == CaCryptoperiod.OutlivesParent).Message);
    }

    [Fact]
    public async Task A_hidden_parent_whose_certificate_does_not_end_first_raises_no_notice_and_is_not_named()
    {
        using var world = new World(parentEnd: new DateTime(2040, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var child = world.Db.CertificateAuthorities.Single(ca => ca.Id == world.Child.Id);
        world.Db.Entry(child).Reference(ca => ca.Certificate).Load();

        var report = (await new CaLifecycleService(world.Db, new SystemConfig())
            .DescribeAsync([child], new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc), default, world.Fenced.Allows))[child.Id];

        Assert.Equal(CaWithheldParent.NoEarlierEnd, report.Facts.WithheldParent);
        Assert.Null(report.Facts.ParentName);
        Assert.Null(report.Facts.ParentCertificateNotAfter);
        Assert.DoesNotContain(report.Advisories, a => a.Reason == CaCryptoperiod.OutlivesParent);
    }

    [Fact]
    public async Task A_parent_among_the_cas_shown_is_named_whatever_the_caller_says_of_spaces()
    {
        using var world = new World();
        var cas = world.Db.CertificateAuthorities.ToList();
        foreach (var ca in cas)
            world.Db.Entry(ca).Reference(c => c.Certificate).Load();

        var report = (await new CaLifecycleService(world.Db, new SystemConfig())
            .DescribeAsync(cas, new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc)))[world.Child.Id];

        Assert.Equal(ParentName, report.Facts.ParentName);
        Assert.Null(report.Facts.WithheldParent);
    }
}
