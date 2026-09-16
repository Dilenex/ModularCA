using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The template list takes the console's CA scope as an optional filter; without it the whole
/// list still comes back.
/// </summary>
public class CertificateTemplateScopeTests
{
    // The list joins the CA and both profiles (required navigations), so each template needs
    // real rows behind it or the in-memory provider drops it from the join.
    private static CertificateTemplateEntity Template(ModularCA.Database.ModularCADbContext db, string name, Guid caId)
    {
        var cp = new CertProfileEntity { Id = Guid.NewGuid(), Name = $"cp-{name}" };
        var sp = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"sp-{name}" };
        db.CertProfiles.Add(cp);
        db.SigningProfiles.Add(sp);
        return new CertificateTemplateEntity { Id = Guid.NewGuid(), Name = name, CaId = caId, CertProfileId = cp.Id, SigningProfileId = sp.Id };
    }

    [Fact]
    public async Task The_list_can_be_narrowed_to_one_issuing_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var caA = Guid.NewGuid();
        var caB = Guid.NewGuid();
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = caA, Name = "A", Label = "a" },
            new CertificateAuthorityEntity { Id = caB, Name = "B", Label = "b" });
        db.CertificateTemplates.AddRange(Template(db, "web", caA), Template(db, "device", caB), Template(db, "vpn", caA));
        await db.SaveChangesAsync();
        var service = new CertificateTemplateService(db);

        var all = await service.GetAllAsync();
        var onlyA = await service.GetAllAsync(caA);

        Assert.Equal(3, all.Count);
        Assert.Equal(new[] { "vpn", "web" }, onlyA.Select(t => t.Name));
        Assert.All(onlyA, t => Assert.Equal(caA, t.CaId));
    }
}
