using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Which signing profile issues the instance's Web TLS certificate. Every new CA's signing profile
/// is linked to the instance-wide cert profiles, the Web TLS one included, so taking the first link
/// could hand the instance's TLS identity to any space's CA, or to a disabled or system CA, in row
/// order. Only instance CAs are considered, then CAs of the bootstrap's primary space (which holds
/// the bootstrap root), oldest signing profile first.
/// </summary>
public sealed class WebTlsSigningProfileTests
{
    private sealed class Seed(ModularCADbContext db)
    {
        public Guid WebTls { get; } = Add(db, new CertProfileEntity { Name = "Web TLS Certificate Profile", KeyUsages = "[]", ExtendedKeyUsages = "[]" }).Id;
        public Guid Primary { get; } = Add(db, new SpaceEntity { Name = "Primary", Slug = "primary", CanBeDeleted = false }).Id;
        public Guid Delegated { get; } = Add(db, new SpaceEntity { Name = "Delegated", Slug = "delegated" }).Id;
        private DateTime _clock = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>A CA with a signing profile linked to the Web TLS profile, created a minute after the previous one.</summary>
        public SigningProfileEntity Ca(string label, Guid? spaceId, bool enabled = true, bool deleted = false)
        {
            var cert = Add(db, new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = label, SubjectDN = $"CN={label}", Issuer = $"CN={label}", Pem = "x", IsCA = true });
            Add(db, new CertificateAuthorityEntity { Name = label, Label = label, SpaceId = spaceId, CertificateId = cert.CertificateId, IsEnabled = enabled, IsDeleted = deleted });
            _clock = _clock.AddMinutes(1);
            var profile = Add(db, new SigningProfileEntity { Name = $"{label} signing", IssuerId = cert.CertificateId, CreatedAt = _clock });
            Add(db, new AllowedCertProfileSigningProfileEntity { CertProfileId = WebTls, SigningProfileId = profile.Id });
            return profile;
        }

        private static T Add<T>(ModularCADbContext db, T row) where T : class
        {
            db.Add(row);
            db.SaveChanges();
            return row;
        }
    }

    [Fact]
    public async Task Only_instance_cas_then_the_primary_space_are_considered_oldest_first()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = new Seed(db);
        s.Ca("delegated-old", s.Delegated);
        s.Ca("system-signing-ca", null);
        s.Ca("disabled", null, enabled: false);
        s.Ca("deleted", null, deleted: true);
        var primary = s.Ca("primary-root", s.Primary);
        var instanceOld = s.Ca("instance-old", null);
        s.Ca("instance-new", null);

        Assert.Equal(instanceOld.Id, (await WebTlsProvisioningService.ResolveSigningProfileAsync(db, s.WebTls))!.Id);

        db.CertificateAuthorities.Where(c => c.SpaceId == null).ToList().ForEach(c => c.IsEnabled = false);
        db.SaveChanges();
        Assert.Equal(primary.Id, (await WebTlsProvisioningService.ResolveSigningProfileAsync(db, s.WebTls))!.Id);
    }

    [Fact]
    public async Task A_delegated_space_ca_alone_is_never_chosen()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = new Seed(db);
        s.Ca("delegated", s.Delegated);
        s.Ca("system-signing-ca", null);

        Assert.Null(await WebTlsProvisioningService.ResolveSigningProfileAsync(db, s.WebTls));
    }
}
