using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Linking legacy certificate rows to the CA certificate that issued them. CA-scoped access and
/// the console's lists scope by <see cref="CertificateEntity.IssuerCertificateId"/>, so a row
/// without it is invisible to a CA-scoped user; a row with the wrong one is visible to the wrong
/// CA, which is why an ambiguous match is left alone.
/// </summary>
public sealed class IssuerCertificateBackfillTests
{
    private static readonly DateTimeOffset From = DateTimeOffset.UtcNow.AddDays(-30);
    private static readonly DateTimeOffset To = DateTimeOffset.UtcNow.AddYears(2);

    private static X509Certificate2 Ca(string dn, ECDsa key, DateTimeOffset? from = null, DateTimeOffset? to = null)
    {
        var req = new CertificateRequest(dn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req.CreateSelfSigned(from ?? From, to ?? To);
    }

    private static X509Certificate2 Leaf(X509Certificate2 issuer, string cn = "CN=legacy.example")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        var serial = new byte[12];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        using var signed = req.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), serial);
        return X509CertificateLoader.LoadCertificate(signed.Export(X509ContentType.Cert));
    }

    private static CertificateEntity Row(X509Certificate2 cert, bool isCa, Guid? signingProfileId = null) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = cert.SerialNumber,
        Pem = cert.ExportCertificatePem(),
        RawCertificate = cert.RawData,
        SubjectDN = cert.Subject,
        Issuer = cert.Issuer,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
        IsCA = isCa,
        SigningProfileId = signingProfileId,
    };

    private static CertificateAuthorityEntity Authority(CertificateEntity caRow, Guid tenantId, string label) => new()
    {
        Id = Guid.NewGuid(), Name = label, Label = label, TenantId = tenantId, CertificateId = caRow.CertificateId,
    };

    private static async Task<Guid?> IssuerOf(ModularCADbContext db, Guid certificateId)
        => (await db.Certificates.AsNoTracking().FirstAsync(c => c.CertificateId == certificateId)).IssuerCertificateId;

    [Fact]
    public async Task A_legacy_row_is_linked_to_the_ca_that_signed_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = Ca("CN=Legacy CA", key);
        var caRow = Row(ca, isCa: true);
        var leafRow = Row(Leaf(ca), isCa: false);
        db.Certificates.AddRange(caRow, leafRow);
        db.CertificateAuthorities.Add(Authority(caRow, Guid.NewGuid(), "legacy"));
        db.SaveChanges();

        var result = await IssuerCertificateBackfill.RunAsync(db);

        Assert.Equal(caRow.CertificateId, await IssuerOf(db, leafRow.CertificateId));
        Assert.Equal(caRow.CertificateId, await IssuerOf(db, caRow.CertificateId));
        Assert.Equal(2, result.Linked);

        var again = await IssuerCertificateBackfill.RunAsync(db);
        Assert.Equal(0, again.Scanned);
    }

    [Fact]
    public async Task On_a_relational_provider_rows_are_linked_by_a_set_based_update()
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        connection.Open();
        using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(connection).Options);
        db.Database.EnsureCreated();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = Ca("CN=Relational CA", key);
        var caRow = Row(ca, isCa: true);
        var leafRows = Enumerable.Range(0, 5).Select(i => Row(Leaf(ca, $"CN=leaf{i}.example"), isCa: false)).ToList();
        db.Certificates.Add(caRow);
        db.Certificates.AddRange(leafRows);
        db.SaveChanges();
        db.ChangeTracker.Clear();

        var result = await IssuerCertificateBackfill.RunAsync(db, batchSize: 2);

        Assert.Equal(6, result.Linked);
        Assert.Empty(db.ChangeTracker.Entries());
        foreach (var leaf in leafRows)
            Assert.Equal(caRow.CertificateId, await IssuerOf(db, leaf.CertificateId));
        Assert.Equal(0, (await IssuerCertificateBackfill.RunAsync(db)).Scanned);
    }

    [Fact]
    public async Task A_row_issued_under_a_superseded_ca_certificate_is_linked_to_that_certificate()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var superseded = Ca("CN=Renewed CA", oldKey);
        using var current = Ca("CN=Renewed CA", newKey);
        var supersededRow = Row(superseded, isCa: true);
        var currentRow = Row(current, isCa: true);
        var leafRow = Row(Leaf(superseded), isCa: false);
        db.Certificates.AddRange(supersededRow, currentRow, leafRow);
        db.CertificateAuthorities.Add(Authority(currentRow, Guid.NewGuid(), "renewed"));
        db.SaveChanges();

        await IssuerCertificateBackfill.RunAsync(db);

        Assert.Equal(supersededRow.CertificateId, await IssuerOf(db, leafRow.CertificateId));
    }

    [Fact]
    public async Task An_ambiguous_match_is_left_null()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var first = Ca("CN=Twin CA", key);
        using var second = Ca("CN=Twin CA", key);
        var firstRow = Row(first, isCa: true);
        var secondRow = Row(second, isCa: true);
        var leafRow = Row(Leaf(first), isCa: false);
        db.Certificates.AddRange(firstRow, secondRow, leafRow);
        db.CertificateAuthorities.AddRange(Authority(firstRow, Guid.NewGuid(), "twin-a"), Authority(secondRow, Guid.NewGuid(), "twin-b"));
        db.SaveChanges();

        var result = await IssuerCertificateBackfill.RunAsync(db);

        Assert.Null(await IssuerOf(db, leafRow.CertificateId));
        Assert.Equal(1, result.Ambiguous);
    }

    [Fact]
    public async Task The_signing_profiles_tenant_settles_a_match_that_is_otherwise_ambiguous()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var first = Ca("CN=Twin CA", key);
        using var second = Ca("CN=Twin CA", key);
        var firstRow = Row(first, isCa: true);
        var secondRow = Row(second, isCa: true);
        var tenantB = Guid.NewGuid();
        var profile = new SigningProfileEntity { Name = "b", IssuerId = secondRow.CertificateId };
        var leafRow = Row(Leaf(first), isCa: false, profile.Id);
        db.Certificates.AddRange(firstRow, secondRow, leafRow);
        db.SigningProfiles.Add(profile);
        db.CertificateAuthorities.AddRange(Authority(firstRow, Guid.NewGuid(), "twin-a"), Authority(secondRow, tenantB, "twin-b"));
        db.SaveChanges();

        await IssuerCertificateBackfill.RunAsync(db);

        Assert.Equal(secondRow.CertificateId, await IssuerOf(db, leafRow.CertificateId));
    }

    [Fact]
    public async Task A_same_named_ca_in_another_tenant_is_not_matched()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var mineKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var theirKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var strangerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var mine = Ca("CN=Shared Name CA", mineKey);
        using var theirs = Ca("CN=Shared Name CA", theirKey);
        using var stranger = Ca("CN=Shared Name CA", strangerKey);
        var mineRow = Row(mine, isCa: true);
        var theirRow = Row(theirs, isCa: true);
        var mineLeaf = Row(Leaf(mine), isCa: false);
        var strangerLeaf = Row(Leaf(stranger, "CN=forged.example"), isCa: false);
        db.Certificates.AddRange(mineRow, theirRow, mineLeaf, strangerLeaf);
        db.CertificateAuthorities.AddRange(Authority(mineRow, Guid.NewGuid(), "mine"), Authority(theirRow, Guid.NewGuid(), "theirs"));
        db.SaveChanges();

        await IssuerCertificateBackfill.RunAsync(db);

        Assert.Equal(mineRow.CertificateId, await IssuerOf(db, mineLeaf.CertificateId));
        Assert.Null(await IssuerOf(db, strangerLeaf.CertificateId));
    }
}
