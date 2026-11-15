using ModularCA.Core.Helpers;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Helpers;

/// <summary>
/// <see cref="AnchorIssuerPath"/>: which certificates above a stored CA certificate are handed to
/// the chain validator, and when none are.
/// </summary>
public sealed class AnchorIssuerPathTests
{
    [Fact]
    public async Task An_issuing_CA_under_a_stored_root_gets_the_root_when_revocation_is_required()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var anchor = db.Certificates.Single(c => c.CertificateId == pki.IssuingCertificateId);

        using var path = await AnchorIssuerPath.LoadAsync(db, anchor, requireRevocationCheck: true);

        var only = Assert.Single(path.Certificates);
        Assert.Equal(pki.Root.RawData, only.RawData);
    }

    [Fact]
    public async Task Nothing_is_loaded_when_revocation_is_not_required()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var anchor = db.Certificates.Single(c => c.CertificateId == pki.IssuingCertificateId);

        using var path = await AnchorIssuerPath.LoadAsync(db, anchor, requireRevocationCheck: false);

        Assert.Empty(path.Certificates);
    }

    [Fact]
    public async Task A_root_has_no_issuers_to_load()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var root = db.Certificates.Single(c => c.CertificateId == pki.RootCertificateId);

        using var path = await AnchorIssuerPath.LoadAsync(db, root, requireRevocationCheck: true);

        Assert.Empty(path.Certificates);
    }

    [Fact]
    public async Task An_issuing_CA_whose_root_is_not_stored_gets_an_empty_path()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db, storeRoot: false);
        var anchor = db.Certificates.Single(c => c.CertificateId == pki.IssuingCertificateId);

        using var path = await AnchorIssuerPath.LoadAsync(db, anchor, requireRevocationCheck: true);

        Assert.Empty(path.Certificates);
    }

    /// <summary>
    /// A parent row that cannot be parsed must not break the sign-in with an exception; the path
    /// comes back empty and the validator is left on what it does without issuers.
    /// </summary>
    [Fact]
    public async Task A_parent_row_that_cannot_be_parsed_gives_an_empty_path()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var root = db.Certificates.Single(c => c.CertificateId == pki.RootCertificateId);
        root.RawCertificate = null;
        root.Pem = "-";
        db.SaveChanges();
        var anchor = db.Certificates.Single(c => c.CertificateId == pki.IssuingCertificateId);

        using var path = await AnchorIssuerPath.LoadAsync(db, anchor, requireRevocationCheck: true);

        Assert.Empty(path.Certificates);
    }
}
