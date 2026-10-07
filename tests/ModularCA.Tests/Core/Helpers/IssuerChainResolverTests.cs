using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Helpers;

/// <summary>
/// The single issuer-chain walk: which issuer each hop follows, where the root is included,
/// truncation by the caller's predicate, and cycle safety.
/// </summary>
public sealed class IssuerChainResolverTests
{
    private static CertificateEntity Cert(string cn, bool isCa, Guid? issuerCertId = null, Guid? signingProfileId = null, string? issuerCn = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var x509 = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = x509.SerialNumber,
            Pem = x509.ExportCertificatePem(),
            SubjectDN = x509.Subject,
            Issuer = issuerCn == null ? x509.Issuer : $"CN={issuerCn}",
            IsCA = isCa,
            IssuerCertificateId = issuerCertId,
            SigningProfileId = signingProfileId,
        };
    }

    private sealed record Hierarchy(CertificateEntity Root, CertificateEntity Int, CertificateEntity Leaf,
        CertificateAuthorityEntity RootCa, CertificateAuthorityEntity IntCa, SigningProfileEntity Profile);

    private static Hierarchy Seed(ModularCADbContext db)
    {
        var root = Cert("Root", isCa: true);
        root.IssuerCertificateId = root.CertificateId;
        var intermediate = Cert("Int", isCa: true, issuerCertId: root.CertificateId, issuerCn: "Root");
        var profile = new SigningProfileEntity { Name = "p", IssuerId = intermediate.CertificateId };
        var leaf = Cert("Leaf", isCa: false, issuerCertId: intermediate.CertificateId, signingProfileId: profile.Id, issuerCn: "Int");
        var space = Guid.NewGuid();
        var rootCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Root", Label = "root", SpaceId = space, CertificateId = root.CertificateId };
        var intCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Int", Label = "int", SpaceId = space, CertificateId = intermediate.CertificateId, ParentCaId = rootCa.Id };
        db.Certificates.AddRange(root, intermediate, leaf);
        db.SigningProfiles.Add(profile);
        db.CertificateAuthorities.AddRange(rootCa, intCa);
        db.SaveChanges();
        return new Hierarchy(root, intermediate, leaf, rootCa, intCa, profile);
    }

    private static List<Guid> Ids(IEnumerable<CertificateEntity> chain) => chain.Select(c => c.CertificateId).ToList();

    [Fact]
    public async Task A_leaf_under_an_intermediate_gets_the_intermediate_but_not_the_root()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);

        Assert.Equal([h.Int.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Leaf)));
    }

    [Fact]
    public async Task The_root_is_included_when_it_is_the_direct_issuer()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);

        Assert.Equal([h.Root.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Int)));
        Assert.Empty(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Root));
    }

    [Fact]
    public async Task The_certificates_own_issuer_wins_over_a_repointed_signing_profile()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        var renewed = Cert("Int", isCa: true, issuerCertId: h.Root.CertificateId, issuerCn: "Root");
        db.Certificates.Add(renewed);
        h.Profile.IssuerId = renewed.CertificateId;
        h.IntCa.CertificateId = renewed.CertificateId;
        db.SaveChanges();

        Assert.Equal([h.Int.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Leaf)));
    }

    [Fact]
    public async Task The_signing_profile_is_the_fallback_when_the_issuer_link_is_missing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        h.Leaf.IssuerCertificateId = null;
        h.Int.IssuerCertificateId = null;
        db.SaveChanges();

        Assert.Equal([h.Int.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Leaf)));
        Assert.Equal([h.Root.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Int)));
    }

    [Fact]
    public async Task A_cycle_in_the_issuer_links_ends_the_walk()
    {
        using var db = InMemoryDbContextFactory.Create();
        var a = Cert("A", isCa: true, issuerCn: "B");
        var b = Cert("B", isCa: true, issuerCertId: a.CertificateId, issuerCn: "A");
        a.IssuerCertificateId = b.CertificateId;
        var leaf = Cert("Leaf", isCa: false, issuerCertId: a.CertificateId, issuerCn: "A");
        db.Certificates.AddRange(a, b, leaf);
        db.SaveChanges();

        Assert.Equal([a.CertificateId, b.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, leaf)));
    }

    [Fact]
    public async Task An_intermediate_under_an_unstored_external_root_is_included_and_ends_the_walk()
    {
        using var db = InMemoryDbContextFactory.Create();
        var policy = Cert("Policy", isCa: true, issuerCn: "Offline Root");
        var issuing = Cert("Issuing", isCa: true, issuerCertId: policy.CertificateId, issuerCn: "Policy");
        var leaf = Cert("Leaf", isCa: false, issuerCertId: issuing.CertificateId, issuerCn: "Issuing");
        var space = Guid.NewGuid();
        var policyCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Policy", Label = "policy", SpaceId = space, CertificateId = policy.CertificateId };
        var issuingCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Issuing", Label = "issuing", SpaceId = space, CertificateId = issuing.CertificateId, ParentCaId = policyCa.Id };
        db.Certificates.AddRange(policy, issuing, leaf);
        db.CertificateAuthorities.AddRange(policyCa, issuingCa);
        db.SaveChanges();

        Assert.Equal([issuing.CertificateId, policy.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, leaf)));
        Assert.Equal([policy.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, issuing)));
        Assert.Empty(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, policy));

        var resolved = await IssuerChainResolver.ResolveAsync(db, leaf, includeChain: true);
        Assert.Equal(issuingCa.Id, resolved.CaId);
        Assert.Equal(2, resolved.Chain.Count);
    }

    [Fact]
    public async Task A_self_signed_root_found_by_dn_is_excluded_when_it_is_not_the_direct_issuer()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        var policy = Cert("Policy", isCa: true, issuerCertId: h.Root.CertificateId, issuerCn: "Root");
        h.Int.IssuerCertificateId = policy.CertificateId;
        h.Int.Issuer = "CN=Policy";
        h.Root.IssuerCertificateId = null;
        db.Certificates.Add(policy);
        db.SaveChanges();

        Assert.Equal([h.Int.CertificateId, policy.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Leaf)));
        Assert.Equal([h.Root.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, policy)));
    }

    [Fact]
    public async Task An_intermediate_named_like_its_parent_is_kept_in_the_middle_of_the_chain()
    {
        using var db = InMemoryDbContextFactory.Create();
        var root = Cert("Acme CA", isCa: true);
        root.IssuerCertificateId = root.CertificateId;
        var i1 = Cert("Acme CA", isCa: true, issuerCertId: root.CertificateId, issuerCn: "Acme CA");
        var i2 = Cert("Acme Issuing", isCa: true, issuerCertId: i1.CertificateId, issuerCn: "Acme CA");
        var leaf = Cert("Leaf", isCa: false, issuerCertId: i2.CertificateId, issuerCn: "Acme Issuing");
        db.Certificates.AddRange(root, i1, i2, leaf);
        db.SaveChanges();

        Assert.Equal([i2.CertificateId, i1.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, leaf)));
        Assert.Equal([i1.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, i2)));
        Assert.Equal([root.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, i1)));
        Assert.Equal(2, (await IssuerChainResolver.ResolveAsync(db, leaf, includeChain: true)).Chain.Count);
    }

    private static CertificateEntity Supersede(ModularCADbContext db, Hierarchy h)
    {
        var renewed = Cert("Int", isCa: true, issuerCertId: h.Root.CertificateId, issuerCn: "Root");
        db.Certificates.Add(renewed);
        h.IntCa.CertificateId = renewed.CertificateId;
        return renewed;
    }

    [Fact]
    public async Task ResolveAsync_attributes_a_superseded_issuer_to_its_ca_despite_a_repointed_profile()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        Supersede(db, h);
        h.Profile.IssuerId = h.Root.CertificateId;
        db.SaveChanges();

        var resolved = await IssuerChainResolver.ResolveAsync(db, h.Leaf, includeChain: true);

        Assert.Equal(h.IntCa.Id, resolved.CaId);
        Assert.Equal(h.IntCa.SpaceId, resolved.SpaceId);
        using var x509 = X509CertificateLoader.LoadCertificate(Assert.Single(resolved.Chain));
        Assert.Equal(h.Int.Pem, x509.ExportCertificatePem());
    }

    [Fact]
    public async Task ResolveAsync_attributes_a_superseded_issuer_to_its_ca_without_a_profile()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        Supersede(db, h);
        h.Leaf.SigningProfileId = null;
        db.SaveChanges();

        var resolved = await IssuerChainResolver.ResolveAsync(db, h.Leaf, includeChain: false);

        Assert.Equal(h.IntCa.Id, resolved.CaId);
        Assert.Empty(resolved.Chain);
    }

    [Fact]
    public async Task A_key_match_outranks_a_same_named_ca_in_another_space()
    {
        // The renewed intermediate kept its key but moved under a new root, so its issuer DN no
        // longer matches the superseded one; a same-named CA in another space has the old issuer
        // DN. Ranking the DN above the key attributed the superseded certificate to the stranger.
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        var renewed = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "renewed", Pem = h.Int.Pem, SubjectDN = h.Int.SubjectDN,
            Issuer = "CN=Root G2", IsCA = true,
        };
        db.Certificates.Add(renewed);
        h.IntCa.CertificateId = renewed.CertificateId;
        var stranger = Cert("Int", isCa: true, issuerCn: "Root");
        db.Certificates.Add(stranger);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = "Int", Label = "int-elsewhere", SpaceId = Guid.NewGuid(), CertificateId = stranger.CertificateId,
        });
        db.SaveChanges();

        var owner = IssuerChainResolver.OwnerOf(db, h.Int.CertificateId);

        Assert.Equal(h.IntCa.Id, owner?.CaId);
        Assert.Equal(h.IntCa.Id, (await IssuerChainResolver.ResolveAsync(db, h.Leaf, includeChain: false)).CaId);
    }

    [Fact]
    public void A_dn_only_match_is_restricted_to_the_superseded_certificates_space()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        Supersede(db, h);
        h.RootCa.SpaceId = Guid.NewGuid();
        h.IntCa.SpaceId = h.RootCa.SpaceId;
        var stranger = Cert("Int", isCa: true, issuerCn: "Root");
        db.Certificates.Add(stranger);
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = "Int", Label = "int-elsewhere", SpaceId = Guid.NewGuid(), CertificateId = stranger.CertificateId,
        });
        db.SaveChanges();

        Assert.Equal(h.IntCa.Id, IssuerChainResolver.OwnerOf(db, h.Int.CertificateId)?.CaId);

        h.Int.IssuerCertificateId = null;
        db.SaveChanges();
        Assert.Null(IssuerChainResolver.OwnerOf(db, h.Int.CertificateId));
    }

    [Fact]
    public async Task A_hop_takes_its_ca_space_and_parent_from_one_ca_row()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);
        h.Int.IssuerCertificateId = null;
        db.SaveChanges();

        var resolved = await IssuerChainResolver.ResolveAsync(db, h.Leaf, includeChain: true);

        Assert.Equal(h.IntCa.Id, resolved.CaId);
        Assert.Equal(h.IntCa.SpaceId, resolved.SpaceId);
        Assert.Equal([h.Root.CertificateId], Ids(await IssuerChainResolver.ResolveIssuerCertificatesAsync(db, h.Int)));
    }

    [Fact]
    public async Task ResolveAsync_returns_der_and_the_issuing_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var h = Seed(db);

        var chain = await IssuerChainResolver.ResolveAsync(db, h.Leaf, includeChain: true);

        Assert.Equal(h.IntCa.Id, chain.CaId);
        Assert.Equal(h.IntCa.SpaceId, chain.SpaceId);
        var der = Assert.Single(chain.Chain);
        using var x509 = X509CertificateLoader.LoadCertificate(der);
        Assert.Equal(h.Int.SubjectDN, x509.Subject);
    }
}
