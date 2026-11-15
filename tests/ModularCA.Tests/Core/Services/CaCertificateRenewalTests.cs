using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Journal;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Xunit;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Renewing a CA's certificate over the key it has (<c>docs/architecture/ca-certificate-renewal.md</c>),
/// through the real creation, issuance, CRL and OCSP services over the in-process signer: what
/// the new certificate is, what moves to it, what a relying party that holds either certificate
/// can validate, what the signer refuses, and what the journal records.
/// </summary>
public sealed class CaCertificateRenewalTests
{
    internal sealed class World : IAsyncDisposable
    {
        public JournalSandbox Sandbox { get; } = new();
        public SignerJournal Journal { get; }
        public NameConstraintIssuanceTests.IssuanceWorld W { get; }
        public CrlService Crls { get; }
        public CaCertificateRenewalService Renewal { get; }

        public World()
        {
            Journal = new SignerJournal(() => Sandbox.Options(), new SignerJournalSettings(Sandbox.Home, true, "0.0.0-test", new byte[32]), NullLogger.Instance);
            W = new NameConstraintIssuanceTests.IssuanceWorld(Journal);
            Crls = new CrlService(W.Db, W.World.Keystore, NullLogger<CrlService>.Instance, new RecordingAuditService(),
                InstanceCeremonyEndpointTests.Fake<ICaServiceUrlService>.Create(), InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), W.Signer);
            Renewal = new CaCertificateRenewalService(W.Db, W.Signer, W.World.Keystore,
                InstanceCeremonyEndpointTests.Fake<ICaServiceUrlService>.Create(), Crls, NullLogger<CaCertificateRenewalService>.Instance);
        }

        public X509Certificate Certificate(Guid? id)
        {
            using var db = W.World.OpenDb();
            return new X509Certificate(db.Certificates.Single(c => c.CertificateId == id).RawCertificate);
        }

        public CertificateAuthorityEntity Ca(Guid id)
        {
            using var db = W.World.OpenDb();
            return db.CertificateAuthorities.Single(c => c.Id == id);
        }

        /// <summary>Renews for <paramref name="years"/> with no ceremony, as a scope that waives ceremonies does.</summary>
        public async Task<CaRenewalResult> RenewAsync(CertificateAuthorityEntity ca, int years = 20, Guid? ceremonyId = null)
        {
            var plan = await Renewal.PlanAsync(ca.Id, years, DateTime.UtcNow);
            return await Renewal.RenewAsync(ca.Id, plan.NotAfter, ceremonyId, "tester");
        }

        public async Task<(CertificateEntity Row, X509Certificate Certificate)> LeafAsync(CertificateAuthorityEntity ca, string name)
        {
            var current = Ca(ca.Id);
            var result = await W.IssueLeafAsync(current, $"CN={name}", [$"DNS:{name}.acme.test"]);
            var certificate = CertificateUtil.ParseFromPem(result.Pem);
            var serial = CertificateUtil.FormatSerialNumber(certificate.SerialNumber);
            W.Db.ChangeTracker.Clear();
            return (W.Db.Certificates.Single(c => c.SerialNumber == serial), certificate);
        }

        public List<CertificatePayload> JournalCertificates()
            => Sandbox.Records().Where(r => r.Record.Type == RecordType.Certificate).Select(r => CertificatePayload.Decode(r.Record.Payload)).ToList();

        public CertificatePayload JournalRecordOf(X509Certificate certificate)
            => JournalCertificates().Single(p => new BigInteger(1, p.Serial).Equals(certificate.SerialNumber));

        public async ValueTask DisposeAsync()
        {
            await Journal.DisposeAsync();
            Sandbox.Dispose();
        }
    }

    private static X509Certificate2 Net(X509Certificate certificate) => X509CertificateLoader.LoadCertificate(certificate.GetEncoded());

    private static byte[] Sha(byte[] data) => SHA256.HashData(data);

    private static byte[] Spki(X509Certificate certificate)
        => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(certificate.GetPublicKey()).GetDerEncoded();

    /// <summary>Every extension of <paramref name="a"/> is in <paramref name="b"/> with the same criticality and bytes, and the reverse.</summary>
    private static void AssertSameExtensions(X509Certificate a, X509Certificate b, params DerObjectIdentifier[] except)
    {
        var left = a.CertificateStructure.TbsCertificate.Extensions;
        var right = b.CertificateStructure.TbsCertificate.Extensions;
        var oids = left.GetExtensionOids().Concat(right.GetExtensionOids()).Distinct().Where(o => !except.Contains(o)).ToList();
        Assert.NotEmpty(oids);
        foreach (var oid in oids)
        {
            var was = left.GetExtension(oid);
            var now = right.GetExtension(oid);
            Assert.True(was != null && now != null, $"extension {oid.Id} is in one certificate only");
            Assert.Equal(was!.IsCritical, now!.IsCritical);
            Assert.Equal(was.Value.GetOctets(), now.Value.GetOctets());
        }
    }

    /// <summary>
    /// The product's own validator (mTLS sign-in, EST client certificates): <paramref name="leaf"/>
    /// chains to <paramref name="anchor"/>, the CA certificate a relying party holds, with
    /// <paramref name="above"/> the certificates over that anchor.
    /// </summary>
    private static void AssertChains(X509Certificate leaf, X509Certificate anchor, params X509Certificate[] above)
    {
        var ok = X509ChainValidationUtil.ValidateAgainstAnchor(Net(leaf), Net(anchor), above.Select(Net).ToList(), requireRevocationCheck: false, out var errors);
        Assert.True(ok, $"'{leaf.SubjectDN}' does not chain to '{anchor.SubjectDN}' (serial {anchor.SerialNumber.ToString(16)}): {errors}");
    }

    // ── A root ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_root_gets_a_new_certificate_over_the_same_key_and_everything_of_its_key_moves_to_it()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Renewed Root", "[\"DNS:acme.test\"]", null);
        var before = world.Certificate(root.CertificateId);
        var oldId = root.CertificateId!.Value;

        var result = await world.RenewAsync(root, years: 20);

        var after = result.Certificate;
        Assert.Equal(Spki(before), Spki(after));
        Assert.Equal(before.SubjectDN.GetEncoded(), after.SubjectDN.GetEncoded());
        Assert.Equal(after.SubjectDN.GetEncoded(), after.IssuerDN.GetEncoded());
        Assert.NotEqual(before.SerialNumber, after.SerialNumber);
        Assert.True(after.NotAfter > before.NotAfter);
        Assert.Equal(before.SigAlgOid, after.SigAlgOid);
        after.Verify(before.GetPublicKey());
        AssertSameExtensions(before, after);
        Assert.NotNull(after.GetExtensionValue(X509Extensions.NameConstraints));

        using var db = w.World.OpenDb();
        var ca = db.CertificateAuthorities.Single(c => c.Id == root.Id);
        Assert.Equal(result.Renewed.CertificateId, ca.CertificateId);
        var newRow = db.Certificates.Single(c => c.CertificateId == ca.CertificateId);
        Assert.Equal(newRow.CertificateId, newRow.IssuerCertificateId);       // a root's row links to itself
        Assert.True(newRow.IsCA);
        var oldRow = db.Certificates.Single(c => c.CertificateId == oldId);
        Assert.False(oldRow.Revoked);                                          // renewal revokes nothing
        Assert.NotNull(oldRow.ExpiryWarningDismissedAt);
        Assert.Empty(db.SigningProfiles.Where(p => p.IssuerId == oldId));
        Assert.NotEmpty(db.SigningProfiles.Where(p => p.IssuerId == ca.CertificateId));
        Assert.Empty(db.CrlConfigurations.Where(c => c.CaCertificateId == oldId));
        Assert.NotEmpty(db.CrlConfigurations.Where(c => c.CaCertificateId == ca.CertificateId));

        var history = db.CaCertificates.Where(h => h.CertificateAuthorityId == root.Id).OrderBy(h => h.ActivatedAt).ToList();
        Assert.Equal(new[] { oldId, ca.CertificateId!.Value }, history.Select(h => h.CertificateId).ToArray());
        Assert.Equal(new[] { CaCertificateEntity.OriginInitial, CaCertificateEntity.OriginRenewal }, history.Select(h => h.Origin).ToArray());
        Assert.NotNull(history[0].SupersededAt);
        Assert.Null(history[1].SupersededAt);
        Assert.Equal("tester", history[1].Actor);
        Assert.Equal(Convert.ToHexStringLower(Sha(Spki(after))), history[1].KeyId);
        Assert.Equal(history[0].KeyId, history[1].KeyId);

        // The earlier certificate is still the CA's, and still in its revocation scope.
        Assert.Equal(root.Id, IssuerChainResolver.OwnerOf(db, oldId)?.CaId);
        Assert.Equal(new[] { oldId, ca.CertificateId.Value }.OrderBy(x => x),
            (await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, ca.CertificateId.Value, after)).OrderBy(x => x));
        Assert.Equal(ca.CertificateId.Value, await IssuerChainResolver.CurrentSameKeyCertificateIdAsync(db, oldId));

        // The signer serves the key under the new certificate, and no longer as a CA key under the old.
        var keys = await w.Signer.ListKeysAsync(SigningContext.ForCa("test", SigningPurpose.Certificate, root.Id, root.SpaceId));
        Assert.Contains(keys, k => k.Kind == KeyKind.Ca && k.Key.CertificateId == ca.CertificateId);
        Assert.DoesNotContain(keys, k => k.Key.CertificateId == oldId);
    }

    [Fact]
    public async Task Leaves_issued_before_and_after_validate_under_either_root_certificate_and_share_one_crl_and_ocsp()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Two Certificates Root", null, null);
        var oldRoot = world.Certificate(root.CertificateId);
        var oldId = root.CertificateId!.Value;
        var (oldLeafRow, oldLeaf) = await world.LeafAsync(root, "before");
        var (oldRevokedRow, oldRevoked) = await world.LeafAsync(root, "before-revoked");

        var renewed = await world.RenewAsync(root);
        var newRoot = renewed.Certificate;
        var newId = renewed.Renewed.CertificateId;
        var (newLeafRow, newLeaf) = await world.LeafAsync(root, "after");
        var (newRevokedRow, newRevoked) = await world.LeafAsync(root, "after-revoked");

        // Issuer links: each leaf names the certificate that was current when it was issued.
        Assert.Equal(oldId, oldLeafRow.IssuerCertificateId);
        Assert.Equal(newId, newLeafRow.IssuerCertificateId);
        Assert.True(newLeaf.NotAfter <= newRoot.NotAfter);

        // Chain: an old leaf under the new root certificate, a new leaf under the old one, and the plain cases.
        AssertChains(oldLeaf, newRoot);
        AssertChains(newLeaf, oldRoot);
        AssertChains(oldLeaf, oldRoot);
        AssertChains(newLeaf, newRoot);
        oldLeaf.Verify(newRoot.GetPublicKey());
        newLeaf.Verify(oldRoot.GetPublicKey());

        // Revocation. (The CRL itself needs PostgreSQL: PostgresCaCertificateRenewalTests.)
        foreach (var row in new[] { oldRevokedRow, newRevokedRow })
        {
            var tracked = w.Db.Certificates.Single(c => c.CertificateId == row.CertificateId);
            tracked.Revoked = true;
            tracked.RevocationReason = "KeyCompromise";
            tracked.RevocationDate = DateTime.UtcNow;
        }
        w.Db.SaveChanges();
        // OCSP: the same answers whether the request was built from the old or the new CA certificate.
        using var db = w.World.OpenDb();
        var responder = new OcspResponderService(db, w.World.Keystore, NullLogger<OcspResponderService>.Instance,
            new StubSecurityPolicyService(new SecurityPolicyEntity()), w.Signer);
        foreach (var issuer in new[] { oldRoot, newRoot })
        {
            foreach (var (leaf, revoked) in new[] { (oldLeaf, false), (newLeaf, false), (oldRevoked, true), (newRevoked, true) })
            {
                var requests = new OcspReqGenerator();
#pragma warning disable CS0618 // The responder uses the same overload.
                requests.AddRequest(new CertificateID(CertificateID.HashSha1, issuer, leaf.SerialNumber));
#pragma warning restore CS0618
                var response = new OcspResp(await responder.ProcessOcspRequestAsync(requests.Generate().GetEncoded(), root.Label, new OcspProcessingResult()));
                Assert.Equal(OcspRespStatus.Successful, response.Status);
                var basic = (BasicOcspResp)response.GetResponseObject();
                var status = Assert.Single(basic.Responses).GetCertStatus();
                Assert.True(revoked ? status is RevokedStatus : status == null, $"{leaf.SubjectDN} asked under serial {issuer.SerialNumber.ToString(16)}: {status}");
                // The delegated responder was issued under the old certificate and still signs: it chains to either.
                var responderCert = world.Certificate(world.Ca(root.Id).OcspResponderCertificateId);
                Assert.True(basic.Verify(responderCert.GetPublicKey()));
                responderCert.Verify(newRoot.GetPublicKey());
            }
        }
    }

    // ── An intermediate, and children ───────────────────────────────────────────────────────

    [Fact]
    public async Task An_intermediate_is_renewed_by_its_parent_and_its_children_and_leaves_keep_validating()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Parent Root", null, null);
        var rootCert = world.Certificate(root.CertificateId);
        var issuing = await w.CreateIntermediateAsync(root, "Issuing", null, null);
        var before = world.Certificate(issuing.CertificateId);
        var (_, oldLeaf) = await world.LeafAsync(issuing, "under-old");

        // The parent's certificate ends in five years and the intermediate's in two: three more are possible.
        var result = await world.RenewAsync(issuing, years: 4);
        var after = result.Certificate;
        var (_, newLeaf) = await world.LeafAsync(issuing, "under-new");

        Assert.Equal(Spki(before), Spki(after));
        Assert.Equal(before.SubjectDN.GetEncoded(), after.SubjectDN.GetEncoded());
        Assert.Equal(rootCert.SubjectDN.GetEncoded(), after.IssuerDN.GetEncoded());
        after.Verify(rootCert.GetPublicKey());
        Assert.Equal(0, after.GetBasicConstraints());
        Assert.True(after.NotAfter > before.NotAfter && after.NotAfter <= rootCert.NotAfter);
        AssertSameExtensions(before, after);
        Assert.Equal(root.CertificateId, result.Renewed.IssuerCertificateId);

        AssertChains(oldLeaf, after, rootCert);      // an old leaf, the new intermediate certificate
        AssertChains(newLeaf, before, rootCert);     // a new leaf, the old intermediate certificate
        AssertChains(oldLeaf, before, rootCert);
        AssertChains(newLeaf, after, rootCert);
        AssertChains(after, rootCert);
    }

    [Fact]
    public async Task Renewing_a_parent_renews_no_child_and_the_child_validates_under_either_parent_certificate()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Renewed Parent", null, null);
        var oldRoot = world.Certificate(root.CertificateId);
        var child = await w.CreateIntermediateAsync(root, "Untouched Child", null, null);
        var childCert = world.Certificate(child.CertificateId);
        var (_, leaf) = await world.LeafAsync(child, "grandchild");

        var newRoot = (await world.RenewAsync(root)).Certificate;

        var childAfter = world.Ca(child.Id);
        Assert.Equal(child.CertificateId, childAfter.CertificateId);
        Assert.Equal(root.Id, childAfter.ParentCaId);
        AssertChains(childCert, newRoot);
        AssertChains(childCert, oldRoot);
        AssertChains(leaf, childCert, newRoot);
        AssertChains(leaf, childCert, oldRoot);

        // The child still issues, and can itself be renewed under the parent's new certificate.
        var (_, later) = await world.LeafAsync(child, "later");
        AssertChains(later, childCert, newRoot);
        var renewedChild = (await world.RenewAsync(child, years: 10)).Certificate;
        renewedChild.Verify(newRoot.GetPublicKey());
        Assert.True(renewedChild.NotAfter > oldRoot.NotAfter, "the child's certificate can now outlast the parent's earlier certificate");
        AssertChains(leaf, renewedChild, newRoot);
    }

    // ── What is refused before anything is signed ───────────────────────────────────────────

    [Fact]
    public async Task An_intermediate_cannot_be_renewed_past_its_parents_certificate()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Short Root", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Clamped", null, null);
        var rootCert = world.Certificate(root.CertificateId);

        var plan = await world.Renewal.PlanAsync(issuing.Id, 30, DateTime.UtcNow);
        Assert.True(plan.ShortenedToParent);
        Assert.Equal(rootCert.NotAfter.ToUniversalTime(), plan.NotAfter);

        // Asked outright for an end past the parent's, the service refuses rather than shorten what was approved.
        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.RenewAsync(issuing.Id, rootCert.NotAfter.ToUniversalTime().AddDays(1), null, "tester"));
        Assert.Contains("Renew the parent first", refused.Message);
        Assert.Equal(issuing.CertificateId, world.Ca(issuing.Id).CertificateId);
    }

    /// <summary>
    /// A refusal names the parent CA only to a reader whose space fence admits it. Said nothing of
    /// the reader, or told the reader may not see the parent's space, it says "parent CA".
    /// </summary>
    [Fact]
    public async Task A_renewal_refusal_names_the_parent_only_to_a_reader_who_may_see_it()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Hidden Anchor", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Fenced Issuing", null, null);
        var pastParent = world.Certificate(root.CertificateId).NotAfter.ToUniversalTime().AddDays(1);

        var byDefault = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.RenewAsync(issuing.Id, pastParent, null, "tester"));
        var fenced = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.RenewAsync(issuing.Id, pastParent, null, "tester", default, _ => false));
        var open = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.RenewAsync(issuing.Id, pastParent, null, "tester", default, _ => true));

        foreach (var refusal in new[] { byDefault, fenced })
        {
            Assert.DoesNotContain("Hidden Anchor", refusal.Message);
            Assert.Contains("after the certificate of its parent CA (", refusal.Message);
        }
        Assert.Contains("its parent CA 'Hidden Anchor' (", open.Message);

        // The parent disabled: the same rule.
        using (var db = w.World.OpenDb())
        {
            db.CertificateAuthorities.Single(c => c.Id == root.Id).IsEnabled = false;
            db.SaveChanges();
        }
        w.Db.ChangeTracker.Clear();
        var disabledFenced = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.PlanAsync(issuing.Id, 2, DateTime.UtcNow, default, _ => false));
        var disabledOpen = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => world.Renewal.PlanAsync(issuing.Id, 2, DateTime.UtcNow, default, _ => true));
        Assert.Equal("The parent CA is disabled and cannot sign a renewed certificate.", disabledFenced.Message);
        Assert.Equal("The parent CA 'Hidden Anchor' is disabled and cannot sign a renewed certificate.", disabledOpen.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(51)]
    public async Task A_validity_outside_one_to_fifty_years_is_refused(int years)
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Bounded Root", null, null);

        await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.Renewal.PlanAsync(root.Id, years, DateTime.UtcNow));
    }

    [Fact]
    public async Task A_renewal_that_would_not_end_later_a_revoked_ca_and_an_unknown_ca_are_refused()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Five Year Root", null, null);

        var shorter = await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.Renewal.PlanAsync(root.Id, 1, DateTime.UtcNow));
        Assert.Contains("not after the current one", shorter.Message);

        w.Db.Certificates.Single(c => c.CertificateId == root.CertificateId).Revoked = true;
        w.Db.SaveChanges();
        var revoked = await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.Renewal.PlanAsync(root.Id, 20, DateTime.UtcNow));
        Assert.Contains("revoked", revoked.Message);

        await Assert.ThrowsAsync<ResourceNotFoundException>(() => world.Renewal.PlanAsync(Guid.NewGuid(), 20, DateTime.UtcNow));
    }

    // ── What the signer refuses ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Offers the signer a certificate under the renewal purpose: the current certificate of
    /// <paramref name="subjectCa"/> with a new serial and validity, changed by <paramref name="change"/>,
    /// to be signed with the key of <paramref name="signingCa"/>.
    /// </summary>
    private static Task<byte[]> OfferAsync(World world, CertificateAuthorityEntity signingCa, CertificateAuthorityEntity subjectCa,
        Action<Draft>? change = null, Guid? ceremonyId = null, SigningPurpose purpose = SigningPurpose.CaCertificateRenewal)
    {
        var signing = world.Certificate(world.Ca(signingCa.Id).CertificateId);
        var current = world.Certificate(world.Ca(subjectCa.Id).CertificateId);
        var draft = new Draft
        {
            Subject = current.SubjectDN,
            PublicKey = current.GetPublicKey(),
            NotBefore = DateTime.UtcNow.AddMinutes(-5),
            NotAfter = signingCa.Id == subjectCa.Id ? DateTime.UtcNow.AddYears(20) : signing.NotAfter.AddDays(-1),
        };
        var extensions = current.CertificateStructure.TbsCertificate.Extensions;
        foreach (var oid in extensions.GetExtensionOids())
            draft.Extensions[oid] = (extensions.GetExtension(oid).IsCritical, extensions.GetExtension(oid).Value.GetOctets());
        change?.Invoke(draft);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
        generator.SetIssuerDN(signing.SubjectDN);
        generator.SetSubjectDN(draft.Subject);
        generator.SetNotBefore(draft.NotBefore);
        generator.SetNotAfter(draft.NotAfter);
        generator.SetPublicKey(draft.PublicKey);
        foreach (var (oid, extension) in draft.Extensions)
            generator.AddExtension(oid, extension.Critical, Asn1Object.FromByteArray(extension.Value));

        // The to-be-signed bytes, taken from a certificate signed with a throwaway key of the same kind.
        var algorithmName = KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(signing.GetPublicKey());
        var throwaway = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var tbs = generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(algorithmName, throwaway.Private)).GetTbsCertificate();
        var context = SigningContext.ForCa("renewal-test", purpose, signingCa.Id, signingCa.SpaceId) with { CeremonyId = ceremonyId };
        return world.W.Signer.SignAsync(new KeyRef(world.Ca(signingCa.Id).CertificateId!.Value), SignatureAlgorithm.FromName(algorithmName), tbs, context);
    }

    private sealed class Draft
    {
        public X509Name Subject = null!;
        public Org.BouncyCastle.Crypto.AsymmetricKeyParameter PublicKey = null!;
        public DateTime NotBefore;
        public DateTime NotAfter;
        public Dictionary<DerObjectIdentifier, (bool Critical, byte[] Value)> Extensions = [];
    }

    [Fact]
    public async Task The_signer_signs_a_faithful_renewal_of_a_root_and_of_an_intermediate()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Faithful Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Faithful Issuing", null, null);

        Assert.NotEmpty(await OfferAsync(world, root, root));
        Assert.NotEmpty(await OfferAsync(world, root, issuing));
    }

    [Fact]
    public async Task The_signer_refuses_a_renewal_over_another_key()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Key Root", null, null);
        var outside = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");

        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root, d => d.PublicKey = outside.Public));

        Assert.Equal(SigningRefusalReason.EvidenceRequired, refused.Reason);
        Assert.Contains("key of no CA's current certificate", refused.Message);
    }

    [Fact]
    public async Task The_signer_refuses_a_renewal_under_another_subject()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Subject Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Subject Issuing", null, null);

        var refused = await Assert.ThrowsAsync<SigningRefusedException>(
            () => OfferAsync(world, root, issuing, d => d.Subject = new X509Name("CN=Another Name,O=Acme,C=US")));

        Assert.Equal(SigningRefusalReason.EvidenceRequired, refused.Reason);
        Assert.Contains("keeps the CA's subject", refused.Message);
    }

    [Fact]
    public async Task The_signer_refuses_a_widened_or_dropped_path_length()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Path Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Path Issuing", null, null);

        foreach (var widened in new[] { new BasicConstraints(1), new BasicConstraints(true) })
        {
            var refused = await Assert.ThrowsAsync<SigningRefusedException>(
                () => OfferAsync(world, root, issuing, d => d.Extensions[X509Extensions.BasicConstraints] = (true, widened.GetDerEncoded())));

            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, refused.Reason);
            Assert.Contains("does not widen the path length", refused.Message);
        }
    }

    [Fact]
    public async Task The_signer_refuses_a_validity_beyond_the_parents()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Validity Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Validity Issuing", null, null);
        var rootEnd = world.Certificate(root.CertificateId).NotAfter;

        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, issuing, d => d.NotAfter = rootEnd.AddSeconds(1)));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, refused.Reason);
        Assert.Contains("outside its parent's validity", refused.Message);

        Assert.NotEmpty(await OfferAsync(world, root, issuing, d => d.NotAfter = rootEnd));     // exactly the parent's end is within it
        var past = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root, d => d.NotAfter = DateTime.UtcNow.AddDays(-1)));
        Assert.Contains("no validity", past.Message);
        var future = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root, d => d.NotBefore = DateTime.UtcNow.AddDays(2)));
        Assert.Contains("a renewal starts now", future.Message);
    }

    [Fact]
    public async Task The_signer_refuses_a_changed_added_or_dropped_extension()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Extension Root", "[\"DNS:acme.test\"]", null);

        var changed = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root,
            d => d.Extensions[X509Extensions.KeyUsage] = (true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment).GetDerEncoded())));
        Assert.Contains("differs", changed.Message);

        var dropped = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root, d => d.Extensions.Remove(X509Extensions.NameConstraints)));
        Assert.Contains("is missing", dropped.Message);

        var added = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, root,
            d => d.Extensions[X509Extensions.CertificatePolicies] = (false, new DerSequence(new PolicyInformation(new DerObjectIdentifier("2.5.29.32.0"))).GetDerEncoded())));
        Assert.Contains("adds no extension", added.Message);
        Assert.All(new[] { changed, dropped, added }, r => Assert.Equal(SigningRefusalReason.PurposeNotPermitted, r.Reason));
    }

    [Fact]
    public async Task The_signer_holds_a_renewal_to_the_hierarchy()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Hierarchy Root", null, null);
        var other = await world.W.CreateRootAsync("Other Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Hierarchy Issuing", null, null);

        // Another root's key does not renew this intermediate, and an intermediate does not renew itself.
        var stranger = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, other, issuing));
        Assert.Equal(SigningRefusalReason.CaMismatch, stranger.Reason);
        var self = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, issuing, issuing));
        Assert.Equal(SigningRefusalReason.CaMismatch, self.Reason);
        var rootByChild = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, issuing, root));
        Assert.True(rootByChild.Reason is SigningRefusalReason.CaMismatch or SigningRefusalReason.IssuerMismatch);
    }

    [Fact]
    public async Task The_ordinary_certificate_purpose_still_signs_no_ca_certificate_for_a_committed_key()
    {
        await using var world = new World();
        var root = await world.W.CreateRootAsync("Ordinary Root", null, null);
        var issuing = await world.W.CreateIntermediateAsync(root, "Ordinary Issuing", null, null);

        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => OfferAsync(world, root, issuing, purpose: SigningPurpose.Certificate));

        Assert.Equal(SigningRefusalReason.EvidenceRequired, refused.Reason);
    }

    // ── Ceremonies ──────────────────────────────────────────────────────────────────────────

    private static Guid StrictSpace(World world)
    {
        var id = Guid.NewGuid();
        world.W.Db.Spaces.Add(new SpaceEntity { Id = id, Name = "strict", Slug = "strict", RequireKeyCeremony = true });
        world.W.Db.SaveChanges();
        return id;
    }

    private static Guid Ceremony(World world, string operation, Guid spaceId, Guid? caId = null, Guid? currentCertificateId = null, DateTime? notAfter = null, string status = "Approved")
    {
        var id = Guid.NewGuid();
        world.W.Db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            Id = id, OperationType = operation, Description = "renewal test", Status = status, SpaceId = spaceId,
            TargetEntityId = caId?.ToString() ?? string.Empty,
            RequiredApprovals = 1, CurrentApprovals = 1, ExpiresAt = DateTime.UtcNow.AddHours(1),
            ParametersJson = caId == null ? "{}" : System.Text.Json.JsonSerializer.Serialize(new RenewCaCertificateCeremonyParameters
            {
                CaId = caId.Value, CaName = "x", CurrentCertificateId = currentCertificateId ?? Guid.Empty, NotAfter = notAfter ?? default, SpaceId = spaceId,
            }, SafeJsonOptions.Stored),
        });
        world.W.Db.SaveChanges();
        return id;
    }

    [Fact]
    public async Task Where_the_scope_requires_a_ceremony_the_signer_renews_only_under_an_approved_one_for_that_ca_and_expiry()
    {
        await using var world = new World();
        var w = world.W;
        var strict = StrictSpace(world);
        var root = await w.Creation.CreateRootAsync("Strict Root", "Acme", null, null, null, "US", "ECDSA", 256, 5, null, strict,
            ceremonyId: Ceremony(world, "CreateRootCA", strict));
        var other = await w.Creation.CreateRootAsync("Strict Other", "Acme", null, null, null, "US", "ECDSA", 256, 5, null, strict,
            ceremonyId: Ceremony(world, "CreateRootCA", strict));
        var plan = await world.Renewal.PlanAsync(root.Id, 20, DateTime.UtcNow);

        async Task<SigningRefusedException> RefusedAsync(Guid? ceremonyId)
        {
            var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => world.Renewal.RenewAsync(root.Id, plan.NotAfter, ceremonyId, "tester"));
            Assert.Equal(root.CertificateId, world.Ca(root.Id).CertificateId);
            return refused;
        }

        Assert.Equal(SigningRefusalReason.CeremonyRequired, (await RefusedAsync(null)).Reason);
        Assert.Equal(SigningRefusalReason.CeremonyNotApproved, (await RefusedAsync(Guid.NewGuid())).Reason);
        // A ceremony of another kind, one still pending, one for another CA, one that approved another expiry.
        Assert.Contains("RenewCaCertificate", (await RefusedAsync(Ceremony(world, "CreateRootCA", strict))).Message);
        Assert.Contains("Pending", (await RefusedAsync(Ceremony(world, "RenewCaCertificate", strict, root.Id, root.CertificateId, plan.NotAfter, "Pending"))).Message);
        Assert.Contains("does not target", (await RefusedAsync(Ceremony(world, "RenewCaCertificate", strict, other.Id, other.CertificateId, plan.NotAfter))).Message);
        Assert.Contains("approved a certificate valid until", (await RefusedAsync(Ceremony(world, "RenewCaCertificate", strict, root.Id, root.CertificateId, plan.NotAfter.AddDays(1)))).Message);

        var approved = Ceremony(world, "RenewCaCertificate", strict, root.Id, root.CertificateId, plan.NotAfter);
        var result = await world.Renewal.RenewAsync(root.Id, plan.NotAfter, approved, "tester");
        Assert.Equal(result.Renewed.CertificateId, world.Ca(root.Id).CertificateId);
        using (var db = w.World.OpenDb())
            Assert.Equal(approved, db.CaCertificates.Single(h => h.CertificateId == result.Renewed.CertificateId).CeremonyId);

        // The same approval does not renew the CA a second time: it named the certificate it replaced.
        var again = await world.Renewal.PlanAsync(root.Id, 30, DateTime.UtcNow);
        var second = await Assert.ThrowsAsync<SigningRefusedException>(() => world.Renewal.RenewAsync(root.Id, again.NotAfter, approved, "tester"));
        Assert.Equal(SigningRefusalReason.CeremonyNotApproved, second.Reason);
    }

    // ── The journal ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_journal_names_the_old_certificate_before_the_renewal_and_the_new_one_after_under_the_same_key()
    {
        await using var world = new World();
        var w = world.W;
        var root = await w.CreateRootAsync("Journal Renewed Root", null, null);
        var oldRoot = world.Certificate(root.CertificateId);
        var (_, before) = await world.LeafAsync(root, "journal-before");

        var newRoot = (await world.RenewAsync(root)).Certificate;
        var (_, after) = await world.LeafAsync(root, "journal-after");

        var caKey = Sha(Spki(oldRoot));
        var beforeRecord = world.JournalRecordOf(before);
        var renewalRecord = world.JournalRecordOf(newRoot);
        var afterRecord = world.JournalRecordOf(after);

        Assert.Equal(Sha(oldRoot.GetEncoded()), beforeRecord.CaCert);
        Assert.Equal(Sha(newRoot.GetEncoded()), afterRecord.CaCert);
        Assert.Equal(caKey, beforeRecord.CaKey);
        Assert.Equal(caKey, afterRecord.CaKey);
        Assert.Equal(root.Id.ToString("D"), beforeRecord.Ca);
        Assert.Equal(root.Id.ToString("D"), afterRecord.Ca);

        // The renewal itself is a Certificate record like any other: a CA certificate, signed while
        // the old certificate was current, that rebuilds byte for byte and says what it replaces.
        Assert.True(renewalRecord.IsCa);
        Assert.Equal(Sha(oldRoot.GetEncoded()), renewalRecord.CaCert);
        Assert.Equal(caKey, renewalRecord.CaKey);
        Assert.Equal(caKey, renewalRecord.SubjectKey);
        var tbs = TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(renewalRecord.Tbs));
        Assert.Equal(newRoot.GetEncoded(), new DerSequence(tbs, tbs.Signature, new DerBitString(renewalRecord.Signature)).GetDerEncoded());
        Assert.NotNull(renewalRecord.Replaces);
    }
}
