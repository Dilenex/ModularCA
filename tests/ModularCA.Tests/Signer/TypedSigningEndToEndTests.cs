using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cmp;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// Typed signing under the real flows: CA creation and issuance run as the node runs them, over
/// the in-process signer, and everything they ask it to sign has to pass the typing. A root and
/// an intermediate are created where the space waives ceremonies and where it requires them;
/// each CA issues its own responder and TSA certificates, a leaf, CRLs as the CRL service builds
/// them, an OCSP response through the responder service, and a CMP protection signature as the
/// CMP service builds it.
/// </summary>
public sealed class TypedSigningEndToEndTests
{
    private const string OcspSigning = "1.3.6.1.5.5.7.3.9";
    private const string TimeStamping = "1.3.6.1.5.5.7.3.8";

    /// <summary>
    /// The issuance world with the infrastructure profiles carrying their EKUs, as bootstrap
    /// seeds them, so the responder certificate a CA issues itself is an OCSP-signing certificate.
    /// </summary>
    private static NameConstraintIssuanceTests.IssuanceWorld NewWorld()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var ocsp = w.Db.CertProfiles.Single(p => p.Name == "OCSP Responder Certificate Profile");
        ocsp.KeyUsages = "[\"Digital Signature\"]";
        ocsp.ExtendedKeyUsages = $"[\"{OcspSigning}\"]";
        var tsa = w.Db.CertProfiles.Single(p => p.Name == "TSA Certificate Profile");
        tsa.KeyUsages = "[\"Digital Signature\"]";
        tsa.ExtendedKeyUsages = $"[\"{TimeStamping}\"]";
        w.Db.OIDOptions.AddRange(
            new OIDOptionEntity { OID = OcspSigning, FriendlyName = "OCSPSigning", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = TimeStamping, FriendlyName = "timeStamping", KeyUsage = "Extended" },
            new OIDOptionEntity { OID = "2.5.29.15.0", FriendlyName = "digitalSignature", KeyUsage = "Standard" });
        w.Db.SaveChanges();
        return w;
    }

    private static Guid SeedStrictSpace(NameConstraintIssuanceTests.IssuanceWorld w)
    {
        var id = Guid.NewGuid();
        w.Db.Spaces.Add(new SpaceEntity { Id = id, Name = "strict-space", Slug = "strict-space", RequireKeyCeremony = true });
        w.Db.SaveChanges();
        return id;
    }

    private static Guid SeedApprovedCeremony(NameConstraintIssuanceTests.IssuanceWorld w, string operation, Guid spaceId)
    {
        var id = Guid.NewGuid();
        w.Db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            Id = id, OperationType = operation, Description = "typed signing end to end", Status = "Approved", SpaceId = spaceId,
            RequiredApprovals = 1, CurrentApprovals = 1, ExpiresAt = DateTime.UtcNow.AddHours(1),
        });
        w.Db.SaveChanges();
        return id;
    }

    private static X509Certificate Certificate(NameConstraintIssuanceTests.IssuanceWorld w, Guid? certificateId)
    {
        using var db = w.World.OpenDb();
        return CertificateUtil.ParseFromPem(db.Certificates.Single(c => c.CertificateId == certificateId).Pem);
    }

    private static Task<CertificateAuthorityEntity> RootAsync(NameConstraintIssuanceTests.IssuanceWorld w, string name, Guid spaceId, Guid? ceremonyId)
        => w.Creation.CreateRootAsync(name, "Acme", null, null, null, "US", "ECDSA", 256, 5, null, spaceId, ceremonyId: ceremonyId);

    private static Task<CertificateAuthorityEntity> IntermediateAsync(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity parent, string name, Guid spaceId, Guid? ceremonyId)
        => w.Creation.CreateIntermediateAsync(parent, w.Db.Certificates.Single(c => c.CertificateId == parent.CertificateId),
            name, "Acme", null, null, null, "US", "ECDSA", 256, 2, null, spaceId, ceremonyId: ceremonyId);

    /// <summary>
    /// What a created CA must be: a CA certificate its parent (or itself) signed, a responder
    /// certificate carrying the OCSP-signing EKU and a TSA certificate, both signed by the CA
    /// while its key was still pending, and all three keys committed under their kinds.
    /// </summary>
    private static async Task<X509Certificate> AssertCreatedAsync(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity ca, X509Certificate? parent)
    {
        var cert = Certificate(w, ca.CertificateId);
        Assert.True(cert.GetBasicConstraints() >= 0, "the CA certificate asserts cA=TRUE");
        cert.Verify((parent ?? cert).GetPublicKey());
        Assert.True(cert.IssuerDN.Equivalent((parent ?? cert).SubjectDN, true));
        if (parent != null)
            Assert.Equal(0, cert.GetBasicConstraints());

        var responder = Certificate(w, ca.OcspResponderCertificateId);
        responder.Verify(cert.GetPublicKey());
        Assert.Equal(-1, responder.GetBasicConstraints());
        Assert.Contains(OcspSigning, responder.GetExtendedKeyUsage().Select(o => o.Id));
        var tsa = Certificate(w, ca.TsaCertificateId);
        tsa.Verify(cert.GetPublicKey());
        Assert.Contains(TimeStamping, tsa.GetExtendedKeyUsage().Select(o => o.Id));

        var keys = await w.Signer.ListKeysAsync(SigningContext.ForCa("e2e", SigningPurpose.Ocsp, ca.Id, ca.SpaceId));
        Assert.Equal(new[] { KeyKind.Ca, KeyKind.OcspResponder, KeyKind.Tsa }, keys.Select(k => k.Kind).OrderBy(k => k).ToArray());
        return cert;
    }

    /// <summary>A full or delta CRL built with the calls the CRL service makes, signed through the signer under the CRL purpose.</summary>
    private static X509Crl SignCrl(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity ca, X509Certificate caCert, BigInteger revokedSerial, bool delta)
    {
        var now = DateTime.UtcNow;
        var gen = new X509V2CrlGenerator();
        gen.SetIssuerDN(caCert.SubjectDN);
        gen.SetThisUpdate(now);
        gen.SetNextUpdate(now.AddHours(6));
        gen.AddCrlEntry(revokedSerial, now, CrlReason.KeyCompromise);
        gen.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(delta ? 2 : 1)));
        gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey())));
        if (delta)
            gen.AddExtension(X509Extensions.DeltaCrlIndicator, true, new DerInteger(BigInteger.One));
        var algorithm = SignatureAlgorithm.FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey()));
        var crl = gen.Generate(new SigningServiceSignatureFactory(w.Signer, new KeyRef(ca.CertificateId!.Value), algorithm,
            SigningContext.ForCa("e2e-crl", SigningPurpose.Crl, ca.Id, ca.SpaceId)));
        crl.Verify(caCert.GetPublicKey());
        return crl;
    }

    /// <summary>Everything a committed CA signs after creation: a leaf, CRLs, an OCSP answer about the leaf, a CMP response.</summary>
    private static async Task AssertServesAsync(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity ca, X509Certificate caCert)
    {
        var leaf = CertificateUtil.ParseFromPem((await w.IssueLeafAsync(ca, $"CN=leaf of {ca.Name}", ["DNS:leaf.acme.test"])).Pem);
        leaf.Verify(caCert.GetPublicKey());
        Assert.Equal(-1, leaf.GetBasicConstraints());

        Assert.NotNull(SignCrl(w, ca, caCert, leaf.SerialNumber, delta: false).GetRevokedCertificate(leaf.SerialNumber));
        Assert.NotNull(SignCrl(w, ca, caCert, leaf.SerialNumber, delta: true).GetExtensionValue(X509Extensions.DeltaCrlIndicator));

        using (var db = w.World.OpenDb())
        {
            var responder = new OcspResponderService(db, w.World.Keystore, NullLogger<OcspResponderService>.Instance,
                new StubSecurityPolicyService(new SecurityPolicyEntity()), w.Signer);
            var requests = new OcspReqGenerator();
#pragma warning disable CS0618 // The responder uses the same overload.
            requests.AddRequest(new CertificateID(CertificateID.HashSha1, caCert, leaf.SerialNumber));
#pragma warning restore CS0618
            var response = new OcspResp(await responder.ProcessOcspRequestAsync(requests.Generate().GetEncoded(), ca.Label, new OcspProcessingResult()));
            Assert.Equal(OcspRespStatus.Successful, response.Status);
            var basic = (BasicOcspResp)response.GetResponseObject();
            Assert.True(basic.Verify(Certificate(w, ca.OcspResponderCertificateId).GetPublicKey()), "the delegated responder signed the response");
            Assert.Null(Assert.Single(basic.Responses).GetCertStatus());
        }

        var cmp = new ProtectedPkiMessageBuilder(new GeneralName(caCert.SubjectDN), new GeneralName(new X509Name("CN=cmp client")));
        cmp.SetBody(new PkiBody(PkiBody.TYPE_CONFIRM, DerNull.Instance));
        cmp.SetTransactionId(new byte[16]);
        cmp.SetSenderNonce(new byte[16]);
        cmp.SetMessageTime(DateTime.UtcNow);
        cmp.AddCmpCertificate(caCert);
        var cmpAlgorithm = SignatureAlgorithm.FromName(CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey())));
        var message = cmp.Build(new SigningServiceSignatureFactory(w.Signer, new KeyRef(ca.CertificateId!.Value), cmpAlgorithm,
            SigningContext.ForCa("e2e-cmp", SigningPurpose.Cmp, ca.Id, ca.SpaceId)));
        Assert.True(message.Verify(new Asn1VerifierFactoryProvider(caCert.GetPublicKey())), "the CMP protection verifies under the CA certificate");
    }

    [Fact]
    public async Task A_root_and_an_intermediate_are_created_and_serve_where_the_space_waives_ceremonies()
    {
        var w = NewWorld();

        var root = await RootAsync(w, "Waived Root", w.SpaceId, ceremonyId: null);
        var rootCert = await AssertCreatedAsync(w, root, parent: null);
        var intermediate = await IntermediateAsync(w, root, "Waived Sub", w.SpaceId, ceremonyId: null);
        var intermediateCert = await AssertCreatedAsync(w, intermediate, rootCert);

        await AssertServesAsync(w, root, rootCert);
        await AssertServesAsync(w, intermediate, intermediateCert);

        // Reissue: the committed CA key signs new responder, TSA and CMP signer certificates for
        // keys the signer generated under the CA's infrastructure context, and they serve.
        var firstResponder = root.OcspResponderCertificateId;
        await w.Creation.ReissueInfrastructureCertsAsync(root.Id, reissueOcsp: true, reissueTsa: true, reissueCmpSigner: true);
        Assert.NotEqual(firstResponder, root.OcspResponderCertificateId);
        Assert.Contains(OcspSigning, Certificate(w, root.OcspResponderCertificateId).GetExtendedKeyUsage().Select(o => o.Id));
        await AssertServesAsync(w, root, rootCert);
        var cmpSigner = Certificate(w, root.CmpSigningCertificateId);
        cmpSigner.Verify(rootCert.GetPublicKey());
        var delegated = new ProtectedPkiMessageBuilder(new GeneralName(cmpSigner.SubjectDN), new GeneralName(new X509Name("CN=cmp client")));
        delegated.SetBody(new PkiBody(PkiBody.TYPE_CONFIRM, DerNull.Instance));
        var delegatedAlgorithm = SignatureAlgorithm.FromName(CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(cmpSigner.GetPublicKey())));
        Assert.True(delegated.Build(new SigningServiceSignatureFactory(w.Signer, new KeyRef(root.CmpSigningCertificateId!.Value), delegatedAlgorithm,
            SigningContext.ForCa("e2e-cmp", SigningPurpose.Cmp, root.Id, root.SpaceId))).Verify(new Asn1VerifierFactoryProvider(cmpSigner.GetPublicKey())));

        // An intermediate cannot certify a further CA: its path length is zero, and the signer holds it to that.
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => IntermediateAsync(w, intermediate, "Too Deep", w.SpaceId, ceremonyId: null));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);

        // Nothing the real flows asked for was refused, apart from that one certificate.
        using var audit = w.World.OpenDb();
        var refusedRow = Assert.Single(audit.SignerAudit.Where(r => r.Outcome == SignerAuditEntity.RefusedOutcome).ToList());
        Assert.Equal("Sign", refusedRow.Operation);
        Assert.Equal(nameof(SigningPurpose.Certificate), refusedRow.Purpose);
        Assert.Equal(intermediate.Id, refusedRow.CaId);
    }

    [Fact]
    public async Task A_root_and_an_intermediate_are_created_and_serve_under_approved_ceremonies()
    {
        var w = NewWorld();
        var strict = SeedStrictSpace(w);

        // With no ceremony the signer generates no key for the space, so there is nothing to certify.
        var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => RootAsync(w, "Unapproved Root", strict, ceremonyId: null));
        Assert.Equal(SigningRefusalReason.CeremonyRequired, refused.Reason);

        var root = await RootAsync(w, "Ceremony Root", strict, SeedApprovedCeremony(w, "CreateRootCA", strict));
        var rootCert = await AssertCreatedAsync(w, root, parent: null);
        var intermediate = await IntermediateAsync(w, root, "Ceremony Sub", strict, SeedApprovedCeremony(w, "CreateIntermediateCA", strict));
        var intermediateCert = await AssertCreatedAsync(w, intermediate, rootCert);

        // A parent in another space: the waived space's root certifies an intermediate of the strict one.
        var foreignRoot = await RootAsync(w, "Foreign Root", w.SpaceId, ceremonyId: null);
        var foreignRootCert = await AssertCreatedAsync(w, foreignRoot, parent: null);
        var crossSpace = await IntermediateAsync(w, foreignRoot, "Cross Space Sub", strict, SeedApprovedCeremony(w, "CreateIntermediateCA", strict));
        var crossSpaceCert = await AssertCreatedAsync(w, crossSpace, foreignRootCert);
        var unapproved = await Assert.ThrowsAsync<SigningRefusedException>(() => IntermediateAsync(w, foreignRoot, "Unapproved Sub", strict, ceremonyId: null));
        Assert.Equal(SigningRefusalReason.CeremonyRequired, unapproved.Reason);

        await AssertServesAsync(w, root, rootCert);
        await AssertServesAsync(w, intermediate, intermediateCert);
        await AssertServesAsync(w, crossSpace, crossSpaceCert);
    }

    /// <summary>
    /// What the node could do before typing and cannot now, shown against a CA the real flow
    /// created: have the CA key sign a subordinate CA or a delegated responder for a key of the
    /// node's own, or sign a certificate under the OCSP label.
    /// </summary>
    [Fact]
    public async Task A_created_ca_signs_no_ca_or_responder_certificate_for_a_key_from_outside_the_signer()
    {
        var w = NewWorld();
        var root = await RootAsync(w, "Guarded Root", w.SpaceId, ceremonyId: null);
        var rootCert = Certificate(w, root.CertificateId);
        var key = new KeyRef(root.CertificateId!.Value);
        var algorithm = SignatureAlgorithm.ForPublicKey(rootCert.GetPublicKey());
        var outside = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public;
        var certificate = SigningContext.ForCa("compromised-node", SigningPurpose.Certificate, root.Id, root.SpaceId);

        async Task Refused(byte[] data, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => w.Signer.SignAsync(key, algorithm, data, context));
            Assert.Equal(reason, ex.Reason);
        }
        var rogueCa = TypedSigningData.CaCertificate(rootCert.SubjectDN, outside, algorithm, new X509Name("CN=Rogue Sub CA"), pathLength: 0);
        var rogueResponder = TypedSigningData.OcspSigningCertificate(rootCert.SubjectDN, outside, algorithm);
        await Refused(rogueCa, certificate, SigningRefusalReason.EvidenceRequired);
        await Refused(rogueResponder, certificate, SigningRefusalReason.EvidenceRequired);
        foreach (var purpose in new[] { SigningPurpose.Ocsp, SigningPurpose.Crl, SigningPurpose.Cmp, SigningPurpose.Scep })
        {
            await Refused(rogueCa, SigningContext.ForCa("compromised-node", purpose, root.Id, root.SpaceId), SigningRefusalReason.UntypedData);
            await Refused(rogueResponder, SigningContext.ForCa("compromised-node", purpose, root.Id, root.SpaceId), SigningRefusalReason.UntypedData);
        }
    }
}
