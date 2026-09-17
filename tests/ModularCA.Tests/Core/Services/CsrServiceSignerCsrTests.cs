using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The CSR service builds an infrastructure request over a key it does not hold: the public
/// half comes from the signer's generated key and the proof of possession is signed through the
/// signer, so a new CA or infrastructure certificate never needs its key outside the signer.
/// </summary>
public sealed class CsrServiceSignerCsrTests
{

    [Fact]
    public async Task An_infrastructure_csr_over_a_generated_key_verifies_and_is_stored_approved()
    {
        var world = SignerTestWorld.Create();
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName);
        using var db = world.OpenDb();
        var signingProfile = new SigningProfileEntity { Name = "generated-ca", AllowedAlgorithms = "[]", IssuerId = world["ca-rsa"].Ref.CertificateId };
        var certProfile = new CertProfileEntity
        {
            Name = "TSA Certificate Profile",
            KeyUsages = "[\"Digital Signature\"]",
            ExtendedKeyUsages = "[\"1.3.6.1.5.5.7.3.8\"]",
            AllowedKeySizes = "[]",
            AllowedSignatureAlgorithms = "[]",
        };
        db.SigningProfiles.Add(signingProfile);
        db.CertProfiles.Add(certProfile);
        await db.SaveChangesAsync();
        var service = new CsrService(db);

        var ceremony = new SigningContext("csr-test", SigningPurpose.Ceremony, world.TenantA, world.CaRsaId);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var csrSigner = new SigningServiceSignatureFactory(signer, generated.Key,
            SignatureAlgorithm.FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithm("ECDSA", 256)), ceremony);

        var csrId = await service.GenerateInfrastructureCsrAsync(
            "CN=Signer Test RSA CA TSA", "ECDSA", 256, certProfile.Id, signingProfile.Id, publicKey, csrSigner);

        var row = db.CertificateRequests.Single(r => r.Id == csrId);
        Assert.Equal("Approved", row.Status);
        Assert.True(row.IsInfrastructureCert);
        Assert.Equal("P-256", row.KeySize);
        using var reader = new StringReader(row.CSR);
        var csr = Assert.IsType<Pkcs10CertificationRequest>(new PemReader(reader).ReadObject());
        Assert.True(csr.Verify());
        Assert.Equal(publicKey, csr.GetPublicKey());

        var signRow = Assert.Single(await ReadAuditAsync(world), r => r.Operation == "Sign");
        Assert.Equal("allowed", signRow.Outcome);
        Assert.Equal("Ceremony", signRow.Purpose);
        Assert.Equal(generated.Key.CertificateId, signRow.KeyCertificateId);
    }

    private static Task<IReadOnlyList<SignerAuditEntity>> ReadAuditAsync(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        IReadOnlyList<SignerAuditEntity> rows = db.SignerAudit.OrderBy(r => r.At).ToList();
        return Task.FromResult(rows);
    }
}
