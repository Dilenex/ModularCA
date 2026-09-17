using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Tests.Signer;

/// <summary>
/// One key the signer holds in a test, with everything a test needs to name it and check it:
/// its reference, its public half, and the CA and tenant the database says own it.
/// </summary>
/// <param name="PrivateKeyPkcs8">The private half, DER-encoded PKCS#8, for the import tests; the signer never sees it otherwise.</param>
internal sealed record SignerTestKey(string Name, KeyRef Ref, X509Certificate Certificate, AsymmetricKeyParameter PublicKey, Guid? CaId, Guid? TenantId, byte[] PrivateKeyPkcs8);

/// <summary>
/// The world a signer contract test runs in: two CAs in two tenants, one RSA and one ECDSA,
/// with the infrastructure keys a CA owns under the first, plus the keys that must be refused.
/// The database rows are the ones the signer classifies from, seeded exactly as the node writes
/// them; the keystore is the in-memory <see cref="TestKeystore"/> holding every key.
/// </summary>
/// <remarks>
/// Keys by name:
/// <list type="bullet">
/// <item><c>ca-rsa</c>: the RSA CA in tenant A.</item>
/// <item><c>ca-ec</c>: the P-256 CA in tenant B.</item>
/// <item><c>ocsp</c>: the delegated OCSP responder of <c>ca-rsa</c>.</item>
/// <item><c>tsa</c>: the timestamp authority of <c>ca-rsa</c>.</item>
/// <item><c>cmp</c>: the CMP protection key of <c>ca-rsa</c>.</item>
/// <item><c>leaf</c>: an end-entity certificate under <c>ca-rsa</c> whose key the keystore holds, and whose row also carries the key wrapped under <c>ca-rsa</c>, as the node stored end-entity keys before re-download ended.</item>
/// <item><c>leaf-unheld</c>: an end-entity certificate under <c>ca-rsa</c> with no key anywhere, as every certificate issued since.</item>
/// <item><c>orphan</c>: a CA certificate no CertificateAuthorities row names, key held.</item>
/// <item><c>keyless</c>: a CA with a row but no key in the keystore.</item>
/// </list>
/// </remarks>
internal sealed class SignerTestWorld
{
    public string DatabaseName { get; }
    public Guid TenantA { get; }
    public Guid TenantB { get; }
    public Guid CaRsaId { get; }
    public Guid CaEcId { get; }
    public Guid KeylessCaId { get; }
    public TestKeystore Keystore { get; }
    public IServiceScopeFactory Scopes { get; }

    /// <summary>Where the signer under test persists committed keys; a test reads back what it appended.</summary>
    public InMemorySignerKeyPersistence Persistence { get; } = new();
    public IReadOnlyDictionary<string, SignerTestKey> Keys { get; }

    /// <summary>The names of the materials the keystore holds no private key for.</summary>
    private static readonly HashSet<string> Unheld = new() { "keyless", "leaf-unheld" };

    /// <summary>Every key the keystore holds a private key for; <c>keyless</c> and <c>leaf-unheld</c> are not among them.</summary>
    public IEnumerable<SignerTestKey> HeldKeys => Keys.Values.Where(k => !Unheld.Contains(k.Name));

    public SignerTestKey this[string name] => Keys[name];

    private SignerTestWorld(string databaseName, Ids ids, TestKeystore keystore, IServiceScopeFactory scopes, IReadOnlyDictionary<string, SignerTestKey> keys)
    {
        DatabaseName = databaseName;
        TenantA = ids.TenantA;
        TenantB = ids.TenantB;
        CaRsaId = ids.CaRsa;
        CaEcId = ids.CaEc;
        KeylessCaId = ids.KeylessCa;
        Keystore = keystore;
        Scopes = scopes;
        Keys = keys;
    }

    private sealed record Ids(Guid TenantA, Guid TenantB, Guid CaRsa, Guid CaEc, Guid KeylessCa);

    /// <summary>Opens a context over the world's database, for seeding and for reading the audit back.</summary>
    public ModularCADbContext OpenDb() => InMemoryDbContextFactory.Create(DatabaseName);

    /// <summary>Builds the material, seeds the rows and returns the world.</summary>
    public static SignerTestWorld Create()
    {
        var world = new Builder();
        var caRsa = world.SelfSignedCa("ca-rsa", "CN=Signer Test RSA CA, O=ModularCA", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"));
        var caEc = world.SelfSignedCa("ca-ec", "CN=Signer Test EC CA, O=ModularCA", KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256"));
        var ocsp = world.Issued("ocsp", caRsa, "CN=Signer Test OCSP Responder", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"));
        var tsa = world.Issued("tsa", caRsa, "CN=Signer Test TSA", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"),
            new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        var cmp = world.Issued("cmp", caRsa, "CN=Signer Test CMP Signer", KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256"));
        var leaf = world.Issued("leaf", caRsa, "CN=leaf.signer.test", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"));
        var leafUnheld = world.Issued("leaf-unheld", caRsa, "CN=unheld.signer.test", KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256"));
        var orphan = world.SelfSignedCa("orphan", "CN=Signer Test Orphan CA, O=ModularCA", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"));
        var keyless = world.SelfSignedCa("keyless", "CN=Signer Test Keyless CA, O=ModularCA", KeyAlgorithmPolicy.GenerateKeyPair("RSA", "2048"));

        var databaseName = $"signer-{Guid.NewGuid():N}";
        var ids = new Ids(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());

        using (var db = InMemoryDbContextFactory.Create(databaseName))
        {
            foreach (var m in world.Materials)
                db.Certificates.Add(CertificateRow(m));

            // The leaf's key is stored on its row the way the node stored end-entity keys before
            // re-download ended: wrapped under the issuing CA's public key, with that CA's serial
            // recorded so the signer can find the key that unwraps it.
            var leafRow = db.Certificates.Local.Single(c => c.CertificateId == leaf.Id);
            var wrap = KeyEncryptionUtil.EncryptPrivateKey(caRsa.KeyPair.Public, leaf.KeyPair.Private);
            leafRow.EncryptedAesForPrivateKey = wrap.aesKeyEncrypted;
            leafRow.AesKeyEncryptionIv = wrap.iv;
            leafRow.EncryptedPrivateKey = wrap.encryptedPrivateKey;
            leafRow.EncryptionCertSerialNumber = CertificateUtil.FormatSerialNumber(caRsa.Certificate.SerialNumber);

            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = ids.CaRsa, Name = "signer-test-rsa", Label = "signer-test-rsa", TenantId = ids.TenantA,
                CertificateId = caRsa.Id,
                OcspResponderCertificateId = ocsp.Id,
                TsaCertificateId = tsa.Id,
                CmpSigningCertificateId = cmp.Id,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = ids.CaEc, Name = "signer-test-ec", Label = "signer-test-ec", TenantId = ids.TenantB,
                CertificateId = caEc.Id,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = ids.KeylessCa, Name = "signer-test-keyless", Label = "signer-test-keyless", TenantId = ids.TenantA,
                CertificateId = keyless.Id,
            });
            db.SaveChanges();
        }

        var keystore = new TestKeystore(world.Materials
            .Where(m => !Unheld.Contains(m.Name))
            .Select(m => (m.Certificate, (ModularCA.Keystore.IPrivateKeyHandle)new ModularCA.Keystore.Adapters.SoftwarePrivateKeyHandle(m.KeyPair.Private)))
            .ToArray());

        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(o => o
            .UseInMemoryDatabase(databaseName)
            .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning)));
        var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();

        var keys = new Dictionary<string, SignerTestKey>();
        foreach (var m in world.Materials)
        {
            (Guid? caId, Guid? tenantId) = m.Name switch
            {
                "ca-rsa" or "ocsp" or "tsa" or "cmp" => (ids.CaRsa, ids.TenantA),
                "ca-ec" => (ids.CaEc, ids.TenantB),
                "keyless" => (ids.KeylessCa, ids.TenantA),
                _ => ((Guid?)null, (Guid?)null),
            };
            keys[m.Name] = new SignerTestKey(m.Name, new KeyRef(m.Id), m.Certificate, m.KeyPair.Public, caId, tenantId,
                Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(m.KeyPair.Private).GetDerEncoded());
        }

        return new SignerTestWorld(databaseName, ids, keystore, scopes, keys);
    }

    private static CertificateEntity CertificateRow(Material m) => new()
    {
        CertificateId = m.Id,
        SerialNumber = CertificateUtil.FormatSerialNumber(m.Certificate.SerialNumber),
        SubjectDN = m.Certificate.SubjectDN.ToString(),
        Issuer = m.Certificate.IssuerDN.ToString(),
        IsCA = m.IsCa,
        Pem = CertificateUtil.ConvertDerToPem(m.Certificate.GetEncoded(), "CERTIFICATE"),
        RawCertificate = m.Certificate.GetEncoded(),
        NotBefore = m.Certificate.NotBefore,
        NotAfter = m.Certificate.NotAfter,
    };

    private sealed record Material(string Name, Guid Id, X509Certificate Certificate, AsymmetricCipherKeyPair KeyPair, bool IsCa);

    private sealed class Builder
    {
        private static readonly DateTime NotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static readonly DateTime NotAfter = new(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private long _serial = 1;

        public List<Material> Materials { get; } = new();

        public Material SelfSignedCa(string name, string dn, AsymmetricCipherKeyPair keyPair)
        {
            var subject = new X509Name(dn);
            var gen = Start(subject, subject, keyPair.Public);
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));
            var cert = gen.Generate(new Asn1SignatureFactory(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(keyPair.Public), keyPair.Private, new SecureRandom()));
            return Add(name, cert, keyPair, isCa: true);
        }

        /// <summary>
        /// Issues an end-entity certificate under <paramref name="issuer"/>. An
        /// <paramref name="extendedKeyUsage"/> is written critical, as the TSA certificate
        /// needs it for the timestamp generator to accept the certificate at all.
        /// </summary>
        public Material Issued(string name, Material issuer, string dn, AsymmetricCipherKeyPair keyPair, ExtendedKeyUsage? extendedKeyUsage = null)
        {
            var gen = Start(issuer.Certificate.SubjectDN, new X509Name(dn), keyPair.Public);
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            if (extendedKeyUsage != null)
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, true, extendedKeyUsage);
            var cert = gen.Generate(new Asn1SignatureFactory(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(issuer.KeyPair.Public), issuer.KeyPair.Private, new SecureRandom()));
            return Add(name, cert, keyPair, isCa: false);
        }

        private X509V3CertificateGenerator Start(X509Name issuer, X509Name subject, AsymmetricKeyParameter publicKey)
        {
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ValueOf(_serial++));
            gen.SetIssuerDN(issuer);
            gen.SetSubjectDN(subject);
            gen.SetNotBefore(NotBefore);
            gen.SetNotAfter(NotAfter);
            gen.SetPublicKey(publicKey);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, X509ExtensionUtilities.CreateSubjectKeyIdentifier(spki));
            return gen;
        }

        private Material Add(string name, X509Certificate cert, AsymmetricCipherKeyPair keyPair, bool isCa)
        {
            var m = new Material(name, Guid.NewGuid(), cert, keyPair, isCa);
            Materials.Add(m);
            return m;
        }
    }
}
