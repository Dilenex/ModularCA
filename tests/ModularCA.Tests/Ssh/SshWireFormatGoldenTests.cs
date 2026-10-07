using System.Buffers.Binary;
using ModularCA.Ssh;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Ssh;

/// <summary>
/// The OpenSSH encoder, parser and KRL writer against certificates and KRLs made by
/// <c>ssh-keygen</c> (OpenSSH 10.2, <c>Fixtures/generate.sh</c>).
/// </summary>
public class SshWireFormatGoldenTests
{
    [Theory]
    [MemberData(nameof(SshFixtures.CaseData), MemberType = typeof(SshFixtures))]
    public void The_encoder_reproduces_ssh_keygen_byte_for_byte(SshFixtureCase c)
    {
        var expected = SshFixtures.CertificateBlob(c);
        var reference = SshCertificate.Parse(expected);

        var tbs = SshCertificateEncoder.EncodeToBeSigned(SshFixtures.Fields(c), SshFixtures.CaPublic(c.Ca), reference.Nonce);
        var certificate = SshCertificateEncoder.Assemble(tbs, reference.SignatureBlob);

        Assert.Equal(expected, certificate);
        Assert.Equal(SshFixtures.CertificateText(c), SshCertificate.ToOpenSsh(certificate, $"subj-{c.Subject}"));
    }

    [Theory]
    [MemberData(nameof(SshFixtures.CaseData), MemberType = typeof(SshFixtures))]
    public void The_parser_reads_every_field_back(SshFixtureCase c)
    {
        var parsed = SshCertificate.ParseOpenSsh(SshFixtures.CertificateText(c));
        var expected = SshFixtures.Fields(c);

        Assert.Equal(SshKeyTypes.CertificateType(expected.SubjectKey.KeyType), parsed.CertificateType);
        Assert.Equal(32, parsed.Nonce.Length);
        Assert.Equal(expected.SubjectKey, parsed.Fields.SubjectKey);
        Assert.Equal(c.Type, parsed.Fields.Type);
        Assert.Equal(c.Serial, parsed.Fields.Serial);
        Assert.Equal(c.Name, parsed.Fields.KeyId);
        Assert.Equal(c.Principals, parsed.Fields.Principals);
        Assert.Equal(c.ValidAfter, parsed.Fields.ValidAfter);
        Assert.Equal(c.ValidBefore, parsed.Fields.ValidBefore);
        Assert.Equal(c.CriticalOptions.OrderBy(o => o.Name, StringComparer.Ordinal), parsed.Fields.CriticalOptions);
        Assert.Equal(c.Extensions.OrderBy(o => o.Name, StringComparer.Ordinal), parsed.Fields.Extensions);
        Assert.Empty(parsed.Reserved);
        Assert.Equal(SshFixtures.CaPublic(c.Ca), parsed.SignatureKey);
        Assert.Equal(c.SignatureAlgorithm, parsed.SignatureAlgorithm);
        Assert.Equal($"subj-{c.Subject}", parsed.Comment);
    }

    [Theory]
    [MemberData(nameof(SshFixtures.CaseData), MemberType = typeof(SshFixtures))]
    public void Every_ssh_keygen_signature_verifies(SshFixtureCase c)
    {
        var parsed = SshCertificate.ParseOpenSsh(SshFixtures.CertificateText(c));

        Assert.True(parsed.VerifySignature());
        Assert.True(SshFixtures.IndependentVerify(parsed.SignatureKey, parsed.ToBeSigned, parsed.SignatureBlob));
    }

    [Theory]
    [MemberData(nameof(SshFixtures.DeterministicCaseData), MemberType = typeof(SshFixtures))]
    public void Deterministic_signatures_match_ssh_keygen_when_signed_in_process(SshFixtureCase c)
    {
        var expected = SshFixtures.CertificateBlob(c);
        var reference = SshCertificate.Parse(expected);
        var ca = SshFixtures.CaPrivate(c.Ca);

        var tbs = SshCertificateEncoder.EncodeToBeSigned(SshFixtures.Fields(c), ca.PublicKey, reference.Nonce);
        var signature = SshSignature.Create(ca.PrivateKey, c.SignatureAlgorithm, tbs);

        Assert.Equal(reference.SignatureBlob, signature);
        Assert.Equal(expected, SshCertificateEncoder.Assemble(tbs, signature));
    }

    [Theory]
    [InlineData("p256", SshSignatureAlgorithms.EcdsaP256)]
    [InlineData("p384", SshSignatureAlgorithms.EcdsaP384)]
    [InlineData("p521", SshSignatureAlgorithms.EcdsaP521)]
    public void Ecdsa_signatures_made_in_process_with_the_fixture_ca_verify(string ca, string algorithm)
    {
        var c = SshFixtures.Cases.First(x => x.Ca == ca && x.Name.StartsWith("user-p", StringComparison.Ordinal));
        var caKey = SshFixtures.CaPrivate(ca);
        var tbs = SshCertificateEncoder.EncodeToBeSigned(SshFixtures.Fields(c), caKey.PublicKey, SshCertificateEncoder.NewNonce());

        var signature = SshSignature.Create(caKey.PrivateKey, algorithm, tbs);
        var parsed = SshCertificate.Parse(SshCertificateEncoder.Assemble(tbs, signature));

        Assert.Equal(algorithm, parsed.SignatureAlgorithm);
        Assert.True(parsed.VerifySignature());
        Assert.True(SshFixtures.IndependentVerify(caKey.PublicKey, tbs, signature));
    }

    public static IEnumerable<object[]> InMemoryAlgorithms =>
    [
        ["ed25519", SshSignatureAlgorithms.Ed25519],
        ["p256", SshSignatureAlgorithms.EcdsaP256],
        ["p384", SshSignatureAlgorithms.EcdsaP384],
        ["p521", SshSignatureAlgorithms.EcdsaP521],
        ["rsa", SshSignatureAlgorithms.RsaSha256],
        ["rsa", SshSignatureAlgorithms.RsaSha512],
    ];

    [Theory]
    [MemberData(nameof(InMemoryAlgorithms))]
    public void Sign_and_verify_round_trips_with_in_memory_keys(string keyKind, string algorithm)
    {
        var ca = Generate(keyKind);
        var subject = Generate(keyKind);
        var caPublic = SshPublicKey.FromKeyParameter(ca.Public);
        var fields = new SshCertificateFields
        {
            SubjectKey = SshPublicKey.FromKeyParameter(subject.Public),
            Type = SshCertificateType.User,
            Serial = 42,
            KeyId = "round-trip",
            Principals = ["alice"],
            ValidAfter = 1_800_000_000,
            ValidBefore = 1_800_003_600,
            CriticalOptions = [new SshOption("force-command", "/bin/true")],
            Extensions = [new SshOption("permit-pty")],
        };
        var nonce = SshCertificateEncoder.NewNonce();

        var tbs = SshCertificateEncoder.EncodeToBeSigned(fields, caPublic, nonce);
        var certificate = SshCertificateEncoder.Assemble(tbs, SshSignature.Create(ca.Private, algorithm, tbs));
        var parsed = SshCertificate.ParseOpenSsh(SshCertificate.ToOpenSsh(certificate, "test"));

        Assert.True(parsed.VerifySignature());
        Assert.True(SshFixtures.IndependentVerify(caPublic, parsed.ToBeSigned, parsed.SignatureBlob));
        Assert.Equal(nonce, parsed.Nonce);
        Assert.Equal(fields.SubjectKey, parsed.Fields.SubjectKey);
        Assert.Equal(fields.Principals, parsed.Fields.Principals);
        Assert.Equal(fields.CriticalOptions, parsed.Fields.CriticalOptions);
        Assert.Equal(fields.Extensions, parsed.Fields.Extensions);
        Assert.Equal(caPublic, parsed.SignatureKey);
        Assert.Equal(certificate, parsed.Blob);

        var tampered = (byte[])certificate.Clone();
        tampered[4 + parsed.CertificateType.Length + 4] ^= 1;
        Assert.False(SshCertificate.Parse(tampered).VerifySignature());
    }

    [Theory]
    [InlineData("p256", SshSignatureAlgorithms.EcdsaP256, 32)]
    [InlineData("p384", SshSignatureAlgorithms.EcdsaP384, 48)]
    [InlineData("p521", SshSignatureAlgorithms.EcdsaP521, 66)]
    public void Ecdsa_signer_output_encodes_the_same_from_der_and_raw(string keyKind, string algorithm, int fieldBytes)
    {
        var key = Generate(keyKind);
        var data = "to be signed"u8.ToArray();
        var signer = SignerUtilities.GetSigner(SshSignatureAlgorithms.SignerAlgorithmName(algorithm));
        signer.Init(true, key.Private);
        signer.BlockUpdate(data, 0, data.Length);
        var der = signer.GenerateSignature();

        var seq = (Org.BouncyCastle.Asn1.Asn1Sequence)Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(der);
        var raw = new byte[2 * fieldBytes];
        var r = Org.BouncyCastle.Asn1.DerInteger.GetInstance(seq[0]).Value.ToByteArrayUnsigned();
        var s = Org.BouncyCastle.Asn1.DerInteger.GetInstance(seq[1]).Value.ToByteArrayUnsigned();
        r.CopyTo(raw, fieldBytes - r.Length);
        s.CopyTo(raw, 2 * fieldBytes - s.Length);

        var fromDer = SshSignature.Encode(algorithm, der, EcdsaSignatureFormat.Der);
        var fromRaw = SshSignature.Encode(algorithm, raw, EcdsaSignatureFormat.Raw);

        Assert.Equal(fromDer, fromRaw);
        Assert.True(SshSignature.Verify(SshPublicKey.FromKeyParameter(key.Public), data, fromDer));
        Assert.Throws<ArgumentException>(() => SshSignature.Encode(algorithm, raw[1..], EcdsaSignatureFormat.Raw));
        Assert.Throws<ArgumentException>(() => SshSignature.Encode(algorithm, raw, EcdsaSignatureFormat.Der));
    }

    [Fact]
    public void Options_are_sorted_by_ordinal_name_with_flags_empty_and_values_nested()
    {
        var encoded = SshCertificateEncoder.EncodeOptions(
        [
            new SshOption("permit-pty"),
            new SshOption("login@example.com", "alice"),
            new SshOption("permit-X11-forwarding"),
        ]);

        var expected = new SshWriter()
            .String("login@example.com").String(new SshWriter().String("alice").ToArray())
            .String("permit-X11-forwarding").String([])
            .String("permit-pty").String([])
            .ToArray();
        Assert.Equal(expected, encoded);
        Assert.Throws<ArgumentException>(() => SshCertificateEncoder.EncodeOptions([new SshOption("permit-pty"), new SshOption("permit-pty")]));
        Assert.Throws<ArgumentException>(() => SshCertificateEncoder.EncodeOptions([new SshOption("")]));
    }

    [Fact]
    public void A_certificate_carries_exactly_the_extensions_given()
    {
        var c = SshFixtures.Cases.First(x => x.Name == "user-ed25519");
        var fields = SshFixtures.Fields(c) with { Extensions = [new SshOption("permit-pty")] };

        var tbs = SshCertificateEncoder.EncodeToBeSigned(fields, SshFixtures.CaPublic("ed25519"), SshCertificateEncoder.NewNonce());
        var parsed = SshCertificate.Parse(SshCertificateEncoder.Assemble(tbs, SshSignature.Create(SshFixtures.CaPrivate("ed25519").PrivateKey, SshSignatureAlgorithms.Ed25519, tbs)));

        Assert.Equal([new SshOption("permit-pty")], parsed.Fields.Extensions);
    }

    [Fact]
    public void The_encoder_refuses_a_bad_nonce_and_a_dsa_subject()
    {
        var c = SshFixtures.Cases[0];
        var ca = SshFixtures.CaPublic(c.Ca);
        Assert.Throws<ArgumentException>(() => SshCertificateEncoder.EncodeToBeSigned(SshFixtures.Fields(c), ca, new byte[16]));

        var dsa = SshPublicKey.FromKeyParameter(GenerateDsa().Public);
        Assert.Throws<ArgumentException>(() => SshCertificateEncoder.EncodeToBeSigned(
            SshFixtures.Fields(c) with { SubjectKey = dsa }, ca, SshCertificateEncoder.NewNonce()));
    }

    [Fact]
    public void The_parser_refuses_trailing_bytes_truncation_and_unsorted_extensions()
    {
        var blob = SshFixtures.CertificateBlob(SshFixtures.Cases[0]);
        Assert.Throws<FormatException>(() => SshCertificate.Parse([.. blob, 0]));
        Assert.Throws<FormatException>(() => SshCertificate.Parse(blob[..^1]));

        var c = SshFixtures.Cases[0];
        var reference = SshCertificate.Parse(blob);
        var fields = SshFixtures.Fields(c) with { Extensions = [new("permit-pty"), new("permit-X11-forwarding")] };
        var tbs = SshCertificateEncoder.EncodeToBeSigned(fields, SshFixtures.CaPublic(c.Ca), reference.Nonce);
        var sorted = new SshWriter().String("permit-X11-forwarding").String([]).String("permit-pty").String([]).ToArray();
        var unsorted = new SshWriter().String("permit-pty").String([]).String("permit-X11-forwarding").String([]).ToArray();

        var swapped = Replace(tbs, sorted, unsorted);

        Assert.Throws<FormatException>(() => SshCertificate.Parse(SshCertificateEncoder.Assemble(swapped, reference.SignatureBlob)));
    }

    [Fact]
    public void A_krl_matches_ssh_keygen_byte_for_byte()
    {
        var expected = File.ReadAllBytes(SshFixtures.PathOf("revoked.krl"));

        var krl = SshKrl.Encode(SshFixtures.CaPublic("ed25519"), [18446744073709551000, 1001, 5000000, 1001], 42, GeneratedAt(expected));

        Assert.Equal(expected, krl);
    }

    [Fact]
    public void An_empty_krl_matches_ssh_keygen_byte_for_byte()
    {
        var expected = File.ReadAllBytes(SshFixtures.PathOf("empty.krl"));

        var krl = SshKrl.Encode(SshFixtures.CaPublic("ed25519"), [], 7, GeneratedAt(expected));

        Assert.Equal(expected, krl);
    }

    [Fact]
    public void A_krl_refuses_serial_zero()
    {
        Assert.Throws<ArgumentException>(() => SshKrl.Encode(SshFixtures.CaPublic("ed25519"), [0], 1, DateTimeOffset.UnixEpoch));
    }

    [Theory]
    [InlineData("ed25519")]
    [InlineData("p256")]
    [InlineData("p384")]
    [InlineData("p521")]
    [InlineData("rsa")]
    public void BouncyCastle_reads_each_openssh_private_key_type_the_migration_needs(string ca)
    {
        var key = SshFixtures.CaPrivate(ca);

        Assert.Equal(SshFixtures.CaPublic(ca), key.PublicKey);
        var pkcs8 = key.ToPkcs8();
        var reread = PrivateKeyFactory.CreateKey(pkcs8);
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.PublicKey.KeyParameter);
        Assert.Equal(key.PublicKey, SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(spki)));
        Assert.Equal(PrivateKeyInfoFactory.CreatePrivateKeyInfo(reread).GetEncoded(), pkcs8);
    }

    [Fact]
    public void An_encrypted_or_foreign_private_key_file_is_refused()
    {
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.Read(SshFixtures.Text("ca-ed25519.pub")));
        var body = SshFixtures.Text("ca-ed25519.testkey").Trim().Split('\n');
        var blob = Convert.FromBase64String(string.Concat(body[1..^1]));
        var encrypted = Replace(blob, new SshWriter().String("none").String("none").ToArray(),
            new SshWriter().String("aes256-ctr").String("bcrypt").ToArray());
        // A key under a passphrase is refused as a format error of a type of its own, so a caller can say what to do about it.
        Assert.IsAssignableFrom<FormatException>(Assert.Throws<SshPrivateKeyEncryptedException>(() => SshPrivateKeyFile.ReadBlob(encrypted)));
        var armoured = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(encrypted) + "\n-----END OPENSSH PRIVATE KEY-----\n";
        Assert.Throws<SshPrivateKeyEncryptedException>(() => SshPrivateKeyFile.Read(armoured));
        Assert.Throws<SshPrivateKeyEncryptedException>(() => SshPrivateKeyFile.ReadFile(System.Text.Encoding.ASCII.GetBytes(armoured)));
    }

    /// <summary>
    /// The import reads a key file as bytes, so the key never passes through a string. It reads
    /// what the text reader reads, and refuses what it refuses.
    /// </summary>
    [Theory]
    [InlineData("ed25519")]
    [InlineData("p256")]
    [InlineData("p384")]
    [InlineData("p521")]
    [InlineData("rsa")]
    public void A_key_file_read_as_bytes_is_the_key_its_text_reads_as(string ca)
    {
        var bytes = File.ReadAllBytes(SshFixtures.PathOf($"ca-{ca}.testkey"));
        var before = (byte[])bytes.Clone();

        var key = SshPrivateKeyFile.ReadFile(bytes);

        Assert.Equal(SshFixtures.CaPublic(ca), key.PublicKey);
        Assert.Equal(SshFixtures.CaPrivate(ca).ToPkcs8(), key.ToPkcs8());
        Assert.Equal(before, bytes);
        // Windows line endings, and blank lines around the armour, are the same file.
        var crlf = System.Text.Encoding.ASCII.GetBytes("\r\n" + SshFixtures.Text($"ca-{ca}.testkey").ReplaceLineEndings("\r\n") + "\r\n\r\n");
        Assert.Equal(key.PublicKey, SshPrivateKeyFile.ReadFile(crlf).PublicKey);
    }

    [Fact]
    public void Bytes_that_are_not_a_key_file_are_refused_as_the_text_reader_refuses_them()
    {
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile([]));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile([0x00, 0xFF, 0xFE, 0x80]));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile(new byte[4096]));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile(File.ReadAllBytes(SshFixtures.PathOf("ca-ed25519.pub"))));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile("-----BEGIN OPENSSH PRIVATE KEY-----\n!!not base64!!\n-----END OPENSSH PRIVATE KEY-----\n"u8));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile("-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----\n"u8));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile("-----BEGIN OPENSSH PRIVATE KEY-----"u8));
        // A truncated key: the armour is whole, the key inside is not.
        var lines = SshFixtures.Text("ca-ed25519.testkey").Trim().Split('\n');
        var truncated = string.Join("\n", lines[..3].Append(lines[^1]));
        Assert.Throws<FormatException>(() => SshPrivateKeyFile.ReadFile(System.Text.Encoding.ASCII.GetBytes(truncated)));
    }

    internal static AsymmetricCipherKeyPair Generate(string kind)
    {
        var random = new SecureRandom();
        IAsymmetricCipherKeyPairGenerator generator;
        switch (kind)
        {
            case "ed25519":
                generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(random));
                break;
            case "rsa":
                generator = new RsaKeyPairGenerator();
                generator.Init(new KeyGenerationParameters(random, 2048));
                break;
            default:
                generator = new ECKeyPairGenerator();
                var domain = SshPublicKey.Domain(kind switch
                {
                    "p256" => SshKeyTypes.EcdsaP256,
                    "p384" => SshKeyTypes.EcdsaP384,
                    _ => SshKeyTypes.EcdsaP521,
                });
                generator.Init(new ECKeyGenerationParameters(domain, random));
                break;
        }
        return generator.GenerateKeyPair();
    }

    internal static AsymmetricCipherKeyPair GenerateDsa()
    {
        var parameters = new DsaParametersGenerator();
        parameters.Init(1024, 20, new SecureRandom());
        var generator = new DsaKeyPairGenerator();
        generator.Init(new DsaKeyGenerationParameters(new SecureRandom(), parameters.GenerateParameters()));
        return generator.GenerateKeyPair();
    }

    private static DateTimeOffset GeneratedAt(byte[] krl) =>
        DateTimeOffset.FromUnixTimeSeconds((long)BinaryPrimitives.ReadUInt64BigEndian(krl.AsSpan(20, 8)));

    private static byte[] Replace(byte[] data, byte[] find, byte[] replacement)
    {
        var index = data.AsSpan().IndexOf(find);
        Assert.True(index >= 0, "pattern not found");
        return [.. data[..index], .. replacement, .. data[(index + find.Length)..]];
    }
}
