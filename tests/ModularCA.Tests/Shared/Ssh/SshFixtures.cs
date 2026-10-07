using System.Security.Cryptography;
using ModularCA.Shared.Ssh;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace ModularCA.Tests.Shared.Ssh;

/// <summary>
/// One certificate made by <c>Fixtures/generate.sh</c>, with the inputs it was made from. Only the
/// nonce and the signature are taken from the file; every other field is stated here.
/// </summary>
public sealed record SshFixtureCase(
    string Name,
    string Ca,
    string Subject,
    SshCertificateType Type,
    ulong Serial,
    string[] Principals,
    ulong ValidAfter,
    ulong ValidBefore,
    SshOption[] CriticalOptions,
    SshOption[] Extensions,
    string SignatureAlgorithm)
{
    /// <inheritdoc />
    public override string ToString() => Name;
}

/// <summary>Reads the golden fixtures and holds the cases <c>generate.sh</c> made.</summary>
public static class SshFixtures
{
    /// <summary>2026-01-01T00:00:00Z.</summary>
    public const ulong After = 1767225600;

    /// <summary>2027-01-01T00:00:00Z.</summary>
    public const ulong Before = 1798761600;

    private static readonly string[] Users = ["alice", "bob"];
    private static readonly string[] Hosts = ["host1.example.com", "host1"];

    /// <summary>ssh-keygen's default user extensions, deliberately out of order: the encoder sorts.</summary>
    private static readonly SshOption[] DefaultUserExtensions =
    [
        new("permit-user-rc"),
        new("permit-pty"),
        new("permit-port-forwarding"),
        new("permit-agent-forwarding"),
        new("permit-X11-forwarding"),
    ];

    /// <summary>Every certificate fixture.</summary>
    public static readonly SshFixtureCase[] Cases =
    [
        User("user-ed25519", "ed25519", "ed25519", 1001, SshSignatureAlgorithms.Ed25519),
        Host("host-ed25519", "ed25519", "ed25519", 1002, SshSignatureAlgorithms.Ed25519),
        User("user-p256", "p256", "p256", 2001, SshSignatureAlgorithms.EcdsaP256),
        Host("host-p256", "p256", "p256", 2002, SshSignatureAlgorithms.EcdsaP256),
        User("user-p384", "p384", "p384", 3001, SshSignatureAlgorithms.EcdsaP384),
        Host("host-p384", "p384", "p384", 3002, SshSignatureAlgorithms.EcdsaP384),
        User("user-p521", "p521", "p521", 4001, SshSignatureAlgorithms.EcdsaP521),
        Host("host-p521", "p521", "p521", 4002, SshSignatureAlgorithms.EcdsaP521),
        User("user-rsa-sha512", "rsa", "rsa", 5001, SshSignatureAlgorithms.RsaSha512),
        Host("host-rsa-sha512", "rsa", "rsa", 5002, SshSignatureAlgorithms.RsaSha512),
        User("user-rsa-sha256", "rsa", "rsa", 5003, SshSignatureAlgorithms.RsaSha256),
        Host("host-rsa-sha256", "rsa", "rsa", 5004, SshSignatureAlgorithms.RsaSha256),
        new("user-options", "ed25519", "rsa", SshCertificateType.User, 18446744073709551000, ["deploy"], After, Before,
            [
                new("verify-required"),
                new("source-address", "10.0.0.0/8,192.0.2.1"),
                new("force-command", "/usr/bin/rsync --server"),
            ],
            [
                new("permit-pty"),
                new("no-touch-required"),
                new("login@example.com", "alice"),
                new("permit-X11-forwarding"),
            ],
            SshSignatureAlgorithms.Ed25519),
        new("user-forever", "p256", "ed25519", SshCertificateType.User, 7, ["alice"], 0, SshCertificateFields.Forever,
            [], DefaultUserExtensions, SshSignatureAlgorithms.EcdsaP256),
    ];

    /// <summary>The cases as xUnit theory data.</summary>
    public static IEnumerable<object[]> CaseData => Cases.Select(c => new object[] { c });

    /// <summary>The cases whose signatures are deterministic (Ed25519, RSA PKCS#1 v1.5).</summary>
    public static IEnumerable<object[]> DeterministicCaseData =>
        Cases.Where(c => !c.SignatureAlgorithm.StartsWith("ecdsa", StringComparison.Ordinal)).Select(c => new object[] { c });

    /// <summary>The full path of a fixture file.</summary>
    public static string PathOf(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Shared", "Ssh", "Fixtures", name);

    /// <summary>The text of a fixture file.</summary>
    public static string Text(string name) => File.ReadAllText(PathOf(name));

    /// <summary>The CA public key of a case.</summary>
    public static SshPublicKey CaPublic(string ca) => SshPublicKey.ParseAuthorizedKey(Text($"ca-{ca}.pub"));

    /// <summary>The CA private key of a case, made for these tests only.</summary>
    public static SshPrivateKey CaPrivate(string ca) => SshPrivateKeyFile.Read(Text($"ca-{ca}.testkey"));

    /// <summary>The subject public key of a case.</summary>
    public static SshPublicKey Subject(string subject) => SshPublicKey.ParseAuthorizedKey(Text($"subj-{subject}.pub"));

    /// <summary>The certificate file's text.</summary>
    public static string CertificateText(SshFixtureCase c) => Text($"{c.Name}-cert.pub").Trim();

    /// <summary>The certificate file's blob.</summary>
    public static byte[] CertificateBlob(SshFixtureCase c) => Convert.FromBase64String(CertificateText(c).Split(' ')[1]);

    /// <summary>The certificate fields a case states.</summary>
    public static SshCertificateFields Fields(SshFixtureCase c) => new()
    {
        SubjectKey = Subject(c.Subject),
        Type = c.Type,
        Serial = c.Serial,
        KeyId = c.Name,
        Principals = c.Principals,
        ValidAfter = c.ValidAfter,
        ValidBefore = c.ValidBefore,
        CriticalOptions = c.CriticalOptions,
        Extensions = c.Extensions,
    };

    /// <summary>
    /// Verifies an SSH signature blob without the code under test: .NET for RSA and ECDSA,
    /// BouncyCastle's Ed25519 directly for Ed25519.
    /// </summary>
    public static bool IndependentVerify(SshPublicKey key, byte[] data, byte[] signatureBlob)
    {
        var outer = new SshReader(signatureBlob);
        var algorithm = outer.Utf8String();
        var signature = outer.String();
        switch (key.KeyParameter)
        {
            case Ed25519PublicKeyParameters ed when algorithm == "ssh-ed25519":
                var verifier = new Ed25519Signer();
                verifier.Init(false, ed);
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature);

            case RsaKeyParameters rsaKey when algorithm is "rsa-sha2-256" or "rsa-sha2-512":
                using (var rsa = RSA.Create(new RSAParameters
                       {
                           Modulus = rsaKey.Modulus.ToByteArrayUnsigned(),
                           Exponent = rsaKey.Exponent.ToByteArrayUnsigned(),
                       }))
                {
                    var hash = algorithm == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
                    return rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1);
                }

            case ECPublicKeyParameters ecKey when algorithm == key.KeyType:
                var (curve, hashName, size) = key.KeyType switch
                {
                    "ecdsa-sha2-nistp256" => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, 32),
                    "ecdsa-sha2-nistp384" => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, 48),
                    _ => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, 66),
                };
                var inner = new SshReader(signature);
                var r = inner.MPInt().ToByteArrayUnsigned();
                var s = inner.MPInt().ToByteArrayUnsigned();
                var p1363 = new byte[2 * size];
                r.CopyTo(p1363, size - r.Length);
                s.CopyTo(p1363, 2 * size - s.Length);
                var q = ecKey.Q.Normalize();
                using (var ecdsa = ECDsa.Create(new ECParameters
                       {
                           Curve = curve,
                           Q = new ECPoint
                           {
                               X = q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned().PadLeft(size),
                               Y = q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned().PadLeft(size),
                           },
                       }))
                {
                    return ecdsa.VerifyData(data, p1363, hashName);
                }

            default:
                return false;
        }
    }

    private static byte[] PadLeft(this byte[] bytes, int size)
    {
        var padded = new byte[size];
        bytes.CopyTo(padded, size - bytes.Length);
        return padded;
    }

    private static SshFixtureCase User(string name, string ca, string subject, ulong serial, string algorithm) =>
        new(name, ca, subject, SshCertificateType.User, serial, Users, After, Before, [], DefaultUserExtensions, algorithm);

    private static SshFixtureCase Host(string name, string ca, string subject, ulong serial, string algorithm) =>
        new(name, ca, subject, SshCertificateType.Host, serial, Hosts, After, Before, [], [], algorithm);
}
