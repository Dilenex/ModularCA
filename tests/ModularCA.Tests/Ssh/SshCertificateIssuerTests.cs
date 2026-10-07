using ModularCA.Ssh;
using Xunit;

namespace ModularCA.Tests.Ssh;

/// <summary>
/// Issuing through <see cref="ISshSigner"/>: the issuer checks, builds, has the key sign and hands
/// out a certificate only when the signature is the CA key's.
/// </summary>
public class SshCertificateIssuerTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1790000000);
    private static readonly SshCaLimits Limits = new(AllowUser: true, AllowHost: true, MaxValidity: TimeSpan.FromHours(24));

    private static SshCertificateFields Fields(string subject = "rsa", params string[] principals) => new()
    {
        SubjectKey = SshFixtures.Subject(subject),
        Type = SshCertificateType.User,
        Serial = 42,
        KeyId = "alice@example.com",
        Principals = principals.Length > 0 ? principals : ["alice"],
        ValidAfter = (ulong)Now.ToUnixTimeSeconds(),
        ValidBefore = (ulong)Now.AddHours(8).ToUnixTimeSeconds(),
        CriticalOptions = [new("source-address", "10.0.0.0/8")],
        Extensions = [new("permit-pty")],
    };

    /// <summary>Counts what it is asked to sign, and can be made to answer wrongly.</summary>
    private sealed class RecordingSigner(ISshSigner inner, Func<string, byte[], byte[]>? answer = null) : ISshSigner
    {
        public int Calls { get; private set; }
        public string? Algorithm { get; private set; }
        public SshPublicKey PublicKey => inner.PublicKey;

        public async ValueTask<byte[]> SignAsync(string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            Calls++;
            Algorithm = algorithm;
            return answer != null ? answer(algorithm, data.ToArray()) : await inner.SignAsync(algorithm, data, cancellationToken);
        }
    }

    [Theory]
    [InlineData("ed25519", "rsa", SshSignatureAlgorithms.Ed25519)]
    [InlineData("p256", "ed25519", SshSignatureAlgorithms.EcdsaP256)]
    [InlineData("p384", "ed25519", SshSignatureAlgorithms.EcdsaP384)]
    [InlineData("p521", "ed25519", SshSignatureAlgorithms.EcdsaP521)]
    [InlineData("rsa", "ed25519", SshSignatureAlgorithms.RsaSha512)]
    public async Task A_certificate_is_built_signed_by_the_key_and_says_what_was_asked(string ca, string subject, string algorithm)
    {
        var signer = new RecordingSigner(new SshKeySigner(SshFixtures.CaPrivate(ca)));
        var fields = Fields(subject);

        var certificate = await SshCertificateIssuer.IssueAsync(fields, signer, Limits, Now);

        Assert.Equal(1, signer.Calls);
        Assert.Equal(algorithm, signer.Algorithm);
        Assert.Equal(algorithm, certificate.SignatureAlgorithm);
        Assert.True(certificate.VerifySignature());
        Assert.Equal(SshFixtures.CaPublic(ca).Blob, certificate.SignatureKey.Blob);
        Assert.Equal(SshCertificateEncoder.NonceLength, certificate.Nonce.Length);

        Assert.Equal(fields.SubjectKey.Blob, certificate.Fields.SubjectKey.Blob);
        Assert.Equal(fields.Type, certificate.Fields.Type);
        Assert.Equal(fields.Serial, certificate.Fields.Serial);
        Assert.Equal(fields.KeyId, certificate.Fields.KeyId);
        Assert.Equal(fields.Principals, certificate.Fields.Principals);
        Assert.Equal(fields.ValidAfter, certificate.Fields.ValidAfter);
        Assert.Equal(fields.ValidBefore, certificate.Fields.ValidBefore);
        Assert.Equal(fields.CriticalOptions, certificate.Fields.CriticalOptions);
        Assert.Equal(fields.Extensions, certificate.Fields.Extensions);

        // The text form reads back as the same certificate.
        Assert.Equal(certificate.Blob, SshCertificate.ParseOpenSsh(certificate.ToOpenSsh("alice")).Blob);
    }

    [Fact]
    public async Task Each_certificate_has_its_own_nonce()
    {
        var signer = new SshKeySigner(SshFixtures.CaPrivate("ed25519"));

        var first = await SshCertificateIssuer.IssueAsync(Fields(), signer, Limits, Now);
        var second = await SshCertificateIssuer.IssueAsync(Fields(), signer, Limits, Now);

        Assert.NotEqual(first.Nonce, second.Nonce);
    }

    [Fact]
    public async Task A_certificate_that_breaks_a_rule_is_refused_before_the_key_is_asked()
    {
        var signer = new RecordingSigner(new SshKeySigner(SshFixtures.CaPrivate("ed25519")));

        var noPrincipals = Fields() with { Principals = [] };
        var tooLong = Fields() with { ValidBefore = (ulong)Now.AddDays(30).ToUnixTimeSeconds() };
        var hostOnly = new SshCaLimits(AllowUser: false, AllowHost: true, MaxValidity: TimeSpan.FromHours(24));

        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () => await SshCertificateIssuer.IssueAsync(noPrincipals, signer, Limits, Now));
        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () => await SshCertificateIssuer.IssueAsync(tooLong, signer, Limits, Now));
        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () => await SshCertificateIssuer.IssueAsync(Fields(), signer, hostOnly, Now));
        Assert.Equal(0, signer.Calls);
    }

    /// <summary>The issuer holds <c>valid_after</c> to the allowance it is given, each way on its own.</summary>
    [Fact]
    public async Task The_issuer_holds_the_start_to_a_clock_skew_allowance_for_each_direction()
    {
        var signer = new RecordingSigner(new SshKeySigner(SshFixtures.CaPrivate("ed25519")));
        var skew = new SshClockSkew(Past: TimeSpan.FromMinutes(10), Future: TimeSpan.FromMinutes(5));
        SshCertificateFields StartingAt(TimeSpan offset) => Fields() with { ValidAfter = (ulong)Now.Add(offset).ToUnixTimeSeconds() };

        var backdated = await SshCertificateIssuer.IssueAsync(StartingAt(TimeSpan.FromMinutes(-10)), signer, Limits, Now, skew);
        Assert.True(backdated.VerifySignature());
        Assert.True((await SshCertificateIssuer.IssueAsync(StartingAt(TimeSpan.FromMinutes(5)), signer, Limits, Now, skew)).VerifySignature());
        Assert.Equal(2, signer.Calls);

        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () =>
            await SshCertificateIssuer.IssueAsync(StartingAt(TimeSpan.FromSeconds(-601)), signer, Limits, Now, skew));
        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () =>
            await SshCertificateIssuer.IssueAsync(StartingAt(TimeSpan.FromSeconds(301)), signer, Limits, Now, skew));
        // Without an allowance of its own the default holds, both ways.
        await Assert.ThrowsAsync<SshCertificateRefusedException>(async () =>
            await SshCertificateIssuer.IssueAsync(StartingAt(TimeSpan.FromMinutes(-10)), signer, Limits, Now));
        Assert.Equal(2, signer.Calls);
    }

    [Fact]
    public async Task A_signature_that_is_not_the_CA_keys_does_not_become_a_certificate()
    {
        var ca = new SshKeySigner(SshFixtures.CaPrivate("rsa"));
        var other = SshFixtures.CaPrivate("ed25519");

        // Another key answered, under the right name.
        var wrongKey = new RecordingSigner(ca, (algorithm, data) =>
            SshSignature.Create(other.PrivateKey, SshSignatureAlgorithms.Ed25519, data));
        // The right key, with the weaker hash than the one asked for.
        var wrongAlgorithm = new RecordingSigner(ca, (_, data) =>
            SshSignature.Create(SshFixtures.CaPrivate("rsa").PrivateKey, SshSignatureAlgorithms.RsaSha256, data));
        // The right key over other bytes.
        var wrongData = new RecordingSigner(ca, (algorithm, _) =>
            SshSignature.Create(SshFixtures.CaPrivate("rsa").PrivateKey, algorithm, [1, 2, 3]));
        var garbage = new RecordingSigner(ca, (_, _) => [0, 0, 0, 1]);

        foreach (var signer in new[] { wrongKey, wrongAlgorithm, wrongData, garbage })
            await Assert.ThrowsAsync<SshSigningFailedException>(async () => await SshCertificateIssuer.IssueAsync(Fields("ed25519"), signer, Limits, Now));
    }

    [Fact]
    public async Task A_software_signer_refuses_an_algorithm_its_key_does_not_sign_with()
    {
        var signer = new SshKeySigner(SshFixtures.CaPrivate("ed25519"));

        await Assert.ThrowsAsync<ArgumentException>(async () => await signer.SignAsync(SshSignatureAlgorithms.RsaSha512, new byte[] { 1 }));
        Assert.Throws<ArgumentException>(() => new SshKeySigner(SshFixtures.CaPublic("ed25519").KeyParameter, SshFixtures.CaPublic("ed25519")));
    }
}
