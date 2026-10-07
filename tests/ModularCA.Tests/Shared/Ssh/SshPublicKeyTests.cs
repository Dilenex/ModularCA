using ModularCA.Shared.Ssh;
using Xunit;

namespace ModularCA.Tests.Shared.Ssh;

/// <summary>Parsing subject public keys from authorized_keys lines, which replaces the node's prefix check.</summary>
public class SshPublicKeyTests
{
    [Theory]
    [InlineData("subj-ed25519.pub", SshKeyTypes.Ed25519, 256)]
    [InlineData("subj-p256.pub", SshKeyTypes.EcdsaP256, 256)]
    [InlineData("subj-p384.pub", SshKeyTypes.EcdsaP384, 384)]
    [InlineData("subj-p521.pub", SshKeyTypes.EcdsaP521, 521)]
    [InlineData("subj-rsa.pub", SshKeyTypes.Rsa, 2048)]
    [InlineData("ca-rsa.pub", SshKeyTypes.Rsa, 3072)]
    public void Ssh_keygen_public_keys_parse_and_render_back_unchanged(string file, string type, int bits)
    {
        var text = SshFixtures.Text(file).Trim();

        var key = SshPublicKey.ParseAuthorizedKey(text);

        Assert.Equal(type, key.KeyType);
        Assert.Equal(bits, key.KeySizeBits);
        Assert.Equal(text, key.ToAuthorizedKey(key.Comment));
        Assert.Equal(key, SshPublicKey.FromKeyParameter(key.KeyParameter));
        Assert.Equal(key, SshPublicKey.FromBlob(key.Blob));
    }

    [Theory]
    [InlineData("subj-ed25519.pub", "SHA256:n3rzdFoEhSBWRQkNLnbYTK2dx6C6/ORRviaizrbEkAY")]
    [InlineData("subj-p521.pub", "SHA256:spoCRjQVInD15Pu7sHd1EwPbN7U29Drmgo9/dIRNwRw")]
    [InlineData("ca-rsa.pub", "SHA256:jbAvjBehRx+7VpPzvSFkn81Z/1Q2pQwBJdrfuiRxBiM")]
    public void Fingerprints_match_ssh_keygen(string file, string fingerprint)
    {
        Assert.Equal(fingerprint, SshPublicKey.ParseAuthorizedKey(SshFixtures.Text(file)).Fingerprint);
    }

    [Fact]
    public void Surrounding_whitespace_tabs_and_a_missing_comment_are_accepted()
    {
        var parts = SshFixtures.Text("subj-ed25519.pub").Trim().Split(' ');

        var key = SshPublicKey.ParseAuthorizedKey($"  {parts[0]}\t{parts[1]}\r\n");

        Assert.Null(key.Comment);
        Assert.Equal(SshFixtures.Subject("ed25519"), key);
    }

    public static IEnumerable<object[]> Refused()
    {
        var ed = SshFixtures.Text("subj-ed25519.pub").Trim().Split(' ');
        var rsa = SshFixtures.Text("subj-rsa.pub").Trim().Split(' ');
        var p256 = SshFixtures.Text("subj-p256.pub").Trim().Split(' ');
        var blob = Convert.FromBase64String(ed[1]);
        var p256Blob = Convert.FromBase64String(p256[1]);
        var offCurve = (byte[])p256Blob.Clone();
        offCurve[^1] ^= 1;
        var compressed = new SshWriter().String(SshKeyTypes.EcdsaP256).String("nistp256").String([0x02, .. p256Blob[^64..^32]]).ToArray();
        var wrongCurve = new SshWriter().String(SshKeyTypes.EcdsaP256).String("nistp384").Raw(p256Blob[(4 + 19 + 4 + 8)..]).ToArray();
        var shortEd = new SshWriter().String(SshKeyTypes.Ed25519).String(new byte[31]).ToArray();

        return new[]
        {
            "",
            "   ",
            ed[1],
            $"{ed[0]}",
            $"{ed[0]} not-base64!",
            $"{rsa[0]} {ed[1]}",
            $"from=\"10.0.0.1\" {ed[0]} {ed[1]}",
            $"{ed[0]} {ed[1]}\n{ed[0]} {ed[1]}",
            $"{ed[0]} {Convert.ToBase64String([.. blob, 0])}",
            $"{ed[0]} {Convert.ToBase64String(blob[..^1])}",
            $"{ed[0]} {Convert.ToBase64String(shortEd)}",
            $"{p256[0]} {Convert.ToBase64String(offCurve)}",
            $"{p256[0]} {Convert.ToBase64String(compressed)}",
            $"{p256[0]} {Convert.ToBase64String(wrongCurve)}",
            SshFixtures.Text("user-ed25519-cert.pub"),
            $"sk-ssh-ed25519@openssh.com {ed[1]}",
            $"ssh-ed448 {ed[1]}",
            $"{ed[0]} {new string('A', SshPublicKey.MaxAuthorizedKeyLength)}",
        }.Select(line => new object[] { line });
    }

    [Theory]
    [MemberData(nameof(Refused))]
    public void Malformed_or_unsupported_lines_are_refused(string line)
    {
        Assert.Throws<FormatException>(() => SshPublicKey.ParseAuthorizedKey(line));
    }

    [Fact]
    public void A_dsa_key_parses_so_the_caller_can_refuse_it_by_name()
    {
        var dsa = SshPublicKey.FromKeyParameter(SshWireFormatGoldenTests.GenerateDsa().Public);

        var parsed = SshPublicKey.ParseAuthorizedKey(dsa.ToAuthorizedKey("old"));

        Assert.Equal(SshKeyTypes.Dss, parsed.KeyType);
        Assert.NotNull(SshCertificateRules.CheckSubjectKey(parsed, SshFixtures.CaPublic("ed25519")));
    }

    [Fact]
    public void A_private_key_is_not_a_public_key()
    {
        var pair = SshWireFormatGoldenTests.Generate("ed25519");
        Assert.Throws<ArgumentException>(() => SshPublicKey.FromKeyParameter(pair.Private));
    }
}
