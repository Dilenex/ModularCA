using ModularCA.Shared.Ssh;
using Xunit;

namespace ModularCA.Tests.Shared.Ssh;

/// <summary>The key-level checks the signer will run before signing an SSH certificate.</summary>
public class SshCertificateRulesTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    private static readonly SshCaLimits Limits = new(AllowUser: true, AllowHost: true, MaxValidity: TimeSpan.FromHours(24));

    private static SshCertificateFields Valid(SshCertificateType type = SshCertificateType.User) => new()
    {
        SubjectKey = SshFixtures.Subject("ed25519"),
        Type = type,
        Serial = 1,
        KeyId = "k",
        Principals = ["alice"],
        ValidAfter = 1_800_000_000,
        ValidBefore = 1_800_000_000 + 3600,
        CriticalOptions = type == SshCertificateType.User
            ? [new("force-command", "/bin/true"), new("source-address", "10.0.0.0/8,192.0.2.1,2001:db8::/32"), new("verify-required")]
            : [],
        Extensions = type == SshCertificateType.User ? [new("permit-pty"), new("no-touch-required")] : [],
    };

    private static string? Check(SshCertificateFields fields, SshCaLimits? limits = null) =>
        SshCertificateRules.Check(fields, SshFixtures.CaPublic("p256"), limits ?? Limits, Now);

    [Theory]
    [InlineData(SshCertificateType.User)]
    [InlineData(SshCertificateType.Host)]
    public void A_well_formed_certificate_passes(SshCertificateType type)
    {
        Assert.Null(Check(Valid(type)));
    }

    [Fact]
    public void An_empty_principal_list_is_refused()
    {
        Assert.Contains("principal", Check(Valid() with { Principals = [] }));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a\nb")]
    public void A_bad_principal_is_refused(string principal)
    {
        Assert.NotNull(Check(Valid() with { Principals = ["alice", principal] }));
    }

    [Fact]
    public void Principal_length_count_and_repeats_are_bounded()
    {
        Assert.Null(Check(Valid() with { Principals = [new string('a', 256)] }));
        Assert.NotNull(Check(Valid() with { Principals = [new string('a', 257)] }));
        Assert.NotNull(Check(Valid() with { Principals = [new string('é', 129)] }));
        Assert.NotNull(Check(Valid() with { Principals = Enumerable.Range(0, 257).Select(i => $"u{i}").ToList() }));
        Assert.NotNull(Check(Valid() with { Principals = ["alice", "alice"] }));
    }

    [Fact]
    public void Serial_zero_is_refused()
    {
        Assert.NotNull(Check(Valid() with { Serial = 0 }));
    }

    [Fact]
    public void A_type_the_key_is_not_configured_for_is_refused()
    {
        Assert.NotNull(Check(Valid(SshCertificateType.User), Limits with { AllowUser = false }));
        Assert.NotNull(Check(Valid(SshCertificateType.Host), Limits with { AllowHost = false }));
        Assert.NotNull(Check(Valid() with { Type = (SshCertificateType)3 }));
    }

    [Fact]
    public void Validity_is_bounded_by_the_key_maximum_and_the_clock()
    {
        var start = (ulong)Now.ToUnixTimeSeconds();
        Assert.Null(Check(Valid() with { ValidAfter = start, ValidBefore = start + 24 * 3600 }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start, ValidBefore = start + 24 * 3600 + 1 }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start, ValidBefore = start }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start + 10, ValidBefore = start }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start, ValidBefore = SshCertificateFields.Forever }));
        Assert.Null(Check(Valid() with { ValidAfter = start - 300, ValidBefore = start + 3600 }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start - 301, ValidBefore = start + 3600 }));
        Assert.Null(Check(Valid() with { ValidAfter = start + 300, ValidBefore = start + 3600 }));
        Assert.NotNull(Check(Valid() with { ValidAfter = start + 301, ValidBefore = start + 3600 }));
        Assert.NotNull(Check(Valid() with { ValidAfter = 0, ValidBefore = 3600 }));
    }

    [Fact]
    public void The_clock_skew_allowance_is_a_parameter()
    {
        var start = (ulong)Now.ToUnixTimeSeconds();
        var backdated = Valid() with { ValidAfter = start - 600, ValidBefore = start + 3600 };

        Assert.NotNull(SshCertificateRules.Check(backdated, SshFixtures.CaPublic("p256"), Limits, Now));
        Assert.Null(SshCertificateRules.Check(backdated, SshFixtures.CaPublic("p256"), Limits, Now, TimeSpan.FromMinutes(10)));
    }

    public static IEnumerable<object[]> BadUserOptions() => new (SshOption[] Critical, SshOption[] Extensions)[]
    {
        ([new("permit-pty")], []),
        ([new("no-such-option", "x")], []),
        ([new("force-command")], []),
        ([new("force-command", "a\nb")], []),
        ([new("force-command", "a"), new("force-command", "b")], []),
        ([new("verify-required", "yes")], []),
        ([new("source-address")], []),
        ([new("source-address", "10.0.0.1/8")], []),
        ([new("source-address", "example.com")], []),
        ([new("source-address", "10.0.0.0/8,")], []),
        ([new("source-address", "1")], []),
        ([new("source-address", "10.0.0.0/33")], []),
        ([], [new("force-command", "/bin/sh")]),
        ([], [new("permit-everything")]),
        ([], [new("login@example.com", "alice")]),
        ([], [new("permit-pty", "yes")]),
        ([], [new("permit-pty"), new("permit-pty")]),
    }.Select(x => new object[] { x.Critical, x.Extensions });

    [Theory]
    [MemberData(nameof(BadUserOptions))]
    public void Unknown_repeated_or_malformed_options_are_refused(SshOption[] critical, SshOption[] extensions)
    {
        Assert.NotNull(Check(Valid() with { CriticalOptions = critical, Extensions = extensions }));
    }

    [Fact]
    public void A_host_certificate_carries_no_options_or_extensions()
    {
        Assert.NotNull(Check(Valid(SshCertificateType.Host) with { CriticalOptions = [new("force-command", "/bin/true")] }));
        Assert.NotNull(Check(Valid(SshCertificateType.Host) with { Extensions = [new("permit-pty")] }));
    }

    [Fact]
    public void Every_known_user_extension_is_accepted()
    {
        Assert.Null(Check(Valid() with { Extensions = SshCertificateRules.UserExtensions.Select(n => new SshOption(n)).ToList() }));
    }

    [Fact]
    public void Subject_keys_are_limited_to_the_certifiable_types_and_sizes()
    {
        var ca = SshFixtures.CaPublic("p256");
        foreach (var subject in new[] { "ed25519", "p256", "p384", "p521", "rsa" })
            Assert.Null(SshCertificateRules.CheckSubjectKey(SshFixtures.Subject(subject), ca));

        Assert.NotNull(SshCertificateRules.CheckSubjectKey(ca, ca));

        var smallRsa = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
        smallRsa.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), 1024));
        Assert.NotNull(SshCertificateRules.CheckSubjectKey(SshPublicKey.FromKeyParameter(smallRsa.GenerateKeyPair().Public), ca));
    }
}
