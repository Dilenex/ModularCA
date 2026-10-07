using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Xunit;

namespace ModularCA.Tests.Core.Helpers;

/// <summary>
/// The signer lists SSH CA keys beside X.509 keys, each under a row id. A caller that asks
/// whether the signer holds the key of a certificate must not take an SSH CA key listed under
/// the same id for it (<c>docs/architecture/ssh-keystore.md</c>, "Carried from stage 2").
/// </summary>
public sealed class X509SignerKeysTests
{
    private static readonly byte[] Spki = [0x30, 0x00];

    private static KeyInfo Key(Guid id, KeyKind kind, string keystore = KeyRef.DefaultKeystore)
        => new(new KeyRef(id, keystore), Spki, kind, Guid.NewGuid(), null, SignerHealth.SoftwareBackend);

    [Fact]
    public void An_ssh_ca_key_is_never_the_key_of_a_certificate_whatever_id_it_is_listed_under()
    {
        var id = Guid.NewGuid();
        var ssh = Key(id, KeyKind.SshCa, KeyRef.SshKeystore);
        var mislabelled = Key(id, KeyKind.Ca, KeyRef.SshKeystore);
        var misfiled = Key(id, KeyKind.SshCa);
        var ca = Key(id, KeyKind.Ca);

        Assert.False(X509SignerKeys.Holds([ssh], id));
        Assert.False(X509SignerKeys.Holds([mislabelled], id));
        Assert.False(X509SignerKeys.Holds([misfiled], id));
        Assert.Null(X509SignerKeys.Find([ssh, mislabelled, misfiled], id));
        Assert.Same(ca, X509SignerKeys.Find([ssh, ca], id));
        Assert.False(X509SignerKeys.Holds([ca], Guid.NewGuid()));
        Assert.All(new[] { KeyKind.Ca, KeyKind.OcspResponder, KeyKind.Tsa, KeyKind.CmpSigner, KeyKind.EndEntity, KeyKind.Unknown },
            kind => Assert.True(X509SignerKeys.Holds([Key(id, kind)], id)));
    }

    /// <summary>The signer's list as it would be if every X.509 key in it were an SSH CA key under the same id.</summary>
    private static RelayingSigner ListingOnlySshKeys(SignerTestWorld world)
        => new(TestSigner.Over(world.Keystore, world.DatabaseName))
        {
            RewriteListed = listed => listed.Select(k => k with { Kind = KeyKind.SshCa, Key = new KeyRef(k.Key.CertificateId, KeyRef.SshKeystore) }).ToList(),
        };

    [Fact]
    public async Task The_timestamp_service_does_not_take_an_ssh_ca_key_for_its_tsa_key()
    {
        var world = SignerTestWorld.Create();
        using var db = world.OpenDb();
        var request = new TimeStampRequestGenerator().Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.One);

        var held = new TimeStampResponse(await new TimestampService(db, NullLogger<TimestampService>.Instance, TestSigner.Over(world.Keystore, world.DatabaseName))
            .ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-rsa"));
        Assert.Equal(0, held.Status);

        var response = new TimeStampResponse(await new TimestampService(db, NullLogger<TimestampService>.Instance, ListingOnlySshKeys(world))
            .ProcessTimestampRequestAsync(request.GetEncoded(), "signer-test-rsa"));

        Assert.NotEqual(0, response.Status);
        Assert.Null(response.TimeStampToken);
    }

    [Fact]
    public async Task Ca_creation_does_not_take_an_ssh_ca_key_for_the_key_of_a_ca()
    {
        var world = SignerTestWorld.Create();
        using var db = world.OpenDb();
        var service = new CaCreationService(db, null!, null!, null!, null!, new SystemConfig(), NullLogger<CaCreationService>.Instance, ListingOnlySshKeys(world));

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => service.ReissueInfrastructureCertsAsync(world.CaRsaId, reissueOcsp: true, reissueTsa: false));

        Assert.Equal(ErrorCodes.IssuingCaKeyUnavailable, ex.Code);
    }

    /// <summary>
    /// Every caller of <c>ListKeysAsync</c> that looks a key up by certificate id does it through
    /// <see cref="X509SignerKeys"/>; none compares the id itself.
    /// </summary>
    [Theory]
    [InlineData("ModularCA.Core/Services/CaCreationService.cs", 1)]
    [InlineData("ModularCA.Core/Services/Ocsp/OcspResponderService.cs", 1)]
    [InlineData("ModularCA.Core/Services/TimestampService.cs", 1)]
    [InlineData("ModularCA.Core/Services/Scep/ScepService.cs", 1)]
    [InlineData("ModularCA.Core/Services/Cmp/CmpService.cs", 2)]
    public void A_consumer_of_the_signer_s_key_list_looks_a_key_up_through_the_one_helper(string path, int lookups)
    {
        var source = File.ReadAllText(Path.Combine(RepoRoot(), path.Replace('/', Path.DirectorySeparatorChar)));

        Assert.Equal(lookups, System.Text.RegularExpressions.Regex.Matches(source, @"X509SignerKeys\.(Holds|Find)\(").Count);
        Assert.DoesNotMatch(@"\.Key\.CertificateId\s*==", source);
    }

    [Fact]
    public void No_other_source_of_the_node_matches_a_listed_key_by_id_alone()
    {
        var root = RepoRoot();
        var offenders = new[] { "ModularCA.Core", "ModularCA.API", "ModularCA.Auth", "ModularCA.Bootstrap" }
            .SelectMany(project => Directory.EnumerateFiles(Path.Combine(root, project), "*.cs", SearchOption.AllDirectories))
            .Select(file => Path.GetRelativePath(root, file).Replace('\\', '/'))
            .Where(file => !file.Contains("/bin/") && !file.Contains("/obj/") && file != "ModularCA.Core/Helpers/X509SignerKeys.cs")
            .Where(file => System.Text.RegularExpressions.Regex.IsMatch(File.ReadAllText(Path.Combine(root, file)), @"\.Key\.CertificateId\s*=="))
            .ToList();

        Assert.True(offenders.Count == 0, "Look a listed key up through X509SignerKeys: " + string.Join(", ", offenders));
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
