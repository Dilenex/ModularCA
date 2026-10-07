using ModularCA.Bootstrap;
using ModularCA.Shared.Utils;
using Xunit;
using YamlDotNet.Serialization;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The ACME client matrix (tests/acme-clients) runs only in CI, against a container. These keep
/// its files honest where they can be checked without one: they parse, and the unattended install
/// they describe is the one <c>run.sh</c> and the clients' configuration address.
/// </summary>
public class AcmeClientMatrixFixtureTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string Fixture(params string[] parts)
        => Path.Combine([RepoRoot(), "tests", "acme-clients", .. parts]);

    [Theory]
    [InlineData("tests/acme-clients/compose.yaml")]
    [InlineData("tests/acme-clients/bootstrap.yaml")]
    [InlineData("tests/acme-clients/traefik/traefik.yaml")]
    [InlineData("tests/acme-clients/traefik/dynamic.yaml")]
    [InlineData(".github/workflows/acme-clients.yml")]
    public void Every_yaml_file_parses(string relative)
    {
        var path = Path.Combine(RepoRoot(), relative.Replace('/', Path.DirectorySeparatorChar));
        var parsed = new DeserializerBuilder().Build().Deserialize<object>(File.ReadAllText(path));
        Assert.IsType<Dictionary<object, object>>(parsed);
    }

    [Fact]
    public void The_install_serves_ACME_to_private_clients_under_the_name_the_clients_use()
    {
        var config = YamlBootstrapLoader.Load(Fixture("bootstrap.yaml"));

        Assert.True(config.Features.ACME);
        Assert.True(config.Acme.AllowPrivateAddressValidation);
        Assert.False(config.Administration.MultipleAdministrators);
        BootstrapServiceUrlBuilder.EnsurePublicDomainUsable(config.HttpsApi.PublicDomain);
        BootstrapCertCreator.EnsureWebTlsSansSupported(config.HttpsApi.SANs);
        BootstrapCertCreator.EnsureRootLabelUsable(config.CA.Subject.CN!);

        var publicName = BootstrapServiceUrlBuilder.ResolvePublicDomain(config.HttpsApi.PublicDomain, config.HttpsApi.SANs);
        var label = BootstrapCertCreator.LabelFor(config.CA.Subject.CN!);
        var directory = $"https://{publicName}:{config.HttpsApi.Port}/acme/{label}/directory";
        var root = $"http://{publicName}:{config.HttpsApi.HttpPort}/ca/{label}";

        Assert.Contains($"DIRECTORY={directory}\n", File.ReadAllText(Fixture("run.sh")).Replace("\r\n", "\n"));
        Assert.Contains(root, File.ReadAllText(Fixture("run.sh")));
        Assert.Contains($"acme_ca {directory}", File.ReadAllText(Fixture("Caddyfile")));
        Assert.Contains($"caServer: {directory}", File.ReadAllText(Fixture("traefik", "traefik.yaml")));

        var compose = File.ReadAllText(Fixture("compose.yaml"));
        Assert.Contains($"aliases: [{publicName}]", compose);
        Assert.Equal(2, compose.Split(directory).Length - 1);
    }

    /// <summary>Each client is reachable under the name it asks a certificate for.</summary>
    [Theory]
    [InlineData("certbot")]
    [InlineData("acmesh")]
    [InlineData("caddy")]
    [InlineData("traefik")]
    public void Each_client_has_its_name_on_the_network(string client)
    {
        Assert.Contains($"aliases: [{client}.acme.test]", File.ReadAllText(Fixture("compose.yaml")));
        Assert.Contains($"run_{client}()", File.ReadAllText(Fixture("run.sh")));
    }
}
