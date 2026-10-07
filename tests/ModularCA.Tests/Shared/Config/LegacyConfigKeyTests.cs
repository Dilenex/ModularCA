using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Xunit;

namespace ModularCA.Tests.Shared.Config;

/// <summary>
/// The config keys renamed in 0.4.0 still load under their old names. A legacy key read as
/// nothing would leave an integration API key unscoped, so the loader moves it, refuses a
/// conflict, and warns until the file is renamed; the first save writes only the new key.
/// </summary>
public sealed class LegacyConfigKeyTests : IDisposable
{
    private const string Space = "6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60";
    private const string Other = "0f8fad5b-d9cb-469f-a165-70867728950e";
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"legacy-config-{Guid.NewGuid():N}.yaml");
    private readonly List<string> _warnings = [];

    public void Dispose() => File.Delete(_path);

    private SystemConfig Load(string yaml)
    {
        File.WriteAllText(_path, yaml);
        return YamlConfigLoader.Load(_path, _warnings.Add);
    }

    [Fact]
    public void A_legacy_key_loads_into_SpaceId_with_a_warning_naming_the_file_and_key()
    {
        var config = Load($"IntegrationApi:\n  Enabled: true\n  TenantId: {Space}\nCertManager:\n  TenantId: {Space}\n");

        Assert.Equal(Guid.Parse(Space), config.IntegrationApi.SpaceScope().SpaceId);
        Assert.Equal(Guid.Parse(Space), config.CertManager.SpaceScope().SpaceId);
        Assert.True(config.IntegrationApi.Enabled);
        Assert.Equal(2, _warnings.Count);
        Assert.Contains(_warnings, w => w.Contains("IntegrationApi.TenantId") && w.Contains(_path) && w.Contains("IntegrationApi.SpaceId"));
        Assert.Contains(_warnings, w => w.Contains("CertManager.TenantId"));
    }

    [Fact]
    public void Both_keys_set_and_different_refuse_to_start()
    {
        var ex = Assert.Throws<ConfigKeyConflictException>(() =>
            Load($"IntegrationApi:\n  TenantId: {Space}\n  SpaceId: {Other}\n"));

        Assert.Contains(_path, ex.Message);
        Assert.Contains("IntegrationApi.TenantId", ex.Message);
        Assert.Contains("IntegrationApi.SpaceId", ex.Message);
    }

    [Fact]
    public void Both_keys_set_to_the_same_space_load_with_a_warning()
    {
        var config = Load($"CertManager:\n  TenantId: {Space.ToUpperInvariant()}\n  SpaceId: {Space}\n");

        Assert.Equal(Guid.Parse(Space), config.CertManager.SpaceScope().SpaceId);
        Assert.Single(_warnings);
    }

    [Fact]
    public void An_empty_new_key_takes_the_legacy_value()
    {
        var config = Load($"IntegrationApi:\n  SpaceId:\n  TenantId: {Space}\n");

        Assert.Equal(Guid.Parse(Space), config.IntegrationApi.SpaceScope().SpaceId);
    }

    [Fact]
    public void A_config_without_legacy_keys_loads_silently()
    {
        var config = Load($"IntegrationApi:\n  SpaceId: {Space}\n");

        Assert.Equal(Guid.Parse(Space), config.IntegrationApi.SpaceScope().SpaceId);
        Assert.Empty(_warnings);
    }

    [Theory]
    [InlineData("IntegrationApi:\n  SpaceId: instance\n")]
    [InlineData("IntegrationApi:\n  TenantId: instance\n")]
    [InlineData("IntegrationApi:\n  SpaceId: Instance\n")]
    public void Instance_scopes_a_key_to_the_instance_CAs_under_either_key(string yaml)
    {
        var scope = Load(yaml).IntegrationApi.SpaceScope();

        Assert.Equal(IntegrationScopeKind.Instance, scope.Kind);
        Assert.True(scope.Allows(null));
        Assert.False(scope.Allows(Guid.Parse(Space)));
    }

    [Fact]
    public void Unset_reaches_every_CA_a_space_id_its_space_and_anything_else_nothing()
    {
        var everything = IntegrationSpaceScope.Parse(null);
        Assert.False(everything.IsRestricted);
        Assert.True(everything.Allows(null) && everything.Allows(Guid.Parse(Space)));

        var space = IntegrationSpaceScope.Parse(Space.ToUpperInvariant());
        Assert.Equal((IntegrationScopeKind.Space, (Guid?)Guid.Parse(Space)), (space.Kind, space.SpaceId));
        Assert.True(space.Allows(Guid.Parse(Space)));
        Assert.False(space.Allows(null));
        Assert.False(space.Allows(Guid.Parse(Other)));

        var typo = IntegrationSpaceScope.Parse("instanse");
        Assert.Equal(IntegrationScopeKind.Invalid, typo.Kind);
        Assert.True(typo.IsRestricted);
        Assert.False(typo.Allows(null) || typo.Allows(Guid.Parse(Space)));
    }

    [Fact]
    public void The_retired_multiple_organisations_flag_is_ignored_with_a_warning()
    {
        var config = Load("Features:\n  AllowMultipleOrganizations: false\n");

        Assert.NotNull(config);
        var warning = Assert.Single(_warnings);
        Assert.Contains("Features.AllowMultipleOrganizations", warning);
        Assert.Contains("retired", warning);
    }

    [Fact]
    public void Saving_writes_only_the_new_key()
    {
        var config = Load($"IntegrationApi:\n  TenantId: {Space}\nCertManager:\n  TenantId: {Space}\nFeatures:\n  AllowMultipleOrganizations: true\n");

        // The serializer AdminConfigController.PersistConfig writes config.yaml with.
        var yaml = new SerializerBuilder().WithNamingConvention(PascalCaseNamingConvention.Instance).Build().Serialize(config);

        Assert.DoesNotContain("TenantId", yaml);
        Assert.DoesNotContain("AllowMultipleOrganizations", yaml);
        Assert.Contains($"SpaceId: {Space}", yaml);
        _warnings.Clear();
        File.WriteAllText(_path, yaml);
        Assert.Equal(Guid.Parse(Space), YamlConfigLoader.Load(_path, _warnings.Add).IntegrationApi.SpaceScope().SpaceId);
        Assert.Empty(_warnings);
    }
}
