using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using Xunit;

namespace ModularCA.Tests.Shared.Settings;

/// <summary>
/// The catalog decides which settings leave <c>config.yaml</c> for the database. A setting put in
/// the wrong class either loses a per-host value at the import or leaves a secret readable in a
/// table, so the classes that matter are pinned here and a new setting has to be placed on
/// purpose.
/// </summary>
public class SettingsCatalogTests
{
    /// <summary>
    /// Building the catalog is the check that every leaf of <see cref="SystemConfig"/> carries a
    /// <c>[Setting]</c>: it throws, naming the property, when one does not.
    /// </summary>
    [Fact]
    public void Every_setting_declares_where_it_lives_and_how_it_reloads()
    {
        Assert.True(SettingsCatalog.Definitions.Count > 200, $"only {SettingsCatalog.Definitions.Count} settings were found");
    }

    [Fact]
    public void A_key_is_the_property_path_joined_by_underscores()
    {
        foreach (var definition in SettingsCatalog.Definitions)
        {
            Assert.Matches(new Regex("^[A-Za-z0-9]+(_[A-Za-z0-9]+)*$"), definition.Key);
            Assert.Equal(definition.Path.Replace('.', '_'), definition.Key);
            Assert.Equal(definition.Key.Split('_')[0], definition.Section);
            Assert.Same(definition, SettingsCatalog.Find(definition.Key));
        }

        Assert.NotNull(SettingsCatalog.Find("Acme_Http01_MaxAddresses"));
        Assert.NotNull(SettingsCatalog.Find("Audit_Retention_GeneralRetentionDays"));
        Assert.NotNull(SettingsCatalog.Find("DB_App_Host"));
        Assert.Null(SettingsCatalog.Find("acme_http01_maxaddresses"));
        Assert.Null(SettingsCatalog.Find("Acme"));
    }

    /// <summary>
    /// The database connection cannot come from the database, and the signer reads nothing but
    /// its own directory. These sections never have a row.
    /// </summary>
    [Theory]
    [InlineData("DB", SettingClass.Bootstrap)]
    [InlineData("Schema", SettingClass.Bootstrap)]
    [InlineData("Hsm", SettingClass.SignerLocal)]
    [InlineData("Ingress", SettingClass.HostLocal)]
    [InlineData("Redis", SettingClass.HostLocal)]
    [InlineData("SshCa", SettingClass.HostLocal)]
    [InlineData("PolicySync", SettingClass.HostLocal)]
    [InlineData("Roles", SettingClass.HostLocal)]
    public void A_section_that_stays_in_files_has_no_setting_in_the_database(string section, SettingClass expected)
    {
        var settings = SettingsCatalog.Definitions.Where(d => d.Section == section).ToList();

        Assert.NotEmpty(settings);
        Assert.All(settings, d =>
        {
            Assert.Equal(expected, d.Class);
            Assert.False(d.StoredInDatabase);
        });
    }

    [Fact]
    public void The_signer_section_is_split_between_the_signer_and_the_host_and_none_of_it_is_in_the_database()
    {
        var signer = SettingsCatalog.Definitions.Where(d => d.Section == "Signer").ToList();

        Assert.Contains(signer, d => d.Class == SettingClass.SignerLocal);
        Assert.Contains(signer, d => d.Class == SettingClass.HostLocal);
        Assert.All(signer, d => Assert.False(d.StoredInDatabase));
    }

    /// <summary>Listeners, files and network position describe one host.</summary>
    [Theory]
    [InlineData("Https_Port")]
    [InlineData("Https_ListenAddress")]
    [InlineData("Https_CertificatePath")]
    [InlineData("Https_CertificatePassword")]
    [InlineData("Http_Port")]
    [InlineData("Http_TrustedProxyCidrs")]
    [InlineData("Security_BehindReverseProxy")]
    [InlineData("Logging_FilePath")]
    [InlineData("Backup_OutputPath")]
    [InlineData("Backup_EncryptionKeyPath")]
    [InlineData("Mtls_TrustedCaCertPaths")]
    [InlineData("Audit_Retention_ArchivePath")]
    public void A_setting_that_describes_one_host_stays_on_that_host(string key)
    {
        Assert.Equal(SettingClass.HostLocal, SettingsCatalog.Find(key)!.Class);
    }

    /// <summary>Exactly these are secrets in the database. Adding one is a decision, made here.</summary>
    [Fact]
    public void The_secrets_are_the_ones_listed_and_each_says_how_it_is_kept()
    {
        var secrets = SettingsCatalog.Definitions
            .Where(d => d.Class == SettingClass.Secret)
            .ToDictionary(d => d.Key, d => d.Secret);

        Assert.Equal(
            new Dictionary<string, SettingSecretKind>
            {
                ["JWT_Secret"] = SettingSecretKind.Wrapped,
                ["LdapAuth_BindPassword"] = SettingSecretKind.Wrapped,
                ["Email_Password"] = SettingSecretKind.Wrapped,
                ["Email_OAuth2AccessToken"] = SettingSecretKind.Wrapped,
                ["Email_OAuth2ClientSecret"] = SettingSecretKind.Wrapped,
                ["Webhook_Endpoints"] = SettingSecretKind.Wrapped,
                ["IntegrationApi_ApiKey"] = SettingSecretKind.Hashed,
                ["CertManager_ApiKey"] = SettingSecretKind.Hashed,
            }.OrderBy(p => p.Key),
            secrets.OrderBy(p => p.Key));

        Assert.All(SettingsCatalog.Definitions.Where(d => d.Class != SettingClass.Secret),
            d => Assert.Equal(SettingSecretKind.None, d.Secret));
    }

    /// <summary>
    /// A name that reads like a credential is never an ordinary database setting, whose value
    /// would sit readable in the table, its history and the audit record.
    /// </summary>
    [Fact]
    public void Nothing_named_like_a_credential_is_stored_as_an_ordinary_setting()
    {
        var credential = new Regex("(Password|Secret|Pin|ApiKey|AccessToken)$");

        var exposed = SettingsCatalog.Definitions
            .Where(d => d.Class == SettingClass.InstanceWide && credential.IsMatch(d.Key))
            .Select(d => d.Key);

        Assert.Empty(exposed);
    }

    /// <summary>
    /// Every setting's built-in default goes to JSON and back unchanged, so each type in the
    /// configuration can be stored: lists, the job timeout dictionary, enums, nullable numbers.
    /// </summary>
    [Fact]
    public void Every_default_survives_the_trip_through_json()
    {
        var defaults = new SystemConfig();
        var target = new SystemConfig();

        foreach (var definition in SettingsCatalog.Definitions)
        {
            var value = SettingsCatalog.Read(defaults, definition);
            if (value == null) continue;

            Assert.Null(SettingsCatalog.Problem(definition, value));
            var canonical = SettingsCatalog.CanonicalJson(definition, value);
            SettingsCatalog.Apply(target, definition, JsonNode.Parse(canonical));
            Assert.Equal(canonical, SettingsCatalog.CanonicalJson(definition, SettingsCatalog.Read(target, definition)));
        }
    }

    /// <summary>A dictionary has no order of its own, so the stored text cannot depend on one.</summary>
    [Fact]
    public void One_value_has_one_stored_spelling()
    {
        var jobTimeouts = SettingsCatalog.Find("Scheduler_JobTimeouts")!;

        Assert.Equal(
            SettingsCatalog.CanonicalJson(jobTimeouts, JsonNode.Parse("{ \"Zeta\": 5, \"Alpha\": 9 }")),
            SettingsCatalog.CanonicalJson(jobTimeouts, JsonNode.Parse("{\"Alpha\":9,\"Zeta\":5}")));
        Assert.Equal("{\"Alpha\":9,\"Zeta\":5}", SettingsCatalog.CanonicalJson(jobTimeouts, JsonNode.Parse("{\"Zeta\":5,\"Alpha\":9}")));
        Assert.Equal("null", SettingsCatalog.CanonicalJson(SettingsCatalog.Find("Http_PublicPort")!, null));
    }

    [Fact]
    public void A_value_has_to_be_of_the_settings_type()
    {
        var maxAddresses = SettingsCatalog.Find("Acme_Http01_MaxAddresses")!;
        Assert.Null(SettingsCatalog.Problem(maxAddresses, JsonValue.Create(8)));
        Assert.Contains("a number", SettingsCatalog.Problem(maxAddresses, JsonValue.Create("eight")));
        Assert.Contains("cannot be null", SettingsCatalog.Problem(maxAddresses, null));

        var failMode = SettingsCatalog.Find("Audit_FailMode")!;
        Assert.Null(SettingsCatalog.Problem(failMode, JsonValue.Create(nameof(AuditFailMode.FailClosed))));
        Assert.Contains("one of", SettingsCatalog.Problem(failMode, JsonValue.Create("Sometimes")));

        var exemptPaths = SettingsCatalog.Find("IpWhitelist_ExemptPaths")!;
        Assert.Null(SettingsCatalog.Problem(exemptPaths, new JsonArray("/health")));
        Assert.Contains("a list", SettingsCatalog.Problem(exemptPaths, JsonValue.Create("/health")));

        var publicPort = SettingsCatalog.Find("Http_PublicPort")!;
        Assert.True(publicPort.AllowsNull);
        Assert.Null(SettingsCatalog.Problem(publicPort, null));
    }

    [Fact]
    public void Applying_a_value_changes_that_setting_and_no_other()
    {
        var config = new SystemConfig();
        var before = config.Acme.Http01.TimeoutSeconds;

        SettingsCatalog.Apply(config, SettingsCatalog.Find("Acme_Http01_MaxAddresses")!, JsonValue.Create(9));
        SettingsCatalog.Apply(config, SettingsCatalog.Find("IpWhitelist_ExemptPaths")!, new JsonArray("/only"));

        Assert.Equal(9, config.Acme.Http01.MaxAddresses);
        Assert.Equal(before, config.Acme.Http01.TimeoutSeconds);
        // A list replaces the default whole; it is not merged into it.
        Assert.Equal(["/only"], config.IpWhitelist.ExemptPaths);
    }
}
