using ModularCA.Bootstrap;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// <see cref="BootstrapInputSections"/>: a setup request or bootstrap.yaml whose required section
/// deserialized to null is refused by name before the bootstrap changes anything, instead of
/// failing later with a null reference. Optional sections may be empty.
/// </summary>
public sealed class BootstrapInputSectionsTests
{
    [Fact]
    public void A_complete_setup_request_passes()
    {
        BootstrapInputSections.EnsureSetupSectionsPresent(new SetupRequest());
    }

    [Fact]
    public void A_setup_request_with_empty_sections_is_refused_naming_each()
    {
        var request = new SetupRequest { Admin = null!, WebTlsCertificate = null!, Security = null! };

        var ex = Assert.Throws<InvalidRequestException>(() => BootstrapInputSections.EnsureSetupSectionsPresent(request));

        Assert.Equal(ErrorCodes.RequestInvalid, ex.Code);
        Assert.Contains("admin", ex.Message);
        Assert.Contains("webTlsCertificate", ex.Message);
        Assert.DoesNotContain("security", ex.Message); // optional: the procedure reads it with ?.
    }

    /// <summary>
    /// The wizard's entry point answers the refusal as a failed setup response, before it reads
    /// any file or touches a database.
    /// </summary>
    [Fact]
    public void The_wizard_answers_an_empty_admin_section_with_a_refusal()
    {
        var response = BootstrapService.RunFromSetupRequest(new SetupRequest { Admin = null! });

        Assert.False(response.Success);
        Assert.Contains("admin", response.Message);
        Assert.Contains(ErrorCodes.RequestInvalid, response.Message);
    }

    [Fact]
    public void A_bootstrap_yaml_with_a_bare_section_key_is_refused_naming_it()
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, "CA:\n  ValidityYears: 10\nHttpsApi:\nAdministration:\n");
        try
        {
            var config = YamlBootstrapLoader.Load(path);
            Assert.Null(config.HttpsApi); // what the deserializer really does with a bare key

            var ex = Assert.Throws<InvalidRequestException>(() => BootstrapInputSections.EnsureBootstrapSectionsPresent(config));
            Assert.Contains("HttpsApi", ex.Message);
            Assert.DoesNotContain("Administration", ex.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
