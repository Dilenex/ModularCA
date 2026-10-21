using ModularCA.Bootstrap;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// ACME and CMP refuse a request whose request profile requires approval, because neither lets a
/// client come back for a certificate approved later. The request profiles a new install gives
/// them must therefore not require approval, or those protocols could never issue.
/// </summary>
public sealed class SeededProtocolApprovalTests
{
    [Theory]
    [InlineData("WebServer", "Web Server (ACME)")]
    [InlineData("EnterpriseUser", "Enterprise User (CMP)")]
    public void The_seeded_profile_of_a_protocol_that_cannot_wait_does_not_require_approval(string key, string name)
    {
        using var db = InMemoryDbContextFactory.Create();

        var profiles = BootstrapProfileSeeder.SeedDefaultRequestProfiles(db);

        var profile = profiles[key];
        Assert.Equal(name, profile.Name);
        Assert.False(profile.RequireApproval);
        Assert.DoesNotContain("approval", profile.Description ?? "", StringComparison.OrdinalIgnoreCase);
    }
}
