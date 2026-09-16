using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The signing profile bootstrap binds to the root CA must permit the CA's OWN infrastructure
/// EKUs — OCSP signing and time stamping — not just the leaf ones.
/// <para>
/// It was built from the three-entry leaf list, so "reissue infrastructure certificates" on the
/// primary CA always failed: it resolves the profile by <c>sp.IssuerId == caEntity.CertificateId</c>,
/// lands on exactly this profile, and <c>EnsureSigningProfilePermitsInfrastructureEkus</c>
/// refuses for both. The OCSP responder and TSA of the install's own CA could never be rotated,
/// including after a responder key compromise.
/// </para>
/// <para>
/// It stayed invisible because bootstrap issues those two certificates through
/// <c>BootstrapCertCreator</c>, which hardcodes the EKU and bypasses the profile — so the
/// defect only surfaced at the first reissue, long after install.
/// </para>
/// </summary>
public class BootstrapSigningProfileEkuTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string Read(string relativePath)
    {
        var path = Path.Combine(RepoRoot(), relativePath);
        Assert.True(File.Exists(path), $"expected {path}");
        return File.ReadAllText(path);
    }

    public static TheoryData<string> BootstrapPaths() => new()
    {
        Path.Combine("ModularCA.Bootstrap", "BootstrapService.cs"),      // setup wizard
        Path.Combine("ModularCA.Bootstrap", "BootstrapModularCA.cs"),    // --bootstrap CLI
    };

    [Theory]
    [MemberData(nameof(BootstrapPaths))]
    public void The_signing_profile_is_seeded_from_the_full_infrastructure_eku_list(string relativePath)
    {
        var source = Read(relativePath);

        var call = Regex.Match(source,
            @"CertExtendedOidsJson\s*=\s*BootstrapProfileSeeder\.SetupAllowedExtendedOidsJson\(\s*(?<list>\w+)\s*,");
        Assert.True(call.Success, $"could not find the signing profile's EKU seeding call in {relativePath}");

        Assert.Equal("allowedRootCaExtendedOids", call.Groups["list"].Value);
    }

    [Theory]
    [MemberData(nameof(BootstrapPaths))]
    public void That_list_contains_ocsp_signing_and_time_stamping(string relativePath)
    {
        var source = Read(relativePath);

        var decl = Regex.Match(source, @"allowedRootCaExtendedOids\s*=\s*new\[\]\s*\{(?<items>[^}]*)\}");
        Assert.True(decl.Success, $"could not find allowedRootCaExtendedOids in {relativePath}");

        var items = decl.Groups["items"].Value;
        Assert.Contains("OCSP Signer", items, StringComparison.Ordinal);
        Assert.Contains("Time Stamping", items, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("config/bootstrap.yaml.example")]
    [InlineData("ModularCA.Bootstrap/bootstrap.yaml.example")]
    public void The_shipped_template_does_not_enable_enrollment_protocols(string relativePath)
    {
        // YamlBootstrapLoader.FeaturesConfig defaults these to false on purpose, and the setup
        // wizard leaves them unticked. The template shipped them all true, so a CLI install from
        // the documented starting point exposed ACME, EST, SCEP and CMP — with their request
        // profiles seeded RequireApproval = false — that the operator never asked for.
        var text = Read(relativePath.Replace('/', Path.DirectorySeparatorChar));

        foreach (var protocol in new[] { "ACME", "EST", "SCEP", "CMP", "MSAE" })
        {
            var match = Regex.Match(text, $@"^\s*{protocol}:\s*(?<value>\w+)", RegexOptions.Multiline);
            Assert.True(match.Success, $"{protocol} not found in {relativePath}");
            Assert.Equal("false", match.Groups["value"].Value);
        }

        // Revocation publishing stays on — a PKI cannot function without it.
        foreach (var always in new[] { "CRL", "OCSP" })
        {
            var match = Regex.Match(text, $@"^\s*{always}:\s*(?<value>\w+)", RegexOptions.Multiline);
            Assert.True(match.Success, $"{always} not found in {relativePath}");
            Assert.Equal("true", match.Groups["value"].Value);
        }
    }
}
