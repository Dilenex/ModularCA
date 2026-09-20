using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// Replacing one section of config.yaml and nothing else.
/// <para>
/// Two tools now update that file after a deployment exists — the database migration writes its
/// DB section, the signer identity command writes its Signer section — and both must leave every
/// other section exactly as the operator left it. Bootstrap rewrites the whole file, which is
/// right on a first install and wrong ever after.
/// </para>
/// </summary>
public class YamlSectionSplicerTests
{
    private const string Config = """
        Https:
          PublicDomain: ca4.example.net
          PublicPort: 443

        Signer:
          Mode: InProcess
          Listen: 127.0.0.1:8446

        Features:
          MSAE: true
        """;

    [Fact]
    public void The_named_section_is_replaced_and_the_others_are_untouched()
    {
        var result = YamlSectionSplicer.Replace(Config, "Signer", new SignerConfig
        {
            Mode = SignerConfig.RemoteMode,
            Endpoint = "https://127.0.0.1:8446",
            PinnedClientSpki = "sha256/abc",
        });

        Assert.Contains("PublicDomain: ca4.example.net", result);
        Assert.Contains("MSAE: true", result);
        Assert.Contains("Mode: Remote", result);
        Assert.Contains("PinnedClientSpki: sha256/abc", result);
        Assert.DoesNotContain("Mode: InProcess", result);
    }

    [Fact]
    public void A_section_that_is_absent_is_appended()
    {
        var result = YamlSectionSplicer.Replace("Features:\n  MSAE: true\n", "Signer",
            new SignerConfig { Mode = SignerConfig.RemoteMode });

        Assert.StartsWith("Features:", result);
        Assert.Contains("Signer:", result);
        Assert.Contains("Mode: Remote", result);
    }

    [Fact]
    public void The_block_boundary_is_the_next_top_level_key_not_the_next_blank_line()
    {
        // A section with blank lines inside it is still one section. Ending the block at the
        // first blank line would leave the tail of the old section behind, under the new one,
        // where the loader would read whichever came last.
        const string withGap = """
            Signer:
              Mode: InProcess

              Listen: 127.0.0.1:8446
            Features:
              MSAE: true
            """;

        var result = YamlSectionSplicer.Replace(withGap, "Signer", new SignerConfig { Mode = SignerConfig.RemoteMode });

        Assert.DoesNotContain("Mode: InProcess", result);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(result, @"(?m)^\s+Listen:"));
        Assert.Contains("MSAE: true", result);
    }

    [Fact]
    public void A_key_that_merely_starts_with_the_section_name_is_not_the_section()
    {
        // "DB:" must not match "DBBackup:", or a splice aimed at one would eat the other.
        const string tricky = "DBBackup:\n  Enabled: true\nDB:\n  App:\n    Host: old\n";

        var result = YamlSectionSplicer.Replace(tricky, "DB",
            new DbConfig { App = new DbInstance { Host = "new" } });

        Assert.Contains("DBBackup:", result);
        Assert.Contains("Enabled: true", result);
        Assert.Contains("Host: new", result);
        Assert.DoesNotContain("Host: old", result);
    }

    [Fact]
    public void The_result_loads_back_as_the_node_reads_it()
    {
        // Proof that the rendering matches the loader, which is the only thing that matters:
        // a section that looks right and loads wrong is the failure mode this exists to prevent.
        var directory = Path.Combine(Path.GetTempPath(), "mca-splice-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "config.yaml");
        try
        {
            File.WriteAllText(path, YamlSectionSplicer.Replace(Config, "Signer", new SignerConfig
            {
                Mode = SignerConfig.RemoteMode,
                Endpoint = "https://127.0.0.1:8446",
                ClientCertificate = "config/signer-client.pfx",
                PinnedServerSpki = "sha256/server",
                PinnedClientSpki = "sha256/client",
                Listen = "127.0.0.1:8446",
            }));

            var loaded = YamlConfigLoader.Load(path);

            Assert.True(loaded.Signer.IsRemote);
            Assert.Equal("sha256/server", loaded.Signer.PinnedServerSpki);
            Assert.Equal("sha256/client", loaded.Signer.PinnedClientSpki);
            Assert.Equal("ca4.example.net", loaded.Https.PublicDomain);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
