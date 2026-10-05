using System.Text.RegularExpressions;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// Text assertions on the systemd units and the Debian packaging that the schema startup check
/// relies on: exit status 3 is not retried, the signer starts after the node, an upgrade restarts
/// exactly the units that were running, and the one database step the package takes runs the
/// root-owned repair through the root-owned helper and never fails the install.
/// </summary>
public class DeploymentFileTests
{
    [Theory]
    [InlineData("deploy/modularca.service")]
    [InlineData("deploy/modularca-signer.service")]
    public void Both_units_do_not_retry_exit_status_3(string unit)
    {
        Assert.Contains("RestartPreventExitStatus=3", Directives(unit));
    }

    [Fact]
    public void The_signer_starts_after_the_node_and_never_before_it()
    {
        var directives = Directives("deploy/modularca-signer.service");

        var after = Assert.Single(directives, d => d.StartsWith("After=", StringComparison.Ordinal));
        Assert.Contains("modularca.service", after.Split('=', 2)[1].Split(' ', StringSplitOptions.RemoveEmptyEntries));
        Assert.DoesNotContain(directives, d => d.StartsWith("Before=", StringComparison.Ordinal) && d.Contains("modularca.service"));
    }

    [Fact]
    public void The_signer_reads_its_own_directory_and_only_the_signer_may_write_it()
    {
        var signer = Directives("deploy/modularca-signer.service");
        Assert.Contains("ExecStart=/opt/modularca/ModularCA.API --role signer --signer-dir /opt/modularca/signer", signer);
        var writable = Assert.Single(signer, d => d.StartsWith("ReadWritePaths=", StringComparison.Ordinal));
        Assert.Equal(new[] { "/opt/modularca/keystores", "-/opt/modularca/signer" }, writable["ReadWritePaths=".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries));

        var node = Directives("deploy/modularca.service");
        Assert.DoesNotContain(node, d => d.StartsWith("ReadWritePaths=", StringComparison.Ordinal) && d.Contains("signer", StringComparison.Ordinal));
    }

    [Fact]
    public void The_package_ships_the_repair_script_and_its_helper_root_owned_outside_the_payload()
    {
        var sql = NfpmEntry("dst: " + SchemaOwnership.LinuxRepairScriptPath);
        Assert.Contains("owner: root", sql);
        Assert.Contains("group: root", sql);
        Assert.Contains("mode: 0644", sql);

        var helper = NfpmEntry("dst: /usr/share/modularca/db-ownership.sh");
        Assert.Contains("owner: root", helper);
        Assert.Contains("group: root", helper);
        Assert.Contains("src: packaging/debian/db-ownership.sh", helper);
    }

    [Fact]
    public void Postinst_runs_the_ownership_repair_only_on_configure_and_never_fails_on_it()
    {
        var postinst = Read("packaging/debian/postinst");
        var code = CodeLines(postinst);

        var calls = code.Where(l => l.Contains("$DB_OWNERSHIP", StringComparison.Ordinal) && !l.TrimStart().StartsWith("DB_OWNERSHIP=", StringComparison.Ordinal)
            && !l.Contains("[ -f \"$DB_OWNERSHIP\" ]", StringComparison.Ordinal)).ToList();
        var call = Assert.Single(calls);
        Assert.Equal("sh \"$DB_OWNERSHIP\" repair || true", call.Trim());
        Assert.Contains("DB_OWNERSHIP=/usr/share/modularca/db-ownership.sh", code.Select(l => l.Trim()));

        var configure = Branch(postinst, "configure");
        Assert.Contains(call.Trim(), configure);
        Assert.DoesNotContain("$DB_OWNERSHIP\" repair", Branch(postinst, "abort-upgrade"));
        Assert.Contains("MODULARCA_SKIP_DB_REPAIR", configure);
    }

    [Fact]
    public void Postinst_itself_runs_no_database_client()
    {
        foreach (var line in CodeLines(Read("packaging/debian/postinst")))
        {
            Assert.DoesNotMatch(@"\bpsql\b", line);
            Assert.DoesNotMatch(@"\brunuser\b", line);
            Assert.DoesNotContain("/opt/modularca/ModularCA.API --", line);
        }
    }

    [Fact]
    public void Prerm_records_the_running_units_and_stops_the_signer_too_on_upgrade()
    {
        var prerm = Read("packaging/debian/prerm");
        var upgrade = Branch(prerm, "    upgrade");

        Assert.Contains("UNITS=\"modularca.service modularca-signer.service\"", CodeLines(prerm).Select(l => l.Trim()));
        Assert.Contains("systemctl is-active --quiet \"$unit\"", upgrade);
        Assert.Contains("touch \"$MARKERS/restart-$unit\"", upgrade);
        Assert.Contains("systemctl stop $UNITS", upgrade);
    }

    [Fact]
    public void The_helper_reads_only_db_yaml_under_the_payload_and_only_as_the_service_account()
    {
        var code = CodeLines(Read("packaging/debian/db-ownership.sh"));

        var opt = code.Where(l => l.Contains("/opt/modularca", StringComparison.Ordinal)).Select(l => l.Trim()).ToList();
        Assert.Equal(["APP_DIR=/opt/modularca"], opt);
        var appDir = code.Where(l => l.Contains("$APP_DIR", StringComparison.Ordinal)).Select(l => l.Trim()).ToList();
        Assert.Equal(["DB_YAML=$APP_DIR/config/db.yaml"], appDir);

        var reads = code.Where(l => l.Contains("$DB_YAML", StringComparison.Ordinal)
            && Regex.IsMatch(l, @"\b(head|cat|awk|sed|grep|tail|less|more)\b|<\s*""?\$DB_YAML|^\s*\.\s")).ToList();
        var read = Assert.Single(reads);
        Assert.Contains("runuser -u \"$SERVICE_USER\" -- head -c 65536 -- \"$DB_YAML\"", read);

        Assert.Contains($"REPAIR_SQL={SchemaOwnership.LinuxRepairScriptPath}", code.Select(l => l.Trim()));
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @"\beval\b"));
    }

    [Fact]
    public void The_helper_passes_every_value_to_psql_as_a_variable()
    {
        var script = Read("packaging/debian/db-ownership.sh");

        Assert.Contains("\\connect :\"db\"", script);
        Assert.Contains("\\i :repair_sql", script);
        Assert.Contains("rolname = :'role'", script);
        Assert.Contains("-v \"db=$3\"", script);
        Assert.Contains("-v \"kind=$4\" -v \"target=$5\" -v \"repair_sql=$REPAIR_SQL\"", script);
        Assert.DoesNotMatch(@":(db|role|kind|target)\b", Regex.Replace(script, @":""db""|:'role'|:'kind'|:'target'", ""));
        Assert.Contains("runuser -u \"$PG_OS_USER\" -- env -i", script);
    }

    /// <summary>The non-blank, non-comment lines of a unit, trimmed.</summary>
    private static List<string> Directives(string relativePath) =>
        CodeLines(Read(relativePath)).Select(l => l.Trim()).ToList();

    /// <summary>The lines of a script or unit that are not blank and not comments.</summary>
    private static List<string> CodeLines(string text) =>
        text.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))
            .ToList();

    /// <summary>
    /// One arm of a shell <c>case</c>: from the line <c>label)</c> (exactly as indented) to the
    /// next line at the same indentation that ends with <c>)</c>, or <c>esac</c>.
    /// </summary>
    private static string Branch(string script, string label)
    {
        var lines = script.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var start = lines.FindIndex(l => l == label + ")");
        Assert.True(start >= 0, $"no '{label})' arm");
        var indent = label.Length - label.TrimStart().Length;
        var end = lines.FindIndex(start + 1, l =>
            l.Trim() == "esac"
            || (l.Length > indent && l.Length - l.TrimStart().Length == indent && l.TrimEnd().EndsWith(')') && !l.TrimStart().StartsWith('#')));
        return string.Join("\n", lines.Skip(start).Take((end < 0 ? lines.Count : end) - start));
    }

    /// <summary>The nfpm <c>contents</c> entry holding <paramref name="line"/>, from its <c>- src:</c> to the next entry.</summary>
    private static string NfpmEntry(string line)
    {
        var nfpm = Read("packaging/nfpm.yaml").Replace("\r", "");
        var at = nfpm.IndexOf(line, StringComparison.Ordinal);
        Assert.True(at >= 0, $"nfpm.yaml has no '{line}'");
        var start = nfpm.LastIndexOf("- src:", at, StringComparison.Ordinal);
        var next = nfpm.IndexOf("- src:", at, StringComparison.Ordinal);
        var blank = nfpm.IndexOf("\n\n", at, StringComparison.Ordinal);
        var end = new[] { next, blank, nfpm.Length }.Where(i => i >= 0).Min();
        return nfpm[start..end];
    }

    /// <summary>A repository file's text.</summary>
    private static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar)));

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
