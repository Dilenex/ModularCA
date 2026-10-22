using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// Text assertions on the KRL fetcher an SSH server runs (<c>deploy/ssh-krl/</c>) and on how it is
/// shipped. <see cref="SshKrlFetchScriptTests"/> runs the script; these pin what a run cannot
/// show: that the installed file is written in one place only, that nothing but HTTPS is asked
/// for, that the script needs no tool a minimal server lacks, and that the tarball and the
/// package carry the same four files, root-owned, outside the payload.
/// </summary>
public class SshKrlFetchFileTests
{
    private const string Script = "deploy/ssh-krl/modularca-krl-fetch.sh";
    private const string Service = "deploy/ssh-krl/modularca-krl-fetch.service";
    private const string Timer = "deploy/ssh-krl/modularca-krl-fetch.timer";
    private const string Settings = "deploy/ssh-krl/modularca-krl-fetch.env.example";

    private static readonly string[] Files = [Script, Service, Timer, Settings];

    /// <summary>
    /// sshd refuses every public-key login while its RevokedKeys file cannot be read, so the
    /// destination is touched by one command: the rename of a file that was already found
    /// non-empty, read as a KRL, compared by version and given its mode.
    /// </summary>
    [Fact]
    public void The_installed_list_is_written_only_by_renaming_a_checked_file_over_it()
    {
        var code = CodeLines(Read(Script));

        var install = Assert.Single(code, l => Regex.IsMatch(l, @"""\$dest""") && Regex.IsMatch(l, @"^\s*(mv|cp|rm|ln|install|truncate|dd|tee)\b"));
        Assert.Equal("mv -f \"$tmp\" \"$dest\" || fail \"could not move the new list into place\"", install.Trim());
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @">>?\s*""?\$dest\b"));
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @"\brm\b[^|;]*\$(dest|dir)\b"));

        int At(string fragment)
        {
            var index = code.FindIndex(l => l.Contains(fragment, StringComparison.Ordinal));
            Assert.True(index >= 0, $"the script has no line with: {fragment}");
            return index;
        }
        var steps = new[]
        {
            At("tmp=$(mktemp \"$dir/"),
            At("status=$(curl \"$@\")"),
            At("[ -s \"$tmp\" ] || fail"),
            At("ssh-keygen -Q -l -f \"$tmp\""),
            At("[ \"$new_version\" -lt \"$old_version\" ]"),
            At("chmod 0644 \"$tmp\""),
            At("mv -f \"$tmp\" \"$dest\""),
            At("mv -f \"$state_tmp\" \"$state\""),
        };
        Assert.Equal(steps.OrderBy(s => s), steps);
    }

    [Fact]
    public void The_fetch_is_https_only_with_timeouts_and_no_way_to_turn_verification_off()
    {
        var script = Read(Script);
        var code = CodeLines(script);

        var curl = Assert.Single(code, l => l.TrimStart().StartsWith("set -- -q ", StringComparison.Ordinal));
        Assert.Contains("--proto '=https'", curl);
        Assert.Contains("--connect-timeout \"$connect_timeout\"", script);
        Assert.Contains("--max-time \"$max_time\"", script);
        Assert.Contains("https://?*) ;;", script);
        Assert.DoesNotContain(code, l => Regex.IsMatch(l, @"(--insecure|\s-k\b|--location|\s-L\b|--proto-redir)"));
        Assert.Single(code, l => Regex.IsMatch(l, @"\bcurl ""\$@"""));
    }

    /// <summary>A server has sh, curl, ssh-keygen and coreutils; the script asks for nothing else and is not written for bash.</summary>
    [Fact]
    public void The_script_is_posix_sh_and_names_no_tool_beyond_curl_ssh_keygen_and_coreutils()
    {
        var script = Read(Script);
        var code = CodeLines(script);

        Assert.StartsWith("#!/bin/sh\n", script.Replace("\r", ""));
        Assert.DoesNotContain(code, l => Regex.IsMatch(l,
            @"(^|[;&|(]|\$\()\s*(sed|awk|gawk|grep|egrep|cmp|diff|find|xargs|perl|python3?|jq|wget|openssl|bash|tr|cut|stat|readlink|realpath)\b"));
        Assert.DoesNotContain(code, l => Regex.IsMatch(l,
            @"(^|\s)\[\[\s|\s\]\](\s|;|$)|<<<|\blocal\b|\bfunction\b|\$\{[A-Za-z_]+//|=\(\s|\bsource\b|\beval\b|\bdeclare\b"));
    }

    [Fact]
    public void No_file_of_the_fetcher_has_a_carriage_return()
    {
        foreach (var file in Files)
            Assert.False(File.ReadAllBytes(PathOf(file)).Contains((byte)'\r'), $"{file} has a carriage return");
    }

    [Fact]
    public void The_unit_runs_the_script_once_with_its_settings_and_may_write_only_beside_the_list()
    {
        var service = CodeLines(Read(Service)).Select(l => l.Trim()).ToList();

        Assert.Contains("Type=oneshot", service);
        Assert.Contains("EnvironmentFile=/etc/default/modularca-krl-fetch", service);
        Assert.Contains("ExecStart=/usr/local/sbin/modularca-krl-fetch", service);
        Assert.Contains("ProtectSystem=strict", service);
        Assert.Contains("ReadWritePaths=/etc/ssh", service);
        Assert.Contains("NoNewPrivileges=true", service);
        Assert.DoesNotContain(service, d => d.StartsWith("Restart=", StringComparison.Ordinal));
        Assert.DoesNotContain(service, d => d.StartsWith("[Install]", StringComparison.Ordinal));

        var timer = CodeLines(Read(Timer)).Select(l => l.Trim()).ToList();
        Assert.Contains("OnCalendar=*:*:00", timer);
        Assert.Contains("WantedBy=timers.target", timer);
        Assert.Contains(timer, d => d.StartsWith("RandomizedDelaySec=", StringComparison.Ordinal));
        Assert.DoesNotContain(timer, d => d.StartsWith("Unit=", StringComparison.Ordinal));
    }

    /// <summary>The settings file, the script's header and what the script reads name the same variables.</summary>
    [Fact]
    public void Every_setting_in_the_example_is_one_the_script_reads_and_its_header_explains()
    {
        var script = Read(Script);
        var read = Regex.Matches(string.Join("\n", CodeLines(script)), @"\$\{(MODULARCA_KRL_[A-Z_]+):-").Select(m => m.Groups[1].Value).ToHashSet();
        var header = string.Join("\n", script.Split('\n').TakeWhile(l => l.StartsWith('#')));
        var example = Regex.Matches(Read(Settings), @"^#?(MODULARCA_KRL_[A-Z_]+)=", RegexOptions.Multiline).Select(m => m.Groups[1].Value).ToHashSet();

        Assert.Equal(
            new[] { "MODULARCA_KRL_ALLOW_LOWER_VERSION", "MODULARCA_KRL_CACERT", "MODULARCA_KRL_CONNECT_TIMEOUT", "MODULARCA_KRL_DEST", "MODULARCA_KRL_MAX_TIME", "MODULARCA_KRL_URL" },
            read.OrderBy(n => n, StringComparer.Ordinal));
        Assert.All(read, name => Assert.Contains(name, header));
        Assert.Subset(read, example);
        Assert.Contains("MODULARCA_KRL_URL", example);
        Assert.Matches(@"(?m)^MODULARCA_KRL_URL=https://", Read(Settings));
        Assert.Contains("dest=${MODULARCA_KRL_DEST:-/etc/ssh/revoked_keys.krl}", script);
    }

    [Fact]
    public void The_tarball_stages_the_four_files_under_share_and_refuses_one_that_is_missing_or_has_a_carriage_return()
    {
        var build = Read("scripts/build-linux-dist.sh");

        Assert.Contains("SSH_KRL_FILES=(modularca-krl-fetch.sh modularca-krl-fetch.service modularca-krl-fetch.timer modularca-krl-fetch.env.example)", build);
        Assert.Contains("cp \"deploy/ssh-krl/$krl_file\" \"$STAGE/share/ssh-krl/$krl_file\"", build);
        Assert.Contains("\"${SSH_KRL_FILES[@]/#/share/ssh-krl/}\"", build);
        Assert.Contains("grep -qU \"$(printf '\\r')\" \"$STAGE/share/ssh-krl/$krl_file\"", build);
        foreach (var file in Files)
            Assert.True(File.Exists(PathOf(file)), $"{file} is missing");

        Assert.Contains("share/ssh-krl/modularca-krl-fetch.sh", Read("scripts/build-deb.sh"));
    }

    [Fact]
    public void The_installer_and_the_package_put_the_fetcher_root_owned_under_usr_share_and_enable_nothing()
    {
        var install = CodeLines(Read("packaging/install.sh"));
        Assert.Contains(install, l => l.Trim() == "install -d -o root -g root -m 0755 /usr/share/modularca/ssh-krl");
        Assert.Contains(install, l => l.Trim()
            == "install -o root -g root -m 0755 \"$SRC/share/ssh-krl/modularca-krl-fetch.sh\" /usr/share/modularca/ssh-krl/modularca-krl-fetch.sh");
        Assert.DoesNotContain(install, l => l.Contains("modularca-krl-fetch", StringComparison.Ordinal) && l.Contains("systemctl", StringComparison.Ordinal));

        foreach (var (name, mode) in new[]
        {
            ("modularca-krl-fetch.sh", "0755"), ("modularca-krl-fetch.service", "0644"),
            ("modularca-krl-fetch.timer", "0644"), ("modularca-krl-fetch.env.example", "0644"),
        })
        {
            var entry = NfpmEntry($"dst: /usr/share/modularca/ssh-krl/{name}");
            Assert.Contains($"src: ${{SHAREDIR}}/ssh-krl/{name}", entry);
            Assert.Contains($"mode: {mode}", entry);
            Assert.Contains("owner: root", entry);
            Assert.Contains("group: root", entry);
        }
        var nfpm = Read("packaging/nfpm.yaml");
        Assert.DoesNotContain("/lib/systemd/system/modularca-krl-fetch", nfpm);
        Assert.DoesNotContain("/opt/modularca/ssh-krl", nfpm);
        foreach (var maintainer in new[] { "postinst", "prerm", "postrm", "preinst" })
            Assert.DoesNotContain("krl", Read($"packaging/debian/{maintainer}"), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The lines of a script or unit that are not blank and not comments.</summary>
    private static List<string> CodeLines(string text) =>
        text.Split('\n').Select(l => l.TrimEnd('\r'))
            .Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))
            .ToList();

    /// <summary>The nfpm <c>contents</c> entry holding <paramref name="line"/>, from its <c>- src:</c> to the next entry.</summary>
    private static string NfpmEntry(string line)
    {
        var nfpm = Read("packaging/nfpm.yaml").Replace("\r", "");
        var at = nfpm.IndexOf(line + "\n", StringComparison.Ordinal);
        Assert.True(at >= 0, $"nfpm.yaml has no '{line}'");
        var start = nfpm.LastIndexOf("- src:", at, StringComparison.Ordinal);
        var next = nfpm.IndexOf("- src:", at, StringComparison.Ordinal);
        var blank = nfpm.IndexOf("\n\n", at, StringComparison.Ordinal);
        var end = new[] { next, blank, nfpm.Length }.Where(i => i >= 0).Min();
        return nfpm[start..end];
    }

    private static string Read(string relativePath) => File.ReadAllText(PathOf(relativePath));

    private static string PathOf(string relativePath) =>
        Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));

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
