using System.Diagnostics;
using System.Text;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// A <see cref="FactAttribute"/> that runs only where a bash is available (Git Bash on Windows,
/// /bin/bash elsewhere), and is otherwise reported as skipped.
/// </summary>
public sealed class RequiresBashFactAttribute : FactAttribute
{
    /// <summary>Skips the test when no bash is found.</summary>
    public RequiresBashFactAttribute()
    {
        if (DbOwnershipScriptTests.FindBash() is null)
            Skip = "No bash found (Git Bash on Windows, /bin/bash elsewhere).";
    }
}

/// <summary>
/// Runs <c>packaging/debian/db-ownership.sh</c>, the .deb's legacy ownership repair, under bash
/// with its functions loaded and the system commands it calls replaced by stubs: <c>psql</c>
/// answers from per-database state files and records its argument vector, <c>systemctl</c>
/// records what it was asked to do, and <c>runuser</c> and <c>timeout</c> pass through. Pins the
/// guards: hostile or remote <c>db.yaml</c> values never reach psql, values reach psql only as
/// <c>-v</c> variables, only administrator-owned objects are repaired, the units are stopped
/// first and restored afterwards, and a failure prints the manual command.
/// </summary>
public sealed class DbOwnershipScriptTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-dbown-{Guid.NewGuid():N}");

    private const string PsqlStub = """
        #!/bin/bash
        st="$(cd "$(dirname "$0")/.." && pwd)"
        { printf 'ARGV:'; for a in "$@"; do printf ' [%s]' "$a"; done; printf ' PGPASSWORD=[%s]\n' "${PGPASSWORD:-}"; } >> "$st/calls"
        db=; role=; kind=; target=; sql=
        while [ $# -gt 0 ]; do
          case "$1" in
            -v)
              case "$2" in
                db=*) db="${2#db=}" ;;
                role=*) role="${2#role=}" ;;
                kind=*) kind="${2#kind=}" ;;
                target=*) target="${2#target=}" ;;
                repair_sql=*) sql="${2#repair_sql=}" ;;
              esac
              shift 2 ;;
            *) shift ;;
          esac
        done
        input=$(cat)
        f="$st/db-$db"
        if [ ! -f "$f" ]; then echo "psql: error: FATAL:  database \"$db\" does not exist" >&2; exit 2; fi
        . "$f"
        case "$input" in
          *'count(*) FILTER'*)
            if [ "$role" = "$ROLE" ]; then echo "1 $ADOPT $TOTAL"; else echo "0 0 0"; fi ;;
          *'\i :repair_sql'*)
            if [ "${FAIL:-0}" = 1 ]; then echo "psql:adopt-ownership.sql:24: ERROR:  refused: $target does not own $db" >&2; exit 3; fi
            echo "psql:adopt-ownership.sql:41: NOTICE:  modularca: $ADOPT object(s) in $db now owned by $target" >&2
            printf 'ROLE=%s\nADOPT=0\nTOTAL=%s\n' "$ROLE" "$((TOTAL - ADOPT))" > "$f"
            echo "REPAIRED db=$db kind=$kind target=$target sql=$sql" >> "$st/calls" ;;
          *) echo "unexpected script" >&2; exit 7 ;;
        esac
        """;

    private const string Driver = """
        #!/bin/bash
        set -u
        posix() { cygpath -u "$1" 2>/dev/null || printf '%s' "$1"; }
        T="$(posix "$1")"
        S="$(posix "$2")"
        MODE_ARG="$3"
        : > "$T/calls"; : > "$T/systemctl"; : > "$T/runuser"
        DB_OWNERSHIP_SOURCED=1 . "$S"
        PATH="$T/bin:$PATH"
        DB_YAML="$T/db.yaml"
        REPAIR_SQL="$T/sql/adopt-ownership.sql"
        SYSTEMD_DIR="$T"
        PGPASSWORD=leaked
        export PGPASSWORD
        id() { echo 0; }
        getent() { return 0; }
        logger() { :; }
        stat() { echo "0 644"; }
        runuser() { echo "runuser $1 $2" >> "$T/runuser"; shift 3; "$@"; }
        timeout() { shift 3; "$@"; }
        systemctl() {
          echo "$*" >> "$T/systemctl"
          case "$1" in
            is-active) shift; [ "$1" = --quiet ] && shift; grep -qx "$1" "$T/active" 2>/dev/null ;;
            stop) return "${STOP_RC:-0}" ;;
            *) return 0 ;;
          esac
        }
        main "$MODE_ARG"
        echo "EXIT=$?"
        """;

    private const string GuardDriver = """
        #!/bin/bash
        posix() { cygpath -u "$1" 2>/dev/null || printf '%s' "$1"; }
        S="$(posix "$1")"
        IN="$(posix "$2")"
        DB_OWNERSHIP_SOURCED=1 . "$S"
        while IFS= read -r line; do
          fn="${line%%|*}"
          value="${line#*|}"
          if "$fn" "$value" >/dev/null 2>&1; then echo 1; else echo 0; fi
        done < "$IN"
        """;

    private const string LegacyYaml = """
        # Auto-generated runtime database credentials
        App:
          Host: localhost
          Port: 5432
          Database: modularca-app
          Username: modularca_app
          Password: "p@ss: $(touch PWNED_PATH)"
          SslMode: Require
        Audit:
          Host: "127.0.0.1"
          Port: 5432
          Database: "modularca-audit"
          Username: modularca_audit
          Password: "x"
          SslMode: Require
        """;

    /// <summary>Creates the stub directory: the psql stub and a stand-in for the repair script.</summary>
    public DbOwnershipScriptTests()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "bin"));
        Directory.CreateDirectory(Path.Combine(_dir, "sql"));
        WriteScript(Path.Combine(_dir, "bin", "psql"), PsqlStub);
        WriteScript(Path.Combine(_dir, "run.sh"), Driver);
        WriteScript(Path.Combine(_dir, "guards.sh"), GuardDriver);
        WriteScript(Path.Combine(_dir, "posix.sh"), "#!/bin/bash\ncygpath -u \"$1\" 2>/dev/null || printf '%s' \"$1\"");
        File.WriteAllText(Path.Combine(_dir, "sql", "adopt-ownership.sql"), "-- stand-in\n");
    }

    /// <summary>Removes the stub directory.</summary>
    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [RequiresBashFact]
    public void The_name_port_and_host_guards_accept_only_plain_local_values()
    {
        (string Function, string Value, bool Accepted)[] cases =
        [
            ("is_identifier", "modularca_app", true),
            ("is_identifier", "modularca-app", true),
            ("is_identifier", new string('a', 63), true),
            ("is_identifier", new string('a', 64), false),
            ("is_identifier", "", false),
            ("is_identifier", "-d", false),
            ("is_identifier", "x; rm -rf /", false),
            ("is_identifier", "$(touch /tmp/pwned)", false),
            ("is_identifier", "a`id`", false),
            ("is_identifier", "a'b", false),
            ("is_identifier", "a\"b", false),
            ("is_identifier", "modularca app", false),
            ("is_port", "5432", true),
            ("is_port", "65535", true),
            ("is_port", "0", false),
            ("is_port", "65536", false),
            ("is_port", "5432 -h evil", false),
            ("is_port", "", false),
            ("is_port", "-1", false),
            ("local_socket", "localhost", true),
            ("local_socket", "127.0.0.1", true),
            ("local_socket", "::1", true),
            ("local_socket", "/var/run/postgresql", true),
            ("local_socket", "/var/run/postgresql/../../tmp", false),
            ("local_socket", "/tmp/a b", false),
            ("local_socket", "db.internal", false),
            ("local_socket", "10.0.0.5", false),
            ("local_socket", "", false),
        ];
        var input = Path.Combine(_dir, "guards.txt");
        File.WriteAllText(input, string.Join("\n", cases.Select(c => $"{c.Function}|{c.Value}")) + "\n");

        var (exit, stdout, stderr) = Bash(Path.Combine(_dir, "guards.sh"), ScriptPath(), input);

        Assert.True(exit == 0, stderr);
        var results = stdout.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(cases.Length, results.Length);
        for (var i = 0; i < cases.Length; i++)
            Assert.True((results[i] == "1") == cases[i].Accepted, $"{cases[i].Function} '{cases[i].Value}' gave {results[i]}");
    }

    [RequiresBashFact]
    public void A_legacy_local_install_is_repaired_with_values_passed_only_as_psql_variables()
    {
        var run = Run(LegacyYaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 40, 40), ["modularca-audit"] = State("modularca_audit", 5, 5) },
            active: ["modularca.service"]);

        Assert.Equal(0, run.Exit);
        Assert.Contains($"REPAIRED db=modularca-app kind=app target=modularca_app sql={run.Posix}/sql/adopt-ownership.sql", run.Calls);
        Assert.Contains($"REPAIRED db=modularca-audit kind=audit target=modularca_audit sql={run.Posix}/sql/adopt-ownership.sql", run.Calls);
        Assert.Contains("[-v] [db=modularca-app]", run.Calls);
        Assert.Contains("[-d] [postgres]", run.Calls);
        Assert.DoesNotContain("PGPASSWORD=[leaked]", run.Calls);
        Assert.DoesNotContain("modularca-app]", run.Calls.Replace("[db=modularca-app]", ""));
        Assert.Equal(["is-active --quiet modularca.service", "is-active --quiet modularca-signer.service", "stop modularca.service", "start --no-block modularca.service"],
            run.Systemctl);
        Assert.Contains("runuser -u modularca", run.Runuser);
        Assert.Contains("runuser -u postgres", run.Runuser);
        Assert.False(File.Exists(Path.Combine(_dir, "PWNED")));
        Assert.Contains("every object is now owned by 'modularca_app'", run.Output);
    }

    [RequiresBashFact]
    public void A_sound_install_is_left_alone()
    {
        var run = Run(LegacyYaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 0, 0), ["modularca-audit"] = State("modularca_audit", 0, 0) },
            active: ["modularca.service"]);

        Assert.Equal(0, run.Exit);
        Assert.DoesNotContain("REPAIRED", run.Calls);
        Assert.DoesNotContain(run.Systemctl, c => c.StartsWith("stop", StringComparison.Ordinal));
    }

    [RequiresBashFact]
    public void Hostile_values_never_reach_psql_or_a_shell()
    {
        var yaml = """
            App:
              Host: localhost
              Port: 5432
              Database: "x; rm -rf /"
              Username: modularca_app
            Audit:
              Host: "localhost"
              Port: "5432 -h evil"
              Database: modularca-audit
              Username: "$(touch PWNED_PATH)"
            """;

        var run = Run(yaml, "repair", states: new(), active: ["modularca.service"]);

        Assert.Equal(2, run.Exit);
        Assert.Empty(run.Calls);
        Assert.DoesNotContain(run.Systemctl, c => c.StartsWith("stop", StringComparison.Ordinal));
        Assert.False(File.Exists(Path.Combine(_dir, "PWNED")));
        Assert.Contains("not a plain name", run.Output);
    }

    [RequiresBashFact]
    public void Remote_or_escaping_hosts_are_left_alone()
    {
        var yaml = """
            App:
              Host: "db.internal"
              Port: 5432
              Database: modularca-app
              Username: modularca_app
            Audit:
              Host: /var/run/postgresql/../../tmp
              Port: 5432
              Database: modularca-audit
              Username: modularca_audit
            """;

        var run = Run(yaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 3, 3), ["modularca-audit"] = State("modularca_audit", 3, 3) },
            active: []);

        Assert.Equal(2, run.Exit);
        Assert.Empty(run.Calls);
        Assert.Contains("is not local", run.Output);
    }

    [RequiresBashFact]
    public void A_socket_directory_and_port_are_passed_through()
    {
        var yaml = """
            App:
              Host: /var/run/postgresql
              Port: 5433
              Database: modularca-app
              Username: modularca_app
            Audit:
              Host: db.internal
              Port: 5432
              Database: modularca-audit
              Username: modularca_audit
            """;

        var run = Run(yaml, "repair", states: new() { ["modularca-app"] = State("modularca_app", 2, 2) }, active: []);

        Assert.Equal(0, run.Exit);
        Assert.Contains("[-h] [/var/run/postgresql]", run.Calls);
        Assert.Contains("[-p] [5433]", run.Calls);
        Assert.Contains("REPAIRED db=modularca-app kind=app", run.Calls);
        Assert.DoesNotContain("modularca-audit", run.Calls);
    }

    [RequiresBashFact]
    public void Objects_owned_by_ordinary_roles_are_not_moved()
    {
        var run = Run(LegacyYaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 0, 3), ["modularca-audit"] = State("modularca_audit", 0, 0) },
            active: ["modularca.service"]);

        Assert.Equal(1, run.Exit);
        Assert.DoesNotContain("REPAIRED", run.Calls);
        Assert.DoesNotContain(run.Systemctl, c => c.StartsWith("stop", StringComparison.Ordinal));
        Assert.Contains("owned by ordinary roles", run.Output);
    }

    [RequiresBashFact]
    public void A_failed_repair_restores_the_units_and_prints_the_manual_command()
    {
        var run = Run(LegacyYaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 4, 4, fail: true), ["modularca-audit"] = State("modularca_audit", 0, 0) },
            active: ["modularca.service", "modularca-signer.service"]);

        Assert.Equal(1, run.Exit);
        Assert.Contains("stop modularca.service modularca-signer.service", run.Systemctl);
        Assert.Contains("start --no-block modularca.service", run.Systemctl);
        Assert.Contains("start --no-block modularca-signer.service", run.Systemctl);
        Assert.Contains("NOT repaired", run.Output);
        Assert.Contains("sudo -u postgres psql -X -d 'modularca-app' -v kind=app -v target='modularca_app' -f", run.Output);
    }

    [RequiresBashFact]
    public void A_unit_that_will_not_stop_means_no_repair()
    {
        var run = Run(LegacyYaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 4, 4), ["modularca-audit"] = State("modularca_audit", 0, 0) },
            active: ["modularca.service"], stopFails: true);

        Assert.Equal(1, run.Exit);
        Assert.DoesNotContain("REPAIRED", run.Calls);
        Assert.Contains("could not stop", run.Output);
    }

    [RequiresBashFact]
    public void The_same_database_or_role_for_both_is_left_alone()
    {
        var yaml = LegacyYaml.Replace("\"modularca-audit\"", "modularca-app");

        var run = Run(yaml, "repair",
            states: new() { ["modularca-app"] = State("modularca_app", 4, 4) }, active: []);

        Assert.Equal(2, run.Exit);
        Assert.Empty(run.Calls);
        Assert.Contains("same database or role", run.Output);
    }

    [RequiresBashFact]
    public void Check_reports_a_needed_repair_and_changes_nothing()
    {
        var run = Run(LegacyYaml, "check",
            states: new() { ["modularca-app"] = State("modularca_app", 40, 40), ["modularca-audit"] = State("modularca_audit", 0, 0) },
            active: ["modularca.service"]);

        Assert.Equal(1, run.Exit);
        Assert.DoesNotContain("REPAIRED", run.Calls);
        Assert.DoesNotContain(run.Systemctl, c => !c.StartsWith("is-active", StringComparison.Ordinal));
        Assert.Contains("a repair is needed", run.Output);
    }

    /// <summary>What one run of the helper did.</summary>
    private sealed record RunResult(int Exit, string Output, string Calls, IReadOnlyList<string> Systemctl, string Runuser, string Posix);

    /// <summary>A state file for the psql stub: the role that exists, how many objects are adoptable and in total.</summary>
    private static string State(string role, int adoptable, int total, bool fail = false) =>
        $"ROLE={role}\nADOPT={adoptable}\nTOTAL={total}\nFAIL={(fail ? 1 : 0)}\n";

    /// <summary>Writes <paramref name="dbYaml"/> and the state files, runs <c>main</c>, and collects what it did.</summary>
    private RunResult Run(string dbYaml, string mode, Dictionary<string, string> states, string[] active, bool stopFails = false)
    {
        var pwned = Path.Combine(_dir, "PWNED").Replace('\\', '/');
        File.WriteAllText(Path.Combine(_dir, "db.yaml"), dbYaml.Replace("\r\n", "\n").Replace("PWNED_PATH", pwned));
        foreach (var (database, state) in states)
            File.WriteAllText(Path.Combine(_dir, "db-" + database), state);
        File.WriteAllText(Path.Combine(_dir, "active"), string.Concat(active.Select(a => a + "\n")));

        var env = stopFails ? new Dictionary<string, string> { ["STOP_RC"] = "1" } : null;
        var (_, stdout, stderr) = BashWith(Path.Combine(_dir, "run.sh"), env, _dir, ScriptPath(), mode);

        var exitLine = stdout.Replace("\r", "").Split('\n').LastOrDefault(l => l.StartsWith("EXIT=", StringComparison.Ordinal));
        Assert.True(exitLine is not null, $"the helper did not finish.{Environment.NewLine}stdout: {stdout}{Environment.NewLine}stderr: {stderr}");
        var calls = File.ReadAllText(Path.Combine(_dir, "calls")).Replace("\r", "");
        var systemctl = File.ReadAllText(Path.Combine(_dir, "systemctl")).Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var runuser = File.ReadAllText(Path.Combine(_dir, "runuser")).Replace("\r", "");
        var posix = Bash(Path.Combine(_dir, "posix.sh"), _dir).Stdout.Trim();
        return new RunResult(int.Parse(exitLine!["EXIT=".Length..]), stdout + stderr, calls, systemctl, runuser, posix);
    }

    /// <summary>The helper under test.</summary>
    private static string ScriptPath() => Path.Combine(RepoRoot(), "packaging", "debian", "db-ownership.sh");

    /// <summary>Writes a script with LF line endings, executable where that matters.</summary>
    private void WriteScript(string path, string content)
    {
        File.WriteAllText(path, content.Replace("\r\n", "\n") + "\n", new UTF8Encoding(false));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    /// <summary>Runs <paramref name="script"/> under bash with <paramref name="args"/>.</summary>
    private static (int Exit, string Stdout, string Stderr) Bash(string script, params string[] args) => BashWith(script, null, args);

    /// <summary>Runs <paramref name="script"/> under bash with extra environment and <paramref name="args"/>.</summary>
    private static (int Exit, string Stdout, string Stderr) BashWith(string script, IDictionary<string, string>? env, params string[] args)
    {
        var start = new ProcessStartInfo(FindBash()!)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add(script.Replace('\\', '/'));
        foreach (var arg in args)
            start.ArgumentList.Add(arg.Replace('\\', '/'));
        foreach (var (name, value) in env ?? new Dictionary<string, string>())
            start.Environment[name] = value;
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"bash {script} did not finish in 60 s");
        }
        return (process.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>
    /// A bash to run the helper with: /bin/bash off Windows; on Windows the first bash.exe on the
    /// PATH that is not the WSL launcher, then Git for Windows' own. Null when there is none.
    /// </summary>
    internal static string? FindBash()
    {
        if (!OperatingSystem.IsWindows())
            return File.Exists("/bin/bash") ? "/bin/bash" : null;
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), "bash.exe");
            if (File.Exists(candidate)
                && !candidate.StartsWith(system, StringComparison.OrdinalIgnoreCase)
                && !candidate.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase))
                return candidate;
        }
        var git = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "bash.exe");
        return File.Exists(git) ? git : null;
    }

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
