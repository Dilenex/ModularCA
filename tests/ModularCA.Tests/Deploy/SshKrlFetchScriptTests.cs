using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ModularCA.Ssh;
using ModularCA.Tests.Ssh;
using Xunit;

namespace ModularCA.Tests.Deploy;

/// <summary>
/// A <see cref="TheoryAttribute"/> that runs only where a POSIX shell, <c>curl</c> and an
/// <c>ssh-keygen</c> that lists a KRL are available (Git Bash on Windows), and is otherwise
/// reported as skipped.
/// </summary>
public sealed class RequiresKrlFetchToolsTheoryAttribute : TheoryAttribute
{
    /// <summary>Skips the test when no shell with the tools was found.</summary>
    public RequiresKrlFetchToolsTheoryAttribute()
    {
        if (SshKrlFetchScriptTests.ShellPaths.Count == 0)
            Skip = "No POSIX shell with curl and an ssh-keygen that lists a KRL (OpenSSH 8.0 or later) was found.";
    }
}

/// <summary>
/// Runs <c>deploy/ssh-krl/modularca-krl-fetch.sh</c>, the script an SSH server fetches its KRL
/// with, for real: under <c>sh</c>, and under <c>dash</c> where there is one, with the real
/// <c>curl</c> and <c>ssh-keygen</c>, against a stand-in for the CA that speaks HTTPS on the
/// loopback interface with a certificate made for the test. Pins what a host depends on: a good
/// list is installed and its ETag sent back, a 304 is success, and every failure (an empty
/// body, garbage, a lower version, an unreachable or untrusted server, an error status, a
/// transfer cut short) leaves the installed file byte for byte as it was and exits non-zero.
/// </summary>
public sealed class SshKrlFetchScriptTests : IDisposable
{
    private const string FirstETag = "\"0123456789abcdef0123456789abcdef\"";
    private const string SecondETag = "\"fedcba9876543210fedcba9876543210\"";

    /// <summary>The shells the script is run under, by name, each with the tools the script needs.</summary>
    internal static IReadOnlyDictionary<string, string> ShellPaths { get; } = FindShells();

    /// <summary>The names of <see cref="ShellPaths"/> as theory data.</summary>
    public static IEnumerable<object[]> Shells => ShellPaths.Keys.OrderBy(k => k, StringComparer.Ordinal).Select(k => new object[] { k });

    private static readonly Lazy<(X509Certificate2 Certificate, string Pem)> ServerIdentity = new(MakeServerIdentity);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-krl-fetch-{Guid.NewGuid():N}");
    private readonly string _ssh;
    private readonly StandInCa _ca;

    /// <summary>Creates the directory that stands for <c>/etc/ssh</c> and starts the stand-in CA.</summary>
    public SshKrlFetchScriptTests()
    {
        _ssh = Path.Combine(_dir, "ssh");
        Directory.CreateDirectory(_ssh);
        _ca = new StandInCa(_dir);
    }

    /// <summary>Stops the stand-in CA and removes the directory.</summary>
    public void Dispose()
    {
        _ca.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string Dest => Path.Combine(_ssh, "revoked_keys.krl");
    private string State => Dest + ".etag";

    /// <summary>A KRL of the fixture CA key, as the node encodes one.</summary>
    private static byte[] Krl(ulong version, params ulong[] serials)
        => SshKrl.Encode(SshFixtures.CaPublic("ed25519"), serials, version, new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero));

    // ---- The good path -----------------------------------------------------------------------

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_good_list_is_installed_its_etag_is_sent_back_and_304_is_success(string shell)
    {
        var first = Krl(1, 1001);
        var second = Krl(2, 1001, 2002);
        _ca.Answer = asked => asked == FirstETag ? Reply.NotModified(FirstETag) : Reply.Ok(first, FirstETag);

        var installed = Fetch(shell);

        Assert.True(installed.Exit == 0, installed.Output);
        Assert.Equal(first, File.ReadAllBytes(Dest));
        Assert.Contains("installed KRL version 1", installed.Output);
        Assert.Null(_ca.Requests[0].IfNoneMatch);
        Assert.Equal($"/ssh/ca-keys/{StandInCa.KeyId}/krl", _ca.Requests[0].Path);
        var state = File.ReadAllLines(State);
        Assert.Equal(FirstETag, state[0]);
        Assert.Equal(_ca.Url, state[2]);
        AssertOnlyTheListAndItsETagAreThere();
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead, File.GetUnixFileMode(Dest));

        var unchanged = Fetch(shell);

        Assert.True(unchanged.Exit == 0, unchanged.Output);
        Assert.Contains("not modified", unchanged.Output);
        Assert.Equal(FirstETag, _ca.Requests[1].IfNoneMatch);
        Assert.Equal(first, File.ReadAllBytes(Dest));
        Assert.Equal(state, File.ReadAllLines(State));
        AssertOnlyTheListAndItsETagAreThere();

        _ca.Answer = asked => asked == SecondETag ? Reply.NotModified(SecondETag) : Reply.Ok(second, SecondETag);

        var replaced = Fetch(shell);

        Assert.True(replaced.Exit == 0, replaced.Output);
        Assert.Contains("installed KRL version 2 (was 1)", replaced.Output);
        Assert.Equal(FirstETag, _ca.Requests[2].IfNoneMatch);
        Assert.Equal(second, File.ReadAllBytes(Dest));
        Assert.Equal(SecondETag, File.ReadAllLines(State)[0]);
        AssertOnlyTheListAndItsETagAreThere();

        Assert.Equal(0, Fetch(shell).Exit);
        Assert.Equal(SecondETag, _ca.Requests[3].IfNoneMatch);
        Assert.Equal(second, File.ReadAllBytes(Dest));
    }

    /// <summary>As the systemd unit runs it: no argument, every setting from the environment.</summary>
    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void The_settings_can_all_come_from_the_environment(string shell)
    {
        var list = Krl(3, 7, 8, 9);
        _ca.Answer = _ => Reply.Ok(list, FirstETag);

        var run = Run(shell, new()
        {
            ["MODULARCA_KRL_URL"] = _ca.Url,
            ["MODULARCA_KRL_DEST"] = Posix(Dest),
            ["MODULARCA_KRL_CACERT"] = Posix(_ca.BundlePath),
        });

        Assert.True(run.Exit == 0, run.Output);
        Assert.Equal(list, File.ReadAllBytes(Dest));
    }

    /// <summary>
    /// The saved ETag describes one file from one URL. When the installed file is no longer
    /// that file, a 304 would vouch for the wrong bytes, so the ETag is not sent.
    /// </summary>
    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void The_etag_is_not_sent_once_the_installed_file_is_not_the_one_it_was_saved_for(string shell)
    {
        var current = Krl(2, 1001, 2002);
        _ca.Answer = asked => asked == FirstETag ? Reply.NotModified(FirstETag) : Reply.Ok(current, FirstETag);
        Assert.Equal(0, Fetch(shell).Exit);

        // An older list put back by hand, with the ETag file left behind.
        File.WriteAllBytes(Dest, Krl(1, 1001));

        var run = Fetch(shell);

        Assert.True(run.Exit == 0, run.Output);
        Assert.Null(_ca.Requests[1].IfNoneMatch);
        Assert.Equal(current, File.ReadAllBytes(Dest));

        // A file that is not a KRL at all is replaced by one that is.
        File.WriteAllText(Dest, "not a KRL");
        var repaired = Fetch(shell);

        Assert.True(repaired.Exit == 0, repaired.Output);
        Assert.Null(_ca.Requests[2].IfNoneMatch);
        Assert.Equal(current, File.ReadAllBytes(Dest));
        AssertOnlyTheListAndItsETagAreThere();
    }

    // ---- Failures: the installed file is never touched ------------------------------------------

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void An_empty_body_is_refused_and_the_installed_list_is_untouched(string shell)
        => AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok([], SecondETag), "empty body");

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_body_that_is_not_a_krl_is_refused_and_the_installed_list_is_untouched(string shell)
        => AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok(Encoding.ASCII.GetBytes("<html>maintenance</html>\n"), SecondETag), "not a KRL");

    /// <summary>A list cut off inside its certificate section, with a length header that says so honestly.</summary>
    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_list_that_ends_early_is_refused_and_the_installed_list_is_untouched(string shell)
        => AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok(Krl(9, 1, 2, 3, 4)[..^11], SecondETag), "not a KRL");

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_transfer_cut_short_is_refused_and_the_installed_list_is_untouched(string shell)
        => AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok(Krl(9, 1, 2, 3, 4), SecondETag) with { DeclaredLength = 4096 }, "could not be fetched");

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void An_error_status_is_refused_and_the_installed_list_is_untouched(string shell)
    {
        AssertRefused(shell, () => _ca.Answer = _ => Reply.Status(503, Encoding.ASCII.GetBytes("{\"error\":\"starting\"}")), "HTTP 503");
        AssertStillRefused(shell, () => _ca.Answer = _ => Reply.Status(404, []), "HTTP 404");
        AssertStillRefused(shell, () => _ca.Answer = _ => Reply.Status(308, []) with { Location = "http://localhost/elsewhere" }, "HTTP 308");
    }

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_lower_version_is_refused_until_it_is_allowed(string shell)
    {
        var restored = Krl(2, 1001, 2002);
        AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok(restored, SecondETag), "lower than the installed version 5", installedVersion: 5);

        var byOption = Fetch(shell, "--allow-lower-version");

        Assert.True(byOption.Exit == 0, byOption.Output);
        Assert.Equal(restored, File.ReadAllBytes(Dest));
        Assert.Equal(SecondETag, File.ReadAllLines(State)[0]);

        File.WriteAllBytes(Dest, Krl(5, 1, 2, 3, 4, 5));
        var byVariable = Run(shell, new() { ["MODULARCA_KRL_ALLOW_LOWER_VERSION"] = "1" }, StandardArguments());

        Assert.True(byVariable.Exit == 0, byVariable.Output);
        Assert.Equal(restored, File.ReadAllBytes(Dest));
        AssertOnlyTheListAndItsETagAreThere();
    }

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void An_unreachable_server_leaves_the_installed_list_untouched(string shell)
    {
        var closed = FreePort();
        AssertRefused(shell, () => { }, "could not be fetched",
            arguments: ["--url", $"https://localhost:{closed}/ssh/ca-keys/{StandInCa.KeyId}/krl", "--dest", Posix(Dest), "--cacert", Posix(_ca.BundlePath)],
            expectARequest: false);
    }

    /// <summary>Without the CA bundle the stand-in's certificate has no trusted issuer, so nothing it says is believed.</summary>
    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_server_whose_certificate_is_not_trusted_leaves_the_installed_list_untouched(string shell)
        => AssertRefused(shell, () => _ca.Answer = _ => Reply.Ok(Krl(9, 1, 2, 3, 4), SecondETag), "could not be fetched",
            arguments: ["--url", _ca.Url, "--dest", Posix(Dest)], expectARequest: false);

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_304_to_a_request_that_named_no_etag_is_a_failure(string shell)
    {
        _ca.Answer = _ => Reply.NotModified(FirstETag);

        var run = Fetch(shell);

        Assert.Equal(1, run.Exit);
        Assert.Contains("named no ETag", run.Output);
        Assert.Empty(Directory.GetFileSystemEntries(_ssh));
    }

    /// <summary>A first run that fails creates no file: there is nothing for <c>RevokedKeys</c> to name yet.</summary>
    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_failed_first_fetch_installs_nothing(string shell)
    {
        _ca.Answer = _ => Reply.Ok(Encoding.ASCII.GetBytes("SSHKRL but not really"), FirstETag);

        var run = Fetch(shell);

        Assert.Equal(1, run.Exit);
        Assert.Single(_ca.Requests);
        Assert.Empty(Directory.GetFileSystemEntries(_ssh));
    }

    [RequiresKrlFetchToolsTheory]
    [MemberData(nameof(Shells))]
    public void A_setting_that_is_wrong_is_refused_before_anything_is_fetched(string shell)
    {
        _ca.Answer = _ => Reply.Ok(Krl(1, 1001), FirstETag);
        var plainHttp = _ca.Url.Replace("https://", "http://", StringComparison.Ordinal);

        (string[] Arguments, string Says)[] cases =
        [
            (["--url", plainHttp, "--dest", Posix(Dest)], "must begin with https://"),
            (["--dest", Posix(Dest)], "no KRL URL"),
            (["--url", _ca.Url, "--dest", Posix(Path.Combine(_ssh, "missing", "revoked_keys.krl"))], "directory does not exist"),
            (["--url", _ca.Url, "--dest", Posix(_ssh)], "is a directory"),
            (["--url", _ca.Url, "--dest", Posix(Dest), "--cacert", Posix(Path.Combine(_dir, "no-such.pem"))], "CA bundle cannot be read"),
            (["--url", _ca.Url, "--dest", Posix(Dest), "--insecure"], "unknown argument"),
        ];
        foreach (var (arguments, says) in cases)
        {
            var run = Run(shell, [], arguments);
            Assert.True(run.Exit == 2, $"{string.Join(' ', arguments)}: {run.Output}");
            Assert.Contains(says, run.Output);
        }

        Assert.Empty(_ca.Requests);
        Assert.Empty(Directory.GetFileSystemEntries(_ssh));
    }

    // ---- Helpers -----------------------------------------------------------------------------

    /// <summary>
    /// Installs a good list of <paramref name="installedVersion"/> with a successful run, then
    /// lets <paramref name="arrange"/> break the server and asserts the next run refuses.
    /// </summary>
    private void AssertRefused(string shell, Action arrange, string says, ulong installedVersion = 1, string[]? arguments = null, bool expectARequest = true)
    {
        var good = Krl(installedVersion, 1001);
        _ca.Answer = asked => asked == FirstETag ? Reply.NotModified(FirstETag) : Reply.Ok(good, FirstETag);
        var installed = Fetch(shell);
        Assert.True(installed.Exit == 0, installed.Output);

        AssertStillRefused(shell, arrange, says, arguments, expectARequest);
    }

    /// <summary>
    /// Asserts that a run after <paramref name="arrange"/> exits 1 saying <paramref name="says"/>,
    /// and that the installed list, its ETag file and the directory are exactly as before it.
    /// </summary>
    private void AssertStillRefused(string shell, Action arrange, string says, string[]? arguments = null, bool expectARequest = true)
    {
        var list = File.ReadAllBytes(Dest);
        var state = File.ReadAllBytes(State);
        var written = File.GetLastWriteTimeUtc(Dest);
        var requests = _ca.Requests.Count;
        arrange();

        var run = Run(shell, new() { ["MODULARCA_KRL_CONNECT_TIMEOUT"] = "5", ["MODULARCA_KRL_MAX_TIME"] = "20" }, arguments ?? StandardArguments());

        Assert.True(run.Exit == 1, run.Output);
        Assert.Contains(says, run.Output);
        Assert.Contains("the installed list was left as it is", run.Output);
        Assert.Equal(list, File.ReadAllBytes(Dest));
        Assert.Equal(state, File.ReadAllBytes(State));
        Assert.Equal(written, File.GetLastWriteTimeUtc(Dest));
        Assert.Equal(expectARequest ? requests + 1 : requests, _ca.Requests.Count);
        AssertOnlyTheListAndItsETagAreThere();
    }

    /// <summary>No temporary file is left beside the installed list, whatever happened.</summary>
    private void AssertOnlyTheListAndItsETagAreThere()
        => Assert.Equal(new[] { "revoked_keys.krl", "revoked_keys.krl.etag" },
            Directory.GetFileSystemEntries(_ssh).Select(p => Path.GetFileName(p)!).OrderBy(n => n, StringComparer.Ordinal).ToArray());

    private string[] StandardArguments() => ["--url", _ca.Url, "--dest", Posix(Dest), "--cacert", Posix(_ca.BundlePath)];

    private ScriptRun Fetch(string shell, params string[] extra) => Run(shell, [], [.. StandardArguments(), .. extra]);

    private static string Posix(string path) => path.Replace('\\', '/');

    private sealed record ScriptRun(int Exit, string Output);

    /// <summary>Runs the script under <paramref name="shell"/> with only the <c>MODULARCA_KRL_*</c> variables given.</summary>
    private static ScriptRun Run(string shell, Dictionary<string, string> environment, params string[] arguments)
    {
        var start = new ProcessStartInfo(ShellPaths[shell])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add(Posix(ScriptPath()));
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("MODULARCA_KRL_", StringComparison.OrdinalIgnoreCase)).ToList())
            start.Environment.Remove(name);
        foreach (var (name, value) in environment)
            start.Environment[name] = value;
        if (ToolPath is { } tools)
            start.Environment["PATH"] = tools + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(90_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("modularca-krl-fetch.sh did not finish in 90 s");
        }
        return new ScriptRun(process.ExitCode, stdout.Result + stderr.Result);
    }

    private static string ScriptPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "deploy", "ssh-krl", "modularca-krl-fetch.sh");
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>On Windows, the directories of Git for Windows that hold the shell's tools, to put first on the path.</summary>
    private static string? ToolPath { get; set; }

    /// <summary>
    /// The shells to run the script under: <c>sh</c>, and <c>dash</c> where installed. One is
    /// kept only when <c>curl</c> resolves in it and its <c>ssh-keygen</c> lists a KRL.
    /// </summary>
    private static Dictionary<string, string> FindShells()
    {
        var candidates = new Dictionary<string, string>(StringComparer.Ordinal);
        if (OperatingSystem.IsWindows())
        {
            var root = DbOwnershipScriptTests.FindBash() is { } bash ? new FileInfo(bash).Directory : null;
            while (root != null && !File.Exists(Path.Combine(root.FullName, "usr", "bin", "sh.exe")))
                root = root.Parent;
            if (root != null)
            {
                var usrBin = Path.Combine(root.FullName, "usr", "bin");
                ToolPath = usrBin + Path.PathSeparator + Path.Combine(root.FullName, "mingw64", "bin");
                candidates["sh"] = Path.Combine(usrBin, "sh.exe");
                if (File.Exists(Path.Combine(usrBin, "dash.exe")))
                    candidates["dash"] = Path.Combine(usrBin, "dash.exe");
            }
        }
        else
        {
            if (File.Exists("/bin/sh"))
                candidates["sh"] = "/bin/sh";
            foreach (var dash in new[] { "/bin/dash", "/usr/bin/dash" })
            {
                if (File.Exists(dash))
                    candidates.TryAdd("dash", dash);
            }
        }

        var krl = Posix(SshFixtures.PathOf("revoked.krl"));
        return candidates.Where(c => Probe(c.Value, krl)).ToDictionary(c => c.Key, c => c.Value, StringComparer.Ordinal);
    }

    private static bool Probe(string shellPath, string krl)
    {
        try
        {
            var start = new ProcessStartInfo(shellPath)
            {
                RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true,
            };
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("command -v curl >/dev/null && command -v mktemp >/dev/null && ssh-keygen -Q -l -f \"$1\" >/dev/null");
            start.ArgumentList.Add("probe");
            start.ArgumentList.Add(krl);
            if (ToolPath is { } tools)
                start.Environment["PATH"] = tools + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
            using var process = Process.Start(start)!;
            process.StandardInput.Close();
            _ = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30_000))
            {
                process.Kill(entireProcessTree: true);
                return false;
            }
            return process.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// A self-signed certificate for <c>localhost</c> that is its own issuer, so the one PEM
    /// file is the whole trust bundle a test hands to <c>--cacert</c>.
    /// </summary>
    private static (X509Certificate2 Certificate, string Pem) MakeServerIdentity()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var made = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pkcs12), null), made.ExportCertificatePem());
    }

    /// <summary>What the stand-in answers one request with.</summary>
    private sealed record Reply(int StatusCode, byte[] Body, string? ETag)
    {
        /// <summary>A <c>Content-Length</c> other than the body's, for a transfer that ends early.</summary>
        public int? DeclaredLength { get; init; }

        /// <summary>A <c>Location</c> header, for a redirect.</summary>
        public string? Location { get; init; }

        public static Reply Ok(byte[] body, string? etag) => new(200, body, etag);

        public static Reply NotModified(string etag) => new(304, [], etag);

        public static Reply Status(int status, byte[] body) => new(status, body, null);

        public byte[] ToBytes()
        {
            var head = new StringBuilder($"HTTP/1.1 {StatusCode} {(StatusCode == 200 ? "OK" : StatusCode == 304 ? "Not Modified" : "Status")}\r\n");
            if (StatusCode == 200)
                head.Append("Content-Type: application/octet-stream\r\n");
            if (ETag != null)
                head.Append($"ETag: {ETag}\r\nCache-Control: no-cache\r\n");
            if (Location != null)
                head.Append($"Location: {Location}\r\n");
            if (StatusCode != 304)
                head.Append($"Content-Length: {DeclaredLength ?? Body.Length}\r\n");
            head.Append("Connection: close\r\n\r\n");
            return [.. Encoding.ASCII.GetBytes(head.ToString()), .. Body];
        }
    }

    /// <summary>
    /// A stand-in for the CA's public KRL route: an HTTPS listener on the loopback interface
    /// that records each request's path and <c>If-None-Match</c>, and answers with what
    /// <see cref="Answer"/> returns for it.
    /// </summary>
    private sealed class StandInCa : IDisposable
    {
        public const string KeyId = "6f1c2a3b-0000-4000-8000-00000000c0de";

        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly List<(string Path, string? IfNoneMatch)> _requests = [];

        public StandInCa(string directory)
        {
            BundlePath = Path.Combine(directory, "stand-in-ca.pem");
            File.WriteAllText(BundlePath, ServerIdentity.Value.Pem + "\n");
            _listener.Start();
            Url = $"https://localhost:{((IPEndPoint)_listener.LocalEndpoint).Port}/ssh/ca-keys/{KeyId}/krl";
            _ = AcceptAsync();
        }

        /// <summary>The PEM file that makes the stand-in's certificate trusted.</summary>
        public string BundlePath { get; }

        /// <summary>The KRL URL the stand-in serves.</summary>
        public string Url { get; }

        /// <summary>The answer to a request, given its <c>If-None-Match</c> value or null.</summary>
        public Func<string?, Reply> Answer { get; set; } = _ => Reply.Status(500, []);

        /// <summary>The requests that got as far as HTTP, oldest first.</summary>
        public IReadOnlyList<(string Path, string? IfNoneMatch)> Requests
        {
            get { lock (_requests) return _requests.ToList(); }
        }

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                    return;
                }
                _ = Task.Run(() => ServeAsync(client));
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            try
            {
                using (client)
                await using (var tls = new SslStream(client.GetStream()))
                {
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = ServerIdentity.Value.Certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    });

                    var head = new StringBuilder();
                    var one = new byte[1];
                    while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && head.Length < 16384)
                    {
                        if (await tls.ReadAsync(one) == 0)
                            return;
                        head.Append((char)one[0]);
                    }
                    var lines = head.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                    var path = lines[0].Split(' ')[1];
                    var asked = lines.Skip(1).FirstOrDefault(l => l.StartsWith("If-None-Match:", StringComparison.OrdinalIgnoreCase));
                    var ifNoneMatch = asked?[(asked.IndexOf(':') + 1)..].Trim();
                    lock (_requests)
                        _requests.Add((path, ifNoneMatch));

                    await tls.WriteAsync(Answer(ifNoneMatch).ToBytes());
                    await tls.FlushAsync();
                    await tls.ShutdownAsync();
                }
            }
            catch (Exception ex) when (ex is IOException or AuthenticationException or SocketException or ObjectDisposedException or InvalidOperationException)
            {
                // A client that does not trust the certificate hangs up during the handshake.
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _stop.Dispose();
        }
    }
}
