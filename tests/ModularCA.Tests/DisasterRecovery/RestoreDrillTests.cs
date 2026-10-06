using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Database;
using Npgsql;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Xunit;
using Xunit.Abstractions;

namespace ModularCA.Tests.DisasterRecovery;

/// <summary>How the host a backup is restored onto was prepared.</summary>
public enum NewHost
{
    /// <summary>Two roles and two empty databases made by hand, and a <c>db.yaml</c> naming them.</summary>
    EmptyDatabases,

    /// <summary>A complete new install with its own root, which the restore replaces.</summary>
    FreshInstall,
}

/// <summary>
/// The restore drill: the built node, run as an operator runs it. One host is installed
/// unattended, started and backed up; the host and its databases are then destroyed, and the
/// archive is restored onto a second host from nothing but what an operator keeps off the first
/// (the archive, the backup key and <c>keystore.yaml</c>). The second host must start, serve the
/// same root, sign with its key and carry the audit trail.
/// </summary>
/// <remarks>
/// Opt-in through <c>MODULARCA_TEST_PG</c>, as the other PostgreSQL harness tests, and it needs
/// <c>pg_dump</c> and <c>pg_restore</c>. Build ModularCA.API first: the drill runs a copy of its
/// output. The unattended install needs a superuser in <c>setup-database.yaml</c>; the drill
/// makes one for itself and drops it, so the harness's own credentials never reach a file or
/// another process.
/// </remarks>
[Trait("Category", "PostgreSQL")]
public sealed class RestoreDrillTests(ITestOutputHelper output)
{
    private const string ServerVariable = "MODULARCA_TEST_PG";
    private const string RootLabel = "drill-root";

    [RequiresPostgresClientToolsTheory(ServerVariable)]
    [InlineData(NewHost.EmptyDatabases)]
    [InlineData(NewHost.FreshInstall)]
    public async Task A_backup_restores_onto_a_new_host_and_the_ca_signs_again(NewHost newHost)
    {
        await using var server = await DrillServer.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!);
        var (httpsPort, httpPort) = (FreePort(), FreePort());
        var work = Path.Combine(Path.GetTempPath(), $"modularca-drill-{Guid.NewGuid():N}"[..40]);
        Directory.CreateDirectory(work);
        DrillHost? old = null, restored = null;
        try
        {
            // The first host: installed unattended, started, used, stopped, backed up.
            var oldLayout = server.NewLayout();
            old = DrillHost.Create(Path.Combine(work, "old"), server, output);
            old.WriteInstallFiles(oldLayout, httpsPort, httpPort);
            await old.RunAsync("install", ["--bootstrap"]);
            await old.StartAsync(httpPort);
            var root = await old.GetAsync(httpPort, $"/ca/{RootLabel}");
            var crlBefore = ParseCrl(await old.GetUntilAsync(httpPort, $"/crl/{RootLabel}", TimeSpan.FromMinutes(3)));
            var rootCertificate = new X509CertificateParser().ReadCertificate(root);
            var leafBefore = await ServedUnderAsync(httpsPort, rootCertificate);
            await old.StopAsync();

            var dbYaml = old.Databases();
            var certificates = await CountAsync(dbYaml.App, "SELECT count(*) FROM \"Certificates\"");
            var auditRecords = await CountAsync(dbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\"");
            var keyRing = Directory.GetFiles(Path.Combine(old.ConfigDirectory, "dp-keys")).Select(Path.GetFileName).Order().ToList();
            Assert.NotEmpty(keyRing);

            var backup = await old.RunAsync("backup", ["--backup"]);
            // The node's scheduler may have taken a backup of its own while it ran; the drill restores the last one.
            var archive = Directory.GetFiles(Path.Combine(old.Directory, "backups"), "modularca-backup-*.enc")
                .OrderBy(File.GetLastWriteTimeUtc).Last();

            // What an operator keeps off the host, and nothing else.
            var kit = Path.Combine(work, "kit");
            Directory.CreateDirectory(kit);
            File.Copy(archive, Path.Combine(kit, Path.GetFileName(archive)));
            File.Copy(Path.Combine(old.ConfigDirectory, "backup.key"), Path.Combine(kit, "backup.key"));
            File.Copy(Path.Combine(old.ConfigDirectory, "keystore.yaml"), Path.Combine(kit, "keystore.yaml"));

            // The disaster: the host and both databases are gone.
            Directory.Delete(old.Directory, recursive: true);
            await server.DropAsync(oldLayout);

            // The second host.
            var newLayout = server.NewLayout();
            restored = DrillHost.Create(Path.Combine(work, "new"), server, output);
            if (newHost == NewHost.FreshInstall)
            {
                restored.WriteInstallFiles(newLayout, httpsPort, httpPort);
                await restored.RunAsync("install on the new host", ["--bootstrap"]);
                await restored.StartAsync(httpPort);
                Assert.NotEqual(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
                await restored.StopAsync();
            }
            else
            {
                await server.CreateEmptyDatabasesAsync(newLayout);
                restored.WriteDbYaml(newLayout);
            }

            Directory.CreateDirectory(Path.Combine(restored.Directory, "backups"));
            var archiveOnNewHost = Path.Combine(restored.Directory, "backups", Path.GetFileName(archive));
            File.Copy(Path.Combine(kit, Path.GetFileName(archive)), archiveOnNewHost);
            File.Copy(Path.Combine(kit, "backup.key"), Path.Combine(restored.ConfigDirectory, "backup.key"), overwrite: true);
            File.Copy(Path.Combine(kit, "keystore.yaml"), Path.Combine(restored.ConfigDirectory, "keystore.yaml"), overwrite: true);

            var restore = await restored.RunAsync("restore", ["--restore", archiveOnNewHost], stdin: "RESTORE\n");

            var newDbYaml = restored.Databases();
            Assert.Equal(certificates, await CountAsync(newDbYaml.App, "SELECT count(*) FROM \"Certificates\""));
            Assert.True(await CountAsync(newDbYaml.Audit, "SELECT count(*) FROM \"AuditLogs\"") >= auditRecords);

            var start = await restored.StartAsync(httpPort);

            // The same root, and a certificate the restored key signed after the restore.
            Assert.Equal(root, await restored.GetAsync(httpPort, $"/ca/{RootLabel}"));
            // The web certificate's key is in no backup, so the one served now is new.
            var leafAfter = await ServedUnderAsync(httpsPort, rootCertificate);
            Assert.NotEqual(leafBefore.SerialNumber, leafAfter.SerialNumber);
            Assert.Equal(leafBefore.SubjectDN.ToString(), leafAfter.SubjectDN.ToString());
            Assert.Equal(SubjectAltNames(leafBefore), SubjectAltNames(leafAfter));

            // A CRL signed after the restore, numbered above every CRL the first host published.
            var crlAfter = await UntilAsync(TimeSpan.FromMinutes(3), async () =>
            {
                var crl = ParseCrl(await restored.GetAsync(httpPort, $"/crl/{RootLabel}"));
                return CrlNumber(crl) > CrlNumber(crlBefore) ? crl : null;
            }, "the restored node published no CRL numbered above the last one the first host published");
            crlAfter.Verify(rootCertificate.GetPublicKey());

            // The configuration secrets were unwrapped, and the audit trail is whole.
            Assert.False(Directory.Exists(Path.Combine(restored.ConfigDirectory, "restore-pending")));
            var restoredKeyRing = Directory.GetFiles(Path.Combine(restored.ConfigDirectory, "dp-keys")).Select(Path.GetFileName).ToList();
            Assert.All(keyRing, name => Assert.Contains(name, restoredKeyRing));
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                             .UseNpgsql(PostgresConnection.Build(newDbYaml.Audit)).Options))
            {
                var chain = await new AuditHashChainService().VerifyAsync(audit, null, limit: 100_000);
                Assert.Empty(chain.Breaks);
                Assert.False(chain.Truncated);
            }

            output.WriteLine($"backup {backup.TotalSeconds:F0}s, restore {restore.TotalSeconds:F0}s, start to serving {start.TotalSeconds:F0}s");
        }
        finally
        {
            if (old is not null) await old.StopAsync();
            if (restored is not null) await restored.StopAsync();
            NpgsqlConnection.ClearAllPools();
            try { Directory.Delete(work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private static X509Crl ParseCrl(byte[] der) => new X509CrlParser().ReadCrl(der);

    private static long CrlNumber(X509Crl crl) =>
        DerInteger.GetInstance(Asn1Object.FromByteArray(crl.GetExtensionValue(X509Extensions.CrlNumber).GetOctets())).Value.LongValue;

    private static async Task<long> CountAsync(DbInstance instance, string sql)
    {
        await using var conn = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Pooling = false }.ConnectionString);
        await conn.OpenAsync();
        return Convert.ToInt64(await new NpgsqlCommand(sql, conn).ExecuteScalarAsync());
    }

    /// <summary>Waits until the node serves, on its HTTPS port, a certificate <paramref name="root"/> signed.</summary>
    private static Task<Org.BouncyCastle.X509.X509Certificate> ServedUnderAsync(int httpsPort, Org.BouncyCastle.X509.X509Certificate root) =>
        UntilAsync(TimeSpan.FromMinutes(2), async () =>
        {
            var served = await ServedCertificateAsync(httpsPort);
            try
            {
                served.Verify(root.GetPublicKey());
                return served;
            }
            catch (Org.BouncyCastle.Security.GeneralSecurityException)
            {
                return null;
            }
        }, "the node never served a web certificate its root signed");

    private static string SubjectAltNames(Org.BouncyCastle.X509.X509Certificate certificate) =>
        string.Join(",", (certificate.GetSubjectAlternativeNames() ?? []).Select(n => $"{n[0]}:{n[1]}").Order());

    /// <summary>The certificate the node serves on its HTTPS port.</summary>
    private static async Task<Org.BouncyCastle.X509.X509Certificate> ServedCertificateAsync(int httpsPort)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, httpsPort);
        await using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync("localhost");
        return new X509CertificateParser().ReadCertificate(tls.RemoteCertificate!.GetRawCertData());
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }

    /// <summary>Polls <paramref name="probe"/> until it returns a value; fails with <paramref name="failure"/> when it never does.</summary>
    internal static async Task<T> UntilAsync<T>(TimeSpan limit, Func<Task<T?>> probe, string failure) where T : class
    {
        var watch = Stopwatch.StartNew();
        Exception? last = null;
        while (watch.Elapsed < limit)
        {
            try
            {
                if (await probe() is { } value)
                    return value;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or TaskCanceledException)
            {
                last = ex;
            }
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
        throw new Xunit.Sdk.XunitException($"{failure} (waited {limit.TotalSeconds:F0}s{(last is null ? "" : "; last error: " + last.Message)})");
    }
}

/// <summary>The role and database names of one install on the drill's server.</summary>
internal sealed record DrillLayout(string AppRole, string AuditRole, string AppDatabase, string AuditDatabase)
{
    public string AppPassword { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    public string AuditPassword { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    public string AuditOwnerRole => AuditRole + PostgresLayoutNames.OwnerSuffix;
}

/// <summary>
/// The PostgreSQL server the drill uses: a superuser made for the drill, the layouts it handed
/// out, and their removal. Everything is dropped on dispose.
/// </summary>
internal sealed class DrillServer : IAsyncDisposable
{
    private readonly string _admin;
    private readonly List<DrillLayout> _layouts = [];

    private DrillServer(string admin)
    {
        _admin = new NpgsqlConnectionStringBuilder(admin) { Pooling = false }.ConnectionString;
        var b = new NpgsqlConnectionStringBuilder(admin);
        (Host, Port, SslMode) = (b.Host ?? "localhost", b.Port, b.SslMode.ToString());
        SetupRole = $"mcat_dr_su_{Guid.NewGuid().ToString("N")[..10]}";
        SetupPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    }

    public string Host { get; }
    public int Port { get; }
    public string SslMode { get; }

    /// <summary>The superuser the drill's unattended installs log in as.</summary>
    public string SetupRole { get; }
    public string SetupPassword { get; }

    public static async Task<DrillServer> CreateAsync(string admin)
    {
        var server = new DrillServer(admin);
        await server.ExecuteAsync($"CREATE ROLE {Q(server.SetupRole)} WITH LOGIN SUPERUSER PASSWORD '{server.SetupPassword}'");
        return server;
    }

    public DrillLayout NewLayout()
    {
        var suffix = Guid.NewGuid().ToString("N")[..10];
        var layout = new DrillLayout($"mcat_dr_app_{suffix}", $"mcat_dr_audit_{suffix}", $"mcat-dr-app-{suffix}", $"mcat-dr-audit-{suffix}");
        _layouts.Add(layout);
        return layout;
    }

    /// <summary>Two login roles and two empty databases, each owned by its role: a new host prepared by hand.</summary>
    public async Task CreateEmptyDatabasesAsync(DrillLayout layout)
    {
        await ExecuteAsync($"CREATE ROLE {Q(layout.AppRole)} WITH LOGIN PASSWORD '{layout.AppPassword}'");
        await ExecuteAsync($"CREATE ROLE {Q(layout.AuditRole)} WITH LOGIN PASSWORD '{layout.AuditPassword}'");
        await ExecuteAsync($"CREATE DATABASE {Q(layout.AppDatabase)} OWNER {Q(layout.AppRole)} ENCODING 'UTF8' TEMPLATE template0");
        await ExecuteAsync($"CREATE DATABASE {Q(layout.AuditDatabase)} OWNER {Q(layout.AuditRole)} ENCODING 'UTF8' TEMPLATE template0");
    }

    public async Task DropAsync(DrillLayout layout)
    {
        NpgsqlConnection.ClearAllPools();
        foreach (var database in new[] { layout.AppDatabase, layout.AuditDatabase })
            await TryAsync($"DROP DATABASE IF EXISTS {Q(database)} WITH (FORCE)");
        foreach (var role in new[] { layout.AppRole, layout.AuditRole, layout.AuditOwnerRole })
            await TryAsync($"DROP ROLE IF EXISTS {Q(role)}");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var layout in _layouts)
            await DropAsync(layout);
        await TryAsync($"DROP ROLE IF EXISTS {Q(SetupRole)}");
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var conn = new NpgsqlConnection(_admin);
        await conn.OpenAsync();
        await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
    }

    private async Task TryAsync(string sql)
    {
        try { await ExecuteAsync(sql); }
        catch (PostgresException) { }
    }

    private static string Q(string identifier) => PostgresConnection.QuoteIdentifier(identifier);
}

/// <summary>
/// One host of the drill: a copy of the built node in its own directory, run as its own
/// processes. The harness's own connection string is taken out of their environment.
/// </summary>
internal sealed class DrillHost
{
    private static readonly string[] RuntimeDirectories = ["config", "keystores", "logs", "backups", "BuildHost-net472", "BuildHost-netcore"];

    private readonly DrillServer _server;
    private readonly ITestOutputHelper _output;
    private readonly StringBuilder _nodeLog = new();
    private Process? _node;

    private DrillHost(string directory, DrillServer server, ITestOutputHelper output)
    {
        (Directory, _server, _output) = (directory, server, output);
    }

    public string Directory { get; }
    public string ConfigDirectory => Path.Combine(Directory, "config");

    /// <summary>Copies the built node into <paramref name="directory"/> with the example files a distribution ships, and nothing a run left behind.</summary>
    public static DrillHost Create(string directory, DrillServer server, ITestOutputHelper output)
    {
        var repo = RepoRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).Parent!.Name;
        var build = Path.Combine(repo, "ModularCA.API", "bin", configuration, "net10.0");
        Assert.True(File.Exists(Path.Combine(build, "ModularCA.API.dll")), $"Build ModularCA.API ({configuration}) before the drill: {build} holds no node.");

        Copy(build, directory, top: true);
        var host = new DrillHost(directory, server, output);
        System.IO.Directory.CreateDirectory(host.ConfigDirectory);
        foreach (var example in System.IO.Directory.GetFiles(Path.Combine(repo, "config"), "*.example"))
            File.Copy(example, Path.Combine(host.ConfigDirectory, Path.GetFileName(example)));
        return host;
    }

    /// <summary>The two files an unattended install reads.</summary>
    public void WriteInstallFiles(DrillLayout layout, int httpsPort, int httpPort)
    {
        File.WriteAllText(Path.Combine(ConfigDirectory, "bootstrap.yaml"), $"""
            CA:
              Subject:
                CN: "Drill Root"
                O: "ModularCA Drill"
                C: "US"
              Algorithm: ECDSA
              KeySize: 384
              ValidityYears: 10
            SigningProfile:
              Name: "default"
              IsCa: true
              KeyUsages:
                - digitalSignature
                - keyCertSign
                - crlSign
              ExtendedKeyUsages:
                - 1.3.6.1.5.5.7.3.1
            Features:
              CRL: true
              OCSP: true
              ACME: false
              EST: false
              SCEP: false
              CMP: false
              MSAE: false
            Administration:
              MultipleAdministrators: false
            HttpsApi:
              CN: "localhost"
              PublicDomain: "localhost"
              SANs:
                - "DNS:localhost"
                - "IP:127.0.0.1"
              Port: {httpsPort}
              HttpPort: {httpPort}
              ValidityDays: 397
            """);
        File.WriteAllText(Path.Combine(ConfigDirectory, "setup-database.yaml"), $"""
            SqlRoot:
              Host: {_server.Host}
              Port: {_server.Port}
              Username: {_server.SetupRole}
              Password: "{_server.SetupPassword}"
              SslMode: {_server.SslMode}
            SqlApp:
              Database: {layout.AppDatabase}
              Username: {layout.AppRole}
              SslMode: {_server.SslMode}
            SqlAudit:
              Database: {layout.AuditDatabase}
              Username: {layout.AuditRole}
              SslMode: {_server.SslMode}
            """);
    }

    /// <summary>A <c>db.yaml</c> written by hand, as on a host whose databases the operator created.</summary>
    public void WriteDbYaml(DrillLayout layout) =>
        File.WriteAllText(Path.Combine(ConfigDirectory, "db.yaml"), $"""
            App:
              Host: {_server.Host}
              Port: {_server.Port}
              Database: {layout.AppDatabase}
              Username: {layout.AppRole}
              Password: "{layout.AppPassword}"
              SslMode: {_server.SslMode}
            Audit:
              Host: {_server.Host}
              Port: {_server.Port}
              Database: {layout.AuditDatabase}
              Username: {layout.AuditRole}
              Password: "{layout.AuditPassword}"
              SslMode: {_server.SslMode}
            """);

    /// <summary>The databases this host's <c>db.yaml</c> names, with its runtime roles' credentials.</summary>
    public (DbInstance App, DbInstance Audit) Databases()
    {
        var yaml = YamlDbConfigLoader.Load(Path.Combine(ConfigDirectory, "db.yaml"))!;
        static DbInstance From(YamlDbConfigLoader.DbInstanceConfig c) => new()
        {
            Host = c.Host, Port = c.Port, Database = c.Database, Username = c.Username, Password = c.Password, SslMode = c.SslMode,
        };
        return (From(yaml.App), From(yaml.Audit));
    }

    /// <summary>Runs the node with <paramref name="arguments"/> to completion and requires exit code 0.</summary>
    public async Task<TimeSpan> RunAsync(string step, string[] arguments, string? stdin = null)
    {
        var watch = Stopwatch.StartNew();
        using var process = Start(arguments);
        var log = new StringBuilder();
        Capture(process, log);
        if (stdin is not null)
            await process.StandardInput.WriteAsync(stdin);
        process.StandardInput.Close();

        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail($"The {step} did not finish in 10 minutes:{Environment.NewLine}{Redact(log)}");
        }
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"The {step} exited {process.ExitCode}:{Environment.NewLine}{Redact(log)}");
        _output.WriteLine($"--- {step} ({watch.Elapsed.TotalSeconds:F0}s){Environment.NewLine}{Redact(log)}");
        return watch.Elapsed;
    }

    /// <summary>Starts the node and waits until it serves its root over plain HTTP.</summary>
    public async Task<TimeSpan> StartAsync(int httpPort)
    {
        var watch = Stopwatch.StartNew();
        _nodeLog.Clear();
        _node = Start([]);
        Capture(_node, _nodeLog);
        _node.StandardInput.Close();
        try
        {
            await RestoreDrillTests.UntilAsync<byte[]>(TimeSpan.FromMinutes(4), async () =>
            {
                if (_node.HasExited)
                    throw new Xunit.Sdk.XunitException($"The node exited {_node.ExitCode} while starting.");
                return await GetAsync(httpPort, "/ca/drill-root");
            }, "the node never served its root");
        }
        catch (Xunit.Sdk.XunitException ex)
        {
            throw new Xunit.Sdk.XunitException($"{ex.Message}{Environment.NewLine}{Redact(_nodeLog)}");
        }
        return watch.Elapsed;
    }

    public async Task StopAsync()
    {
        if (_node is null)
            return;
        try
        {
            if (!_node.HasExited)
            {
                _node.Kill(entireProcessTree: true);
                await _node.WaitForExitAsync();
            }
        }
        catch (InvalidOperationException)
        {
        }
        _node.Dispose();
        _node = null;
    }

    public async Task<byte[]> GetAsync(int httpPort, string path)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await http.GetAsync($"http://127.0.0.1:{httpPort}{path}");
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"GET {path} answered {(int)response.StatusCode}");
        return await response.Content.ReadAsByteArrayAsync();
    }

    public Task<byte[]> GetUntilAsync(int httpPort, string path, TimeSpan limit) =>
        RestoreDrillTests.UntilAsync<byte[]>(limit, async () => await GetAsync(httpPort, path), $"GET {path} never succeeded");

    private Process Start(string[] arguments)
    {
        var executable = Path.Combine(Directory, OperatingSystem.IsWindows() ? "ModularCA.API.exe" : "ModularCA.API");
        var start = File.Exists(executable)
            ? new ProcessStartInfo(executable)
            : new ProcessStartInfo("dotnet") { ArgumentList = { Path.Combine(Directory, "ModularCA.API.dll") } };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.WorkingDirectory = Directory;
        start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.StandardOutputEncoding = start.StandardErrorEncoding = Encoding.UTF8;
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("MODULARCA", StringComparison.OrdinalIgnoreCase)).ToList())
            start.Environment.Remove(name);
        start.Environment["PATH"] = PostgresClientTools.Directory + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        return Process.Start(start)!;
    }

    private static void Capture(Process process, StringBuilder log)
    {
        void Append(string? line)
        {
            if (line is null) return;
            lock (log) log.AppendLine(line);
        }
        process.OutputDataReceived += (_, e) => Append(e.Data);
        process.ErrorDataReceived += (_, e) => Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    /// <summary>A log with the server's address and the drill's passwords taken out.</summary>
    private string Redact(StringBuilder log)
    {
        string text;
        lock (log) text = log.ToString();
        return text.Replace(_server.Host, "<db-host>", StringComparison.OrdinalIgnoreCase)
            .Replace(_server.SetupPassword, "<password>", StringComparison.Ordinal);
    }

    private static void Copy(string source, string destination, bool top)
    {
        System.IO.Directory.CreateDirectory(destination);
        foreach (var file in System.IO.Directory.GetFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        foreach (var directory in System.IO.Directory.GetDirectories(source))
        {
            var name = Path.GetFileName(directory);
            if (top && RuntimeDirectories.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            Copy(directory, Path.Combine(destination, name), top: false);
        }
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
