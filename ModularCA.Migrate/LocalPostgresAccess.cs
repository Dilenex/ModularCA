using System.Diagnostics;
using System.Security.Cryptography;

namespace ModularCA.Migrate;

/// <summary>
/// Obtains an administrative PostgreSQL account without the operator inventing one.
/// <para>
/// On a Debian or Ubuntu host the PostgreSQL superuser is reachable with no password at all: the
/// package ships <c>local all postgres peer</c>, so the operating system's own <c>postgres</c> user
/// is trusted on the unix socket. Root can become that user. What root cannot do is connect as it
/// over TCP, because the role has no password — which is why asking an operator to supply
/// administrative credentials means first asking them to invent some.
/// </para>
/// <para>
/// So when no credentials are given, this creates a temporary role through the socket, uses it for
/// the run, and drops it at the end. The role is exactly what the preflight requires and no more —
/// <c>CREATEDB</c> and <c>CREATEROLE</c>, never superuser — so even while it exists it cannot read
/// anything the migration does not create.
/// </para>
/// <para>
/// Everything here degrades to an explanation. If the host is not one where this works, the
/// operator is told the single statement to run instead, rather than being left with a failure to
/// interpret.
/// </para>
/// </summary>
public sealed class LocalPostgresAccess : IAsyncDisposable
{
    /// <summary>The name of the temporary role, chosen to be obvious in a role listing.</summary>
    public const string TemporaryRole = "modularca_migration_tmp";

    private readonly Action<string> _say;
    private bool _created;

    private LocalPostgresAccess(string user, string password, Action<string> say)
    {
        User = user;
        Password = password;
        _say = say;
    }

    /// <summary>The administrative role to connect as.</summary>
    public string User { get; }

    /// <summary>That role's password.</summary>
    public string Password { get; }

    /// <summary>
    /// Whether this host can hand out an administrative role without being asked for credentials.
    /// </summary>
    /// <returns>True on Linux, running as root, with psql present.</returns>
    public static bool IsAvailable() =>
        OperatingSystem.IsLinux()
        && string.Equals(Environment.UserName, "root", StringComparison.Ordinal)
        && (File.Exists("/usr/bin/psql") || File.Exists("/usr/local/bin/psql"));

    /// <summary>
    /// The statement an operator runs when this cannot be done automatically. Printed rather than
    /// hidden, because it is short, it is the whole of what is needed, and it is the same thing
    /// this class does on their behalf.
    /// </summary>
    /// <returns>A copy-pasteable shell line.</returns>
    public static string ManualInstructions() =>
        "sudo -u postgres psql -c \"CREATE ROLE migrator WITH LOGIN PASSWORD 'choose-one' CREATEDB CREATEROLE;\"\n"
        + "then re-run with --target-admin-user migrator --target-admin-password 'choose-one'";

    /// <summary>
    /// Creates the temporary administrative role through the local socket.
    /// </summary>
    /// <param name="say">Progress sink.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The access, which must be disposed so the role is dropped.</returns>
    /// <exception cref="InvalidOperationException">The role could not be created.</exception>
    public static async Task<LocalPostgresAccess> AcquireAsync(Action<string> say, CancellationToken ct)
    {
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        // Existence first, so a leftover role from an interrupted run is a clear message rather
        // than a confusing "already exists" from the create.
        var existing = await PsqlAsync($"SELECT 1 FROM pg_roles WHERE rolname = '{TemporaryRole}'", ct);
        if (existing.ExitCode != 0)
            throw new InvalidOperationException(
                "Could not reach the local PostgreSQL as the postgres user: "
                + (string.IsNullOrWhiteSpace(existing.Error) ? "psql failed" : existing.Error.Trim()));

        if (existing.Output.Trim() == "1")
            throw new InvalidOperationException(
                $"The role '{TemporaryRole}' already exists, which means a previous run was interrupted "
                + $"before it could clean up. Remove it with: sudo -u postgres psql -c \"DROP ROLE {TemporaryRole};\"");

        var create = await PsqlAsync(
            $"CREATE ROLE {TemporaryRole} WITH LOGIN PASSWORD '{password}' CREATEDB CREATEROLE", ct);
        if (create.ExitCode != 0)
            throw new InvalidOperationException(
                "Could not create a temporary administrative role: "
                + (string.IsNullOrWhiteSpace(create.Error) ? "psql failed" : create.Error.Trim()));

        say($"  using a temporary role '{TemporaryRole}' (CREATEDB, CREATEROLE — not superuser)");
        return new LocalPostgresAccess(TemporaryRole, password, say) { _created = true };
    }

    /// <summary>Drops the temporary role. Safe to call more than once.</summary>
    /// <returns>A task that completes when the role is gone.</returns>
    public async ValueTask DisposeAsync()
    {
        if (!_created)
            return;
        _created = false;

        var drop = await PsqlAsync($"DROP ROLE IF EXISTS {TemporaryRole}", CancellationToken.None);
        if (drop.ExitCode == 0)
            _say($"  temporary role '{TemporaryRole}' removed");
        else
            _say($"  (!) could not remove the temporary role '{TemporaryRole}'; drop it by hand");
    }

    private static async Task<(int ExitCode, string Output, string Error)> PsqlAsync(string sql, CancellationToken ct)
    {
        // runuser rather than sudo: it is in the base system, needs no sudoers entry, and we are
        // already root or IsAvailable would have said no.
        var startInfo = new ProcessStartInfo("runuser")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-u");
        startInfo.ArgumentList.Add("postgres");
        startInfo.ArgumentList.Add("--");
        startInfo.ArgumentList.Add("psql");
        startInfo.ArgumentList.Add("-tAc");
        startInfo.ArgumentList.Add(sql);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("could not start runuser");

        var output = await process.StandardOutput.ReadToEndAsync(ct);
        var error = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return (process.ExitCode, output, error);
    }
}
