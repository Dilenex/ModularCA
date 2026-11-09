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
/// <c>CREATEDB</c> and <c>CREATEROLE</c>, never superuser. While the run lasts it is a member of
/// the application and audit roles it creates, so its password is a real credential: it travels
/// to <c>psql</c> on standard input, never on the command line (where any local user could read
/// it from <c>/proc</c>), and as a SCRAM verifier, so the server log never holds the plaintext.
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

    /// <summary>
    /// The command line <see cref="PsqlAsync"/> runs. It carries no SQL: the statement goes on
    /// standard input. <c>-X</c> skips the postgres user's <c>.psqlrc</c>, <c>-q</c> keeps command
    /// tags out of the output, <c>-tA</c> prints bare values, and <c>ON_ERROR_STOP</c> makes a
    /// failed statement a non-zero exit, as <c>-c</c> did.
    /// </summary>
    public static readonly IReadOnlyList<string> PsqlArguments =
        ["-u", "postgres", "--", "psql", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1"];

    /// <summary>
    /// The SCRAM-SHA-256 verifier PostgreSQL stores for <paramref name="password"/> (RFC 7677, in
    /// PostgreSQL's <c>SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey</c> form). Given in
    /// <c>CREATE ROLE ... PASSWORD</c>, it is stored as is, so the plaintext never reaches the
    /// server or its log. The password must be ASCII, which needs no SASLprep.
    /// </summary>
    /// <param name="password">The ASCII password.</param>
    /// <param name="salt">The salt; 16 random bytes when null.</param>
    /// <param name="iterations">PBKDF2 iterations; 4096 is PostgreSQL's default.</param>
    /// <returns>The verifier.</returns>
    public static string ScramSha256Verifier(string password, byte[]? salt = null, int iterations = 4096)
    {
        salt ??= RandomNumberGenerator.GetBytes(16);
        var salted = Rfc2898DeriveBytes.Pbkdf2(System.Text.Encoding.ASCII.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);
        var clientKey = HMACSHA256.HashData(salted, "Client Key"u8);
        var storedKey = SHA256.HashData(clientKey);
        var serverKey = HMACSHA256.HashData(salted, "Server Key"u8);
        CryptographicOperations.ZeroMemory(salted);
        CryptographicOperations.ZeroMemory(clientKey);
        return $"SCRAM-SHA-256${iterations}:{Convert.ToBase64String(salt)}${Convert.ToBase64String(storedKey)}:{Convert.ToBase64String(serverKey)}";
    }

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

        // The verifier, not the password: PostgreSQL stores a SCRAM verifier it is given as is, so
        // the statement (on stdin, see PsqlAsync) and any server log of it hold no plaintext.
        var create = await PsqlAsync(
            $"CREATE ROLE {TemporaryRole} WITH LOGIN PASSWORD '{ScramSha256Verifier(password)}' CREATEDB CREATEROLE", ct);
        if (create.ExitCode != 0)
            throw new InvalidOperationException(
                "Could not create a temporary administrative role: "
                + (string.IsNullOrWhiteSpace(create.Error) ? "psql failed" : create.Error.Trim()));

        say($"  using a temporary role '{TemporaryRole}' (CREATEDB, CREATEROLE — not superuser)");
        return new LocalPostgresAccess(TemporaryRole, password, say) { _created = true };
    }

    /// <summary>
    /// Drops the temporary role. Safe to call more than once.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The role could not be dropped. It can still create databases and roles, so the caller fails
    /// the run and the message carries the statement to run.
    /// </exception>
    public async Task ReleaseAsync()
    {
        if (!_created)
            return;
        _created = false;

        var drop = await PsqlAsync($"DROP ROLE IF EXISTS {TemporaryRole}", CancellationToken.None);
        if (drop.ExitCode != 0)
            throw new InvalidOperationException(
                $"The temporary role '{TemporaryRole}' could not be dropped"
                + (string.IsNullOrWhiteSpace(drop.Error) ? "" : $" ({drop.Error.Trim()})")
                + $". It can create databases and roles; drop it now: sudo -u postgres psql -c \"DROP ROLE {TemporaryRole};\"");
        _say($"  temporary role '{TemporaryRole}' removed");
    }

    /// <summary>
    /// Drops the temporary role if <see cref="ReleaseAsync"/> has not, reporting rather than
    /// throwing a failure: the path that reaches here is already failing.
    /// </summary>
    /// <returns>A task that completes when the attempt is over.</returns>
    public async ValueTask DisposeAsync()
    {
        try
        {
            await ReleaseAsync();
        }
        catch (InvalidOperationException ex)
        {
            _say($"  (!) {ex.Message}");
        }
    }

    /// <summary>
    /// Runs one statement as the <c>postgres</c> user over the local socket. The statement goes to
    /// <c>psql</c> on standard input, not as a <c>-c</c> argument: arguments are readable by every
    /// local user through <c>/proc/&lt;pid&gt;/cmdline</c> and <c>ps</c> for as long as the process
    /// runs, and the role-creating statement carries a credential.
    /// </summary>
    /// <param name="sql">The statement.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>psql's exit code (non-zero when the statement failed), output and error text.</returns>
    private static async Task<(int ExitCode, string Output, string Error)> PsqlAsync(string sql, CancellationToken ct)
    {
        // runuser rather than sudo: it is in the base system, needs no sudoers entry, and we are
        // already root or IsAvailable would have said no.
        var startInfo = new ProcessStartInfo("runuser")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in PsqlArguments)
            startInfo.ArgumentList.Add(arg);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("could not start runuser");

        await process.StandardInput.WriteLineAsync(sql.AsMemory(), ct);
        process.StandardInput.Close();

        var output = await process.StandardOutput.ReadToEndAsync(ct);
        var error = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return (process.ExitCode, output, error);
    }
}
