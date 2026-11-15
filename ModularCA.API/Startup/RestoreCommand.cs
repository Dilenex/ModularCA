using System.Text;
using ModularCA.Bootstrap;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--restore &lt;archive&gt; [--restore-audit] [--unattended] [--key-file &lt;file&gt;] [--password-file &lt;file&gt;]</c>:
/// the command-line restore (<see cref="BackupRestore.RestoreWithVerdictAsync"/>), run with the
/// node stopped.
/// </summary>
/// <remarks>
/// <para>
/// <b>Exit status and last line.</b> The process exits with a status from
/// <see cref="RestoreExit"/>, and the last line it writes to standard output starts with the
/// matching marker: <c>RESTORE: DONE</c> (0), <c>RESTORE: REFUSED</c> (3, nothing was changed),
/// <c>RESTORE: FAILED AFTER CHANGES</c> (4) or <c>RESTORE: UNREACHABLE</c> (75, nothing was
/// changed; try again). An orchestrator that gets any other status, or no such line, cannot know
/// what was changed and treats it as 4.
/// </para>
/// <para>
/// <b>Prompts.</b> There are two, and <see cref="UnattendedFlag"/> turns both off: the word
/// <c>RESTORE</c> typed to confirm, and the backup password of an archive this host's stored
/// password key does not open. Without the flag, the password is also never asked for when
/// standard input is not a terminal; the restore is refused instead, saying what to give.
/// </para>
/// <para>
/// <b>Secrets.</b> Every secret is read from a file: the archive's key from <c>config/backup.key</c>
/// or <c>config/backup-password.key</c> (or the paths this host's <c>config.yaml</c> names), or
/// from the file <see cref="BackupManifestCommand.KeyFileFlag"/> names; a backup password from
/// the file <see cref="BackupManifestCommand.PasswordFileFlag"/> names; the database credentials
/// from <c>config/db.yaml</c>; the keystore passphrases from the signer's <c>keystore.yaml</c>.
/// <c>--password &lt;password&gt;</c> still works for a person at a terminal and is refused with
/// <see cref="UnattendedFlag"/>: an argument is readable by every process on the host.
/// </para>
/// </remarks>
public static class RestoreCommand
{
    /// <summary>The flag, followed by the archive's path.</summary>
    public const string Flag = "--restore";

    /// <summary>The flag that turns every prompt off.</summary>
    public const string UnattendedFlag = "--unattended";

    /// <summary>The flag that replaces this host's audit database with the archive's.</summary>
    public const string RestoreAuditFlag = "--restore-audit";

    /// <summary>The flag that gives the backup password as an argument; for a person at a terminal only.</summary>
    public const string PasswordFlag = "--password";

    /// <summary>The usage lines printed for missing or wrong arguments.</summary>
    public const string Usage =
        "Usage: --restore <archive> [--restore-audit] [--unattended] [--key-file <file>] [--password-file <file>]\n"
        + "  --restore-audit    Replace this host's audit database with the archive's. Without it the audit database is kept.\n"
        + "  --unattended       Ask nothing: no confirmation and no password prompt. For an orchestrator.\n"
        + "  --key-file         The archive's key file (backup.key, or backup-password.key), when it is not this host's.\n"
        + "  --password-file    A file holding the backup password, for an archive protected by one.\n"
        + "Exit status: 0 done; 3 refused, nothing was changed; 4 failed after something was changed; 75 a database could not be reached, try again.";

    /// <summary>True when <paramref name="args"/> ask for a restore.</summary>
    /// <param name="args">The process arguments.</param>
    public static bool IsNamedIn(string[] args) => args.Contains(Flag, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Runs the restore, writes its verdict as the last line of standard output, after the log
    /// has been flushed, and returns the exit status.
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="signerPaths">Where the signer's files are, for its journal.</param>
    /// <param name="signerForAppDatabase">Builds the maintenance signer over the application database restored into.</param>
    public static async Task<int> RunAsync(string[] args, SignerPaths signerPaths, Func<string, ISigningService> signerForAppDatabase)
    {
        RestoreResult result;
        try
        {
            result = await RestoreAsync(args, signerPaths, signerForAppDatabase);
        }
        catch (Exception ex)
        {
            // Nothing below the restore itself throws once a database has been touched: the
            // restore turns its own failures into a verdict. What reaches here failed around it.
            Console.WriteLine($"❌ {ex.GetType().Name}: {ex.Message}");
            result = RestoreResult.Refused($"{ex.GetType().Name}: {ex.Message}");
        }

        try { await Log.CloseAndFlushAsync(); } catch (Exception) { /* the verdict still goes out */ }
        Console.Out.WriteLine(result.Verdict);
        Console.Out.Flush();
        return result.ExitCode;
    }

    /// <summary>Reads the arguments, asks what a person at a terminal must be asked, and restores.</summary>
    private static async Task<RestoreResult> RestoreAsync(string[] args, SignerPaths signerPaths, Func<string, ISigningService> signerForAppDatabase)
    {
        var archivePath = BackupManifestCommand.ValueOf(args, Flag, out _);
        if (archivePath == null)
        {
            Console.WriteLine(Usage);
            return RestoreResult.Refused("no archive was named after --restore");
        }

        var unattended = args.Contains(UnattendedFlag, StringComparer.OrdinalIgnoreCase);
        var restoreAudit = args.Contains(RestoreAuditFlag, StringComparer.OrdinalIgnoreCase);

        BackupKeySource keys;
        try
        {
            keys = BackupManifestCommand.KeysFrom(args);
        }
        catch (BackupArchiveException ex)
        {
            Console.WriteLine($"❌ {ex.Message}");
            return RestoreResult.Refused(ex.Message);
        }

        var typedPassword = BackupManifestCommand.ValueOf(args, PasswordFlag, out var passwordGiven);
        if (passwordGiven)
        {
            if (unattended)
            {
                Console.WriteLine($"❌ {PasswordFlag} puts the backup password on the command line, where every process on the host can read it.");
                Console.WriteLine($"   With {UnattendedFlag}, give it in a file: {BackupManifestCommand.PasswordFileFlag} <file>.");
                return RestoreResult.Refused($"{PasswordFlag} is not accepted with {UnattendedFlag}; give the password in a file with {BackupManifestCommand.PasswordFileFlag}");
            }
            if (typedPassword == null)
            {
                Console.WriteLine(Usage);
                return RestoreResult.Refused($"{PasswordFlag} was given without a password");
            }
            Console.WriteLine($"⚠  {PasswordFlag} puts the backup password on the command line; prefer {BackupManifestCommand.PasswordFileFlag} <file>.");
            keys = keys with { Password = keys.Password ?? typedPassword };
        }

        // An archive protected by a password that this host's stored key file does not open: a
        // person at a terminal is asked for the password. Nobody is asked with --unattended or
        // when standard input is not a terminal; the restore then refuses and says what to give.
        if (!unattended && !Console.IsInputRedirected && keys.Password == null && NeedsPassword(archivePath, keys))
        {
            Console.WriteLine();
            Console.WriteLine("This archive is encrypted in StoredPassword mode and cannot be restored with the");
            Console.WriteLine("current password key file. Enter the backup password to proceed (or Ctrl+C to abort):");
            Console.Write("Password: ");

            var entered = new StringBuilder();
            ConsoleKeyInfo keyInfo;
            while ((keyInfo = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
            {
                if (keyInfo.Key == ConsoleKey.Backspace && entered.Length > 0)
                    entered.Remove(entered.Length - 1, 1);
                else if (!char.IsControl(keyInfo.KeyChar))
                    entered.Append(keyInfo.KeyChar);
            }
            Console.WriteLine();
            if (entered.Length == 0)
            {
                Console.WriteLine("No password entered — aborting.");
                return RestoreResult.Refused("no backup password was entered");
            }
            keys = keys with { Password = entered.ToString() };
        }

        Log.Warning("Operator triggered restore (--restore) archive={ArchivePath} restoreAudit={RestoreAudit} unattended={Unattended}",
            archivePath, restoreAudit, unattended);

        // As for --backup: run as the signer from its own directory, the restore is recorded in the
        // signer's audit journal. The password is never part of what is recorded.
        var journal = SignerToolJournal.Open(signerPaths, message => Log.Warning("{Message}", message));
        RestoreResult? result = null;
        await SignerToolJournal.RestoreAsync(journal, archivePath, restoreAudit, async () =>
        {
            result = await BackupRestore.RestoreWithVerdictAsync(archivePath, signerForAppDatabase, new RestoreOptions
            {
                RestoreAudit = restoreAudit,
                Interactive = !unattended,
                Keys = keys,
            });
            return result.ExitCode;
        });
        return result!;
    }

    /// <summary>
    /// True when the archive is protected by a backup password and the stored password key file
    /// (the one named, or this host's) is missing or was made for another password. False for
    /// every other archive, and for one that cannot be read at all: the restore says why.
    /// </summary>
    private static bool NeedsPassword(string archivePath, BackupKeySource keys)
    {
        try
        {
            var info = BackupKeyManager.PeekArchiveInfo(archivePath);
            if (info is not { IsLegacyFormat: false, Mode: BackupEncryptionMode.StoredPassword })
                return false;
            var keyPath = keys.KeyFilePath ?? BackupArchiveFile.DefaultKeyPaths(AppContext.BaseDirectory).PasswordKeyPath;
            if (!File.Exists(keyPath))
                return true;
            var (kek, storedSalt, _, _, _) = BackupKeyManager.ReadPasswordKeyFile(keyPath);
            BackupKeyManager.ZeroKey(kek);
            return info.Salt == null || !storedSalt.AsSpan().SequenceEqual(info.Salt);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or BackupArchiveException)
        {
            return false;
        }
    }
}
