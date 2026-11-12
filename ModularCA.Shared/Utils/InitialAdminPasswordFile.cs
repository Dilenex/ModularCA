using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The file a headless bootstrap leaves the first administrator's generated password in,
/// <c>config/initial-admin-password</c>, when bootstrap.yaml gives no claim token. The password used
/// to be printed to standard output, which under systemd or Podman is the journal: anyone who can
/// read the journal, and anything it is forwarded to, kept a copy for as long as the journal did.
/// The file is readable by the instance's own account only (<see cref="FileSecurityUtil.WriteOwnerOnly"/>);
/// whoever runs the instance reads it, signs in, and changes the password, which the account is
/// made to do at first sign-in. The application deletes the file when that change replaces the
/// password it holds (<see cref="TryDeleteIfHolds"/>), so a forgotten file does not outlive the
/// password in it.
/// </summary>
public static class InitialAdminPasswordFile
{
    /// <summary>The file's name in the config directory.</summary>
    public const string FileName = "initial-admin-password";

    /// <summary>The file's path in <paramref name="configDir"/>.</summary>
    /// <param name="configDir">The instance's config directory.</param>
    public static string PathIn(string configDir) => Path.Combine(configDir, FileName);

    /// <summary>
    /// Writes <paramref name="password"/>, followed by a newline, to the file in
    /// <paramref name="configDir"/>, readable by the current account only, replacing any file there.
    /// Throws when the file cannot be written.
    /// </summary>
    /// <param name="configDir">The instance's config directory.</param>
    /// <param name="password">The generated password.</param>
    /// <returns>The file's path.</returns>
    public static string Write(string configDir, string password)
    {
        var path = PathIn(configDir);
        FileSecurityUtil.WriteOwnerOnly(path, Encoding.UTF8.GetBytes(password + "\n"));
        return path;
    }

    /// <summary>
    /// The password the file in <paramref name="configDir"/> holds, without the trailing newline;
    /// null when there is no file or it cannot be read.
    /// </summary>
    /// <param name="configDir">The instance's config directory.</param>
    public static string? Read(string configDir)
    {
        try
        {
            var path = PathIn(configDir);
            return File.Exists(path) ? File.ReadAllText(path).TrimEnd('\r', '\n') : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <paramref name="password"/> is the one the file holds, compared in constant time.
    /// False when there is no file.
    /// </summary>
    /// <param name="configDir">The instance's config directory.</param>
    /// <param name="password">The password to compare.</param>
    public static bool Holds(string configDir, string? password)
    {
        var held = Read(configDir);
        if (held == null || password == null) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(held), Encoding.UTF8.GetBytes(password));
    }

    /// <summary>
    /// Deletes the file in <paramref name="configDir"/> when <paramref name="holdsReplacedPassword"/>
    /// says the password in it is the one just replaced, so a file belonging to another account, or
    /// to an earlier install, is left alone. Best-effort: a failure is returned in
    /// <paramref name="error"/>, never thrown, so the password change it follows still stands.
    /// </summary>
    /// <param name="configDir">The instance's config directory.</param>
    /// <param name="holdsReplacedPassword">Given the file's password, whether it is the one just replaced.</param>
    /// <param name="error">Why the file could not be deleted; null when it was, or was not there, or was left alone.</param>
    /// <returns>True when the file was deleted.</returns>
    public static bool TryDeleteIfHolds(string configDir, Func<string, bool> holdsReplacedPassword, out string? error)
    {
        error = null;
        var path = PathIn(configDir);
        try
        {
            if (!File.Exists(path)) return false;
            var held = File.ReadAllText(path).TrimEnd('\r', '\n');
            if (!holdsReplacedPassword(held)) return false;
            File.Delete(path);
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }
}
