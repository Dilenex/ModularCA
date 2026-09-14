using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// Decides whether the SSH certificate extensions a caller asked for are permitted by a cert
/// profile.
/// </summary>
/// <remarks>
/// <para>
/// This check existed only in the admin controller. The self-service path applied the principal
/// patterns and merged the required extensions but never consulted <c>AllowedExtensions</c>, so a
/// user with certificate-request rights could ask for any extension, including a
/// <c>force-command</c> the profile never offered. Combined with the argument handling at the
/// time, that value could also carry extra <c>ssh-keygen</c> flags.
/// </para>
/// <para>
/// One implementation for both controllers, so "allowed by the profile" cannot drift between the
/// path an administrator uses and the path a user does.
/// </para>
/// </remarks>
public static class SshExtensionPolicy
{
    /// <summary>
    /// Validates caller-requested extensions against a profile's allowed list.
    /// </summary>
    /// <param name="requested">Extensions the caller asked for; server-added ones do not belong here.</param>
    /// <param name="allowedExtensionsJson">The profile's <c>AllowedExtensions</c> column, a JSON array.</param>
    /// <returns>An error message naming the first disallowed extension, or null when all are permitted.</returns>
    /// <remarks>
    /// An empty allowed list means the profile places no restriction, which matches how the admin
    /// path has always read it. Each entry may name a bare extension (<c>permit-pty</c>) or a
    /// specific <c>name=value</c>; a bare entry permits any value for that name.
    /// </remarks>
    public static string? Validate(IEnumerable<string>? requested, string? allowedExtensionsJson)
    {
        if (requested == null)
            return null;

        List<string> allowed;
        try
        {
            allowed = string.IsNullOrWhiteSpace(allowedExtensionsJson)
                ? []
                : JsonSerializer.Deserialize<List<string>>(allowedExtensionsJson) ?? [];
        }
        catch (JsonException)
        {
            // A profile whose allowed list cannot be read permits nothing the caller asked for,
            // rather than everything. The server-side defaults still apply.
            allowed = [];
            if (requested.Any())
                return "The cert profile's allowed-extension list could not be read; no caller-requested extensions are permitted.";
        }

        if (allowed.Count == 0)
            return null;

        foreach (var ext in requested)
        {
            if (string.IsNullOrWhiteSpace(ext))
                return "An empty extension was requested.";

            var extName = ext.Contains('=') ? ext[..ext.IndexOf('=')] : ext;
            if (!allowed.Any(a => a == extName || a == ext))
                return $"Extension '{ext}' is not allowed by the cert profile";
        }

        return null;
    }
}
