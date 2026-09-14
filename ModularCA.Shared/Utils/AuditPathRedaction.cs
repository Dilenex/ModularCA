namespace ModularCA.Shared.Utils;

/// <summary>
/// Removes bearer credentials from request paths before they are written to the network audit.
/// </summary>
/// <remarks>
/// <para>
/// The public enrollment token is the credential and it travels in the URL path:
/// <c>/api/v1/public/enroll/{token}</c> and <c>/api/v1/public/enroll/{token}/page</c>. The
/// network audit records every request path, so every live enrollment token was being persisted
/// in the audit database, readable by anyone with audit access and surviving for the retention
/// period. The audit still needs to show that an enrollment happened and where; it does not need
/// the token to show it.
/// </para>
/// <para>
/// Kept as a pure function over the path string so the rule can be pinned by tests, and so a new
/// credential-in-path route has one place to be added.
/// </para>
/// </remarks>
public static class AuditPathRedaction
{
    private const string Placeholder = "{token}";

    // Prefixes after which the next segment is a credential. Both the API form and the
    // short-URL form the QR code carries.
    private static readonly string[] CredentialPrefixes =
    [
        "/api/v1/public/enroll/",
        "/public/enroll/",
    ];

    /// <summary>
    /// Returns the path with any credential segment replaced by a placeholder.
    /// </summary>
    /// <param name="path">The request path as received.</param>
    /// <returns>The path safe to persist. Unchanged when it carries no credential.</returns>
    public static string Redact(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return path ?? string.Empty;

        foreach (var prefix in CredentialPrefixes)
        {
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                continue;

            var rest = path[prefix.Length..];
            if (rest.Length == 0)
                return path;

            var slash = rest.IndexOf('/');
            var tail = slash < 0 ? string.Empty : rest[slash..];
            return path[..prefix.Length] + Placeholder + tail;
        }

        return path;
    }
}
