using System.Text;

namespace ModularCA.Auth.Utils;

/// <summary>
/// Parses an HTTP <c>Authorization: Basic</c> header value per RFC 7617.
/// </summary>
/// <remarks>
/// Separated from the authentication handler that uses it because the parsing rules carry the
/// subtleties — where the colon splits, what an empty user-id means, what a non-base64 body means —
/// and a handler needs an HttpContext to exercise. The rules are worth pinning on their own.
/// </remarks>
public static class BasicAuthHeader
{
    private const string Prefix = "Basic ";

    /// <summary>
    /// Attempts to decode a Basic credential from a raw Authorization header value.
    /// </summary>
    /// <param name="headerValue">The raw header value, e.g. <c>Basic dXNlcjpwYXNz</c>.</param>
    /// <param name="username">The decoded user-id when parsing succeeds.</param>
    /// <param name="password">The decoded password when parsing succeeds; may be empty.</param>
    /// <returns><c>true</c> when a well-formed Basic credential was present.</returns>
    public static bool TryParse(string? headerValue, out string username, out string password)
    {
        username = string.Empty;
        password = string.Empty;

        if (string.IsNullOrEmpty(headerValue))
            return false;

        // The scheme token is case-insensitive per RFC 7235; clients in the field send "basic".
        if (!headerValue.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(headerValue[Prefix.Length..].Trim()));
        }
        catch (FormatException)
        {
            return false;
        }

        // Split on the FIRST colon only. RFC 7617 forbids a colon in the user-id and explicitly
        // permits one in the password, so splitting on every colon would silently truncate any
        // password containing one — and the resulting failure looks like a wrong password.
        var separator = decoded.IndexOf(':');

        // No colon at all is malformed. A leading colon means an empty user-id, which cannot
        // identify an account; treating it as a parse failure keeps the empty-username check from
        // being the thing that has to catch it.
        if (separator <= 0)
            return false;

        username = decoded[..separator];
        password = decoded[(separator + 1)..];
        return true;
    }
}
