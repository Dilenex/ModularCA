using System.Text.RegularExpressions;
using ModularCA.Shared.Errors;

namespace ModularCA.Core.Services;

/// <summary>
/// The one place an SSH certificate's key id is composed. <c>sshd</c> logs the key id with every
/// login, so it has to say who the certificate is for and may never be text a requester chose.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>A user: the username.</description></item>
///   <item><description>A service identity: <c>svc:</c> and its label, of 1 to 64 letters, digits and <c>. _ -</c>.</description></item>
///   <item><description>A host certificate: its first hostname.</description></item>
/// </list>
/// A username that begins with <c>svc:</c> is refused, so the key id of a service identity is
/// never the key id of a user, whatever rule a username was created under.
/// </remarks>
public static partial class SshKeyIds
{
    /// <summary>What the key id of a service identity begins with.</summary>
    public const string ServicePrefix = "svc:";

    /// <summary>The longest key id, in characters: the width of the column that stores it.</summary>
    public const int MaxLength = 255;

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceLabelPattern();

    /// <summary>Whether <paramref name="label"/> can be the label of a service identity.</summary>
    public static bool IsServiceLabel(string? label) => label != null && ServiceLabelPattern().IsMatch(label);

    /// <summary>The key id of a certificate for the user named <paramref name="username"/>.</summary>
    /// <exception cref="InvalidRequestException">The username is empty, begins with <c>svc:</c>, holds a control character or is too long.</exception>
    public static string ForUser(string? username)
    {
        if (string.IsNullOrEmpty(username))
            throw new InvalidRequestException("The user has no username, so no SSH certificate can name them.");
        if (username.StartsWith(ServicePrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidRequestException(
                $"The username begins with '{ServicePrefix}', which marks a service identity in host logs; no SSH certificate is issued under it.");
        return Checked(username, "The username");
    }

    /// <summary>The key id of a certificate for the service identity labelled <paramref name="label"/>.</summary>
    /// <exception cref="InvalidRequestException">The label is not 1 to 64 letters, digits and <c>. _ -</c>.</exception>
    public static string ForService(string? label)
    {
        if (!IsServiceLabel(label))
            throw new InvalidRequestException("A service label is 1 to 64 letters, digits and . _ -");
        return ServicePrefix + label;
    }

    /// <summary>
    /// The key id of a host certificate: its first hostname. With no hostname it is empty; the
    /// signer certifies nothing with no principal or an empty one, so an empty key id is never issued.
    /// </summary>
    /// <exception cref="InvalidRequestException">The first hostname holds a control character or is too long.</exception>
    public static string ForHost(IReadOnlyList<string>? hostnames)
        => hostnames is { Count: > 0 } && !string.IsNullOrEmpty(hostnames[0]) ? Checked(hostnames[0], "The first hostname") : string.Empty;

    /// <summary>The label of the service identity a key id names, or null when it names none.</summary>
    public static string? ServiceLabelOf(string? keyId)
        => keyId != null && keyId.StartsWith(ServicePrefix, StringComparison.Ordinal) && IsServiceLabel(keyId[ServicePrefix.Length..])
            ? keyId[ServicePrefix.Length..]
            : null;

    private static string Checked(string keyId, string what)
    {
        if (keyId.Length > MaxLength)
            throw new InvalidRequestException($"{what} is longer than {MaxLength} characters and cannot be a key id.");
        if (keyId.Any(char.IsControl))
            throw new InvalidRequestException($"{what} holds a control character and cannot be a key id.");
        return keyId;
    }
}
