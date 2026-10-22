using System.Net;
using System.Text;

namespace ModularCA.Ssh;

/// <summary>The limits an SSH CA key places on what it signs.</summary>
/// <param name="AllowUser">Whether the key signs user certificates.</param>
/// <param name="AllowHost">Whether the key signs host certificates.</param>
/// <param name="MaxValidity">The longest validity window the key signs.</param>
public sealed record SshCaLimits(bool AllowUser, bool AllowHost, TimeSpan MaxValidity);

/// <summary>
/// How far a certificate's <c>valid_after</c> may sit from the signer's clock, each way. The two
/// directions are separate because they are different risks: a start in the past is what a caller
/// asks for when it backdates for clock skew, and a start in the future is a certificate that is
/// not valid yet when it is handed out. A negative allowance is read as none.
/// </summary>
/// <param name="Past">How long before the signer's clock <c>valid_after</c> may be.</param>
/// <param name="Future">How long after the signer's clock <c>valid_after</c> may be.</param>
public readonly record struct SshClockSkew(TimeSpan Past, TimeSpan Future)
{
    /// <summary>The same allowance both ways.</summary>
    public static SshClockSkew Symmetric(TimeSpan either) => new(either, either);
}

/// <summary>
/// The key-level checks an SSH certificate must pass before it is signed. Each check returns a
/// refusal reason, or null when the certificate passes. These are pure functions for the signer to
/// call; profile policy (principal patterns, allowed extensions, approvals) stays in the node.
/// </summary>
public static class SshCertificateRules
{
    /// <summary>OpenSSH's own limit on principals per certificate (<c>SSHKEY_CERT_MAX_PRINCIPALS</c>).</summary>
    public const int MaxPrincipals = 256;

    /// <summary>The longest principal accepted, in UTF-8 bytes.</summary>
    public const int MaxPrincipalBytes = 256;

    /// <summary>The longest key id accepted, in UTF-8 bytes.</summary>
    public const int MaxKeyIdBytes = 256;

    /// <summary>The smallest RSA subject key accepted.</summary>
    public const int MinRsaBits = 2048;

    /// <summary>How far <c>valid_after</c> may sit from the signer's clock by default, either way.</summary>
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>The critical options a user certificate may carry.</summary>
    public static readonly IReadOnlySet<string> UserCriticalOptions =
        new HashSet<string>(StringComparer.Ordinal) { "force-command", "source-address", "verify-required" };

    /// <summary>The extensions a user certificate may carry.</summary>
    public static readonly IReadOnlySet<string> UserExtensions = new HashSet<string>(StringComparer.Ordinal)
    {
        "no-touch-required",
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };

    /// <summary>Runs every check below, returning the first refusal.</summary>
    /// <param name="fields">The certificate to be signed.</param>
    /// <param name="caKey">The public key of the CA that would sign it.</param>
    /// <param name="limits">That CA key's limits.</param>
    /// <param name="now">The signer's clock.</param>
    /// <param name="maxClockSkew">How far <c>valid_after</c> may be from <paramref name="now"/>; <see cref="DefaultClockSkew"/> when null.</param>
    public static string? Check(SshCertificateFields fields, SshPublicKey caKey, SshCaLimits limits,
        DateTimeOffset now, TimeSpan? maxClockSkew = null)
        => Check(fields, caKey, limits, now, SshClockSkew.Symmetric(maxClockSkew ?? DefaultClockSkew));

    /// <summary>
    /// Runs every check below, returning the first refusal, with an allowance for
    /// <c>valid_after</c> that differs between the past and the future.
    /// </summary>
    /// <param name="fields">The certificate to be signed.</param>
    /// <param name="caKey">The public key of the CA that would sign it.</param>
    /// <param name="limits">That CA key's limits.</param>
    /// <param name="now">The signer's clock.</param>
    /// <param name="clockSkew">How far <c>valid_after</c> may be before and after <paramref name="now"/>.</param>
    public static string? Check(SshCertificateFields fields, SshPublicKey caKey, SshCaLimits limits,
        DateTimeOffset now, SshClockSkew clockSkew)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(limits);
        return CheckType(fields.Type, limits)
            ?? CheckSerial(fields.Serial)
            ?? CheckKeyId(fields.KeyId)
            ?? CheckPrincipals(fields.Principals)
            ?? CheckValidity(fields.ValidAfter, fields.ValidBefore, now, limits.MaxValidity, clockSkew)
            ?? CheckOptions(fields.Type, fields.CriticalOptions, fields.Extensions)
            ?? CheckSubjectKey(fields.SubjectKey, caKey);
    }

    /// <summary>Refuses a certificate type the CA key is not configured for.</summary>
    public static string? CheckType(SshCertificateType type, SshCaLimits limits) => type switch
    {
        SshCertificateType.User when limits.AllowUser => null,
        SshCertificateType.Host when limits.AllowHost => null,
        SshCertificateType.User => "This SSH CA key does not sign user certificates.",
        SshCertificateType.Host => "This SSH CA key does not sign host certificates.",
        _ => "The certificate type must be user or host.",
    };

    /// <summary>Refuses serial zero.</summary>
    public static string? CheckSerial(ulong serial) => serial == 0 ? "The serial must not be zero." : null;

    /// <summary>
    /// Refuses a key id longer than <see cref="MaxKeyIdBytes"/> or containing a control character.
    /// The key id is free text that every server the certificate is shown to writes to its log.
    /// An empty key id passes, as OpenSSH accepts one.
    /// </summary>
    public static string? CheckKeyId(string? keyId)
    {
        if (string.IsNullOrEmpty(keyId))
            return null;
        if (System.Text.Encoding.UTF8.GetByteCount(keyId) > MaxKeyIdBytes)
            return $"The key id is longer than {MaxKeyIdBytes} bytes.";
        if (keyId.Any(char.IsControl))
            return "The key id contains a control character.";
        return null;
    }

    /// <summary>
    /// Refuses an empty principal list, which OpenSSH reads as "any user" or "any host", and any
    /// principal that is empty, longer than <see cref="MaxPrincipalBytes"/>, repeated or contains a
    /// control character. No refusal names a principal, so a refusal can be logged where a list
    /// of principals must not build up.
    /// </summary>
    public static string? CheckPrincipals(IReadOnlyList<string>? principals)
    {
        if (principals == null || principals.Count == 0)
            return "At least one principal is required; a certificate with none is valid for every principal.";
        if (principals.Count > MaxPrincipals)
            return $"A certificate carries at most {MaxPrincipals} principals.";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var principal in principals)
        {
            if (string.IsNullOrEmpty(principal))
                return "A principal is empty.";
            if (Encoding.UTF8.GetByteCount(principal) > MaxPrincipalBytes)
                return $"A principal is longer than {MaxPrincipalBytes} bytes.";
            if (principal.Any(char.IsControl))
                return "A principal contains a control character.";
            if (!seen.Add(principal))
                return "A principal appears twice.";
        }
        return null;
    }

    /// <summary>
    /// Refuses a window that is empty or inverted, longer than <paramref name="maxValidity"/>, or
    /// that starts more than <paramref name="maxClockSkew"/> before or after <paramref name="now"/>.
    /// </summary>
    public static string? CheckValidity(ulong validAfter, ulong validBefore, DateTimeOffset now,
        TimeSpan maxValidity, TimeSpan? maxClockSkew = null)
        => CheckValidity(validAfter, validBefore, now, maxValidity, SshClockSkew.Symmetric(maxClockSkew ?? DefaultClockSkew));

    /// <summary>
    /// Refuses a window that is empty or inverted, longer than <paramref name="maxValidity"/>, or
    /// that starts more than <see cref="SshClockSkew.Past"/> before or more than
    /// <see cref="SshClockSkew.Future"/> after <paramref name="now"/>. A maximum validity or an
    /// allowance that is not positive is read as zero, so it permits nothing rather than everything.
    /// </summary>
    public static string? CheckValidity(ulong validAfter, ulong validBefore, DateTimeOffset now,
        TimeSpan maxValidity, SshClockSkew clockSkew)
    {
        var nowSeconds = (ulong)Math.Max(0, now.ToUnixTimeSeconds());
        if (validBefore <= validAfter)
            return "The certificate's validity window is empty.";
        if (validBefore - validAfter > WholeSeconds(maxValidity))
            return $"The validity window exceeds this SSH CA key's maximum of {Math.Max(0, maxValidity.TotalHours):0.##} hours.";
        if (validAfter > nowSeconds && validAfter - nowSeconds > WholeSeconds(clockSkew.Future))
            return "The certificate starts too far in the future.";
        if (validAfter < nowSeconds && nowSeconds - validAfter > WholeSeconds(clockSkew.Past))
            return "The certificate starts too far in the past.";
        return null;
    }

    /// <summary>A span in whole seconds, with a span that is not positive read as zero rather than cast.</summary>
    private static ulong WholeSeconds(TimeSpan span) => span <= TimeSpan.Zero ? 0 : (ulong)span.TotalSeconds;

    /// <summary>
    /// Refuses unknown, repeated or malformed options. A user certificate may carry the options in
    /// <see cref="UserCriticalOptions"/> and the flags in <see cref="UserExtensions"/>; a host
    /// certificate carries neither. <c>force-command</c> and <c>source-address</c> need a value,
    /// <c>source-address</c> must be a comma-separated list of addresses or CIDR blocks, and
    /// <c>verify-required</c> and every extension are flags with no value.
    /// </summary>
    public static string? CheckOptions(SshCertificateType type, IReadOnlyList<SshOption> criticalOptions,
        IReadOnlyList<SshOption> extensions)
    {
        ArgumentNullException.ThrowIfNull(criticalOptions);
        ArgumentNullException.ThrowIfNull(extensions);
        if (type == SshCertificateType.Host)
        {
            if (criticalOptions.Count > 0)
                return "A host certificate carries no critical options.";
            if (extensions.Count > 0)
                return "A host certificate carries no extensions.";
            return null;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var option in criticalOptions)
        {
            if (!UserCriticalOptions.Contains(option.Name))
                return $"Unknown critical option '{option.Name}'.";
            if (!names.Add(option.Name))
                return $"Critical option '{option.Name}' appears twice.";
            var error = option.Name switch
            {
                "force-command" when string.IsNullOrEmpty(option.Value) => "force-command needs a command.",
                "force-command" when option.Value.Any(c => c is '\0' or '\n' or '\r') => "force-command contains a line break or NUL.",
                "source-address" => CheckSourceAddress(option.Value),
                "verify-required" when option.Value.Length > 0 => "verify-required takes no value.",
                _ => null,
            };
            if (error != null)
                return error;
        }

        names.Clear();
        foreach (var extension in extensions)
        {
            if (!UserExtensions.Contains(extension.Name))
                return $"Unknown extension '{extension.Name}'.";
            if (!names.Add(extension.Name))
                return $"Extension '{extension.Name}' appears twice.";
            if (extension.Value.Length > 0)
                return $"Extension '{extension.Name}' takes no value.";
        }
        return null;
    }

    /// <summary>
    /// Refuses a subject key that is not Ed25519, ECDSA P-256/P-384/P-521 or RSA of at least
    /// <see cref="MinRsaBits"/> bits, and the CA's own key.
    /// </summary>
    public static string? CheckSubjectKey(SshPublicKey subjectKey, SshPublicKey caKey)
    {
        ArgumentNullException.ThrowIfNull(subjectKey);
        ArgumentNullException.ThrowIfNull(caKey);
        if (!SshKeyTypes.Certifiable.Contains(subjectKey.KeyType))
            return $"{subjectKey.KeyType} keys cannot be certified; use Ed25519, ECDSA or RSA.";
        if (subjectKey.KeyType == SshKeyTypes.Rsa && subjectKey.KeySizeBits < MinRsaBits)
            return $"RSA keys must be at least {MinRsaBits} bits.";
        if (subjectKey.Equals(caKey))
            return "The subject key is the CA's own key.";
        return null;
    }

    private static string? CheckSourceAddress(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "source-address needs at least one address.";
        foreach (var entry in value.Split(','))
        {
            var slash = entry.IndexOf('/');
            var ok = slash < 0
                ? IsAddress(entry, out _)
                : IsAddress(entry[..slash], out var network)
                  && entry[(slash + 1)..] is { Length: > 0 and <= 3 } prefix
                  && prefix.All(char.IsAsciiDigit)
                  && HostBitsClear(network, int.Parse(prefix));
            if (!ok)
                return $"source-address entry '{entry}' is not an address or a CIDR block without host bits.";
        }
        return null;
    }

    private static bool IsAddress(string text, out IPAddress address) =>
        IPAddress.TryParse(text, out address!)
        && (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? text.Contains(':') && !text.Contains('%')
            : address.ToString() == text);

    private static bool HostBitsClear(IPAddress network, int prefixLength)
    {
        var bytes = network.GetAddressBytes();
        if (prefixLength > bytes.Length * 8)
            return false;
        for (var bit = prefixLength; bit < bytes.Length * 8; bit++)
        {
            if ((bytes[bit / 8] & (0x80 >> (bit % 8))) != 0)
                return false;
        }
        return true;
    }
}
