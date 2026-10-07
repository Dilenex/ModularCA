using ModularCA.Shared.Signing;
using ModularCA.Ssh;

namespace ModularCA.Core.Services;

/// <summary>
/// Turns the option strings a profile or a request carries (<c>permit-pty</c>,
/// <c>force-command=/usr/bin/backup</c>) into the option set the signer is asked for. The set is
/// exact: a certificate carries these options and no others, and nothing is added by default.
/// </summary>
/// <remarks>
/// <para>
/// A name is matched without regard to case and written as OpenSSH writes it in a certificate
/// (<c>permit-x11-forwarding</c> becomes <c>permit-X11-forwarding</c>). <c>force-command</c>,
/// <c>source-address</c> and <c>verify-required</c> are critical options; every other name is an
/// extension. A value is passed as it is given. A name this does not know is passed on as an
/// extension, so that the signer refuses it by name rather than the node dropping it.
/// </para>
/// <para>
/// The <c>no-*</c> names (<c>no-pty</c>, <c>no-port-forwarding</c>, <c>no-agent-forwarding</c>,
/// <c>no-x11-forwarding</c>, <c>no-user-rc</c>) come from a time when options were added to a
/// default set, and removed one of the defaults. There are no defaults now, so they add nothing
/// to a certificate. Each is still honoured as a restriction: the matching <c>permit-*</c> is
/// left out even when the same list names it, wherever in the list either stands, so a list
/// that says both issues the narrower certificate. <c>clear</c>, which emptied the default set,
/// is ignored: the set starts empty. <c>no-touch-required</c> is not one of these; it is an
/// extension in its own right.
/// </para>
/// </remarks>
public static class SshCertificateOptions
{
    /// <summary>The name that emptied the default set when there was one.</summary>
    private const string Clear = "clear";

    private static readonly Dictionary<string, string> CriticalNames =
        SshCertificateRules.UserCriticalOptions.ToDictionary(n => n, n => n, StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, string> ExtensionNames =
        SshCertificateRules.UserExtensions.ToDictionary(n => n, n => n, StringComparer.OrdinalIgnoreCase);

    /// <summary>Each <c>no-*</c> name and the extension it withholds.</summary>
    private static readonly Dictionary<string, string> Withholding = new(StringComparer.OrdinalIgnoreCase)
    {
        ["no-agent-forwarding"] = "permit-agent-forwarding",
        ["no-port-forwarding"] = "permit-port-forwarding",
        ["no-pty"] = "permit-pty",
        ["no-user-rc"] = "permit-user-rc",
        ["no-x11-forwarding"] = "permit-X11-forwarding",
    };

    /// <summary>
    /// The critical options and the extensions <paramref name="options"/> name, each once. An
    /// entry given twice with the same value counts once; the same name with two values is
    /// passed twice, for the signer to refuse.
    /// </summary>
    /// <param name="options">The option strings, <c>name</c> or <c>name=value</c>; null is none.</param>
    public static (IReadOnlyList<SshCertificateOption> CriticalOptions, IReadOnlyList<SshCertificateOption> Extensions) From(IEnumerable<string>? options)
    {
        var critical = new List<SshCertificateOption>();
        var extensions = new List<SshCertificateOption>();
        var withheld = new HashSet<string>(StringComparer.Ordinal);

        foreach (var option in options ?? [])
        {
            var text = option ?? string.Empty;
            var split = text.IndexOf('=');
            var name = (split < 0 ? text : text[..split]).Trim();
            var value = split < 0 ? string.Empty : text[(split + 1)..];

            if (split < 0 && name.Equals(Clear, StringComparison.OrdinalIgnoreCase))
                continue;
            if (split < 0 && Withholding.TryGetValue(name, out var permit))
            {
                withheld.Add(permit);
                continue;
            }

            if (CriticalNames.TryGetValue(name, out var criticalName))
                AddOnce(critical, new SshCertificateOption(criticalName, value));
            else
                AddOnce(extensions, new SshCertificateOption(ExtensionNames.GetValueOrDefault(name, name), value));
        }

        extensions.RemoveAll(e => withheld.Contains(e.Name));
        return (critical, extensions);
    }

    /// <summary>
    /// The options a certificate carries, as the strings a profile writes them: <c>name</c> for a
    /// flag, <c>name=value</c> otherwise, critical options first.
    /// </summary>
    public static List<string> Describe(IEnumerable<SshOption> criticalOptions, IEnumerable<SshOption> extensions)
        => criticalOptions.Concat(extensions)
            .Select(o => o.Value.Length == 0 ? o.Name : $"{o.Name}={o.Value}")
            .ToList();

    private static void AddOnce(List<SshCertificateOption> into, SshCertificateOption option)
    {
        if (!into.Contains(option))
            into.Add(option);
    }
}
