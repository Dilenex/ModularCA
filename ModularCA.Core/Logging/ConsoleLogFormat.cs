namespace ModularCA.Core.Logging;

/// <summary>How log events are rendered to stdout.</summary>
public enum ConsoleLogFormat
{
    /// <summary>
    /// One line per event, prefixed with the syslog priority journald reads. For hosts where
    /// stdout is captured by the systemd journal. See <see cref="SystemdTextFormatter"/>.
    /// </summary>
    Systemd,

    /// <summary>
    /// CLEF JSON, one object per line. For hosts where stdout is scraped by a log shipper
    /// (Loki, Fluent Bit, Datadog) that parses structured events.
    /// </summary>
    Json,

    /// <summary>Human-readable multi-line template, for an interactive terminal.</summary>
    Text,
}

/// <summary>
/// Resolves the configured console format against what is actually consuming stdout.
/// </summary>
/// <remarks>
/// The default (<c>Auto</c>) picks by consumer, because the right answer differs per host and
/// getting it wrong is not cosmetic: JSON in the journal costs an operator severity filtering
/// (<c>journalctl -p err</c>) and readability, while a text template piped to Fluent Bit costs
/// every structured field. This service previously treated systemd and container hosts
/// identically and emitted JSON to both, which is correct for exactly one of them.
/// </remarks>
public static class ConsoleLogFormatResolver
{
    /// <summary>
    /// Resolves <paramref name="configured"/> — <c>"Auto"</c>, <c>"Systemd"</c>, <c>"Json"</c>,
    /// or <c>"Text"</c>, case-insensitive — into the format to use. Null, empty, and
    /// unrecognised values all fall back to <c>Auto</c> rather than failing startup: a typo in
    /// a log setting must never be the reason the CA won't boot.
    /// </summary>
    public static ConsoleLogFormat Resolve(string? configured, bool underSystemd, bool inContainer)
    {
        if (Enum.TryParse<ConsoleLogFormat>(configured, ignoreCase: true, out var explicitFormat))
            return explicitFormat;

        // Auto. Container first: DOTNET_RUNNING_IN_CONTAINER is an explicit signal that a
        // runtime — not journald — is collecting stdout, even on a host that also runs systemd.
        if (inContainer)
            return ConsoleLogFormat.Json;

        return underSystemd ? ConsoleLogFormat.Systemd : ConsoleLogFormat.Text;
    }
}
