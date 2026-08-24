namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Request body for <c>PUT /api/v1/admin/config/logging</c>. Every member is nullable and
/// <c>null</c> means "not sent — leave it alone".
/// </summary>
/// <remarks>
/// <para>
/// This type exists because the endpoint used to bind <see cref="LoggingConfig"/> directly, and
/// that is a trap: a JSON body that omits a field does not leave the property null, it leaves
/// the property at its <b>constructor default</b>. The admin UI's log-level control sends only
/// <c>{"minLevel": "..."}</c>, so every save of the log level silently rewrote FilePath to
/// <c>logs/modularca-.log</c>, RetentionDays to 30, and MaxFileSizeMb to 100 — clobbering an
/// operator's configured values with defaults they never chose.
/// </para>
/// <para>
/// On a CA that is a compliance problem, not an annoyance: an operator who set 365-day log
/// retention loses it, silently, by changing the log level from Information to Debug. Nothing
/// in the response says anything was reset.
/// </para>
/// <para>
/// Nullable-means-absent is the pattern the other request DTOs in this controller already use.
/// Keep it that way: never bind a config class straight from a request body when partial
/// updates are possible.
/// </para>
/// </remarks>
public class LoggingUpdateRequest
{
    /// <summary>Minimum level: Debug, Information, Warning, or Error. Applied immediately.</summary>
    public string? MinLevel { get; set; }

    /// <summary>Console rendering: Auto, Systemd, Json, or Text. Requires a restart.</summary>
    public string? ConsoleFormat { get; set; }

    /// <summary>Rolling log file path. Requires a restart.</summary>
    public string? FilePath { get; set; }

    /// <summary>Days of rolled log files to retain. Requires a restart.</summary>
    public int? RetentionDays { get; set; }

    /// <summary>Size in MB at which a log file rolls. Requires a restart.</summary>
    public int? MaxFileSizeMb { get; set; }

    /// <summary>Whether framework errors log full stack traces. Requires a restart.</summary>
    public bool? VerboseErrors { get; set; }
}
