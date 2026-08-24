using System.Text.Json;
using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Shared.Models;

/// <summary>
/// Pins partial-update semantics for the logging config endpoint.
/// <para>
/// The admin UI's log-level control sends exactly <c>{"minLevel":"..."}</c> — the only save on
/// the Settings page that posts a hand-built partial body. The endpoint used to bind
/// <see cref="LoggingConfig"/> straight from that body, so the omitted fields arrived as
/// constructor defaults rather than null and were written back over the operator's values.
/// </para>
/// </summary>
public class LoggingUpdateRequestTests
{
    private static readonly JsonSerializerOptions Wire =
        new() { PropertyNameCaseInsensitive = true };

    /// <summary>The exact body <c>Settings.tsx</c> posts when saving the log level.</summary>
    private const string LogLevelOnlySave = """{"minLevel":"Debug"}""";

    [Fact]
    public void Saving_only_the_log_level_leaves_every_other_setting_absent()
    {
        var request = JsonSerializer.Deserialize<LoggingUpdateRequest>(LogLevelOnlySave, Wire)!;

        Assert.Equal("Debug", request.MinLevel);

        // null here is what lets the handler skip them. Any non-null value would be applied.
        Assert.Null(request.FilePath);
        Assert.Null(request.RetentionDays);
        Assert.Null(request.MaxFileSizeMb);
        Assert.Null(request.ConsoleFormat);
        Assert.Null(request.VerboseErrors);
    }

    [Fact]
    public void Binding_the_config_class_directly_is_the_trap_this_type_replaces()
    {
        // Documents WHY the dedicated request type exists, so nobody "simplifies" the endpoint
        // back to [FromBody] LoggingConfig. Deserializing the same partial body into the config
        // class yields defaults that are indistinguishable from a deliberate choice.
        var bound = JsonSerializer.Deserialize<LoggingConfig>(LogLevelOnlySave, Wire)!;

        Assert.Equal("Debug", bound.MinLevel);
        Assert.Equal("logs/modularca-.log", bound.FilePath);  // not null - a default
        Assert.Equal(30, bound.RetentionDays);                // an operator's 365 would be lost
        Assert.Equal(100, bound.MaxFileSizeMb);
        Assert.Equal("Auto", bound.ConsoleFormat);
    }

    [Fact]
    public void A_full_save_carries_every_setting_through()
    {
        // The Log Storage card posts the whole logging object; nothing may be dropped.
        var body = """
        {"minLevel":"Warning","consoleFormat":"Json","filePath":"/var/log/modularca/ca-.log",
         "retentionDays":365,"maxFileSizeMb":500,"verboseErrors":true}
        """;

        var request = JsonSerializer.Deserialize<LoggingUpdateRequest>(body, Wire)!;

        Assert.Equal("Warning", request.MinLevel);
        Assert.Equal("Json", request.ConsoleFormat);
        Assert.Equal("/var/log/modularca/ca-.log", request.FilePath);
        Assert.Equal(365, request.RetentionDays);
        Assert.Equal(500, request.MaxFileSizeMb);
        Assert.True(request.VerboseErrors);
    }

    [Fact]
    public void An_explicit_zero_is_distinguishable_from_absent()
    {
        // The old handler used `if (RetentionDays > 0)` as a stand-in for "was it sent?", which
        // silently ignored an out-of-range 0 instead of rejecting it. Nullable lets the handler
        // tell "not sent" from "sent, and invalid".
        var request = JsonSerializer.Deserialize<LoggingUpdateRequest>("""{"retentionDays":0}""", Wire)!;

        Assert.Equal(0, request.RetentionDays);
        Assert.NotNull(request.RetentionDays);
    }
}
