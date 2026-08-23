using System.Text;
using ModularCA.Core.Logging;
using Serilog.Events;
using Serilog.Parsing;
using Xunit;

namespace ModularCA.Tests.Core.Logging;

/// <summary>
/// Pins the journald contract for stdout logging.
/// <para>
/// The service used to write CLEF JSON to stdout under systemd. journald stores each stdout
/// line verbatim as MESSAGE= and stamps unprefixed lines PRIORITY=6, so the journal was both
/// unreadable and unfilterable: <c>journalctl -p err -u modularca</c> returned nothing no
/// matter how badly the CA was failing.
/// </para>
/// </summary>
public class SystemdTextFormatterTests
{
    /// <summary>
    /// Counts Write calls so the single-write property can be asserted, not just assumed.
    /// </summary>
    private sealed class CountingWriter : TextWriter
    {
        private readonly StringBuilder _buffer = new();
        public int WriteCalls { get; private set; }
        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(string? value) { WriteCalls++; _buffer.Append(value); }
        public override void Write(char value) { WriteCalls++; _buffer.Append(value); }
        public override void Write(char[] buffer, int index, int count) { WriteCalls++; _buffer.Append(buffer, index, count); }
        public override string ToString() => _buffer.ToString();
    }

    private static LogEvent Event(
        LogEventLevel level = LogEventLevel.Information,
        string template = "hello",
        Exception? exception = null,
        params (string Name, object Value)[] properties)
    {
        var parsed = new MessageTemplateParser().Parse(template);
        var props = properties.Select(p => new LogEventProperty(p.Name, new ScalarValue(p.Value)));
        return new LogEvent(DateTimeOffset.UnixEpoch, level, exception, parsed, props);
    }

    private static string Format(LogEvent e)
    {
        var writer = new CountingWriter();
        new SystemdTextFormatter().Format(e, writer);
        return writer.ToString();
    }

    [Theory]
    [InlineData(LogEventLevel.Fatal, 2)]
    [InlineData(LogEventLevel.Error, 3)]
    [InlineData(LogEventLevel.Warning, 4)]
    [InlineData(LogEventLevel.Information, 6)]
    [InlineData(LogEventLevel.Debug, 7)]
    [InlineData(LogEventLevel.Verbose, 7)]
    public void Every_line_opens_with_the_syslog_priority_journald_reads(LogEventLevel level, int priority)
    {
        // Without this prefix journald files everything as info and severity filtering is dead.
        var line = Format(Event(level));

        Assert.StartsWith($"<{priority}>", line, StringComparison.Ordinal);
    }

    [Fact]
    public void An_event_renders_as_exactly_one_journal_record()
    {
        // journald splits stdout on newlines, so an interior newline would silently fan one
        // event out into several records - and only the first would keep the priority prefix.
        var line = Format(Event(
            template: "line one {Detail}",
            properties: ("Detail", "\nline two\r\nline three")));

        Assert.EndsWith("\n", line, StringComparison.Ordinal);
        Assert.Single(line.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.DoesNotContain('\r', line);
    }

    [Fact]
    public void A_stack_trace_stays_on_one_line()
    {
        Exception caught;
        try { throw new InvalidOperationException("keystore is sealed"); }
        catch (Exception ex) { caught = ex; }

        var line = Format(Event(LogEventLevel.Error, "issuance failed", caught));

        Assert.Single(line.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("keystore is sealed", line, StringComparison.Ordinal);
        Assert.StartsWith("<3>", line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_whole_event_is_handed_over_in_a_single_write()
    {
        // Chunked writes are how one event's bytes end up spliced into another's on a shared
        // descriptor. Composing in memory and writing once keeps an event atomic against any
        // other writer on stdout.
        var writer = new CountingWriter();
        Exception caught;
        try { throw new InvalidOperationException("boom"); }
        catch (Exception ex) { caught = ex; }

        new SystemdTextFormatter().Format(
            Event(LogEventLevel.Error, "failed {Op}", caught, ("Op", "sign"), ("CorrelationId", "abc123")),
            writer);

        Assert.Equal(1, writer.WriteCalls);
    }

    [Fact]
    public void The_source_context_becomes_a_readable_prefix()
    {
        var line = Format(Event(properties: ("SourceContext", "ModularCA.Core.Services.CaCreationService")));

        Assert.StartsWith("<6>[ModularCA.Core.Services.CaCreationService] hello", line, StringComparison.Ordinal);
        // ...and is not then repeated as a key=value pair.
        Assert.DoesNotContain("SourceContext=", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Properties_the_template_did_not_consume_survive_as_key_values()
    {
        // These are exactly what an operator greps a journal for.
        var line = Format(Event(
            template: "HTTP {Method} responded {Status}",
            properties: new[] { ("Method", (object)"GET"), ("Status", 200), ("CorrelationId", "9ec3fa34") }));

        Assert.Contains("HTTP GET responded 200", line, StringComparison.Ordinal);
        Assert.Contains("CorrelationId=9ec3fa34", line, StringComparison.Ordinal);
        // Rendered ones are not duplicated as trailing pairs.
        Assert.DoesNotContain("Method=", line, StringComparison.Ordinal);
        Assert.DoesNotContain("Status=", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_request_log_line_is_far_shorter_than_the_json_it_replaces()
    {
        // Not cosmetic: shorter lines are what keeps a single write under PIPE_BUF on the
        // journald socket. The CLEF form of this same event ran 463 bytes.
        var line = Format(Event(
            template: "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms",
            properties: new[]
            {
                ("RequestMethod", (object)"GET"),
                ("RequestPath", "/acme/maroongang-ca-s1/directory"),
                ("StatusCode", 200),
                ("Elapsed", 8.108654),
                ("SourceContext", "Serilog.AspNetCore.RequestLoggingMiddleware"),
                ("CorrelationId", "9ec3fa34082490f12c3d563263545978"),
            }));

        Assert.True(line.Length < 240, $"expected a compact line, got {line.Length} chars: {line}");
    }
}

/// <summary>
/// Pins how the console format is chosen, because systemd and container hosts want opposite
/// things and this service used to give them the same thing.
/// </summary>
public class ConsoleLogFormatResolverTests
{
    [Theory]
    [InlineData("Systemd", false, false, ConsoleLogFormat.Systemd)]
    [InlineData("json", false, false, ConsoleLogFormat.Json)]
    [InlineData("TEXT", true, true, ConsoleLogFormat.Text)]
    public void An_explicit_setting_wins_over_the_detected_host(string configured, bool systemd, bool container, ConsoleLogFormat expected)
    {
        Assert.Equal(expected, ConsoleLogFormatResolver.Resolve(configured, systemd, container));
    }

    [Fact]
    public void Auto_gives_journald_priority_prefixed_lines_not_json()
    {
        Assert.Equal(ConsoleLogFormat.Systemd, ConsoleLogFormatResolver.Resolve("Auto", underSystemd: true, inContainer: false));
    }

    [Fact]
    public void Auto_still_gives_a_container_json_for_its_log_shipper()
    {
        Assert.Equal(ConsoleLogFormat.Json, ConsoleLogFormatResolver.Resolve("Auto", underSystemd: false, inContainer: true));
    }

    [Fact]
    public void A_container_that_also_reports_systemd_is_treated_as_a_container()
    {
        Assert.Equal(ConsoleLogFormat.Json, ConsoleLogFormatResolver.Resolve("Auto", underSystemd: true, inContainer: true));
    }

    [Fact]
    public void An_interactive_host_gets_the_readable_template()
    {
        Assert.Equal(ConsoleLogFormat.Text, ConsoleLogFormatResolver.Resolve("Auto", underSystemd: false, inContainer: false));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("yaml-typo")]
    public void An_unusable_setting_falls_back_to_Auto_rather_than_failing_startup(string? configured)
    {
        // A typo in a log setting must never be the reason the CA won't boot.
        Assert.Equal(ConsoleLogFormat.Systemd, ConsoleLogFormatResolver.Resolve(configured, underSystemd: true, inContainer: false));
    }
}
