using System.Text;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;
using Serilog.Parsing;

namespace ModularCA.Core.Logging;

/// <summary>
/// Formats log events for a systemd journal consumer: one journal record per event, prefixed
/// with the syslog priority journald uses to classify it.
/// </summary>
/// <remarks>
/// <para>
/// Under systemd the process's stdout is a journald socket, not a log shipper. Writing CLEF
/// JSON there — which is what this service used to do — breaks the journal in two ways that
/// matter operationally:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Severity is lost.</b> journald stamps every unprefixed stdout line PRIORITY=6 (info), so
/// <c>journalctl -p err -u modularca</c> returns nothing even when the service is failing. The
/// only fix is the <c>&lt;N&gt;</c> prefix convention that journald strips and interprets — the
/// same one .NET's own <c>AddSystemdConsole()</c> formatter emits.
/// </description></item>
/// <item><description>
/// <b>Readability.</b> <c>journalctl</c> renders MESSAGE= verbatim, so an operator tailing the
/// unit reads raw JSON. Structured output belongs in the file sink (still CLEF) or in a
/// container's stdout, where something is actually parsing it.
/// </description></item>
/// </list>
/// <para>
/// Two properties are load-bearing and pinned by tests. Every event renders to <b>exactly one
/// line</b> — embedded newlines, above all stack traces, are folded to <c>" | "</c> — because
/// journald splits stdout on newlines and a multi-line exception would otherwise become a dozen
/// unrelated records, most of them stamped info. And the whole line is composed in memory and
/// handed to the writer in a <b>single Write call</b>, so an event cannot interleave with a
/// concurrent writer on the same descriptor.
/// </para>
/// </remarks>
public sealed class SystemdTextFormatter : ITextFormatter
{
    /// <summary>
    /// Properties that carry no operator value on a journal line: either already shown elsewhere
    /// on the line, or constant for the whole unit.
    /// </summary>
    /// <summary>
    /// Renders just the message, with <c>:lj</c> — literal strings (no surrounding quotes) and
    /// JSON for structured values. Matches the interactive console template, so the same event
    /// reads identically whether an operator is tailing a terminal or the journal.
    /// </summary>
    private static readonly MessageTemplateTextFormatter MessageRenderer = new("{Message:lj}");

    private static readonly HashSet<string> SuppressedProperties = new(StringComparer.Ordinal)
    {
        "SourceContext",  // rendered as the [category] prefix
        "Application",    // constant — it's the unit name
    };

    /// <summary>
    /// Maps a Serilog level to the RFC 5424 severity journald reads from the <c>&lt;N&gt;</c>
    /// prefix. Matches the mapping used by .NET's systemd console formatter so a mixed-stack
    /// deployment filters consistently.
    /// </summary>
    public static int SyslogPriority(LogEventLevel level) => level switch
    {
        LogEventLevel.Fatal => 2,        // crit
        LogEventLevel.Error => 3,        // err
        LogEventLevel.Warning => 4,      // warning
        LogEventLevel.Information => 6,  // info
        _ => 7,                          // debug — Debug and Verbose
    };

    /// <summary>
    /// Renders <paramref name="logEvent"/> as a single journald record and writes it to
    /// <paramref name="output"/> in one call.
    /// </summary>
    public void Format(LogEvent logEvent, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(output);

        var line = new StringBuilder(256);

        line.Append('<').Append(SyslogPriority(logEvent.Level)).Append('>');

        if (logEvent.Properties.TryGetValue("SourceContext", out var source) &&
            source is ScalarValue { Value: string context } && context.Length > 0)
        {
            line.Append('[').Append(context).Append("] ");
        }

        using (var message = new StringWriter())
        {
            MessageRenderer.Format(logEvent, message);
            AppendFolded(line, message.ToString());
        }

        // Properties the message template did not consume would otherwise be dropped — and
        // they are the ones an operator greps for (CorrelationId, RequestId, trace ids).
        var rendered = new HashSet<string>(StringComparer.Ordinal);
        foreach (var token in logEvent.MessageTemplate.Tokens)
        {
            if (token is PropertyToken property)
                rendered.Add(property.PropertyName);
        }

        foreach (var (name, value) in logEvent.Properties)
        {
            if (rendered.Contains(name) || SuppressedProperties.Contains(name))
                continue;

            line.Append(' ').Append(name).Append('=');
            AppendFolded(line, value is ScalarValue { Value: string s } ? s : value.ToString());
        }

        if (logEvent.Exception != null)
        {
            line.Append(" | ");
            AppendFolded(line, logEvent.Exception.ToString());
        }

        line.Append('\n');

        // One Write, one line: see the atomicity note in the type remarks.
        output.Write(line.ToString());
    }

    /// <summary>
    /// Appends <paramref name="text"/> with every line break folded into <c>" | "</c> so the
    /// result cannot split one event across multiple journal records.
    /// </summary>
    private static void AppendFolded(StringBuilder builder, string text)
    {
        if (text.Length == 0)
            return;

        if (text.IndexOf('\n') < 0 && text.IndexOf('\r') < 0)
        {
            builder.Append(text);
            return;
        }

        var first = true;
        foreach (var segment in text.Split('\n'))
        {
            var trimmed = segment.Trim('\r', ' ', '\t');
            if (trimmed.Length == 0)
                continue;

            if (!first)
                builder.Append(" | ");
            builder.Append(trimmed);
            first = false;
        }
    }
}
