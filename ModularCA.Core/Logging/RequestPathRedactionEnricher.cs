using ModularCA.Shared.Utils;
using Serilog.Core;
using Serilog.Events;

namespace ModularCA.Core.Logging;

/// <summary>
/// Replaces the credential segment of a <c>RequestPath</c> property with a placeholder on every
/// log event, by the rule the network audit uses (<see cref="AuditPathRedaction"/>). The public
/// enrollment token travels in the path, and the request-completed event of the Serilog request
/// logging, and every event logged through <c>ILogger</c> inside the request's scope, carry that
/// path to every sink: the journal, the log files, syslog and the SIEM.
/// </summary>
public sealed class RequestPathRedactionEnricher : ILogEventEnricher
{
    /// <summary>The property ASP.NET Core's hosting scope and the Serilog request logging both use.</summary>
    public const string PropertyName = "RequestPath";

    /// <summary>Redacts <see cref="PropertyName"/> in <paramref name="logEvent"/> when it carries a credential.</summary>
    /// <param name="logEvent">The event.</param>
    /// <param name="propertyFactory">Unused.</param>
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        if (!logEvent.Properties.TryGetValue(PropertyName, out var value)
            || value is not ScalarValue { Value: string path })
            return;
        var redacted = AuditPathRedaction.Redact(path);
        if (redacted != path)
            logEvent.AddOrUpdateProperty(new LogEventProperty(PropertyName, new ScalarValue(redacted)));
    }
}
