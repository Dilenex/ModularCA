using ModularCA.Core.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace ModularCA.Tests.Core.Logging;

/// <summary>
/// The Serilog request log recorded the raw request path, so every public enrollment token
/// reached the journal, the log files and any syslog or SIEM target, though the network audit
/// already redacted it. <see cref="RequestPathRedactionEnricher"/> applies the audit's rule to
/// every event's <c>RequestPath</c>.
/// </summary>
public class RequestPathRedactionEnricherTests
{
    private sealed class Capture : ILogEventSink
    {
        public readonly List<LogEvent> Events = [];
        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }

    private static (Logger Logger, Capture Sink) Build()
    {
        var sink = new Capture();
        var logger = new LoggerConfiguration()
            .Enrich.With(new RequestPathRedactionEnricher())
            .WriteTo.Sink(sink)
            .CreateLogger();
        return (logger, sink);
    }

    [Fact]
    public void The_request_completed_event_does_not_carry_the_enrollment_token()
    {
        var (logger, sink) = Build();
        using (logger)
        {
            // The template the Serilog request logging middleware uses.
            logger.Information("HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms",
                "GET", "/api/v1/public/enroll/s3cr3t-token/page", 200, 1.5);
        }

        var logged = Assert.Single(sink.Events);
        var rendered = logged.RenderMessage();
        Assert.DoesNotContain("s3cr3t-token", rendered);
        Assert.Contains("/api/v1/public/enroll/{token}/page", rendered);
        Assert.Equal("/api/v1/public/enroll/{token}/page", ((ScalarValue)logged.Properties["RequestPath"]).Value);
    }

    [Fact]
    public void A_path_from_the_request_scope_is_redacted_too()
    {
        var (logger, sink) = Build();
        using (logger)
        {
            logger.ForContext("RequestPath", "/public/enroll/s3cr3t-token").Warning("Enrollment refused");
        }

        Assert.Equal("/public/enroll/{token}", ((ScalarValue)Assert.Single(sink.Events).Properties["RequestPath"]).Value);
    }

    [Fact]
    public void Other_paths_are_left_alone()
    {
        var (logger, sink) = Build();
        using (logger)
        {
            logger.Information("HTTP {RequestMethod} {RequestPath}", "GET", "/api/v1/admin/users");
        }

        Assert.Equal("/api/v1/admin/users", ((ScalarValue)Assert.Single(sink.Events).Properties["RequestPath"]).Value);
    }
}
