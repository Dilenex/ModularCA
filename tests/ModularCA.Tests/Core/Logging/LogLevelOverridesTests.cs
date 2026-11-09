using ModularCA.Core.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace ModularCA.Tests.Core.Logging;

/// <summary>
/// The built-in ingress (YARP) logged "Proxying to {targetUrl}" at Information with the full
/// upstream path, so an enrolment routed through it put its token in the logs.
/// <see cref="LogLevelOverrides"/> holds YARP at Warning whatever the global level.
/// </summary>
public class LogLevelOverridesTests
{
    private sealed class Capture : ILogEventSink
    {
        public readonly List<LogEvent> Events = [];
        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }

    private static (Logger Logger, Capture Sink) Build()
    {
        var sink = new Capture();
        var configuration = new LoggerConfiguration().MinimumLevel.Verbose();
        var logger = LogLevelOverrides.Apply(configuration, LogEventLevel.Warning, LogEventLevel.Fatal)
            .WriteTo.Sink(sink)
            .CreateLogger();
        return (logger, sink);
    }

    [Fact]
    public void The_ingress_proxy_log_line_is_dropped_even_at_debug()
    {
        var (logger, sink) = Build();
        using (logger)
        {
            var yarp = logger.ForContext(Constants.SourceContextPropertyName, "Yarp.ReverseProxy.Forwarder.HttpForwarder");
            yarp.Information("Proxying to {targetUrl} {version} {versionPolicy} {isStreaming}",
                "https://node1:8443/api/v1/public/enroll/s3cr3t-token/page", "2.0", "RequestVersionOrLower", false);
            yarp.Debug("Received HTTP/2 response");
        }

        Assert.Empty(sink.Events);
    }

    [Fact]
    public void Ingress_warnings_and_application_information_still_log()
    {
        var (logger, sink) = Build();
        using (logger)
        {
            logger.ForContext(Constants.SourceContextPropertyName, "Yarp.ReverseProxy.Forwarder.HttpForwarder").Warning("Request failed");
            logger.ForContext(Constants.SourceContextPropertyName, "ModularCA.Core.Services.CertificateRevocationService").Information("Revoked");
            logger.ForContext(Constants.SourceContextPropertyName, "Microsoft.AspNetCore.Hosting.Diagnostics").Information("Request starting");
        }

        Assert.Equal(["Request failed", "Revoked"], sink.Events.Select(e => e.MessageTemplate.Text));
    }
}
