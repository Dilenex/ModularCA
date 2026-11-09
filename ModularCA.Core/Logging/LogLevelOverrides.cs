using Serilog;
using Serilog.Events;

namespace ModularCA.Core.Logging;

/// <summary>
/// The per-source minimum levels of the node's logger, whatever level the global switch is at.
/// </summary>
public static class LogLevelOverrides
{
    /// <summary>
    /// Applies the overrides to <paramref name="configuration"/>: ModularCA's own sources log from
    /// Information, ASP.NET Core from <paramref name="aspNetLevel"/>, EF Core from
    /// <paramref name="efCoreLevel"/>, and the built-in ingress (YARP) from Warning only. YARP logs
    /// each proxied request's full upstream URL at Information, and enrolment tokens travel in the
    /// path, so below Warning every routed enrolment would put its token in the logs.
    /// </summary>
    public static LoggerConfiguration Apply(LoggerConfiguration configuration, LogEventLevel aspNetLevel, LogEventLevel efCoreLevel)
        => configuration
            // Positive override so ModularCA.* logs are not clamped by the
            // Microsoft.AspNetCore warning override (which also affects MVC-sourced events).
            .MinimumLevel.Override("ModularCA", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.AspNetCore", aspNetLevel)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", efCoreLevel)
            .MinimumLevel.Override("Yarp", LogEventLevel.Warning);
}
