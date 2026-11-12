using System.Runtime.CompilerServices;

namespace ModularCA.API.Startup;

/// <summary>
/// Whether this build can build its web host at all: the step every serving role and most
/// commands begin with. A payload with a wrong or missing framework assembly fails here, before
/// it reads its configuration, and nothing short of starting the program shows it.
/// <c>--upgrade-check</c> runs this first, so an orchestrator that checks a new build before it
/// stops the old one learns that the new one cannot start while the old one is still serving.
/// </summary>
/// <remarks>
/// 0.4.4-dev.1.1 shipped a command-line tool's <c>Microsoft.Extensions.ObjectPool</c> 7.0.0 over
/// the web framework's 10.0. <c>--upgrade-check</c> passed on it, the old version was stopped,
/// and the new one then died in <c>WebApplication.CreateBuilder</c>.
/// </remarks>
public static class HostSelfCheck
{
    /// <summary>The text that leads the message when the host cannot be built; scripts match on it.</summary>
    public const string Marker = "THIS BUILD CANNOT START";

    /// <summary>
    /// Builds a web host with this build's defaults and throws it away. Nothing listens and
    /// nothing is read but what the host's own defaults read. Returns null when it could be
    /// built, otherwise one line saying what failed, starting with <see cref="Marker"/>.
    /// </summary>
    public static string? Run()
    {
        try
        {
            BuildAndDiscard();
            return null;
        }
        catch (Exception ex)
        {
            var cause = ex is System.Reflection.TargetInvocationException { InnerException: { } inner } ? inner : ex;
            return $"{Marker}: its web host could not be built ({cause.GetType().Name}: {cause.Message.Trim()}). "
                + "The installation is incomplete or was built wrong; install a correct build.";
        }
    }

    /// <summary>
    /// The host construction itself, kept out of line: an assembly that cannot be loaded is
    /// reported when the method that needs it is compiled, so the caller's catch must not be in
    /// the same method.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void BuildAndDiscard()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
        builder.Logging.ClearProviders();
        var app = builder.Build();
        ((IDisposable)app).Dispose();
    }
}
