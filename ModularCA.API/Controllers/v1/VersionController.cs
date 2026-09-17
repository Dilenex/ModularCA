using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1;

/// <summary>
/// Reports the running application's version and build provenance. The version originates from the
/// repo-root VERSION file, applied to every assembly via Directory.Build.props (<c>&lt;Version&gt;</c>)
/// and read back here from the entry assembly's <see cref="AssemblyInformationalVersionAttribute"/> —
/// whose SourceLink-appended <c>+&lt;git-sha&gt;</c> suffix also gives us the commit for free. The same
/// VERSION file is injected into the UI bundles at build time, so this endpoint and the UI's
/// compile-time version match by construction; comparing them surfaces deploy drift (UI and API built
/// from different versions). Requires authentication — the version is not exposed pre-auth.
/// </summary>
[ApiController]
[Route("api/v1/version")]
[NodeRole(ProcessRole.Control)]
public class VersionController : ControllerBase
{
    // Resolved once — assembly metadata cannot change at runtime.
    private static readonly object Info = ResolveInfo();

    /// <summary>
    /// Returns the running version + provenance, e.g.
    /// <c>{ "version": "0.1.0-rc2", "commit": "386f835", "buildTime": "2026-06-28T..Z" }</c>.
    /// </summary>
    [HttpGet]
    public IActionResult Get() => Ok(Info);

    private static object ResolveInfo()
    {
        var entry = Assembly.GetEntryAssembly();
        var informational = entry?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty;

        // InformationalVersion is "<version>+<full-git-sha>" when built in a git repo (SourceLink), or
        // just "<version>" otherwise.
        string version;
        string commit;
        var plus = informational.IndexOf('+');
        if (plus >= 0)
        {
            version = informational[..plus];
            var sha = informational[(plus + 1)..];
            // Shorten to a 7-char short SHA to match the UI's `git rev-parse --short HEAD`.
            commit = sha.Length >= 7 ? sha[..7] : sha;
        }
        else
        {
            version = string.IsNullOrWhiteSpace(informational)
                ? (entry?.GetName().Version?.ToString() ?? "unknown")
                : informational;
            commit = "unknown";
        }

        // Best-effort build time = the entry assembly file's last-write time (UTC). Empty for
        // single-file/trimmed publishes where the location isn't available — never throws.
        string? buildTime = null;
        try
        {
            var location = entry?.Location;
            if (!string.IsNullOrEmpty(location) && System.IO.File.Exists(location))
                buildTime = System.IO.File.GetLastWriteTimeUtc(location).ToString("o");
        }
        catch
        {
            // best-effort only
        }

        return new { version, commit, buildTime };
    }
}
