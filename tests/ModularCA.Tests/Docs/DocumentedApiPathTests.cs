using System.Net;
using System.Text.RegularExpressions;
using Xunit;

namespace ModularCA.Tests.Docs;

/// <summary>
/// Every <c>VERB /api/...</c> string in the documentation UI must resolve to a route the API
/// actually serves.
/// <para>
/// The admin guide's "Related API Endpoints" blocks listed ~90 paths under an <c>/api/...</c>
/// namespace that has never existed — <c>/api/certificates</c>, <c>/api/authorities</c>,
/// <c>/api/users</c> — against a real surface of <c>/api/v1/admin/...</c>. Exactly one of them
/// resolved. Nothing connected the docs to the routes, so the drift was invisible: the docs
/// compile, render, and look authoritative whatever they claim.
/// </para>
/// <para>
/// This reads both sides from source. It is deliberately structural rather than semantic: it
/// cannot tell you a path is the RIGHT endpoint for the page it appears on, only that it is a
/// real one. That is the failure mode worth automating — a wrong-but-real path is a
/// documentation error, a nonexistent path is a dead end for whoever follows it.
/// </para>
/// </summary>
public class DocumentedApiPathTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    /// <summary>Class-level [Route] attributes; a controller may carry more than one.</summary>
    private static readonly Regex RouteAttribute = new(@"\[Route\(""([^""]+)""\)\]", RegexOptions.Compiled);

    /// <summary>Method-level [HttpVerb] attributes, with or without a relative template.</summary>
    private static readonly Regex HttpAttribute =
        new(@"\[Http(Get|Post|Put|Delete|Patch|Head)(?:\(""([^""]*)""\))?\]", RegexOptions.Compiled);

    /// <summary>A documented endpoint reference inside the docs UI.</summary>
    private static readonly Regex DocumentedPath =
        new(@"\b(GET|POST|PUT|DELETE|PATCH)\s+(/api/[^\s<]*)", RegexOptions.Compiled);

    /// <summary>Collapses route parameters and query strings so {id:guid} and {serial} compare equal.</summary>
    private static string Normalize(string path) =>
        "/" + Regex.Replace(path.Split('?')[0], @"\{[^}]*\}", "{}").Trim('/');

    private static HashSet<(string Verb, string Path)> RealRoutes()
    {
        var routes = new HashSet<(string, string)>();
        var controllers = Path.Combine(RepoRoot(), "ModularCA.API", "Controllers");
        Assert.True(Directory.Exists(controllers), $"expected controllers at {controllers}");

        foreach (var file in Directory.EnumerateFiles(controllers, "*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(file);
            var prefixes = RouteAttribute.Matches(source).Select(m => m.Groups[1].Value).ToList();
            if (prefixes.Count == 0) continue;

            foreach (Match http in HttpAttribute.Matches(source))
            {
                var verb = http.Groups[1].Value.ToUpperInvariant();
                var relative = http.Groups[2].Success ? http.Groups[2].Value : string.Empty;

                foreach (var prefix in prefixes)
                {
                    var full = prefix.Trim('/');
                    if (relative.Length > 0) full += "/" + relative.Trim('/');
                    routes.Add((verb, Normalize(full)));
                }
            }
        }

        Assert.True(routes.Count > 100, $"route extraction found only {routes.Count} routes — the attribute shape changed and this guard went blind");
        return routes;
    }

    /// <summary>
    /// Enumerated rather than listed, so a new documentation page is covered the day it is
    /// written instead of the day someone remembers to add it here.
    /// </summary>
    public static TheoryData<string> DocPages()
    {
        var data = new TheoryData<string>();
        var pages = Path.Combine(RepoRoot(), "modularca.docsui", "src", "pages");
        foreach (var file in Directory.EnumerateFiles(pages, "*.tsx").OrderBy(f => f, StringComparer.Ordinal))
            data.Add(Path.GetFileName(file));
        return data;
    }

    [Theory]
    [MemberData(nameof(DocPages))]
    public void Every_endpoint_the_docs_name_is_one_the_api_serves(string pageFileName)
    {
        var path = Path.Combine(RepoRoot(), "modularca.docsui", "src", "pages", pageFileName);

        // Docs write braces as HTML entities inside JSX, so decode before matching.
        var text = WebUtility.HtmlDecode(File.ReadAllText(path));
        var real = RealRoutes();

        var unresolved = DocumentedPath.Matches(text)
            .Select(m => (Verb: m.Groups[1].Value, Path: m.Groups[2].Value))
            .Where(d => !Resolves(d.Verb, d.Path, real))
            .Select(d => $"{d.Verb} {d.Path}")
            .Distinct()
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        Assert.True(unresolved.Count == 0,
            $"{pageFileName} documents {unresolved.Count} endpoint(s) the API does not serve:\n  "
            + string.Join("\n  ", unresolved));
    }

    /// <summary>
    /// A documented path resolves if it matches a route exactly, or — when it ends in a slash,
    /// which is how the ASCII sequence diagrams wrap a long path across two cells — if it is a
    /// prefix of one. The prefix rule still fails for a namespace that does not exist at all,
    /// which is the drift this guards against; it only tolerates truncation.
    /// </summary>
    private static bool Resolves(string verb, string path, HashSet<(string Verb, string Path)> real)
    {
        var normalized = Normalize(path);
        if (real.Contains((verb, normalized))) return true;

        return path.EndsWith('/')
            && real.Any(r => r.Verb == verb && r.Path.StartsWith(normalized + "/", StringComparison.Ordinal));
    }
}
