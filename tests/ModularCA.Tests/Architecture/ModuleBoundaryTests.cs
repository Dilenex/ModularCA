using System.Xml.Linq;
using Xunit;

namespace ModularCA.Tests.Architecture;

/// <summary>
/// Pins the project dependency direction that future private modules depend on.
/// </summary>
/// <remarks>
/// <para>
/// The commercial plan puts some features in a separate private repository. That only works if
/// one thing stays true: <b>a private module may reference the open-source projects, and the
/// open-source projects may never reference a private module.</b> The open repository has to
/// build, test and ship standalone, with no conditional compilation, no stub project and no hole
/// where private code would go — otherwise the free edition is broken for everyone who clones it,
/// which is the opposite of what an open core is for.
/// </para>
/// <para>
/// Two properties of the current graph are what make that possible, and neither is obvious enough
/// to survive on its own:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>ModularCA.Shared</c> references nothing. It holds the interfaces, the error codes, the
///     entitlement contract and the licence catalogue, so it is what a private module compiles
///     against. The moment it gains a project reference, that module drags a transitive graph —
///     eventually the database and the keystore — into something that wanted a handful of types.
///   </description></item>
///   <item><description>
///     Nothing references <c>ModularCA.API</c>. It is the composition root, and a leaf. An
///     enterprise build adds its registrations by composing around it; if some project started
///     referencing it, the dependency graph would have a cycle in exactly the place the extension
///     point needs to be.
///   </description></item>
/// </list>
/// <para>
/// These are cheap to assert and expensive to rediscover. A reference added for a good local
/// reason is invisible in review — it is one line in a csproj — and the cost surfaces months
/// later as "why can't the module just reference that?".
/// </para>
/// </remarks>
public class ModuleBoundaryTests
{
    /// <summary>
    /// Layer order, lowest first. A project may reference only projects earlier in this list.
    /// </summary>
    /// <remarks>
    /// Declared rather than derived, because the point is to pin the intended shape and notice
    /// when reality diverges. Deriving it from the csproj files would make the test agree with
    /// whatever the graph happens to be, which is not a test.
    /// </remarks>
    private static readonly string[] LayerOrder =
    [
        "ModularCA.Shared",
        "ModularCA.Database",
        "ModularCA.Keystore",
        "ModularCA.Core",
        "ModularCA.Auth",
        "ModularCA.Bootstrap",
        "ModularCA.API",
    ];

    /// <summary>Repository root, found by walking up from the test assembly to the solution file.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    /// <summary>The ModularCA projects each project references, by project name.</summary>
    private static Dictionary<string, List<string>> ReferenceGraph()
    {
        var root = RepoRoot();
        var graph = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var name in LayerOrder.Concat(["ModularCA.KeystoreCli"]))
        {
            var csproj = Path.Combine(root, name, $"{name}.csproj");
            if (!File.Exists(csproj)) continue;

            var refs = XDocument.Load(csproj)
                .Descendants("ProjectReference")
                .Select(e => (string?)e.Attribute("Include"))
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => Path.GetFileNameWithoutExtension(v!.Replace('\\', '/')))
                .Where(n => n.StartsWith("ModularCA.", StringComparison.Ordinal))
                .ToList();

            graph[name] = refs;
        }

        return graph;
    }

    [Fact]
    public void The_projects_under_test_are_actually_found()
    {
        // Guards the guard. A wrong root would make every assertion below vacuously pass, and this
        // is precisely the kind of test that is never looked at again once it is green.
        var graph = ReferenceGraph();

        Assert.Equal(LayerOrder.Length, graph.Count(kv => LayerOrder.Contains(kv.Key)));
        Assert.Contains("ModularCA.Shared", graph.Keys);
        Assert.NotEmpty(graph["ModularCA.API"]);
    }

    [Fact]
    public void Shared_references_nothing()
    {
        // The contract assembly a private module compiles against. Anything added here is added to
        // every module's transitive graph, whether the module wanted it or not.
        var refs = ReferenceGraph()["ModularCA.Shared"];

        Assert.True(
            refs.Count == 0,
            "ModularCA.Shared must stay dependency-free — it is what a private module references. "
            + $"Found: {string.Join(", ", refs)}");
    }

    [Fact]
    public void Nothing_references_the_composition_root()
    {
        // ModularCA.API wires everything together and must stay a leaf so an enterprise build can
        // compose around it. A reference into it would put a cycle exactly where the extension
        // point has to go.
        var offenders = ReferenceGraph()
            .Where(kv => kv.Value.Contains("ModularCA.API"))
            .Select(kv => kv.Key)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"ModularCA.API must stay a leaf. Referenced by: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void Every_reference_points_down_the_layer_order()
    {
        // Catches a cycle and an inversion in one assertion. Both are the same failure from the
        // module's point of view: a graph it cannot attach to without pulling in the world.
        var graph = ReferenceGraph();
        var violations = new List<string>();

        foreach (var (project, refs) in graph)
        {
            var from = Array.IndexOf(LayerOrder, project);
            if (from < 0) continue; // KeystoreCli is a separate executable, not part of the chain

            foreach (var reference in refs)
            {
                var to = Array.IndexOf(LayerOrder, reference);
                if (to < 0)
                {
                    violations.Add($"{project} references {reference}, which is not a declared layer");
                    continue;
                }

                if (to >= from)
                    violations.Add($"{project} references {reference}, which is not below it");
            }
        }

        Assert.True(violations.Count == 0, string.Join("; ", violations));
    }
}
