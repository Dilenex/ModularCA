using System.Reflection;
using Xunit;

namespace ModularCA.Tests.Roles;

/// <summary>
/// Loads <c>ModularCA.API</c> from its build output for the role architecture tests. The test
/// project does not reference the API (it is the host, not a library), so the assembly is
/// found beside the test output in the same configuration and loaded by reflection, the way
/// the signer seam test does it. A source file newer than the assembly fails rather than
/// inspecting a stale build.
/// </summary>
internal static class ApiAssembly
{
    private static readonly Lazy<Assembly> Loaded = new(Load);

    /// <summary>The API assembly, loaded once per test run.</summary>
    public static Assembly Instance => Loaded.Value;

    /// <summary>Every concrete controller type the API declares, by base type name so no load-context question arises.</summary>
    public static IReadOnlyList<Type> ControllerTypes()
        => Instance.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && DerivesFromControllerBase(t))
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .ToList();

    /// <summary>A type the API declares, by full name; fails the test when it is not there.</summary>
    public static Type TypeNamed(string fullName)
    {
        var type = Instance.GetType(fullName, throwOnError: false);
        Assert.True(type != null, $"{fullName} is not declared by ModularCA.API.");
        return type!;
    }

    private static bool DerivesFromControllerBase(Type type)
    {
        for (var t = type.BaseType; t != null; t = t.BaseType)
        {
            if (t.FullName == "Microsoft.AspNetCore.Mvc.ControllerBase")
                return true;
        }
        return false;
    }

    private static Assembly Load()
    {
        var testDir = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        // tests/ModularCA.Tests/bin/<configuration>/<tfm>/
        var configuration = testDir.Parent?.Name ?? "Debug";
        var repoRoot = testDir;
        while (repoRoot != null && !Directory.Exists(Path.Combine(repoRoot.FullName, "ModularCA.API")))
            repoRoot = repoRoot.Parent;
        Assert.True(repoRoot != null, $"The repository root was not found above {testDir.FullName}.");

        var apiProject = Path.Combine(repoRoot!.FullName, "ModularCA.API");
        var apiDll = Path.Combine(apiProject, "bin", configuration, testDir.Name, "ModularCA.API.dll");
        Assert.True(File.Exists(apiDll), $"{apiDll} does not exist; build ModularCA.API in the {configuration} configuration before running the role tests.");

        var builtAt = File.GetLastWriteTimeUtc(apiDll);
        var newerSource = Directory.EnumerateFiles(apiProject, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .FirstOrDefault(f => File.GetLastWriteTimeUtc(f) > builtAt);
        Assert.True(newerSource == null, $"{newerSource} is newer than {apiDll}; rebuild ModularCA.API before running the role tests.");

        return Assembly.LoadFrom(apiDll);
    }
}
