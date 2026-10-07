using System.Text.RegularExpressions;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace ModularCA.API.Startup;

/// <summary>The OpenAPI document's generator settings, shared by the host and its tests.</summary>
public static class ApiSwagger
{
    /// <summary>
    /// Configures the <c>v1</c> document: its description, the bearer scheme, the XML comments,
    /// and <see cref="UnboundPathParameterFilter"/>.
    /// </summary>
    public static void Configure(SwaggerGenOptions c)
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "ModularCA API",
            Version = "0.1.0-rc1",
            Description = "Enterprise Certificate Authority — REST API for certificate lifecycle management, PKI protocols, and administration.",
            Contact = new OpenApiContact { Name = "ModularCA" }
        });

        // JWT Bearer auth in Swagger UI
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer {token}'",
            Name = "Authorization",
            In = ParameterLocation.Header,
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer"
        });
        // Security requirement applied globally — Swagger UI shows the lock icon on all endpoints

        // Include XML comments from the API project
        var xmlFile = $"{typeof(ApiSwagger).Assembly.GetName().Name}.xml";
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        if (File.Exists(xmlPath))
            c.IncludeXmlComments(xmlPath);

        c.OperationFilter<UnboundPathParameterFilter>();
        c.CustomSchemaIds(SchemaId);
    }

    /// <summary>ModularCA type names declared more than once (in different namespaces), over the API and the ModularCA assemblies it references.</summary>
    private static readonly Lazy<HashSet<string>> SharedNames = new(() =>
    {
        var api = typeof(ApiSwagger).Assembly;
        var assemblies = api.GetReferencedAssemblies()
            .Where(a => a.Name?.StartsWith("ModularCA.", StringComparison.Ordinal) == true)
            .Select(System.Reflection.Assembly.Load)
            .Append(api);
        return assemblies.SelectMany(a => a.GetTypes())
            .GroupBy(t => t.Name, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToHashSet(StringComparer.Ordinal);
    });

    /// <summary>
    /// The schema id of <paramref name="type"/>: its name, as the default selector gives it, but
    /// its full name when another ModularCA type has the same name (an admin and a user
    /// <c>ParseCsrRequest</c>), which would otherwise fail the whole document. A generic type is
    /// named after its arguments, as the default does, and that holds for a type nested in a generic
    /// type too, whose name has no arity suffix. An array is its element's id followed by
    /// <c>Array</c>, as the default gives <c>Foo[]</c>; a multi-dimensional one adds its rank.
    /// </summary>
    internal static string SchemaId(Type type)
    {
        if (type.IsArray)
        {
            var rank = type.GetArrayRank();
            return SchemaId(type.GetElementType()!) + (rank == 1 && type.IsSZArray ? "Array" : $"Array{rank}D");
        }
        if (type.IsConstructedGenericType)
        {
            var tick = type.Name.IndexOf('`');
            var name = tick < 0 ? type.Name : type.Name[..tick];
            return string.Concat(type.GetGenericArguments().Select(SchemaId)) + name;
        }
        return SharedNames.Value.Contains(type.Name) && type.FullName is { } full
            ? full.Replace('+', '.')
            : type.Name;
    }
}

/// <summary>
/// Removes a path parameter from an operation whose route template does not name it. A controller
/// serving two routes, one with a route value and one without (the space and instance Kerberos
/// realm routes), binds that value from the route on both; on the route without it the parameter
/// is always null, and listing it there makes the document invalid, since every path parameter must
/// appear in the path.
/// </summary>
public sealed partial class UnboundPathParameterFilter : IOperationFilter
{
    /// <summary>Drops each path parameter of <paramref name="operation"/> that its path does not name.</summary>
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (operation.Parameters is not { Count: > 0 } parameters)
            return;
        var named = RouteNames(context.ApiDescription.RelativePath);
        for (var i = parameters.Count - 1; i >= 0; i--)
        {
            if (parameters[i].In == ParameterLocation.Path && !named.Contains(parameters[i].Name ?? ""))
                parameters.RemoveAt(i);
        }
    }

    /// <summary>The route value names in <paramref name="template"/>, without constraints, defaults or catch-all marks.</summary>
    internal static HashSet<string> RouteNames(string? template) =>
        RouteValue().Matches(template ?? "").Select(m => m.Groups[1].Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"\{\**([^}:=?]+)")]
    private static partial Regex RouteValue();
}
