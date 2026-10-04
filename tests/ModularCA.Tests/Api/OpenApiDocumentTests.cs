using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The API's OpenAPI document, generated with the host's own generator settings
/// (<c>ApiSwagger.Configure</c>) over every controller. The test project does not reference
/// Swashbuckle, so the generator is loaded beside the API assembly and driven by reflection.
/// </summary>
public class OpenApiDocumentTests
{
    private static readonly Lazy<JsonDocument> Document = new(Generate);

    /// <summary>
    /// Every path parameter of every operation is named in its path, which OpenAPI requires. The
    /// Kerberos realm controller serves a space route with <c>{spaceId}</c> and an instance route
    /// without it; both are documented, each with the parameters its path names.
    /// </summary>
    [Fact]
    public void Every_path_parameter_is_named_in_its_path_and_both_realm_routes_are_documented()
    {
        var paths = Document.Value.RootElement.GetProperty("paths");
        var unbound = new List<string>();
        foreach (var path in paths.EnumerateObject())
        {
            foreach (var operation in path.Value.EnumerateObject())
            {
                if (!operation.Value.TryGetProperty("parameters", out var parameters))
                    continue;
                foreach (var parameter in parameters.EnumerateArray())
                {
                    if (parameter.GetProperty("in").GetString() == "path"
                        && !path.Name.Contains("{" + parameter.GetProperty("name").GetString() + "}", StringComparison.OrdinalIgnoreCase))
                        unbound.Add($"{operation.Name.ToUpperInvariant()} {path.Name}: {parameter.GetProperty("name").GetString()}");
                }
            }
        }
        Assert.Empty(unbound);

        string[] PathParameters(string path, string method) =>
            paths.GetProperty(path).GetProperty(method).TryGetProperty("parameters", out var p)
                ? p.EnumerateArray().Where(x => x.GetProperty("in").GetString() == "path").Select(x => x.GetProperty("name").GetString()!).OrderBy(n => n).ToArray()
                : [];
        Assert.Equal(["spaceId"], PathParameters("/api/v1/admin/spaces/{spaceId}/kerberos-realms", "get"));
        Assert.Empty(PathParameters("/api/v1/admin/instance/kerberos-realms", "get"));
        Assert.Empty(PathParameters("/api/v1/admin/instance/kerberos-realms", "post"));
        Assert.Equal(["id", "spaceId"], PathParameters("/api/v1/admin/spaces/{spaceId}/kerberos-realms/{id}", "put"));
        Assert.Equal(["id"], PathParameters("/api/v1/admin/instance/kerberos-realms/{id}", "put"));
        Assert.Equal(["id", "kvno"], PathParameters("/api/v1/admin/instance/kerberos-realms/{id}/keys/{kvno}/retire", "post"));
    }

    private sealed class Outer<T>
    {
        public sealed class Inner { }
    }

    /// <summary>Calls <c>ApiSwagger.SchemaId</c>.</summary>
    private static string SchemaId(Type type) =>
        (string)ApiAssembly.TypeNamed("ModularCA.API.Startup.ApiSwagger")
            .GetMethod("SchemaId", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [type])!;

    /// <summary>
    /// A type nested in a generic type is generic but its name has no arity suffix, and an array's
    /// name ends in brackets; both get the id Swashbuckle's default selector gives them.
    /// </summary>
    [Fact]
    public void A_schema_id_names_a_type_nested_in_a_generic_and_an_array_as_the_default_does()
    {
        Assert.Equal("Int32Inner", SchemaId(typeof(Outer<int>.Inner)));
        Assert.Equal("StringArray", SchemaId(typeof(string[])));
        Assert.Equal("StringArrayArray", SchemaId(typeof(string[][])));
        Assert.Equal("StringArrayList", SchemaId(typeof(List<string[]>)));
        Assert.Equal("StringInt32ArrayDictionary", SchemaId(typeof(Dictionary<string, int[]>)));
        Assert.Equal("Int32", SchemaId(typeof(int)));
    }

    private static JsonDocument Generate()
    {
        var api = ApiAssembly.Instance;
        var apiDir = Path.GetDirectoryName(api.Location)!;
        // MVC loads the API's dependencies by name while it scans the controllers; resolve them
        // beside the API, which is where the test project does not look.
        System.Runtime.Loader.AssemblyLoadContext.Default.Resolving += (context, name) =>
            File.Exists(Path.Combine(apiDir, name.Name + ".dll")) ? context.LoadFromAssemblyPath(Path.Combine(apiDir, name.Name + ".dll")) : null;
        Assembly Beside(string name) => Assembly.LoadFrom(Path.Combine(apiDir, name + ".dll"));
        var gen = Beside("Swashbuckle.AspNetCore.SwaggerGen");
        var swagger = Beside("Swashbuckle.AspNetCore.Swagger");
        var openApi = Beside("Microsoft.OpenApi");

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>(new Host());
        services.AddControllers().AddApplicationPart(api);
        var optionsType = gen.GetType("Swashbuckle.AspNetCore.SwaggerGen.SwaggerGenOptions", throwOnError: true)!;
        var configure = Delegate.CreateDelegate(typeof(Action<>).MakeGenericType(optionsType),
            ApiAssembly.TypeNamed("ModularCA.API.Startup.ApiSwagger").GetMethod("Configure")!);
        gen.GetType("Microsoft.Extensions.DependencyInjection.SwaggerGenServiceCollectionExtensions", throwOnError: true)!
            .GetMethod("AddSwaggerGen", [typeof(IServiceCollection), configure.GetType()])!
            .Invoke(null, [services, configure]);

        using var provider = services.BuildServiceProvider();
        var providerType = swagger.GetType("Swashbuckle.AspNetCore.Swagger.ISwaggerProvider", throwOnError: true)!;
        var document = providerType.GetMethod("GetSwagger")!.Invoke(provider.GetRequiredService(providerType), ["v1", null, null])!;

        using var text = new StringWriter();
        var writer = Activator.CreateInstance(openApi.GetTypes().Single(t => t.Name == "OpenApiJsonWriter"), text)!;
        Method(document, "SerializeAsV3").Invoke(document, [writer]);
        var flush = Method(writer, "FlushAsync");
        ((Task)flush.Invoke(writer, flush.GetParameters().Select(_ => (object?)CancellationToken.None).ToArray())!).GetAwaiter().GetResult();
        return JsonDocument.Parse(text.ToString());
    }

    /// <summary>The first method named <paramref name="name"/> on the object's type or one of its interfaces.</summary>
    private static MethodInfo Method(object target, string name) =>
        target.GetType().GetInterfaces().Prepend(target.GetType())
            .SelectMany(t => t.GetMethods())
            .First(m => m.Name == name);

    private sealed class Host : Microsoft.AspNetCore.Hosting.IWebHostEnvironment
    {
        public string WebRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider WebRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
        public string ApplicationName { get; set; } = "ModularCA.API";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public string EnvironmentName { get; set; } = "Development";
    }
}
