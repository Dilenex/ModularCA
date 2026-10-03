using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Shared.Models;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A client built before 0.4.0 sends <c>tenantId</c>. On a request body where a null space means
/// the instance, ignoring that member would create something instance-wide, so each such body
/// refuses an unknown member: the API's own MVC JSON options bind it to a 400 problem response
/// that names the member. The same body with <c>spaceId</c> binds.
/// </summary>
public sealed class StaleTenantBodyTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";
    private static readonly Guid Space = Guid.Parse("6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60");

    /// <summary>Every request body that carries a space, where a null space means the instance.</summary>
    public static TheoryData<string> DisallowBodies() => new()
    {
        Ns + "CreateRootCaRequest",
        Ns + "CreateIntermediateCaRequest",
        Ns + "CreateGroupRequest",
        Ns + "CreateRoleRequest",
        Ns + "CreateRoleAssignmentRequest",
        Ns + "CreateUserGrantRequest",
        Ns + "ServiceIdentityRequest",
        Ns + "GenerateSshCaKeyRequest",
        typeof(KeyCeremonyParameters).FullName!,
    };

    private static Type TypeOf(string name)
        => name == typeof(KeyCeremonyParameters).FullName ? typeof(KeyCeremonyParameters) : ApiAssembly.TypeNamed(name);

    private static ServiceProvider Mvc()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddControllers().AddJsonOptions(o =>
            ApiAssembly.TypeNamed("ModularCA.API.Json.ApiJsonOptions").GetMethod("Apply")!.Invoke(null, [o.JsonSerializerOptions]));
        return services.BuildServiceProvider();
    }

    /// <summary>Reads <paramref name="json"/> as <paramref name="type"/> through MVC's JSON input formatter, with the API's options.</summary>
    private static async Task<(InputFormatterResult Result, ActionContext Context)> BindAsync(Type type, string json)
    {
        var sp = Mvc();
        var options = sp.GetRequiredService<IOptions<JsonOptions>>().Value;
        var formatter = new SystemTextJsonInputFormatter(options, NullLogger<SystemTextJsonInputFormatter>.Instance);
        var http = new DefaultHttpContext { RequestServices = sp };
        http.Request.ContentType = "application/json";
        http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var state = new ModelStateDictionary();
        var metadata = new EmptyModelMetadataProvider().GetMetadataForType(type);
        var result = await formatter.ReadAsync(new InputFormatterContext(http, "request", state, metadata, (s, e) => new StreamReader(s, e)));
        return (result, new ActionContext(http, new RouteData(), new ActionDescriptor(), state));
    }

    /// <summary>The API's 400 for an invalid model state: [ApiController]'s factory, which the API does not replace.</summary>
    private static ValidationProblemDetails Problem(ActionContext context)
    {
        var factory = context.HttpContext.RequestServices.GetRequiredService<IOptions<ApiBehaviorOptions>>().Value.InvalidModelStateResponseFactory;
        var bad = Assert.IsType<BadRequestObjectResult>(factory(context));
        Assert.Equal(400, bad.StatusCode);
        return Assert.IsType<ValidationProblemDetails>(bad.Value);
    }

    private static string Body(Type type, string spaceMember) => $$"""{"{{spaceMember}}":"{{Space}}"}""";

    [Theory]
    [MemberData(nameof(DisallowBodies))]
    public void The_body_refuses_unknown_members(string typeName)
    {
        var attribute = TypeOf(typeName).GetCustomAttribute<JsonUnmappedMemberHandlingAttribute>();
        Assert.True(attribute?.UnmappedMemberHandling == JsonUnmappedMemberHandling.Disallow, $"{typeName} does not refuse unknown members");
    }

    [Theory]
    [MemberData(nameof(DisallowBodies))]
    public async Task A_stale_tenantId_body_is_a_400_that_names_the_member(string typeName)
    {
        var type = TypeOf(typeName);
        var (result, context) = await BindAsync(type, Body(type, "tenantId"));

        Assert.True(result.HasError, $"{typeName} bound a body that sends tenantId");
        var problem = Problem(context);
        Assert.Contains(problem.Errors, e => e.Key.Contains("tenantId") || e.Value.Any(m => m.Contains("tenantId")));
    }

    [Theory]
    [MemberData(nameof(DisallowBodies))]
    public async Task The_same_body_with_spaceId_binds(string typeName)
    {
        var type = TypeOf(typeName);
        var (result, context) = await BindAsync(type, Body(type, "spaceId"));

        Assert.False(result.HasError, string.Join("; ", context.ModelState.SelectMany(s => s.Value!.Errors.Select(e => $"{s.Key}: {e.ErrorMessage}"))));
        Assert.Equal(Space, type.GetProperty("SpaceId")!.GetValue(result.Model));
    }

    /// <summary>KeyCeremonyParameters reaches the API nested in the ceremony initiation body; the refusal holds there.</summary>
    [Fact]
    public async Task A_stale_tenantId_inside_a_ceremony_initiation_is_a_400()
    {
        var type = ApiAssembly.TypeNamed(Ns + "InitiateCeremonyRequest");
        var (result, context) = await BindAsync(type, $$$"""{"operationType":"CreateRootCA","parameters":{"subjectCN":"Acme Root","tenantId":"{{{Space}}}","scope":null}}""");

        Assert.True(result.HasError);
        Assert.Contains(Problem(context).Errors, e => e.Key.Contains("tenantId") || e.Value.Any(m => m.Contains("tenantId")));
    }

    /// <summary>
    /// A stored ceremony row is read leniently (its shape may predate the class), except for the
    /// pre-0.4.0 scope keys, which <see cref="CeremonyParametersJson"/> refuses on its own.
    /// </summary>
    [Fact]
    public void A_stored_row_skips_unknown_members_but_still_refuses_a_legacy_scope_key()
    {
        var read = CeremonyParametersJson.Read<KeyCeremonyParameters>($$"""{"SubjectCN":"Acme Root","SpaceId":"{{Space}}","RetiredField":1}""");
        Assert.Equal(Space, read!.SpaceId);
        Assert.Throws<JsonException>(() => CeremonyParametersJson.Read<KeyCeremonyParameters>($$"""{"SubjectCN":"Acme Root","TenantId":"{{Space}}"}"""));
    }

    /// <summary>
    /// The list above is complete: every body an API action reads, and every object nested in one,
    /// that carries a <c>SpaceId</c> refuses unknown members.
    /// </summary>
    [Fact]
    public void Every_request_body_that_carries_a_space_is_on_the_list()
    {
        var listed = ((IEnumerable<object[]>)DisallowBodies()).Select(row => (string)row[0]).ToHashSet();
        var seen = new HashSet<Type>();
        var queue = new Queue<Type>(ApiAssembly.ControllerTypes()
            .SelectMany(c => c.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            .SelectMany(m => m.GetParameters())
            .Where(p => p.GetCustomAttributes().Any(a => a.GetType().Name == "FromBodyAttribute")
                || (IsModel(p.ParameterType) && !p.GetCustomAttributes().Any(a => a.GetType().Name.StartsWith("From", StringComparison.Ordinal))))
            .Select(p => p.ParameterType));
        var carriers = new List<string>();
        while (queue.Count > 0)
        {
            var type = queue.Dequeue();
            if (!IsModel(type) || !seen.Add(type))
                continue;
            if (type.GetProperty("SpaceId") is { CanWrite: true })
                carriers.Add(type.FullName!);
            foreach (var property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                var inner = property.PropertyType.IsGenericType ? property.PropertyType.GetGenericArguments() : [property.PropertyType];
                foreach (var t in inner)
                    queue.Enqueue(t);
            }
        }

        Assert.NotEmpty(carriers);
        var missing = carriers.Where(c => !listed.Contains(c)).ToList();
        Assert.True(missing.Count == 0, "Request bodies with a SpaceId that are not on the list:\n" + string.Join("\n", missing));
    }

    private static bool IsModel(Type type)
        => type.IsClass && type != typeof(string) && type.Namespace?.StartsWith("ModularCA", StringComparison.Ordinal) == true;
}
