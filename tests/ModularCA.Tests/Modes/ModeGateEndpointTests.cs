using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Modes;
using ModularCA.Tests.Auth;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Modes;

/// <summary>
/// The declaration on every mutating endpoint, and the filter that enforces it. There is no
/// WebApplicationFactory for this host, so a request is driven the way the other endpoint tests
/// drive one: the endpoint's authorization metadata is evaluated through the real policy set and
/// handlers, then the global <see cref="ModeGateFilter"/> runs over the endpoint's own metadata,
/// then (for the console endpoint) its step-up filter and the action itself.
/// </summary>
public sealed class ModeGateEndpointTests : IDisposable
{
    private const string Admin = "ModularCA.API.Controllers.v1.Admin.";
    private const string ModeController = Admin + "AdminInstanceModeController";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mca-modeep-" + Guid.NewGuid().ToString("N"));
    private readonly ControlledUserWorld _w = new();
    private readonly RecordingAuditService _audit = new();
    private readonly IDistributedCache _cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private sealed class CurrentUserStub(Guid id, string name) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = name };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    // ---- the guard -------------------------------------------------------------------------

    private static IEnumerable<(Type Controller, MethodInfo Action, object[] Attributes)> Actions(IEnumerable<Type> controllers)
    {
        foreach (var controller in controllers)
            foreach (var action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
                yield return (controller, action, action.GetCustomAttributes(true));
    }

    /// <summary>The mutating actions among <paramref name="controllers"/> that declare no mode class.</summary>
    private static List<string> Undeclared(IEnumerable<Type> controllers)
        => Actions(controllers)
            .Where(a => a.Attributes.OfType<HttpMethodAttribute>().Any(v => v is not HttpGetAttribute and not HttpHeadAttribute))
            .Where(a => !a.Attributes.OfType<ModeGateAttribute>().Any())
            .Select(a => $"{a.Controller.Name}.{a.Action.Name}")
            .Order(StringComparer.Ordinal).ToList();

    private static ModeGateAttribute Declared(string controller, string action)
    {
        var type = ApiAssembly.TypeNamed(controller.Contains('.') ? controller : Admin + controller);
        var methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly).Where(m => m.Name == action).ToList();
        Assert.NotEmpty(methods);
        return Assert.Single(methods.Select(m => m.GetCustomAttribute<ModeGateAttribute>()).OfType<ModeGateAttribute>().DistinctBy(a => (a.Operation, a.AnsweredByAction)));
    }

    [Fact]
    public void Every_mutating_endpoint_declares_its_mode_class()
    {
        var controllers = ApiAssembly.ControllerTypes();
        Assert.True(Actions(controllers).Count(a => a.Attributes.OfType<ModeGateAttribute>().Any()) >= 290,
            "Too few declarations were found; the check is probably not seeing the controllers.");

        var undeclared = Undeclared(controllers);

        Assert.True(undeclared.Count == 0,
            "These endpoints change something and declare no mode class. Put [ModeGate(ModeOperation.X)] on the action: "
            + "Fact (a new fact: issuing, signing), Restriction (revoking, disabling, locking), Frozen (everything that waits "
            + "for full mode: users, grants, roles, profiles, policy, settings, CAs, keys, ceremonies, undoing a restriction) "
            + "or Manage (signing in, the caller's own credentials, the mode, backups, and requests that change nothing). "
            + "When unsure, Frozen.\n" + string.Join("\n", undeclared));
    }

    [ApiController]
    private sealed class UndeclaredController : ControllerBase
    {
        [HttpPost("x")] public IActionResult Changes() => Ok();
        [HttpGet("x")] public IActionResult Reads() => Ok();
        [HttpDelete("x")][ModeGate(ModeOperation.Frozen)] public IActionResult Declared() => Ok();
    }

    [Fact]
    public void The_check_sees_a_mutating_endpoint_that_declares_nothing()
        => Assert.Equal(["UndeclaredController.Changes"], Undeclared([typeof(UndeclaredController)]));

    [Fact]
    public void The_filter_is_registered_for_every_controller()
    {
        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "ModularCA.sln"))) dir = Path.GetDirectoryName(dir)!;
        var startup = File.ReadAllText(Path.Combine(dir, "ModularCA.API", "StartModularCA.cs"));

        Assert.Contains("options.Filters.Add(new ModularCA.Auth.Authorization.ModeGateFilter());", startup);
        Assert.Equal(int.MinValue, new ModeGateFilter().Order);
    }

    [Theory]
    // The table's rows, one endpoint or more each.
    [InlineData("AdminIssuanceController", "IssueCertificate", ModeOperation.Issue)]
    [InlineData("AdminRevocationController", "RevokeByCertId", ModeOperation.Restriction)]
    [InlineData("AdminRevocationController", "HoldByCertId", ModeOperation.Restriction)]
    [InlineData("AdminRevocationController", "UnholdByCertId", ModeOperation.Frozen)]
    [InlineData("AdminCaController", "UpdateCa", ModeOperation.Restriction)]
    [InlineData("AdminCaController", "CreateRoot", ModeOperation.Frozen)]
    [InlineData("AdminCaController", "ReissueInfrastructure", ModeOperation.Frozen)]
    [InlineData("AdminKeyCeremonyController", "Approve", ModeOperation.Frozen)]
    [InlineData("AdminUserGrantController", "Create", ModeOperation.Frozen)]
    [InlineData("AdminRoleController", "Create", ModeOperation.Frozen)]
    [InlineData("AdminCertProfileController", "Update", ModeOperation.Frozen)]
    [InlineData("AdminConfigController", "UpdateSecurity", ModeOperation.Frozen)]
    [InlineData("AdminSshController", "GenerateCaKey", ModeOperation.Frozen)]
    [InlineData("Management.AdminUserManagerController", "CreateUser", ModeOperation.Frozen)]
    [InlineData("Management.AdminUserManagerController", "UpdateUser", ModeOperation.Restriction)]
    [InlineData("AdminBackupController", "CreateBackup", ModeOperation.Manage)]
    [InlineData("AdminBackupController", "RestoreBackup", ModeOperation.Manage)]
    [InlineData("AdminInstanceModeController", "Set", ModeOperation.Manage)]
    // Signing in to manage and repair.
    [InlineData("ModularCA.API.Controllers.v1.Auth.AuthController", "Login", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Auth.AuthController", "Claim", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Auth.MfaStepUpController", "VerifyStepUpTotp", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Auth.TotpController", "VerifySetup", ModeOperation.Manage)]
    // The enrollment protocols are issuance.
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "FinalizeOrder", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "RevokeCert", ModeOperation.Restriction)]
    [InlineData("ModularCA.API.Controllers.v1.Est.EstController", "SimpleEnroll", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Scep.ScepController", "Post", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Msae.MsaeController", "Ces", ModeOperation.Issue)]
    // Protocol reads stay up in DR mode; what issues does not.
    [InlineData("ModularCA.API.Controllers.v1.Msae.MsaeController", "Cep", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "GetOrder", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "DownloadCertificate", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "NewOrder", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeChallengeController", "GetAuthorization", ModeOperation.Manage)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeChallengeController", "RespondToChallenge", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeAccountController", "NewAccount", ModeOperation.Fact)]
    [InlineData("ModularCA.API.Controllers.v1.Public.TsaController", "Timestamp", ModeOperation.Fact)]
    [InlineData("ModularCA.API.Controllers.v1.User.UserCertificateController", "RevokeOwnCertificate", ModeOperation.Restriction)]
    public void The_class_of_a_representative_endpoint_is_pinned(string controller, string action, ModeOperation expected)
    {
        var declared = Declared(controller.StartsWith("ModularCA.", StringComparison.Ordinal) ? controller : Admin + controller, action);
        Assert.Equal(expected, declared.Operation);
        Assert.False(declared.AnsweredByAction);
    }

    /// <summary>
    /// Two protocol endpoints carry a read and a change on one route: SCEP's GET (GetCACert and
    /// GetCACaps beside PKIOperation) and the ACME account URL (POST-as-GET beside an update).
    /// The read is answered in every mode, so the action asks the gate itself for the change.
    /// </summary>
    [Theory]
    [InlineData("ModularCA.API.Controllers.v1.Scep.ScepController", "Get", "HandlePkiOperationGet", ModeOperation.Issue)]
    [InlineData("ModularCA.API.Controllers.v1.Acme.AcmeAccountController", "UpdateAccount", "UpdateAccount", ModeOperation.Fact)]
    [InlineData("ModularCA.API.Controllers.v1.Cmp.CmpController", "Post", "Post", ModeOperation.Issue)]
    public void A_route_that_reads_and_changes_asks_the_gate_for_the_change_only(string controller, string action, string asksIn, ModeOperation declaredAs)
    {
        var declared = Declared(controller, action);
        Assert.Equal(declaredAs, declared.Operation);
        Assert.True(declared.AnsweredByAction);

        var file = controller[(controller.LastIndexOf('.') + 1)..] + ".cs";
        var folder = controller.Split('.')[^2];
        var source = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "Controllers", "v1", folder, file));
        var body = source[source.IndexOf("Task<IActionResult> " + asksIn + "(", StringComparison.Ordinal)..];
        Assert.Contains("ModeGateFilter.RequireAsync(", body[..Math.Min(body.Length, 2500)]);
    }

    /// <summary>
    /// CMP carries enrollment and revocation on one route. A revocation request goes on in
    /// maintenance mode, where an enrollment is refused; a message that cannot be read is held to
    /// the stricter class.
    /// </summary>
    [Fact]
    public void A_CMP_revocation_request_is_a_restriction_and_everything_else_an_enrollment()
    {
        var classify = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Cmp.CmpController")
            .GetMethod("ModeOperationOf", BindingFlags.NonPublic | BindingFlags.Static)!;
        ModeOperation Of(byte[] der) => (ModeOperation)classify.Invoke(null, [der])!;
        static byte[] Message(int type, Org.BouncyCastle.Asn1.Asn1Encodable content)
        {
            var header = new Org.BouncyCastle.Asn1.Cmp.PkiHeader(2,
                new Org.BouncyCastle.Asn1.X509.GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=client")),
                new Org.BouncyCastle.Asn1.X509.GeneralName(new Org.BouncyCastle.Asn1.X509.X509Name("CN=ca")));
            return new Org.BouncyCastle.Asn1.Cmp.PkiMessage(header, new Org.BouncyCastle.Asn1.Cmp.PkiBody(type, content)).GetDerEncoded();
        }
        var empty = new Org.BouncyCastle.Asn1.DerSequence();

        Assert.Equal(ModeOperation.Restriction, Of(Message(Org.BouncyCastle.Asn1.Cmp.PkiBody.TYPE_REVOCATION_REQ, empty)));
        Assert.Equal(ModeOperation.Fact, Of(Message(Org.BouncyCastle.Asn1.Cmp.PkiBody.TYPE_GEN_MSG, empty)));
        Assert.Equal(ModeOperation.Issue, Of(Message(Org.BouncyCastle.Asn1.Cmp.PkiBody.TYPE_INIT_REQ, empty)));
        Assert.Equal(ModeOperation.Issue, Of([0x30, 0x03, 0x02, 0x01]));
        Assert.Equal(ModeOperation.Issue, Of([]));
    }

    /// <summary>The repository's root: the directory that holds the solution file.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("ModularCA.sln not found above the test directory");
    }

    [Fact]
    public void OCSP_answers_the_mode_in_its_own_protocol_and_serving_a_CRL_declares_nothing()
    {
        foreach (var (controller, action) in new[]
                 {
                     ("OcspController", "Post"), ("OcspController", "Get"),
                     ("PublicShortUrlController", "OcspPost"), ("PublicShortUrlController", "OcspGet"),
                 })
        {
            var declared = Declared("ModularCA.API.Controllers.v1.Public." + controller, action);
            Assert.True(declared.AnsweredByAction, $"{controller}.{action}");
            Assert.Equal(ModeOperation.Fact, declared.Operation);
        }

        // A CRL that is already signed is served in every mode: the reads carry no declaration.
        foreach (var (controller, action) in new[]
                 {
                     ("PublicCrlController", "GetCrl"), ("PublicCrlController", "GetDeltaCrl"),
                     ("PublicShortUrlController", "GetCrl"), ("PublicShortUrlController", "GetDeltaCrl"), ("PublicShortUrlController", "GetCaCert"),
                 })
        {
            var method = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Public." + controller).GetMethod(action)!;
            Assert.Null(method.GetCustomAttribute<ModeGateAttribute>());
        }
    }

    // ---- a request through authorization and the filter ----------------------------------------

    private sealed record Sent(int Status, bool ReachedAction, ObjectResult? Result, HttpContext Http);

    private HttpContext Http(Guid actor, IInstanceModeGate? gate, string? mfaToken = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuditService>(_audit);
        services.AddSingleton(_cache);
        if (gate != null) services.AddSingleton(gate);
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", actor.ToString()), new Claim(ClaimTypes.NameIdentifier, actor.ToString())], "test")),
            RequestServices = services.BuildServiceProvider(),
        };
        http.Request.Method = HttpMethods.Post;
        http.Request.Path = "/api/v1/test";
        if (mfaToken != null) http.Request.Headers["X-MFA-Token"] = mfaToken;
        return http;
    }

    private async Task<bool> PolicyAllows(Type controller, MethodInfo action, HttpContext http)
    {
        var attributes = controller.GetCustomAttributes(true).Concat(action.GetCustomAttributes(true)).ToList();
        if (attributes.OfType<IAllowAnonymous>().Any()) return true;

        var accessor = new HttpContextAccessor { HttpContext = http };
        var groupAuth = new CaGroupAuthorizationService(_w.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor, new AccessBadgeContext(_w.Db, accessor));
        var services = new ServiceCollection().AddLogging().AddAuthorizationCore(options =>
        {
            PolicyDefinitions.AddTo(options);
            options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });
        services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, _w.Db, NullLogger<CaGroupAuthorizationHandler>.Instance));
        services.AddSingleton<IAuthorizationHandler>(new AnyScopeCapabilityAuthorizationHandler(groupAuth));
        var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await AuthorizationPolicy.CombineAsync(provider, attributes.OfType<IAuthorizeData>()) ?? await provider.GetFallbackPolicyAsync();
        return (await sp.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, http, policy!)).Succeeded;
    }

    /// <summary>
    /// Authorization, then the mode filter, then the step-up filter when the action carries one
    /// (its other filters are not run). <c>ReachedAction</c> is whether it got that far.
    /// </summary>
    private async Task<Sent> Send(Guid actor, string controller, string action, IInstanceModeGate? gate, string? mfaToken = null)
    {
        var type = ApiAssembly.TypeNamed(controller.StartsWith("ModularCA.", StringComparison.Ordinal) ? controller : Admin + controller);
        var method = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly).First(m => m.Name == action);
        var http = Http(actor, gate, mfaToken);
        if (!await PolicyAllows(type, method, http))
            return new Sent(403, false, null, http);

        var attributes = type.GetCustomAttributes(true).Concat(method.GetCustomAttributes(true)).ToList();
        var descriptor = new ActionDescriptor { EndpointMetadata = attributes, DisplayName = $"{type.Name}.{action}" };
        var filters = new List<IAsyncActionFilter> { new ModeGateFilter() };
        // Of the action's own filters only the step-up is run: the others need the services of a full host.
        filters.AddRange(method.GetCustomAttributes(true).OfType<IAsyncActionFilter>().Where(f => f.GetType().Name == "RequireStepUpAttribute"));

        foreach (var filter in filters)
        {
            var context = new ActionExecutingContext(new ActionContext(http, new RouteData(), descriptor), [], new Dictionary<string, object?>(), new object());
            var passed = false;
            await filter.OnActionExecutionAsync(context, () =>
            {
                passed = true;
                return Task.FromResult(new ActionExecutedContext(context, [], new object()));
            });
            if (!passed)
            {
                var result = (ObjectResult)context.Result!;
                return new Sent(result.StatusCode ?? 200, false, result, http);
            }
        }
        return new Sent(200, true, null, http);
    }

    private string StepUp(Guid actor, string op)
    {
        var token = Guid.NewGuid().ToString("N");
        _cache.SetString($"mfa-stepup:{actor}:{op}", token);
        return token;
    }

    private static object? Field(ObjectResult result, string name) => result.Value!.GetType().GetProperty(name)!.GetValue(result.Value);

    [Theory]
    // Frozen: a role. Fact: issuing. Restriction: revoking. All three as the system administrator,
    // with a step-up where the endpoint asks for one.
    [InlineData(InstanceMode.Full, "AdminRoleController", "Create", true)]
    [InlineData(InstanceMode.Full, "AdminIssuanceController", "IssueCertificate", true)]
    [InlineData(InstanceMode.Full, "AdminRevocationController", "RevokeByCertId", true)]
    [InlineData(InstanceMode.Restricted, "AdminRoleController", "Create", false)]
    [InlineData(InstanceMode.Restricted, "AdminIssuanceController", "IssueCertificate", true)]
    [InlineData(InstanceMode.Restricted, "AdminRevocationController", "RevokeByCertId", true)]
    [InlineData(InstanceMode.DisasterRecovery, "AdminRoleController", "Create", false)]
    [InlineData(InstanceMode.DisasterRecovery, "AdminIssuanceController", "IssueCertificate", false)]
    [InlineData(InstanceMode.DisasterRecovery, "AdminRevocationController", "RevokeByCertId", false)]
    // Signing in is allowed in every mode.
    [InlineData(InstanceMode.Restricted, "ModularCA.API.Controllers.v1.Auth.AuthController", "Login", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Auth.AuthController", "Login", true)]
    // Maintenance: nothing is issued or reconfigured; revoking, signing in and repairs go on.
    [InlineData(InstanceMode.Maintenance, "AdminIssuanceController", "IssueCertificate", false)]
    [InlineData(InstanceMode.Maintenance, "AdminCertSignRequestController", "Approve", false)]
    [InlineData(InstanceMode.Maintenance, "AdminRoleController", "Create", false)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.Est.EstController", "SimpleEnroll", false)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "NewOrder", false)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.User.UserCertSignRequestController", "UploadCsrRequest", false)]
    [InlineData(InstanceMode.Maintenance, "AdminRevocationController", "RevokeByCertId", true)]
    [InlineData(InstanceMode.Maintenance, "AdminRevokedSerialController", "Record", true)]
    [InlineData(InstanceMode.Maintenance, "AdminRevokedSerialController", "Adopt", true)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "RevokeCert", true)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.User.UserCertificateController", "RevokeOwnCertificate", true)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.Public.TsaController", "Timestamp", true)]
    [InlineData(InstanceMode.Maintenance, "AdminBackupController", "RestoreBackup", true)]
    [InlineData(InstanceMode.Maintenance, "ModularCA.API.Controllers.v1.Auth.AuthController", "Login", true)]
    // DR mode: a restore is how the instance is repaired; protocol reads stay up; nothing issues.
    [InlineData(InstanceMode.DisasterRecovery, "AdminBackupController", "RestoreBackup", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "GetOrder", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "DownloadCertificate", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Acme.AcmeChallengeController", "GetAuthorization", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Msae.MsaeController", "Cep", true)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "NewOrder", false)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Acme.AcmeOrderController", "FinalizeOrder", false)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Msae.MsaeController", "Ces", false)]
    [InlineData(InstanceMode.DisasterRecovery, "ModularCA.API.Controllers.v1.Est.EstController", "SimpleEnroll", false)]
    public async Task Each_mode_allows_its_rows_of_the_table_and_refuses_the_rest(InstanceMode mode, string controller, string action, bool allowed)
    {
        var sent = await Send(_w.Super, controller, action, new FixedModeGate(mode));

        if (allowed)
        {
            // Past the mode filter; an endpoint with a step-up filter then asks for it (403), which is not the mode's refusal.
            Assert.True(sent.ReachedAction || sent.Status == 403, $"status {sent.Status}");
            Assert.DoesNotContain(_audit.Entries, e => e.Action == AuditActionType.InstanceModeRefused);
            return;
        }

        Assert.Equal(503, sent.Status);
        Assert.False(sent.ReachedAction);
        Assert.Equal(mode switch { InstanceMode.Restricted => "MCA-MOD-001", InstanceMode.Maintenance => "MCA-MOD-003", _ => "MCA-MOD-002" },
            Field(sent.Result!, "code"));
        Assert.Equal(InstanceModeGate.NameOf(mode), Field(sent.Result!, "mode"));
        Assert.Contains(mode switch { InstanceMode.Restricted => "Issuing, revoking", InstanceMode.Maintenance => "Revoking, placing a hold", _ => "Signing in" },
            (string)Field(sent.Result!, "detail")!);
        Assert.Equal(ModeGateFilter.RetryAfterSeconds, sent.Http.Response.Headers.RetryAfter.ToString());

        var audited = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.InstanceModeRefused);
        Assert.Equal("POST /api/v1/test", audited.TargetId);
    }

    /// <summary>
    /// A caller who is not signed in is refused every time and recorded once per interval for
    /// each endpoint, with the count: an enrollment client that retries every minute, or anyone
    /// who can reach a protocol endpoint, must not fill the audit trail while the instance is in
    /// maintenance or DR mode. A signed-in caller's refusal stays one record each.
    /// </summary>
    [Fact]
    public async Task Refusals_of_callers_who_are_not_signed_in_are_counted_into_one_record_per_interval()
    {
        var now = new DateTime(2026, 11, 12, 22, 0, 0, DateTimeKind.Utc);
        var clock = ModeGateFilter.UtcNow;
        ModeGateFilter.UtcNow = () => now;
        try
        {
            // A name no other test uses: what is counted is kept per mode and endpoint.
            var what = "Enrollment in the counted-refusals test " + Guid.NewGuid().ToString("N");
            HttpContext Anonymous()
            {
                var http = new DefaultHttpContext
                {
                    RequestServices = new ServiceCollection()
                        .AddSingleton<IInstanceModeGate>(new FixedModeGate(InstanceMode.DisasterRecovery))
                        .AddSingleton<IAuditService>(_audit).BuildServiceProvider(),
                };
                http.Request.Method = "POST";
                http.Request.Path = "/est/lab/simpleenroll";
                return http;
            }
            List<(string Action, string? TargetId, object? Details)> Recorded() => _audit.Entries.Where(e => e.Action == AuditActionType.InstanceModeRefused).ToList();

            // Refused every time; recorded the first time only.
            for (var i = 0; i < 6; i++)
            {
                Assert.Equal(503, (await ModeGateFilter.RequireAsync(Anonymous(), ModeOperation.Issue, what))!.StatusCode);
                now = now.AddSeconds(20);
            }
            var first = Assert.Single(Recorded());
            Assert.Equal(1, first.Details!.GetType().GetProperty("Refusals")!.GetValue(first.Details));

            // The first refusal after the interval is one record for the five counted and itself.
            now = now.Add(ModeGateFilter.AnonymousAuditInterval);
            Assert.NotNull(await ModeGateFilter.RequireAsync(Anonymous(), ModeOperation.Issue, what));
            Assert.Equal(2, Recorded().Count);
            var second = Recorded()[1];
            Assert.Equal(6, second.Details!.GetType().GetProperty("Refusals")!.GetValue(second.Details));
            Assert.NotNull(second.Details.GetType().GetProperty("SinceUtc")!.GetValue(second.Details));

            // A signed-in caller's refusal is always its own record.
            var before = Recorded().Count;
            for (var i = 0; i < 3; i++)
            {
                var http = Anonymous();
                http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", _w.Super.ToString()), new Claim("unique_name", "root")], "test"));
                Assert.NotNull(await ModeGateFilter.RequireAsync(http, ModeOperation.Issue, what));
            }
            Assert.Equal(before + 3, Recorded().Count);
        }
        finally
        {
            ModeGateFilter.UtcNow = clock;
        }
    }

    [Fact]
    public async Task A_caller_the_policy_refuses_is_turned_away_before_the_mode_is_asked()
    {
        var sent = await Send(_w.Plain, "AdminRoleController", "Create", new FixedModeGate(InstanceMode.DisasterRecovery));

        Assert.Equal(403, sent.Status);
        Assert.Empty(_audit.Entries);
    }

    [Fact]
    public async Task With_no_mode_set_no_declared_endpoint_is_refused_anywhere()
    {
        // The filter over every declared endpoint: with the default gate, and with none registered at all.
        foreach (var gate in new IInstanceModeGate?[] { FullInstanceModeGate.Instance, null })
        {
            foreach (var (controller, action, attributes) in Actions(ApiAssembly.ControllerTypes()).Where(a => a.Attributes.OfType<ModeGateAttribute>().Any()))
            {
                var http = Http(_w.Super, gate);
                var descriptor = new ActionDescriptor { EndpointMetadata = attributes.ToList(), DisplayName = action.Name };
                var context = new ActionExecutingContext(new ActionContext(http, new RouteData(), descriptor), [], new Dictionary<string, object?>(), new object());
                var passed = false;
                await new ModeGateFilter().OnActionExecutionAsync(context, () =>
                {
                    passed = true;
                    return Task.FromResult(new ActionExecutedContext(context, [], new object()));
                });
                Assert.True(passed, $"{controller.Name}.{action.Name}");
            }
        }
        Assert.Empty(_audit.Entries);
    }

    [Fact]
    public async Task An_action_that_decides_its_own_class_is_let_through_and_can_refuse_with_the_same_answer()
    {
        var gate = new FixedModeGate(InstanceMode.Restricted);
        // UpdateCa is declared a restriction (disabling a CA); the filter lets it through while restricted.
        Assert.NotEqual(503, (await Send(_w.Super, "AdminCaController", "UpdateCa", gate)).Status);

        var http = Http(_w.Super, gate);
        var refusal = await ModeGateFilter.RequireAsync(http, ModeOperation.Frozen, "Renaming a CA");
        Assert.NotNull(refusal);
        Assert.Equal(503, refusal!.StatusCode);
        Assert.StartsWith("Renaming a CA is not available while this instance is in restricted mode.", (string)Field(refusal, "detail")!);
        Assert.Single(_audit.Entries, e => e.Action == AuditActionType.InstanceModeRefused);

        Assert.Null(await ModeGateFilter.RequireAsync(http, ModeOperation.Restriction, "Disabling a CA"));
    }

    // ---- the console endpoint ----------------------------------------------------------------

    private InstanceModeStore Store(InstanceMode? start = null)
    {
        var store = InstanceModeStore.Open(start == null ? null : Path.Combine(_dir, "hub.sock"), start == null ? null : InstanceModeGate.NameOf(start.Value), _dir);
        return store;
    }

    private async Task<IActionResult> Call(InstanceModeStore store, Guid actor, string action, params object?[] args)
    {
        var type = ApiAssembly.TypeNamed(ModeController);
        var controller = Activator.CreateInstance(type, store, _audit, new CurrentUserStub(actor, "sysadmin"), store, null)!;
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = Http(actor, store) });
        var result = type.GetMethod(action)!.Invoke(controller, args)!;
        return result is Task<IActionResult> task ? await task : (IActionResult)result;
    }

    [Fact]
    public async Task Setting_the_mode_needs_system_manage_at_system_scope()
    {
        var gate = new FixedModeGate(InstanceMode.Full);

        Assert.Equal(403, (await Send(_w.Plain, ModeController, "Set", gate)).Status);
        Assert.Equal(403, (await Send(_w.A1AdminUser, ModeController, "Set", gate)).Status);
        Assert.Equal(403, (await Send(_w.Auditor, ModeController, "Set", gate)).Status);
        Assert.Equal(403, (await Send(_w.Operator, ModeController, "Set", gate)).Status);

        // The system administrator is past the policy and is then asked to step up.
        var asked = await Send(_w.SystemAdmin, ModeController, "Set", gate);
        Assert.Equal(403, asked.Status);
        Assert.Equal(true, Field(asked.Result!, "requiresStepUp"));
        Assert.Equal(StepUpOps.SetInstanceMode, Field(asked.Result!, "operation"));
    }

    [Fact]
    public async Task Setting_the_mode_needs_a_step_up_for_that_operation()
    {
        var gate = new FixedModeGate(InstanceMode.Full);

        var wrongOperation = await Send(_w.SystemAdmin, ModeController, "Set", gate, StepUp(_w.SystemAdmin, StepUpOps.UpdateConfig));
        Assert.Equal(403, wrongOperation.Status);

        var steppedUp = await Send(_w.SystemAdmin, ModeController, "Set", gate, StepUp(_w.SystemAdmin, StepUpOps.SetInstanceMode));
        Assert.True(steppedUp.ReachedAction);
        Assert.Contains(StepUpOps.SetInstanceMode, StepUpOps.All);
    }

    [Theory]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.DisasterRecovery)]
    public async Task Setting_the_mode_is_allowed_in_every_mode_and_reading_it_is_open_to_every_signed_in_user(InstanceMode mode)
    {
        var gate = new FixedModeGate(mode);

        var set = await Send(_w.SystemAdmin, ModeController, "Set", gate, StepUp(_w.SystemAdmin, StepUpOps.SetInstanceMode));
        Assert.True(set.ReachedAction);

        var read = await Send(_w.Plain, ModeController, "Get", gate);
        Assert.True(read.ReachedAction);
        Assert.Empty(_audit.Entries);
    }

    [Fact]
    public async Task An_administrator_leaves_DR_mode_the_hub_set_and_the_record_says_who_and_why()
    {
        var store = Store(InstanceMode.Restricted);
        store.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, "hub-operator", "failover");

        var result = await Call(store, _w.SystemAdmin, "Set", new SetInstanceModeRequest { Mode = "full", Reason = "  the hub has gone silent  " });

        var status = Assert.IsType<InstanceModeStatus>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal("full", status.Mode);
        Assert.Equal("administrator", status.Source);
        Assert.Equal("sysadmin", status.SetBy);
        Assert.Equal("the hub has gone silent", status.Reason);
        Assert.NotNull(status.SetAtUtc);

        Assert.Equal(InstanceMode.Full, store.Current.Mode);
        Assert.Equal(InstanceMode.Full, InstanceModeStore.Open(Path.Combine(_dir, "hub.sock"), "restricted", _dir).Current.Mode);

        var audited = Assert.Single(_audit.Entries, e => e.Action == AuditActionType.InstanceModeChanged);
        Assert.Equal("full", audited.TargetId);
        var details = audited.Details!;
        Assert.Equal("dr", details.GetType().GetProperty("From")!.GetValue(details));
        Assert.Equal("the hub has gone silent", details.GetType().GetProperty("Reason")!.GetValue(details));
        Assert.Equal("hub-operator", details.GetType().GetProperty("PreviousSetBy")!.GetValue(details));
    }

    [Fact]
    public async Task The_console_reads_the_mode_and_who_set_it()
    {
        var store = Store(InstanceMode.Restricted);

        var status = Assert.IsType<InstanceModeStatus>(Assert.IsType<OkObjectResult>(await Call(store, _w.Plain, "Get")).Value);

        Assert.Equal("restricted", status.Mode);
        Assert.Equal("start", status.Source);
        Assert.Contains("Issuing, revoking", status.StillWorks);
    }

    [Fact]
    public async Task Health_ready_carries_the_mode_and_who_set_it_without_failing_readiness()
    {
        var store = Store(InstanceMode.Restricted);
        store.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, "hub-operator", "failover");
        var check = (Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.InstanceModeHealthCheck"), store)!;

        var result = await check.CheckHealthAsync(new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext());

        Assert.Equal(Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy, result.Status);
        var mode = result.Data["instanceMode"];
        Assert.Equal("dr", mode.GetType().GetProperty("mode")!.GetValue(mode));
        Assert.Equal("hub", mode.GetType().GetProperty("source")!.GetValue(mode));
        Assert.Equal("hub-operator", mode.GetType().GetProperty("setBy")!.GetValue(mode));

        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "ModularCA.sln"))) dir = Path.GetDirectoryName(dir)!;
        Assert.Contains(".AddCheck<ModularCA.API.HealthChecks.InstanceModeHealthCheck>(\"instance-mode\")",
            File.ReadAllText(Path.Combine(dir, "ModularCA.API", "StartModularCA.cs")));
    }

    [Theory]
    [InlineData("paused", "a reason")]
    [InlineData("", "a reason")]
    [InlineData("dr", "")]
    [InlineData("dr", "   ")]
    public async Task A_mode_that_is_not_one_or_a_missing_reason_is_refused_and_nothing_changes(string mode, string reason)
    {
        var store = Store();

        var result = await Call(store, _w.SystemAdmin, "Set", new SetInstanceModeRequest { Mode = mode, Reason = reason });

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(InstanceModeRecord.DefaultFull, store.Current);
        Assert.Empty(_audit.Entries);
        Assert.False(File.Exists(store.FilePath));
    }
}
