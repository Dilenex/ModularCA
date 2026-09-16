using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using Serilog;

namespace ModularCA.API.Filters;

/// <summary>
/// The CA-scoped check for an action whose target arrives in the request body. The
/// <c>CaAdmin</c>/<c>CaOperator</c>/<c>CaUser</c> policies resolve their CA from the route, and
/// fail closed on a mutation with no CA there; an action like "issue a certificate" names its
/// CA only through the signing profile in the body, which is bound after authorization runs.
/// This filter runs after binding: it reads the named argument, resolves it to the CA or CAs
/// (<see cref="CaTargetResolver"/>) and requires the capability on every one of them.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description><c>[RequireCaCapability(Capabilities.CertRequest, CaTarget.SigningProfile, "request.SigningProfileId")]</c>
///     reads <c>request.SigningProfileId</c>, follows it to its issuing CA and checks there.</description></item>
///   <item><description>A null or absent target is a system matter (a system-level profile, a global whitelist):
///     the capability must then be held at system scope.</description></item>
///   <item><description>A target that names nothing is refused, never widened to a cross-CA check.</description></item>
///   <item><description><see cref="CaTarget.AnyCa"/> needs no argument: holding the capability on any CA is
///     enough, the rule a listing endpoint already gets.</description></item>
/// </list>
/// Pair it with a plain <c>[Authorize]</c>; a CA-scoped policy on the same action would deny
/// before this filter runs.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireCaCapabilityAttribute : ActionFilterAttribute
{
    private readonly string _capability;
    private readonly CaTarget _target;
    private readonly string? _argumentPath;

    /// <summary>Requires <paramref name="capability"/> on the CA named by the bound argument at <paramref name="argumentPath"/>.</summary>
    /// <param name="capability">A <see cref="ModularCA.Shared.Authorization.Capabilities"/> constant.</param>
    /// <param name="target">What the argument identifies.</param>
    /// <param name="argumentPath">
    /// <c>argument</c> or <c>argument.Property[.Property]</c>, matched case-insensitively.
    /// Omit for <see cref="CaTarget.AnyCa"/>.
    /// </param>
    public RequireCaCapabilityAttribute(string capability, CaTarget target, string? argumentPath = null)
    {
        _capability = capability;
        _target = target;
        _argumentPath = argumentPath;
        if (target != CaTarget.AnyCa && string.IsNullOrWhiteSpace(argumentPath))
            throw new ArgumentException("A body target needs the argument path that names it.", nameof(argumentPath));
    }

    /// <inheritdoc />
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var http = context.HttpContext;
        var auth = http.RequestServices.GetRequiredService<ICaGroupAuthorizationService>();
        var db = http.RequestServices.GetRequiredService<ModularCADbContext>();

        var userId = UserIdOf(http.User);
        if (userId == null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var allowed = await EvaluateAsync(auth, new CaTargetResolver(db), userId.Value, context.ActionArguments);
        if (!allowed)
        {
            Log.Warning(
                "Authorization denied for user {UserId} on {Method} {Path}: required capability {Capability} on the {Target} named in the request",
                userId, http.Request.Method, http.Request.Path.Value, _capability, _target);
            context.Result = new ObjectResult(new { error = $"You need {_capability} on the certificate authority this request targets." }) { StatusCode = 403 };
            return;
        }

        await next();
    }

    /// <summary>Reads the target from the bound arguments and hands the decision to <see cref="BodyTargetAuthorization"/>.</summary>
    private Task<bool> EvaluateAsync(ICaGroupAuthorizationService auth, CaTargetResolver resolver, Guid userId, IDictionary<string, object?> arguments)
    {
        var value = _target == CaTarget.AnyCa ? null : ReadArgument(arguments, _argumentPath!);
        return BodyTargetAuthorization.IsAllowedAsync(auth, resolver, userId, _capability, _target, value);
    }

    private static object? ReadArgument(IDictionary<string, object?> arguments, string path)
    {
        var parts = path.Split('.');
        var key = arguments.Keys.FirstOrDefault(k => string.Equals(k, parts[0], StringComparison.OrdinalIgnoreCase));
        if (key == null)
            return null;
        var current = arguments[key];
        foreach (var part in parts.Skip(1))
        {
            if (current == null) return null;
            var prop = current.GetType().GetProperties()
                .FirstOrDefault(p => string.Equals(p.Name, part, StringComparison.OrdinalIgnoreCase));
            if (prop == null) return null;
            current = prop.GetValue(current);
        }
        return current;
    }

    private static Guid? UserIdOf(ClaimsPrincipal? principal)
    {
        var sub = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        return Guid.TryParse(sub, out var g) ? g : null;
    }
}
