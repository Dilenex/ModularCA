using System.Diagnostics;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Msae;
using ModularCA.Core.Services.Msae.Kerberos;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using Serilog;

namespace ModularCA.API.Controllers.v1.Msae;

/// <summary>
/// The two web services Windows autoenrollment talks to: the Certificate Enrollment Policy Web
/// Service (CEP, MS-XCEP) at <c>/cep</c>, which tells a client what it may enroll for, and the
/// Certificate Enrollment Web Service (CES, MS-WSTEP) at <c>/ces</c>, which issues.
/// </summary>
/// <remarks>
/// <para>
/// A Windows client, whether the Group Policy autoenrollment engine or <c>certreq</c>, POSTs
/// SOAP 1.2 envelopes here. The envelope formats live in <see cref="XcepMessages"/> and
/// <see cref="WstepMessages"/>; policy lives in <see cref="IXcepPolicyService"/> and issuance in
/// <see cref="IMsaeEnrollmentService"/>. This controller only joins them: read, authenticate,
/// act, answer.
/// </para>
/// <para>
/// Three credentials are understood, and the CA's MSAE configuration says which are allowed.
/// <b>Kerberos</b>: a client configured for Windows integrated authentication sends
/// <c>Authorization: Negotiate</c>; the token is accepted by <see cref="KerberosAcceptor"/>
/// against the tenant's realm bindings, without the operating system's Kerberos stack. A client
/// that sends nothing is challenged with 401 so it obtains a ticket. <b>UsernameToken</b>: the
/// WS-Security header a client configured for username authentication sends. <b>Basic</b>: what
/// a hand-driven test sends. The last two go through the same credential service as EST and the
/// interactive login, so lockout, account state and audit apply.
/// </para>
/// <para>
/// Every refusal is a SOAP fault rather than a bare status code, because a WS-Trust client
/// surfaces the fault reason to its operator and swallows a plain HTTP error. Client-caused
/// faults (malformed envelope, bad credentials, refused policy) are coded <c>Sender</c>; server
/// failures are coded <c>Receiver</c> with a generic reason. All are sent with HTTP 500, the
/// only status a Windows client reads a fault from. The one exception is the Kerberos
/// challenge, which is HTTP's own handshake and never reaches the SOAP layer.
/// </para>
/// </remarks>
[ApiController]
[Route("api/v1/msae")]
[Route("api/v1/msae/{caLabel}")]
[Route("msae/{caLabel}")]
[AllowAnonymous]
public class MsaeController(
    IMsaeEnrollmentService enrollment,
    IXcepPolicyService policy,
    IProtocolCredentialService credentials,
    ICaResolverService caResolver,
    KerberosAcceptor kerberos,
    KerberosRealmService realms,
    IProtocolAuditService protocolAudit,
    ModularCADbContext db) : ControllerBase
{
    /// <summary>SOAP 1.2 media type, as WCF sends and expects it.</summary>
    public const string SoapContentType = "application/soap+xml; charset=utf-8";

    // A PKCS#10 is a few kilobytes; a SOAP envelope around it a few more. Anything past this is
    // not an enrollment request.
    private const int MaxBodyBytes = 256 * 1024;

    /// <summary>Answers an MS-XCEP <c>GetPolicies</c> request with the templates this CA offers.</summary>
    [HttpPost("cep")]
    [RequestSizeLimit(MaxBodyBytes)]
    public async Task<IActionResult> Cep(string? caLabel = null)
    {
        var stopwatch = Stopwatch.StartNew();
        var body = await ReadBodyAsync();

        XcepMessages.GetPoliciesRequest request;
        try
        {
            request = XcepMessages.ParseGetPolicies(body);
        }
        catch (WstepMessages.WstepParseException ex)
        {
            return Fault(ex.Message, null, "parse");
        }

        var (caller, fault) = await AuthenticateAsync(caLabel, request.UsernameToken, request.KerberosToken, request.MessageId);
        if (fault != null) return fault;

        try
        {
            var policies = await policy.GetPoliciesAsync(caLabel, caller!);
            RecordSuccess(stopwatch);
            MutualAuth(caller!);
            return Content(XcepMessages.BuildGetPoliciesResponse(policies, request.MessageId), SoapContentType);
        }
        catch (MsaeEnrollmentException ex)
        {
            return Fault(ex.Message, request.MessageId, "refused");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MSAE policy query failed for {Caller}", caller!.AuditPrincipal);
            return Fault(
                "Policy query failed. Contact the administrator if the problem persists.",
                request.MessageId, "internal", senderFault: false);
        }
    }

    /// <summary>Answers an MS-WSTEP <c>Issue</c> request with the issued certificate.</summary>
    [HttpPost("ces")]
    [RequestSizeLimit(MaxBodyBytes)]
    public async Task<IActionResult> Ces(string? caLabel = null)
    {
        var stopwatch = Stopwatch.StartNew();
        var body = await ReadBodyAsync();

        WstepMessages.WstepIssueRequest request;
        try
        {
            request = WstepMessages.ParseIssueRequest(body);
        }
        catch (WstepMessages.WstepParseException ex)
        {
            return Fault(ex.Message, null, "parse");
        }

        var (caller, fault) = await AuthenticateAsync(caLabel, request.UsernameToken, request.KerberosToken, request.MessageId);
        if (fault != null) return fault;

        try
        {
            if (request.IsStatusQuery)
            {
                var status = await enrollment.QueryStatusAsync(request.RequestId!, caller!, SourceIp, caLabel);
                RecordSuccess(stopwatch);
                MutualAuth(caller!);
                return status.State switch
                {
                    MsaeRequestState.Issued => Content(WstepMessages.BuildIssueResponse(status.Pkcs7!, request.MessageId, request.RequestId), SoapContentType),
                    MsaeRequestState.Pending => Content(WstepMessages.BuildPendingResponse(request.MessageId, request.RequestId!, ServiceUrl), SoapContentType),
                    _ => Fault(status.Reason ?? "The request was denied.", request.MessageId, "refused"),
                };
            }

            var result = await enrollment.EnrollAsync(request.Pkcs10Der, caller!, SourceIp, caLabel, request.Renewal);
            RecordSuccess(stopwatch);
            MutualAuth(caller!);
            if (result.IsPending)
                return Content(WstepMessages.BuildPendingResponse(request.MessageId, result.PendingRequestId!.Value.ToString(), ServiceUrl), SoapContentType);
            return Content(WstepMessages.BuildIssueResponse(result.Pkcs7!, request.MessageId, request.RequestId), SoapContentType);
        }
        catch (MsaeEnrollmentException ex)
        {
            return Fault(ex.Message, request.MessageId, "refused");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MSAE enrollment failed for {Caller}", caller!.AuditPrincipal);
            return Fault(
                "Enrollment failed. Contact the administrator if the problem persists.",
                request.MessageId, "internal", senderFault: false);
        }
    }

    /// <summary>
    /// Diagnostic: who does the Kerberos path think the caller is? Answers the Negotiate handshake
    /// exactly as <c>/cep</c> and <c>/ces</c> do, without a SOAP body, so an operator can test a
    /// forest binding with <c>curl.exe --negotiate -u :</c> or <c>Invoke-WebRequest
    /// -UseDefaultCredentials</c> before involving the enrollment engine. Reports the accepted
    /// principal or the refusal reason; never anything the caller could not learn by enrolling.
    /// </summary>
    [HttpGet("whoami")]
    public async Task<IActionResult> WhoAmI(string? caLabel = null)
    {
        var (allowKerberos, _, tenantId) = await AuthModesAsync(caLabel);
        if (tenantId == null)
            return NotFound(new { error = "No such CA, or MSAE is not enabled on it." });

        if (!Request.Headers.TryGetValue("Authorization", out var header)
            || !header.ToString().StartsWith("Negotiate ", StringComparison.OrdinalIgnoreCase))
        {
            Response.Headers.WWWAuthenticate = "Negotiate";
            return StatusCode(StatusCodes.Status401Unauthorized, new { error = "Send a Kerberos ticket: Authorization: Negotiate <token>.", kerberosEnabledOnCa = allowKerberos });
        }

        byte[] bytes;
        try { bytes = Convert.FromBase64String(header.ToString()["Negotiate ".Length..].Trim()); }
        catch (FormatException) { return BadRequest(new { error = "The Negotiate header is not base64." }); }

        var result = await kerberos.AcceptAsync(bytes, tenantId.Value, HttpContext.RequestAborted);
        if (!result.Accepted)
            return StatusCode(StatusCodes.Status403Forbidden, new { refusal = result.Refusal.ToString(), result.Realm, servicePrincipal = result.ServicePrincipal, detail = result.Detail, kerberosEnabledOnCa = allowKerberos });

        var c = result.Caller!;
        Response.Headers.WWWAuthenticate = "Negotiate " + Convert.ToBase64String(c.MutualAuthToken.ToArray());
        return Ok(new
        {
            principal = c.FullName,
            c.IsMachine,
            c.DnsHostName,
            c.Upn,
            actingAs = c.Binding.EnrollmentUsername,
            realm = c.Realm,
            kerberosEnabledOnCa = allowKerberos,
            tokenBytes = bytes.Length,
        });
    }

    /// <summary>
    /// Completes mutual authentication for a Kerberos caller: the AP-REP, framed like the request
    /// token, goes back in <c>WWW-Authenticate</c> on the 200. A client that asked for mutual
    /// authentication (Windows always does) does not trust the reply without it.
    /// </summary>
    private void MutualAuth(MsaeCaller caller)
    {
        if (caller.Kerberos is { } k && !k.MutualAuthToken.IsEmpty)
            Response.Headers.WWWAuthenticate = "Negotiate " + Convert.ToBase64String(k.MutualAuthToken.ToArray());
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    private string? SourceIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    private async Task<string> ReadBodyAsync()
    {
        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    /// <summary>
    /// Establishes the caller: a Kerberos ticket in the Authorization header, else the
    /// envelope's UsernameToken, else an HTTP Basic header. Which of these the CA allows comes
    /// from its MSAE configuration. Returns the caller, or the response to send instead: a SOAP
    /// fault, or the 401 challenge that makes a Windows client fetch a ticket.
    /// </summary>
    private async Task<(MsaeCaller? Caller, IActionResult? Fault)> AuthenticateAsync(
        string? caLabel, WstepMessages.WstepUsernameToken? token, WstepMessages.WstepKerberosToken? kerberosToken, string? messageId)
    {
        var (allowKerberos, allowUsername, tenantId) = await AuthModesAsync(caLabel);

        // The Windows enrollment engine set to Kerberos carries its AP-REQ in the WS-Security
        // header (Kerberos Token Profile); curl and the like carry it in the HTTP header. Both
        // land on the same acceptor.
        byte[]? bytes = null;
        var where = "header";
        if (kerberosToken != null)
        {
            bytes = kerberosToken.GssFramed ? kerberosToken.Token : KerberosAcceptor.FrameApReq(kerberosToken.Token).ToArray();
            where = kerberosToken.GssFramed ? "message (GSS)" : "message (bare AP-REQ)";
        }
        else if (Request.Headers.TryGetValue("Authorization", out var header)
            && header.ToString().StartsWith("Negotiate ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                bytes = Convert.FromBase64String(header.ToString()["Negotiate ".Length..].Trim());
            }
            catch (FormatException)
            {
                return (null, Fault("The Negotiate header is not base64.", messageId, "auth_failed"));
            }
        }

        if (bytes != null)
        {
            if (!allowKerberos || tenantId == null)
                return (null, Fault("Kerberos authentication is not enabled for this CA.", messageId, "auth_mode"));

            Log.Information("MSAE: Kerberos token ({Bytes} bytes, {Where}) from {Ip} for CA {CaLabel}", bytes.Length, where, SourceIp, caLabel);
            var result = await kerberos.AcceptAsync(bytes, tenantId.Value, HttpContext.RequestAborted);
            if (!result.Accepted)
            {
                Log.Warning("MSAE Kerberos token refused ({Refusal}) realm={Realm} spn={Spn} from {Ip} for CA {CaLabel}: {Detail}",
                    result.Refusal, result.Realm, result.ServicePrincipal, SourceIp, caLabel, result.Detail);
                await protocolAudit.LogMsaeAsync(MsaeEnrollmentService.RejectOperation, null, null, null, null, null, caLabel, SourceIp,
                    success: false, errorMessage: $"Kerberos token refused: {result.Refusal}", tenantId: tenantId,
                    callerPrincipal: result.Realm != null ? $"krb:?@{result.Realm}" : "krb:?", realm: result.Realm, authMethod: "Kerberos");
                return (null, Fault("Authentication failed.", messageId, "auth_failed"));
            }

            await realms.TouchAsync(result.Caller!.Realm, HttpContext.RequestAborted);
            return (MsaeCaller.FromKerberos(result.Caller), null);
        }

        string username, password, method;
        if (token != null)
        {
            (username, password, method) = (token.Username, token.Password, "UsernameToken");
        }
        else if (Request.Headers.TryGetValue("Authorization", out var basic)
            && BasicAuthHeader.TryParse(basic.ToString(), out var basicUser, out var basicPassword))
        {
            (username, password, method) = (basicUser, basicPassword, "Basic");
        }
        else if (allowKerberos)
        {
            // HTTP's own handshake: the client obtains a ticket and repeats the request.
            //
            // The challenge is deliberately bare: status line, WWW-Authenticate, nothing else.
            // An ApiController's StatusCodeResult would attach a problem+json body, and the
            // pipeline would attach a CSRF cookie; a real IIS Negotiate challenge carries
            // neither, and a strict client (WWSAPI) may not drain them before retrying.
            //
            // The attempt is recorded on the MSAE audit tab rather than only in the log, because
            // a challenge that is never answered is otherwise invisible: the operator sees no
            // enrollment and no refusal, and cannot tell a silent client from a broken binding.
            var headers = string.Join(",", Request.Headers.Keys);
            await protocolAudit.LogMsaeAsync(MsaeEnrollmentService.RejectOperation, null, null, null, null, null, caLabel, SourceIp,
                success: false, errorMessage: Truncate($"No credential presented; challenged with Negotiate. Request headers: {headers}", 500),
                tenantId: tenantId, callerPrincipal: null, realm: null, authMethod: "None");

            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.Headers.WWWAuthenticate = "Negotiate";
            Response.ContentLength = 0;
            Response.Headers.Remove("Set-Cookie");
            Response.OnStarting(state =>
            {
                ((HttpResponse)state).Headers.Remove("Set-Cookie");
                return Task.CompletedTask;
            }, Response);
            return (null, new EmptyResult());
        }
        else
        {
            return (null, Fault(
                "Authentication required: present a WS-Security UsernameToken or HTTP Basic credentials.",
                messageId, "unauthenticated"));
        }

        if (!allowUsername)
            return (null, Fault("Username authentication is not enabled for this CA; use Windows integrated authentication.", messageId, "auth_mode"));

        var verified = await credentials.VerifyAsync(username, password, MsaeEnrollmentService.Protocol, SourceIp);
        if (verified == null)
            return (null, Fault("Authentication failed.", messageId, "auth_failed"));
        return (MsaeCaller.Credential(verified, method), null);
    }

    /// <summary>
    /// The CA's MSAE authentication modes and tenant. A CA that cannot be resolved (no label,
    /// protocol off) reports username-only, so the request fails later with the resolver's own
    /// message rather than a Kerberos challenge that could never succeed.
    /// </summary>
    private async Task<(bool AllowKerberos, bool AllowUsername, Guid? TenantId)> AuthModesAsync(string? caLabel)
    {
        try
        {
            var context = await caResolver.ResolveAsync(caLabel, MsaeEnrollmentService.Protocol);
            var ca = context.Ca;
            if (ca == null) return (false, true, null);
            var config = await db.CaProtocolConfigs.AsNoTracking()
                .Where(p => p.CaId == ca.Id && p.Protocol == MsaeEnrollmentService.Protocol)
                .Select(p => new { p.MsaeAllowKerberos, p.MsaeAllowUsernameToken })
                .FirstOrDefaultAsync();
            return (config?.MsaeAllowKerberos ?? false, config?.MsaeAllowUsernameToken ?? true, ca.TenantId);
        }
        catch (InvalidOperationException)
        {
            return (false, true, null);
        }
    }

    private static void RecordSuccess(Stopwatch stopwatch)
    {
        stopwatch.Stop();
        MetricsService.ProtocolRequestsTotal.WithLabels(MsaeEnrollmentService.Protocol, "ok").Inc();
        MetricsService.ProtocolRequestDuration.WithLabels(MsaeEnrollmentService.Protocol)
            .Observe(stopwatch.Elapsed.TotalSeconds);
    }

    /// <summary>
    /// Builds the fault response. The HTTP status is always 500: SOAP 1.2 over HTTP maps every
    /// fault to 500, WCF and Microsoft's own CES do exactly that, and the Windows client reads a
    /// fault only from a 500. A 400 or 401 carrying a fault body is not read as a fault at all;
    /// certreq reports it as WS_E_INVALID_FORMAT and the operator never sees the reason. The
    /// Sender/Receiver code inside the fault carries the "whose fault" distinction instead.
    /// </summary>
    /// <summary>This request's own URL, which a pending response names as where the request is collected.</summary>
    private string ServiceUrl => $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}";

    private ContentResult Fault(string reason, string? relatesTo, string errorKind, bool senderFault = true)
    {
        MetricsService.ProtocolRequestsTotal.WithLabels(MsaeEnrollmentService.Protocol, "error").Inc();
        MetricsService.ProtocolErrorsTotal.WithLabels(MsaeEnrollmentService.Protocol, errorKind).Inc();
        return new ContentResult
        {
            StatusCode = StatusCodes.Status500InternalServerError,
            ContentType = SoapContentType,
            Content = WstepMessages.BuildFault(reason, relatesTo, senderFault),
        };
    }
}
