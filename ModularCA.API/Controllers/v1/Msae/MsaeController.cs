using System.Diagnostics;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Msae;
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
/// Credentials are taken from the WS-Security <c>UsernameToken</c> in the SOAP header, which is
/// what a Windows client configured for username authentication sends, or from an HTTP Basic
/// header, which is what a hand-driven test sends. Both go through the same credential service
/// as EST and the interactive login, so lockout, account state and audit apply.
/// </para>
/// <para>
/// Every refusal is a SOAP fault rather than a bare status code, because a WS-Trust client
/// surfaces the fault reason to its operator and swallows a plain HTTP error. Client-caused
/// faults (malformed envelope, bad credentials, refused policy) are coded <c>Sender</c>; server
/// failures are coded <c>Receiver</c> with a generic reason. All are sent with HTTP 500, the
/// only status a Windows client reads a fault from.
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
    IProtocolCredentialService credentials) : ControllerBase
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

        var (username, fault) = await AuthenticateAsync(request.UsernameToken, request.MessageId);
        if (fault != null) return fault;

        try
        {
            var policies = await policy.GetPoliciesAsync(caLabel, username!);
            RecordSuccess(stopwatch);
            return Content(XcepMessages.BuildGetPoliciesResponse(policies, request.MessageId), SoapContentType);
        }
        catch (MsaeEnrollmentException ex)
        {
            return Fault(ex.Message, request.MessageId, "refused");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MSAE policy query failed for {Username}", username);
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

        var (username, fault) = await AuthenticateAsync(request.UsernameToken, request.MessageId);
        if (fault != null) return fault;

        try
        {
            var pkcs7 = await enrollment.EnrollAsync(request.Pkcs10Der, username!, SourceIp, caLabel);
            RecordSuccess(stopwatch);
            return Content(WstepMessages.BuildIssueResponse(pkcs7, request.MessageId, request.RequestId), SoapContentType);
        }
        catch (MsaeEnrollmentException ex)
        {
            return Fault(ex.Message, request.MessageId, "refused");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MSAE enrollment failed for {Username}", username);
            return Fault(
                "Enrollment failed. Contact the administrator if the problem persists.",
                request.MessageId, "internal", senderFault: false);
        }
    }

    private string? SourceIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    private async Task<string> ReadBodyAsync()
    {
        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    /// <summary>
    /// Verifies the caller: the envelope's UsernameToken when present, else an HTTP Basic header.
    /// Returns the verified username, or the fault to send when there is no credential or it
    /// does not verify.
    /// </summary>
    private async Task<(string? Username, IActionResult? Fault)> AuthenticateAsync(
        WstepMessages.WstepUsernameToken? token, string? messageId)
    {
        string username, password;
        if (token != null)
        {
            (username, password) = (token.Username, token.Password);
        }
        else if (Request.Headers.TryGetValue("Authorization", out var header)
            && BasicAuthHeader.TryParse(header.ToString(), out var basicUser, out var basicPassword))
        {
            (username, password) = (basicUser, basicPassword);
        }
        else
        {
            return (null, Fault(
                "Authentication required: present a WS-Security UsernameToken or HTTP Basic credentials.",
                messageId, "unauthenticated"));
        }

        var verified = await credentials.VerifyAsync(username, password, MsaeEnrollmentService.Protocol, SourceIp);
        if (verified == null)
            return (null, Fault("Authentication failed.", messageId, "auth_failed"));
        return (verified, null);
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
