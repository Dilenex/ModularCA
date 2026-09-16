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
/// The Certificate Enrollment Web Service (CES) endpoint for Windows autoenrollment: MS-WSTEP
/// over HTTPS, authenticated by username and password.
/// </summary>
/// <remarks>
/// <para>
/// A Windows client, whether the Group Policy autoenrollment engine or <c>certreq</c>, POSTs a
/// SOAP 1.2 <c>RequestSecurityToken</c> here and expects a
/// <c>RequestSecurityTokenResponseCollection</c> carrying its certificate. The envelope formats
/// live in <see cref="WstepMessages"/>; issuance lives in <see cref="IMsaeEnrollmentService"/>.
/// This controller only joins the two: read, authenticate, enroll, answer.
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
/// faults (malformed envelope, bad credentials, refused policy) are coded <c>Sender</c> and sent
/// with a 4xx; server failures are coded <c>Receiver</c> with a 500 and a generic reason.
/// </para>
/// </remarks>
[ApiController]
[Route("api/v1/msae")]
[Route("api/v1/msae/{caLabel}")]
[Route("msae/{caLabel}")]
[AllowAnonymous]
public class MsaeController(
    IMsaeEnrollmentService enrollment,
    IProtocolCredentialService credentials) : ControllerBase
{
    /// <summary>SOAP 1.2 media type, as WCF sends and expects it.</summary>
    public const string SoapContentType = "application/soap+xml; charset=utf-8";

    // A PKCS#10 is a few kilobytes; a SOAP envelope around it a few more. Anything past this is
    // not an enrollment request.
    private const int MaxBodyBytes = 256 * 1024;

    /// <summary>Answers an MS-WSTEP <c>Issue</c> request with the issued certificate.</summary>
    [HttpPost("ces")]
    [RequestSizeLimit(MaxBodyBytes)]
    public async Task<IActionResult> Ces(string? caLabel = null)
    {
        var stopwatch = Stopwatch.StartNew();

        string body;
        using (var reader = new StreamReader(Request.Body, Encoding.UTF8))
            body = await reader.ReadToEndAsync();

        WstepMessages.WstepIssueRequest request;
        try
        {
            request = WstepMessages.ParseIssueRequest(body);
        }
        catch (WstepMessages.WstepParseException ex)
        {
            return Fault(StatusCodes.Status400BadRequest, ex.Message, null, "parse");
        }

        if (request.IsRenewal)
        {
            return Fault(StatusCodes.Status400BadRequest,
                "Renewal on behalf of an existing certificate is not supported yet; submit a new enrollment.",
                request.MessageId, "renewal");
        }

        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var credential = ResolveCredential(request);
        if (credential == null)
        {
            return Fault(StatusCodes.Status401Unauthorized,
                "Authentication required: present a WS-Security UsernameToken or HTTP Basic credentials.",
                request.MessageId, "unauthenticated");
        }

        var verified = await credentials.VerifyAsync(credential.Value.Username, credential.Value.Password,
            MsaeEnrollmentService.Protocol, sourceIp);
        if (verified == null)
            return Fault(StatusCodes.Status401Unauthorized, "Authentication failed.", request.MessageId, "auth_failed");

        try
        {
            var pkcs7 = await enrollment.EnrollAsync(request.Pkcs10Der, verified, sourceIp, caLabel);

            stopwatch.Stop();
            MetricsService.ProtocolRequestsTotal.WithLabels(MsaeEnrollmentService.Protocol, "ok").Inc();
            MetricsService.ProtocolRequestDuration.WithLabels(MsaeEnrollmentService.Protocol)
                .Observe(stopwatch.Elapsed.TotalSeconds);

            return Content(WstepMessages.BuildIssueResponse(pkcs7, request.MessageId, request.RequestId), SoapContentType);
        }
        catch (MsaeEnrollmentException ex)
        {
            return Fault(StatusCodes.Status400BadRequest, ex.Message, request.MessageId, "refused");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "MSAE enrollment failed for {Username}", verified);
            return Fault(StatusCodes.Status500InternalServerError,
                "Enrollment failed. Contact the administrator if the problem persists.",
                request.MessageId, "internal", senderFault: false);
        }
    }

    /// <summary>
    /// The credential to verify: the envelope's UsernameToken when present, else an HTTP Basic
    /// header, else nothing.
    /// </summary>
    private (string Username, string Password)? ResolveCredential(WstepMessages.WstepIssueRequest request)
    {
        if (request.UsernameToken != null)
            return (request.UsernameToken.Username, request.UsernameToken.Password);

        if (Request.Headers.TryGetValue("Authorization", out var header)
            && BasicAuthHeader.TryParse(header.ToString(), out var username, out var password))
        {
            return (username, password);
        }
        return null;
    }

    private ContentResult Fault(int status, string reason, string? relatesTo, string errorKind, bool senderFault = true)
    {
        MetricsService.ProtocolRequestsTotal.WithLabels(MsaeEnrollmentService.Protocol, "error").Inc();
        MetricsService.ProtocolErrorsTotal.WithLabels(MsaeEnrollmentService.Protocol, errorKind).Inc();
        return new ContentResult
        {
            StatusCode = status,
            ContentType = SoapContentType,
            Content = WstepMessages.BuildFault(reason, relatesTo, senderFault),
        };
    }
}
