using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Refusals two anonymous protocol endpoints answered and recorded nowhere: token (QR or link)
/// enrollment, and ACME revocation. Both controllers are driven by reflection, as the other
/// endpoint tests drive theirs.
/// </summary>
public sealed class ProtocolRefusalAuditEndpointTests
{
    private static async Task<IActionResult> InvokeAsync(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static object NullLoggerFor(Type type)
        => typeof(NullLogger<>).MakeGenericType(type).GetField("Instance")!.GetValue(null)!;

    // ---- token enrollment -------------------------------------------------------------------

    /// <summary>A token service that knows one token, by any value, and nothing else.</summary>
    public class OneToken : DispatchProxy
    {
        public EnrollmentTokenEntity? Token { get; set; }

        /// <summary>How many times the token was spent; spending is refused unless <see cref="Spendable"/>.</summary>
        public int Consumed { get; private set; }

        public bool Spendable { get; set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            switch (targetMethod!.Name)
            {
                case nameof(IEnrollmentTokenService.GetByTokenAsync):
                    return Task.FromResult(Token);
                case nameof(IEnrollmentTokenService.ValidateAndConsumeAsync) when Spendable:
                    Consumed++;
                    return Task.FromResult<(bool, string?)>((true, null));
                default:
                    throw new NotSupportedException(targetMethod.Name);
            }
        }
    }

    /// <summary>An issuance service whose every issuance is refused by certificate policy.</summary>
    public class PolicyRefusingIssuance : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var inner = targetMethod!.ReturnType.GetGenericArguments()[0];
            var refusal = new ModularCA.Shared.Errors.CertificatePolicyViolationException(
                ["[KeyAlgorithmPolicy] The subject key (RSA 1024) is not permitted by the system key policy."]);
            return typeof(Task).GetMethods().Single(m => m.Name == nameof(Task.FromException) && m.IsGenericMethod)
                .MakeGenericMethod(inner).Invoke(null, [refusal]);
        }
    }

    private static object EnrollmentController(EnrollmentTokenEntity? token, RecordingAuditService audit)
        => EnrollmentController(token, audit, InMemoryDbContextFactory.Create(), null, spendable: false, out _);

    private static object EnrollmentController(EnrollmentTokenEntity? token, RecordingAuditService audit,
        ModularCA.Database.ModularCADbContext db, ICertificateIssuanceService? issuance, bool spendable, out OneToken tokenProxy)
    {
        var tokens = DispatchProxy.Create<IEnrollmentTokenService, OneToken>();
        tokenProxy = (OneToken)(object)tokens;
        tokenProxy.Token = token;
        tokenProxy.Spendable = spendable;
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Public.PublicEnrollmentController"),
            tokens,
            issuance ?? InstanceCeremonyEndpointTests.Fake<ICertificateIssuanceService>.Create(),
            new RequestProfileValidationService(db, profiles),
            profiles,
            db,
            audit)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static object EnrollmentRequest(string csrPem)
    {
        var request = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Public.QrEnrollmentRequest"))!;
        request.GetType().GetProperty("CsrPem")!.SetValue(request, csrPem);
        return request;
    }

    private static string CsrPem(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
    }

    [Fact]
    public async Task An_unusable_token_is_refused_and_audited()
    {
        var audit = new RecordingAuditService();

        var result = await InvokeAsync(EnrollmentController(null, audit), "SubmitEnrollment",
            "no-such-token", EnrollmentRequest(CsrPem("CN=device")));

        Assert.IsType<BadRequestObjectResult>(result);
        var row = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.QrEnrollmentRejected, row.Action);
        Assert.Null(row.TargetId);
    }

    [Fact]
    public async Task A_subject_outside_the_tokens_restriction_is_refused_and_audited_against_the_token()
    {
        var audit = new RecordingAuditService();
        var token = new EnrollmentTokenEntity { Id = Guid.NewGuid(), SubjectRestriction = "O=Acme" };

        var result = await InvokeAsync(EnrollmentController(token, audit), "SubmitEnrollment",
            "the-token", EnrollmentRequest(CsrPem("CN=intruder, O=Other")));

        Assert.IsType<BadRequestObjectResult>(result);
        var row = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.QrEnrollmentRejected, row.Action);
        Assert.Equal(token.Id.ToString(), row.TargetId);
        Assert.Contains("Subject restriction", JsonSerializer.Serialize(row.Details));
    }

    [Fact]
    public async Task An_unreadable_csr_is_refused_and_audited()
    {
        var audit = new RecordingAuditService();
        var token = new EnrollmentTokenEntity { Id = Guid.NewGuid() };

        await InvokeAsync(EnrollmentController(token, audit), "SubmitEnrollment",
            "the-token", EnrollmentRequest("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----"));

        Assert.Contains("could not be parsed", JsonSerializer.Serialize(Assert.Single(audit.Entries).Details));
    }

    private static string RsaCsrPem(string subject, int bits)
    {
        using var key = RSA.Create(bits);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
    }

    /// <summary>
    /// A key outside the system key policy is refused with 400 and MCA-POL-000 before the token is
    /// spent. It used to spend the single-use token and then fail at issuance with a 500.
    /// </summary>
    [Fact]
    public async Task A_key_outside_the_system_policy_is_refused_before_the_token_is_spent()
    {
        var audit = new RecordingAuditService();
        var token = new EnrollmentTokenEntity { Id = Guid.NewGuid() };
        var controller = EnrollmentController(token, audit, InMemoryDbContextFactory.Create(), null, spendable: true, out var tokens);

        var result = await InvokeAsync(controller, "SubmitEnrollment", "the-token", EnrollmentRequest(RsaCsrPem("CN=device", 1024)));

        var refused = Assert.IsType<BadRequestObjectResult>(result);
        var body = JsonSerializer.Serialize(refused.Value);
        Assert.Contains("RSA 1024", body);
        Assert.Contains("MCA-POL-000", body);
        Assert.Equal(0, tokens.Consumed);
        var row = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.QrEnrollmentRejected, row.Action);
        Assert.Contains("RSA 1024", JsonSerializer.Serialize(row.Details));
    }

    /// <summary>
    /// The issuance-time check stays as the backstop, and its refusal is answered 400 with the
    /// policy code and audited as a rejection, where it was a 500 recorded as a failed completion.
    /// </summary>
    [Fact]
    public async Task A_certificate_policy_refusal_at_issuance_is_answered_400_and_audited_as_a_rejection()
    {
        var audit = new RecordingAuditService();
        var db = InMemoryDbContextFactory.Create();
        var caCertificateId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = caId, Name = "lab", Label = "lab", IsEnabled = true, CertificateId = caCertificateId, SpaceId = Guid.NewGuid(),
        });
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "lab-signing", IssuerId = caCertificateId };
        var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "lab-device", ValidityPeriodMax = "P30D" };
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        await db.SaveChangesAsync();
        var token = new EnrollmentTokenEntity
        {
            Id = Guid.NewGuid(), SigningProfileId = signing.Id, CertProfileId = certProfile.Id, CertificateAuthorityId = caId,
        };
        var controller = EnrollmentController(token, audit, db,
            DispatchProxy.Create<ICertificateIssuanceService, PolicyRefusingIssuance>(), spendable: true, out _);

        var result = await InvokeAsync(controller, "SubmitEnrollment", "the-token", EnrollmentRequest(CsrPem("CN=device")));

        var refused = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("MCA-POL-000", JsonSerializer.Serialize(refused.Value));
        var row = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.QrEnrollmentRejected, row.Action);
        Assert.Contains("KeyAlgorithmPolicy", JsonSerializer.Serialize(row.Details));
    }

    // ---- ACME revocation -------------------------------------------------------------------

    /// <summary>Records ACME rows only.</summary>
    private sealed class AcmeAudit : IProtocolAuditService
    {
        public List<(string Operation, bool Success, string? Error, string? Serial, Guid? CaId)> Entries { get; } = [];

        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
        {
            Entries.Add((operation, success, errorMessage, certSerial, certificateAuthorityId));
            return Task.CompletedTask;
        }

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }

    /// <summary>An order service that names one owner for every certificate serial.</summary>
    public class SerialOwner : DispatchProxy
    {
        public Guid? Owner { get; set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => targetMethod!.Name == nameof(IAcmeOrderService.GetAccountIdForCertificateSerialAsync)
                ? Task.FromResult(Owner)
                : throw new NotSupportedException(targetMethod.Name);
    }

    private static (object Controller, AcmeAudit Audit, CertificateAuthorityEntity Ca) RevokeController(
        Guid? owner, Guid account, int? reason)
    {
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Acme.AcmeOrderController");
        var orders = DispatchProxy.Create<IAcmeOrderService, SerialOwner>();
        ((SerialOwner)(object)orders).Owner = owner;
        var audit = new AcmeAudit();
        var controller = (ControllerBase)Activator.CreateInstance(type,
            orders,
            InstanceCeremonyEndpointTests.Fake<IAcmeAuthorizationService>.Create(),
            InstanceCeremonyEndpointTests.Fake<ICertificateRevocationService>.Create(),
            audit,
            InstanceCeremonyEndpointTests.Fake<IAcmeAccountRateLimiter>.Create(),
            new RecordingAuditService(),
            NullLoggerFor(type),
            new SystemConfig(),
            InMemoryDbContextFactory.Create())!;

        using var cert = TestCertificates.CreateCa("CN=revoke-me.example.test");
        var payload = JsonSerializer.Serialize(new
        {
            certificate = Convert.ToBase64String(cert.RawData).Replace('+', '-').Replace('/', '_').TrimEnd('='),
            reason,
        });
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "prod", Label = "prod", SpaceId = Guid.NewGuid() };
        var http = new DefaultHttpContext();
        http.Items["AcmeJws"] = new AcmeJwsPayload { Payload = payload, AccountId = account };
        http.Items["AcmeCa"] = ca;
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        return (controller, audit, ca);
    }

    [Fact]
    public async Task A_revocation_of_a_certificate_not_issued_over_acme_is_refused_and_audited()
    {
        var (controller, audit, ca) = RevokeController(owner: null, account: Guid.NewGuid(), reason: 1);

        var result = await InvokeAsync(controller, "RevokeCert");

        Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
        var row = Assert.Single(audit.Entries);
        Assert.Equal("RevokeRefused", row.Operation);
        Assert.False(row.Success);
        Assert.Equal(ca.Id, row.CaId);
        Assert.NotNull(row.Serial);
    }

    [Fact]
    public async Task A_revocation_of_another_accounts_certificate_is_refused_and_audited()
    {
        var (controller, audit, _) = RevokeController(owner: Guid.NewGuid(), account: Guid.NewGuid(), reason: 1);

        await InvokeAsync(controller, "RevokeCert");

        Assert.Contains("Account did not issue", Assert.Single(audit.Entries).Error);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(42)]
    public async Task A_reason_the_account_may_not_set_is_refused_and_audited(int reason)
    {
        var account = Guid.NewGuid();
        var (controller, audit, _) = RevokeController(owner: account, account: account, reason: reason);

        await InvokeAsync(controller, "RevokeCert");

        var row = Assert.Single(audit.Entries);
        Assert.Equal("RevokeRefused", row.Operation);
        Assert.Contains("reason", row.Error, StringComparison.OrdinalIgnoreCase);
    }
}
