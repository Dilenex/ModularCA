using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Cmp;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Core.Services.Est;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// An enrollment the shared pipeline answers with <see cref="EnrollmentOutcome.Failed"/> (a CA with
/// no certificate profile to issue from, a configured profile row that is gone) is a fault the
/// pipeline does not audit; the protocol writes the row. SCEP did; EST and CMP answered their
/// protocol error and wrote nothing, so the failure was in the log and on no protocol tab.
/// </summary>
public class FailedEnrollmentAuditTests
{
    private const string FailureText = "No certificate profile available for this CA";

    /// <summary>A pipeline that fails every submission with <see cref="FailureText"/>, and says how often it ran.</summary>
    private sealed class FailingPipeline : IEnrollmentPipeline
    {
        public int Calls;

        public Task<EnrollmentOutcome> SubmitAsync(EnrollmentSubmission submission, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult<EnrollmentOutcome>(new EnrollmentOutcome.Failed(
                FailureText, Reason: EnrollmentFailureReason.NoCertificateProfileAvailable));
        }
    }

    /// <summary>Records every protocol audit row as (protocol, operation, success, error, subject).</summary>
    private sealed class RecordingAudit : IProtocolAuditService
    {
        public List<(string Protocol, string Operation, bool Success, string? Error, string? Subject, string? CaLabel)> Rows { get; } = [];

        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
        {
            Rows.Add(("EST", operation, success, errorMessage, subjectDN, caLabel));
            return Task.CompletedTask;
        }

        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
        {
            Rows.Add(("CMP", messageType, success, errorMessage, subjectDN, caLabel));
            return Task.CompletedTask;
        }

        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }

    /// <summary>A base64 PKCS#10 request for <paramref name="subject"/>, as an EST client posts it.</summary>
    private static string Base64Csr(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(request.CreateSigningRequest());
    }

    [Fact]
    public async Task An_EST_enrollment_the_pipeline_fails_is_audited_once_with_the_reason()
    {
        using var db = InMemoryDbContextFactory.Create();
        var audit = new RecordingAudit();
        var pipeline = new FailingPipeline();
        var service = new EstService(db, null!, null!, audit, null!, null!, pipeline, NullLogger<EstService>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.SimpleEnrollAsync(Base64Csr("CN=device-01.example.test"), "lab", "10.0.0.5"));

        Assert.Equal(1, pipeline.Calls);
        var row = Assert.Single(audit.Rows);
        Assert.Equal("EST", row.Protocol);
        Assert.Equal("EstEnrollRejected", row.Operation);
        Assert.False(row.Success);
        Assert.Equal(FailureText, row.Error);
        Assert.Equal("CN=device-01.example.test", row.Subject);
        Assert.Equal("lab", row.CaLabel);
    }

    [Fact]
    public async Task A_CMP_certification_request_the_pipeline_fails_is_audited_once_with_the_reason()
    {
        using var db = InMemoryDbContextFactory.Create();
        var audit = new RecordingAudit();
        var pipeline = new FailingPipeline();
        var service = new CmpService(db, null!, null!, null!, audit, pipeline, new EnrollmentTokenServiceStub(),
            NullLogger<CmpService>.Instance, InstanceCeremonyEndpointTests.Fake<ISigningService>.Create());

        using var key = RSA.Create(2048);
        var template = new CertTemplateBuilder()
            .SetSubject(new X509Name("CN=printer1,O=Acme"))
            .SetSubjectPublicKeyInfo(SubjectPublicKeyInfo.GetInstance(key.ExportSubjectPublicKeyInfo()))
            .Build();
        var context = new ResolvedCaContext
        {
            Ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Label = "lab", Name = "lab", SpaceId = Guid.NewGuid() },
            SigningProfileId = Guid.NewGuid(),
            CertProfileId = Guid.NewGuid(),
        };
        var reqCtx = new CmpService.CmpRequestContext
        {
            CaLabel = "lab",
            SourceIp = "10.0.0.5",
            Ca = context.Ca,
            TransactionIdHex = "AABBCCDD",
            ProtectionMode = CmpService.CmpProtectionMode.Signature,
            SignerSubjectDn = "CN=printer1,O=Acme",
        };

        var process = typeof(CmpService).GetMethod("ProcessSingleCertRequestAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var call = (Task)process.Invoke(service, [new CertRequest(1, template, null), context, reqCtx, null])!;
        await Assert.ThrowsAsync<InvalidOperationException>(() => call);

        Assert.Equal(1, pipeline.Calls);
        var row = Assert.Single(audit.Rows);
        Assert.Equal("CMP", row.Protocol);
        Assert.Equal("IRRejected", row.Operation);
        Assert.False(row.Success);
        Assert.Equal(FailureText, row.Error);
        Assert.Equal("CN=printer1,O=Acme", row.Subject);
        Assert.Equal("lab", row.CaLabel);
    }
}
