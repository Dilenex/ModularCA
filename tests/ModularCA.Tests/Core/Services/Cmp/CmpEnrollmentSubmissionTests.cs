using System.Security.Cryptography;
using ModularCA.Core.Services.Cmp;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Pins the two pieces CMP kept for itself when its issuing middle moved behind the enrollment
/// pipeline: the binding of the requested names to the credential that carried the message, and
/// the reading of the window the CertTemplate asked for.
/// </summary>
/// <remarks>
/// Both were reachable before only by driving a whole PKIMessage through the service, which is why
/// neither had a test of its own while the rules they carry are the ones that stop a shared secret
/// enrolling the CA's own service names. Moving the middle out left them small enough to call
/// directly, and the credential binding in particular now runs from the pipeline's
/// post-authorization hook rather than from the middle of a method, so what it refuses is worth
/// stating separately from what the middle refuses.
/// </remarks>
public class CmpEnrollmentSubmissionTests
{
    private const string DeviceDn = "CN=printer1,O=Acme,C=US";

    /// <summary>A request as the CertTemplate reading produces one.</summary>
    private static EnrollmentRequestMaterial Request(string subject, params string[] sans)
        => new() { Subject = subject, SubjectAlternativeNames = sans };

    /// <summary>A PBMAC-protected exchange whose credential carries the given restrictions.</summary>
    private static CmpService.CmpRequestContext PbMac(string? subjectRestriction, string? sanRestriction)
        => new()
        {
            ProtectionMode = CmpService.CmpProtectionMode.PbMac,
            PbmToken = new EnrollmentTokenEntity
            {
                SubjectRestriction = subjectRestriction,
                SANRestriction = sanRestriction,
            },
        };

    /// <summary>A signature-protected exchange whose signer holds the given subject and SANs.</summary>
    private static CmpService.CmpRequestContext Signed(
        string signerSubject, params string[] signerSans)
        => new()
        {
            CaLabel = "lab",
            SourceIp = "10.0.0.5",
            ProtectionMode = CmpService.CmpProtectionMode.Signature,
            SignerSubjectDn = signerSubject,
            SignerSans = [.. signerSans],
        };

    // ── PBMAC shared-secret credentials ──────────────────────────────────────

    [Fact]
    public void A_shared_secret_may_enroll_the_subject_it_is_scoped_to()
    {
        CmpService.BindNamesToCredential(Request(DeviceDn), PbMac("O=Acme", null));
    }

    [Fact]
    public void A_shared_secret_may_not_enroll_a_subject_outside_its_scope()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CmpService.BindNamesToCredential(Request("CN=ca-admin,O=Other Corp,C=US"), PbMac("O=Acme", null)));
        Assert.Contains("Subject not permitted for this CMP credential", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_shared_secret_may_not_enroll_a_san_outside_its_scope()
    {
        // The case that made this rule: a credential issued to enroll one device naming the CA's
        // own front-end in its alternative names, which the subject check alone never saw.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CmpService.BindNamesToCredential(
                Request(DeviceDn, "DNS:printer1.devices.example.com", "DNS:ca.example.com"),
                PbMac(null, "devices.example.com")));
        Assert.Contains("SAN not permitted for this CMP credential", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_shared_secret_may_enroll_alternative_names_inside_its_scope()
    {
        CmpService.BindNamesToCredential(
            Request(DeviceDn, "DNS:printer1.devices.example.com"),
            PbMac(null, "devices.example.com"));
    }

    // ── Signature-protected requests ─────────────────────────────────────────

    [Fact]
    public void A_signature_protected_request_may_name_its_signer()
    {
        CmpService.BindNamesToCredential(
            Request(DeviceDn, "DNS:printer1.devices.example.com"),
            Signed(DeviceDn, "DNS:printer1.devices.example.com"));
    }

    [Fact]
    public void A_signature_protected_request_may_not_name_another_subject()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CmpService.BindNamesToCredential(Request("CN=ca-admin,O=Acme,C=US"), Signed(DeviceDn)));
        Assert.Contains("Request not permitted for this signing certificate", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_signature_protected_request_may_not_ask_for_a_san_its_signer_does_not_hold()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CmpService.BindNamesToCredential(
                Request(DeviceDn, "DNS:ca.example.com"),
                Signed(DeviceDn, "DNS:printer1.devices.example.com")));
        Assert.Contains("is not held by the signing certificate", ex.Message, StringComparison.Ordinal);
    }

    // ── The window the CertTemplate asks for ─────────────────────────────────

    /// <summary>A CertTemplate carrying the given OptionalValidity, or none at all.</summary>
    private static CertTemplate Template(DateTime? notBefore, DateTime? notAfter)
    {
        var builder = new CertTemplateBuilder();
        if (notBefore != null || notAfter != null)
        {
            builder.SetValidity(new OptionalValidity(
                notBefore == null ? null : new Time(notBefore.Value),
                notAfter == null ? null : new Time(notAfter.Value)));
        }
        return builder.Build();
    }

    [Fact]
    public void A_template_with_no_validity_asks_for_nothing_and_takes_the_defaults()
    {
        var (notBefore, notAfter) = CmpService.RequestedWindow(Template(null, null), out var raised);

        Assert.Null(notBefore);
        Assert.Null(notAfter);
        Assert.False(raised);
    }

    [Fact]
    public void Both_ends_of_a_requested_window_are_read_from_the_template()
    {
        var start = DateTime.UtcNow.AddDays(2);
        var end = start.AddDays(5);

        var (notBefore, notAfter) = CmpService.RequestedWindow(Template(start, end), out var raised);

        // Seconds, because a Time is encoded to second precision on the wire.
        Assert.Equal(start, notBefore!.Value, TimeSpan.FromSeconds(1));
        Assert.Equal(end, notAfter!.Value, TimeSpan.FromSeconds(1));
        Assert.False(raised);
    }

    [Fact]
    public void An_expiry_alone_is_read_without_inventing_a_start()
    {
        var end = DateTime.UtcNow.AddDays(5);

        var (notBefore, notAfter) = CmpService.RequestedWindow(Template(null, end), out var raised);

        Assert.Null(notBefore);
        Assert.Equal(end, notAfter!.Value, TimeSpan.FromSeconds(1));
        Assert.False(raised);
    }

    /// <summary>
    /// A start in the past is reported as one the middle will raise, which is what the operator
    /// sees in the log. The raising itself belongs to the middle, so what is asserted here is that
    /// CMP notices, not that it clamps.
    /// </summary>
    [Fact]
    public void A_start_in_the_past_is_reported_as_one_that_will_be_raised()
    {
        var backdated = DateTime.UtcNow.AddYears(-3);

        var (notBefore, _) = CmpService.RequestedWindow(Template(backdated, DateTime.UtcNow.AddDays(5)), out var raised);

        Assert.True(raised);
        // Read as asked: the floor is the middle's to apply, and it applies the same one.
        Assert.Equal(backdated, notBefore!.Value, TimeSpan.FromSeconds(1));
        Assert.True(CertificateValidityUtil.ClampRequestedNotBefore(notBefore, out _) > backdated);
    }

    // ── The submission CMP hands the shared middle ───────────────────────────

    /// <summary>A CertRequest whose template carries a subject, a SAN, a real key and a window.</summary>
    private static CertRequest CertRequestFor(DateTime? notBefore = null, DateTime? notAfter = null)
    {
        using var key = RSA.Create(2048);
        var spki = SubjectPublicKeyInfo.GetInstance(key.ExportSubjectPublicKeyInfo());

        var builder = new CertTemplateBuilder()
            .SetSubject(new X509Name(DeviceDn))
            .SetPublicKey(spki)
            .SetExtensions(new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>
            {
                [X509Extensions.SubjectAlternativeName] = new X509Extension(
                    DerBoolean.False,
                    new DerOctetString(new GeneralNames(
                        new GeneralName(GeneralName.DnsName, "printer1.devices.example.com")))),
            }));

        if (notBefore != null || notAfter != null)
        {
            builder.SetValidity(new OptionalValidity(
                notBefore == null ? null : new Time(notBefore.Value),
                notAfter == null ? null : new Time(notAfter.Value)));
        }

        return new CertRequest(1, builder.Build(), null);
    }

    /// <summary>The CA and profiles a CMP exchange resolves before it dispatches.</summary>
    private static ResolvedCaContext Context() => new()
    {
        Ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Label = "lab", Name = "lab" },
        SigningProfileId = Guid.NewGuid(),
        CertProfileId = Guid.NewGuid(),
    };

    /// <summary>
    /// The submission says it is CMP, addresses the CA the route named, carries the transactionID
    /// as its correlation, hands the middle the CA and profiles this exchange already resolved,
    /// and asks for the clamp CMP has always applied to an over-long OptionalValidity.
    /// </summary>
    [Fact]
    public void The_submission_carries_what_the_exchange_already_settled()
    {
        var context = Context();
        var reqCtx = Signed(DeviceDn, "DNS:printer1.devices.example.com");
        reqCtx.TransactionIdHex = "AABBCCDD";

        var submission = CmpService.BuildSubmission(CertRequestFor(), context, reqCtx, null, out _);

        Assert.Equal("CMP", submission.Protocol);
        Assert.Equal("lab", submission.CaLabel);
        Assert.Equal("10.0.0.5", submission.SourceIp);
        Assert.Equal("AABBCCDD", submission.Correlation);
        Assert.Same(context, submission.ResolvedContext);
        Assert.True(submission.ClampRequestedNotAfterToProfileMax,
            "An over-long OptionalValidity would be refused by issuance instead of shortened.");
    }

    /// <summary>
    /// The CertTemplate's subject, alternative names and public key are what the request row is
    /// written from, and the key stands in for the PKCS#10 CMP never carries.
    /// </summary>
    [Fact]
    public void The_certificate_template_is_what_the_request_is_built_from()
    {
        var reqCtx = Signed(DeviceDn, "DNS:printer1.devices.example.com");

        var submission = CmpService.BuildSubmission(CertRequestFor(), Context(), reqCtx, null, out _);

        Assert.Equal(DeviceDn, submission.Request.Subject);
        Assert.Equal(["DNS:printer1.devices.example.com"], submission.Request.SubjectAlternativeNames);
        Assert.Equal("RSA", submission.Request.KeyAlgorithm);
        Assert.Equal("2048", submission.Request.KeySize);
        Assert.NotNull(submission.Request.CsrPem);
        Assert.StartsWith("-----CMP-PUBKEY-----", submission.Request.CsrPem, StringComparison.Ordinal);
    }

    /// <summary>
    /// The window the client named reaches the middle as the client named it. The floor under the
    /// start and the ceiling of the profile's maximum are the middle's to apply.
    /// </summary>
    [Fact]
    public void A_window_the_client_named_reaches_the_middle()
    {
        var start = DateTime.UtcNow.AddDays(2);
        var end = start.AddYears(10);
        var reqCtx = Signed(DeviceDn, "DNS:printer1.devices.example.com");

        var submission = CmpService.BuildSubmission(CertRequestFor(start, end), Context(), reqCtx, null, out _);

        Assert.Equal(start, submission.RequestedNotBefore!.Value, TimeSpan.FromSeconds(1));
        Assert.Equal(end, submission.RequestedNotAfter!.Value, TimeSpan.FromSeconds(1));
    }

    /// <summary>
    /// Each kind of protection names the credential it is, and either counts as verified: an
    /// unprotected PKIMessage is refused before anything is dispatched, so a caller that reaches
    /// here has proven itself one way or the other.
    /// </summary>
    [Fact]
    public void The_protection_that_carried_the_message_names_the_caller()
    {
        var signed = CmpService.BuildSubmission(
            CertRequestFor(), Context(), Signed(DeviceDn, "DNS:printer1.devices.example.com"), null, out _);
        Assert.Equal(EnrollmentAuthMethod.MessageSignature, signed.Caller.AuthMethod);
        Assert.True(signed.Caller.IsVerified);

        var pbmac = PbMac(null, null);
        pbmac.CallerPrincipal = "cmp-pbmac:printer-fleet";
        var shared = CmpService.BuildSubmission(CertRequestFor(), Context(), pbmac, null, out _);
        Assert.Equal(EnrollmentAuthMethod.SharedSecret, shared.Caller.AuthMethod);
        Assert.True(shared.Caller.IsVerified);
        Assert.Equal("cmp-pbmac:printer-fleet", shared.Caller.Principal);
    }

    /// <summary>
    /// A key update's renewal evidence reaches the middle, which is what links the new request row
    /// to the certificate being replaced.
    /// </summary>
    [Fact]
    public void A_key_updates_renewal_evidence_reaches_the_middle()
    {
        var renewed = Guid.NewGuid();
        var reqCtx = Signed(DeviceDn, "DNS:printer1.devices.example.com");

        var submission = CmpService.BuildSubmission(
            CertRequestFor(), Context(), reqCtx, new EnrollmentRenewal(renewed, "0A1B2C"), out _);

        Assert.Equal(renewed, submission.Renewal!.RenewedCertificateId);
        Assert.Equal("0A1B2C", submission.Renewal.SerialNumber);
        Assert.True(submission.Renewal.ProvenByHolderOfKey,
            "The protection signature is what proves the holder of the old key made the request.");
    }

    /// <summary>
    /// The post-authorization hook the submission carries is the credential binding, so the
    /// middle cannot run a CMP request without holding its names to what the credential vouches
    /// for.
    /// </summary>
    [Fact]
    public async Task The_submission_carries_the_credential_binding_as_its_post_authorization_check()
    {
        var reqCtx = Signed("CN=someone-else,O=Acme,C=US");

        var submission = CmpService.BuildSubmission(CertRequestFor(), Context(), reqCtx, null, out _);

        Assert.NotNull(submission.AfterAuthorization);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            submission.AfterAuthorization!(new EnrollmentAuthorizedRequest(submission.Request, null)));
        Assert.Contains("Request not permitted for this signing certificate", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Only a key update renews. An initialization and a certification request each ask for a new
    /// certificate and name none they replace, so neither carries renewal evidence into the middle
    /// however the message was protected.
    /// </summary>
    /// <remarks>
    /// The distinction matters beyond the request row it links: a renewal the middle records is
    /// what stops the renewal job queueing a second replacement for a certificate the client has
    /// already replaced itself. Treating an <c>ir</c> as a renewal would link every bootstrap
    /// request to whichever certificate happened to sign it.
    /// </remarks>
    [Theory]
    [InlineData(1, false)]   // ip  — initialization response
    [InlineData(3, false)]   // cp  — certification response
    [InlineData(8, true)]    // kup — key update response
    public void Only_a_key_update_renews(int responseType, bool renews)
    {
        Assert.Equal(renews, CmpService.RenewsExistingCertificate(responseType));
    }
}
