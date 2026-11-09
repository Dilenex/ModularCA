using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A reissue that is refused leaves its predecessor in service. Every check that can refuse
/// (certificate profile limits, overrides, certificate policy, name constraints across the
/// chain) runs before anything changes; the predecessor is revoked as Superseded only after the
/// replacement has been issued and stored. These checks all used to run after the auto-revocation,
/// so a refusal left the old certificate revoked and no replacement.
/// </summary>
public sealed class ReissueRefusalOrderTests
{
    public enum Refusal { NameConstraint, SubjectOverrideUnparseable, SanOverrideType, ValidityBeyondProfile, CertificatePolicy }

    [Theory]
    [InlineData(Refusal.NameConstraint)]
    [InlineData(Refusal.SubjectOverrideUnparseable)]
    [InlineData(Refusal.SanOverrideType)]
    [InlineData(Refusal.ValidityBeyondProfile)]
    [InlineData(Refusal.CertificatePolicy)]
    public async Task A_refused_reissue_does_not_revoke_the_predecessor(Refusal refusal)
    {
        var (w, csrId, predecessorId) = await IssuedAsync();
        string? subject = null;
        List<string>? sans = null;
        DateTime? notAfter = null;
        switch (refusal)
        {
            case Refusal.NameConstraint: sans = ["DNS:host.other.test"]; break;
            case Refusal.SubjectOverrideUnparseable: subject = "not a distinguished name"; break;
            case Refusal.SanOverrideType: sans = ["FOO:bar"]; break;
            case Refusal.ValidityBeyondProfile: notAfter = DateTime.UtcNow.AddYears(20); break;
            case Refusal.CertificatePolicy: w.Policy.Violations.Add(new PolicyViolation { Rule = "Test", Message = "refused by policy" }); break;
        }

        var before = w.Db.Certificates.AsNoTracking().Count();
        var ex = await Record.ExceptionAsync(() => w.Issuance.ReissueCertificateAsync(null, null, csrId, null, notAfter, subject, sans));

        Assert.NotNull(ex);
        if (refusal == Refusal.NameConstraint)
            Assert.Equal(ErrorCodes.NameConstraintViolation, Assert.IsType<CertificatePolicyViolationException>(ex).Code);
        var predecessor = await w.Db.Certificates.AsNoTracking().SingleAsync(c => c.CertificateId == predecessorId);
        Assert.False(predecessor.Revoked, ex.Message);
        Assert.False(predecessor.IsReissued);
        Assert.Equal(before, w.Db.Certificates.AsNoTracking().Count());
    }

    [Fact]
    public async Task A_successful_reissue_revokes_the_predecessor_after_issuing_its_replacement()
    {
        var (w, csrId, predecessorId) = await IssuedAsync();

        var before = w.Db.Certificates.AsNoTracking().Count();
        var result = await w.Issuance.ReissueCertificateAsync(null, null, csrId, null, null, null, ["DNS:new.acme.test"]);

        Assert.Contains("BEGIN CERTIFICATE", result.Pem);
        var predecessor = await w.Db.Certificates.AsNoTracking().SingleAsync(c => c.CertificateId == predecessorId);
        Assert.True(predecessor.Revoked);
        Assert.Equal("Superseded", predecessor.RevocationReason);
        Assert.True(predecessor.IsReissued);
        Assert.Equal(before + 1, w.Db.Certificates.AsNoTracking().Count());
    }

    /// <summary>
    /// CLM-007 (bug hunt 2026-11, F3): an expired certificate revoked for key compromise is not
    /// reissued with the same key. The refusal used to be swallowed by a catch meant for other
    /// errors, and the CA signed a fresh certificate for the compromised key.
    /// </summary>
    [Theory]
    [InlineData("KeyCompromise")]
    [InlineData("CACompromise")]
    public async Task A_compromised_and_expired_certificate_is_not_reissued_with_its_key(string reason)
    {
        var (w, csrId, predecessorId) = await IssuedAsync();
        var predecessor = await w.Db.Certificates.SingleAsync(c => c.CertificateId == predecessorId);
        predecessor.Revoked = true;
        predecessor.RevocationReason = reason;
        predecessor.RevocationDate = DateTime.UtcNow.AddDays(-2);
        predecessor.NotAfter = DateTime.UtcNow.AddDays(-1);
        await w.Db.SaveChangesAsync();

        var before = w.Db.Certificates.AsNoTracking().Count();
        var ex = await Record.ExceptionAsync(() => w.Issuance.ReissueCertificateAsync(null, null, csrId, null, null, null, null));

        Assert.Equal(ErrorCodes.KeyReuseAfterCompromise, Assert.IsType<ConfigurationValidationException>(ex).Code);
        Assert.Equal(before, w.Db.Certificates.AsNoTracking().Count());
    }

    /// <summary>A compromise check that cannot compare the keys refuses rather than allows.</summary>
    [Fact]
    public async Task An_unreadable_compromised_certificate_counts_as_reused()
    {
        var (w, csrId, _) = await IssuedAsync();
        var pem = w.Db.CertificateRequests.AsNoTracking().Single(r => r.Id == csrId).CSR;
        var csr = new CsrParserService().ParseFromPem(pem);

        var reused = CertificateIssuanceService.ReusesCompromisedKey(
            new CertificateEntity { RawCertificate = [0x30, 0x01, 0x00] }, csr, out var error);

        Assert.True(reused);
        Assert.NotNull(error);
    }

    /// <summary>A CA permitted <c>.acme.test</c>, and a leaf issued under it, ready to reissue.</summary>
    private static async Task<(NameConstraintIssuanceTests.IssuanceWorld World, Guid CsrId, Guid PredecessorId)> IssuedAsync()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var ca = await w.CreateRootAsync("Reissue Root", "[\"DNS:.acme.test\"]", null);
        await w.IssueLeafAsync(ca, "CN=leaf", ["DNS:host.acme.test"]);
        var request = w.Db.CertificateRequests.AsNoTracking().Single(r => r.CertProfileId == w.LeafProfileId);
        return (w, request.Id, request.IssuedCertificateId!.Value);
    }
}
