using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Nothing is issued from a retired certificate: issuance refuses a request that renews one,
/// whatever created the request, and a reissue of one, with <see cref="ErrorCodes.CertificateRetired"/>.
/// A certificate whose expiry warning was only dismissed renews as before.
/// </summary>
public sealed class RetiredCertificateIssuanceTests
{
    [Fact]
    public async Task A_retired_certificate_is_not_reissued()
    {
        var (w, csrId, issuedId) = await IssuedAsync();
        await MarkAsync(w, issuedId, c => c.RetiredAt = DateTime.UtcNow);

        var ex = await Assert.ThrowsAsync<ResourceConflictException>(
            () => w.Issuance.ReissueCertificateAsync(null, null, csrId, null, null));

        Assert.Equal(ErrorCodes.CertificateRetired, ex.Code);
        Assert.False((await w.Db.Certificates.AsNoTracking().SingleAsync(c => c.CertificateId == issuedId)).IsReissued);
    }

    [Fact]
    public async Task A_request_renewing_a_retired_certificate_is_not_issued()
    {
        var (w, csrId, issuedId) = await IssuedAsync();
        await MarkAsync(w, issuedId, c => c.RetiredAt = DateTime.UtcNow);
        var renewalId = await RenewalRequestAsync(w, csrId, issuedId);

        var before = w.Db.Certificates.AsNoTracking().Count();
        var ex = await Assert.ThrowsAsync<ResourceConflictException>(
            () => w.Issuance.IssueCertificateAsync(renewalId, null, DateTime.UtcNow.AddDays(30)));

        Assert.Equal(ErrorCodes.CertificateRetired, ex.Code);
        Assert.Equal(before, w.Db.Certificates.AsNoTracking().Count());
    }

    [Fact]
    public async Task A_certificate_whose_warning_was_dismissed_still_renews()
    {
        var (w, csrId, issuedId) = await IssuedAsync();
        await MarkAsync(w, issuedId, c => c.ExpiryWarningDismissedAt = DateTime.UtcNow);
        var renewalId = await RenewalRequestAsync(w, csrId, issuedId);

        var result = await w.Issuance.IssueCertificateAsync(renewalId, null, DateTime.UtcNow.AddDays(30));

        Assert.Contains("BEGIN CERTIFICATE", result.Pem);
    }

    private static async Task<(NameConstraintIssuanceTests.IssuanceWorld World, Guid CsrId, Guid IssuedId)> IssuedAsync()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var ca = await w.CreateRootAsync("Retire Root", null, null);
        await w.IssueLeafAsync(ca, "CN=leaf", ["DNS:host.acme.test"]);
        var request = w.Db.CertificateRequests.AsNoTracking().Single(r => r.CertProfileId == w.LeafProfileId);
        return (w, request.Id, request.IssuedCertificateId!.Value);
    }

    private static async Task MarkAsync(NameConstraintIssuanceTests.IssuanceWorld w, Guid certificateId, Action<CertificateEntity> mark)
    {
        var cert = await w.Db.Certificates.SingleAsync(c => c.CertificateId == certificateId);
        mark(cert);
        await w.Db.SaveChangesAsync();
    }

    /// <summary>A copy of the original request that renews <paramref name="renewedId"/>, as auto-renewal or the console writes one.</summary>
    private static async Task<Guid> RenewalRequestAsync(NameConstraintIssuanceTests.IssuanceWorld w, Guid originalId, Guid renewedId)
    {
        var original = await w.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == originalId);
        var renewal = new CertRequestEntity
        {
            Id = Guid.NewGuid(), CSR = original.CSR, Subject = original.Subject, SubjectAlternativeNames = original.SubjectAlternativeNames,
            Status = "Approved", KeyAlgorithm = original.KeyAlgorithm, KeySize = original.KeySize, SignatureAlgorithm = original.SignatureAlgorithm,
            CertProfileId = original.CertProfileId, SigningProfileId = original.SigningProfileId, RenewalOfCertificateId = renewedId,
        };
        w.Db.CertificateRequests.Add(renewal);
        await w.Db.SaveChangesAsync();
        return renewal.Id;
    }
}
