using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Est;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// EST's proof that a presented client certificate was issued by the CA being enrolled against
/// (<c>EstService.VerifyPresentedCertificateAsync</c>, shared by enrollment and re-enrollment), for
/// an issuing CA under a root with the <c>RequireMtlsOcspCheck</c> policy on: the CA's stored
/// issuers have to reach the validator for the online check to be possible at all.
/// </summary>
public sealed class EstIntermediateRevocationTests
{
    /// <summary>Resolves every request to the one CA and signing profile it was built with.</summary>
    private sealed class FixedResolver(CertificateAuthorityEntity ca, Guid signingProfileId) : ICaResolverService
    {
        public Task<ResolvedCaContext> ResolveAsync(string? caLabel, string protocol)
            => Task.FromResult(new ResolvedCaContext { Ca = ca, SigningProfileId = signingProfileId });

        public Task<ResolvedCaContext> ResolveByTemplateAsync(string templateName) => throw new NotSupportedException();

        public Task<CertificateAuthorityEntity?> ResolveCaEntityAsync(string? caLabel) => throw new NotSupportedException();
    }

    /// <summary>
    /// Runs the verification and returns the reason it rejected with, or null when it accepted.
    /// </summary>
    private static async Task<string?> RejectionAsync(ModularCADbContext db, StoredIntermediateCa pki, X509Certificate2 clientCert, bool requireRevocationCheck)
    {
        var ca = db.CertificateAuthorities.Single(c => c.Id == pki.IssuingCaId);
        var policy = new StubSecurityPolicyService(new SecurityPolicyEntity { RequireMtlsOcspCheck = requireRevocationCheck });
        var service = new EstService(db, null!, new FixedResolver(ca, pki.SigningProfile.Id), null!, null!, policy, null!, NullLogger<EstService>.Instance);
        var verify = typeof(EstService).GetMethod("VerifyPresentedCertificateAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;

        Func<string, Task> reject = reason => throw new InvalidOperationException(reason);
        try
        {
            var verified = await (Task<Guid>)verify.Invoke(service, [clientCert, "lab", reject])!;
            Assert.Equal(pki.IssuingCertificateId, verified);
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    [Fact]
    public async Task A_certificate_of_an_issuing_CA_is_accepted_with_the_online_check_required()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var (leaf, crlUrl) = pki.IssueClient();

        Assert.Null(await RejectionAsync(db, pki, leaf, requireRevocationCheck: true));
        Assert.True(pki.Crls.RequestsFor(crlUrl) > 0, "the certificate's CRL was never fetched, so its revocation was not checked");
    }

    [Fact]
    public async Task A_certificate_its_CRL_lists_is_rejected_with_the_online_check_required()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var (leaf, _) = pki.IssueClient(revoked: true);

        Assert.Equal(
            "Client certificate does not chain to the CA being enrolled against.",
            await RejectionAsync(db, pki, leaf, requireRevocationCheck: true));
    }

    [Fact]
    public async Task Without_the_root_stored_the_required_online_check_is_refused()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db, storeRoot: false);
        var (leaf, _) = pki.IssueClient();

        Assert.Equal(
            "Client certificate does not chain to the CA being enrolled against.",
            await RejectionAsync(db, pki, leaf, requireRevocationCheck: true));
        Assert.Null(await RejectionAsync(db, pki, leaf, requireRevocationCheck: false));
    }
}
