using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Database;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// <c>MtlsChainValidator.ValidateAgainstCredentialCaAsync</c>, the entry point of mTLS sign-in and
/// step-up, for a credential whose signing CA is an issuing CA under a root: with a revocation
/// check required it must hand the validator the CA's stored issuers, or no such credential can
/// ever sign in, and it must go on refusing when the check finds a revocation or cannot be made.
/// </summary>
public sealed class MtlsChainValidatorIssuerPathTests
{
    private static Task<bool> ValidateAsync(ModularCADbContext db, Guid signingCaId, X509Certificate2 clientCert, bool requireRevocationCheck)
    {
        var method = ApiAssembly.TypeNamed("ModularCA.API.Services.MtlsChainValidator")
            .GetMethod("ValidateAgainstCredentialCaAsync", BindingFlags.Public | BindingFlags.Static)!;
        return (Task<bool>)method.Invoke(null, [db, signingCaId, clientCert, requireRevocationCheck, CancellationToken.None])!;
    }

    [Fact]
    public async Task A_client_certificate_of_an_issuing_CA_signs_in_with_revocation_required()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var (leaf, crlUrl) = pki.IssueClient();

        Assert.True(await ValidateAsync(db, pki.IssuingCaId, leaf, requireRevocationCheck: true));
        Assert.True(pki.Crls.RequestsFor(crlUrl) > 0, "the client certificate's CRL was never fetched, so its revocation was not checked");
    }

    [Fact]
    public async Task A_revoked_client_certificate_of_an_issuing_CA_does_not_sign_in()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var (leaf, _) = pki.IssueClient(revoked: true);

        Assert.False(await ValidateAsync(db, pki.IssuingCaId, leaf, requireRevocationCheck: true));
    }

    /// <summary>
    /// The issuing CA's root is not in the database, so there is no complete chain to check
    /// revocation on, and a required check that cannot be made is a refusal.
    /// </summary>
    [Fact]
    public async Task Without_the_root_stored_a_required_revocation_check_is_refused()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db, storeRoot: false);
        var (leaf, _) = pki.IssueClient();

        Assert.False(await ValidateAsync(db, pki.IssuingCaId, leaf, requireRevocationCheck: true));
        Assert.True(await ValidateAsync(db, pki.IssuingCaId, leaf, requireRevocationCheck: false));
    }

    [Fact]
    public async Task Without_a_revocation_requirement_issuance_alone_decides_and_nothing_is_fetched()
    {
        using var db = InMemoryDbContextFactory.Create();
        using var pki = new StoredIntermediateCa(db);
        var (leaf, crlUrl) = pki.IssueClient(revoked: true);
        using var stranger = TestCertificates.IssueLeaf(pki.Root, "CN=issued by the root and not by the issuing CA");

        Assert.True(await ValidateAsync(db, pki.IssuingCaId, leaf, requireRevocationCheck: false));
        Assert.False(await ValidateAsync(db, pki.IssuingCaId, stranger, requireRevocationCheck: false));
        Assert.False(await ValidateAsync(db, pki.IssuingCaId, stranger, requireRevocationCheck: true));
        Assert.Equal(0, pki.Crls.RequestsFor(crlUrl));
    }
}
