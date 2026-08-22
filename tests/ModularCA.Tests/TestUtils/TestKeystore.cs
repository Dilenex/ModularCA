using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// In-memory <see cref="IKeystoreCertificates"/> holding whatever CAs a test hands it.
/// <para>
/// The real keystore reads signed, encrypted files off disk and unlocks them with a passphrase,
/// which is not something a unit test should stand up. What protocol responders actually need
/// from it is narrow: the list of signers and a private-key handle per signer.
/// </para>
/// </summary>
internal sealed class TestKeystore : IKeystoreCertificates
{
    private readonly List<CertificateAuthorityIdentity> _signers;

    public TestKeystore(params CertificateAuthorityIdentity[] signers)
        => _signers = signers.ToList();

    public List<X509Certificate> GetTrustedAuthorities()
        => _signers.Select(s => s.PublicCertificate).ToList();

    public List<CertificateAuthorityIdentity> GetSigners() => _signers;

    public IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert)
        => _signers.FirstOrDefault(s => s.PublicCertificate.SerialNumber.Equals(cert.SerialNumber)
                                     && s.PublicCertificate.SubjectDN.Equivalent(cert.SubjectDN))
                   ?.PrivateKeyHandle;
}

/// <summary>
/// Returns a fixed <see cref="SecurityPolicyEntity"/>. Tests that care about a specific switch —
/// RequireSignedRequests, RequireMtlsOcspCheck, the OCSP TTLs — construct one with that value set
/// rather than seeding a row and hoping the caching layer agrees.
/// </summary>
internal sealed class StubSecurityPolicyService : ISecurityPolicyService
{
    private readonly SecurityPolicyEntity _policy;

    public StubSecurityPolicyService(SecurityPolicyEntity? policy = null)
        => _policy = policy ?? new SecurityPolicyEntity();

    public Task<SecurityPolicyEntity> GetAsync() => Task.FromResult(_policy);

    public void InvalidateCache() { }
}
