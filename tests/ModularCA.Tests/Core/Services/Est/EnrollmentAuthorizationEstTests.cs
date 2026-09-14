using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Est;

/// <summary>
/// Pins which CA's policy an EST request is judged against, and what "HTTP authenticated" has to
/// mean before it satisfies that policy.
/// </summary>
/// <remarks>
/// <para>
/// Two defects lived here. The service selected a protocol row by <c>FirstOrDefault</c> over
/// every CA's rows with no ordering and no enabled filter, so a label-less request could be
/// judged by a disabled lab CA's "Basic is enough" policy while the default production CA, which
/// required a client certificate, did the issuing. And the HTTP-auth branch checked only
/// <c>isAuthenticated</c>, which the bearer scheme sets for every valid session token: any user in
/// any tenant could enroll at any EST-enabled CA.
/// </para>
/// </remarks>
public class EnrollmentAuthorizationEstTests
{
    /// <summary>Answers membership questions with a fixed verdict and remembers what was asked.</summary>
    private sealed class RecordingAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public List<(string Username, Guid CaId)> Asked { get; } = [];

        public Task<bool> MayEnrollAsync(string username, Guid caId)
        {
            Asked.Add((username, caId));
            return Task.FromResult(verdict);
        }
    }

    private static CertificateAuthorityEntity AddCa(ModularCADbContext db, string label, bool isDefault = false, bool enabled = true)
    {
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label, Label = label, IsDefault = isDefault, IsEnabled = enabled };
        db.CertificateAuthorities.Add(ca);
        return ca;
    }

    private static void AddEst(ModularCADbContext db, CertificateAuthorityEntity ca,
        bool requireCert, bool httpAuth, bool enabled = true)
    {
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(),
            CaId = ca.Id,
            Protocol = "EST",
            IsEnabled = enabled,
            EstRequireClientCert = requireCert,
            EstHttpAuthEnabled = httpAuth,
        });
    }

    private static (EnrollmentAuthorizationService Service, RecordingAuthorizer Authorizer) Build(
        ModularCADbContext db, bool memberVerdict)
    {
        var authorizer = new RecordingAuthorizer(memberVerdict);
        var service = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), new CaResolverService(db), authorizer,
            NullLogger<EnrollmentAuthorizationService>.Instance);
        return (service, authorizer);
    }

    [Fact]
    public async Task A_label_less_request_is_judged_by_the_default_CA_not_whichever_row_comes_first()
    {
        using var db = InMemoryDbContextFactory.Create();
        // Seeded first so a naive FirstOrDefault would land on it.
        var lab = AddCa(db, "lab");
        AddEst(db, lab, requireCert: false, httpAuth: true);
        var prod = AddCa(db, "prod", isDefault: true);
        AddEst(db, prod, requireCert: true, httpAuth: false);
        db.SaveChanges();

        var (service, _) = Build(db, memberVerdict: true);

        // Basic-authenticated, no client certificate. Under the lab row this passes; under the
        // production row, which is the CA that will actually issue, it must not.
        var (allowed, error) = await service.ValidateAsync("EST", null, null, null, isAuthenticated: true, callerUsername: "bob");

        Assert.False(allowed);
        Assert.Contains("client certificate", error);
    }

    [Fact]
    public async Task A_disabled_EST_row_refuses_rather_than_lending_its_policy()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = AddCa(db, "prod", isDefault: true);
        AddEst(db, ca, requireCert: false, httpAuth: true, enabled: false);
        db.SaveChanges();

        var (service, _) = Build(db, memberVerdict: true);
        var (allowed, error) = await service.ValidateAsync("EST", "prod", null, null, true, "bob");

        Assert.False(allowed);
        Assert.Contains("not enabled", error);
    }

    [Fact]
    public async Task HTTP_authentication_is_satisfied_only_by_an_account_entitled_on_that_CA()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = AddCa(db, "prod");
        AddEst(db, ca, requireCert: false, httpAuth: true);
        db.SaveChanges();

        var (denied, deniedAuthorizer) = Build(db, memberVerdict: false);
        var (allowed, error) = await denied.ValidateAsync("EST", "prod", null, null, true, "bob");
        Assert.False(allowed);
        Assert.Contains("not entitled", error);

        // The question must be asked about the CA that was resolved, not about nothing.
        var asked = Assert.Single(deniedAuthorizer.Asked);
        Assert.Equal("bob", asked.Username);
        Assert.Equal(ca.Id, asked.CaId);

        var (granted, _) = Build(db, memberVerdict: true);
        var (ok, _) = await granted.ValidateAsync("EST", "prod", null, null, true, "bob");
        Assert.True(ok);
    }

    [Fact]
    public async Task An_authenticated_caller_with_no_username_is_refused()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = AddCa(db, "prod");
        AddEst(db, ca, requireCert: false, httpAuth: true);
        db.SaveChanges();

        // The shape of a mis-wired scheme: IsAuthenticated is true and nothing says who. There is
        // no membership to check, so this must fail rather than fall through as "authenticated".
        var (service, authorizer) = Build(db, memberVerdict: true);
        var (allowed, _) = await service.ValidateAsync("EST", "prod", null, null, true, callerUsername: null);

        Assert.False(allowed);
        Assert.Empty(authorizer.Asked);
    }

    [Fact]
    public async Task An_unauthenticated_caller_gets_the_plain_HTTP_auth_message_not_the_entitlement_one()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = AddCa(db, "prod");
        AddEst(db, ca, requireCert: false, httpAuth: true);
        db.SaveChanges();

        var (service, _) = Build(db, memberVerdict: true);
        var (allowed, error) = await service.ValidateAsync("EST", "prod", null, null, isAuthenticated: false);

        Assert.False(allowed);
        Assert.Contains("requires HTTP authentication", error);
    }

    [Fact]
    public async Task When_both_are_required_a_certificate_and_an_entitled_account_are_both_needed()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = AddCa(db, "prod");
        AddEst(db, ca, requireCert: true, httpAuth: true);
        db.SaveChanges();
        using var estCa = TestCertificates.CreateCa("CN=EST CA");
        using var device = TestCertificates.IssueLeaf(estCa, "CN=device");

        var (notMember, _) = Build(db, memberVerdict: false);
        var (a, _) = await notMember.ValidateAsync("EST", "prod", null, device, true, "bob");
        Assert.False(a);

        var (member, _) = Build(db, memberVerdict: true);
        var (b, _) = await member.ValidateAsync("EST", "prod", null, null, true, "bob");
        Assert.False(b);
        var (c, _) = await member.ValidateAsync("EST", "prod", null, device, true, "bob");
        Assert.True(c);
    }

    [Fact]
    public async Task An_unknown_label_is_refused_by_name()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (service, _) = Build(db, memberVerdict: true);

        var (allowed, error) = await service.ValidateAsync("EST", "nope", null, null, true, "bob");

        Assert.False(allowed);
        Assert.Contains("nope", error);
    }
}
