using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the MSAE branch of enrollment authorization: an enabled per-CA MSAE row, an authenticated
/// username, and that user's enrollment capability on the CA. Nothing else satisfies it.
/// </summary>
public class EnrollmentAuthorizationMsaeTests
{
    private sealed class RecordingAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public List<(string Username, Guid CaId)> Asked { get; } = [];

        public Task<bool> MayEnrollAsync(string username, Guid caId)
        {
            Asked.Add((username, caId));
            return Task.FromResult(verdict);
        }
    }

    private static (ModularCADbContext Db, CertificateAuthorityEntity Ca, EnrollmentAuthorizationService Service, RecordingAuthorizer Authorizer)
        Build(bool addRow, bool rowEnabled = true, bool member = true)
    {
        var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "lab", Label = "lab", IsDefault = true, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        if (addRow)
        {
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
            {
                Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "MSAE", IsEnabled = rowEnabled,
                SigningProfileId = Guid.NewGuid(), CertProfileId = Guid.NewGuid(),
            });
        }
        db.SaveChanges();

        var authorizer = new RecordingAuthorizer(member);
        var service = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), new CaResolverService(db), authorizer,
            NullLogger<EnrollmentAuthorizationService>.Instance);
        return (db, ca, service, authorizer);
    }

    [Fact]
    public async Task No_msae_row_means_the_protocol_is_off_for_that_ca()
    {
        var (_, _, service, authorizer) = Build(addRow: false);
        var (allowed, error) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: true, "svc-enroll");
        Assert.False(allowed);
        Assert.Contains("MSAE is not enabled", error);
        Assert.Empty(authorizer.Asked);
    }

    [Fact]
    public async Task A_disabled_row_refuses_without_consulting_membership()
    {
        var (_, _, service, authorizer) = Build(addRow: true, rowEnabled: false);
        var (allowed, _) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: true, "svc-enroll");
        Assert.False(allowed);
        Assert.Empty(authorizer.Asked);
    }

    [Fact]
    public async Task An_unauthenticated_caller_is_refused_even_with_a_username()
    {
        var (_, _, service, authorizer) = Build(addRow: true);
        var (allowed, error) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: false, "svc-enroll");
        Assert.False(allowed);
        Assert.Contains("authenticated username", error);
        Assert.Empty(authorizer.Asked);
    }

    [Fact]
    public async Task An_authenticated_but_nameless_caller_is_refused()
    {
        var (_, _, service, authorizer) = Build(addRow: true);
        var (allowed, _) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: true, callerUsername: "  ");
        Assert.False(allowed);
        Assert.Empty(authorizer.Asked);
    }

    [Fact]
    public async Task A_member_of_the_ca_is_allowed_and_the_check_names_that_ca()
    {
        var (_, ca, service, authorizer) = Build(addRow: true, member: true);
        var (allowed, error) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: true, "svc-enroll");
        Assert.True(allowed);
        Assert.Null(error);
        Assert.Equal([("svc-enroll", ca.Id)], authorizer.Asked);
    }

    [Fact]
    public async Task A_non_member_is_refused_by_name()
    {
        var (_, _, service, _) = Build(addRow: true, member: false);
        var (allowed, error) = await service.ValidateAsync("MSAE", "lab", null, null, isAuthenticated: true, "svc-enroll");
        Assert.False(allowed);
        Assert.Contains("svc-enroll", error);
        Assert.Contains("lab", error);
    }

    [Fact]
    public async Task A_label_less_request_is_judged_against_the_default_ca()
    {
        var (_, ca, service, authorizer) = Build(addRow: true);
        var (allowed, _) = await service.ValidateAsync("MSAE", null, null, null, isAuthenticated: true, "svc-enroll");
        Assert.True(allowed);
        Assert.Equal(ca.Id, authorizer.Asked.Single().CaId);
    }
}
