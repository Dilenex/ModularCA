using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers <see cref="EnrollmentTokenTarget.ResolveAsync"/>: the scope a creator chooses for a new
/// enrollment token becomes the CA and space it is stamped with, which
/// <see cref="EnrollmentTokenService.ScopeRefusal"/> then enforces, and a signing profile sent
/// alongside must issue from inside that scope.
/// </summary>
public class EnrollmentTokenTargetTests
{
    private sealed class World : IDisposable
    {
        public readonly ModularCADbContext Db = InMemoryDbContextFactory.Create();
        public readonly SpaceEntity Space = new() { Id = Guid.NewGuid(), Name = "Staging", Slug = "staging" };
        public readonly CertificateAuthorityEntity SpaceCa = new() { Id = Guid.NewGuid(), Name = "R3", Label = "r3", CertificateId = Guid.NewGuid() };
        public readonly CertificateAuthorityEntity OtherSpaceCa = new() { Id = Guid.NewGuid(), Name = "R1", Label = "r1", CertificateId = Guid.NewGuid() };
        public readonly CertificateAuthorityEntity InstanceCa = new() { Id = Guid.NewGuid(), Name = "Instance", Label = "inst", CertificateId = Guid.NewGuid() };
        public readonly CertificateAuthorityEntity SshCa = new() { Id = Guid.NewGuid(), Name = "SSH", Label = "ssh", IsSshCa = true };
        public readonly SigningProfileEntity SpaceProfile = new() { Id = Guid.NewGuid(), Name = "r3-signing" };
        public readonly SigningProfileEntity OtherProfile = new() { Id = Guid.NewGuid(), Name = "r1-signing" };
        public readonly SigningProfileEntity InstanceProfile = new() { Id = Guid.NewGuid(), Name = "inst-signing" };

        public World()
        {
            SpaceCa.SpaceId = Space.Id;
            OtherSpaceCa.SpaceId = Guid.NewGuid();
            SpaceProfile.IssuerId = SpaceCa.CertificateId;
            OtherProfile.IssuerId = OtherSpaceCa.CertificateId;
            InstanceProfile.IssuerId = InstanceCa.CertificateId;
            Db.Spaces.Add(Space);
            Db.CertificateAuthorities.AddRange(SpaceCa, OtherSpaceCa, InstanceCa, SshCa);
            Db.SigningProfiles.AddRange(SpaceProfile, OtherProfile, InstanceProfile);
            Db.SaveChanges();
        }

        public Task<EnrollmentTokenTarget> Resolve(EnrollmentTokenScope scope, Guid? scopeId, Guid? profileId = null)
            => EnrollmentTokenTarget.ResolveAsync(Db, scope, scopeId, profileId);

        public void Dispose() => Db.Dispose();
    }

    [Fact]
    public async Task A_ca_scope_binds_the_token_to_the_ca_and_its_space()
    {
        using var w = new World();
        var target = await w.Resolve(EnrollmentTokenScope.Ca, w.SpaceCa.Id);
        Assert.Equal(new EnrollmentTokenTarget(w.SpaceCa.Id, w.Space.Id), target);
        Assert.Null(EnrollmentTokenService.ScopeRefusal(Stamped(target), w.SpaceCa.Id, w.Space.Id));
        Assert.NotNull(EnrollmentTokenService.ScopeRefusal(Stamped(target), w.OtherSpaceCa.Id, w.Space.Id));
    }

    [Fact]
    public async Task A_space_scope_binds_the_token_to_the_space_alone()
    {
        using var w = new World();
        var target = await w.Resolve(EnrollmentTokenScope.Space, w.Space.Id, w.SpaceProfile.Id);
        Assert.Equal(new EnrollmentTokenTarget(null, w.Space.Id), target);
        Assert.Null(EnrollmentTokenService.ScopeRefusal(Stamped(target), Guid.NewGuid(), w.Space.Id));
    }

    [Fact]
    public async Task An_instance_scope_binds_to_nothing_and_takes_an_instance_cas_profile()
    {
        using var w = new World();
        var target = await w.Resolve(EnrollmentTokenScope.Instance, null, w.InstanceProfile.Id);
        Assert.Equal(new EnrollmentTokenTarget(null, null), target);
    }

    [Fact]
    public async Task A_signing_profile_from_outside_the_scope_is_refused()
    {
        using var w = new World();
        Assert.NotNull((await w.Resolve(EnrollmentTokenScope.Ca, w.SpaceCa.Id, w.OtherProfile.Id)).Error);
        Assert.NotNull((await w.Resolve(EnrollmentTokenScope.Space, w.Space.Id, w.OtherProfile.Id)).Error);
        Assert.NotNull((await w.Resolve(EnrollmentTokenScope.Instance, null, w.SpaceProfile.Id)).Error);
    }

    [Fact]
    public async Task A_scope_that_names_nothing_is_not_found()
    {
        using var w = new World();
        Assert.True((await w.Resolve(EnrollmentTokenScope.Ca, Guid.NewGuid())).NotFound);
        Assert.True((await w.Resolve(EnrollmentTokenScope.Ca, null)).NotFound);
        Assert.True((await w.Resolve(EnrollmentTokenScope.Ca, w.SshCa.Id)).NotFound);
        Assert.True((await w.Resolve(EnrollmentTokenScope.Space, Guid.NewGuid())).NotFound);
        Assert.True((await w.Resolve(EnrollmentTokenScope.Ca, w.SpaceCa.Id, Guid.NewGuid())).NotFound);
        Assert.NotNull((await w.Resolve(EnrollmentTokenScope.Instance, w.Space.Id)).Error);
    }

    private static EnrollmentTokenEntity Stamped(EnrollmentTokenTarget target)
        => new() { CertificateAuthorityId = target.CaId, SpaceId = target.SpaceId };
}
