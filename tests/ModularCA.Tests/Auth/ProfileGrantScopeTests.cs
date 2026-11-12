using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Who may use and see a profile. Three kinds of grant count: one naming the profile, one naming
/// the profile type with no id, and an unrestricted <c>profile.*</c> capability (as the built-in
/// roles give) held at a scope that covers the profile: its CA, its space, or anywhere for a
/// profile bound to neither. The third kind used to be ignored, so only a system administrator
/// could issue or approve. It must never reach past the scope it is held in.
/// </summary>
public sealed class ProfileGrantScopeTests
{
    private sealed class World
    {
        public ControlledUserWorld W { get; } = new();
        public Guid CertUnbound { get; } = Guid.NewGuid();
        public Guid CertOfA1 { get; } = Guid.NewGuid();
        public Guid CertOfB1 { get; } = Guid.NewGuid();
        public Guid CertOfSpaceA { get; } = Guid.NewGuid();
        public Guid SigningOfA1 { get; } = Guid.NewGuid();
        public Guid SigningOfA2 { get; } = Guid.NewGuid();
        public Guid SigningOfB1 { get; } = Guid.NewGuid();
        public Guid SigningUnbound { get; } = Guid.NewGuid();
        public Guid SigningOfNoCa { get; } = Guid.NewGuid();
        public Guid RequestOfA1 { get; } = Guid.NewGuid();
        public Guid RequestOfB1 { get; } = Guid.NewGuid();

        public Guid SpaceAdmin { get; }
        public Guid A1Operator { get; }
        public Guid Nobody { get; }
        public Guid Granted { get; }
        public CaGroupAuthorizationService Auth { get; }

        public World()
        {
            var db = W.Db;
            var certificates = new Dictionary<Guid, Guid> { [W.CaA1] = Guid.NewGuid(), [W.CaA2] = Guid.NewGuid(), [W.CaB1] = Guid.NewGuid() };
            foreach (var ca in db.CertificateAuthorities.Local.ToList())
                ca.CertificateId = certificates[ca.Id];

            db.CertProfiles.AddRange(
                new CertProfileEntity { Id = CertUnbound, Name = "unbound" },
                new CertProfileEntity { Id = CertOfA1, Name = "a1", CertificateAuthorityId = W.CaA1, SpaceId = W.SpaceA },
                new CertProfileEntity { Id = CertOfB1, Name = "b1", CertificateAuthorityId = W.CaB1, SpaceId = W.SpaceB },
                new CertProfileEntity { Id = CertOfSpaceA, Name = "space-a", SpaceId = W.SpaceA });
            db.SigningProfiles.AddRange(
                new SigningProfileEntity { Id = SigningOfA1, Name = "sign-a1", IssuerId = certificates[W.CaA1] },
                new SigningProfileEntity { Id = SigningOfA2, Name = "sign-a2", IssuerId = certificates[W.CaA2] },
                new SigningProfileEntity { Id = SigningOfB1, Name = "sign-b1", IssuerId = certificates[W.CaB1] },
                new SigningProfileEntity { Id = SigningUnbound, Name = "sign-unbound" },
                new SigningProfileEntity { Id = SigningOfNoCa, Name = "sign-orphan", IssuerId = Guid.NewGuid() });
            db.RequestProfiles.AddRange(
                new RequestProfileEntity { Id = RequestOfA1, Name = "req-a1", CertificateAuthorityId = W.CaA1 },
                new RequestProfileEntity { Id = RequestOfB1, Name = "req-b1", CertificateAuthorityId = W.CaB1 });

            SpaceAdmin = W.User("sam-space-admin", W.SpaceAdminA);
            A1Operator = W.User("olga-operator", W.Group("a1-operator", W.SpaceA, W.CaA1, "Operator"));
            Nobody = W.User("nora-nobody");
            // A requester of B1 given one profile by name, as a system administrator can grant it.
            Granted = W.User("gina-granted", W.B1Requester);
            db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
            {
                UserId = Granted, Capability = Capabilities.ProfileUse, ResourceType = "CertProfile", ResourceId = CertOfB1,
            });
            db.SaveChanges();

            Auth = new CaGroupAuthorizationService(db, NullLogger<CaGroupAuthorizationService>.Instance, null, new HttpContextAccessor());
        }

        public Task<bool> MayUse(Guid user, string type, Guid id) => Auth.HasResourceCapabilityAsync(user, Capabilities.ProfileUse, type, id);

        /// <summary>The ids the lists show <paramref name="user"/>, as <see cref="Ids"/> writes them, and whether it is all of them.</summary>
        public async Task<(string Ids, bool All)> Sees(Guid user, string type)
        {
            var (ids, all) = await Auth.GetGrantedResourceIdsAsync(user, "profile.", type);
            return (Ids([.. ids]), all);
        }
    }

    /// <summary>A set of ids in one fixed order, so two sets compare as text.</summary>
    private static string Ids(params Guid[] ids) => string.Join(",", ids.Distinct().Order());

    /// <summary>
    /// The administrator of one CA uses that CA's signing, certificate and request profiles, the
    /// certificate profile of its space and the profiles bound to nothing. It cannot use another
    /// CA's, in its own space or another, nor a signing profile whose issuer is no CA.
    /// </summary>
    [Fact]
    public async Task A_ca_administrator_uses_the_profiles_of_its_ca_and_no_other()
    {
        var w = new World();
        var admin = w.W.A1AdminUser;

        Assert.True(await w.MayUse(admin, "SigningProfile", w.SigningOfA1));
        Assert.True(await w.MayUse(admin, "CertProfile", w.CertOfA1));
        Assert.True(await w.MayUse(admin, "RequestProfile", w.RequestOfA1));
        Assert.True(await w.MayUse(admin, "CertProfile", w.CertOfSpaceA));
        Assert.True(await w.MayUse(admin, "CertProfile", w.CertUnbound));
        Assert.True(await w.MayUse(admin, "SigningProfile", w.SigningUnbound));

        Assert.False(await w.MayUse(admin, "SigningProfile", w.SigningOfA2));
        Assert.False(await w.MayUse(admin, "SigningProfile", w.SigningOfB1));
        Assert.False(await w.MayUse(admin, "CertProfile", w.CertOfB1));
        Assert.False(await w.MayUse(admin, "RequestProfile", w.RequestOfB1));
        Assert.False(await w.MayUse(admin, "SigningProfile", w.SigningOfNoCa));
        Assert.False(await w.MayUse(admin, "SigningProfile", Guid.NewGuid()));
    }

    /// <summary>A space administrator uses the profiles of every CA of its space, and none of another space.</summary>
    [Fact]
    public async Task A_space_administrator_uses_the_profiles_of_every_ca_of_its_space()
    {
        var w = new World();

        Assert.True(await w.MayUse(w.SpaceAdmin, "SigningProfile", w.SigningOfA1));
        Assert.True(await w.MayUse(w.SpaceAdmin, "SigningProfile", w.SigningOfA2));
        Assert.True(await w.MayUse(w.SpaceAdmin, "CertProfile", w.CertOfSpaceA));
        Assert.False(await w.MayUse(w.SpaceAdmin, "SigningProfile", w.SigningOfB1));
        Assert.False(await w.MayUse(w.SpaceAdmin, "CertProfile", w.CertOfB1));
    }

    /// <summary>
    /// Roles without <c>profile.use</c> use nothing: the auditor template does not carry it, a
    /// requester and an account in no group hold no profile capability at all. The operator
    /// template carries it since 0.4.4, so an operator uses the profiles of its own CA and no
    /// other, and a system operator every CA's. A system administrator uses everything.
    /// </summary>
    [Fact]
    public async Task Only_a_role_that_carries_profile_use_may_use_a_profile()
    {
        var w = new World();

        foreach (var user in new[] { w.W.Auditor, w.W.Plain, w.Nobody })
        {
            Assert.False(await w.MayUse(user, "SigningProfile", w.SigningOfA1));
            Assert.False(await w.MayUse(user, "CertProfile", w.CertUnbound));
        }
        Assert.True(await w.MayUse(w.A1Operator, "SigningProfile", w.SigningOfA1));
        Assert.True(await w.MayUse(w.A1Operator, "CertProfile", w.CertUnbound));
        Assert.False(await w.MayUse(w.A1Operator, "SigningProfile", w.SigningOfA2));
        Assert.False(await w.MayUse(w.A1Operator, "SigningProfile", w.SigningOfB1));
        Assert.True(await w.MayUse(w.W.Operator, "SigningProfile", w.SigningOfB1));
        Assert.True(await w.MayUse(w.W.SystemAdmin, "SigningProfile", w.SigningOfB1));
        Assert.True(await w.MayUse(w.W.SystemAdmin, "SigningProfile", w.SigningOfNoCa));
    }

    /// <summary>A grant that names one profile still gives that profile and nothing else.</summary>
    [Fact]
    public async Task A_grant_naming_one_profile_gives_that_profile_only()
    {
        var w = new World();

        Assert.True(await w.MayUse(w.Granted, "CertProfile", w.CertOfB1));
        Assert.False(await w.MayUse(w.Granted, "CertProfile", w.CertOfA1));
        Assert.False(await w.MayUse(w.Granted, "CertProfile", w.CertUnbound));
        Assert.False(await w.MayUse(w.Granted, "SigningProfile", w.SigningOfB1));
        Assert.Equal((Ids(w.CertOfB1), false), await w.Sees(w.Granted, "CertProfile"));
    }

    /// <summary>
    /// The lists follow the same scopes. Any <c>profile.*</c> capability shows a profile, so the
    /// operator and the CA administrator see the same ones; a system auditor sees all of them;
    /// a requester and an account in no group see none.
    /// </summary>
    [Fact]
    public async Task The_profile_lists_show_what_the_callers_scope_covers()
    {
        var w = new World();

        foreach (var user in new[] { w.W.A1AdminUser, w.A1Operator })
        {
            Assert.Equal((Ids(w.CertUnbound, w.CertOfA1, w.CertOfSpaceA), false), await w.Sees(user, "CertProfile"));
            Assert.Equal((Ids(w.SigningOfA1, w.SigningUnbound), false), await w.Sees(user, "SigningProfile"));
            Assert.Equal((Ids(w.RequestOfA1), false), await w.Sees(user, "RequestProfile"));
        }
        Assert.Equal((Ids(w.SigningOfA1, w.SigningOfA2, w.SigningUnbound), false), await w.Sees(w.SpaceAdmin, "SigningProfile"));

        Assert.True((await w.Sees(w.W.Auditor, "CertProfile")).All);
        Assert.True((await w.Sees(w.W.SystemAdmin, "SigningProfile")).All);

        foreach (var user in new[] { w.W.Plain, w.Nobody })
        {
            Assert.Equal((Ids(), false), await w.Sees(user, "CertProfile"));
            Assert.Equal((Ids(), false), await w.Sees(user, "SigningProfile"));
        }
    }
}
