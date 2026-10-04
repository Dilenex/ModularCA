using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.Tests.Roles;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// Writes that take a CA from the body, sent through the real policies like the matrix: the
/// route-driven policy checks only the row's current CA, so each rebind or create checks the new
/// target itself (fence, capability, same scope). Also the instance credentials (ACME EAB keys)
/// and the user list's trimming of memberships.
/// </summary>
public sealed class SpaceBindingTests
{
    private const string SigningProfiles = "Admin.AdminSigningProfileController";
    private const string CertProfiles = "Admin.AdminCertProfileController";
    private const string RequestProfiles = "Admin.AdminRequestProfileController";
    private const string SshTemplates = "Admin.AdminSshTemplateController";
    private const string SshProfiles = "Admin.AdminSshProfileController";
    private const string Eab = "Admin.AdminAcmeEabController";

    private static object Body(string apiType, params (string Property, object? Value)[] values)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin." + apiType))!;
        foreach (var (property, value) in values)
            body.GetType().GetProperty(property)!.SetValue(body, value);
        return body;
    }

    /// <summary>A user in space A's CA-X admin group who also holds <paramref name="template"/> on B's CA.</summary>
    private static Guid AdminOfAWith(World w, string name, string[] template)
        => w.User(name, w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id, w.Group($"{name}-b", w.B.SpaceId, w.B.CaId, template));

    /// <summary>
    /// A user in <paramref name="baseGroup"/> who also operates another CA of space B, not the
    /// target: B is inside their fence for the operator capabilities, but they hold none on the target.
    /// </summary>
    private static Guid OperatorOfAnotherCaOfB(World w, string name, Guid baseGroup, bool ssh = false)
    {
        var other = ssh ? SshCa(w, $"{name}-ssh", w.B.SpaceId).CaId : Guid.NewGuid();
        if (!ssh)
        {
            w.Db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = other, Name = $"{name} ca", Label = $"{name}-ca", SpaceId = w.B.SpaceId, Type = "Root", IsEnabled = true });
            w.Db.SaveChanges();
        }
        return w.User(name, baseGroup, w.Group($"{name}-b", w.B.SpaceId, other, Capabilities.OperatorTemplate));
    }

    /// <summary>An SSH CA and key in <paramref name="spaceId"/>, for rebinding SSH rows across scopes.</summary>
    private static (Guid CaId, Guid KeyId) SshCa(World w, string label, Guid? spaceId)
    {
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = label, Label = label, SpaceId = spaceId, IsSshCa = true, Type = "SSH", IsEnabled = true };
        var key = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = label, KeyType = "ed25519", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "x", CertificateAuthorityId = ca.Id, IsUserCa = true, MaxValidityHours = 24, IsEnabled = true };
        w.Db.CertificateAuthorities.Add(ca);
        w.Db.SshCaKeys.Add(key);
        w.Db.SaveChanges();
        return (ca.Id, key.Id);
    }

    // ── Signing profiles (item 1) ───────────────────────────────────────────

    /// <summary>
    /// A CA-X admin of space A cannot point a signing profile at space B's CA or at an instance CA,
    /// on create or update (404, the CA is outside their fence), nor can an auditor of B, whose
    /// fence admits B for no ca.manage (404); one who manages another CA of B but not that one is
    /// refused 403. Their own CA is accepted.
    /// </summary>
    [Fact]
    public async Task A_signing_profile_issuer_must_be_a_ca_the_caller_manages_inside_the_fence()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var auditorOfB = AdminOfAWith(w, "b-viewer", Capabilities.AuditorTemplate);
        var viewerOfB = OperatorOfAnotherCaOfB(w, "b-other", w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id);
        Assert.Equal(404, (await SendAsync(w, auditorOfB, Send("PUT", SigningProfiles, "Update",
            $"/api/v1/admin/signing-profiles/{w.A.SigningProfile}", ("id", w.A.SigningProfile),
            ("r", new UpdateSigningProfileRequest { Name = "a-signing", IssuerId = w.B.CaCertId })))).Status);

        Task<(int Status, string Body)> Update(Guid user, Guid issuer) => SendAsync(w, user, Send("PUT", SigningProfiles, "Update",
            $"/api/v1/admin/signing-profiles/{w.A.SigningProfile}", ("id", w.A.SigningProfile),
            ("r", new UpdateSigningProfileRequest { Name = "a-signing", IssuerId = issuer })));
        Task<(int Status, string Body)> Create(Guid user, Guid issuer) => SendAsync(w, user, Send("POST", SigningProfiles, "Create",
            "/api/v1/admin/signing-profiles", ("r", new CreateSigningProfileRequest { Name = $"new-{Guid.NewGuid():N}", IssuerId = issuer })));

        Assert.Equal(404, (await Update(caX, w.B.CaCertId)).Status);
        Assert.Equal(404, (await Update(caX, w.Instance.RootCert)).Status);
        Assert.Equal(403, (await Update(viewerOfB, w.B.CaCertId)).Status);
        Assert.Equal(w.A.CaCertId, w.Db.SigningProfiles.Single(p => p.Id == w.A.SigningProfile).IssuerId);

        Assert.Equal(404, (await Create(caX, w.B.CaCertId)).Status);
        Assert.Equal(404, (await Create(caX, w.Instance.RootCert)).Status);
        Assert.Equal(403, (await Create(viewerOfB, w.B.CaCertId)).Status);
        Assert.Equal(201, (await Create(caX, w.A.CaCertId)).Status);
    }

    // ── Certificate and request profiles (item 11) ──────────────────────────

    /// <summary>
    /// Moving a certificate profile to another CA needs that CA inside the fence for cert.revoke,
    /// which an auditor of its space is not (404), cert.revoke on it (403 for an operator of
    /// another CA of that space) and the profile's own space (400); unbinding it needs cert.revoke
    /// across the space, which a CA-X admin lacks (403).
    /// </summary>
    [Fact]
    public async Task A_cert_profile_moves_only_to_a_ca_of_its_space_the_caller_operates()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var auditorOfB = AdminOfAWith(w, "b-viewer", Capabilities.AuditorTemplate);
        var viewerOfB = OperatorOfAnotherCaOfB(w, "b-other", w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id);
        var operatorOfB = AdminOfAWith(w, "b-operator", Capabilities.OperatorTemplate);

        Task<(int Status, string Body)> Move(Guid user, Guid? ca) => SendAsync(w, user, Send("PUT", CertProfiles, "Update",
            $"/api/v1/admin/cert-profiles/{w.A.BoundProfile}", ("id", w.A.BoundProfile),
            ("request", new UpdateCertProfileRequest { Name = "a-bound", KeyUsages = "[]", ExtendedKeyUsages = "[]", CertificateAuthorityId = ca }),
            ("mfaToken", w.StepUp(user, StepUpOps.UpdateCertProfile, w.A.BoundProfile))));

        Assert.Equal(404, (await Move(caX, w.B.CaId)).Status);
        Assert.Equal(404, (await Move(caX, w.Instance.Root)).Status);
        Assert.Equal(404, (await Move(auditorOfB, w.B.CaId)).Status);
        Assert.Equal(403, (await Move(viewerOfB, w.B.CaId)).Status);
        Assert.Equal(400, (await Move(operatorOfB, w.B.CaId)).Status);
        Assert.Equal(403, (await Move(caX, null)).Status);
        Assert.Equal(w.A.CaId, w.Db.CertProfiles.Single(p => p.Id == w.A.BoundProfile).CertificateAuthorityId);
        Assert.Equal(204, (await Move(w.Users["space admin"], null)).Status);
    }

    /// <summary>The same rules for a request profile, whose scope is its current CA's.</summary>
    [Fact]
    public async Task A_request_profile_moves_only_to_a_ca_of_its_scope_the_caller_operates()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var auditorOfB = AdminOfAWith(w, "b-viewer", Capabilities.AuditorTemplate);
        var viewerOfB = OperatorOfAnotherCaOfB(w, "b-other", w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id);
        var operatorOfB = AdminOfAWith(w, "b-operator", Capabilities.OperatorTemplate);

        Task<(int Status, string Body)> Move(Guid user, Guid? ca) => SendAsync(w, user, Send("PUT", RequestProfiles, "Update",
            $"/api/v1/admin/request-profiles/{w.A.RequestProfile}", ("id", w.A.RequestProfile),
            ("request", new UpdateRequestProfileRequest { Name = "a-request", CertificateAuthorityId = ca }),
            ("mfaToken", w.StepUp(user, StepUpOps.UpdateRequestProfile, w.A.RequestProfile))));

        Assert.Equal(404, (await Move(caX, w.B.CaId)).Status);
        Assert.Equal(404, (await Move(caX, w.Instance.Root)).Status);
        Assert.Equal(404, (await Move(auditorOfB, w.B.CaId)).Status);
        Assert.Equal(403, (await Move(viewerOfB, w.B.CaId)).Status);
        Assert.Equal(400, (await Move(operatorOfB, w.B.CaId)).Status);
        Assert.Equal(403, (await Move(caX, null)).Status);
        Assert.Equal(w.A.CaId, w.Db.RequestProfiles.Single(p => p.Id == w.A.RequestProfile).CertificateAuthorityId);
    }

    /// <summary>
    /// A request or signing profile has no scope of its own beyond its CA, so unbinding one makes
    /// it instance-wide: it needs the capability at system scope, as creating an unbound one does.
    /// A space admin, who holds it only across their space, is refused (403) and the binding
    /// stays; a system admin unbinds.
    /// </summary>
    [Fact]
    public async Task Unbinding_a_request_or_signing_profile_needs_system_scope()
    {
        var w = new World();
        var spaceAdmin = w.Users["space admin"];
        var systemAdmin = w.User("system-admin", w.Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true));

        Task<(int Status, string Body)> UnbindRequest(Guid user) => SendAsync(w, user, Send("PUT", RequestProfiles, "Update",
            $"/api/v1/admin/request-profiles/{w.A.RequestProfile}", ("id", w.A.RequestProfile),
            ("request", new UpdateRequestProfileRequest { Name = "a-request", CertificateAuthorityId = null }),
            ("mfaToken", w.StepUp(user, StepUpOps.UpdateRequestProfile, w.A.RequestProfile))));
        Task<(int Status, string Body)> UnbindSigning(Guid user) => SendAsync(w, user, Send("PUT", SigningProfiles, "Update",
            $"/api/v1/admin/signing-profiles/{w.A.SigningProfile}", ("id", w.A.SigningProfile),
            ("r", new UpdateSigningProfileRequest { Name = "a-signing", IssuerId = null })));

        Assert.Equal(403, (await UnbindRequest(spaceAdmin)).Status);
        Assert.Equal(w.A.CaId, w.Db.RequestProfiles.AsNoTracking().Single(p => p.Id == w.A.RequestProfile).CertificateAuthorityId);
        Assert.Equal(403, (await UnbindSigning(spaceAdmin)).Status);
        Assert.Equal(403, (await UnbindSigning(w.Users["CA-X admin"])).Status);
        Assert.Equal(w.A.CaCertId, w.Db.SigningProfiles.AsNoTracking().Single(p => p.Id == w.A.SigningProfile).IssuerId);

        Assert.Equal(200, (await UnbindRequest(systemAdmin)).Status);
        Assert.Null(w.Db.RequestProfiles.AsNoTracking().Single(p => p.Id == w.A.RequestProfile).CertificateAuthorityId);
        Assert.Equal(204, (await UnbindSigning(systemAdmin)).Status);
        Assert.Null(w.Db.SigningProfiles.AsNoTracking().Single(p => p.Id == w.A.SigningProfile).IssuerId);
    }

    // ── SSH templates and profiles (item 11) ────────────────────────────────

    /// <summary>
    /// An SSH template, signing profile or request profile of the instance moves only to an SSH CA
    /// inside the caller's fence for cert.revoke (404, also for an auditor of its space), that they
    /// operate (403 for an operator of another SSH CA of that space) and that is an instance CA too (400).
    /// </summary>
    [Fact]
    public async Task Ssh_rows_move_only_to_an_ssh_ca_of_their_scope_the_caller_operates()
    {
        var w = new World();
        var (bSsh, bKey) = SshCa(w, "b-ssh", w.B.SpaceId);
        var sshAdmin = w.Instance.SshMember;
        var auditorOfB = w.User("ssh-b-viewer", w.Instance.SshCaGroup, w.Group("b-ssh-auditor", w.B.SpaceId, bSsh, Capabilities.AuditorTemplate));
        var viewerOfB = OperatorOfAnotherCaOfB(w, "ssh-b-other", w.Instance.SshCaGroup, ssh: true);
        var operatorOfB = w.User("ssh-b-operator", w.Instance.SshCaGroup, w.Group("b-ssh-operator", w.B.SpaceId, bSsh, Capabilities.OperatorTemplate));

        Task<(int Status, string Body)> Template(Guid user, Guid key) => SendAsync(w, user, Send("PUT", SshTemplates, "Update",
            $"/api/v1/admin/ssh/templates/{w.Instance.SshTemplate}", ("id", w.Instance.SshTemplate),
            ("request", Body("UpdateSshTemplateRequest", ("SshCaKeyId", (Guid?)key)))));
        Task<(int Status, string Body)> Signing(Guid user, Guid key) => SendAsync(w, user, Send("PUT", SshProfiles, "UpdateSigningProfile",
            $"/api/v1/admin/ssh/profiles/signing/{w.Instance.SshSigningProfile}", ("id", w.Instance.SshSigningProfile),
            ("request", Body("UpdateSshSigningProfileRequest", ("SshCaKeyId", (Guid?)key)))));
        Task<(int Status, string Body)> Request(Guid user, Guid ca) => SendAsync(w, user, Send("PUT", SshProfiles, "UpdateRequestProfile",
            $"/api/v1/admin/ssh/profiles/request/{w.Instance.SshRequestProfile}", ("id", w.Instance.SshRequestProfile),
            ("request", Body("UpdateSshRequestProfileRequest", ("CertificateAuthorityId", (Guid?)ca)))));

        foreach (var (move, target) in new (Func<Guid, Guid, Task<(int, string)>>, Guid)[] { (Template, bKey), (Signing, bKey), (Request, bSsh) })
        {
            Assert.Equal(404, (await move(sshAdmin, target)).Item1);
            Assert.Equal(404, (await move(auditorOfB, target)).Item1);
            Assert.Equal(403, (await move(viewerOfB, target)).Item1);
            Assert.Equal(400, (await move(operatorOfB, target)).Item1);
        }
        Assert.Equal(w.Instance.SshKey, w.Db.SshCertificateTemplates.Single(t => t.Id == w.Instance.SshTemplate).SshCaKeyId);
        Assert.Equal(w.Instance.SshKey, w.Db.SshSigningProfiles.Single(p => p.Id == w.Instance.SshSigningProfile).SshCaKeyId);
        Assert.Equal(w.Instance.SshCa, w.Db.SshRequestProfiles.Single(p => p.Id == w.Instance.SshRequestProfile).CertificateAuthorityId);
    }

    // ── ACME EAB keys (item 8) ──────────────────────────────────────────────

    /// <summary>
    /// EAB keys are accepted at every CA, so creating and deleting one needs cert.revoke at system
    /// scope: a CA operator is refused (403, 404 for delete) and the key survives; a system operator
    /// creates and deletes. The list follows the cert.revoke fence: a system auditor who operates
    /// one CA sees none.
    /// </summary>
    [Fact]
    public async Task Eab_keys_are_managed_only_with_cert_revoke_at_system_scope()
    {
        var w = new World();
        var caX = w.Users["CA-X admin"];
        var sysOperator = w.User("sys-operator", w.Group("system-operator", null, null, Capabilities.OperatorTemplate, system: true));
        var sysAuditor = w.User("sys-auditor", w.Group("system-auditor", null, null, Capabilities.AuditorTemplate, system: true),
            w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id);
        var create = Send("POST", Eab, "CreateEabKey", "/api/v1/admin/acme/eab-keys", ("request", null));
        Call Delete(Guid id) => Send("DELETE", Eab, "DeleteEabKey", $"/api/v1/admin/acme/eab-keys/{id}", ("id", id));
        var list = Get(Eab, "ListEabKeys", "/api/v1/admin/acme/eab-keys");

        Assert.Equal(403, (await SendAsync(w, caX, create)).Status);
        Assert.Equal(404, (await SendAsync(w, caX, Delete(w.Instance.EabKey))).Status);
        Assert.True(w.Db.AcmeEabKeys.Any(k => k.Id == w.Instance.EabKey));

        var (listed, listBody) = await SendAsync(w, sysAuditor, list);
        Assert.Equal(200, listed);
        Assert.DoesNotContain(w.Instance.EabKey.ToString(), listBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(w.Instance.EabKey.ToString(), (await SendAsync(w, sysOperator, list)).Body, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(200, (await SendAsync(w, sysOperator, create)).Status);
        Assert.Equal(200, (await SendAsync(w, sysOperator, Delete(w.Instance.EabKey))).Status);
        Assert.False(w.Db.AcmeEabKeys.Any(k => k.Id == w.Instance.EabKey));
    }

    // ── Protocol audit (item 6) ─────────────────────────────────────────────

    /// <summary>
    /// Protocol audit rows are scoped by their CA id, so a row of B's CA carrying A's label is not
    /// shown to A's auditor and a row of A's CA under an old label is; only a legacy row with no CA
    /// id falls back to its label. The list, its CA filter and the by-id read agree, and name the
    /// row's space <c>spaceId</c>.
    /// </summary>
    [Fact]
    public async Task Protocol_audit_rows_are_scoped_by_ca_id_and_by_label_only_without_one()
    {
        var w = new World();
        var audit = new ModularCA.Database.AuditDbContext(new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<ModularCA.Database.AuditDbContext>()
            .UseInMemoryDatabase($"audit-{Guid.NewGuid():N}").Options);
        var foreign = new AuditEstEntity { Operation = "simpleenroll", CaLabel = "a-root", CertificateAuthorityId = w.B.CaId };
        var relabelled = new AuditEstEntity { Operation = "simpleenroll", CaLabel = "a-old-label", CertificateAuthorityId = w.A.CaId };
        var legacy = new AuditEstEntity { Operation = "simpleenroll", CaLabel = "a-root" };
        audit.AuditEst.AddRange(foreign, relabelled, legacy);
        audit.SaveChanges();
        w.Services[typeof(ModularCA.Database.AuditDbContext)] = audit;
        var auditor = w.Users["CA-X auditor"];
        const string Audit = "Admin.AdminAuditController";

        foreach (var caId in new Guid?[] { null, w.A.CaId })
        {
            var (status, body) = await SendAsync(w, auditor, Get(Audit, "GetEstAudit", "/api/v1/admin/audit/est", ("caId", caId), ("page", 1), ("pageSize", 50)));
            Assert.Equal(200, status);
            Assert.Contains(relabelled.Id.ToString(), body, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(legacy.Id.ToString(), body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(foreign.Id.ToString(), body, StringComparison.OrdinalIgnoreCase);
            // The audit database keeps its TenantId column; the API names it spaceId.
            Assert.Contains("\"spaceId\"", body);
            Assert.DoesNotContain("tenantId", body, StringComparison.OrdinalIgnoreCase);
        }
        Call ById(Guid id) => Get(Audit, "GetEstAuditById", $"/api/v1/admin/audit/est/{id}", ("id", id));
        Assert.Equal(404, (await SendAsync(w, auditor, ById(foreign.Id))).Status);
        Assert.Equal(200, (await SendAsync(w, auditor, ById(relabelled.Id))).Status);
        Assert.Equal(200, (await SendAsync(w, auditor, ById(legacy.Id))).Status);
    }

    // ── The user list (items 7 and 14) ──────────────────────────────────────

    /// <summary>
    /// The control behind the matrix's user-list row: the unscoped list does carry B's member and
    /// the instance SSH CA's member, so their absence from the scoped list is the fence's work.
    /// </summary>
    [Fact]
    public async Task The_unscoped_user_list_holds_the_members_the_fence_must_hide()
    {
        var w = new World();
        var service = (IUserManagementService)new Resolver(w.Db).GetService(typeof(IUserManagementService))!;
        var ids = (await service.GetAllUsers()).Select(u => u.Id).ToList();
        Assert.Contains(w.B.Member, ids);
        Assert.Contains(w.Instance.SshMember, ids);
    }

    /// <summary>
    /// A visible user's memberships are trimmed to the caller's fence, and a user placed in the
    /// caller's space only by a user-level grant is visible too (owner decision Q2); one placed
    /// only in another space is not.
    /// </summary>
    [Fact]
    public async Task A_visible_users_groups_are_trimmed_to_the_fence_and_grant_holders_are_listed()
    {
        var w = new World();
        var dual = w.User("dual", w.A.Group, w.B.Group);
        var grantInB = w.User("grant-in-b");
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = grantInB, Capability = Capabilities.CertView, SpaceId = w.B.SpaceId });
        w.Db.SaveChanges();

        var (status, body) = await SendAsync(w, w.Users["space admin"], Get("Admin.Management.AdminUserManagerController", "GetUsers", "/api/v1/admin/users"));

        Assert.Equal(200, status);
        var users = JsonDocument.Parse(body).RootElement.EnumerateArray().ToDictionary(u => u.GetProperty("Id").GetGuid());
        Assert.Equal([w.A.Group], users[dual].GetProperty("Groups").EnumerateArray().Select(g => g.GetProperty("GroupId").GetGuid()));
        Assert.True(users.ContainsKey(w.Users["user-level grant only"]));
        Assert.False(users.ContainsKey(grantInB));
        Assert.DoesNotContain(w.B.Group.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }
}
