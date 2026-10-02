using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;
using Xunit.Abstractions;

namespace ModularCA.Tests.Api;

/// <summary>
/// The S4 cross-space matrix. Two spaces, A and B, each with a CA and everything that hangs off
/// one, plus instance rows (an SSH CA with its key, profiles and template, a profile bound to an
/// instance CA, a global whitelist and an EAB key). Five kinds of user live in A. Every GET list
/// and read the design fences (1.A, 1.B, 1.E) is sent as each user the way a request reaches it:
/// the fence the middleware would store, the real policy set evaluated through
/// <see cref="CaGroupAuthorizationHandler"/> with the route values and path the handler resolves,
/// and only then the action. No list may carry an id of B or of the instance, and a read of one
/// is refused (403 or 404). <see cref="SpaceFenceGuardTests"/> keeps the endpoint set honest.
/// </summary>
public sealed class SpaceIsolationMatrixTests(ITestOutputHelper output)
{
    private const string Ns = "ModularCA.API.Controllers.v1.";

    /// <summary>The seeded rows of one space.</summary>
    internal sealed class Space
    {
        public Guid TenantId { get; init; }
        public Guid CaId { get; init; }
        public Guid CaCertId { get; init; }
        public Guid SpaceProfile { get; init; }
        public Guid BoundProfile { get; init; }
        public Guid SigningProfile { get; init; }
        public Guid RequestProfile { get; init; }
        public Guid Csr { get; init; }
        public Guid Cert { get; init; }
        public string CertSerial { get; init; } = "";
        public Guid Token { get; init; }
        public Guid CrlSchedule { get; init; }
        public Guid Ldap { get; init; }
        public Guid Group { get; init; }
        public Guid Ceremony { get; init; }
        public Guid Whitelist { get; init; }
        public Guid ServiceUrl { get; init; }
        public Guid CaProfile { get; init; }
        public Guid Member { get; init; }

        public IEnumerable<Guid> Ids() => [TenantId, CaId, CaCertId, SpaceProfile, BoundProfile, SigningProfile, RequestProfile, Csr, Cert,
            Token, CrlSchedule, Ldap, Group, Ceremony, Whitelist, ServiceUrl, CaProfile, Member];
    }

    /// <summary>The instance rows no space user may see.</summary>
    internal sealed class InstanceRows
    {
        public Guid SshCa { get; init; }
        public Guid SshKey { get; init; }
        public Guid SshSigningProfile { get; init; }
        public Guid SshRequestProfile { get; init; }
        public Guid SshTemplate { get; init; }
        public Guid BoundProfile { get; init; }
        public Guid GlobalWhitelist { get; init; }
        public Guid EabKey { get; init; }
        public Guid SshCaGroup { get; init; }
        public Guid SshMember { get; init; }
        public Guid Root { get; init; }
        public Guid RootCert { get; init; }

        public IEnumerable<Guid> Ids() => [SshCa, SshKey, SshSigningProfile, SshRequestProfile, SshTemplate, BoundProfile, GlobalWhitelist, EabKey, SshCaGroup,
            SshMember, Root, RootCert];
    }

    private sealed class CurrentUserStub(ModularCADbContext db, Guid id) : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; private set; }
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync()
        {
            User ??= db.Users.Single(u => u.Id == id);
            return Task.CompletedTask;
        }
    }

    internal sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        /// <summary>Further services every request of this world resolves, such as an audit database.</summary>
        public Dictionary<Type, object> Services { get; } = new();
        public Space A { get; }
        public Space B { get; }
        public InstanceRows Instance { get; }
        public Guid UnboundProfile { get; } = Guid.NewGuid();
        public Dictionary<string, Guid> Users { get; } = new();
        private int _serial;

        public World()
        {
            A = SeedSpace("a");
            B = SeedSpace("b");
            Instance = SeedInstance();
            Db.CertProfiles.Add(new CertProfileEntity { Id = UnboundProfile, Name = "unbound", KeyUsages = "[]", ExtendedKeyUsages = "[]" });

            var spaceAdmin = Group("space-a-admin", A.TenantId, null, Capabilities.AdministratorTemplate);
            var spaceOperator = Group("space-a-operator", A.TenantId, null, Capabilities.OperatorTemplate);
            var caAdmin = Group("ca-a-admin", A.TenantId, A.CaId, Capabilities.AdministratorTemplate);
            var caAuditor = Group("ca-a-auditor", A.TenantId, A.CaId, Capabilities.AuditorTemplate);
            Users["space admin"] = User("space-admin", spaceAdmin);
            Users["space operator"] = User("space-operator", spaceOperator);
            Users["CA-X admin"] = User("ca-admin", caAdmin);
            Users["CA-X auditor"] = User("ca-auditor", caAuditor);
            var grantOnly = User("grant-only");
            foreach (var c in Capabilities.AdministratorTemplate)
                Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = grantOnly, Capability = c, CertificateAuthorityId = A.CaId });
            Users["user-level grant only"] = grantOnly;
            Db.SaveChanges();
        }

        public Guid Group(string name, Guid? tenantId, Guid? caId, IEnumerable<string> caps, bool system = false)
        {
            var g = new CaGroupEntity { Id = Guid.NewGuid(), Name = name, DisplayName = name, TenantId = tenantId, CertificateAuthorityId = caId, IsSystemGroup = system };
            Db.CaGroups.Add(g);
            foreach (var c in caps)
                Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = g.Id, Capability = c });
            return g.Id;
        }

        /// <summary>Seeds the step-up token an action validates for <paramref name="userId"/>, and returns it.</summary>
        public string StepUp(Guid userId, string operation, Guid? target = null)
        {
            var token = Guid.NewGuid().ToString("N");
            Cache.SetString(target == null ? $"mfa-stepup:{userId}:{operation}" : $"mfa-stepup:{userId}:{operation}:{target}", token);
            return token;
        }

        public Guid User(string username, params Guid[] groups)
        {
            var id = Guid.NewGuid();
            Db.Users.Add(new UserEntity { Id = id, Username = username, Email = $"{username}@x" });
            foreach (var g in groups)
                Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = g, UserId = id });
            Db.SaveChanges();
            return id;
        }

        private CertificateEntity Cert(bool isCa, Guid? issuer, Guid? signingProfile, string cn)
        {
            var id = Guid.NewGuid();
            var cert = new CertificateEntity
            {
                CertificateId = id, SerialNumber = $"{++_serial:X8}{id:N}"[..16], SubjectDN = $"CN={cn}", Issuer = $"CN={cn}",
                Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----", NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter = DateTime.UtcNow.AddYears(1), IsCA = isCa, IssuerCertificateId = issuer ?? id, SigningProfileId = signingProfile,
            };
            Db.Certificates.Add(cert);
            return cert;
        }

        private Space SeedSpace(string s)
        {
            var tenant = new TenantEntity { Id = Guid.NewGuid(), Name = $"Space {s}", Slug = $"space-{s}" };
            Db.Tenants.Add(tenant);
            var caCert = Cert(true, null, null, $"{s} root");
            var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{s} root", Label = $"{s}-root", TenantId = tenant.Id, CertificateId = caCert.CertificateId, Type = "Root", IsEnabled = true };
            Db.CertificateAuthorities.Add(ca);
            var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = $"{s}-signing", IssuerId = caCert.CertificateId };
            Db.SigningProfiles.Add(signing);
            Db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { CaId = ca.Id, Protocol = "EST", SigningProfileId = signing.Id });
            var spaceProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = $"{s}-space", TenantId = tenant.Id, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
            var boundProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = $"{s}-bound", TenantId = tenant.Id, CertificateAuthorityId = ca.Id, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
            Db.CertProfiles.AddRange(spaceProfile, boundProfile);
            var request = new RequestProfileEntity { Id = Guid.NewGuid(), Name = $"{s}-request", CertificateAuthorityId = ca.Id };
            Db.RequestProfiles.Add(request);
            var leaf = Cert(false, caCert.CertificateId, signing.Id, $"{s}.leaf");
            var csr = new CertRequestEntity
            {
                Id = Guid.NewGuid(), CSR = "stub", Subject = $"CN={s}.leaf", Status = "Pending", KeyAlgorithm = "ECDSA", KeySize = "P-256",
                SignatureAlgorithm = "SHA256withECDSA", CertProfileId = spaceProfile.Id, SigningProfileId = signing.Id,
            };
            Db.CertificateRequests.Add(csr);
            var token = new EnrollmentTokenEntity { Id = Guid.NewGuid(), Token = $"hash-{s}", ExpiresAt = DateTime.UtcNow.AddDays(1), MaxUses = 1, UsesRemaining = 1, TenantId = tenant.Id, CertificateAuthorityId = ca.Id };
            Db.EnrollmentTokens.Add(token);
            var crl = new CrlConfigurationEntity { TaskId = Guid.NewGuid(), Name = $"{s}-crl", CaCertificateId = caCert.CertificateId, Description = "", UpdateInterval = "0 * * * *", DeltaInterval = "" };
            Db.CrlConfigurations.Add(crl);
            var ldap = new LdapConfigurationEntity { Id = Guid.NewGuid(), Name = $"{s}-ldap", Host = "ldap", Username = "u", Password = "p", BaseDn = "dc=x", CertificateAuthorityId = ca.Id, UpdateInterval = "0 * * * *" };
            Db.LdapConfigurations.Add(ldap);
            var group = Group($"{s}-root-auditor-seed", tenant.Id, ca.Id, []);
            var ceremony = new KeyCeremonyEntity
            {
                Id = Guid.NewGuid(), OperationType = "CreateRootCA", Description = s, TargetEntityId = "", InitiatedByUserId = Guid.NewGuid(),
                InitiatedByUsername = "someone", RequiredApprovals = 1, Status = "Pending", CreatedAt = DateTime.UtcNow, ExpiresAt = DateTime.UtcNow.AddDays(1),
                ParametersJson = "{}", ApprovalsJson = "[]", TenantId = tenant.Id,
            };
            Db.KeyCeremonies.Add(ceremony);
            var whitelist = new WhitelistEntity { Id = Guid.NewGuid(), Name = $"{s}-wl", Scope = WhitelistScope.Protocol, CertificateAuthorityId = ca.Id, Protocol = "EST", Cidrs = "[\"10.0.0.0/8\"]" };
            Db.Whitelists.Add(whitelist);
            var serviceUrl = new CaServiceUrlEntity { Id = Guid.NewGuid(), CaCertificateId = caCert.CertificateId, PublicBaseUrl = $"https://{s}.example" };
            Db.CaServiceUrls.Add(serviceUrl);
            var caProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = $"{s}-ca", TenantId = tenant.Id, IsCaProfile = true, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
            Db.CertProfiles.Add(caProfile);
            Db.SaveChanges();
            var member = User($"{s}-member", group);
            return new Space
            {
                TenantId = tenant.Id, CaId = ca.Id, CaCertId = caCert.CertificateId, SpaceProfile = spaceProfile.Id, BoundProfile = boundProfile.Id,
                SigningProfile = signing.Id, RequestProfile = request.Id, Csr = csr.Id, Cert = leaf.CertificateId, CertSerial = leaf.SerialNumber,
                Token = token.Id, CrlSchedule = crl.TaskId, Ldap = ldap.Id, Group = group, Ceremony = ceremony.Id, Whitelist = whitelist.Id,
                ServiceUrl = serviceUrl.Id, CaProfile = caProfile.Id, Member = member,
            };
        }

        private InstanceRows SeedInstance()
        {
            var ssh = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Ops SSH", Label = "ops-ssh", TenantId = null, IsSshCa = true, Type = "SSH", IsEnabled = true };
            Db.CertificateAuthorities.Add(ssh);
            var key = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "Ops SSH", KeyType = "ed25519", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "x", CertificateAuthorityId = ssh.Id, IsUserCa = true, MaxValidityHours = 24, IsEnabled = true };
            Db.SshCaKeys.Add(key);
            var signing = new SshSigningProfileEntity { Id = Guid.NewGuid(), Name = "ssh-signing", SshCaKeyId = key.Id, SourceAddressRestrictions = "[]", DefaultExtensions = "[]" };
            var certProfile = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "ssh-cert", AllowedPrincipalPatterns = "[]", AllowedExtensions = "[]", RequiredExtensions = "[]" };
            var request = new SshRequestProfileEntity { Id = Guid.NewGuid(), Name = "ssh-request", AllowedSshSigningProfileIds = "[]", AllowedSshCertProfileIds = "[]", CertificateAuthorityId = ssh.Id };
            Db.SshSigningProfiles.Add(signing);
            Db.SshCertProfiles.Add(certProfile);
            Db.SshRequestProfiles.Add(request);
            var template = new SshCertificateTemplateEntity { Id = Guid.NewGuid(), Name = "ssh-template", SshCaKeyId = key.Id, SshSigningProfileId = signing.Id, SshCertProfileId = certProfile.Id };
            Db.SshCertificateTemplates.Add(template);
            var bound = new CertProfileEntity { Id = Guid.NewGuid(), Name = "instance-bound", TenantId = null, CertificateAuthorityId = ssh.Id, KeyUsages = "[]", ExtendedKeyUsages = "[]" };
            Db.CertProfiles.Add(bound);
            var global = new WhitelistEntity { Id = Guid.NewGuid(), Name = "admin", Scope = WhitelistScope.Admin, Cidrs = "[\"10.0.0.0/8\"]" };
            Db.Whitelists.Add(global);
            var eab = new AcmeEabKeyEntity { Id = Guid.NewGuid(), KeyId = "eab-1", HmacKey = "secret" };
            Db.AcmeEabKeys.Add(eab);
            var sshGroup = Group("ops-ssh-admin", null, ssh.Id, Capabilities.AdministratorTemplate);
            var rootCert = Cert(true, null, null, "ops root");
            var root = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "ops root", Label = "ops-root", TenantId = null, CertificateId = rootCert.CertificateId, Type = "Root", IsEnabled = true };
            Db.CertificateAuthorities.Add(root);
            Db.SaveChanges();
            var sshMember = User("ssh-admin", sshGroup);
            return new InstanceRows
            {
                SshCa = ssh.Id, SshKey = key.Id, SshSigningProfile = signing.Id, SshRequestProfile = request.Id, SshTemplate = template.Id,
                BoundProfile = bound.Id, GlobalWhitelist = global.Id, EabKey = eab.Id, SshCaGroup = sshGroup, SshMember = sshMember,
                Root = root.Id, RootCert = rootCert.CertificateId,
            };
        }
    }

    /// <summary>One endpoint: its controller, action, concrete path, route values and other arguments, and its HTTP method.</summary>
    internal sealed record Call(string Controller, string Action, string Path, Dictionary<string, object?> Args, string Method = "GET");

    internal static Call Get(string controller, string action, string path, params (string Name, object? Value)[] args)
        => new(controller, action, path, args.ToDictionary(a => a.Name, a => a.Value));

    internal static Call Send(string method, string controller, string action, string path, params (string Name, object? Value)[] args)
        => new(controller, action, path, args.ToDictionary(a => a.Name, a => a.Value), method);

    /// <summary>The lists of 1.A, 1.B and 1.E.</summary>
    private static IEnumerable<Call> Lists(World w) =>
    [
        Get("Admin.AdminCaController", "GetCertificateAuthorities", "/api/v1/admin/authorities"),
        Get("Admin.AdminCaController", "GetAllCaCertificates", "/api/v1/admin/authorities/include-system-ca"),
        Get("Admin.AdminCaController", "GetHierarchy", "/api/v1/admin/authorities/hierarchy"),
        Get("Admin.AdminCaServiceUrlController", "GetAll", "/api/v1/admin/ca-service-urls"),
        Get("Admin.AdminCertProfileController", "GetAll", "/api/v1/admin/cert-profiles"),
        Get("Admin.AdminCertSignRequestController", "RetrievePendingRequests", "/api/v1/admin/requests"),
        Get("Admin.AdminCrlScheduleController", "GetAll", "/api/v1/admin/crl-schedules"),
        Get("Admin.AdminEnrollmentTokenController", "GetActiveTokens", "/api/v1/admin/enrollment-tokens"),
        Get("Admin.AdminGroupController", "GetAll", "/api/v1/admin/groups"),
        Get("Admin.AdminQuotaController", "GetAllQuotas", "/api/v1/admin/quotas"),
        Get("Admin.AdminKeyCeremonyController", "List", "/api/v1/admin/ceremonies"),
        Get("Admin.AdminCertificateController", "ListCertificates", "/api/v1/admin/certificates", ("page", 1), ("pageSize", 100)),
        Get("Admin.AdminWhitelistController", "GetAll", "/api/v1/admin/whitelists"),
        Get("Admin.AdminSshController", "GetCaKeys", "/api/v1/admin/ssh/ca-keys"),
        Get("Admin.AdminSshTemplateController", "GetAll", "/api/v1/admin/ssh/templates"),
        Get("Admin.AdminSshProfileController", "GetSigningProfiles", "/api/v1/admin/ssh/profiles/signing"),
        Get("Admin.AdminSshProfileController", "GetRequestProfiles", "/api/v1/admin/ssh/profiles/request"),
        Get("Admin.AdminSigningProfileController", "GetAll", "/api/v1/admin/signing-profiles"),
        Get("Admin.AdminRequestProfileController", "GetAll", "/api/v1/admin/request-profiles"),
        Get("Admin.AdminAcmeEabController", "ListEabKeys", "/api/v1/admin/acme/eab-keys"),
        Get("Admin.Management.AdminUserManagerController", "GetUsers", "/api/v1/admin/users"),
        Get("User.UserCaController", "GetValidCaCertificates", "/api/v1/user/authorities", ("page", 1), ("pageSize", 100)),
        Get("User.UserCertificateController", "ListCertificates", "/api/v1/user/certificates", ("page", 1), ("pageSize", 100)),
    ];

    /// <summary>Reads of one row of <paramref name="s"/>, or of the instance when it is null.</summary>
    private static IEnumerable<Call> Reads(World w, Space s) =>
    [
        Get("Admin.AdminCertProfileController", "GetById", $"/api/v1/admin/cert-profiles/{s.SpaceProfile}", ("id", s.SpaceProfile)),
        Get("Admin.AdminCertProfileController", "GetResolved", $"/api/v1/admin/cert-profiles/{s.SpaceProfile}/resolved", ("id", s.SpaceProfile)),
        Get("Admin.AdminCertProfileController", "GetById", $"/api/v1/admin/cert-profiles/{s.BoundProfile}", ("id", s.BoundProfile)),
        Get("Admin.AdminCertSignRequestController", "GetApprovals", $"/api/v1/admin/requests/{s.Csr}/approvals", ("id", s.Csr)),
        Get("Admin.AdminCrlScheduleController", "GetById", $"/api/v1/admin/crl-schedules/{s.CrlSchedule}", ("id", s.CrlSchedule)),
        Get("Admin.AdminGroupController", "GetById", $"/api/v1/admin/groups/{s.Group}", ("id", s.Group)),
        Get("Admin.AdminGroupController", "GetByCa", $"/api/v1/admin/groups/by-ca/{s.CaId}", ("caId", s.CaId)),
        Get("Admin.AdminLdapPublishersController", "List", $"/api/v1/admin/authorities/{s.CaId}/ldap-publishers", ("caId", s.CaId)),
        Get("Admin.AdminKeyCeremonyController", "GetById", $"/api/v1/admin/ceremonies/{s.Ceremony}", ("id", s.Ceremony)),
        Get("Admin.AdminWhitelistController", "GetById", $"/api/v1/admin/whitelists/{s.Whitelist}", ("id", s.Whitelist)),
        Get("Admin.AdminSigningProfileController", "GetById", $"/api/v1/admin/signing-profiles/{s.SigningProfile}", ("id", s.SigningProfile)),
        Get("Admin.AdminRequestProfileController", "GetById", $"/api/v1/admin/request-profiles/{s.RequestProfile}", ("id", s.RequestProfile)),
        Get("Admin.AdminCertificateController", "GetCertificateInfo", $"/api/v1/admin/certificates/{s.CertSerial}", ("serial", s.CertSerial)),
        Get("Admin.AdminRequestProfileController", "GetResolved", $"/api/v1/admin/request-profiles/{s.RequestProfile}/resolved", ("id", s.RequestProfile)),
        Send("POST", "Admin.AdminCertProfileController", "ValidateInheritance", $"/api/v1/admin/cert-profiles/{s.BoundProfile}/validate-inheritance", ("id", s.BoundProfile)),
        Send("POST", "Admin.AdminRequestProfileController", "ValidateInheritance", $"/api/v1/admin/request-profiles/{s.RequestProfile}/validate-inheritance", ("id", s.RequestProfile)),
        Send("POST", "Admin.AdminCertSignRequestController", "ValidateAgainstProfile", "/api/v1/admin/requests/validate-against-profile",
            ("request", new ModularCA.Shared.Models.Csr.ValidateAgainstProfileRequest { RequestProfileId = s.RequestProfile })),
        Send("POST", "User.UserCertSignRequestController", "ValidateAgainstProfile", "/api/v1/user/requests/validate-against-profile",
            ("request", new ModularCA.Shared.Models.Csr.ValidateAgainstProfileRequest { RequestProfileId = s.RequestProfile })),
    ];

    private static IEnumerable<Call> InstanceReads(World w) =>
    [
        Get("Admin.AdminCertProfileController", "GetById", $"/api/v1/admin/cert-profiles/{w.Instance.BoundProfile}", ("id", w.Instance.BoundProfile)),
        Get("Admin.AdminCertProfileController", "GetResolved", $"/api/v1/admin/cert-profiles/{w.Instance.BoundProfile}/resolved", ("id", w.Instance.BoundProfile)),
        Get("Admin.AdminWhitelistController", "GetById", $"/api/v1/admin/whitelists/{w.Instance.GlobalWhitelist}", ("id", w.Instance.GlobalWhitelist)),
        Get("Admin.AdminSshProfileController", "GetSigningProfile", $"/api/v1/admin/ssh/profiles/signing/{w.Instance.SshSigningProfile}", ("id", w.Instance.SshSigningProfile)),
        Get("Admin.AdminSshProfileController", "GetRequestProfile", $"/api/v1/admin/ssh/profiles/request/{w.Instance.SshRequestProfile}", ("id", w.Instance.SshRequestProfile)),
        Get("Admin.AdminGroupController", "GetById", $"/api/v1/admin/groups/{w.Instance.SshCaGroup}", ("id", w.Instance.SshCaGroup)),
    ];

    public static TheoryData<string> UserKinds() => new() { "space admin", "space operator", "CA-X admin", "CA-X auditor", "user-level grant only" };

    [Theory]
    [MemberData(nameof(UserKinds))]
    public async Task No_list_returns_another_spaces_or_the_instances_rows(string kind)
    {
        var w = new World();
        var forbidden = w.B.Ids().Concat(w.Instance.Ids()).Select(i => i.ToString()).ToList();
        foreach (var call in Lists(w))
        {
            var (status, body) = await SendAsync(w, w.Users[kind], call);
            output.WriteLine($"{kind} {call.Controller}.{call.Action}: {status}");
            Assert.True(status is 200 or 403, $"{kind}: {call.Controller}.{call.Action} answered {status}: {body}");
            var leaked = forbidden.Where(id => body.Contains(id, StringComparison.OrdinalIgnoreCase)).ToList();
            Assert.True(leaked.Count == 0, $"{kind}: {call.Controller}.{call.Action} leaked {string.Join(", ", leaked)}");
        }
    }

    [Theory]
    [MemberData(nameof(UserKinds))]
    public async Task Every_read_of_another_spaces_or_the_instances_row_is_refused(string kind)
    {
        var w = new World();
        foreach (var call in Reads(w, w.B).Concat(InstanceReads(w)))
        {
            var (status, body) = await SendAsync(w, w.Users[kind], call);
            Assert.True(status is 403 or 404, $"{kind}: {call.Controller}.{call.Action} {call.Path} answered {status}: {body}");
        }
    }

    /// <summary>
    /// The same reads with the policy skipped, as if the handler had let the caller through (it
    /// does, for a route it cannot resolve to a CA): the action's own fence still refuses every
    /// row of B and of the instance.
    /// </summary>
    [Theory]
    [MemberData(nameof(UserKinds))]
    public async Task The_action_fence_alone_refuses_another_spaces_and_the_instances_rows(string kind)
    {
        var w = new World();
        foreach (var call in Reads(w, w.B).Concat(InstanceReads(w)))
        {
            var (status, body) = await SendAsync(w, w.Users[kind], call, skipPolicy: true);
            Assert.True(status is 403 or 404, $"{kind}: {call.Controller}.{call.Action} {call.Path} with no policy answered {status}: {body}");
        }
    }

    /// <summary>
    /// The positive control for the instance reads: the instance SSH CA's administrator, who has
    /// instance scope, reads every one of them.
    /// </summary>
    [Fact]
    public async Task An_instance_scope_user_reads_the_instance_rows()
    {
        var w = new World();
        foreach (var call in InstanceReads(w))
        {
            var (status, body) = await SendAsync(w, w.Instance.SshMember, call);
            Assert.True(status == 200, $"{call.Controller}.{call.Action} {call.Path} answered {status}: {body}");
        }
    }

    /// <summary>
    /// The control that keeps the refusals honest: the same reads of space A succeed for its admin
    /// and for the holder of user-level grants only (owner decision Q2), and its lists show A's rows.
    /// </summary>
    [Theory]
    [InlineData("space admin")]
    [InlineData("CA-X admin")]
    [InlineData("user-level grant only")]
    public async Task The_own_spaces_rows_are_visible(string kind)
    {
        var w = new World();
        // A ceremony that creates a CA belongs to its space: only a space-wide ca.manage holder sees it.
        foreach (var call in Reads(w, w.A).Where(c => kind == "space admin" || c.Controller != "Admin.AdminKeyCeremonyController"))
        {
            var (status, body) = await SendAsync(w, w.Users[kind], call);
            Assert.True(status == 200, $"{kind}: {call.Controller}.{call.Action} {call.Path} answered {status}: {body}");
        }
        foreach (var list in new[] { Lists(w).First(), Get("Admin.AdminGroupController", "GetAll", "/api/v1/admin/groups"),
                     Get("Admin.AdminCrlScheduleController", "GetAll", "/api/v1/admin/crl-schedules") })
        {
            var (_, body) = await SendAsync(w, w.Users[kind], list);
            Assert.True(body.Contains(w.A.CaId.ToString(), StringComparison.OrdinalIgnoreCase)
                || body.Contains(w.A.Group.ToString(), StringComparison.OrdinalIgnoreCase)
                || body.Contains(w.A.CrlSchedule.ToString(), StringComparison.OrdinalIgnoreCase), $"{kind}: {list.Controller}.{list.Action} shows nothing of A: {body}");
        }
    }

    /// <summary>A system auditor's fence is instance-wide (owner decision Q1): both spaces' CAs are listed.</summary>
    [Fact]
    public async Task A_system_auditor_sees_both_spaces()
    {
        var w = new World();
        var auditor = w.User("sys-auditor", w.Group("system-auditor", null, null, Capabilities.AuditorTemplate, system: true));
        var (status, body) = await SendAsync(w, auditor, Lists(w).First());
        Assert.Equal(200, status);
        Assert.Contains(w.A.CaId.ToString(), body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(w.B.CaId.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The instance-wide answer is per capability: a system auditor who also administers CA-X sees
    /// every space's CAs (a cert.view view), but the operator configuration lists, which demand
    /// cert.revoke, show only their own space's rows, not B's and not the instance's.
    /// </summary>
    [Fact]
    public async Task A_system_auditor_who_operates_one_ca_sees_only_their_spaces_operator_configuration()
    {
        var w = new World();
        var user = w.User("auditing-operator", w.Group("system-auditor", null, null, Capabilities.AuditorTemplate, system: true),
            w.Db.CaGroups.Single(g => g.Name == "ca-a-admin").Id);

        var (_, cas) = await SendAsync(w, user, Lists(w).First());
        Assert.Contains(w.B.CaId.ToString(), cas, StringComparison.OrdinalIgnoreCase);

        var forbidden = w.B.Ids().Concat(w.Instance.Ids()).Select(i => i.ToString()).ToList();
        string[] operatorLists = ["AdminEnrollmentTokenController", "AdminWhitelistController", "AdminSshController", "AdminSshTemplateController",
            "AdminRequestProfileController", "AdminCaServiceUrlController", "AdminAcmeEabController"];
        foreach (var call in Lists(w).Where(c => operatorLists.Contains(c.Controller.Split('.').Last()) || c.Action.StartsWith("GetSigningProfiles")
                     || c.Action.StartsWith("GetRequestProfiles")))
        {
            var (status, body) = await SendAsync(w, user, call);
            Assert.Equal(200, status);
            var leaked = forbidden.Where(id => body.Contains(id, StringComparison.OrdinalIgnoreCase)).ToList();
            Assert.True(leaked.Count == 0, $"{call.Controller}.{call.Action} leaked {string.Join(", ", leaked)}");
        }
        var (_, whitelists) = await SendAsync(w, user, Get("Admin.AdminWhitelistController", "GetAll", "/api/v1/admin/whitelists"));
        Assert.Contains(w.A.Whitelist.ToString(), whitelists, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The space part of the fence is per capability too: a holder of cert.revoke in A who holds
    /// only cert.request in B (through a requester-only group, a tenant grant or a CA grant) and on
    /// an instance CA sees none of B's or the instance's operator configuration, which cert.revoke
    /// lists fence, yet the user portal still lists B's and that instance CA, which cert.request opens.
    /// </summary>
    [Theory]
    [InlineData("group")]
    [InlineData("tenant grant")]
    [InlineData("ca grant")]
    public async Task Cert_request_in_another_space_opens_none_of_its_operator_configuration(string source)
    {
        var w = new World();
        var bSsh = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "b ssh", Label = "b-ssh", TenantId = w.B.TenantId, IsSshCa = true, Type = "SSH", IsEnabled = true };
        var bKey = new SshCaKeyEntity { Id = Guid.NewGuid(), Name = "b ssh", KeyType = "ed25519", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "x", CertificateAuthorityId = bSsh.Id, IsUserCa = true, MaxValidityHours = 24, IsEnabled = true };
        var bSigning = new SshSigningProfileEntity { Id = Guid.NewGuid(), Name = "b-ssh-signing", SshCaKeyId = bKey.Id, SourceAddressRestrictions = "[]", DefaultExtensions = "[]" };
        var bCertProfile = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "b-ssh-cert", AllowedPrincipalPatterns = "[]", AllowedExtensions = "[]", RequiredExtensions = "[]" };
        var bTemplate = new SshCertificateTemplateEntity { Id = Guid.NewGuid(), Name = "b-ssh-template", SshCaKeyId = bKey.Id, SshSigningProfileId = bSigning.Id, SshCertProfileId = bCertProfile.Id };
        w.Db.AddRange(bSsh, bKey, bSigning, bCertProfile, bTemplate);

        var aOperator = w.Group("a-revoker", w.A.TenantId, null, [Capabilities.CertRevoke]);
        Guid user;
        if (source == "group")
            user = w.User("revoker", aOperator, w.Group("b-requester", w.B.TenantId, null, [Capabilities.CertRequest]));
        else
        {
            user = w.User("revoker", aOperator);
            w.Db.UserCapabilityGrants.Add(source == "tenant grant"
                ? new UserCapabilityGrantEntity { UserId = user, Capability = Capabilities.CertRequest, TenantId = w.B.TenantId }
                : new UserCapabilityGrantEntity { UserId = user, Capability = Capabilities.CertRequest, CertificateAuthorityId = w.B.CaId });
        }
        w.Db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = user, Capability = Capabilities.CertRequest, CertificateAuthorityId = w.Instance.Root });
        w.Db.SaveChanges();

        var forbidden = w.B.Ids().Concat(w.Instance.Ids()).Concat([bSsh.Id, bKey.Id, bTemplate.Id]).Select(i => i.ToString()).ToList();
        Call[] operatorLists =
        [
            Get("Admin.AdminEnrollmentTokenController", "GetActiveTokens", "/api/v1/admin/enrollment-tokens"),
            Get("Admin.AdminWhitelistController", "GetAll", "/api/v1/admin/whitelists"),
            Get("Admin.AdminCrlScheduleController", "GetAll", "/api/v1/admin/crl-schedules"),
            Get("Admin.AdminCaServiceUrlController", "GetAll", "/api/v1/admin/ca-service-urls"),
            Get("Admin.AdminSshTemplateController", "GetAll", "/api/v1/admin/ssh/templates"),
            Get("Admin.AdminRequestProfileController", "GetAll", "/api/v1/admin/request-profiles"),
        ];
        foreach (var call in operatorLists)
        {
            var (status, body) = await SendAsync(w, user, call);
            Assert.True(status is 200 or 403, $"{source}: {call.Controller}.{call.Action} answered {status}: {body}");
            var leaked = forbidden.Where(id => body.Contains(id, StringComparison.OrdinalIgnoreCase)).ToList();
            Assert.True(leaked.Count == 0, $"{source}: {call.Controller}.{call.Action} leaked {string.Join(", ", leaked)}");
        }
        foreach (var (call, own) in new[] { (operatorLists[0], w.A.Token), (operatorLists[1], w.A.Whitelist), (operatorLists[3], w.A.ServiceUrl) })
        {
            var (_, body) = await SendAsync(w, user, call);
            Assert.True(body.Contains(own.ToString(), StringComparison.OrdinalIgnoreCase), $"{source}: {call.Controller}.{call.Action} shows nothing of A: {body}");
        }

        var (portalStatus, portal) = await SendAsync(w, user, Get("User.UserCaController", "GetValidCaCertificates", "/api/v1/user/authorities", ("page", 1), ("pageSize", 100)));
        Assert.Equal(200, portalStatus);
        Assert.Contains(w.B.CaCertId.ToString(), portal, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(w.Instance.RootCert.ToString(), portal, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(w.A.CaCertId.ToString(), portal, StringComparison.OrdinalIgnoreCase);
    }

    // ── The pipeline ────────────────────────────────────────────────────────

    /// <summary>
    /// Sends <paramref name="call"/> as <paramref name="userId"/>: stores the fence the middleware
    /// would, evaluates the endpoint's authorization through the real policies (403 on refusal),
    /// then invokes the action. Returns the status and the serialized body. With
    /// <paramref name="skipPolicy"/> the policy is not evaluated, as if the handler had passed, so
    /// only the action's own fence stands between the caller and the row.
    /// </summary>
    internal static async Task<(int Status, string Body)> SendAsync(World w, Guid userId, Call call, bool skipPolicy = false)
    {
        var claims = new List<Claim> { new("sub", userId.ToString()), new(ClaimTypes.NameIdentifier, userId.ToString()) };
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
        http.Request.Method = call.Method;
        http.Request.Path = call.Path;
        foreach (var (name, value) in call.Args)
            if (value is null or string or Guid or int)
                http.Request.RouteValues[name] = value?.ToString();
        var accessor = new HttpContextAccessor { HttpContext = http };
        var badges = new AccessBadgeContext(w.Db, accessor);
        var groupAuth = new CaGroupAuthorizationService(w.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor, badges);
        TenantFence.Store(http, await groupAuth.GetFenceAsync(userId));

        var services = new Resolver(w.Db, w.Cache);
        foreach (var (serviceType, instance) in w.Services)
            services.Add(serviceType, instance);
        services.Add(typeof(ICaGroupAuthorizationService), groupAuth);
        services.Add(typeof(IHttpContextAccessor), accessor);
        services.Add(typeof(IAccessBadgeContext), badges);
        services.Add(typeof(ModularCA.Auth.Interfaces.ICurrentUserService), new CurrentUserStub(w.Db, userId));
        http.RequestServices = services;

        var type = ApiAssembly.TypeNamed(Ns + call.Controller);
        var method = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Single(m => m.Name == call.Action && m.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>()
                .Any(a => a.HttpMethods.Contains(call.Method, StringComparer.OrdinalIgnoreCase)));
        if (!skipPolicy && !await PolicyAllows(type, method, http, groupAuth, accessor, w.Db))
            return (403, string.Empty);

        var controller = ActivatorUtilities.CreateInstance(services, type);
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });
        var args = method.GetParameters().Select(p => call.Args.TryGetValue(p.Name!, out var v) ? v
            : p.HasDefaultValue ? p.DefaultValue
            : p.ParameterType.IsValueType ? Activator.CreateInstance(p.ParameterType) : null).ToArray();
        object? returned;
        try
        {
            returned = method.Invoke(controller, args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw new InvalidOperationException($"{call.Controller}.{call.Action} threw: {ex.InnerException}");
        }
        var result = await Unwrap(returned);
        return result switch
        {
            ObjectResult o => (o.StatusCode ?? 200, Serialize(o.Value)),
            StatusCodeResult s => (s.StatusCode, string.Empty),
            FileContentResult f => (200, System.Text.Encoding.UTF8.GetString(f.FileContents)),
            ContentResult c => (c.StatusCode ?? 200, c.Content ?? string.Empty),
            IActionResult other => throw new InvalidOperationException($"{call.Controller}.{call.Action} returned {other.GetType().Name}"),
            var value => (200, Serialize(value)),
        };
    }

    private static async Task<object?> Unwrap(object? returned)
    {
        if (returned is not Task task)
            return returned;
        await task;
        var value = task.GetType().GetProperty("Result")!.GetValue(task);
        if (value != null && value.GetType().IsGenericType && value.GetType().GetGenericTypeDefinition() == typeof(ActionResult<>))
        {
            var convert = (IConvertToActionResult)value;
            return convert.Convert();
        }
        return value;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { ReferenceHandler = ReferenceHandler.IgnoreCycles };

    private static string Serialize(object? value) => value == null ? string.Empty : JsonSerializer.Serialize(value, JsonOptions);

    private static async Task<bool> PolicyAllows(Type controller, MethodInfo action, HttpContext http,
        CaGroupAuthorizationService groupAuth, IHttpContextAccessor accessor, ModularCADbContext db)
    {
        var attributes = controller.GetCustomAttributes(true).Concat(action.GetCustomAttributes(true)).ToList();
        if (attributes.OfType<IAllowAnonymous>().Any()) return true;

        var services = new ServiceCollection().AddLogging().AddAuthorizationCore(options =>
        {
            PolicyDefinitions.AddTo(options);
            options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });
        services.AddSingleton<IAuthorizationHandler>(new CaGroupAuthorizationHandler(groupAuth, accessor, db, NullLogger<CaGroupAuthorizationHandler>.Instance));
        var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await AuthorizationPolicy.CombineAsync(provider, attributes.OfType<IAuthorizeData>()) ?? await provider.GetFallbackPolicyAsync();
        return (await sp.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, http, policy!)).Succeeded;
    }

    /// <summary>
    /// The services a controller asks for: the request's own, the in-memory database, the real
    /// implementation of an interface where one can be built over them, and a no-op proxy otherwise.
    /// </summary>
    internal sealed class Resolver : IServiceProvider
    {
        private readonly Dictionary<Type, object> _instances = new();
        private readonly HashSet<Type> _building = new();
        private static readonly Assembly[] Assemblies =
        [
            typeof(ModularCA.Core.Services.CsrService).Assembly, typeof(CaGroupAuthorizationService).Assembly,
            typeof(ModularCADbContext).Assembly, ApiAssembly.Instance,
        ];

        public Resolver(ModularCADbContext db, IDistributedCache? cache = null)
        {
            Add(typeof(ModularCADbContext), db);
            Add(typeof(IAuditService), new RecordingAuditService());
            Add(typeof(ISecurityAlertService), new RecordingAlertService());
            Add(typeof(IDistributedCache), cache ?? new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));
            Add(typeof(SystemConfig), new SystemConfig());
            Add(typeof(ILoggerFactory), NullLoggerFactory.Instance);
            Add(typeof(IServiceScopeFactory), new ScopeFactory(this));
        }

        private sealed class ScopeFactory(IServiceProvider provider) : IServiceScopeFactory, IServiceScope
        {
            public IServiceScope CreateScope() => this;
            public IServiceProvider ServiceProvider => provider;
            public void Dispose() { }
        }

        public void Add(Type type, object instance) => _instances[type] = instance;

        public object? GetService(Type type)
        {
            if (_instances.TryGetValue(type, out var known)) return known;
            if (type == typeof(IServiceProvider)) return this;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ILogger<>))
                return Activator.CreateInstance(typeof(NullLogger<>).MakeGenericType(type.GetGenericArguments()));
            if (type == typeof(ILogger)) return NullLogger.Instance;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IEnumerable<>))
                return Array.CreateInstance(type.GetGenericArguments()[0], 0);
            if (type.IsPrimitive || type == typeof(string) || !_building.Add(type))
                return null;
            try
            {
                object? built = null;
                if (type.IsInterface)
                {
                    var impl = Assemblies.SelectMany(SafeTypes)
                        .Where(t => t.IsClass && !t.IsAbstract && !t.IsGenericTypeDefinition && type.IsAssignableFrom(t))
                        .OrderBy(t => t.Name == type.Name[1..] ? 0 : 1)
                        .FirstOrDefault();
                    if (impl != null)
                        built = TryBuild(impl);
                    built ??= DispatchProxy.Create(type, typeof(NoOpProxy));
                }
                else if (type.IsClass && !type.IsAbstract)
                {
                    built = TryBuild(type);
                }
                if (built != null) _instances[type] = built;
                return built;
            }
            finally
            {
                _building.Remove(type);
            }
        }

        private object? TryBuild(Type type)
        {
            try { return ActivatorUtilities.CreateInstance(this, type); }
            catch { return null; }
        }

        private static IEnumerable<Type> SafeTypes(Assembly a)
        {
            try { return a.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { return ex.Types.Where(t => t != null)!; }
        }
    }

    /// <summary>Answers every call with the type's default: an empty task, false, null.</summary>
    public class NoOpProxy : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var type = targetMethod!.ReturnType;
            if (type == typeof(void)) return null;
            if (type == typeof(Task)) return Task.CompletedTask;
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
            {
                var inner = type.GetGenericArguments()[0];
                var value = inner.IsValueType ? Activator.CreateInstance(inner) : null;
                return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(inner).Invoke(null, [value]);
            }
            return type.IsValueType ? Activator.CreateInstance(type) : null;
        }
    }

    /// <summary>The matrix and the guard cover the same ground: every listed call is a guarded endpoint or names a CA.</summary>
    [Fact]
    public void Every_call_in_the_matrix_is_a_read_the_guard_knows_or_one_that_names_its_ca()
    {
        var w = new World();
        var unresolved = SpaceFenceGuardTests.UnfencedReads();
        foreach (var call in Lists(w).Concat(Reads(w, w.B)).Concat(InstanceReads(w)))
        {
            var key = $"{call.Controller.Split('.').Last()}.{call.Action}";
            var namesCa = Regex.IsMatch(call.Path, "/(by-ca|authorities)/[0-9a-f-]{36}");
            Assert.True(unresolved.ContainsKey(key) || namesCa || key.StartsWith("AdminKeyCeremony", StringComparison.Ordinal)
                || key.StartsWith("AdminQuota", StringComparison.Ordinal), $"{key} is neither guarded nor CA-routed");
        }
    }
}
