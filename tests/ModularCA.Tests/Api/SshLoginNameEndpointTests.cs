using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Ssh;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The routes of SSH login names (<c>docs/architecture/ssh-login-names.md</c>, "The API"): what
/// the self-service and admin sign routes refuse, the key id they write, the grants routes, what
/// a user and a group hold, a user's certificates, finding a certificate, and the rights each
/// route asks for. Answers are read as the API writes them, in camel case.
/// </summary>
public sealed class SshLoginNameEndpointTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.";
    private const string Admin = Ns + "Admin.AdminSshController";
    private const string Names = Ns + "Admin.AdminSshLoginNameController";
    private const string Self = Ns + "User.UserSshController";
    private const string Groups = Ns + "Admin.AdminGroupController";

    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private sealed class CurrentUserStub(UserEntity user) : ICurrentUserService
    {
        public Guid? UserId => user.Id;
        public UserEntity? User { get; } = user;
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static object New(string typeName, UserEntity caller, bool instanceScope, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", caller.Id.ToString()) }, "test")),
        };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: instanceScope));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static JsonElement Json(IActionResult result)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value, Wire)).RootElement;

    private static string Error(IActionResult result)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<BadRequestObjectResult>(result).Value, Wire)).RootElement.GetProperty("error").GetString()!;

    private static CaGroupAuthorizationService Auth(SshNode node) => new(node.Db, NullLogger<CaGroupAuthorizationService>.Instance);

    private static object NamesController(SshNode node, UserEntity caller, bool instanceScope = true)
        => New(Names, caller, instanceScope, node.LoginNames, new CurrentUserStub(caller), node.Db, Auth(node));

    private static object AdminController(SshNode node, UserEntity caller)
        => New(Admin, caller, true, node.Service, new CurrentUserStub(caller), node.Db, new SystemConfig(),
            new KeyCeremonyService(node.Db, new RecordingAuditService()),
            (IDistributedCache)new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())), node.Relay, new SshKeyImportState(), node.LoginNames);

    private static object SelfController(SshNode node, UserEntity caller)
        => New(Self, caller, true, node.Db, node.Service, new CurrentUserStub(caller), new RecordingAuditService(), Auth(node), node.LoginNames);

    /// <summary>
    /// A node with one SSH CA, its administrator, a requester alice in the group web-ops, and
    /// the profiles a request goes through: the CA's own user signing profile (24 hours), a
    /// certificate profile that allows any account (12 hours), and a request profile over both.
    /// </summary>
    private sealed class World : IDisposable
    {
        public SshNode Node { get; } = new();
        public SshCaKeyEntity Ca { get; }
        public UserEntity Operator { get; }
        public UserEntity Alice { get; }
        public CaGroupEntity Ops { get; }
        public Guid SigningProfile { get; }
        public Guid HostSigningProfile { get; }
        public Guid CertProfile { get; }
        public Guid RequestProfile { get; } = Guid.NewGuid();

        public World()
        {
            Ca = Node.CreateCaAsync(maxValidityHours: 48).GetAwaiter().GetResult();
            Ops = Node.AddGroup("web-ops");
            Operator = Node.AddUser("edward", Node.GroupOf(Ca, "admin").Id);
            Alice = Node.AddUser("alice", Node.GroupOf(Ca, "user").Id, Ops.Id);
            SigningProfile = Node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == Ca.Id && p.AllowUserCerts).Id;
            HostSigningProfile = Node.Db.SshSigningProfiles.Single(p => p.SshCaKeyId == Ca.Id && p.AllowHostCerts).Id;
            var certProfile = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = "any account", AllowedPrincipalPatterns = "[]", MaxPrincipals = 5, MaxValidityHours = 12 };
            CertProfile = certProfile.Id;
            Node.Db.SshCertProfiles.Add(certProfile);
            Node.Db.SshRequestProfiles.Add(new SshRequestProfileEntity
            {
                Id = RequestProfile, Name = "self-service", MaxValidityHours = 24, CertificateAuthorityId = Ca.CertificateAuthorityId,
                AllowedSshSigningProfileIds = JsonSerializer.Serialize(new[] { SigningProfile }), AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { CertProfile }),
            });
            Node.Db.SaveChanges();
        }

        public object SelfRequest(int? hours, string? keyId, params string[] principals) => Body("User.UserSshSignRequest",
            ("PublicKey", SshNode.SubjectKey()), ("Principals", principals.ToList()), ("ValidityHours", hours), ("KeyId", keyId), ("SshRequestProfileId", RequestProfile));

        public object AdminRequest(Guid? subject, string? label, string? keyId, params string[] principals) => Body("Admin.SignSshUserKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("SubjectUserId", subject), ("ServiceLabel", label), ("Principals", principals.ToList()), ("ValidityHours", (int?)1),
            ("KeyId", keyId), ("SshSigningProfileId", SigningProfile), ("SshCertProfileId", CertProfile));

        public object HostRequest(string? keyId, params string[] hostnames) => Body("Admin.SignSshHostKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("Hostnames", hostnames.ToList()), ("ValidityHours", (int?)1), ("KeyId", keyId),
            ("SshSigningProfileId", HostSigningProfile), ("SshCertProfileId", CertProfile));

        public Task<IReadOnlyList<SshLoginNameGrantView>> Grant(string name, UserEntity? user = null, CaGroupEntity? group = null, int? hours = null, DateTime? ends = null)
            => Node.LoginNames.GrantAsync(Ca.Id, new SshLoginNameGrantRequest([name], user?.Id, group?.Id, hours, ends, null), new SshCaActor(Operator.Id, Operator.Username));

        public SshCertificateEntity Row(Guid id)
        {
            using var db = Node.Reopen();
            return db.SshCertificates.Single(c => c.Id == id);
        }

        public void Dispose() => Node.Dispose();
    }

    // ---- Self-service ------------------------------------------------------------------------

    [Fact]
    public async Task A_self_service_request_for_a_name_not_held_is_400_and_a_held_one_is_issued_under_the_username()
    {
        using var w = new World();
        await w.Grant("deploy", group: w.Ops, hours: 4);
        var self = SelfController(w.Node, w.Alice);

        var root = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(self, "SignUserKey", w.SelfRequest(1, null, "alice", "root")));
        var colleague = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(self, "SignUserKey", w.SelfRequest(1, null, "edward")));
        var issued = Json(await Call(self, "SignUserKey", w.SelfRequest(1, null, "alice", "deploy")));

        Assert.Equal(400, root.Status);
        Assert.Contains("'root'", root.Message);
        Assert.Contains("'edward'", colleague.Message);
        Assert.Equal("alice", issued.GetProperty("keyId").GetString());
        var certificate = SshCertificate.ParseOpenSsh(issued.GetProperty("signedCertificate").GetString()!);
        Assert.True(certificate.VerifySignature());
        Assert.Equal("alice", certificate.Fields.KeyId);
        Assert.Equal(new[] { "alice", "deploy" }, certificate.Fields.Principals);
        var row = w.Row(issued.GetProperty("id").GetGuid());
        Assert.Equal(w.Alice.Id, row.SubjectUserId);
        Assert.Equal(w.Alice.Id, row.IssuedByUserId);
        Assert.Single(w.Node.Relay.SshSigned);
    }

    [Fact]
    public async Task A_key_id_in_a_self_service_request_is_refused_unless_it_is_what_the_ca_writes_and_a_request_needs_a_principal()
    {
        using var w = new World();
        var self = SelfController(w.Node, w.Alice);

        var chosen = Error(await Call(self, "SignUserKey", w.SelfRequest(1, "root", "alice")));
        var empty = Error(await Call(self, "SignUserKey", w.SelfRequest(1, string.Empty, "alice")));
        var none = Error(await Call(self, "SignUserKey", w.SelfRequest(1, null)));
        var same = Json(await Call(self, "SignUserKey", w.SelfRequest(1, "alice", "alice")));

        Assert.Contains("The CA writes the key id", chosen);
        Assert.Contains("The CA writes the key id", empty);
        Assert.Contains("At least one principal is required", none);
        Assert.Equal("alice", same.GetProperty("keyId").GetString());
        Assert.Single(w.Node.Relay.SshSigned);
    }

    [Fact]
    public async Task A_self_service_validity_is_the_most_allowed_when_none_is_asked_and_400_over_a_name_s_limit()
    {
        using var w = new World();
        await w.Grant("deploy", group: w.Ops, hours: 4);
        var self = SelfController(w.Node, w.Alice);

        var over = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(self, "SignUserKey", w.SelfRequest(5, null, "alice", "deploy")));
        var overProfile = Error(await Call(self, "SignUserKey", w.SelfRequest(13, null, "alice")));
        var most = Json(await Call(self, "SignUserKey", w.SelfRequest(null, null, "alice", "deploy")));
        var own = Json(await Call(self, "SignUserKey", w.SelfRequest(null, null, "alice")));

        Assert.Contains("'deploy'", over.Message);
        Assert.Contains("at most 4 hours", over.Message);
        Assert.Contains("cert profile maximum of 12 hours", overProfile);
        Assert.Equal(TimeSpan.FromHours(4), most.GetProperty("validBefore").GetDateTime() - most.GetProperty("validAfter").GetDateTime());
        // The certificate profile's 12 hours, below the request profile's 24, the signing profile's 24 and the key's 48.
        Assert.Equal(TimeSpan.FromHours(12), own.GetProperty("validBefore").GetDateTime() - own.GetProperty("validAfter").GetDateTime());
    }

    [Fact]
    public async Task The_request_options_and_the_self_service_list_are_the_caller_s_own()
    {
        using var w = new World();
        await w.Grant("deploy", group: w.Ops, hours: 4);
        var ends = DateTime.UtcNow.AddDays(7);
        var root = (await w.Grant("root", user: w.Alice, hours: 8, ends: ends)).Single();
        var self = SelfController(w.Node, w.Alice);

        var options = Json(await Call(self, "GetRequestOptions"));

        Assert.Equal("alice", options.GetProperty("keyId").GetString());
        var key = options.GetProperty("caKeys").EnumerateArray().Single();
        Assert.Equal(w.Ca.Id, key.GetProperty("id").GetGuid());
        Assert.Equal("Fleet SSH", key.GetProperty("name").GetString());
        Assert.Equal(48, key.GetProperty("maxValidityHours").GetInt32());
        Assert.True(key.GetProperty("allowOwnUsername").GetBoolean());
        Assert.StartsWith("SHA256:", key.GetProperty("fingerprint").GetString());
        var names = key.GetProperty("loginNames").EnumerateArray().ToList();
        Assert.Equal(new[] { "alice own 48", "deploy group 4", "root user 8" },
            names.Select(n => $"{n.GetProperty("name").GetString()} {n.GetProperty("source").GetString()} {n.GetProperty("maxValidityHours").GetInt32()}").ToArray());
        Assert.Equal("web-ops", names[1].GetProperty("groupName").GetString());
        Assert.Equal(w.Ops.Id, names[1].GetProperty("groupId").GetGuid());
        Assert.Equal(root.Id, names[2].GetProperty("grantId").GetGuid());
        Assert.Equal(ends, names[2].GetProperty("expiresAt").GetDateTime());
        Assert.Equal(JsonValueKind.Null, names[0].GetProperty("expiresAt").ValueKind);
        var combination = key.GetProperty("profiles").EnumerateArray().Single();
        Assert.Equal(w.RequestProfile, combination.GetProperty("requestProfileId").GetGuid());
        Assert.Equal(w.SigningProfile, combination.GetProperty("signingProfileId").GetGuid());
        Assert.Equal(w.CertProfile, combination.GetProperty("certProfileId").GetGuid());
        Assert.Equal("any account", combination.GetProperty("certProfileName").GetString());
        Assert.Equal(12, combination.GetProperty("maxValidityHours").GetInt32());
        Assert.Equal(5, combination.GetProperty("maxPrincipals").GetInt32());
        Assert.Empty(combination.GetProperty("unavailableLoginNames").EnumerateArray());

        // A user with cert.request on no SSH CA is offered no key.
        Assert.Empty(Json(await Call(SelfController(w.Node, w.Node.AddUser("nobody")), "GetRequestOptions")).GetProperty("caKeys").EnumerateArray());

        // A certificate an administrator signed for alice is alice's, and not the administrator's.
        var admin = AdminController(w.Node, w.Operator);
        var signed = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, null, "alice", "root")));
        var mine = Json(await Call(self, "GetCertificates")).EnumerateArray().Single();
        Assert.Equal(signed.GetProperty("id").GetGuid(), mine.GetProperty("id").GetGuid());
        Assert.Equal("alice", mine.GetProperty("keyId").GetString());
        Assert.Equal("[\"alice\",\"root\"]", mine.GetProperty("principals").GetString());
        Assert.Equal("active", mine.GetProperty("status").GetString());
        Assert.Equal("user", mine.GetProperty("subject").GetProperty("kind").GetString());
        Assert.Equal("alice", mine.GetProperty("subject").GetProperty("username").GetString());
        Assert.Equal("edward", mine.GetProperty("issuedBy").GetProperty("username").GetString());
        Assert.False(mine.GetProperty("issuedBy").GetProperty("selfService").GetBoolean());
        Assert.Equal(JsonValueKind.Null, mine.GetProperty("issuedBy").GetProperty("sourceIp").ValueKind);
        Assert.Equal(new[] { "own", "user" }, mine.GetProperty("loginNameGrounds").EnumerateArray().Select(g => g.GetProperty("source").GetString()).ToArray());
        Assert.Equal("Fleet SSH", mine.GetProperty("sshCaKey").GetProperty("name").GetString());
        Assert.False(mine.TryGetProperty("signedCertificate", out _));
        Assert.Empty(Json(await Call(SelfController(w.Node, w.Operator), "GetCertificates")).EnumerateArray());
        Assert.IsType<ContentResult>(await Call(self, "DownloadCertificate", signed.GetProperty("id").GetGuid()));
        Assert.IsType<NotFoundResult>(await Call(SelfController(w.Node, w.Operator), "DownloadCertificate", signed.GetProperty("id").GetGuid()));
    }

    // ---- The admin sign routes ---------------------------------------------------------------

    [Fact]
    public async Task The_admin_route_signs_for_exactly_one_of_a_user_or_a_service_identity()
    {
        using var w = new World();
        var admin = AdminController(w.Node, w.Operator);

        var neither = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, null, null, "alice")));
        var both = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, "ci", null, "alice")));
        var blank = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, string.Empty, null, "alice")));
        var none = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, null)));

        Assert.Contains("exactly one of subjectUserId", neither);
        Assert.Equal(neither, both);
        Assert.Equal(neither, blank);
        Assert.Contains("At least one principal is required", none);
        Assert.Empty(w.Node.Relay.SshSigned);
    }

    [Fact]
    public async Task An_administrator_cannot_add_a_name_the_user_does_not_hold_and_grants_it_first()
    {
        using var w = new World();
        var admin = AdminController(w.Node, w.Operator);

        var refused = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, null, "alice", "postgres")));
        var unknown = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(Guid.NewGuid(), null, null, "ghost")));
        await w.Grant("postgres", user: w.Alice);
        var issued = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, null, "alice", "postgres")));

        Assert.Equal(400, refused.Status);
        Assert.Contains("'postgres'", refused.Message);
        Assert.Contains("does not exist, is not active", unknown.Message);
        Assert.Equal("alice", issued.GetProperty("keyId").GetString());
        var row = w.Row(issued.GetProperty("id").GetGuid());
        Assert.Equal(w.Alice.Id, row.SubjectUserId);
        Assert.Equal(w.Operator.Id, row.IssuedByUserId);
        Assert.Equal(new[] { "own", "user" }, SshLoginNameHolding.Parse(row.LoginNameGrounds)!.Select(g => g.Source).ToArray());
    }

    [Fact]
    public async Task A_service_identity_is_logged_as_svc_and_its_label_with_typed_names()
    {
        using var w = new World();
        var admin = AdminController(w.Node, w.Operator);

        var issued = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, "deploy-bot", null, "root", "anything")));
        var badLabel = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, "not a label", null, "root")));

        Assert.Equal("svc:deploy-bot", issued.GetProperty("keyId").GetString());
        var row = w.Row(issued.GetProperty("id").GetGuid());
        Assert.Null(row.SubjectUserId);
        Assert.Equal(new[] { "typed", "typed" }, SshLoginNameHolding.Parse(row.LoginNameGrounds)!.Select(g => g.Source).ToArray());
        Assert.Contains("service label", badLabel.Message);
        Assert.Contains("\"ServiceLabel\":\"deploy-bot\"", JsonSerializer.Serialize(w.Node.Audit.Of(AuditActionType.SshCertIssued).Single().Details));
    }

    [Fact]
    public async Task A_key_id_in_an_admin_request_is_refused_unless_it_is_what_the_ca_writes()
    {
        using var w = new World();
        var admin = AdminController(w.Node, w.Operator);

        var user = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, "alice-laptop", "alice")));
        var service = Error(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, "ci", "ci", "root")));
        var host = Error(await Call(admin, "SignHostKey", w.Ca.Id, w.HostRequest("web01", "web01.example.com", "web01")));
        var sameUser = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, "alice", "alice")));
        var sameService = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, "ci", "svc:ci", "root")));
        var sameHost = Json(await Call(admin, "SignHostKey", w.Ca.Id, w.HostRequest("web01.example.com", "web01.example.com", "web01")));
        var noKeyId = Json(await Call(admin, "SignHostKey", w.Ca.Id, w.HostRequest(null, "db01.example.com")));

        Assert.All(new[] { user, service, host }, e => Assert.Contains("The CA writes the key id", e));
        Assert.Equal("alice", sameUser.GetProperty("keyId").GetString());
        Assert.Equal("svc:ci", sameService.GetProperty("keyId").GetString());
        Assert.Equal("web01.example.com", sameHost.GetProperty("keyId").GetString());
        Assert.Equal("db01.example.com", noKeyId.GetProperty("keyId").GetString());
        Assert.Equal(4, w.Node.Relay.SshSigned.Count);
    }

    [Fact]
    public async Task The_admin_certificate_list_and_detail_say_who_each_certificate_is_for()
    {
        using var w = new World();
        var admin = AdminController(w.Node, w.Operator);
        var names = NamesController(w.Node, w.Operator);
        var forAlice = Json(await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(w.Alice.Id, null, null, "alice")));
        await Call(admin, "SignUserKey", w.Ca.Id, w.AdminRequest(null, "ci", null, "root"));
        await Call(admin, "SignHostKey", w.Ca.Id, w.HostRequest(null, "web01.example.com"));

        var list = Json(await Call(admin, "GetCertificates", w.Ca.Id, 1, 50, "keyId")).EnumerateArray().ToList();
        var detail = Json(await Call(names, "GetCertificate", forAlice.GetProperty("id").GetGuid()));

        Assert.Equal(new[] { "alice user", "svc:ci service", "web01.example.com host" },
            list.Select(c => $"{c.GetProperty("keyId").GetString()} {c.GetProperty("subject").GetProperty("kind").GetString()}").ToArray());
        Assert.Equal("ci", list[1].GetProperty("subject").GetProperty("serviceLabel").GetString());
        Assert.Equal(JsonValueKind.Null, list[2].GetProperty("loginNameGrounds").ValueKind);
        // The members the list has always had are still there under their names.
        foreach (var member in new[] { "id", "sshCaKeyId", "certificateType", "keyId", "serialNumber", "principals", "validAfter", "validBefore", "publicKey",
                     "signedCertificate", "extensions", "isRevoked", "issuedByUserId", "sourceIp", "createdAt" })
            Assert.True(list[0].TryGetProperty(member, out _), member);

        Assert.Equal(w.Alice.Id, detail.GetProperty("subject").GetProperty("userId").GetGuid());
        Assert.Equal("alice", detail.GetProperty("subject").GetProperty("username").GetString());
        Assert.Equal("edward", detail.GetProperty("issuedBy").GetProperty("username").GetString());
        Assert.False(detail.GetProperty("issuedBy").GetProperty("selfService").GetBoolean());
        Assert.Equal(w.Ca.Id, detail.GetProperty("sshCaKey").GetProperty("id").GetGuid());
        Assert.StartsWith("SHA256:", detail.GetProperty("sshCaKey").GetProperty("fingerprint").GetString());
        Assert.StartsWith("SHA256:", detail.GetProperty("keyFingerprint").GetString());
        Assert.Equal("own", detail.GetProperty("loginNameGrounds").EnumerateArray().Single().GetProperty("source").GetString());
        Assert.Equal("alice", detail.GetProperty("loginNameGrounds").EnumerateArray().Single().GetProperty("name").GetString());
        Assert.IsType<NotFoundResult>(await Call(names, "GetCertificate", Guid.NewGuid()));
        Assert.IsType<NotFoundResult>(await Call(NamesController(w.Node, w.Alice), "GetCertificate", Guid.NewGuid()));
    }

    // ---- The grants of a key -----------------------------------------------------------------

    [Fact]
    public async Task The_grant_routes_list_grant_change_and_remove_and_say_what_they_revoked()
    {
        using var w = new World();
        var names = NamesController(w.Node, w.Operator);
        var ends = DateTime.UtcNow.AddDays(7);

        var granted = Json(await Call(names, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "deploy", "deployers" }), ("GroupId", (Guid?)w.Ops.Id), ("MaxValidityHours", (int?)24), ("Note", "web tier"))));
        var toUser = Json(await Call(names, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "root" }), ("UserId", (Guid?)w.Alice.Id), ("MaxValidityHours", (int?)8), ("ExpiresAt", (DateTime?)ends))));
        var rootId = toUser.GetProperty("grants").EnumerateArray().Single().GetProperty("id").GetGuid();
        var certificate = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice", "root"], 6, null);

        Assert.Equal(new[] { "deploy", "deployers" }, granted.GetProperty("grants").EnumerateArray().Select(g => g.GetProperty("loginName").GetString()).ToArray());

        var list = Json(await Call(names, "GetLoginNames", w.Ca.Id));
        Assert.True(list.GetProperty("allowOwnUsername").GetBoolean());
        Assert.Equal(48, list.GetProperty("maxValidityHours").GetInt32());
        Assert.Equal(w.Ca.Id, list.GetProperty("sshCaKey").GetProperty("id").GetGuid());
        var grants = list.GetProperty("grants").EnumerateArray().ToList();
        Assert.Equal(new[] { "deploy", "deployers", "root" }, grants.Select(g => g.GetProperty("loginName").GetString()).ToArray());
        var deploy = grants[0];
        Assert.Equal(JsonValueKind.Null, deploy.GetProperty("user").ValueKind);
        Assert.Equal(w.Ops.Id, deploy.GetProperty("group").GetProperty("id").GetGuid());
        Assert.Equal("web-ops", deploy.GetProperty("group").GetProperty("name").GetString());
        Assert.Equal(1, deploy.GetProperty("group").GetProperty("memberCount").GetInt32());
        Assert.Equal(24, deploy.GetProperty("maxValidityHours").GetInt32());
        Assert.Equal(JsonValueKind.Null, deploy.GetProperty("expiresAt").ValueKind);
        Assert.False(deploy.GetProperty("ended").GetBoolean());
        Assert.Equal("web tier", deploy.GetProperty("note").GetString());
        Assert.Equal("edward", deploy.GetProperty("grantedBy").GetProperty("username").GetString());
        Assert.Equal(w.Operator.Id, deploy.GetProperty("grantedBy").GetProperty("id").GetGuid());
        Assert.Equal(JsonValueKind.String, deploy.GetProperty("grantedAt").ValueKind);
        Assert.Equal(0, deploy.GetProperty("liveCertificates").GetInt32());
        var root = grants[2];
        Assert.Equal(w.Alice.Id, root.GetProperty("user").GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("user").GetProperty("username").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("group").ValueKind);
        Assert.Equal(ends, root.GetProperty("expiresAt").GetDateTime());
        Assert.Equal(1, root.GetProperty("liveCertificates").GetInt32());

        // 409 naming the name, and nothing written.
        var conflict = await Assert.ThrowsAsync<ResourceConflictException>(() => Call(names, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "backup", "root" }), ("UserId", (Guid?)w.Alice.Id))));
        Assert.Equal(409, conflict.Status);
        Assert.Contains("'root'", conflict.Message);
        Assert.Equal(3, Json(await Call(names, "GetLoginNames", w.Ca.Id)).GetProperty("grants").GetArrayLength());

        // A limit over the key's maximum and an end in the past are 400.
        Assert.Equal(400, (await Assert.ThrowsAsync<InvalidRequestException>(() => Call(names, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "backup" }), ("UserId", (Guid?)w.Alice.Id), ("MaxValidityHours", (int?)49))))).Status);
        await Assert.ThrowsAsync<InvalidRequestException>(() => Call(names, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "backup" }), ("UserId", (Guid?)w.Alice.Id), ("ExpiresAt", (DateTime?)DateTime.UtcNow.AddHours(-1)))));

        // Lowering the limit revokes nothing; an end before the certificate's end revokes it.
        var lowered = Json(await Call(names, "ChangeLoginNameGrant", w.Ca.Id, rootId, Body("Admin.ChangeSshLoginNameGrantRequest",
            ("MaxValidityHours", (int?)1), ("ExpiresAt", (DateTime?)ends), ("Note", "tightened"))));
        Assert.Equal(0, lowered.GetProperty("revokedCertificates").GetInt32());
        Assert.Equal(1, lowered.GetProperty("grant").GetProperty("maxValidityHours").GetInt32());
        Assert.Equal("tightened", lowered.GetProperty("grant").GetProperty("note").GetString());
        var sooner = Json(await Call(names, "ChangeLoginNameGrant", w.Ca.Id, rootId, Body("Admin.ChangeSshLoginNameGrantRequest",
            ("MaxValidityHours", (int?)1), ("ExpiresAt", (DateTime?)DateTime.UtcNow.AddHours(2)))));
        Assert.Equal(1, sooner.GetProperty("revokedCertificates").GetInt32());
        Assert.True(w.Row(certificate.Id).IsRevoked);
        Assert.IsType<NotFoundResult>(await Call(names, "ChangeLoginNameGrant", w.Ca.Id, Guid.NewGuid(), Body("Admin.ChangeSshLoginNameGrantRequest")));

        // Removing a grant answers how many certificates it revoked.
        var again = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["deploy"], 1, null);
        var deployId = grants[0].GetProperty("id").GetGuid();
        Assert.Equal(1, Json(await Call(names, "RemoveLoginNameGrant", w.Ca.Id, deployId)).GetProperty("revokedCertificates").GetInt32());
        Assert.True(w.Row(again.Id).IsRevoked);
        Assert.IsType<NotFoundResult>(await Call(names, "RemoveLoginNameGrant", w.Ca.Id, deployId));

        // Own usernames: off revokes, and the switch needs a value.
        var own = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice"], 1, null);
        var off = Json(await Call(names, "SetOwnUsername", w.Ca.Id, Body("Admin.SetSshOwnUsernameRequest", ("Allowed", (bool?)false))));
        Assert.False(off.GetProperty("allowOwnUsername").GetBoolean());
        Assert.Equal(1, off.GetProperty("revokedCertificates").GetInt32());
        Assert.True(w.Row(own.Id).IsRevoked);
        Assert.False(Json(await Call(names, "GetLoginNames", w.Ca.Id)).GetProperty("allowOwnUsername").GetBoolean());
        Assert.Contains("allowed", Error(await Call(names, "SetOwnUsername", w.Ca.Id, Body("Admin.SetSshOwnUsernameRequest"))));

        Assert.All(w.Node.Audit.Of(AuditActionType.SshLoginNameGranted), a => Assert.Equal("edward", a.Actor));
        Assert.Single(w.Node.Audit.Of(AuditActionType.SshLoginNameGrantRemoved));
        Assert.Single(w.Node.Audit.Of(AuditActionType.SshOwnUsernameChanged));
    }

    [Fact]
    public async Task A_key_outside_the_caller_s_fence_is_not_found_on_every_route_that_names_one()
    {
        using var w = new World();
        var grant = (await w.Grant("root", user: w.Alice)).Single();
        var outside = NamesController(w.Node, w.Operator, instanceScope: false);

        Assert.IsType<NotFoundResult>(await Call(outside, "GetLoginNames", w.Ca.Id));
        Assert.IsType<NotFoundResult>(await Call(outside, "GrantLoginNames", w.Ca.Id, Body("Admin.GrantSshLoginNamesRequest",
            ("LoginNames", new List<string> { "deploy" }), ("UserId", (Guid?)w.Alice.Id))));
        Assert.IsType<NotFoundResult>(await Call(outside, "ChangeLoginNameGrant", w.Ca.Id, grant.Id, Body("Admin.ChangeSshLoginNameGrantRequest")));
        Assert.IsType<NotFoundResult>(await Call(outside, "RemoveLoginNameGrant", w.Ca.Id, grant.Id));
        Assert.IsType<NotFoundResult>(await Call(outside, "SetOwnUsername", w.Ca.Id, Body("Admin.SetSshOwnUsernameRequest", ("Allowed", (bool?)false))));
        Assert.IsType<NotFoundResult>(await Call(NamesController(w.Node, w.Operator), "GetLoginNames", Guid.NewGuid()));

        using var db = w.Node.Reopen();
        Assert.Equal("root", db.SshLoginNameGrants.Single().LoginName);
        Assert.True(db.SshCaKeys.Single().AllowOwnUsername);
        Assert.IsType<NotFoundResult>(await Call(outside, "GetUserLoginNames", w.Alice.Id));
        Assert.IsType<NotFoundResult>(await Call(outside, "GetUserLoginNamesOnKey", w.Ca.Id, w.Alice.Id));
        Assert.IsType<NotFoundResult>(await Call(outside, "GetUserCertificates", w.Alice.Id, false));
        Assert.IsType<NotFoundResult>(await Call(outside, "RevokeUserCertificates", w.Alice.Id));
        Assert.IsType<NotFoundResult>(await Call(outside, "GetGroupLoginNames", w.Ops.Id));
        Assert.Empty(Json(await Call(outside, "FindCertificates", (long?)1, null, null)).EnumerateArray());
    }

    // ---- What a user and a group hold --------------------------------------------------------

    [Fact]
    public async Task A_user_s_names_and_certificates_cover_the_keys_the_caller_may_view_and_revoking_the_keys_they_may_revoke_on()
    {
        using var w = new World();
        var lab = await w.Node.CreateCaAsync("Lab SSH");
        // The operator administers Fleet SSH and only requests from Lab SSH; alice requests from both.
        w.Node.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = w.Node.GroupOf(lab, "user").Id, UserId = w.Operator.Id });
        w.Node.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = w.Node.GroupOf(lab, "user").Id, UserId = w.Alice.Id });
        w.Node.Db.SaveChanges();
        var deploy = (await w.Grant("deploy", group: w.Ops, hours: 4)).Single();
        var onFleet = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice", "deploy"], 1, null);
        var onLab = await w.Node.Service.SignUserKeyAsync(lab.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice"], 1, null);
        var names = NamesController(w.Node, w.Operator);

        var held = Json(await Call(names, "GetUserLoginNames", w.Alice.Id));
        Assert.Equal(w.Alice.Id, held.GetProperty("user").GetProperty("id").GetGuid());
        Assert.Equal("alice", held.GetProperty("user").GetProperty("username").GetString());
        var rows = held.GetProperty("loginNames").EnumerateArray().ToList();
        Assert.Equal(new[] { "Fleet SSH alice own 48 True", "Fleet SSH deploy group 4 False", "Lab SSH alice own 48 True" },
            rows.Select(r => $"{r.GetProperty("sshCaKey").GetProperty("name").GetString()} {r.GetProperty("loginName").GetString()} {r.GetProperty("source").GetString()} "
                + $"{r.GetProperty("maxValidityHours").GetInt32()} {r.GetProperty("limitIsKeyMaximum").GetBoolean()}").ToArray());
        Assert.Equal(deploy.Id, rows[1].GetProperty("grantId").GetGuid());
        Assert.Equal(w.Ops.Id, rows[1].GetProperty("groupId").GetGuid());
        Assert.Equal("web-ops", rows[1].GetProperty("groupName").GetString());
        Assert.True(rows[1].GetProperty("effective").GetBoolean());
        Assert.Equal(JsonValueKind.Null, rows[1].GetProperty("expiresAt").ValueKind);

        // What the sign-for form reads: the names on one key, for a caller who may sign on it.
        var onKey = Json(await Call(names, "GetUserLoginNamesOnKey", w.Ca.Id, w.Alice.Id));
        Assert.Equal("alice", onKey.GetProperty("user").GetProperty("username").GetString());
        Assert.Equal(new[] { "alice own 48", "deploy group 4" },
            onKey.GetProperty("loginNames").EnumerateArray()
                .Select(n => $"{n.GetProperty("name").GetString()} {n.GetProperty("source").GetString()} {n.GetProperty("maxValidityHours").GetInt32()}").ToArray());
        Assert.IsType<NotFoundResult>(await Call(names, "GetUserLoginNamesOnKey", w.Ca.Id, Guid.NewGuid()));
        Assert.IsType<NotFoundResult>(await Call(names, "GetUserLoginNamesOnKey", Guid.NewGuid(), w.Alice.Id));
        var stranger = w.Node.AddUser("stranger");
        Assert.IsType<NotFoundResult>(await Call(names, "GetUserLoginNamesOnKey", w.Ca.Id, stranger.Id));

        var ofGroup = Json(await Call(names, "GetGroupLoginNames", w.Ops.Id));
        Assert.Equal("web-ops", ofGroup.GetProperty("group").GetProperty("name").GetString());
        Assert.Equal(1, ofGroup.GetProperty("group").GetProperty("memberCount").GetInt32());
        Assert.Equal("deploy", ofGroup.GetProperty("grants").EnumerateArray().Single().GetProperty("loginName").GetString());
        Assert.IsType<NotFoundResult>(await Call(names, "GetGroupLoginNames", Guid.NewGuid()));

        var live = Json(await Call(names, "GetUserCertificates", w.Alice.Id, true)).EnumerateArray().ToList();
        Assert.Equal(new[] { onFleet.Id, onLab.Id }.OrderBy(i => i), live.Select(c => c.GetProperty("id").GetGuid()).OrderBy(i => i));
        Assert.All(live, c => Assert.Equal("alice", c.GetProperty("subject").GetProperty("username").GetString()));

        var revoked = Json(await Call(names, "RevokeUserCertificates", w.Alice.Id));
        Assert.Equal(1, revoked.GetProperty("revoked").GetInt32());
        Assert.Equal(1, revoked.GetProperty("leftForRights").GetInt32());
        Assert.True(w.Row(onFleet.Id).IsRevoked);
        Assert.False(w.Row(onLab.Id).IsRevoked);
        Assert.Equal(onLab.Id, Json(await Call(names, "GetUserCertificates", w.Alice.Id, true)).EnumerateArray().Single().GetProperty("id").GetGuid());
        Assert.Equal(2, Json(await Call(names, "GetUserCertificates", w.Alice.Id, false)).GetArrayLength());

        // A caller who views only Lab SSH sees only what is there.
        var auditor = w.Node.AddUser("lab-auditor", w.Node.GroupOf(lab, "auditor").Id);
        var onlyLab = Json(await Call(NamesController(w.Node, auditor), "GetUserLoginNames", w.Alice.Id));
        Assert.Equal(new[] { "Lab SSH" }, onlyLab.GetProperty("loginNames").EnumerateArray().Select(r => r.GetProperty("sshCaKey").GetProperty("name").GetString()).ToArray());
        Assert.IsType<NotFoundResult>(await Call(names, "GetUserLoginNames", Guid.NewGuid()));
    }

    [Fact]
    public async Task A_certificate_is_found_from_the_serial_the_ca_fingerprint_and_the_key_id_a_host_logged()
    {
        using var w = new World();
        var names = NamesController(w.Node, w.Operator);
        var certificate = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["alice"], 1, null,
            new SshCaActor(w.Alice.Id, "alice", "198.51.100.9"));
        var fingerprint = SshPublicKey.ParseAuthorizedKey(w.Ca.PublicKey).Fingerprint;

        var found = Json(await Call(names, "FindCertificates", (long?)certificate.SerialNumber, fingerprint, "alice")).EnumerateArray().Single();

        Assert.Equal(certificate.Id, found.GetProperty("id").GetGuid());
        Assert.Equal(w.Ca.Id, found.GetProperty("sshCaKey").GetProperty("id").GetGuid());
        Assert.Equal("Fleet SSH", found.GetProperty("sshCaKey").GetProperty("name").GetString());
        Assert.Equal(fingerprint, found.GetProperty("sshCaKey").GetProperty("fingerprint").GetString());
        Assert.True(found.GetProperty("issuedBy").GetProperty("selfService").GetBoolean());
        Assert.Equal("198.51.100.9", found.GetProperty("issuedBy").GetProperty("sourceIp").GetString());
        Assert.Single(Json(await Call(names, "FindCertificates", (long?)certificate.SerialNumber, null, null)).EnumerateArray());
        Assert.Empty(Json(await Call(names, "FindCertificates", (long?)certificate.SerialNumber, "SHA256:other", null)).EnumerateArray());
        Assert.Empty(Json(await Call(names, "FindCertificates", (long?)certificate.SerialNumber, null, "bob")).EnumerateArray());
        Assert.Contains("serial is required", Error(await Call(names, "FindCertificates", null, fingerprint, "alice")));
        // A caller with no right to view the key finds nothing.
        Assert.Empty(Json(await Call(NamesController(w.Node, w.Node.AddUser("nobody")), "FindCertificates", (long?)certificate.SerialNumber, null, null)).EnumerateArray());
    }

    // ---- Membership changes made in the group controller -------------------------------------

    [Fact]
    public async Task Removing_a_member_or_deleting_a_group_in_the_console_revokes_what_the_group_gave()
    {
        using var w = new World();
        var supers = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-super", DisplayName = "System super", IsSystemGroup = true, IsSystemTierSuper = true };
        w.Node.Db.CaGroups.Add(supers);
        foreach (var capability in Capabilities.AdministratorTemplate)
            w.Node.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = supers.Id, Capability = capability });
        var root = w.Node.AddUser("root-admin", supers.Id);
        var bob = w.Node.AddUser("bob", w.Node.GroupOf(w.Ca, "user").Id, w.Ops.Id);
        await w.Grant("deploy", group: w.Ops);
        var alices = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Alice.Id), ["deploy"], 1, null);
        var bobs = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(bob.Id), ["deploy"], 1, null);
        var auth = Auth(w.Node);
        var controlled = new ControlledUserCeremonyService(w.Node.Db, new KeyCeremonyService(w.Node.Db, new RecordingAuditService()), null!,
            NullLogger<ControlledUserCeremonyService>.Instance);
        var http = New(Groups, root, true, w.Node.Db, new CurrentUserStub(root), new RecordingAuditService(),
            (IDistributedCache)new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())), auth, controlled, w.Node.LoginNames);
        SpaceFence.Store(((ControllerBase)http).HttpContext, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));

        Assert.IsType<OkObjectResult>(await Call(http, "RemoveMember", w.Ops.Id, w.Alice.Id));
        Assert.True(w.Row(alices.Id).IsRevoked);
        Assert.False(w.Row(bobs.Id).IsRevoked);

        Assert.IsType<OkObjectResult>(await Call(http, "Delete", w.Ops.Id));
        Assert.True(w.Row(bobs.Id).IsRevoked);
        using var db = w.Node.Reopen();
        Assert.Empty(db.SshLoginNameGrants);
        Assert.False(db.CaGroups.Any(g => g.Id == w.Ops.Id));
        Assert.All(w.Node.Audit.Of(AuditActionType.SshCertRevoked), a => Assert.Equal("root-admin", a.Actor));
    }

    // ---- Rights ------------------------------------------------------------------------------

    private static (string? Policy, string? Capability, string? StepUp, string Verb, string Route) RightsOf(string controller, string action)
    {
        var method = ApiAssembly.TypeNamed(controller).GetMethod(action)!;
        var attributes = method.GetCustomAttributes(inherit: true);
        var policy = attributes.OfType<IAuthorizeData>().Select(a => a.Policy).FirstOrDefault(p => p != null);
        string? Field(string attribute, string field) => attributes.Where(a => a.GetType().Name == attribute)
            .Select(a => a.GetType().GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(a)?.ToString()).FirstOrDefault();
        var http = attributes.OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>().Single();
        return (policy, Field("RequireCaCapabilityAttribute", "_capability"), Field("RequireStepUpAttribute", "_operation"), http.HttpMethods.Single(), http.Template!);
    }

    /// <summary>
    /// Reads of a key's login names ask cert.view on its CA and changes ask ca.manage on it,
    /// through the policy that resolves the CA from <c>caKeyId</c>; the routes about a user ask
    /// user.manage; every change asks step-up MFA. No CA-scoped policy sits on the class.
    /// </summary>
    [Fact]
    public void Each_new_route_asks_for_the_right_it_should()
    {
        Assert.Equal(("CaAuditor", null, null, "GET", "ca-keys/{caKeyId:guid}/login-names"), RightsOf(Names, "GetLoginNames"));
        Assert.Equal(("CaAdmin", null, StepUpOps.ManageSshLoginNames, "POST", "ca-keys/{caKeyId:guid}/login-names"), RightsOf(Names, "GrantLoginNames"));
        Assert.Equal(("CaAdmin", null, StepUpOps.ManageSshLoginNames, "PUT", "ca-keys/{caKeyId:guid}/login-names/{grantId:guid}"), RightsOf(Names, "ChangeLoginNameGrant"));
        Assert.Equal(("CaAdmin", null, StepUpOps.ManageSshLoginNames, "DELETE", "ca-keys/{caKeyId:guid}/login-names/{grantId:guid}"), RightsOf(Names, "RemoveLoginNameGrant"));
        Assert.Equal(("CaAdmin", null, StepUpOps.ManageSshLoginNames, "PUT", "ca-keys/{caKeyId:guid}/login-names/own-username"), RightsOf(Names, "SetOwnUsername"));
        Assert.Equal((null, Capabilities.UserManage, null, "GET", "users/{userId:guid}/login-names"), RightsOf(Names, "GetUserLoginNames"));
        Assert.Equal(("CaOperator", null, null, "GET", "ca-keys/{caKeyId:guid}/users/{userId:guid}/login-names"), RightsOf(Names, "GetUserLoginNamesOnKey"));
        Assert.Equal(("CaAuditor", null, null, "GET", "groups/{groupId:guid}/login-names"), RightsOf(Names, "GetGroupLoginNames"));
        Assert.Equal((null, Capabilities.UserManage, null, "GET", "users/{userId:guid}/certificates"), RightsOf(Names, "GetUserCertificates"));
        Assert.Equal((null, Capabilities.UserManage, StepUpOps.RevokeSshCert, "POST", "users/{userId:guid}/certificates/revoke"), RightsOf(Names, "RevokeUserCertificates"));
        Assert.Equal(("CaAuditor", null, null, "GET", "certificates/find"), RightsOf(Names, "FindCertificates"));
        Assert.Equal(("CaAuditor", null, null, "GET", "certificates/{id:guid}"), RightsOf(Names, "GetCertificate"));
        Assert.Equal(("CaUser", null, null, "GET", "request-options"), RightsOf(Self, "GetRequestOptions"));
        Assert.Equal(("CaOperator", null, StepUpOps.SignSshUserCert, "POST", "ca-keys/{caKeyId:guid}/certificates/sign-user"), RightsOf(Admin, "SignUserKey"));
        Assert.Equal(("CaOperator", null, null, "POST", "ca-keys/{caKeyId:guid}/certificates/sign-host"), RightsOf(Admin, "SignHostKey"));

        Assert.Equal(Capabilities.CertView, PolicyDefinitions.All["CaAuditor"].Capability);
        Assert.Equal(Capabilities.CaManage, PolicyDefinitions.All["CaAdmin"].Capability);
        Assert.False(PolicyDefinitions.All["CaAdmin"].SystemOnly);
        Assert.Contains(StepUpOps.ManageSshLoginNames, StepUpOps.All);
        Assert.DoesNotContain(StepUpOps.ManageSshLoginNames, StepUpOps.AllowedViaMtls);

        var onClass = ApiAssembly.TypeNamed(Names).GetCustomAttributes(inherit: true).OfType<IAuthorizeData>().ToList();
        Assert.All(onClass, a => Assert.Null(a.Policy));
        Assert.NotEmpty(onClass);
    }

    /// <summary>The rights the routes read from, held by the roles an SSH CA is created with.</summary>
    [Fact]
    public async Task The_roles_of_an_ssh_ca_hold_the_rights_the_routes_ask()
    {
        using var w = new World();
        var auth = Auth(w.Node);
        var ca = w.Ca.CertificateAuthorityId;

        Assert.True(await auth.HasCaCapabilityAsync(w.Operator.Id, ca, Capabilities.CaManage));
        Assert.True(await auth.HasCaCapabilityAsync(w.Operator.Id, ca, Capabilities.UserManage));
        Assert.True(await auth.HasCaCapabilityAsync(w.Alice.Id, ca, Capabilities.CertView));
        Assert.False(await auth.HasCaCapabilityAsync(w.Alice.Id, ca, Capabilities.CaManage));
        Assert.False(await auth.HasCaCapabilityAsync(w.Alice.Id, ca, Capabilities.UserManage));
        Assert.False(await auth.HasCaCapabilityAsync(w.Alice.Id, ca, Capabilities.CertRevoke));

        // A requester may read the key's grants (cert.view) and nothing about another user's certificates to revoke.
        var asAlice = NamesController(w.Node, w.Alice);
        Assert.IsType<OkObjectResult>(await Call(asAlice, "GetLoginNames", w.Ca.Id));
        var certificate = await w.Node.Service.SignUserKeyAsync(w.Ca.Id, SshNode.SubjectKey(), SshCertificateSubject.ForUser(w.Operator.Id), ["edward"], 1, null);
        var left = Json(await Call(asAlice, "RevokeUserCertificates", w.Operator.Id));
        Assert.Equal(0, left.GetProperty("revoked").GetInt32());
        Assert.Equal(1, left.GetProperty("leftForRights").GetInt32());
        Assert.False(w.Row(certificate.Id).IsRevoked);
    }
}
