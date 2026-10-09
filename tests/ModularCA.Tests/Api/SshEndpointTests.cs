using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The SSH routes over the signer (<c>docs/architecture/ssh-keystore.md</c>, "API changes"): what
/// each answers when the signer cannot serve, when a key still awaits its import, and when the
/// signer's rules refuse a certificate; the key list's storage column; and the KRL routes.
/// </summary>
public sealed class SshEndpointTests
{
    private const string Admin = "ModularCA.API.Controllers.v1.Admin.AdminSshController";
    private const string Self = "ModularCA.API.Controllers.v1.User.UserSshController";
    private const string Public = "ModularCA.API.Controllers.v1.Public.PublicSshController";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "ssh-operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static object New(string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static HttpContext HttpOf(object controller) => ((ControllerBase)controller).HttpContext;

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType().GetMethod(method)!.Invoke(controller, args)!;

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static object AdminController(SshNode node, ISshCaService service, IDistributedCache? cache = null,
        ISigningService? signer = null, SshKeyImportState? imports = null)
        => New(Admin, node.Actor.UserId!.Value, service, new CurrentUserStub(node.Actor.UserId!.Value), node.Db, new SystemConfig(),
            new KeyCeremonyService(node.Db, new RecordingAuditService()), cache ?? NewCache(), signer ?? node.Relay, imports ?? new SshKeyImportState(),
            node.LoginNames);

    private static object PublicController(ISshCaService service) => New(Public, Guid.NewGuid(), service, new SystemConfig());

    private static string Json(IActionResult result) => JsonSerializer.Serialize(Assert.IsAssignableFrom<ObjectResult>(result).Value);

    /// <summary>
    /// The 503 the SSH routes give for a key that cannot be used now: the reason, and, only
    /// where trying again can help (a locked signer), when to try again.
    /// </summary>
    private static string AssertUnavailable(object controller, IActionResult result, bool retry = true)
    {
        var unavailable = Assert.IsType<ObjectResult>(result);
        Assert.Equal(503, unavailable.StatusCode);
        Assert.Equal(retry ? "30" : string.Empty, HttpOf(controller).Response.Headers.RetryAfter.ToString());
        return JsonDocument.Parse(JsonSerializer.Serialize(unavailable.Value)).RootElement.GetProperty("error").GetString()!;
    }

    private static Guid SshCertProfile(SshNode node)
    {
        var profile = new SshCertProfileEntity { Id = Guid.NewGuid(), Name = $"profile-{Guid.NewGuid():N}", AllowedPrincipalPatterns = "[]", MaxPrincipals = 5, MaxValidityHours = 24 };
        node.Db.SshCertProfiles.Add(profile);
        node.Db.SaveChanges();
        return profile.Id;
    }

    private static Guid SigningProfile(SshNode node, SshCaKeyEntity key, bool host)
    {
        var existing = node.Db.SshSigningProfiles.FirstOrDefault(p => p.SshCaKeyId == key.Id && p.AllowHostCerts == host);
        if (existing != null)
            return existing.Id;
        var profile = new SshSigningProfileEntity
        {
            Id = Guid.NewGuid(), Name = $"signing-{Guid.NewGuid():N}", SshCaKeyId = key.Id, AllowUserCerts = !host, AllowHostCerts = host,
            MaxValidityHours = 24, DefaultExtensions = host ? "[]" : "[\"permit-pty\"]", SourceAddressRestrictions = "[]",
        };
        node.Db.SshSigningProfiles.Add(profile);
        node.Db.SaveChanges();
        return profile.Id;
    }

    /// <summary>An admin request for a user certificate for the service identity <c>ci</c>, whose principals are typed.</summary>
    private static object UserRequest(SshNode node, SshCaKeyEntity key, params string[] principals)
        => Body("ModularCA.API.Controllers.v1.Admin.SignSshUserKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("ServiceLabel", "ci"), ("Principals", principals.ToList()), ("ValidityHours", (int?)1),
            ("SshSigningProfileId", SigningProfile(node, key, host: false)), ("SshCertProfileId", SshCertProfile(node)));

    private static object HostRequest(SshNode node, SshCaKeyEntity key, params string[] hostnames)
        => Body("ModularCA.API.Controllers.v1.Admin.SignSshHostKeyRequest",
            ("PublicKey", SshNode.SubjectKey()), ("Hostnames", hostnames.ToList()), ("ValidityHours", (int?)1),
            ("SshSigningProfileId", SigningProfile(node, key, host: true)), ("SshCertProfileId", SshCertProfile(node)));

    private static InProcessSigningService Locked(SshNode node)
    {
        var scopes = TestSigner.ScopesFor(node.DatabaseName);
        return new InProcessSigningService(node.Keystore, scopes, new DatabaseSignerAuditSink(scopes), node.Persistence,
            NullLogger<InProcessSigningService>.Instance, unlocked: false);
    }

    // ---- Sign --------------------------------------------------------------------------------

    [Fact]
    public async Task The_admin_routes_sign_through_the_signer_with_exactly_the_profile_s_extensions_and_the_service_audits_once()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var controller = AdminController(node, node.Service);

        var user = Assert.IsType<OkObjectResult>(await Call(controller, "SignUserKey", ca.Id, UserRequest(node, ca, "alice")));
        var host = Assert.IsType<OkObjectResult>(await Call(controller, "SignHostKey", ca.Id, HostRequest(node, ca, "host1.example.com")));

        var userCert = SshCertificate.ParseOpenSsh(JsonDocument.Parse(JsonSerializer.Serialize(user.Value)).RootElement.GetProperty("SignedCertificate").GetString()!);
        var hostCert = SshCertificate.ParseOpenSsh(JsonDocument.Parse(JsonSerializer.Serialize(host.Value)).RootElement.GetProperty("SignedCertificate").GetString()!);
        Assert.True(userCert.VerifySignature() && hostCert.VerifySignature());

        // The CA's own default profile names three permits; the certificate carries those three and no others.
        Assert.Equal(new[] { "permit-agent-forwarding", "permit-port-forwarding", "permit-pty" }, userCert.Fields.Extensions.Select(e => e.Name).ToArray());
        Assert.Empty(userCert.Fields.CriticalOptions);
        Assert.Empty(hostCert.Fields.Extensions);

        var audits = node.Audit.Of(AuditActionType.SshCertIssued);
        Assert.Equal(2, audits.Count);
        Assert.All(audits, a => Assert.Equal("ssh-operator", a.Actor));
    }

    [Fact]
    public async Task Signing_with_a_key_awaiting_import_is_503_with_the_reason()
    {
        using var node = new SshNode();
        var legacy = node.SeedLegacyCa();
        var signer = new UnaskedSigner();
        var controller = AdminController(node, node.ServiceOver(signer));

        var user = AssertUnavailable(controller, await Call(controller, "SignUserKey", legacy.Id, UserRequest(node, legacy, "alice")), retry: false);
        var host = AssertUnavailable(controller, await Call(controller, "SignHostKey", legacy.Id, HostRequest(node, legacy, "host1")), retry: false);

        Assert.Contains("SSH CA key awaiting import into the signer", user);
        Assert.Contains("SSH CA key awaiting import into the signer", host);
        Assert.Equal(0, signer.Calls);
    }

    [Fact]
    public async Task Signing_while_the_signer_is_locked_or_cannot_serve_the_key_is_503_with_the_signer_s_reason()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();

        var locked = AdminController(node, node.ServiceOver(Locked(node)));
        Assert.Contains("not unlocked", AssertUnavailable(locked, await Call(locked, "SignUserKey", ca.Id, UserRequest(node, ca, "alice"))));
        Assert.Contains("not unlocked", AssertUnavailable(locked, await Call(locked, "SignHostKey", ca.Id, HostRequest(node, ca, "host1"))));

        node.Relay.OnSignSsh = (_, _) => throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
            "The signer predates the SSH keystore; upgrade the signer first.");
        var older = AdminController(node, node.Service);
        Assert.Contains("predates the SSH keystore", AssertUnavailable(older, await Call(older, "SignUserKey", ca.Id, UserRequest(node, ca, "alice")), retry: false));
    }

    /// <summary>
    /// A rule the signer refuses on leaves the action as the request-validation family, which
    /// the API's middleware renders as 400 with the message; the action does not swallow it. A
    /// user certificate with no principal never reaches the signer: the action answers 400 itself.
    /// </summary>
    [Fact]
    public async Task A_certificate_the_signer_refuses_leaves_the_action_as_a_400_with_the_signer_s_reason()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var controller = AdminController(node, node.Service);

        var none = Assert.IsType<BadRequestObjectResult>(await Call(controller, "SignUserKey", ca.Id, UserRequest(node, ca)));
        var noHost = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(controller, "SignHostKey", ca.Id, HostRequest(node, ca)));
        var dsa = Body("ModularCA.API.Controllers.v1.Admin.SignSshHostKeyRequest",
            ("PublicKey", SshNode.DsaKey()), ("Hostnames", new List<string> { "host1" }), ("ValidityHours", (int?)1),
            ("SshSigningProfileId", SigningProfile(node, ca, host: true)), ("SshCertProfileId", SshCertProfile(node)));
        var refusedKey = await Assert.ThrowsAsync<InvalidRequestException>(() => Call(controller, "SignHostKey", ca.Id, dsa));

        Assert.Contains("At least one principal is required", Json(none));
        Assert.Equal(400, noHost.Status);
        Assert.Contains("At least one principal is required", noHost.Message);
        Assert.Equal(400, refusedKey.Status);
        Assert.Contains("DSA", refusedKey.Message);
    }

    [Fact]
    public async Task The_three_sign_routes_answer_first_for_a_locked_signer_and_creation_does_not()
    {
        static bool Guarded(string controller, string action)
            => ApiAssembly.TypeNamed(controller).GetMethod(action)!.GetCustomAttributes(inherit: true)
                .Any(a => a.GetType().Name == "RequireUnlockedSignerAttribute");

        Assert.True(Guarded(Admin, "SignUserKey"));
        Assert.True(Guarded(Admin, "SignHostKey"));
        Assert.True(Guarded(Self, "SignUserKey"));
        Assert.False(Guarded(Admin, "GenerateCaKey"));
        Assert.False(Guarded(Admin, "DownloadKrl"));
        Assert.False(Guarded(Public, "DownloadKrl"));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task The_self_service_route_signs_through_the_signer_and_its_refusals_and_audit_are_the_service_s()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var user = new UserEntity { Id = node.Actor.UserId!.Value, Username = "ssh-operator", PasswordHash = "x" };
        node.Db.Users.Add(user);
        node.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = node.Db.CaGroups.Single(g => g.Name == "fleet-ssh-user").Id, UserId = user.Id });
        var signing = SigningProfile(node, ca, host: false);
        var certProfile = SshCertProfile(node);
        var requestProfile = new SshRequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = "self-service", MaxValidityHours = 24, CertificateAuthorityId = ca.CertificateAuthorityId,
            AllowedSshSigningProfileIds = JsonSerializer.Serialize(new[] { signing }), AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { certProfile }),
        };
        node.Db.SshRequestProfiles.Add(requestProfile);
        node.Db.SaveChanges();

        object Controller(ISshCaService service) => New(Self, user.Id, node.Db, service, new CurrentUserStub(user.Id),
            new RecordingAuditService(), new CaGroupAuthorizationService(node.Db, NullLogger<CaGroupAuthorizationService>.Instance), node.LoginNames);
        object Request(params string[] principals) => Body("ModularCA.API.Controllers.v1.User.UserSshSignRequest",
            ("PublicKey", SshNode.SubjectKey()), ("Principals", principals.ToList()), ("ValidityHours", (int?)1), ("SshRequestProfileId", requestProfile.Id));

        var signed = Assert.IsType<OkObjectResult>(await Call(Controller(node.Service), "SignUserKey", Request("ssh-operator")));
        var certificate = SshCertificate.ParseOpenSsh(JsonDocument.Parse(JsonSerializer.Serialize(signed.Value)).RootElement.GetProperty("SignedCertificate").GetString()!);
        Assert.True(certificate.VerifySignature());
        Assert.Equal("ssh-operator", certificate.Fields.KeyId);
        var audit = Assert.Single(node.Audit.Of(AuditActionType.SshCertIssued));
        Assert.True(audit.Success);
        Assert.Equal(user.Id, audit.ActorId);

        var locked = Controller(node.ServiceOver(Locked(node)));
        Assert.Contains("not unlocked", AssertUnavailable(locked, await Call(locked, "SignUserKey", Request("ssh-operator"))));

        Assert.IsType<BadRequestObjectResult>(await Call(Controller(node.Service), "SignUserKey", Request()));
    }

    // ---- Create ------------------------------------------------------------------------------

    private static async Task<(object Controller, IActionResult Result)> CreateAsync(SshNode node, string name = "Fleet SSH", string keyType = "ed25519")
    {
        var cache = NewCache();
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{node.Actor.UserId}:{StepUpOps.CreateSshCa}", token);
        var controller = AdminController(node, node.Service, cache);
        return (controller, await Call(controller, "GenerateCaKey",
            Body("ModularCA.API.Controllers.v1.Admin.GenerateSshCaKeyRequest", ("Name", name), ("KeyType", keyType)), token));
    }

    [Fact]
    public async Task Creating_an_ssh_ca_answers_503_while_the_signer_is_locked_or_predates_the_ssh_keystore()
    {
        using var lockedNode = new SshNode(unlocked: false);
        var locked = await CreateAsync(lockedNode);
        Assert.Contains("not unlocked", AssertUnavailable(locked.Controller, locked.Result));
        Assert.Empty(lockedNode.Db.SshCaKeys);

        using var olderNode = new SshNode();
        olderNode.Relay.RewriteSpec = spec => spec with { Usage = KeySpec.X509Usage };
        var older = await CreateAsync(olderNode);
        Assert.Contains("predates the SSH keystore and must be upgraded first", AssertUnavailable(older.Controller, older.Result, retry: false));
        Assert.Empty(olderNode.Db.SshCaKeys);

        using var node = new SshNode();
        var created = Assert.IsType<OkObjectResult>((await CreateAsync(node)).Result);
        Assert.Contains("ssh-ed25519 ", Json(created));
        Assert.Equal(400, Assert.IsType<BadRequestObjectResult>((await CreateAsync(node, "Another SSH", "dsa")).Result).StatusCode);
        Assert.True(Assert.Single(node.Audit.Of(AuditActionType.SshCaKeyCreated)).Success);
    }

    /// <summary>
    /// Executing a <c>CreateSshCa</c> ceremony hands the ceremony's id to the signer, which is
    /// what lets an instance that requires ceremonies have an SSH CA at all; a signer that cannot
    /// act leaves the ceremony approved, to be executed again.
    /// </summary>
    [Fact]
    public async Task Executing_an_ssh_ca_ceremony_names_the_ceremony_to_the_signer_and_survives_a_locked_signer()
    {
        using var node = new SshNode(requireKeyCeremony: true);
        var actor = node.Actor.UserId!.Value;
        var admins = new CaGroupEntity { Id = Guid.NewGuid(), Name = "system-admin", DisplayName = "System administrators", IsSystemGroup = true };
        node.Db.CaGroups.Add(admins);
        foreach (var capability in ModularCA.Shared.Authorization.Capabilities.AdministratorTemplate)
            node.Db.CapabilityGrants.Add(new CapabilityGrantEntity { GroupId = admins.Id, Capability = capability });
        node.Db.Users.Add(new UserEntity { Id = actor, Username = "ssh-operator", PasswordHash = "x" });
        node.Db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = admins.Id, UserId = actor });
        var ceremony = new KeyCeremonyEntity
        {
            Id = Guid.NewGuid(), OperationType = "CreateSshCa", Description = "Create SSH CA 'Fleet SSH'", Status = "Approved",
            InitiatedByUserId = actor, InitiatedByUsername = "ssh-operator", RequiredApprovals = 1, CurrentApprovals = 1,
            ExpiresAt = DateTime.UtcNow.AddHours(1), SpaceId = null,
            ParametersJson = JsonSerializer.Serialize(new ModularCA.Shared.Models.SshKeyCeremonyParameters
                { Name = "Fleet SSH", KeyType = "ed25519", IsUserCa = true, IsHostCa = true, MaxValidityHours = 24 }),
        };
        node.Db.KeyCeremonies.Add(ceremony);
        node.Db.SaveChanges();

        async Task<(object Controller, IActionResult Result)> Execute(ISshCaService service)
        {
            var cache = NewCache();
            var token = Guid.NewGuid().ToString("N");
            cache.SetString($"mfa-stepup:{actor}:{StepUpOps.ExecuteCeremony}:{ceremony.Id}", token);
            var audit = new RecordingAuditService();
            var controller = New("ModularCA.API.Controllers.v1.Admin.AdminKeyCeremonyController", actor,
                new KeyCeremonyService(node.Db, audit), new CurrentUserStub(actor), audit, cache, new RecordingAlertService(), null, node.Db,
                new CaGroupAuthorizationService(node.Db, NullLogger<CaGroupAuthorizationService>.Instance), service, null, null, null);
            return (controller, await Call(controller, "Execute", ceremony.Id, token));
        }

        var locked = await Execute(node.ServiceOver(Locked(node)));
        Assert.Contains("not unlocked", AssertUnavailable(locked.Controller, locked.Result));
        using (var db = node.Reopen())
        {
            Assert.Equal("Approved", db.KeyCeremonies.Single().Status);
            Assert.Empty(db.SshCaKeys);
        }

        var executed = await Execute(node.Service);
        Assert.IsType<OkObjectResult>(executed.Result);
        Assert.Equal(ceremony.Id, Assert.Single(node.Relay.Generated).Context.CeremonyId);
        Assert.Equal(ceremony.Id, Assert.Single(node.Relay.Committed).Context.CeremonyId);
        using (var db = node.Reopen())
        {
            Assert.Equal("Executed", db.KeyCeremonies.Single().Status);
            Assert.Equal(SshCaKeyStorage.Signer, db.SshCaKeys.Single().KeyStorage);
        }
        var created = node.Audit.Of(AuditActionType.SshCaKeyCreated).Single(a => a.Success);
        Assert.Equal(actor, created.ActorId);
        Assert.Contains(ceremony.Id.ToString(), JsonSerializer.Serialize(created.Details));
    }

    // ---- Lists and KRL -----------------------------------------------------------------------

    [Fact]
    public async Task The_admin_key_list_says_where_each_key_is_held_and_the_public_list_does_not()
    {
        using var node = new SshNode();
        var held = await node.CreateCaAsync("Fleet SSH");
        var legacy = node.SeedLegacyCa("Old SSH");
        var token = node.SeedLegacyCa("Token SSH");
        token.KeyStorage = SshCaKeyStorage.Pkcs11;
        token.PrivateKeyPath = null;
        node.Db.SaveChanges();

        var admin = JsonDocument.Parse(Json(await Call(AdminController(node, node.Service), "GetCaKeys"))).RootElement.EnumerateArray()
            .ToDictionary(k => k.GetProperty("Id").GetGuid(), k => k.GetProperty("KeyStorage").GetString());
        var publicList = Json(await Call(PublicController(node.Service), "ListCaKeys"));

        Assert.Equal("signer", admin[held.Id]);
        Assert.Equal("legacyFile", admin[legacy.Id]);
        Assert.Equal("pkcs11", admin[token.Id]);
        Assert.Contains(held.Id.ToString(), publicList);
        Assert.DoesNotContain("KeyStorage", publicList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("legacyFile", publicList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PrivateKeyPath", publicList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ssh-ca-keys", publicList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PrivateKeyPath", Json(await Call(AdminController(node, node.Service), "GetCaKeys")), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Both_krl_routes_answer_200_with_a_valid_krl_with_or_without_revocations_and_ask_no_signer()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var cert = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        var signer = new UnaskedSigner();
        var service = node.ServiceOver(signer);
        var admin = AdminController(node, service);
        var anonymous = PublicController(service);

        foreach (var controller in new[] { admin, anonymous })
        {
            var empty = Assert.IsType<FileContentResult>(await Call(controller, "DownloadKrl", ca.Id));
            Assert.Equal("application/octet-stream", empty.ContentType);
            Assert.Equal(SshKrl.Magic, new SshReader(empty.FileContents).UInt64());
            Assert.Equal(SshKrl.Encode(SshPublicKey.ParseAuthorizedKey(ca.PublicKey), [], 0, DateTimeOffset.UnixEpoch).Length, empty.FileContents.Length);
        }

        Assert.True(await service.RevokeCertificateAsync(cert.Id, ca.Id, node.Actor));
        foreach (var controller in new[] { admin, anonymous })
        {
            var listed = Assert.IsType<FileContentResult>(await Call(controller, "DownloadKrl", ca.Id));
            Assert.True(listed.FileContents.Length > 44);
        }

        Assert.IsType<NotFoundResult>(await Call(anonymous, "DownloadKrl", Guid.NewGuid()));
        Assert.Equal(0, signer.Calls);
    }

    /// <summary>Counts the calls a controller makes on the SSH CA service, by method name, and passes each on.</summary>
    public class CountingSshCaService : DispatchProxy
    {
        /// <summary>The service the calls go to.</summary>
        public ISshCaService Inner { get; set; } = null!;

        /// <summary>How often each method was called.</summary>
        public Dictionary<string, int> Calls { get; } = new();

        /// <inheritdoc />
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            Calls[targetMethod!.Name] = Calls.GetValueOrDefault(targetMethod.Name) + 1;
            return targetMethod.Invoke(Inner, args);
        }
    }

    /// <summary>One KRL request on a fresh controller: the answer and the headers it set.</summary>
    private static async Task<(IActionResult Result, IHeaderDictionary Headers)> KrlRequest(Func<object> route, Guid id, string? ifNoneMatch)
    {
        var controller = route();
        if (ifNoneMatch != null)
            HttpOf(controller).Request.Headers.IfNoneMatch = ifNoneMatch;
        return (await Call(controller, "DownloadKrl", id), HttpOf(controller).Response.Headers);
    }

    /// <summary>
    /// What makes the list cheap to poll: both routes send a strong ETag and
    /// <c>Cache-Control: no-cache</c>, and a request that names the current ETag is answered 304
    /// with no body and without the list being built. The ETag changes with a revocation and
    /// with nothing else.
    /// </summary>
    [Fact]
    public async Task Both_krl_routes_send_a_strong_etag_and_answer_304_to_a_request_that_names_it()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var cert = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);
        var service = node.ServiceOver(new UnaskedSigner());
        var counted = DispatchProxy.Create<ISshCaService, CountingSshCaService>();
        var counting = (CountingSshCaService)(object)counted;
        counting.Inner = service;
        Func<object>[] routes = [() => AdminController(node, counted), () => PublicController(counted)];
        int Built() => counting.Calls.GetValueOrDefault(nameof(ISshCaService.BuildKrlAsync));

        async Task<string> AssertConditionalAsync(Func<object> route)
        {
            var (first, headers) = await KrlRequest(route, ca.Id, null);
            var list = Assert.IsType<FileContentResult>(first).FileContents;
            var etag = headers.ETag.ToString();
            Assert.Matches("^\"[0-9a-f]{32}\"$", etag);
            Assert.Equal("no-cache", headers.CacheControl.ToString());
            Assert.Equal((await service.GetKrlStateAsync(ca.Id)).ETag, etag);

            var built = Built();
            foreach (var asked in new[] { etag, $"W/{etag}", $"\"an-older-list\", {etag}", "*" })
            {
                var (answer, answered) = await KrlRequest(route, ca.Id, asked);
                Assert.Equal(304, Assert.IsType<StatusCodeResult>(answer).StatusCode);
                Assert.Equal(etag, answered.ETag.ToString());
                Assert.Equal("no-cache", answered.CacheControl.ToString());
            }
            Assert.Equal(built, Built());

            foreach (var asked in new[] { "\"an-older-list\"", "not an entity tag", etag.Trim('"') })
            {
                var (answer, answered) = await KrlRequest(route, ca.Id, asked);
                Assert.Equal(list, Assert.IsType<FileContentResult>(answer).FileContents);
                Assert.Equal(etag, answered.ETag.ToString());
            }
            return etag;
        }

        var before = new List<string>();
        foreach (var route in routes)
            before.Add(await AssertConditionalAsync(route));
        Assert.Equal(before[0], before[1]);

        Assert.True(await service.RevokeCertificateAsync(cert.Id, ca.Id, node.Actor));

        foreach (var route in routes)
        {
            var (stale, headers) = await KrlRequest(route, ca.Id, before[0]);
            Assert.True(Assert.IsType<FileContentResult>(stale).FileContents.Length > 44);
            Assert.NotEqual(before[0], headers.ETag.ToString());
            Assert.Equal(headers.ETag.ToString(), await AssertConditionalAsync(route));
        }

        // A key that does not exist is answered as before, with or without the header, and names no ETag.
        var (missing, missingHeaders) = await KrlRequest(routes[1], Guid.NewGuid(), before[0]);
        Assert.IsType<NotFoundResult>(missing);
        Assert.Empty(missingHeaders.ETag.ToString());
        Assert.IsType<BadRequestObjectResult>((await KrlRequest(routes[0], Guid.NewGuid(), before[0])).Result);
        Assert.IsType<BadRequestObjectResult>((await KrlRequest(routes[0], Guid.NewGuid(), null)).Result);
    }

    [Fact]
    public async Task The_admin_key_list_says_what_each_key_s_krl_is_and_the_public_list_does_not()
    {
        using var node = new SshNode();
        var ca = await node.CreateCaAsync();
        var cert = await node.Service.SignUserKeyAsync(ca.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, node.Actor);

        async Task<JsonElement> KeyAsync()
            => JsonDocument.Parse(Json(await Call(AdminController(node, node.Service), "GetCaKeys"))).RootElement.EnumerateArray()
                .Single(k => k.GetProperty("Id").GetGuid() == ca.Id);

        var nothingRevoked = await KeyAsync();
        Assert.Equal(0UL, nothingRevoked.GetProperty("KrlVersion").GetUInt64());
        Assert.Equal(0, nothingRevoked.GetProperty("KrlRevokedCertificates").GetInt32());
        Assert.Equal(JsonValueKind.Null, nothingRevoked.GetProperty("KrlLastRevokedAt").ValueKind);

        var before = DateTime.UtcNow.AddSeconds(-1);
        Assert.True(await node.Service.RevokeCertificateAsync(cert.Id, ca.Id, node.Actor));

        var oneRevoked = await KeyAsync();
        Assert.Equal(1UL, oneRevoked.GetProperty("KrlVersion").GetUInt64());
        Assert.Equal(1, oneRevoked.GetProperty("KrlRevokedCertificates").GetInt32());
        Assert.InRange(oneRevoked.GetProperty("KrlLastRevokedAt").GetDateTime().ToUniversalTime(), before, DateTime.UtcNow.AddSeconds(1));

        var publicList = Json(await Call(PublicController(node.Service), "ListCaKeys"));
        Assert.DoesNotContain("KrlVersion", publicList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Revoked", publicList, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Removed -----------------------------------------------------------------------------

    [Fact]
    public void The_ssh_ca_settings_endpoint_and_section_are_gone()
    {
        var config = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminConfigController");
        var routes = config.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .SelectMany(m => m.GetCustomAttributesData())
            .SelectMany(a => a.ConstructorArguments)
            .Where(a => a.Value is string)
            .Select(a => (string)a.Value!)
            .ToList();

        Assert.Contains("metrics", routes);
        Assert.DoesNotContain("ssh-ca", routes);
        Assert.Null(config.GetMethod("UpdateSshCa"));
        Assert.Null(typeof(SystemConfig).GetProperty("SshCa"));
        Assert.Null(typeof(SystemConfig).Assembly.GetType("ModularCA.Shared.Models.Config.SshCaConfig"));
    }
}
