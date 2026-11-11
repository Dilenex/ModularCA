using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Authorization;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using static ModularCA.Tests.Api.SpaceIsolationMatrixTests;

namespace ModularCA.Tests.Api;

/// <summary>
/// The lists the self-service request form fills its pickers from
/// (<c>GET /api/v1/user/signing-profiles</c>, <c>GET /api/v1/user/request-profiles</c> with the
/// certificate profiles each row names) hold what the caller could submit a request against, and
/// nothing else. The measure is the submission itself: every combination of signing, request and
/// certificate profile is put to the real <c>[RequireCaCapability]</c> filter of the submit
/// actions and then uploaded through the real action, and the lists must equal what was taken.
/// A requester (<c>cert.request</c> and <c>cert.view</c> on one CA) used to get an empty signing
/// profile list, because the list asked for a <c>profile.*</c> capability the submission never
/// asks for.
/// </summary>
public sealed class SelfServiceProfileListTests
{
    private const string Controller = "User.UserCertSignRequestController";

    /// <summary>The matrix world with a second CA in space A and one profile for each way a profile can be placed.</summary>
    private sealed class Rig
    {
        public World W { get; } = new();
        public Guid CaA2 { get; } = Guid.NewGuid();
        public Guid SigningA2 { get; } = Guid.NewGuid();
        public Guid SigningUnbound { get; } = Guid.NewGuid();
        public Guid SigningOrphan { get; } = Guid.NewGuid();
        public Guid CertA2Bound { get; } = Guid.NewGuid();
        public Guid RequestA2 { get; } = Guid.NewGuid();
        public Guid RequestUnbound { get; } = Guid.NewGuid();
        public Guid RequestUnboundBare { get; } = Guid.NewGuid();
        public Guid RequestInstanceRoot { get; } = Guid.NewGuid();
        public Dictionary<string, Guid> Users { get; } = new();

        public Rig()
        {
            var db = W.Db;
            var a2Certificate = Guid.NewGuid();
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = CaA2, Name = "a second", Label = "a-second", SpaceId = W.A.SpaceId, CertificateId = a2Certificate, Type = "Root", IsEnabled = true });
            db.SigningProfiles.AddRange(
                new SigningProfileEntity { Id = SigningA2, Name = "a2-signing", IssuerId = a2Certificate },
                new SigningProfileEntity { Id = SigningUnbound, Name = "unbound-signing" },
                new SigningProfileEntity { Id = SigningOrphan, Name = "orphan-signing", IssuerId = Guid.NewGuid() });
            db.CertProfiles.Add(new CertProfileEntity { Id = CertA2Bound, Name = "a2-bound", SpaceId = W.A.SpaceId, CertificateAuthorityId = CaA2, KeyUsages = "[]", ExtendedKeyUsages = "[]" });

            // Each request profile names certificate profiles of its own CA and of others, so the
            // names a row offers have something to leave out.
            Designate(db.RequestProfiles.Single(p => p.Id == W.A.RequestProfile), W.A.BoundProfile, W.B.BoundProfile, W.UnboundProfile, CertA2Bound, W.A.SpaceProfile);
            Designate(db.RequestProfiles.Single(p => p.Id == W.B.RequestProfile), W.B.SpaceProfile, W.A.SpaceProfile);
            db.RequestProfiles.AddRange(
                Designate(new RequestProfileEntity { Id = RequestA2, Name = "a2-request", CertificateAuthorityId = CaA2 }, CertA2Bound, W.A.BoundProfile),
                Designate(new RequestProfileEntity { Id = RequestUnbound, Name = "unbound-request" },
                    W.UnboundProfile, W.A.BoundProfile, W.A.SpaceProfile, W.B.SpaceProfile, W.B.BoundProfile, CertA2Bound, W.Instance.BoundProfile),
                new RequestProfileEntity { Id = RequestUnboundBare, Name = "unbound-bare-request" },
                Designate(new RequestProfileEntity { Id = RequestInstanceRoot, Name = "instance-root-request", CertificateAuthorityId = W.Instance.Root }, W.UnboundProfile));

            var requesterA = W.Group("a-requester", W.A.SpaceId, W.A.CaId, Capabilities.RequesterTemplate);
            var requesterA2 = W.Group("a2-requester", W.A.SpaceId, CaA2, Capabilities.RequesterTemplate);
            var requesterB = W.Group("b-requester", W.B.SpaceId, W.B.CaId, Capabilities.RequesterTemplate);
            var operatorA = W.Group("a-operator", W.A.SpaceId, W.A.CaId, Capabilities.OperatorTemplate);
            var auditorA = W.Group("a-auditor", W.A.SpaceId, W.A.CaId, Capabilities.AuditorTemplate);
            var spaceRequesterA = W.Group("space-a-requester", W.A.SpaceId, null, Capabilities.RequesterTemplate);
            var systemAdmin = W.Group("system-admin", null, null, Capabilities.AdministratorTemplate, system: true);
            var systemRequester = W.Group("system-requester", null, null, Capabilities.RequesterTemplate, system: true);
            db.SaveChanges();

            Users["requester of A"] = W.User("req-a", requesterA);
            Users["requester of A2"] = W.User("req-a2", requesterA2);
            Users["requester of B"] = W.User("req-b", requesterB);
            Users["requester of A and of B"] = W.User("req-a-b", requesterA, requesterB);
            Users["operator of A"] = W.User("op-a", operatorA);
            Users["auditor of A"] = W.User("aud-a", auditorA);
            Users["auditor of A and requester of B"] = W.User("aud-a-req-b", auditorA, requesterB);
            Users["requester across space A"] = W.User("req-space-a", spaceRequesterA);
            Users["in no group"] = W.User("nobody");
            Users["system administrator"] = W.User("sys-admin", systemAdmin);
            Users["requester at system scope"] = W.User("sys-requester", systemRequester);

            var grantedOnA = W.User("grant-a");
            db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity { UserId = grantedOnA, Capability = Capabilities.CertRequest, CertificateAuthorityId = W.A.CaId });
            Users["cert.request granted on A, no group"] = grantedOnA;

            // profile.use on A's signing profile by name, and no cert.request on A: the grant the
            // list used to follow. Submission refuses it, so the list must not offer it.
            var profileGrant = W.User("req-b-profile-a", requesterB);
            db.UserCapabilityGrants.Add(new UserCapabilityGrantEntity
            {
                UserId = profileGrant, Capability = Capabilities.ProfileUse, ResourceType = "SigningProfile", ResourceId = W.A.SigningProfile,
            });
            Users["requester of B with profile.use on A's signing profile"] = profileGrant;
            db.SaveChanges();
        }

        private static RequestProfileEntity Designate(RequestProfileEntity profile, Guid first, params Guid[] others)
        {
            profile.DefaultCertProfileId = first;
            profile.AllowedCertProfileIds = JsonSerializer.Serialize(others);
            return profile;
        }

        public List<Guid> SigningProfiles() => W.Db.SigningProfiles.Select(p => p.Id).ToList();
        public List<Guid> RequestProfiles() => W.Db.RequestProfiles.Select(p => p.Id).ToList();
        public List<Guid> LeafCertProfiles() => W.Db.CertProfiles.Where(p => !p.IsCaProfile).Select(p => p.Id).ToList();
    }

    public static TheoryData<string> Callers()
    {
        var data = new TheoryData<string>();
        foreach (var caller in new Rig().Users.Keys)
            data.Add(caller);
        return data;
    }

    private static readonly string Csr = CsrPem("CN=host.example");

    private static string CsrPem(string subject)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()),
            new X509Name(subject), keys.Public, null);
        using var sw = new StringWriter();
        new PemWriter(sw).WriteObject(csr);
        return sw.ToString();
    }

    /// <summary>A set of ids in one fixed order, so two sets compare as text.</summary>
    private static string Ids(IEnumerable<Guid> ids) => string.Join(",", ids.Distinct().Order());

    /// <summary>The signing profile list as <paramref name="user"/>: its status and the ids it holds.</summary>
    private static async Task<(int Status, List<Guid> Ids)> SigningListAsync(Rig r, Guid user)
    {
        var (status, body) = await SendAsync(r.W, user, Get("User.UserSigningProfileController", "GetSigningProfiles", "/api/v1/user/signing-profiles"));
        return (status, status == 200 ? JsonDocument.Parse(body).RootElement.EnumerateArray().Select(e => e.GetProperty("Id").GetGuid()).ToList() : []);
    }

    /// <summary>The request profile list as <paramref name="user"/>: its status, and per row the certificate profiles it names.</summary>
    private static async Task<(int Status, Dictionary<Guid, List<Guid>> Rows)> RequestListAsync(Rig r, Guid user)
    {
        var (status, body) = await SendAsync(r.W, user, Get("User.UserRequestProfileController", "GetAccessibleRequestProfiles", "/api/v1/user/request-profiles"));
        var rows = status != 200 ? [] : JsonDocument.Parse(body).RootElement.EnumerateArray().ToDictionary(
            e => e.GetProperty("Id").GetGuid(),
            e => e.GetProperty("CertProfiles").EnumerateArray().Select(c => c.GetProperty("Id").GetGuid()).ToList());
        return (status, rows);
    }

    /// <summary>
    /// Whether the <c>[RequireCaCapability]</c> filter the real submit action carries lets
    /// <paramref name="user"/> through for <paramref name="body"/>. The matrix harness evaluates
    /// policies and runs actions; it does not run action filters, so the filter is run here.
    /// </summary>
    private static async Task<bool> FilterAllowsAsync(Rig r, Guid user, string action, object body)
    {
        var claims = new List<Claim> { new("sub", user.ToString()), new(ClaimTypes.NameIdentifier, user.ToString()) };
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
        http.Request.Method = "POST";
        var accessor = new HttpContextAccessor { HttpContext = http };
        var services = new Resolver(r.W.Db, r.W.Cache);
        services.Add(typeof(ICaGroupAuthorizationService), new CaGroupAuthorizationService(
            r.W.Db, NullLogger<CaGroupAuthorizationService>.Instance, null, accessor, new AccessBadgeContext(r.W.Db, accessor)));
        http.RequestServices = services;

        var method = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1." + Controller).GetMethod(action)!;
        var filters = method.GetCustomAttributes(true).OfType<ActionFilterAttribute>()
            .Where(a => a.GetType().Name == "RequireCaCapabilityAttribute").ToList();
        Assert.Single(filters);
        var arguments = new Dictionary<string, object?> { [method.GetParameters()[0].Name!] = body };
        var executing = new ActionExecutingContext(new ActionContext(http, new RouteData(), new ActionDescriptor()), [], arguments, new object());
        var reached = false;
        await filters[0].OnActionExecutionAsync(executing, () =>
        {
            reached = true;
            return Task.FromResult(new ActionExecutedContext(executing, [], new object()));
        });
        return reached;
    }

    /// <summary>
    /// Whether <paramref name="user"/> can submit a request naming these three profiles: the
    /// filter of each submit action lets them through (the three must agree), and the real upload
    /// action stores the request. A refusal by the request profile or the certificate profile's
    /// scope is a submission that was not taken.
    /// </summary>
    private static async Task<bool> SubmitsAsync(Rig r, Guid user, Guid signing, Guid request, Guid cert)
    {
        var upload = new UploadCsrRequest { Pem = Csr, SigningProfileId = signing, CertificateProfileId = cert, RequestProfileId = request };
        var allowed = await FilterAllowsAsync(r, user, "UploadCsrRequest", upload);
        Assert.Equal(allowed, await FilterAllowsAsync(r, user, "Generate", new CreateCsrRequest { SigningProfileId = signing }));
        Assert.Equal(allowed, await FilterAllowsAsync(r, user, "RequestWithServerKey", new IssueWithKeyRequest { SigningProfileId = signing }));
        if (!allowed)
            return false;
        try
        {
            var (status, body) = await SendAsync(r.W, user, Send("POST", Controller, "UploadCsrRequest", "/api/v1/user/requests/upload", ("request", upload)));
            Assert.True(status == 200, $"upload answered {status}: {body}");
            return true;
        }
        catch (ConfigurationValidationException)
        {
            return false;
        }
    }

    /// <summary>Every (signing, request, certificate) profile combination the caller can submit.</summary>
    private static async Task<List<(Guid Signing, Guid Request, Guid Cert)>> SubmittableAsync(Rig r, Guid user)
    {
        var taken = new List<(Guid, Guid, Guid)>();
        foreach (var signing in r.SigningProfiles())
            foreach (var request in r.RequestProfiles())
                foreach (var cert in r.LeafCertProfiles())
                    if (await SubmitsAsync(r, user, signing, request, cert))
                        taken.Add((signing, request, cert));
        return taken;
    }

    /// <summary>
    /// For every kind of caller: the signing profile list is exactly the signing profiles some
    /// submission of theirs is taken against; no request profile outside the list can be
    /// submitted under; and each listed request profile names exactly the certificate profiles a
    /// submission under it is taken with. A caller the lists refuse (403) can submit nothing.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public async Task The_lists_hold_what_the_caller_can_submit_against_and_nothing_else(string caller)
    {
        var r = new Rig();
        var user = r.Users[caller];
        var (signingStatus, signing) = await SigningListAsync(r, user);
        var (requestStatus, requests) = await RequestListAsync(r, user);
        var taken = await SubmittableAsync(r, user);

        Assert.Equal(signingStatus, requestStatus);
        if (signingStatus == 403)
        {
            Assert.Empty(taken);
            return;
        }
        Assert.Equal(200, signingStatus);

        Assert.Equal(Ids(taken.Select(t => t.Signing)), Ids(signing));

        var submittableRequests = taken.Select(t => t.Request).ToHashSet();
        Assert.True(submittableRequests.IsSubsetOf(requests.Keys), $"{caller}: a request profile that takes a submission is missing from the list");
        foreach (var (request, certProfiles) in requests)
        {
            Assert.Equal(Ids(taken.Where(t => t.Request == request).Select(t => t.Cert)), Ids(certProfiles));
            // The one row the list keeps that takes no submission: a profile the caller's CA goes
            // with, which names no certificate profile they can use. The form says so.
            if (!submittableRequests.Contains(request))
                Assert.Empty(certProfiles);
        }
    }

    /// <summary>A CA as the signing profile list names it on a row.</summary>
    private sealed record ListedCa(Guid Id, string? Name, Guid? SpaceId);

    /// <summary>A nullable id property of a list row; a JSON null is null.</summary>
    private static Guid? GuidOrNull(JsonElement row, string name)
        => row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetGuid();

    /// <summary>The signing profile list as <paramref name="user"/>, each row with the CA it names (null for none).</summary>
    private static async Task<List<(Guid Id, ListedCa? Ca)>> SigningRowsAsync(Rig r, Guid user)
    {
        var (status, body) = await SendAsync(r.W, user, Get("User.UserSigningProfileController", "GetSigningProfiles", "/api/v1/user/signing-profiles"));
        if (status != 200)
            return [];
        return JsonDocument.Parse(body).RootElement.EnumerateArray().Select(e =>
        {
            var caId = GuidOrNull(e, "CaId");
            if (caId == null)
            {
                Assert.Equal(JsonValueKind.Null, e.GetProperty("CaName").ValueKind);
                Assert.Equal(JsonValueKind.Null, e.GetProperty("CaSpaceId").ValueKind);
            }
            return (e.GetProperty("Id").GetGuid(),
                caId is Guid id ? new ListedCa(id, e.GetProperty("CaName").GetString(), GuidOrNull(e, "CaSpaceId")) : null);
        }).ToList();
    }

    /// <summary>A request profile row as the form reads it: the CA it is bound to and the scope of each certificate profile it names.</summary>
    private sealed record ListedRequestProfile(Guid Id, Guid? CaId, List<(Guid Id, Guid? SpaceId, Guid? CaId)> CertProfiles);

    /// <summary>The request profile list as <paramref name="user"/>, with the fields the form filters on.</summary>
    private static async Task<List<ListedRequestProfile>> RequestRowsAsync(Rig r, Guid user)
    {
        var (status, body) = await SendAsync(r.W, user, Get("User.UserRequestProfileController", "GetAccessibleRequestProfiles", "/api/v1/user/request-profiles"));
        if (status != 200)
            return [];
        return JsonDocument.Parse(body).RootElement.EnumerateArray().Select(e => new ListedRequestProfile(
            e.GetProperty("Id").GetGuid(),
            GuidOrNull(e, "CertificateAuthorityId"),
            e.GetProperty("CertProfiles").EnumerateArray()
                .Select(c => (c.GetProperty("Id").GetGuid(), GuidOrNull(c, "SpaceId"), GuidOrNull(c, "CertificateAuthorityId")))
                .ToList())).ToList();
    }

    /// <summary>
    /// The request form's CA picker, measured against the submission. The form reads only the two
    /// lists; for the CA chosen it offers the signing profiles whose row names that CA, the
    /// request profiles bound to it or to none, and of each one's certificate profiles those whose
    /// own scope the CA admits (<c>modularca.adminui/src/pages/requestCaPicker.ts</c>, whose rules
    /// are written out again here rather than called, so a change to either side shows). For
    /// every caller and every CA their signing rows name, that must be exactly the combinations a
    /// real submission against that CA's signing profiles is taken with. A signing profile with no
    /// issuer is not in the form; its row names no CA.
    /// </summary>
    [Theory]
    [MemberData(nameof(Callers))]
    public async Task For_each_ca_the_form_offers_exactly_what_a_submission_against_it_takes(string caller)
    {
        var r = new Rig();
        var user = r.Users[caller];
        var signing = await SigningRowsAsync(r, user);
        var requests = await RequestRowsAsync(r, user);
        var taken = await SubmittableAsync(r, user);

        // The CA each signing profile issues from, read from the database as submission reads it.
        var liveCas = r.W.Db.CertificateAuthorities.Where(c => c.CertificateId != null).ToList();
        var issuingCa = r.W.Db.SigningProfiles.ToList().ToDictionary(
            p => p.Id,
            p => p.IssuerId == null ? null : liveCas.FirstOrDefault(c => c.CertificateId == p.IssuerId));

        foreach (var (id, ca) in signing)
        {
            Assert.Equal(issuingCa[id]?.Id, ca?.Id);
            Assert.Equal(issuingCa[id]?.Name, ca?.Name);
            Assert.Equal(issuingCa[id]?.SpaceId, ca?.SpaceId);
        }

        foreach (var ca in signing.Where(s => s.Ca != null).Select(s => s.Ca!).Distinct())
        {
            var offered = new List<(Guid Signing, Guid Request, Guid Cert)>();
            foreach (var s in signing.Where(s => s.Ca?.Id == ca.Id))
                foreach (var request in requests.Where(q => q.CaId == null || q.CaId == ca.Id))
                    foreach (var cert in request.CertProfiles.Where(c =>
                        (c.SpaceId == null && c.CaId == null) || (c.SpaceId == ca.SpaceId && (c.CaId == null || c.CaId == ca.Id))))
                        offered.Add((s.Id, request.Id, cert.Id));

            var submitted = taken.Where(t => issuingCa[t.Signing]?.Id == ca.Id).ToList();
            Assert.True(offered.Order().SequenceEqual(submitted.Order()),
                $"{caller}, CA {ca.Name}: the form offers [{string.Join(" ", offered.Order())}], submission takes [{string.Join(" ", submitted.Order())}]");
        }
    }

    /// <summary>
    /// A requester of two CAs: each signing row names its own CA, each CA-bound request profile
    /// its CA, and the unbound request profile, offered for both, carries certificate profiles of
    /// both, told apart by their scope fields.
    /// </summary>
    [Fact]
    public async Task The_rows_carry_the_ca_and_the_scope_the_form_filters_on()
    {
        var r = new Rig();
        var user = r.Users["requester of A and of B"];
        var signing = (await SigningRowsAsync(r, user)).ToDictionary(s => s.Id, s => s.Ca);
        Assert.Equal(r.W.A.CaId, signing[r.W.A.SigningProfile]!.Id);
        Assert.Equal(r.W.A.SpaceId, signing[r.W.A.SigningProfile]!.SpaceId);
        Assert.Equal(r.W.B.CaId, signing[r.W.B.SigningProfile]!.Id);
        Assert.Equal(r.W.B.SpaceId, signing[r.W.B.SigningProfile]!.SpaceId);
        Assert.False(string.IsNullOrEmpty(signing[r.W.A.SigningProfile]!.Name));

        var requests = (await RequestRowsAsync(r, user)).ToDictionary(q => q.Id);
        Assert.Equal(r.W.A.CaId, requests[r.W.A.RequestProfile].CaId);
        Assert.Equal(r.W.B.CaId, requests[r.W.B.RequestProfile].CaId);
        Assert.Null(requests[r.RequestUnbound].CaId);

        var unbound = requests[r.RequestUnbound].CertProfiles.ToDictionary(c => c.Id);
        Assert.Equal(((Guid?)r.W.A.SpaceId, (Guid?)r.W.A.CaId), (unbound[r.W.A.BoundProfile].SpaceId, unbound[r.W.A.BoundProfile].CaId));
        Assert.Equal(((Guid?)r.W.B.SpaceId, (Guid?)null), (unbound[r.W.B.SpaceProfile].SpaceId, unbound[r.W.B.SpaceProfile].CaId));
        Assert.Equal(((Guid?)null, (Guid?)null), (unbound[r.W.UnboundProfile].SpaceId, unbound[r.W.UnboundProfile].CaId));
    }

    /// <summary>At system scope the signing profile with no issuer is listed and names no CA, so the form leaves it out.</summary>
    [Fact]
    public async Task The_signing_profile_with_no_issuer_names_no_ca()
    {
        var r = new Rig();
        var signing = (await SigningRowsAsync(r, r.Users["system administrator"])).ToDictionary(s => s.Id, s => s.Ca);
        Assert.Null(signing[r.SigningUnbound]);
        Assert.NotNull(signing[r.W.A.SigningProfile]);
    }

    /// <summary>The bug: a requester of one CA is offered that CA's signing profile, and no other CA's.</summary>
    [Fact]
    public async Task A_requester_is_offered_the_signing_profiles_of_their_ca_and_no_other()
    {
        var r = new Rig();
        var (status, signing) = await SigningListAsync(r, r.Users["requester of A"]);
        Assert.Equal(200, status);
        Assert.Equal(Ids([r.W.A.SigningProfile]), Ids(signing));

        Assert.Equal(Ids([r.SigningA2]), Ids((await SigningListAsync(r, r.Users["requester of A2"])).Ids));
        Assert.Equal(Ids([r.W.B.SigningProfile]), Ids((await SigningListAsync(r, r.Users["requester of B"])).Ids));
        Assert.Equal(Ids([r.W.A.SigningProfile, r.W.B.SigningProfile]), Ids((await SigningListAsync(r, r.Users["requester of A and of B"])).Ids));
        Assert.Equal(Ids([r.W.A.SigningProfile, r.SigningA2]), Ids((await SigningListAsync(r, r.Users["requester across space A"])).Ids));
        Assert.Equal(Ids([r.W.A.SigningProfile]), Ids((await SigningListAsync(r, r.Users["cert.request granted on A, no group"])).Ids));
    }

    /// <summary>
    /// A requester's request profiles: their CA's and the unbound ones, each naming only the
    /// certificate profiles their CA admits. A sibling CA's request profile, one of another
    /// space, and one of a CA with no signing profile are not offered.
    /// </summary>
    [Fact]
    public async Task A_requester_is_offered_the_request_profiles_their_ca_goes_with()
    {
        var r = new Rig();
        var (status, rows) = await RequestListAsync(r, r.Users["requester of A"]);
        Assert.Equal(200, status);
        Assert.Equal(Ids([r.W.A.RequestProfile, r.RequestUnbound, r.RequestUnboundBare]), Ids(rows.Keys));
        Assert.Equal(Ids([r.W.A.BoundProfile, r.W.UnboundProfile, r.W.A.SpaceProfile]), Ids(rows[r.W.A.RequestProfile]));
        Assert.Equal(Ids([r.W.UnboundProfile, r.W.A.BoundProfile, r.W.A.SpaceProfile]), Ids(rows[r.RequestUnbound]));
        Assert.Empty(rows[r.RequestUnboundBare]);
        // The default certificate profile leads the names, as the form takes the first.
        Assert.Equal(r.W.A.BoundProfile, rows[r.W.A.RequestProfile][0]);
    }

    /// <summary>
    /// An operator holds <c>cert.request</c> on their CA and is offered what a requester of it is.
    /// They are no longer offered a signing profile with no issuer: a submission naming it is
    /// refused below system scope.
    /// </summary>
    [Fact]
    public async Task An_operator_is_offered_what_a_requester_of_the_same_ca_is()
    {
        var r = new Rig();
        var requester = r.Users["requester of A"];
        var op = r.Users["operator of A"];
        Assert.Equal(Ids((await SigningListAsync(r, requester)).Ids), Ids((await SigningListAsync(r, op)).Ids));
        Assert.Equal(Ids((await RequestListAsync(r, requester)).Rows.Keys), Ids((await RequestListAsync(r, op)).Rows.Keys));
        Assert.DoesNotContain(r.SigningUnbound, (await SigningListAsync(r, op)).Ids);
    }

    /// <summary>
    /// An auditor holds <c>cert.view</c> and <c>profile.view</c> and no <c>cert.request</c>: both
    /// lists refuse them, as every submission does. With a requester role on another CA they are
    /// offered that CA's profiles and none of the CA they audit, whose group they are a member of.
    /// </summary>
    [Fact]
    public async Task An_auditor_is_offered_nothing_of_the_ca_they_audit()
    {
        var r = new Rig();
        Assert.Equal(403, (await SigningListAsync(r, r.Users["auditor of A"])).Status);
        Assert.Equal(403, (await RequestListAsync(r, r.Users["auditor of A"])).Status);

        var mixed = r.Users["auditor of A and requester of B"];
        Assert.Equal(Ids([r.W.B.SigningProfile]), Ids((await SigningListAsync(r, mixed)).Ids));
        Assert.Equal(Ids([r.W.B.RequestProfile, r.RequestUnbound, r.RequestUnboundBare]), Ids((await RequestListAsync(r, mixed)).Rows.Keys));
    }

    /// <summary>An account in no group is refused both lists.</summary>
    [Fact]
    public async Task An_account_in_no_group_is_refused_both_lists()
    {
        var r = new Rig();
        Assert.Equal(403, (await SigningListAsync(r, r.Users["in no group"])).Status);
        Assert.Equal(403, (await RequestListAsync(r, r.Users["in no group"])).Status);
    }

    /// <summary>A <c>profile.use</c> grant naming a signing profile does not put it in the list: submission asks for <c>cert.request</c> on its CA.</summary>
    [Fact]
    public async Task A_profile_grant_without_cert_request_on_the_ca_offers_nothing()
    {
        var r = new Rig();
        var user = r.Users["requester of B with profile.use on A's signing profile"];
        Assert.Equal(Ids([r.W.B.SigningProfile]), Ids((await SigningListAsync(r, user)).Ids));
        Assert.False(await SubmitsAsync(r, user, r.W.A.SigningProfile, r.RequestUnbound, r.W.UnboundProfile));
    }

    /// <summary>
    /// At system scope: every CA's signing profiles and the one with no issuer, which only system
    /// scope may name. A signing profile whose issuer is no CA is offered to nobody.
    /// </summary>
    [Theory]
    [InlineData("system administrator")]
    [InlineData("requester at system scope")]
    public async Task System_scope_is_offered_every_ca_and_the_profile_with_no_issuer(string caller)
    {
        var r = new Rig();
        var (status, signing) = await SigningListAsync(r, r.Users[caller]);
        Assert.Equal(200, status);
        Assert.Equal(Ids([r.W.A.SigningProfile, r.W.B.SigningProfile, r.SigningA2, r.SigningUnbound]), Ids(signing));
        var rows = (await RequestListAsync(r, r.Users[caller])).Rows;
        Assert.Equal(Ids([r.W.A.RequestProfile, r.W.B.RequestProfile, r.RequestA2, r.RequestUnbound, r.RequestUnboundBare]), Ids(rows.Keys));
    }

    /// <summary>A deleted CA's signing profile and request profile are offered to nobody, its requester and a system administrator included.</summary>
    [Fact]
    public async Task A_deleted_cas_profiles_are_not_offered()
    {
        var r = new Rig();
        r.W.Db.CertificateAuthorities.Single(c => c.Id == r.CaA2).IsDeleted = true;
        r.W.Db.SaveChanges();

        foreach (var caller in new[] { "requester of A2", "requester across space A", "system administrator" })
        {
            var (status, signing) = await SigningListAsync(r, r.Users[caller]);
            Assert.True(status is 200 or 403, $"{caller}: {status}");
            Assert.DoesNotContain(r.SigningA2, signing);
            Assert.DoesNotContain(r.RequestA2, (await RequestListAsync(r, r.Users[caller])).Rows.Keys);
        }
    }

    /// <summary>A CA certificate profile a request profile names is not among the names a row offers.</summary>
    [Fact]
    public async Task A_ca_certificate_profile_is_never_offered()
    {
        var r = new Rig();
        var profile = r.W.Db.RequestProfiles.Single(p => p.Id == r.W.A.RequestProfile);
        profile.AllowedCertProfileIds = JsonSerializer.Serialize(new[] { r.W.A.CaProfile, r.W.A.SpaceProfile });
        r.W.Db.SaveChanges();

        var rows = (await RequestListAsync(r, r.Users["requester of A"])).Rows;
        Assert.Equal(Ids([r.W.A.BoundProfile, r.W.A.SpaceProfile]), Ids(rows[r.W.A.RequestProfile]));
    }

    /// <summary>
    /// The set form of the submit check answers as the check itself does, profile by profile, for
    /// every caller: <see cref="BodyTargetAuthorization.AllowedSigningProfileIdsAsync"/> against
    /// <see cref="BodyTargetAuthorization.IsAllowedAsync"/>, a deleted CA included.
    /// </summary>
    [Fact]
    public async Task The_set_form_of_the_submit_check_agrees_with_the_check()
    {
        var r = new Rig();
        var deleted = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "gone", Label = "gone", SpaceId = r.W.A.SpaceId, CertificateId = Guid.NewGuid(), Type = "Root", IsDeleted = true };
        r.W.Db.CertificateAuthorities.Add(deleted);
        r.W.Db.SigningProfiles.Add(new SigningProfileEntity { Id = Guid.NewGuid(), Name = "gone-signing", IssuerId = deleted.CertificateId });
        r.Users["requester of a deleted CA"] = r.W.User("req-gone", r.W.Group("gone-requester", r.W.A.SpaceId, deleted.Id, Capabilities.RequesterTemplate));
        r.W.Db.SaveChanges();
        // A request never has the deleted CA tracked; left tracked here, FindAsync would hand it
        // back past the query filter that hides it.
        r.W.Db.Entry(deleted).State = Microsoft.EntityFrameworkCore.EntityState.Detached;

        var auth = new CaGroupAuthorizationService(r.W.Db, NullLogger<CaGroupAuthorizationService>.Instance);
        var resolver = new CaTargetResolver(r.W.Db);
        foreach (var (caller, user) in r.Users)
        {
            var set = await BodyTargetAuthorization.AllowedSigningProfileIdsAsync(auth, r.W.Db, user, Capabilities.CertRequest);
            foreach (var signing in r.SigningProfiles())
            {
                var one = await BodyTargetAuthorization.IsAllowedAsync(auth, resolver, user, Capabilities.CertRequest, CaTarget.SigningProfile, signing);
                Assert.True(one == set.Contains(signing), $"{caller}: the check says {one} for {signing}, the set says {set.Contains(signing)}");
            }
        }
    }
}
