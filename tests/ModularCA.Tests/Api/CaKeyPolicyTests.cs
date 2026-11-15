using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Bootstrap;
using ModularCA.Core.Authorization;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A new CA's RSA key is at least 3072 bits on every path that creates a CA key: the admin API
/// directly and through a ceremony, the service behind them, the setup wizard and bootstrap.yaml,
/// and SSH CA keys. RSA 3072 and ECDSA are accepted on the same paths. A CA that already has an
/// RSA 2048 key keeps issuing and carries a notice.
/// </summary>
public sealed class CaKeyPolicyTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    // ── The rule ────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("RSA", 2048)]
    [InlineData("rsa", 2048)]
    [InlineData(" RSA ", 1024)]
    public void An_rsa_key_under_3072_bits_is_refused_with_why_and_what_to_pick(string algorithm, int bits)
    {
        var refusal = CaKeyPolicy.RefusalForNewCa(algorithm, bits);

        Assert.NotNull(refusal);
        Assert.Contains("at least 3072 bits", refusal);
        Assert.Contains("SP 800-57", refusal);
        Assert.Contains("2030", refusal);
        Assert.Contains("RSA 3072 or 4096, or ECDSA P-384", refusal);
        Assert.Equal(refusal, CaKeyPolicy.RefusalForNewCa(algorithm, bits.ToString()));
    }

    [Theory]
    [InlineData("RSA", 3072)]
    [InlineData("RSA", 4096)]
    [InlineData("RSA", 8192)]
    [InlineData("ECDSA", 256)]
    [InlineData("ECDSA", 384)]
    [InlineData("Ed25519", 0)]
    [InlineData("ML-DSA-65", 0)]
    public void Larger_rsa_keys_and_every_other_algorithm_are_not(string algorithm, int size)
    {
        Assert.Null(CaKeyPolicy.RefusalForNewCa(algorithm, size));
    }

    // ── The admin API: directly, and through a ceremony ─────────────────────────────────────

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static IDistributedCache NewCache() => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static string StepUp(IDistributedCache cache, Guid actor, string op)
    {
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{op}", token);
        return token;
    }

    private static CaCreationService CaCreation(SingleAdminWorld w)
        => new(w.Db, null!, null!, null!, null!, new SystemConfig(), NullLogger<CaCreationService>.Instance, null!);

    private static object New(SingleAdminWorld w, string typeName, Guid actor, params object?[] args)
    {
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(typeName), args)!;
        var controlled = new ControlledUserCeremonyService(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), null!, NullLogger<ControlledUserCeremonyService>.Instance);
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
            RequestServices = new ServiceCollection()
                .AddSingleton<ICurrentUserService>(new CurrentUserStub(actor))
                .AddSingleton<IControlledUserCeremonyService>(controlled)
                .BuildServiceProvider(),
        };
        http.Items["IsSystemAdmin"] = true;
        SpaceFence.Store(http, SpaceFence.Of([], instanceScope: true, isSystemAdmin: true));
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });
        return controller;
    }

    private static async Task<IActionResult> Call(object controller, string method, params object?[] args)
        => await (Task<IActionResult>)controller.GetType()
            .GetMethod(method, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.Invoke(controller, args)!;

    private static object Body(string typeName, params (string Name, object? Value)[] props)
    {
        var body = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + typeName))!;
        foreach (var (name, value) in props)
            body.GetType().GetProperty(name)!.SetValue(body, value);
        return body;
    }

    private static object CaController(SingleAdminWorld w)
        => New(w, Ns + "AdminCaController", w.Admin,
            null, new CurrentUserStub(w.Admin), w.Db, new RecordingAuditService(), CaCreation(w), NewCache(), new RecordingAlertService(),
            new CaGroupAuthorizationService(w.Db, NullLogger<CaGroupAuthorizationService>.Instance),
            new KeyCeremonyService(w.Db, new RecordingAuditService()), null, null);

    private static Task<IActionResult> Initiate(SingleAdminWorld w, string operation, KeyCeremonyParameters parameters)
    {
        var cache = NewCache();
        var audit = new RecordingAuditService();
        var controller = New(w, Ns + "AdminKeyCeremonyController", w.Admin,
            new KeyCeremonyService(w.Db, audit), new CurrentUserStub(w.Admin), audit, cache, new RecordingAlertService(), CaCreation(w), w.Db,
            new CaGroupAuthorizationService(w.Db, NullLogger<CaGroupAuthorizationService>.Instance), null, null,
            new SpacePolicyChangeService(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), NullLogger<SpacePolicyChangeService>.Instance),
            new ControlledUserCeremonyService(w.Db, new KeyCeremonyService(w.Db, new RecordingAuditService()), null!, NullLogger<ControlledUserCeremonyService>.Instance));
        var request = Body("InitiateCeremonyRequest", ("OperationType", operation), ("Description", "key rule"), ("Parameters", parameters));
        return Call(controller, "Initiate", request, StepUp(cache, w.Admin, StepUpOps.InitiateCeremony));
    }

    private static Task<IActionResult> Ssh(SingleAdminWorld w, string keyType, int? keySize)
    {
        var cache = NewCache();
        var controller = New(w, Ns + "AdminSshController", w.Admin,
            null, new CurrentUserStub(w.Admin), w.Db, new SystemConfig(),
            new KeyCeremonyService(w.Db, new RecordingAuditService()), cache, null, null, null);
        return Call(controller, "GenerateCaKey",
            Body("GenerateSshCaKeyRequest", ("Name", "Fleet SSH"), ("KeyType", keyType), ("KeySize", keySize)),
            StepUp(cache, w.Admin, StepUpOps.CreateSshCa));
    }

    /// <summary>
    /// Each path of the admin API that asks for a new CA key, as a call with the key it asks for.
    /// The world requires a key ceremony and has a second approver, so an accepted request opens a
    /// ceremony (no key is generated in these tests) and a refused one opens none.
    /// </summary>
    private static readonly Dictionary<string, Func<SingleAdminWorld, string, int, Task<IActionResult>>> Paths = new()
    {
        ["create-root"] = (w, algorithm, size) => Call(CaController(w), "CreateRoot",
            Body("CreateRootCaRequest", ("SubjectCN", "Second Root"), ("SpaceId", (Guid?)w.Space), ("KeyAlgorithm", algorithm), ("KeySize", size))),
        ["create-root (instance)"] = (w, algorithm, size) => Call(CaController(w), "CreateRoot",
            Body("CreateRootCaRequest", ("SubjectCN", "Instance Root"), ("Scope", "instance"), ("KeyAlgorithm", algorithm), ("KeySize", size))),
        ["create-intermediate"] = (w, algorithm, size) => Call(CaController(w), "CreateIntermediate",
            Body("CreateIntermediateCaRequest", ("SubjectCN", "Issuing CA"), ("SpaceId", (Guid?)w.Space), ("ParentCaId", w.Ca), ("KeyAlgorithm", algorithm), ("KeySize", size))),
        ["ceremony: CreateRootCA"] = (w, algorithm, size) => Initiate(w, "CreateRootCA",
            new KeyCeremonyParameters { SubjectCN = "Ceremony Root", KeyAlgorithm = algorithm, KeySize = size, ValidityYears = 10, SpaceId = w.Space }),
        ["ceremony: CreateIntermediateCA"] = (w, algorithm, size) => Initiate(w, "CreateIntermediateCA",
            new KeyCeremonyParameters { SubjectCN = "Ceremony Sub", KeyAlgorithm = algorithm, KeySize = size, ValidityYears = 5, SpaceId = w.Space, ParentCaId = w.Ca }),
        ["ssh-ca create"] = (w, algorithm, size) => Ssh(w, algorithm.ToLowerInvariant(), size),
    };

    public static TheoryData<string> PathNames() => new(Paths.Keys);

    [Theory]
    [MemberData(nameof(PathNames))]
    public async Task An_rsa_2048_ca_is_refused_on_every_api_path_before_any_ceremony_opens(string path)
    {
        var w = new SingleAdminWorld();
        w.User("second", w.SystemAdminGroup);

        var refused = Assert.IsType<BadRequestObjectResult>(await Paths[path](w, "RSA", 2048));

        var message = JsonSerializer.Serialize(refused.Value);
        Assert.Contains("at least 3072 bits", message);
        Assert.Contains("ECDSA P-384", message);
        Assert.Empty(w.Db.KeyCeremonies);
        Assert.Single(w.Db.CertificateAuthorities);
    }

    [Theory]
    [MemberData(nameof(PathNames))]
    public async Task An_rsa_3072_and_an_ecdsa_ca_are_accepted_on_every_api_path(string path)
    {
        foreach (var (algorithm, size) in new[] { ("RSA", 3072), ("ECDSA", 384) })
        {
            var w = new SingleAdminWorld();
            w.User("second", w.SystemAdminGroup);

            var accepted = Assert.IsType<OkObjectResult>(await Paths[path](w, algorithm, size));

            Assert.Equal("Pending", (await w.Db.KeyCeremonies.AsNoTracking().SingleAsync()).Status);
            Assert.DoesNotContain("3072 bits", JsonSerializer.Serialize(accepted.Value));
        }
    }

    [Fact]
    public async Task An_ssh_ca_key_defaults_to_rsa_3072_when_no_size_is_given()
    {
        var w = new SingleAdminWorld();
        w.User("second", w.SystemAdminGroup);

        Assert.IsType<OkObjectResult>(await Ssh(w, "rsa", null));
    }

    // ── The service behind the API: where an approved ceremony is executed ──────────────────

    [Fact]
    public async Task The_creation_service_refuses_rsa_2048_before_it_generates_a_key()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();

        var root = await Assert.ThrowsAsync<ArgumentException>(() => w.Creation.CreateRootAsync(
            "Small Root", "Acme", null, null, null, "US", "RSA", 2048, 5, null, w.SpaceId));
        Assert.Contains("at least 3072 bits", root.Message);

        var parent = await w.CreateRootAsync("Parent Root", null, null);
        var intermediate = await Assert.ThrowsAsync<ArgumentException>(() => w.Creation.CreateIntermediateAsync(
            parent, w.Db.Certificates.Single(c => c.CertificateId == parent.CertificateId),
            "Small Sub", "Acme", null, null, null, "US", "RSA", 2048, 2, null, w.SpaceId));
        Assert.Contains("at least 3072 bits", intermediate.Message);

        Assert.DoesNotContain(w.Db.CertificateAuthorities.Select(c => c.Name).ToList(), name => name.StartsWith("Small", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_creation_service_creates_rsa_3072_and_ecdsa_cas()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();

        var rsa = await w.Creation.CreateRootAsync("Rsa Root", "Acme", null, null, null, "US", "RSA", 3072, 5, null, w.SpaceId);
        var ecdsa = await w.Creation.CreateRootAsync("Ecdsa Root", "Acme", null, null, null, "US", "ECDSA", 384, 5, null, w.SpaceId);
        var sub = await w.Creation.CreateIntermediateAsync(
            ecdsa, w.Db.Certificates.Single(c => c.CertificateId == ecdsa.CertificateId),
            "Rsa Sub", "Acme", null, null, null, "US", "RSA", 3072, 2, null, w.SpaceId);

        Assert.Equal(3072, CaKeyPolicy.RsaBitsOf(w.Db.Certificates.Single(c => c.CertificateId == rsa.CertificateId)));
        Assert.Equal(3072, CaKeyPolicy.RsaBitsOf(w.Db.Certificates.Single(c => c.CertificateId == sub.CertificateId)));
        Assert.Null(CaKeyPolicy.RsaBitsOf(w.Db.Certificates.Single(c => c.CertificateId == ecdsa.CertificateId)));
        Assert.All(new[] { rsa, ecdsa, sub }, ca =>
            Assert.Empty(CaKeyPolicy.Advisories(w.Db.Certificates.Single(c => c.CertificateId == ca.CertificateId))));
    }

    // ── An existing RSA 2048 CA ─────────────────────────────────────────────────────────────

    /// <summary>
    /// A CA as an install made before 0.4.5 may hold one. It is made on the path that skips the
    /// key rule, which the API cannot reach, so the rule itself is not loosened for the test.
    /// </summary>
    [Fact]
    public async Task An_existing_rsa_2048_ca_still_issues_and_carries_its_notice()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var old = await w.Creation.CreateRootWithoutKeyRuleAsync(
            "Old Rsa Root", "Acme", null, null, null, "US", "RSA", 2048, 5, null, w.SpaceId);
        var certificate = w.Db.Certificates.Single(c => c.CertificateId == old.CertificateId);
        Assert.Equal(2048, CaKeyPolicy.RsaBitsOf(certificate));

        var issued = await w.IssueLeafAsync(old, "CN=still-issued.acme.test", []);

        var leaf = CertificateUtil.ParseFromPem(issued.Pem);
        leaf.Verify(CertificateUtil.ParseFromPem(certificate.Pem).GetPublicKey());
        Assert.IsType<RsaKeyParameters>(CertificateUtil.ParseFromPem(certificate.Pem).GetPublicKey());

        var advisory = Assert.Single(CaKeyPolicy.Advisories(certificate));
        Assert.Equal(CaKeyPolicy.RsaKeyBelow3072, advisory.Reason);
        Assert.Contains("RSA 2048", advisory.Message);
        Assert.Contains("before 2031", advisory.Message);
        Assert.Contains("creating a new CA now", advisory.Message);
        Assert.Contains("keeps working", advisory.Message);
    }

    [Fact]
    public void A_ca_whose_certificate_cannot_be_read_gets_no_notice()
    {
        Assert.Empty(CaKeyPolicy.Advisories(null));
        Assert.Empty(CaKeyPolicy.Advisories(new CertificateEntity { Pem = "not a certificate" }));
        Assert.Empty(CaKeyPolicy.AdvisoriesForRsa(3072));
        Assert.Single(CaKeyPolicy.AdvisoriesForRsa(2048));
    }

    /// <summary>The CA feed the console reads puts the notice on each CA, and the SSH key list on each key.</summary>
    [Theory]
    [InlineData("AdminCaController.cs", "KeyAdvisories = CaKeyPolicy.Advisories(ca.Certificate)")]
    [InlineData("AdminSshController.cs", "ModularCA.Shared.Utils.CaKeyPolicy.AdvisoriesForRsa(rsaBits)")]
    public void The_feeds_the_console_reads_carry_the_notice(string file, string source)
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "Controllers", "v1", "Admin", file));

        Assert.Contains(source, text);
    }

    // ── The setup wizard and bootstrap.yaml ─────────────────────────────────────────────────

    [Fact]
    public void Bootstrap_refuses_an_rsa_2048_root_and_accepts_rsa_3072_and_ecdsa()
    {
        var refused = Assert.Throws<ConfigurationValidationException>(() => BootstrapCertCreator.EnsureRootKeyAcceptable("RSA", 2048));
        Assert.Contains("at least 3072 bits", refused.Message);
        Assert.StartsWith("The root CA key:", refused.Message);

        BootstrapCertCreator.EnsureRootKeyAcceptable("RSA", 3072);
        BootstrapCertCreator.EnsureRootKeyAcceptable("RSA", 4096);
        BootstrapCertCreator.EnsureRootKeyAcceptable("ECDSA", 384);
        BootstrapCertCreator.EnsureRootKeyAcceptable("Ed25519", 0);
    }

    [Theory]
    [InlineData("2048", true)]
    [InlineData("3072", false)]
    [InlineData("4096", false)]
    [InlineData(null, false)]   // no size given: the default is now 3072, not 2048
    [InlineData("", false)]
    public void The_wizard_s_rsa_key_size_is_refused_only_at_2048(string? keySize, bool refused)
    {
        var bits = SetupKeySizeParser.ParseToInt("RSA", keySize);

        Assert.Equal(refused, CaKeyPolicy.RefusalForNewCa("RSA", bits) != null);
        if (string.IsNullOrEmpty(keySize)) Assert.Equal(3072, bits);
    }

    /// <summary>
    /// Both bootstrap paths ask before any setup work: the wizard endpoint (400) and
    /// bootstrap.yaml, beside the root label check; the wizard's service asks again where the
    /// key is requested.
    /// </summary>
    [Theory]
    [InlineData("ModularCA.API/Controllers/v1/SetupController.cs", "EnsureRootLabelUsable(request.RootCa.CommonName);", "BootstrapCertCreator.EnsureRootKeyAcceptable(")]
    [InlineData("ModularCA.Bootstrap/BootstrapModularCA.cs", "EnsureRootLabelUsable(bootstrapConfig.CA.Subject.CN ?? \"ModularCA\");", "BootstrapCertCreator.EnsureRootKeyAcceptable(bootstrapConfig.CA.Algorithm, bootstrapConfig.CA.KeySize);")]
    [InlineData("ModularCA.Bootstrap/BootstrapService.cs", "SetupKeySizeParser.ParseToInt(request.RootCa.Algorithm, request.RootCa.KeySize);", "BootstrapCertCreator.EnsureRootKeyAcceptable(rootCaAlgorithm, rootCaKeySizeInt);")]
    public void Each_bootstrap_path_checks_the_root_key_before_it_is_made(string relative, string after, string check)
    {
        var text = File.ReadAllText(Path.Combine(RepoRoot(), relative.Replace('/', Path.DirectorySeparatorChar)));
        var anchor = text.IndexOf(after, StringComparison.Ordinal);
        var asked = text.IndexOf(check, StringComparison.Ordinal);
        var made = text.IndexOf("BootstrapCertCreator.CreateSelfSignedCertificate(", StringComparison.Ordinal);

        Assert.True(anchor > 0 && asked > anchor, $"{relative} must call {check} after {after}");
        Assert.True(made < 0 || asked < made, $"{relative} must check the root key before it creates the certificate");
    }

    [Fact]
    public void The_example_bootstrap_file_passes_the_rule()
    {
        var config = YamlBootstrapLoader.Load(Path.Combine(RepoRoot(), "config", "bootstrap.yaml.example"));

        BootstrapCertCreator.EnsureRootKeyAcceptable(config.CA.Algorithm, config.CA.KeySize);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
