using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Api;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// From 0.4.0 S4 a CA label (compared without regard to case) and a CA name are unique across the
/// instance, soft-deleted CAs included, on every path that names a CA: creation, UpdateCa, SSH CA
/// creation and bootstrap's wizard.
/// </summary>
public class CaNamingTests
{
    private static ModularCADbContext Seeded()
    {
        var db = InMemoryDbContextFactory.Create();
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Acme Root CA", Label = "acme-root", SpaceId = Guid.NewGuid() },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Old CA", Label = "old-ca", SpaceId = null, IsDeleted = true });
        db.SaveChanges();
        return db;
    }

    [Theory]
    [InlineData("Acme-Root")]
    [InlineData("system-root")]
    [InlineData("org-root")]
    [InlineData("space-root")]
    [InlineData("-root")]
    [InlineData("")]
    public void An_invalid_or_reserved_label_is_refused(string label)
        => Assert.Throws<ArgumentException>(() => CaLabelRules.Validate(label));

    [Fact]
    public void Bootstrap_may_use_a_reserved_label() => CaLabelRules.Validate("system-signing-ca", allowReserved: true);

    [Theory]
    [InlineData("acme-root", null)]
    [InlineData("ACME-ROOT", null)]
    [InlineData("old-ca", null)]
    [InlineData(null, "Acme Root CA")]
    [InlineData(null, "Old CA")]
    public async Task A_label_or_name_another_ca_has_or_had_is_a_conflict(string? label, string? name)
    {
        using var db = Seeded();
        var ex = await Assert.ThrowsAsync<ResourceConflictException>(() => CaLabelRules.EnsureUniqueAsync(db, label, name));
        Assert.Equal(ErrorCodes.NameAlreadyTaken, ex.Code);
    }

    [Fact]
    public async Task A_ca_keeping_its_own_label_is_not_a_conflict()
    {
        using var db = Seeded();
        var own = db.CertificateAuthorities.Single(c => c.Label == "acme-root");
        await CaLabelRules.EnsureUniqueAsync(db, "acme-root", "Acme Root CA", exceptCaId: own.Id);
        await CaLabelRules.EnsureUniqueAsync(db, "fresh", "Fresh CA");
    }

    /// <summary>
    /// UpdateCa validates a new label (400 for uppercase or a reserved prefix) and refuses a label
    /// or name another CA has, a deleted one included, with 409; nothing is changed.
    /// </summary>
    [Theory]
    [InlineData("Other", null, 400)]
    [InlineData("system-other", null, 400)]
    [InlineData("acme-root", null, 409)]
    [InlineData("old-ca", null, 409)]
    [InlineData(null, "Old CA", 409)]
    [InlineData(null, "Acme Root CA", 409)]
    [InlineData("renamed", "Renamed CA", 200)]
    public async Task UpdateCa_enforces_the_label_rules(string? label, string? name, int expected)
    {
        using var db = Seeded();
        var target = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Target CA", Label = "target", SpaceId = Guid.NewGuid() };
        db.CertificateAuthorities.Add(target);
        db.SaveChanges();

        var result = await UpdateCaAsync(db, target.Id, label, name);

        Assert.Equal(expected, Status(result));
        Assert.Equal(expected == 200 ? "renamed" : "target", db.CertificateAuthorities.Single(c => c.Id == target.Id).Label);
    }

    /// <summary>
    /// A CA that has issued a certificate, under its current or a superseded certificate, or as a
    /// legacy row with no issuer link whose issuer DN is the CA's subject, keeps its
    /// label (409 <see cref="ErrorCodes.CaLabelLocked"/>): the label is in that certificate's CRL,
    /// OCSP and AIA URLs. Its name may still change, and a CA that has issued nothing may be
    /// relabelled (<see cref="UpdateCa_enforces_the_label_rules"/>).
    /// </summary>
    [Theory]
    [InlineData("current", "relabelled", null, 409)]
    [InlineData("superseded", "relabelled", null, 409)]
    [InlineData("none", "relabelled", null, 200)]
    [InlineData("legacy", "relabelled", null, 409)]
    [InlineData("unrelated-legacy", "relabelled", null, 200)]
    [InlineData("current", null, "Renamed Issuer", 200)]
    public async Task A_ca_that_has_issued_keeps_its_label(string issuedUnder, string? label, string? name, int expected)
    {
        using var db = InMemoryDbContextFactory.Create();
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string Pem(int ageDays)
        {
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Issuer CA", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-ageDays - 1), DateTimeOffset.UtcNow.AddDays(365 - ageDays));
            return cert.ExportCertificatePem();
        }
        CertificateEntity CaCert(int ageDays)
        {
            var c = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"), SubjectDN = "CN=Issuer CA", Issuer = "CN=Issuer CA", Pem = Pem(ageDays), IsCA = true };
            c.IssuerCertificateId = c.CertificateId;
            db.Certificates.Add(c);
            return c;
        }
        var current = CaCert(0);
        var superseded = CaCert(300);
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Issuer CA", Label = "issuer", SpaceId = Guid.NewGuid(), CertificateId = current.CertificateId };
        db.CertificateAuthorities.Add(ca);
        if (issuedUnder != "none")
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"), SubjectDN = "CN=leaf",
                Issuer = issuedUnder == "unrelated-legacy" ? "CN=Other CA" : "CN=Issuer CA", Pem = "x",
                IssuerCertificateId = issuedUnder switch { "current" => current.CertificateId, "superseded" => superseded.CertificateId, _ => null },
            });
        db.SaveChanges();

        Assert.Equal(issuedUnder is "current" or "superseded" or "legacy", await ModularCA.Core.Helpers.IssuerChainResolver.HasIssuedAsync(db, ca.Id));
        var result = await UpdateCaAsync(db, ca.Id, label, name);

        Assert.Equal(expected, Status(result));
        if (expected == 409)
        {
            Assert.Contains("CRL, OCSP and AIA", System.Text.Json.JsonSerializer.Serialize(((ObjectResult)result).Value));
            Assert.Equal("issuer", db.CertificateAuthorities.Single(c => c.Id == ca.Id).Label);
        }
    }

    /// <summary>
    /// A label may change only while nothing references it: not an ACME account bound to the CA
    /// or registered under the label, an ACME order placed under it or by such an account, or a
    /// protocol audit record naming it (any case). Each is a 409 <see cref="ErrorCodes.CaLabelLocked"/>
    /// naming the reference, and the label stays. Before, only issued certificates locked it, so
    /// a label ACME clients and the audit trail still named could be changed and then taken by
    /// another CA.
    /// </summary>
    [Theory]
    [InlineData("none", 200, null)]
    [InlineData("acme-account", 409, "ACME accounts")]
    [InlineData("acme-account-by-label", 409, "ACME accounts")]
    [InlineData("acme-order", 409, "ACME orders")]
    [InlineData("audit-est", 409, "protocol audit records (EST)")]
    [InlineData("audit-acme", 409, "protocol audit records (ACME)")]
    [InlineData("audit-other-ca", 200, null)]
    public async Task A_referenced_label_is_fixed(string reference, int expected, string? named)
    {
        using var db = InMemoryDbContextFactory.Create();
        using var audit = NewAuditDb();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Target CA", Label = "target" };
        db.CertificateAuthorities.Add(ca);
        var account = new AcmeAccountEntity { JwkJson = "{}", JwkThumbprint = "t" };
        switch (reference)
        {
            case "acme-account": account.CertificateAuthorityId = ca.Id; db.AcmeAccounts.Add(account); break;
            case "acme-account-by-label": account.CaLabel = "target"; db.AcmeAccounts.Add(account); break;
            case "acme-order": db.AcmeOrders.Add(new AcmeOrderEntity { AccountId = Guid.NewGuid(), CaLabel = "Target" }); break;
            case "audit-est": audit.AuditEst.Add(new AuditEstEntity { Operation = "simpleenroll", CaLabel = "TARGET" }); break;
            case "audit-acme": audit.AuditAcme.Add(new AuditAcmeEntity { Operation = "OrderCreated", CaLabel = "target" }); break;
            case "audit-other-ca": audit.AuditScep.Add(new AuditScepEntity { Operation = "PKIOperation", CaLabel = "targets" }); break;
        }
        db.SaveChanges();
        audit.SaveChanges();

        var result = await UpdateCaAsync(db, ca.Id, "relabelled", null, audit);

        Assert.Equal(expected, Status(result));
        Assert.Equal(expected == 200 ? "relabelled" : "target", db.CertificateAuthorities.Single(c => c.Id == ca.Id).Label);
        if (named != null)
        {
            var body = System.Text.Json.JsonSerializer.Serialize(((ObjectResult)result).Value);
            Assert.Contains(named, body);
            Assert.Contains(ErrorCodes.CaLabelLocked, body);
        }
    }

    private static AuditDbContext NewAuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase($"audit-{Guid.NewGuid():N}").Options);

    private static int Status(IActionResult result) => result switch { ObjectResult o => o.StatusCode ?? 200, StatusCodeResult s => s.StatusCode, _ => 0 };

    /// <summary>
    /// Invokes the real <c>AdminCaController.UpdateCa</c> on <paramref name="caId"/> as a fresh
    /// operator, with <paramref name="auditDb"/> as the audit database (an empty one when null).
    /// </summary>
    private static async Task<IActionResult> UpdateCaAsync(ModularCADbContext db, Guid caId, string? label, string? name, AuditDbContext? auditDb = null)
    {
        var user = new UserEntity { Id = Guid.NewGuid(), Username = $"op-{Guid.NewGuid():N}", Email = "op@x" };
        db.Users.Add(user);
        db.SaveChanges();
        var services = new SpaceIsolationMatrixTests.Resolver(db);
        services.Add(typeof(ModularCA.Auth.Interfaces.ICurrentUserService), new CurrentUser(db, user.Id));
        services.Add(typeof(AuditDbContext), auditDb ?? NewAuditDb());
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminCaController");
        var controller = ActivatorUtilities.CreateInstance(services, type);
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", user.Id.ToString())], "test")), RequestServices = services };
        type.GetProperty("ControllerContext")!.SetValue(controller, new ControllerContext { HttpContext = http });
        var request = Activator.CreateInstance(ApiAssembly.Instance.GetTypes().Single(t => t.Name == "UpdateCaRequest"))!;
        request.GetType().GetProperty("Label")!.SetValue(request, label);
        request.GetType().GetProperty("Name")!.SetValue(request, name);
        return await (Task<IActionResult>)type.GetMethod("UpdateCa")!.Invoke(controller, [caId, request])!;
    }

    /// <summary>
    /// A unique violation on CertificateAuthorities, a label or name raced past the pre-check, is
    /// recognised so callers answer 409; one on another table, or another error, is not.
    /// </summary>
    [Fact]
    public void A_lost_label_race_is_recognised_as_a_conflict()
    {
        DbUpdateException Wrap(string sqlState, string table) => new("save failed",
            new Npgsql.PostgresException("duplicate key", "ERROR", "ERROR", sqlState, tableName: table, constraintName: "IX_CertificateAuthorities_LabelLower"));
        Assert.True(CaLabelRules.IsNameRace(Wrap("23505", "CertificateAuthorities")));
        Assert.False(CaLabelRules.IsNameRace(Wrap("23505", "CaGroups")));
        Assert.False(CaLabelRules.IsNameRace(Wrap("23503", "CertificateAuthorities")));
        Assert.Equal(ErrorCodes.NameAlreadyTaken, CaLabelRules.NameRaceConflict("x", "X").Code);
    }

    /// <summary>
    /// Bootstrap and the setup wizard refuse a root CA common name whose label would be invalid or
    /// reserved, before anything is built, with a message naming the label.
    /// </summary>
    [Theory]
    [InlineData("System Root", false)]
    [InlineData("Org Root", false)]
    [InlineData("Ünïcode Root", false)]
    [InlineData("Acme Root CA", true)]
    public void The_root_ca_common_name_must_give_a_usable_label(string commonName, bool usable)
    {
        var ex = Record.Exception(() => ModularCA.Bootstrap.BootstrapCertCreator.EnsureRootLabelUsable(commonName));
        if (usable)
            Assert.Null(ex);
        else
            Assert.Contains(ModularCA.Bootstrap.BootstrapCertCreator.LabelFor(commonName), Assert.IsType<ConfigurationValidationException>(ex).Message);
    }

    /// <summary>
    /// An intermediate's CA certificate profile must be unbound, bound to the parent (a space root,
    /// or an instance root above a space intermediate), or space-wide in the new CA's space; any
    /// other reads as not found, like a missing one or a leaf profile.
    /// </summary>
    [Theory]
    [InlineData("unbound", true)]
    [InlineData("own-space", true)]
    [InlineData("bound-to-parent", true)]
    [InlineData("bound-to-instance-parent", true)]
    [InlineData("other-space", false)]
    [InlineData("own-space-other-ca", false)]
    [InlineData("instance-ca-bound", false)]
    [InlineData("leaf", false)]
    [InlineData("missing", false)]
    public async Task An_intermediates_ca_profile_must_be_in_scope(string scope, bool admitted)
    {
        using var db = InMemoryDbContextFactory.Create();
        var space = Guid.NewGuid();
        var parent = Guid.NewGuid();
        var profile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "ca", IsCaProfile = scope != "leaf", KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        (profile.SpaceId, profile.CertificateAuthorityId) = scope switch
        {
            "own-space" => ((Guid?)space, (Guid?)null),
            "bound-to-parent" => (space, parent),
            "bound-to-instance-parent" => (null, parent),
            "other-space" => (Guid.NewGuid(), null),
            "own-space-other-ca" => (space, Guid.NewGuid()),
            "instance-ca-bound" => (null, Guid.NewGuid()),
            _ => (null, null),
        };
        if (scope != "missing")
            db.CertProfiles.Add(profile);
        db.SaveChanges();
        var creation = (CaCreationService)new SpaceIsolationMatrixTests.Resolver(db).GetService(typeof(CaCreationService))!;

        var ex = await Record.ExceptionAsync(() => creation.EnsureCaCertProfileAdmittedAsync(profile.Id, parent, space));

        if (admitted)
            Assert.Null(ex);
        else
            Assert.Equal(ErrorCodes.ResourceNotFound, Assert.IsType<ResourceNotFoundException>(ex).Code);
    }

    /// <summary>
    /// A new CA's default protocol configurations take the first leaf profile, by name, that
    /// CertProfileScope admits for it, never another space's or one bound to another CA.
    /// </summary>
    [Fact]
    public async Task The_default_protocol_profile_is_the_first_admitted_by_name()
    {
        using var db = InMemoryDbContextFactory.Create();
        var space = Guid.NewGuid();
        var ca = Guid.NewGuid();
        db.CertProfiles.AddRange(
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "a-other-space", SpaceId = Guid.NewGuid(), KeyUsages = "[]", ExtendedKeyUsages = "[]" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "b-other-ca", SpaceId = space, CertificateAuthorityId = Guid.NewGuid(), KeyUsages = "[]", ExtendedKeyUsages = "[]" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "c-ca-profile", IsCaProfile = true, KeyUsages = "[]", ExtendedKeyUsages = "[]" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "e-unbound", KeyUsages = "[]", ExtendedKeyUsages = "[]" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "d-own-space", SpaceId = space, KeyUsages = "[]", ExtendedKeyUsages = "[]" });
        db.SaveChanges();

        Assert.Equal("d-own-space", (await CaCreationService.DefaultLeafProfileAsync(db, ca, space))!.Name);
        Assert.Equal("e-unbound", (await CaCreationService.DefaultLeafProfileAsync(db, ca, null))!.Name);
    }

    [Theory]
    [InlineData("Acme Root", typeof(ResourceConflictException))]
    [InlineData("old ca", typeof(ResourceConflictException))]
    [InlineData("System Thing", typeof(ArgumentException))]
    [InlineData("bad/name", typeof(ArgumentException))]
    public async Task An_ssh_ca_is_refused_a_taken_or_invalid_label_before_any_key_is_generated(string name, Type refusal)
    {
        using var db = Seeded();
        var config = new SystemConfig();
        config.SshCa.SshKeygenPath = "does-not-exist";
        var service = new SshCaService(db, config, NullLogger<SshCaService>.Instance);
        var ex = await Record.ExceptionAsync(() => service.GenerateKeyPairAsync(name, "ed25519", true, false, 24));
        Assert.IsType(refusal, ex);
        Assert.Equal(2, db.CertificateAuthorities.IgnoreQueryFilters().Count());
    }

    /// <summary>The label-less default never picks an SSH CA or a reserved system- CA.</summary>
    [Fact]
    public async Task The_default_ca_fallback_skips_ssh_and_system_cas()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "SSH", Label = "ssh", IsSshCa = true, IsEnabled = true, IsDefault = true },
            new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Sys", Label = "system-signing-ca", IsEnabled = true, IsDefault = true });
        db.SaveChanges();
        var resolver = new CaResolverService(db);
        Assert.Null(await resolver.ResolveCaEntityAsync(null));

        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Root", Label = "root", IsEnabled = true });
        db.SaveChanges();
        Assert.Equal("root", (await resolver.ResolveCaEntityAsync(null))!.Label);
    }

    [Theory]
    [InlineData("ModularCA System Signing CA", true)]
    [InlineData("System Signing CA", true)]
    [InlineData("Acme Root CA", false)]
    public void The_setup_wizard_refuses_a_root_name_the_system_signing_ca_takes(string commonName, bool clashes)
    {
        var method = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.SetupController").GetMethod("RootCaNameClashesWithSystemCa")!;
        Assert.Equal(clashes, (bool)method.Invoke(null, [commonName])!);
    }

    private sealed class CurrentUser(ModularCADbContext db, Guid id) : ModularCA.Auth.Interfaces.ICurrentUserService
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
}
