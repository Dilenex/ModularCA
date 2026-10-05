using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Name constraints of every type (DNS, IP, email, URI, DN), permitted and excluded, end to end:
/// a CA carrying them is created through <see cref="CaCreationService"/> with the real
/// <see cref="CertificateIssuanceService"/> issuing its TSA and OCSP certificates (which used to
/// roll the creation back with MCA-CFG-011), then issues a conforming leaf, and refuses a
/// non-conforming one with <see cref="ErrorCodes.NameConstraintViolation"/>. A root's constraint
/// binds a certificate issued two levels below it.
/// </summary>
public sealed class NameConstraintIssuanceTests
{
    public static TheoryData<string, string?, string?, string, string[], string, string[], string> Cases => new()
    {
        // label, permitted, excluded, conforming subject, conforming SANs, refused subject, refused SANs, offending name
        { "DNS permitted .domain", "[\"DNS:.acme.test\"]", null, "CN=leaf", ["DNS:www.acme.test"], "CN=leaf", ["DNS:acme.test"], "acme.test" },
        { "DNS excluded", null, "[\"DNS:bad.acme.test\"]", "CN=leaf", ["DNS:good.acme.test"], "CN=leaf", ["DNS:x.bad.acme.test"], "x.bad.acme.test" },
        { "IPv4 permitted", "[\"IP:10.0.0.0/8\"]", null, "CN=leaf", ["IP:10.1.2.3"], "CN=leaf", ["IP:192.168.0.1"], "192.168.0.1" },
        { "IPv6 permitted", "[\"IP:2001:db8::/32\"]", null, "CN=leaf", ["IP:2001:db8::5"], "CN=leaf", ["IP:2001:db9::5"], "2001:db9::5" },
        { "IP excluded", null, "[\"IP:10.9.0.0/16\"]", "CN=leaf", ["IP:10.8.0.1"], "CN=leaf", ["IP:10.9.1.1"], "10.9.1.1" },
        { "email mailbox permitted", "[\"EMAIL:admin@acme.test\"]", null, "CN=leaf", ["EMAIL:admin@acme.test"], "CN=leaf", ["EMAIL:other@acme.test"], "other@acme.test" },
        { "email host permitted", "[\"EMAIL:acme.test\"]", null, "CN=leaf", ["EMAIL:x@acme.test"], "CN=leaf", ["EMAIL:x@sub.acme.test"], "x@sub.acme.test" },
        { "email .domain permitted", "[\"EMAIL:.acme.test\"]", null, "CN=leaf", ["EMAIL:x@sub.acme.test"], "CN=leaf", ["EMAIL:x@acme.test"], "x@acme.test" },
        { "email excluded, subject emailAddress", null, "[\"EMAIL:.evil.test\"]", "CN=leaf,E=x@acme.test", [], "CN=leaf,E=x@mail.evil.test", [], "x@mail.evil.test" },
        { "URI host permitted", "[\"URI:.acme.test\"]", null, "CN=leaf", ["URI:https://app.acme.test/x"], "CN=leaf", ["URI:https://app.other.test/"], "https://app.other.test/" },
        { "URI excluded", null, "[\"URI:bad.acme.test\"]", "CN=leaf", ["URI:https://good.acme.test/"], "CN=leaf", ["URI:https://bad.acme.test/p"], "https://bad.acme.test/p" },
        { "DN prefix permitted", "[\"DN:C=US,O=Acme\"]", null, "C=US,O=Acme,CN=leaf", ["DNS:leaf.acme.test"], "C=US,O=Other,CN=leaf", [], "O=Other" },
        { "DN prefix excluded", null, "[\"DN:C=US,O=Evil\"]", "C=US,O=Acme,CN=leaf", [], "C=US,O=Evil,OU=x,CN=leaf", [], "O=Evil" },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task A_constrained_ca_is_created_issues_a_conforming_leaf_and_refuses_another(
        string label, string? permitted, string? excluded, string okSubject, string[] okSans, string badSubject, string[] badSans, string offending)
    {
        var w = new IssuanceWorld();
        var root = await w.CreateRootAsync($"NC Root {label.GetHashCode():X}", permitted, excluded);
        Assert.NotNull(root.TsaCertificateId);
        Assert.NotNull(root.OcspResponderCertificateId);

        var pem = (await w.IssueLeafAsync(root, okSubject, okSans)).Pem;
        Assert.Contains("BEGIN CERTIFICATE", pem);

        var ex = await Assert.ThrowsAsync<CertificatePolicyViolationException>(() => w.IssueLeafAsync(root, badSubject, badSans));
        Assert.Equal(ErrorCodes.NameConstraintViolation, ex.Code);
        Assert.Contains(offending, ex.Message);
        Assert.Contains(root.Name, ex.Message);
    }

    /// <summary>
    /// The TSA and OCSP certificates of a CA permitted only a DN subtree are named inside it, or
    /// the CA could not issue them; the subject is the subtree followed by the CN.
    /// </summary>
    [Fact]
    public async Task A_dn_constrained_cas_infrastructure_certificates_are_named_inside_its_subtree()
    {
        var w = new IssuanceWorld();
        var root = await w.CreateRootAsync("DN Root", "[\"DN:C=US,O=Acme\"]", null);

        var tsa = w.Db.Certificates.Single(c => c.CertificateId == root.TsaCertificateId);
        Assert.Equal("C=US,O=Acme,CN=DN Root TSA", tsa.SubjectDN);
    }

    /// <summary>
    /// A root permitted <c>.acme.test</c> above an intermediate permitted the wider <c>.test</c>:
    /// the grandchild leaf is held to the root's subtree too, as path validation would hold it,
    /// and the refusal names the root. The intermediate's own TSA and OCSP certificates, issued
    /// on the CA creation path, pass the same check.
    /// </summary>
    [Fact]
    public async Task An_ancestors_constraint_binds_a_grandchild()
    {
        var w = new IssuanceWorld();
        var root = await w.CreateRootAsync("Ancestor Root", "[\"DNS:.acme.test\"]", null);
        var intermediate = await w.CreateIntermediateAsync(root, "Wide Sub", "[\"DNS:.test\"]", null);

        await w.IssueLeafAsync(intermediate, "CN=leaf", ["DNS:host.acme.test"]);

        var ex = await Assert.ThrowsAsync<CertificatePolicyViolationException>(
            () => w.IssueLeafAsync(intermediate, "CN=leaf", ["DNS:host.other.test"]));
        Assert.Equal(ErrorCodes.NameConstraintViolation, ex.Code);
        Assert.Contains("host.other.test", ex.Message);
        Assert.Contains("Ancestor Root", ex.Message);
        Assert.Contains("DNS:.acme.test", ex.Message);
    }

    /// <summary>
    /// An intermediate is itself checked against its parent's constraints when it is issued: one
    /// whose subject falls outside the parent's DN subtree is refused and nothing is created.
    /// </summary>
    [Fact]
    public async Task An_intermediate_outside_its_parents_dn_subtree_is_refused()
    {
        var w = new IssuanceWorld();
        var root = await w.CreateRootAsync("DN Parent", "[\"DN:C=US,O=Acme\"]", null);

        var ex = await Assert.ThrowsAsync<CertificatePolicyViolationException>(
            () => w.CreateIntermediateAsync(root, "Outsider Sub", null, null));
        Assert.Equal(ErrorCodes.NameConstraintViolation, ex.Code);
        Assert.DoesNotContain(w.Db.CertificateAuthorities, c => c.Name == "Outsider Sub");
    }

    /// <summary>
    /// Real CA creation and issuance over a signer-test world: in-memory database, the in-process
    /// signer, the real builder, store, validation, profile resolution and quota services; CT,
    /// certificate policy, CRL and service URLs are no-ops.
    /// </summary>
    internal sealed class IssuanceWorld
    {
        private readonly SignerTestWorld _world = SignerTestWorld.Create();
        public ModularCADbContext Db { get; }
        public CertificateIssuanceService Issuance { get; }
        public CaCreationService Creation { get; }
        public Guid LeafProfileId { get; }
        public Guid SpaceId => _world.SpaceA;

        /// <summary>The certificate policy issuance evaluates; a test adds violations to refuse.</summary>
        public ConfigurablePolicy Policy { get; } = new();

        public IssuanceWorld()
        {
            var signer = TestSigner.Over(_world.Keystore, _world.DatabaseName, _world.Persistence);
            Db = _world.OpenDb();
            BootstrapProfileSeeder.SeedBuiltInRoles(Db);
            CertProfileEntity Profile(string name, bool isCa = false) => new()
            {
                Name = name, IsCaProfile = isCa, KeyUsages = "[]", ExtendedKeyUsages = "[]",
                AllowedKeySizes = "[]", AllowedSignatureAlgorithms = "[]", ValidityPeriodMax = "P10Y",
            };
            var leaf = Profile("NC Leaf");
            Db.CertProfiles.AddRange(Profile("TSA Certificate Profile"), Profile("OCSP Responder Certificate Profile"),
                Profile("Main CA Certificate Profile", isCa: true), leaf);
            Db.SaveChanges();
            LeafProfileId = leaf.Id;

            Issuance = new CertificateIssuanceService(
                Db,
                keystore: new DbKeystore(Db),
                certStore: new CertificateStore(Db),
                validation: new IssuanceValidationService(Db, NullLogger<IssuanceValidationService>.Instance),
                builder: new CertificateBuilderService(new NoServiceUrls(), signer, NullLogger<CertificateBuilderService>.Instance),
                profileResolver: new ProfileResolutionService(Db, NullLogger<ProfileResolutionService>.Instance),
                ctSubmission: InstanceCeremonyEndpointTests.Fake<ICtSubmissionService>.Create(),
                certPolicy: Policy,
                quotaService: new QuotaService(Db, new RecordingAlertService(), NullLogger<QuotaService>.Instance),
                audit: new RecordingAuditService(),
                certificateAccessService: InstanceCeremonyEndpointTests.Fake<ICertificateAccessService>.Create(),
                revocation: RevokingRevocation.Over(Db),
                logger: NullLogger<CertificateIssuanceService>.Instance);
            Creation = new CaCreationService(
                Db,
                InstanceCeremonyEndpointTests.Fake<ICrlService>.Create(),
                new NoServiceUrls(),
                new CsrService(Db, new HeldKeyService(Db, new EphemeralDataProtectionProvider(), new RecordingAuditService())),
                Issuance,
                new SystemConfig(),
                NullLogger<CaCreationService>.Instance,
                signer);
        }

        public Task<CertificateAuthorityEntity> CreateRootAsync(string name, string? permitted, string? excluded)
            => Creation.CreateRootAsync(name, "Acme", null, null, null, "US", "ECDSA", 256, 5, null, SpaceId,
                nameConstraintsPermittedJson: permitted, nameConstraintsExcludedJson: excluded);

        public Task<CertificateAuthorityEntity> CreateIntermediateAsync(CertificateAuthorityEntity parent, string name, string? permitted, string? excluded)
            => Creation.CreateIntermediateAsync(parent, Db.Certificates.Single(c => c.CertificateId == parent.CertificateId),
                name, "Acme", null, null, null, "US", "ECDSA", 256, 2, null, SpaceId,
                nameConstraintsPermittedJson: permitted, nameConstraintsExcludedJson: excluded);

        /// <summary>Stores an approved request for <paramref name="subject"/> and <paramref name="sans"/> (with <paramref name="sanOverrides"/> as stored, when given) under the CA's own signing profile, and issues it.</summary>
        public Task<IssuanceResult> IssueLeafAsync(CertificateAuthorityEntity ca, string subject, string[] sans, string? sanOverrides = null)
        {
            var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
            var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()),
                new X509Name(subject), keys.Public, null);
            using var sw = new StringWriter();
            new PemWriter(sw).WriteObject(csr);
            var request = new CertRequestEntity
            {
                Id = Guid.NewGuid(),
                CSR = sw.ToString(),
                Subject = subject,
                SubjectAlternativeNames = System.Text.Json.JsonSerializer.Serialize(sans),
                Status = "Approved",
                KeyAlgorithm = "ECDSA",
                KeySize = "P-256",
                SignatureAlgorithm = "SHA256withECDSA",
                CertProfileId = LeafProfileId,
                SigningProfileId = Db.SigningProfiles.Single(p => p.IssuerId == ca.CertificateId).Id,
                SanOverrides = sanOverrides,
            };
            Db.CertificateRequests.Add(request);
            Db.SaveChanges();
            return Issuance.IssueCertificateAsync(request.Id, null, DateTime.UtcNow.AddDays(30));
        }

        private sealed class NoServiceUrls : ICaServiceUrlService
        {
            public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
            public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
            public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
            public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ResolvedCaServiceUrls([], [], []));
            public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
        }

        /// <summary>A certificate policy that reports <see cref="Violations"/>, none by default.</summary>
        internal sealed class ConfigurablePolicy : ICertPolicyService
        {
            public List<PolicyViolation> Violations { get; } = [];
            public List<PolicyViolation> Evaluate(CertificateIssuanceContext context) => [.. Violations];
        }

        /// <summary>
        /// A revocation service whose <c>RevokeCertificateAsync</c> marks the row revoked as the real
        /// one does, refusing an already-revoked certificate; every other member is a no-op.
        /// </summary>
        internal class RevokingRevocation : System.Reflection.DispatchProxy
        {
            private ModularCADbContext _db = null!;

            public static ICertificateRevocationService Over(ModularCADbContext db)
            {
                var proxy = Create<ICertificateRevocationService, RevokingRevocation>();
                ((RevokingRevocation)(object)proxy)._db = db;
                return proxy;
            }

            protected override object? Invoke(System.Reflection.MethodInfo? targetMethod, object?[]? args)
            {
                if (targetMethod!.Name == nameof(ICertificateRevocationService.RevokeCertificateAsync))
                {
                    var cert = _db.Certificates.Single(c => c.CertificateId == (Guid)args![0]!);
                    if (cert.Revoked)
                        throw new InvalidOperationException("Certificate is already revoked.");
                    cert.Revoked = true;
                    cert.RevocationReason = args![2]!.ToString();
                    cert.RevocationDate = DateTime.UtcNow;
                    _db.SaveChanges();
                    return Task.FromResult(new RevocationResult(cert.CertificateId, cert.SerialNumber, "Revoked", (ModularCA.Shared.Enums.RevocationReason)args[2]!, DateTime.UtcNow, null));
                }
                var type = targetMethod.ReturnType;
                if (type == typeof(Task)) return Task.CompletedTask;
                if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Task<>))
                {
                    var inner = type.GetGenericArguments()[0];
                    return typeof(Task).GetMethod(nameof(Task.FromResult))!.MakeGenericMethod(inner)
                        .Invoke(null, [inner.IsValueType ? Activator.CreateInstance(inner) : null]);
                }
                return type.IsValueType && type != typeof(void) ? Activator.CreateInstance(type) : null;
            }
        }

        /// <summary>Every CA certificate the database holds, as the keystore would serve them.</summary>
        private sealed class DbKeystore(ModularCADbContext db) : IKeystoreCertificates
        {
            public List<X509Certificate> GetTrustedAuthorities()
                => db.Certificates.Where(c => c.IsCA).AsEnumerable().Select(c => CertificateUtil.ParseFromPem(c.Pem)).ToList();
            public List<CertificateAuthorityIdentity> GetSigners() => [];
            public void RegisterTrustedCert(X509Certificate cert) { }
        }
    }
}
