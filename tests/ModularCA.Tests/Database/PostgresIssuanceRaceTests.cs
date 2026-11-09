using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Core.Services;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Concurrent issuance against a real PostgreSQL database, where row locks, advisory locks and the
/// <c>xmin</c> concurrency token behave as in production (the in-memory provider enforces none of
/// them). Each race is interleaved by hand rather than by timing: the first issuance is held at the
/// quota check, which every path passes after its request's state is read and before it signs, the
/// second is started and allowed to run until it either finishes or waits on a lock, and only then
/// is the first released. Opt-in through <c>MODULARCA_TEST_PG</c>, as
/// <see cref="PostgresLifecycleQueryTests"/>.
/// </summary>
[Trait("Category", "PostgreSQL")]
public class PostgresIssuanceRaceTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    /// <summary>
    /// Two issuances of one approved request, the second started while the first is between its
    /// state check and its signature: one certificate is signed and stored, and the other caller is
    /// refused with <see cref="ErrorCodes.CsrStateNotEligible"/> before anything is signed for it.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task Two_concurrent_issues_of_one_request_sign_and_store_one_certificate() =>
        OnPostgresAsync(async world =>
        {
            await world.SetQuotaAsync(10);
            var csrId = await world.AddApprovedRequestAsync("CN=once.race.test");

            var (first, second) = await world.RaceAsync(csrId, csrId);

            await using var db = world.Open();
            Assert.Equal(1, await world.CountSignaturesAsync(db));
            var leaves = await db.Certificates.AsNoTracking().Where(c => !c.IsCA).ToListAsync();
            var leaf = Assert.Single(leaves);
            var csr = await db.CertificateRequests.AsNoTracking().SingleAsync(c => c.Id == csrId);
            Assert.Equal("Issued", csr.Status);
            Assert.Equal(leaf.CertificateId, csr.IssuedCertificateId);

            Assert.Null(first);
            var refused = Assert.IsType<ResourceConflictException>(second);
            Assert.Equal(ErrorCodes.CsrStateNotEligible, refused.Code);
        });

    /// <summary>
    /// A CA with a quota of one certificate and two requests issued concurrently, the second
    /// started after the first has passed the quota check but before it has stored its
    /// certificate: one certificate is signed and stored, and the other request is refused with
    /// <see cref="ErrorCodes.QuotaExceeded"/> before anything is signed for it and stays Approved.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task Concurrent_issues_do_not_overshoot_the_cas_quota() =>
        OnPostgresAsync(async world =>
        {
            await world.SetQuotaAsync(1);
            var firstCsr = await world.AddApprovedRequestAsync("CN=one.quota.test");
            var secondCsr = await world.AddApprovedRequestAsync("CN=two.quota.test");

            var (first, second) = await world.RaceAsync(firstCsr, secondCsr);

            await using var db = world.Open();
            Assert.Equal(1, await world.CountSignaturesAsync(db));
            Assert.Equal(1, await db.Certificates.AsNoTracking().CountAsync(c => !c.IsCA));

            Assert.Null(first);
            var refused = Assert.IsType<ResourceConflictException>(second);
            Assert.Equal(ErrorCodes.QuotaExceeded, refused.Code);
            var unissued = await db.CertificateRequests.AsNoTracking().SingleAsync(c => c.Id == secondCsr);
            Assert.Equal("Approved", unissued.Status);
            Assert.Null(unissued.IssuedCertificateId);
        });

    /// <summary>
    /// Two reissues of one certificate, the second started while the first is between reading the
    /// predecessor and signing: one replacement is signed and stored, the predecessor is marked
    /// reissued and revoked once, and the other caller is refused with
    /// <see cref="ErrorCodes.AlreadyReissued"/> before anything is signed for it.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public Task Two_concurrent_reissues_of_one_certificate_sign_and_store_one_replacement() =>
        OnPostgresAsync(async world =>
        {
            await world.SetQuotaAsync(10);
            var original = await world.IssueAsync(await world.AddApprovedRequestAsync("CN=reissue.race.test"));

            var (first, second) = await world.RaceAsync(
                s => s.ReissueCertificateAsync(original, null, null, null, world.NotAfter),
                s => s.ReissueCertificateAsync(original, null, null, null, world.NotAfter));

            await using var db = world.Open();
            Assert.Equal(2, await world.CountSignaturesAsync(db));
            var leaves = await db.Certificates.AsNoTracking().Where(c => !c.IsCA).ToListAsync();
            Assert.Equal(2, leaves.Count);
            var predecessor = leaves.Single(c => c.CertificateId == original);
            Assert.True(predecessor.IsReissued);
            Assert.True(predecessor.Revoked);

            Assert.Null(first);
            var refused = Assert.IsType<ResourceConflictException>(second);
            Assert.Equal(ErrorCodes.AlreadyReissued, refused.Code);
        });

    /// <summary>
    /// The world a race runs in: one RSA CA in a space that waives ceremonies, its signing profile
    /// and an instance-wide leaf profile, the real in-process signer over the database, and a quota
    /// gate shared by every issuance service the world opens.
    /// </summary>
    internal sealed class RaceWorld(string connection, IServiceScopeFactory scopes)
    {
        private readonly TestCaMaterial _ca = TestCaMaterial.CreateCa("CN=Race Test CA, O=ModularCA");
        private InProcessSigningService? _signer;
        private TestKeystore? _keystore;

        /// <summary>The gate the first issuance after <see cref="QuotaGate.Arm"/> stops at.</summary>
        public QuotaGate Gate { get; } = new();

        public Guid CaId { get; } = Guid.NewGuid();
        public Guid CaCertificateId { get; } = Guid.NewGuid();
        public Guid SpaceId { get; } = Guid.NewGuid();
        public Guid SigningProfileId { get; } = Guid.NewGuid();
        public Guid LeafProfileId { get; } = Guid.NewGuid();
        public Guid AdminGroupId { get; } = Guid.NewGuid();

        /// <summary>Opens a new context over the world's database, as a new request scope would.</summary>
        public ModularCADbContext Open() => new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);

        /// <summary>Seeds the CA, its profiles and its admin group (unlimited quota), and binds the signer to the CA key.</summary>
        public async Task SeedAsync()
        {
            await using var db = Open();
            if (!await db.SecurityPolicies.AnyAsync())
                db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = false, CeremonyRequiredApprovals = 1 });
            db.Spaces.Add(new SpaceEntity { Id = SpaceId, Name = "race-space", Slug = "race-space", RequireKeyCeremony = false });
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = CaCertificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(_ca.Certificate.SerialNumber),
                SubjectDN = _ca.SubjectDn,
                Issuer = _ca.SubjectDn,
                IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(_ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = _ca.Certificate.GetEncoded(),
                NotBefore = _ca.Certificate.NotBefore,
                NotAfter = _ca.Certificate.NotAfter,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = CaId, Name = "race-ca", Label = "race-ca", SpaceId = SpaceId, CertificateId = CaCertificateId,
            });
            db.SigningProfiles.Add(new SigningProfileEntity
            {
                Id = SigningProfileId, Name = "Race Signing Profile", IssuerId = CaCertificateId,
                AllowedAlgorithms = "[\"RSA\",\"ECDSA\"]",
            });
            db.CertProfiles.Add(new CertProfileEntity
            {
                Id = LeafProfileId, Name = "Race Leaf", KeyUsages = "[]", ExtendedKeyUsages = "[]",
                AllowedKeySizes = "[]", AllowedSignatureAlgorithms = "[]", ValidityPeriodMax = "P1Y",
            });
            db.CaGroups.Add(new CaGroupEntity
            {
                Id = AdminGroupId, Name = "race-admins", DisplayName = "Race admins", CertificateAuthorityId = CaId,
                TemplateName = "Administrator", IsAutoGenerated = true,
                Grants = { new CapabilityGrantEntity { Capability = Capabilities.CaManage } },
            });
            await db.SaveChangesAsync();

            _keystore = new TestKeystore(_ca.AsSigner());
            _signer = new InProcessSigningService(_keystore, scopes, new DatabaseSignerAuditSink(scopes),
                new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance, unlocked: true);
        }

        /// <summary>Sets the CA's certificate quota on its admin group; 0 is unlimited.</summary>
        public async Task SetQuotaAsync(int maxCertificates)
        {
            await using var db = Open();
            var group = await db.CaGroups.SingleAsync(g => g.Id == AdminGroupId);
            group.MaxCertificates = maxCertificates;
            await db.SaveChangesAsync();
        }

        /// <summary>Stores an approved request for <paramref name="subject"/> over a fresh P-256 key, under the CA's signing profile.</summary>
        public async Task<Guid> AddApprovedRequestAsync(string subject)
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
                SubjectAlternativeNames = "[]",
                Status = "Approved",
                KeyAlgorithm = "ECDSA",
                KeySize = "P-256",
                SignatureAlgorithm = "SHA256withECDSA",
                CertProfileId = LeafProfileId,
                SigningProfileId = SigningProfileId,
            };
            await using var db = Open();
            db.CertificateRequests.Add(request);
            await db.SaveChangesAsync();
            return request.Id;
        }

        /// <summary>
        /// The issuance service a request scope over <paramref name="db"/> would get: the real
        /// store, validation, builder, profile resolution and quota service, signing through the
        /// world's signer; the quota service sits behind <see cref="Gate"/>.
        /// </summary>
        public CertificateIssuanceService Issuance(ModularCADbContext db) => new(
            db,
            keystore: _keystore!,
            certStore: new CertificateStore(db),
            validation: new IssuanceValidationService(db, NullLogger<IssuanceValidationService>.Instance),
            builder: new CertificateBuilderService(new NoServiceUrls(), _signer!, NullLogger<CertificateBuilderService>.Instance),
            profileResolver: new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance),
            ctSubmission: InstanceCeremonyEndpointTests.Fake<ICtSubmissionService>.Create(),
            certPolicy: new NameConstraintIssuanceTests.IssuanceWorld.ConfigurablePolicy(),
            quotaService: new GatedQuota(new QuotaService(db, new RecordingAlertService(), NullLogger<QuotaService>.Instance), Gate),
            audit: new RecordingAuditService(),
            certificateAccessService: InstanceCeremonyEndpointTests.Fake<ICertificateAccessService>.Create(),
            revocation: NameConstraintIssuanceTests.IssuanceWorld.RevokingRevocation.Over(db),
            logger: NullLogger<CertificateIssuanceService>.Instance);

        /// <summary>The validity every issuance in a race asks for.</summary>
        public DateTime NotAfter { get; } = DateTime.UtcNow.AddDays(30);

        /// <summary>Issues <paramref name="csrId"/> from its own context, with the gate unarmed.</summary>
        public async Task<Guid> IssueAsync(Guid csrId)
        {
            await using var db = Open();
            await Issuance(db).IssueCertificateAsync(csrId, null, NotAfter);
            return (await db.CertificateRequests.AsNoTracking().SingleAsync(c => c.Id == csrId)).IssuedCertificateId!.Value;
        }

        /// <summary>Issues <paramref name="firstCsr"/> and <paramref name="secondCsr"/> concurrently; see <see cref="RaceAsync(Func{CertificateIssuanceService, Task}, Func{CertificateIssuanceService, Task})"/>.</summary>
        public Task<(Exception? First, Exception? Second)> RaceAsync(Guid firstCsr, Guid secondCsr)
            => RaceAsync(s => s.IssueCertificateAsync(firstCsr, null, NotAfter), s => s.IssueCertificateAsync(secondCsr, null, NotAfter));

        /// <summary>
        /// Runs <paramref name="first"/> and <paramref name="second"/>, each over its own context
        /// and issuance service: the first is held at the quota gate, the second runs until it
        /// finishes or waits on a lock, then the first is released. Returns what each threw, or
        /// null for a success.
        /// </summary>
        public async Task<(Exception? First, Exception? Second)> RaceAsync(
            Func<CertificateIssuanceService, Task> first, Func<CertificateIssuanceService, Task> second)
        {
            Gate.Arm();
            await using var dbA = Open();
            await using var dbB = Open();

            var firstRun = Capture(() => first(Issuance(dbA)));
            await Gate.Reached.WaitAsync(TimeSpan.FromSeconds(60));

            var secondRun = Capture(() => second(Issuance(dbB)));
            await WaitUntilDoneOrBlockedAsync(secondRun);

            Gate.Release();
            return (await firstRun.WaitAsync(TimeSpan.FromSeconds(60)), await secondRun.WaitAsync(TimeSpan.FromSeconds(60)));
        }

        /// <summary>Signatures the signer allowed, from its audit.</summary>
        public Task<int> CountSignaturesAsync(ModularCADbContext db)
            => db.SignerAudit.AsNoTracking().CountAsync(a => a.Operation == "Sign" && a.Outcome == "allowed");

        private static Task<Exception?> Capture(Func<Task> action) => Task.Run(async () =>
        {
            try
            {
                await action();
                return (Exception?)null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        });

        /// <summary>Returns once <paramref name="task"/> has finished or a backend of this database waits on a lock.</summary>
        private async Task WaitUntilDoneOrBlockedAsync(Task task)
        {
            await using var conn = new NpgsqlConnection(connection);
            await conn.OpenAsync();
            var deadline = DateTime.UtcNow.AddSeconds(60);
            while (!task.IsCompleted)
            {
                await using var command = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'", conn);
                if ((long)(await command.ExecuteScalarAsync())! > 0)
                    return;
                if (DateTime.UtcNow > deadline)
                    throw new TimeoutException("The second issuance neither finished nor waited on a lock.");
                await Task.Delay(20);
            }
        }
    }

    /// <summary>
    /// Holds the first <see cref="IQuotaService.CanIssueCertificateAsync"/> call after <see cref="Arm"/>
    /// until <see cref="Release"/>; every other call passes straight through.
    /// </summary>
    internal sealed class QuotaGate
    {
        private TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _armed;

        /// <summary>Completes when the held call arrives.</summary>
        public Task Reached => _reached.Task;

        /// <summary>Makes the next call wait.</summary>
        public void Arm()
        {
            _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Volatile.Write(ref _armed, 1);
        }

        /// <summary>Lets the held call return.</summary>
        public void Release() => _release.TrySetResult();

        /// <summary>Waits at the gate when it is armed and this is the first call since.</summary>
        public async Task PassAsync()
        {
            if (Interlocked.Exchange(ref _armed, 0) == 1)
            {
                _reached.TrySetResult();
                await _release.Task;
            }
        }
    }

    /// <summary>The real quota service, with <see cref="QuotaGate"/> after its answer to whether a CA may issue.</summary>
    internal sealed class GatedQuota(IQuotaService inner, QuotaGate gate) : IQuotaService
    {
        public Task<QuotaStatus> CheckQuotaAsync(Guid caId) => inner.CheckQuotaAsync(caId);

        public async Task<bool> CanIssueCertificateAsync(Guid caId)
        {
            var answer = await inner.CanIssueCertificateAsync(caId);
            await gate.PassAsync();
            return answer;
        }

        public Task<QuotaUsageSummary> GetUsageSummaryAsync() => inner.GetUsageSummaryAsync();
    }

    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    /// <summary>
    /// Creates a database on the <c>MODULARCA_TEST_PG</c> server, applies every application
    /// migration, seeds a <see cref="RaceWorld"/> with the in-process signer's scopes over the same
    /// database, runs <paramref name="scenario"/> and drops the database, whatever the outcome.
    /// </summary>
    private static async Task OnPostgresAsync(Func<RaceWorld, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = $"modularca_race_{Guid.NewGuid():N}"[..32];
        await ExecAsync(server, $"CREATE DATABASE \"{name}\"");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using (var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options))
                await db.Database.MigrateAsync();

            var services = new ServiceCollection();
            services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
            await using var provider = services.BuildServiceProvider();
            var world = new RaceWorld(connection, provider.GetRequiredService<IServiceScopeFactory>());
            await world.SeedAsync();
            await scenario(world);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await ExecAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        }
    }

    private static async Task ExecAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
