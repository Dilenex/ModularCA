using System.Data.Common;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Database;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;
using Xunit.Abstractions;

namespace ModularCA.Tests.Journal;

/// <summary>
/// Developer tools for timing, not checks: a generator of large valid journals, and
/// measurements of the signer's start-up verification and of the merge. Each runs only when its
/// environment variable is set, and otherwise passes at once. They live in the test project so
/// that nothing of them is in a published build. <c>docs/architecture/signer-journal.md</c>,
/// "Measuring", has the commands.
/// </summary>
/// <remarks>
/// <b>A generated journal belongs to a made-up instance with made-up keys.</b> It verifies
/// (<c>--journal-verify</c> passes), and it is for timing only. It must never be mounted as a
/// real instance's journal: that instance's signer would find another instance's journal and
/// set it aside.
/// </remarks>
public class JournalMeasurementTools(ITestOutputHelper output)
{
    /// <summary>
    /// For a throwaway test instance only: inserts {1} serials as revoked, with no certificate,
    /// for the CA whose identifier is {0}, straight into the application database. It bypasses
    /// the audit trail, step-up and the queue of facts for the journal, so these revocations
    /// reach the journal only through the CA's next CRL. Each serial is 32 random hex digits (16
    /// octets, without leading zeros, upper case, as the product stores them), revoked for
    /// "Superseded" one day ago and listed for a year. <c>docs/architecture/signer-journal.md</c>,
    /// "Measuring", gives it with the steps around it.
    /// </summary>
    public const string TombstoneInsertSql = """
        INSERT INTO "RevokedSerialTombstones"
            ("Id", "CaCertificateId", "CertificateAuthorityId", "IssuerDN", "SerialNumber",
             "RevocationDate", "RevocationReason", "ListedUntil", "Note", "CreatedByUsername", "CreatedAt")
        SELECT gen_random_uuid(), ca."CertificateId", ca."Id", c."SubjectDN",
               ltrim(upper(md5(random()::text || g::text)), '0'),
               now() - interval '1 day', 'Superseded', now() + interval '1 year',
               'Inserted for timing on a test instance', 'timing-test', now()
        FROM "CertificateAuthorities" ca
        JOIN "Certificates" c ON c."CertificateId" = ca."CertificateId"
        CROSS JOIN generate_series(1, {1}) AS g
        WHERE ca."Id" = '{0}'
        ON CONFLICT DO NOTHING;
        """;

    /// <summary>The instance identifier every generated journal names.</summary>
    public static readonly string GeneratedInstanceId = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("ModularCA journal generated for timing only")));

    /// <summary>What a generation wrote.</summary>
    public sealed record Generated(long Records, long Bytes, int Segments, TimeSpan Took);

    /// <summary>
    /// Writes a valid journal of about <paramref name="totalBytes"/> into
    /// <c>&lt;home&gt;/current</c>, with the real writer: certificate records whose sizes cycle
    /// through <paramref name="recordBytes"/>, checkpoints as a signer writes them, segments
    /// sealed at <paramref name="segmentBytes"/>, and, when <paramref name="crlEntries"/> is
    /// above zero, a CRL record at the end that lists that many revoked serials.
    /// </summary>
    internal static async Task<Generated> GenerateAsync(string home, long totalBytes, int[] recordBytes, long segmentBytes, int crlEntries,
        IJournalSigningKey? checkpointKey = null, IJournalSigningKey? systemKey = null, string? instanceId = null)
    {
        var clock = Stopwatch.StartNew();
        var random = new Random(7);
        long written = 0, count = 0;
        await using (var writer = JournalWriter.Open(new JournalWriterOptions
        {
            Directory = JournalLayout.Current(home),
            InstanceId = instanceId ?? GeneratedInstanceId,
            CheckpointKey = checkpointKey ?? new TestJournalKey(),
            SystemKey = systemKey ?? new TestJournalKey(),
            Version = "generated-for-timing",
            SegmentSealBytes = segmentBytes,
        }))
        {
            while (written < totalBytes)
            {
                var batch = new List<Task<JournalAppended>>(1000);
                for (var i = 0; i < 1000 && written < totalBytes; i++)
                {
                    // A certificate record: the to-be-signed bytes make up the size asked for; beside
                    // them a signature, the index and the request's origin, about 400 bytes.
                    var tbs = new byte[Math.Max(64, recordBytes[count % recordBytes.Length] - 400)];
                    random.NextBytes(tbs);
                    var payload = new CertificatePayload("0b7e3a52-0000-4000-8000-000000000001", new byte[32], new byte[32], new SigningContextInfo("Certificate", "ACME", "user-1"), "0.4.5",
                        tbs, new byte[72], BitConverter.GetBytes(count), 1, 2, new byte[32], false,
                        [new SpentToken(TokenKind.EnrollmentToken, "token-row", 1)], new Answers(AnswersKind.AcmeOrder, "order-" + count), null,
                        new Belongs("profile-1", "space-1", OwnerKind.User, "user-1", null)).Encode();
                    written += payload.Length + JournalFormat.RecordOverhead;
                    count++;
                    batch.Add(writer.AppendAsync(RecordType.Certificate, 0, payload));
                }
                await Task.WhenAll(batch);
            }
            if (crlEntries > 0)
            {
                var ca = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
                var generator = new X509V2CrlGenerator();
                generator.SetIssuerDN(new X509Name("CN=Generated For Timing CA"));
                generator.SetThisUpdate(DateTime.UtcNow);
                generator.SetNextUpdate(DateTime.UtcNow.AddHours(6));
                for (var i = 1; i <= crlEntries; i++)
                    generator.AddCrlEntry(BigInteger.ValueOf(0x1000000L + i), DateTime.UtcNow.AddDays(-1), CrlReason.Superseded);
                generator.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.One));
                var crl = generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHECDSA", ca.Private));
                await writer.AppendAsync(RecordType.Crl, 0, new CrlPayload("0b7e3a52-0000-4000-8000-000000000001",
                    SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ca.Public).GetDerEncoded()), null, null, "generated-for-timing",
                    1, JournalFormat.ToMicros(DateTimeOffset.UtcNow), null, crl.GetSignature(), crl.GetTbsCertList(), null, null, false).Encode());
                count++;
            }
        }
        var files = Directory.GetFiles(JournalLayout.Current(home));
        return new Generated(count, files.Sum(f => new FileInfo(f).Length), files.Length, clock.Elapsed);
    }

    private static int[] Sizes(string? text)
        => string.IsNullOrWhiteSpace(text) ? [2048] : text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(int.Parse).ToArray();

    /// <summary>
    /// The generator. Runs when <c>MODULARCA_JOURNAL_GENERATE_DIR</c> names the journal home to
    /// write (it must not hold a journal). Size in MiB from
    /// <c>MODULARCA_JOURNAL_GENERATE_MIB</c> (1024), record sizes in bytes, cycled, from
    /// <c>MODULARCA_JOURNAL_GENERATE_RECORD_BYTES</c> ("2048"; for example "2048,2048,600"),
    /// segment size in MiB from <c>MODULARCA_JOURNAL_GENERATE_SEGMENT_MIB</c> (64), and the
    /// number of revoked serials on a CRL at its end from
    /// <c>MODULARCA_JOURNAL_GENERATE_CRL_ENTRIES</c> (0: none).
    /// </summary>
    [Fact]
    public async Task Generate_a_journal_for_timing()
    {
        var home = Environment.GetEnvironmentVariable("MODULARCA_JOURNAL_GENERATE_DIR");
        if (string.IsNullOrWhiteSpace(home))
            return;
        static long Number(string name, long otherwise) => long.TryParse(Environment.GetEnvironmentVariable(name), out var n) && n >= 0 ? n : otherwise;
        Assert.False(Directory.Exists(JournalLayout.Current(home)) && Directory.EnumerateFileSystemEntries(JournalLayout.Current(home)).Any(),
            $"{JournalLayout.Current(home)} already holds files; the generator writes only into an empty home.");

        var made = await GenerateAsync(Path.GetFullPath(home), Number("MODULARCA_JOURNAL_GENERATE_MIB", 1024) << 20,
            Sizes(Environment.GetEnvironmentVariable("MODULARCA_JOURNAL_GENERATE_RECORD_BYTES")),
            Number("MODULARCA_JOURNAL_GENERATE_SEGMENT_MIB", 64) << 20, (int)Number("MODULARCA_JOURNAL_GENERATE_CRL_ENTRIES", 0));

        output.WriteLine($"GENERATED {made.Records} records, {made.Bytes} bytes ({made.Bytes / 1048576.0:0} MiB) in {made.Segments} segments under {JournalLayout.Current(home)} in {made.Took.TotalSeconds:0.0} s");
        output.WriteLine($"GENERATED instance {GeneratedInstanceId}: a made-up instance with made-up keys, for timing only. Never mount it as a real instance's journal.");
    }

    /// <summary>
    /// How long the signer's start-up verification takes. Runs when
    /// <c>MODULARCA_MEASURE_VERIFY_MIB</c> gives the size of the journal to generate for it, in
    /// MiB; record and segment sizes as for the generator.
    /// </summary>
    [Fact]
    public async Task Measure_the_start_up_verification()
    {
        if (!int.TryParse(Environment.GetEnvironmentVariable("MODULARCA_MEASURE_VERIFY_MIB"), out var mib) || mib <= 0)
            return;
        var world = SignerTestWorld.Create();
        using var sandbox = new JournalSandbox();
        var made = await GenerateAsync(sandbox.Home, (long)mib << 20, Sizes(Environment.GetEnvironmentVariable("MODULARCA_JOURNAL_GENERATE_RECORD_BYTES")),
            64L << 20, 0, sandbox.CheckpointKey, sandbox.SystemKey, sandbox.InstanceId);
        var mibWritten = made.Bytes / 1048576.0;
        output.WriteLine($"MEASURE journal: {made.Records} certificate records, {made.Bytes} bytes ({mibWritten:0} MiB) in {made.Segments} segments, written in {made.Took.TotalSeconds:0.0} s");

        var clock = new Stopwatch();
        for (var pass = 1; pass <= 2; pass++)
        {
            clock.Restart();
            var result = JournalVerifier.Verify(sandbox.Directory, new JournalVerifyOptions { EveryCheckpoint = true });
            output.WriteLine($"MEASURE verifier alone, pass {pass}: {clock.Elapsed.TotalSeconds:0.00} s, {mibWritten / clock.Elapsed.TotalSeconds:0} MiB/s, "
                + $"{result.Records} records, {result.Checkpoints} checkpoints, fault: {result.Fault?.ToString() ?? "none"}");
        }

        clock.Restart();
        await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "measure", new byte[32]), NullLogger.Instance);
        var signer = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
        output.WriteLine($"MEASURE signer start: the journal is open and can take a record after {clock.Elapsed.TotalMilliseconds:0} ms");
        // The CRL and OCSP checks wait for the index only.
        var ca = world["ca-ec"];
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ca.PublicKey).GetDerEncoded();
        await journal.JudgeOcspAsync(spki, GoodFor(ca.Certificate, BigInteger.One));
        output.WriteLine($"MEASURE signer start: the index is read, so the CRL and OCSP checks answer, after {clock.Elapsed.TotalSeconds:0.00} s");
        var mid = (await signer.JournalInfoAsync())!;
        output.WriteLine($"MEASURE signer start: at that moment verified {mid.VerifiedBytes?.ToString() ?? "null"} of {mid.VerifyTotalBytes?.ToString() ?? "null"} bytes, verified={mid.Verified?.ToString() ?? "null"}");

        // While the verification runs: certificates are signed and recorded.
        var issued = 0;
        var issuing = Stopwatch.StartNew();
        while ((await signer.JournalInfoAsync())!.Verified == null && issuing.Elapsed < TimeSpan.FromMinutes(10))
        {
            Issue(signer, ca.Certificate, ca.Ref, ca.CaId!.Value, ca.SpaceId, 0x7000000 + issued);
            issued++;
        }
        output.WriteLine($"MEASURE signer start: {issued} certificates signed and recorded while the verification ran ({issued / Math.Max(0.001, issuing.Elapsed.TotalSeconds):0} /s)");

        await signer.JournaledRevocationsAsync(ca.CaId!.Value, 0, 1);
        output.WriteLine($"MEASURE signer start: the verification has ended, so the merge is answered, after {clock.Elapsed.TotalSeconds:0.00} s "
            + $"({mibWritten / clock.Elapsed.TotalSeconds:0} MiB/s over the whole start)");
        var end = (await signer.JournalInfoAsync())!;
        output.WriteLine($"MEASURE signer start: verified={end.Verified}, {end.VerifiedBytes} of {end.VerifyTotalBytes} bytes");
    }

    private static Org.BouncyCastle.Asn1.Ocsp.ResponseData GoodFor(X509Certificate ca, BigInteger serial)
        => Org.BouncyCastle.Asn1.Ocsp.ResponseData.GetInstance(Asn1Object.FromByteArray(GoodTbs(ca, serial)));

    private static byte[] GoodTbs(X509Certificate ca, BigInteger serial)
    {
        var generator = new Org.BouncyCastle.Ocsp.BasicOcspRespGenerator(new Org.BouncyCastle.Ocsp.RespID(ca.SubjectDN));
        generator.AddResponse(new Org.BouncyCastle.Ocsp.CertificateID(Org.BouncyCastle.Ocsp.CertificateID.DigestSha1, ca, serial), Org.BouncyCastle.Ocsp.CertificateStatus.Good);
        var other = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        return generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHECDSA", other.Private), null, DateTime.UtcNow).GetTbsResponseData();
    }

    private static readonly Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair SubjectKey = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");

    private static void Issue(ISigningService signer, X509Certificate ca, KeyRef key, Guid caId, Guid? spaceId, long serial)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetIssuerDN(ca.SubjectDN);
        generator.SetSubjectDN(new X509Name($"CN=measured-{serial}"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
        generator.SetPublicKey(SubjectKey.Public);
        generator.Generate(new SigningServiceSignatureFactory(signer, key, SignatureAlgorithm.ForPublicKey(ca.GetPublicKey()),
            SigningContext.ForCa("measure", SigningPurpose.Certificate, caId, spaceId)));
    }

    /// <summary>Counts what a database context sends: commands and saves.</summary>
    private sealed class Counter : DbCommandInterceptor
    {
        public long Commands;
        public long Saves;
        public long Ticks;

        public double Milliseconds => TimeSpan.FromTicks(Interlocked.Read(ref Ticks)).TotalMilliseconds;

        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        { Interlocked.Add(ref Ticks, eventData.Duration.Ticks); return ValueTask.FromResult(result); }
        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        { Interlocked.Add(ref Ticks, eventData.Duration.Ticks); return ValueTask.FromResult(result); }

        public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        { Interlocked.Increment(ref Commands); return result; }
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref Commands); return ValueTask.FromResult(result); }
        public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        { Interlocked.Increment(ref Commands); return result; }
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref Commands); return ValueTask.FromResult(result); }
        public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
        { Interlocked.Increment(ref Commands); return result; }
        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref Commands); return ValueTask.FromResult(result); }
    }

    private sealed class SaveCounter(Counter counter) : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref counter.Saves); return ValueTask.FromResult(result); }
    }

    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ModularCA.Shared.Models.ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ModularCA.Shared.Models.ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    /// <summary>
    /// The merge against a real PostgreSQL database: the pass that finds nothing missing, and
    /// the cure. Runs when <c>MODULARCA_MEASURE_MERGE</c> lists the sizes of the journaled
    /// revocation list to try (for example "0,1000,10000,100000") and
    /// <c>MODULARCA_TEST_PG</c> names the test server. Half of each list are certificates the
    /// database holds and half are serials it does not.
    /// </summary>
    [Fact]
    public async Task Measure_the_merge()
    {
        var sizes = Environment.GetEnvironmentVariable("MODULARCA_MEASURE_MERGE");
        if (string.IsNullOrWhiteSpace(sizes) || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(PostgresCaFixture.ServerVariable)))
            return;
        foreach (var n in sizes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(int.Parse))
            await PostgresCaFixture.WithDatabaseAsync("modularca_mmerge", async connection =>
            {
                // The fixture's connections are not pooled, so that its databases can be dropped; a
                // node's are. Without a pool every command pays for a new connection and its
                // authentication, which is most of what would be measured.
                var pooled = new Npgsql.NpgsqlConnectionStringBuilder(connection) { Pooling = true }.ConnectionString;
                try
                {
                    await MeasureMergeAsync(pooled, n);
                }
                finally
                {
                    Npgsql.NpgsqlConnection.ClearAllPools();
                }
            });
    }

    /// <summary>
    /// What the merge's audit rows cost in the real audit trail: rows shaped like the ones the
    /// merge writes, appended one at a time to the hash chain of an audit database on the test
    /// server. Runs when <c>MODULARCA_MEASURE_AUDIT_ROWS</c> gives how many and
    /// <c>MODULARCA_TEST_PG</c> names the server.
    /// </summary>
    [Fact]
    public async Task Measure_the_audit_rows_of_a_merge()
    {
        var rows = int.TryParse(Environment.GetEnvironmentVariable("MODULARCA_MEASURE_AUDIT_ROWS"), out var asked) ? asked : 0;
        if (rows <= 0 || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(PostgresCaFixture.ServerVariable)))
            return;
        await PostgresCaFixture.WithDatabaseAsync("modularca_maudit", async connection =>
        {
            // The audit tables go into a schema of their own in the test database, beside the application's.
            await using (var app = PostgresCaFixture.Open(connection))
                await app.Database.ExecuteSqlRawAsync("CREATE SCHEMA audit_measure");
            var pooled = new Npgsql.NpgsqlConnectionStringBuilder(connection) { Pooling = true, SearchPath = "audit_measure" }.ConnectionString;
            try
            {
                var options = new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(pooled).Options;
                await using (var create = new AuditDbContext(options))
                    await create.GetService<Microsoft.EntityFrameworkCore.Storage.IRelationalDatabaseCreator>().CreateTablesAsync();
                var chain = new AuditHashChainService();
                var caId = Guid.NewGuid();
                var clock = Stopwatch.StartNew();
                await using (var db = new AuditDbContext(options))
                {
                    var audit = new AuditService(NullLogger<AuditService>.Instance, db, hashChain: chain);
                    for (var i = 0; i < rows; i++)
                    {
                        var serial = CertificateUtil.FormatSerialNumber(BigInteger.ValueOf(0x10000000L + i));
                        await audit.LogAsync(AuditActionType.RevocationMergedFromJournal, null, JournalRevocationMerge.Actor, "RevokedSerial", serial, new
                        {
                            CertificateAuthorityId = caId, CaName = "merge-measure", SerialNumber = serial, RevocationDate = DateTime.UtcNow, Reason = "Superseded", ReasonCode = 4,
                            Hold = false, Made = "serial without a certificate", CertificateId = (Guid?)null, Source = "crl", SourceCrlNumber = 12L, SourceSeq = 123456L,
                            JournaledCrlNumber = 12L, JournaledCrlSeq = 123456L,
                        }, certificateAuthorityId: caId);
                        if (i % 500 == 499)
                            db.ChangeTracker.Clear();
                    }
                }
                var took = clock.Elapsed;
                await using var read = new AuditDbContext(options);
                var written = await read.AuditLogs.CountAsync();
                var bytes = await read.Database.SqlQueryRaw<long>("""SELECT pg_total_relation_size('"AuditLogs"') AS "Value" """).SingleAsync();
                output.WriteLine($"AUDIT {written} rows of the merge appended to the hash chain in {took.TotalSeconds:0.00} s ({written / took.TotalSeconds:0} rows/s), {bytes / (double)Math.Max(1, written):0} bytes a row with its indexes ({bytes / 1048576.0:0.0} MiB)");
                Assert.Equal(rows, written);
            }
            finally
            {
                Npgsql.NpgsqlConnection.ClearAllPools();
            }
        });
    }

    private async Task MeasureMergeAsync(string connection, int n)
    {
        PostgresCaFixture.SeededCa ca;
        await using (var seed = PostgresCaFixture.Open(connection))
            ca = await PostgresCaFixture.SeedCaAsync(seed, "merge-measure");
        using var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        var audit = new RecordingAuditService();
        var counter = new Counter();
        var services = new ServiceCollection();
        services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection).AddInterceptors(counter, new SaveCounter(counter)));
        services.AddSingleton<IAuditService>(audit);
        var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
        var keystore = new TestKeystore(ca.Material.AsSigner());
        await using var journal = new SignerJournal(() => sandbox.Options(files), new SignerJournalSettings(sandbox.Home, true, "measure", new byte[32]), NullLogger.Instance);
        var signer = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
            new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance, journal: journal);
        JournalRevocationMerge Merge() => new(scopes, signer, new JournalMergeState(), FullInstanceModeGate.Instance, NullLogger<JournalRevocationMerge>.Instance);
        async Task<string> GenerateCrlAsync()
        {
            await using var db = PostgresCaFixture.Open(connection);
            return await new CrlService(db, keystore, NullLogger<CrlService>.Instance, audit, new NoServiceUrls(),
                InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer).GenerateCrlAsync(ca.CaCertificateId);
        }

        // N revocations: half certificates the database holds, half serials with no certificate.
        var revokedAt = DateTime.UtcNow.AddHours(-3);
        var clock = Stopwatch.StartNew();
        for (var from = 0; from < n; from += 5000)
        {
            await using var db = PostgresCaFixture.Open(connection);
            db.SuppressSignerFacts = true;
            for (var i = from; i < Math.Min(n, from + 5000); i++)
            {
                var serial = CertificateUtil.FormatSerialNumber(BigInteger.ValueOf(0x10000000L + i));
                if (i % 2 == 0)
                    db.Certificates.Add(new CertificateEntity
                    {
                        CertificateId = Guid.NewGuid(), SerialNumber = serial, SubjectDN = $"CN=measured-{i}", Issuer = ca.Material.SubjectDn, IssuerCertificateId = ca.CaCertificateId,
                        Pem = "x", NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(300), Revoked = true, RevocationReason = "Superseded", RevocationDate = revokedAt,
                    });
                else
                    db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
                    {
                        CaCertificateId = ca.CaCertificateId, CertificateAuthorityId = ca.CaId, IssuerDN = ca.Material.SubjectDn, SerialNumber = serial.TrimStart('0'),
                        RevocationDate = revokedAt, RevocationReason = "Superseded", ListedUntil = DateTime.UtcNow.AddYears(1), Note = "measure", CreatedByUsername = "measure", CreatedAt = DateTime.UtcNow,
                    });
            }
            await db.SaveChangesAsync();
        }
        var seeded = clock.Elapsed;
        // A database that has run for a while has statistics; one seeded a moment ago has none.
        await using (var db = PostgresCaFixture.Open(connection))
            await db.Database.ExecuteSqlRawAsync("ANALYZE");
        clock.Restart();
        await GenerateCrlAsync();
        output.WriteLine($"MERGE n={n}: database seeded in {seeded.TotalSeconds:0.0} s; the CRL listing {n} serials generated, signed and journaled in {clock.Elapsed.TotalSeconds:0.00} s");

        // (a) The ordinary start: nothing is missing.
        clock.Restart();
        var calls = 0;
        for (var skip = 0; ; skip += JournalRevocationMerge.PageSize)
        {
            var answer = await signer.JournaledRevocationsAsync(ca.CaId, skip, JournalRevocationMerge.PageSize);
            calls++;
            if (answer == null || answer.Entries.Count == 0 || skip + answer.Entries.Count >= answer.Total)
                break;
        }
        var asking = clock.Elapsed;
        Interlocked.Exchange(ref counter.Commands, 0);
        Interlocked.Exchange(ref counter.Saves, 0);
        Interlocked.Exchange(ref counter.Ticks, 0);
        clock.Restart();
        var nothing = await Merge().MergeAsync(ca.CaId);
        output.WriteLine($"MERGE n={n} (a) nothing missing: {clock.Elapsed.TotalMilliseconds:0} ms, of which the database {counter.Milliseconds:0} ms in {counter.Commands} commands and the signer about {asking.TotalMilliseconds:0} ms in {calls} calls; {counter.Saves} saves, merged {nothing.Merged}, state {nothing.State}");

        if (n == 0)
            return;

        // The database goes back: the certificates are no longer revoked and the tombstones are gone.
        await using (var db = PostgresCaFixture.Open(connection))
        {
            await db.Database.ExecuteSqlRawAsync("""UPDATE "Certificates" SET "Revoked" = false, "RevocationReason" = NULL, "RevocationDate" = NULL WHERE "IssuerCertificateId" IS NOT NULL""");
            await db.Database.ExecuteSqlRawAsync("""DELETE FROM "RevokedSerialTombstones" """);
        }

        // (c) What the signer still does meanwhile: a certificate signed and recorded, and an OCSP "good" signed, in a loop.
        Guid? spaceId;
        await using (var db = PostgresCaFixture.Open(connection))
            spaceId = await db.CertificateAuthorities.AsNoTracking().Where(c => c.Id == ca.CaId).Select(c => c.SpaceId).SingleAsync();
        var caCert = ca.Material.Certificate;
        var key = new KeyRef(ca.CaCertificateId);
        var ocsp = GoodTbs(caCert, BigInteger.ValueOf(0x5555));
        async Task<(int Count, double MeanMs, double MaxMs)> ProbeAsync(Func<bool> until)
        {
            var times = new List<double>();
            var one = new Stopwatch();
            var serial = 0x7100000L + Random.Shared.Next(1, 1 << 20) * 64L;
            while (!until())
            {
                one.Restart();
                await Task.Run(() => Issue(signer, caCert, key, ca.CaId, spaceId, serial++));
                await signer.SignAsync(key, SignatureAlgorithm.ForPublicKey(caCert.GetPublicKey()), ocsp, SigningContext.ForCa("measure", SigningPurpose.Ocsp, ca.CaId, spaceId));
                times.Add(one.Elapsed.TotalMilliseconds);
            }
            return (times.Count, times.Count == 0 ? 0 : times.Average(), times.Count == 0 ? 0 : times.Max());
        }
        var calm = Stopwatch.StartNew();
        var baseline = await ProbeAsync(() => calm.Elapsed > TimeSpan.FromSeconds(3));

        // (b) The cure.
        Interlocked.Exchange(ref counter.Commands, 0);
        Interlocked.Exchange(ref counter.Saves, 0);
        var flushesBefore = files.Flushes;
        var merging = Merge().MergeAsync(ca.CaId);
        clock.Restart();
        var during = await ProbeAsync(() => merging.IsCompleted);
        var cured = await merging;
        var took = clock.Elapsed;
        long queued;
        await using (var db = PostgresCaFixture.Open(connection))
            queued = await db.SignerFacts.LongCountAsync();
        output.WriteLine($"MERGE n={n} (b) cure: merged {cured.Merged} in {took.TotalSeconds:0.00} s ({cured.Merged / Math.Max(0.001, took.TotalSeconds):0} revocations/s), "
            + $"{counter.Commands} database commands, {counter.Saves} saves (transactions), {audit.Entries.Count(e => e.Action == AuditActionType.RevocationMergedFromJournal)} audit rows "
            + $"+ {audit.Entries.Count(e => e.Action == AuditActionType.JournalRevocationMergeCompleted)} summary, {queued} facts queued for the journal");
        output.WriteLine($"MERGE n={n} (c) a certificate signed and recorded plus an OCSP answer signed: before the merge mean {baseline.MeanMs:0.0} ms, max {baseline.MaxMs:0} ms over {baseline.Count}; "
            + $"during the merge mean {during.MeanMs:0.0} ms, max {during.MaxMs:0} ms over {during.Count}");

        // The facts the merged revocations queued, drained through the signer into the journal.
        var recordsBefore = (await signer.JournalInfoAsync())!.Seq;
        flushesBefore = files.Flushes;
        clock.Restart();
        var passes = 0;
        while (true)
        {
            await using var db = PostgresCaFixture.Open(connection);
            if (await SignerFactDrain.DrainOnceAsync(db, signer, NullLogger.Instance) == 0)
                break;
            passes++;
        }
        var drained = clock.Elapsed;
        output.WriteLine($"MERGE n={n} drain: {queued} facts recorded in the journal in {drained.TotalSeconds:0.00} s ({queued / Math.Max(0.001, drained.TotalSeconds):0} facts/s), "
            + $"{passes} passes of {SignerFactDrain.Batch}, {files.Flushes - flushesBefore} flushes of the journal for {(await signer.JournalInfoAsync())!.Seq - recordsBefore} records");

        clock.Restart();
        var pem = await GenerateCrlAsync();
        var listed = PostgresCaFixture.ParseCrl(pem).GetRevokedCertificates()?.Count ?? 0;
        output.WriteLine($"MERGE n={n} after the cure: the CRL lists {listed} serials again and is signed, in {clock.Elapsed.TotalSeconds:0.00} s");
        Assert.Equal(n, listed);
        Assert.Equal(n, cured.Merged);
    }
}
