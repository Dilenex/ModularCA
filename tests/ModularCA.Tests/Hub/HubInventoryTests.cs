using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.HubConnection.Contract;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Database;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Hub;

/// <summary>
/// What <c>inventory.read</c> answers, read by the node's real reader
/// (<see cref="NodeInventoryReader"/>) over seeded rows, a real backup directory and the state
/// the readiness check keeps: every field against what was seeded, that reading starts no work,
/// and that nothing the connection may never carry is in the answer. The wire (the route, the
/// token, the version, the audit count) is in <see cref="HubLocalConnectionTests"/>.
/// </summary>
public sealed class HubInventoryTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 12, 9, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime AlphaExpiry = new(2036, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime BetaExpiry = new(2031, 6, 30, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime OcspExpiry = new(2027, 3, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime NewestCrlNextUpdate = new(2026, 11, 12, 18, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime SignerCheckedAt = new(2026, 11, 12, 8, 59, 30, DateTimeKind.Utc);
    private static readonly DateTime JobFailedAt = new(2026, 11, 12, 6, 0, 0, DateTimeKind.Utc);

    private const string SeededUsername = "zofia.inventory";
    private const string SeededEmail = "zofia@inventory.example";
    private const string SeededPasswordHash = "pbkdf2-hash-7c1e9d";
    private const string SubscriberSubject = "CN=subscriber-device-0042.example";
    private const string SubscriberSerial = "5AFE0042C0FFEE";
    private const string KeyBlob = "c2VjcmV0LWtleS1ibG9i";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mhi-" + Guid.NewGuid().ToString("N")[..10]);
    private readonly SignerContactState _signer = new();
    private readonly ApiCertificateProvider _webTls = new();
    private readonly FixedTimeProvider _clock = new(Now);

    private string BackupDirectory => Path.Combine(_dir, "backups");

    public void Dispose()
    {
        _webTls.GetCertificate()?.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private NodeInventoryReader Reader(ModularCADbContext db, AuditDbContext? audit = null)
        => new(db, audit, _signer, _webTls, BackupDirectory, "0.4.5-test", NullLogger.Instance, _clock);

    private static string Json(HubInventory inventory) => JsonSerializer.Serialize(inventory, HubLocalContract.Json);

    /// <summary>
    /// Two CAs that are listed (one enabled with CRLs and an OCSP responder, one disabled with
    /// neither), a deleted CA, an SSH CA, and around them everything the answer must not carry:
    /// a user, a subscriber certificate with a key blob, CRL bytes.
    /// </summary>
    private static async Task SeedAsync(ModularCADbContext db)
    {
        Guid Certificate(string subject, DateTime notAfter, bool isCa, string? serial = null, byte[]? key = null)
        {
            var id = Guid.NewGuid();
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = id, SerialNumber = serial ?? Guid.NewGuid().ToString("N"), SubjectDN = subject, Issuer = "CN=Alpha Issuing",
                IsCA = isCa, NotBefore = notAfter.AddYears(-1), NotAfter = notAfter,
                Pem = "-----BEGIN CERTIFICATE-----\nMIIBseededPemBody\n-----END CERTIFICATE-----", RawCertificate = [0x30, 0x82, 0x01],
                EncryptedPrivateKey = key,
            });
            return id;
        }

        var alphaCert = Certificate("CN=Alpha Issuing", AlphaExpiry, true);
        var betaCert = Certificate("CN=Beta Root", BetaExpiry, true);
        var goneCert = Certificate("CN=Gone CA", AlphaExpiry, true);
        var ocspCert = Certificate("CN=Alpha OCSP Responder", OcspExpiry, false);
        Certificate(SubscriberSubject, AlphaExpiry.AddYears(-8), false, SubscriberSerial, Convert.FromBase64String(KeyBlob));

        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Name = "Alpha Issuing", Label = "alpha", Type = "Issuing", IsEnabled = true, CertificateId = alphaCert, OcspResponderCertificateId = ocspCert },
            new CertificateAuthorityEntity { Name = "Beta Root", Label = "beta", Type = "Root", IsEnabled = false, CertificateId = betaCert },
            new CertificateAuthorityEntity { Name = "Gone CA", Label = "gone", IsEnabled = true, CertificateId = goneCert, IsDeleted = true, DeletedAt = Now.AddDays(-3) },
            new CertificateAuthorityEntity { Name = "SSH Users", Label = "ssh-users", Type = "SSH", IsSshCa = true, IsEnabled = true });

        var alphaCrls = new CrlConfigurationEntity { TaskId = Guid.Parse("5f0c1f6e-0000-4000-8000-000000000001"), Name = "alpha", CaCertificateId = alphaCert, IssuerDN = "CN=Alpha Issuing", UpdateInterval = "0 */6 * * *", LastCrlNumber = 6 };
        var goneCrls = new CrlConfigurationEntity { Name = "gone", CaCertificateId = goneCert, IssuerDN = "CN=Gone CA", UpdateInterval = "0 */6 * * *", LastCrlNumber = 9 };
        db.CrlConfigurations.AddRange(alphaCrls, goneCrls);

        CrlEntity Crl(CrlConfigurationEntity task, long number, bool delta, DateTime nextUpdate) => new()
        {
            Id = Guid.NewGuid(), IssuerName = task.IssuerDN!, CrlNumber = number, IsDelta = delta, TaskId = task.TaskId,
            ThisUpdate = nextUpdate.AddHours(-6), NextUpdate = nextUpdate, GeneratedAt = nextUpdate.AddHours(-6),
            PemData = "-----BEGIN X509 CRL-----\nMIIBseededCrlBody\n-----END X509 CRL-----", RawData = [0x30, 0x82, 0x02],
        };
        db.Crls.AddRange(
            Crl(alphaCrls, 3, false, NewestCrlNextUpdate.AddHours(-12)),
            Crl(alphaCrls, 5, false, NewestCrlNextUpdate),
            // A delta with a higher number and a later nextUpdate: not the newest full CRL.
            Crl(alphaCrls, 6, true, NewestCrlNextUpdate.AddHours(1)),
            Crl(goneCrls, 9, false, NewestCrlNextUpdate.AddDays(1)));

        db.SchedulerJobStates.AddRange(
            new SchedulerJobStateEntity { JobName = "AutoRenewal", LastRunUtc = JobFailedAt, LastResult = "success" },
            new SchedulerJobStateEntity { JobName = "BackupCreation", LastRunUtc = JobFailedAt, LastResult = "skipped" },
            new SchedulerJobStateEntity
            {
                JobName = "CrlExport:5f0c1f6e-0000-4000-8000-000000000001", LastRunUtc = JobFailedAt, LastResult = "failed", ConsecutiveFailureCount = 4,
                LastError = "The signer refused the request.\r\n   at ModularCA.Core.Services.CrlService.GenerateCrlAsync()\n   at second line",
            },
            new SchedulerJobStateEntity { JobName = "LdapGroupSync", LastRunUtc = JobFailedAt.AddHours(1), LastResult = "cancelled", LastError = "job timed out after 120s" },
            // Failing jobs whose CRL schedule and LDAP publisher were since deleted: not reported.
            new SchedulerJobStateEntity { JobName = "CrlExport:5f0c1f6e-0000-4000-8000-0000000000ff", LastRunUtc = JobFailedAt, LastResult = "failed", LastError = "gone" },
            new SchedulerJobStateEntity { JobName = "LdapPublisher:5f0c1f6e-0000-4000-8000-0000000000fe", LastRunUtc = JobFailedAt, LastResult = "failed", LastError = "gone" });

        db.Users.Add(new UserEntity { Id = Guid.NewGuid(), Username = SeededUsername, Email = SeededEmail, PasswordHash = SeededPasswordHash });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    /// <summary>A self-signed certificate that expires at <paramref name="notAfter"/>, as the HTTPS listener's.</summary>
    private static X509Certificate2 WebTlsCertificate(DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest("CN=ca.inventory.example", key, HashAlgorithmName.SHA256).CreateSelfSigned(notAfter.AddDays(-90), notAfter);
    }

    /// <summary>Writes an archive file of <paramref name="name"/>; with <paramref name="whole"/> it is one the verification job passes.</summary>
    private string Archive(string name, bool whole = true)
    {
        Directory.CreateDirectory(BackupDirectory);
        var path = Path.Combine(BackupDirectory, name);
        if (!whole)
        {
            File.WriteAllBytes(path, [0x50, 0x4B, 0x03, 0x04, 0xFF, 0xFF, 0x00]);
            return path;
        }
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        using (var manifest = new StreamWriter(zip.CreateEntry("manifest.json").Open()))
            manifest.Write("{\"Version\":\"0.4.5\",\"Timestamp\":\"2026-11-11T01:00:00Z\",\"SchemaVersion\":\"x\"}");
        foreach (var entry in new[] { "db-app.dump", "config/config.yaml", "keystores/ca-certs.keystore" })
            using (var body = new StreamWriter(zip.CreateEntry(entry).Open()))
                body.Write("x");
        return path;
    }

    /// <summary>An older and a newer archive, and the clock one hour after the newer was created. Returns the newer.</summary>
    private FileInfo TwoArchives(bool newestWhole = true)
    {
        Archive("modularca-backup-20261110-010000-aaaa.zip");
        File.WriteAllText(Path.Combine(BackupDirectory, "notes.txt"), "not an archive");
        Thread.Sleep(60);
        var newest = new FileInfo(Archive("modularca-backup-20261111-010000-bbbb.zip", newestWhole));
        _clock.Now = new DateTimeOffset(newest.CreationTimeUtc).AddHours(1);
        return newest;
    }

    // ---- every field, against what was seeded ---------------------------------------------------------

    [Fact]
    public async Task Every_field_is_read_from_what_the_instance_already_holds()
    {
        using var db = InMemoryDbContextFactory.Create();
        await SeedAsync(db);
        _signer.Observe(new SignerHealth(true, 2, SignerHealth.SoftwareBackend), SignerCheckedAt);
        var tlsExpiry = new DateTimeOffset(2027, 2, 14, 10, 30, 0, TimeSpan.Zero);
        _webTls.SetCertificate(WebTlsCertificate(tlsExpiry));
        var newest = TwoArchives();
        var verifiedAt = Now.AddMinutes(-20);
        BackupVerificationRecord.Write(BackupDirectory, new BackupVerificationRecord(verifiedAt,
            [new(newest.Name, true), new("modularca-backup-20261110-010000-aaaa.zip", false)]));

        var inventory = await Reader(db).ReadAsync(CancellationToken.None);

        Assert.Equal("0.4.5-test", inventory.InstanceVersion);

        Assert.Equal(new HubInventorySigner(HubInventorySigner.Unlocked, SignerCheckedAt), inventory.Signer);
        Assert.Equal(tlsExpiry.UtcDateTime, inventory.WebTlsCertificate!.ExpiresAtUtc);
        Assert.Equal(DateTimeKind.Utc, inventory.WebTlsCertificate.ExpiresAtUtc.Kind);

        Assert.Equal(new HubInventoryBackup(newest.Name, newest.CreationTimeUtc, 3600, true, verifiedAt), inventory.NewestBackup);

        Assert.Equal(
            [
                new HubInventoryFailingJob("CrlExport:5f0c1f6e-0000-4000-8000-000000000001", "CrlExport", JobFailedAt),
                new HubInventoryFailingJob("LdapGroupSync", "LdapGroupSync", JobFailedAt.AddHours(1)),
            ],
            inventory.FailingJobs);

        Assert.Equal(
            [
                new HubInventoryCertificateAuthority("Alpha Issuing", "alpha", HubInventoryCertificateAuthority.Active, AlphaExpiry,
                    new HubInventoryCrl(5, NewestCrlNextUpdate), OcspExpiry),
                new HubInventoryCertificateAuthority("Beta Root", "beta", HubInventoryCertificateAuthority.Disabled, BetaExpiry, null, null),
            ],
            inventory.CertificateAuthorities);
    }

    /// <summary>The first cut agreed with the hub is these fields and no others; a new one is a decision, not an accident.</summary>
    [Fact]
    public async Task The_answer_has_exactly_the_agreed_fields()
    {
        using var db = InMemoryDbContextFactory.Create();
        await SeedAsync(db);
        _signer.Observe(new SignerHealth(true, 2, SignerHealth.SoftwareBackend), SignerCheckedAt);
        _webTls.SetCertificate(WebTlsCertificate(DateTimeOffset.UtcNow.AddDays(30)));
        TwoArchives();

        using var json = JsonDocument.Parse(Json(await Reader(db).ReadAsync(CancellationToken.None)));
        static string[] Names(JsonElement e) => e.EnumerateObject().Select(p => p.Name).ToArray();
        var root = json.RootElement;

        Assert.Equal(["instanceVersion", "schema", "signer", "webTlsCertificate", "newestBackup", "failingJobs", "certificateAuthorities"], Names(root));
        Assert.Equal(["application", "audit"], Names(root.GetProperty("schema")));
        Assert.Equal(["state", "checkedAtUtc"], Names(root.GetProperty("signer")));
        Assert.Equal(["expiresAtUtc"], Names(root.GetProperty("webTlsCertificate")));
        Assert.Equal(["fileName", "createdAtUtc", "ageSeconds", "valid", "verifiedAtUtc"], Names(root.GetProperty("newestBackup")));
        Assert.All(root.GetProperty("failingJobs").EnumerateArray(), job => Assert.Equal(["name", "kind", "lastRunUtc"], Names(job)));
        // A job whose CRL schedule or LDAP publisher was deleted is not reported.
        Assert.DoesNotContain("0000000000ff", root.GetRawText());
        Assert.DoesNotContain("0000000000fe", root.GetRawText());
        // A failing job's error is an exception's text, the instance's own data: it is not sent.
        Assert.NotEqual(0, root.GetProperty("failingJobs").GetArrayLength());
        Assert.DoesNotContain("The signer refused the request", root.GetRawText());
        Assert.DoesNotContain("timed out", root.GetRawText());
        var cas = root.GetProperty("certificateAuthorities").EnumerateArray().ToList();
        Assert.All(cas, ca => Assert.Equal(["name", "label", "state", "certificateExpiresAtUtc", "crl", "ocspResponderCertificateExpiresAtUtc"], Names(ca)));
        Assert.Equal(["number", "nextUpdateUtc"], Names(cas[0].GetProperty("crl")));
        // Neither health nor the mode is repeated here.
        Assert.DoesNotContain("\"mode\"", json.RootElement.GetRawText());
        Assert.DoesNotContain("\"status\"", json.RootElement.GetRawText());
    }

    [Fact]
    public async Task A_part_with_nothing_to_say_is_sent_as_null_and_an_empty_list_as_empty()
    {
        using var db = InMemoryDbContextFactory.Create();

        var inventory = await Reader(db).ReadAsync(CancellationToken.None);
        var json = Json(inventory);

        Assert.Null(inventory.Signer);
        Assert.Null(inventory.WebTlsCertificate);
        Assert.Null(inventory.NewestBackup);
        Assert.Empty(inventory.FailingJobs);
        Assert.Empty(inventory.CertificateAuthorities);
        // The in-memory provider keeps no migration history; an instance with no audit database has no audit schema.
        Assert.Null(inventory.Schema.Application);
        Assert.Null(inventory.Schema.Audit);
        Assert.Equal(
            "{\"instanceVersion\":\"0.4.5-test\",\"schema\":{\"application\":null,\"audit\":null},\"signer\":null,"
            + "\"webTlsCertificate\":null,\"newestBackup\":null,\"failingJobs\":[],\"certificateAuthorities\":[]}",
            json);
        // And the typed client reads the same thing back.
        Assert.Equivalent(inventory, JsonSerializer.Deserialize<HubInventory>(json, HubLocalContract.Json), strict: true);
    }

    [Fact]
    public async Task A_ca_with_no_certificate_no_crl_and_no_responder_says_null_for_each()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Name = "Bare CA", Label = null, IsEnabled = true });
        await db.SaveChangesAsync();

        var ca = Assert.Single((await Reader(db).ReadAsync(CancellationToken.None)).CertificateAuthorities);

        Assert.Equal(new HubInventoryCertificateAuthority("Bare CA", null, HubInventoryCertificateAuthority.Active, null, null, null), ca);
    }

    // ---- the signer: what the readiness check last saw, never a call of its own ---------------------------

    [Fact]
    public async Task The_signer_is_reported_as_the_readiness_check_last_saw_it_with_the_time_it_asked()
    {
        using var db = InMemoryDbContextFactory.Create();
        async Task<HubInventorySigner?> ReadAsync() => (await Reader(db).ReadAsync(CancellationToken.None)).Signer;

        Assert.Null(await ReadAsync());

        _signer.Observe(new SignerHealth(false, 0, SignerHealth.Pkcs11Backend), SignerCheckedAt);
        Assert.Equal(new HubInventorySigner(HubInventorySigner.Locked, SignerCheckedAt), await ReadAsync());

        _signer.Observe(SignerHealth.Unreachable(), SignerCheckedAt.AddSeconds(30));
        Assert.Equal(new HubInventorySigner(HubInventorySigner.Unreachable, SignerCheckedAt.AddSeconds(30)), await ReadAsync());

        _signer.Observe(new SignerHealth(true, 3, SignerHealth.SoftwareBackend), SignerCheckedAt.AddSeconds(60));
        Assert.Equal(new HubInventorySigner(HubInventorySigner.Unlocked, SignerCheckedAt.AddSeconds(60)), await ReadAsync());

        _signer.ObserveUnreachable(SignerCheckedAt.AddSeconds(90));
        Assert.Equal(new HubInventorySigner(HubInventorySigner.Unreachable, SignerCheckedAt.AddSeconds(90)), await ReadAsync());
    }

    /// <summary>A signer every call of which throws: the readiness check must record that it did not answer.</summary>
    private class ThrowingSigner : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => throw new InvalidOperationException("the signer is away");
    }

    [Fact]
    public async Task The_readiness_check_keeps_what_the_signer_answered_and_when()
    {
        using var db = InMemoryDbContextFactory.Create();
        var keystore = new TestKeystore();
        var scopes = new ServiceCollection().BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
        ISigningService answering = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
            new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance);
        var state = new SignerContactState();
        IHealthCheck Check(ISigningService signer) => (IHealthCheck)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.ModularCAHealthCheck"),
            db, keystore, signer, new ApiCertificateProvider(), new SystemConfig(), null, null, state)!;

        Assert.Null(state.Last);
        var before = DateTime.UtcNow;
        await Check(answering).CheckHealthAsync(new HealthCheckContext());
        var expected = await answering.HealthAsync();

        var seen = state.Last!;
        Assert.True(seen.Reachable);
        Assert.Equal(expected.Unlocked, seen.Unlocked);
        Assert.InRange(seen.AtUtc, before, DateTime.UtcNow);

        await Check(DispatchProxy.Create<ISigningService, ThrowingSigner>()).CheckHealthAsync(new HealthCheckContext());
        Assert.False(state.Last!.Reachable);
        Assert.False(state.Last.Unlocked);
        Assert.True(state.Last.AtUtc >= seen.AtUtc);
    }

    // ---- the newest backup: valid is the verification job's last word, never this request's -----------------

    [Fact]
    public async Task A_backup_the_verification_job_never_checked_says_null_and_reading_it_checks_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        // The newest archive is one the job would fail. Nobody has checked it, so the answer is not "false".
        var newest = TwoArchives(newestWhole: false);

        var backup = (await Reader(db).ReadAsync(CancellationToken.None)).NewestBackup!;

        Assert.Equal(newest.Name, backup.FileName);
        Assert.Equal(3600, backup.AgeSeconds);
        Assert.Null(backup.Valid);
        Assert.Null(backup.VerifiedAtUtc);
        Assert.False(File.Exists(Path.Combine(BackupDirectory, BackupVerificationRecord.FileName)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_backup_the_last_verification_checked_says_what_that_run_found_and_when(bool found)
    {
        using var db = InMemoryDbContextFactory.Create();
        // The file on disk says the opposite of the record: the record is what is reported.
        var newest = TwoArchives(newestWhole: !found);
        var verifiedAt = new DateTime(2026, 11, 11, 2, 0, 0, DateTimeKind.Utc);
        BackupVerificationRecord.Write(BackupDirectory, new BackupVerificationRecord(verifiedAt, [new(newest.Name, found)]));

        var backup = (await Reader(db).ReadAsync(CancellationToken.None)).NewestBackup!;

        Assert.Equal(found, backup.Valid);
        Assert.Equal(verifiedAt, backup.VerifiedAtUtc);
    }

    [Fact]
    public async Task A_backup_newer_than_the_last_verification_is_not_yet_verified()
    {
        using var db = InMemoryDbContextFactory.Create();
        TwoArchives();
        BackupVerificationRecord.Write(BackupDirectory, new BackupVerificationRecord(Now.AddDays(-1),
            [new("modularca-backup-20261110-010000-aaaa.zip", true)]));

        var backup = (await Reader(db).ReadAsync(CancellationToken.None)).NewestBackup!;

        Assert.Equal("modularca-backup-20261111-010000-bbbb.zip", backup.FileName);
        Assert.Null(backup.Valid);
        Assert.Null(backup.VerifiedAtUtc);
    }

    [Fact]
    public async Task A_verification_record_that_cannot_be_read_means_not_verified()
    {
        using var db = InMemoryDbContextFactory.Create();
        TwoArchives();
        File.WriteAllText(Path.Combine(BackupDirectory, BackupVerificationRecord.FileName), "{ not json");

        Assert.Null((await Reader(db).ReadAsync(CancellationToken.None)).NewestBackup!.Valid);
    }

    /// <summary>The verification job is what writes the record the inventory reads: a run leaves what it found for each archive it checked.</summary>
    [Fact]
    public async Task A_run_of_the_verification_job_leaves_what_it_found_and_the_inventory_reports_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var newest = TwoArchives(newestWhole: false);
        var config = new SystemConfig();
        config.Backup.Enabled = true;
        config.Backup.VerifyOnSchedule = true;
        config.Backup.VerifyCount = 2;
        config.Backup.OutputPath = BackupDirectory;
        var services = new ServiceCollection().BuildServiceProvider();
        var alerts = new RecordingAlertService();
        var job = new BackupVerificationJob(services, config, alerts, NullLogger<BackupVerificationJob>.Instance,
            new SchedulerJobRunner(services, NullLogger<SchedulerJobRunner>.Instance, config, "test-instance"));

        var before = DateTime.UtcNow;
        await job.RunAsync(CancellationToken.None);

        var record = BackupVerificationRecord.TryRead(BackupDirectory)!;
        Assert.InRange(record.VerifiedAtUtc, before, DateTime.UtcNow);
        Assert.Equal(
            [new BackupVerificationRecord.Archive(newest.Name, false), new BackupVerificationRecord.Archive("modularca-backup-20261110-010000-aaaa.zip", true)],
            record.Archives);
        Assert.Contains(alerts.Raised, a => a.EventType == "BackupCorrupted");

        var backup = (await Reader(db).ReadAsync(CancellationToken.None)).NewestBackup!;
        Assert.False(backup.Valid);
        Assert.Equal(record.VerifiedAtUtc, backup.VerifiedAtUtc);
        // The record is not taken for an archive by anything that lists them.
        Assert.DoesNotContain(new DirectoryInfo(BackupDirectory).GetFiles("modularca-backup-*.*"), f => f.Name == BackupVerificationRecord.FileName);
    }

    // ---- failing jobs ------------------------------------------------------------------------------------

    // ---- a read starts no work ---------------------------------------------------------------------------

    [Fact]
    public async Task Reading_the_inventory_changes_nothing_and_starts_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        await SeedAsync(db);
        TwoArchives(newestWhole: false);
        string[] Files() => Directory.GetFiles(BackupDirectory).Select(f => $"{Path.GetFileName(f)}:{new FileInfo(f).Length}:{File.GetLastWriteTimeUtc(f):O}").Order().ToArray();
        async Task<string> RowsAsync() => JsonSerializer.Serialize(new
        {
            Crls = await db.Crls.AsNoTracking().OrderBy(c => c.CrlNumber).Select(c => new { c.Id, c.CrlNumber, c.NextUpdate }).ToListAsync(),
            Configurations = await db.CrlConfigurations.AsNoTracking().OrderBy(c => c.Name).Select(c => new { c.LastCrlNumber, c.NextUpdateUtc, c.LastGenerated }).ToListAsync(),
            Jobs = await db.SchedulerJobStates.AsNoTracking().OrderBy(j => j.JobName).ToListAsync(),
        });
        var filesBefore = Files();
        var rowsBefore = await RowsAsync();

        for (var i = 0; i < 3; i++)
            await Reader(db).ReadAsync(CancellationToken.None);

        // No CRL was signed, no job was run or marked, no archive was verified, nothing was written.
        Assert.Equal(rowsBefore, await RowsAsync());
        Assert.Equal(filesBefore, Files());
        Assert.False(db.ChangeTracker.HasChanges());
        Assert.Empty(db.ChangeTracker.Entries());
        Assert.Null(_signer.Last);
    }

    /// <summary>
    /// The reader is given nothing it could start work with: no signer, no CRL service, no
    /// scheduler, no job, no service provider to find one in.
    /// </summary>
    [Fact]
    public void The_reader_is_given_nothing_it_could_sign_verify_or_schedule_with()
    {
        var parameters = Assert.Single(typeof(NodeInventoryReader).GetConstructors()).GetParameters().Select(p => p.ParameterType).ToList();

        Assert.Equal(
            [
                typeof(ModularCADbContext), typeof(AuditDbContext), typeof(SignerContactState), typeof(ApiCertificateProvider),
                typeof(string), typeof(string), typeof(Microsoft.Extensions.Logging.ILogger), typeof(TimeProvider),
            ],
            parameters);
        Assert.DoesNotContain(typeof(NodeInventoryReader).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public),
            f => typeof(ISigningService).IsAssignableFrom(f.FieldType) || typeof(IServiceProvider).IsAssignableFrom(f.FieldType));
    }

    // ---- what the connection may never carry -------------------------------------------------------------

    [Fact]
    public async Task No_issued_certificate_user_key_or_secret_is_in_the_answer()
    {
        using var db = InMemoryDbContextFactory.Create();
        await SeedAsync(db);
        _signer.Observe(new SignerHealth(true, 2, SignerHealth.SoftwareBackend), SignerCheckedAt);
        var tls = WebTlsCertificate(DateTimeOffset.UtcNow.AddDays(30));
        _webTls.SetCertificate(tls);
        TwoArchives();

        var json = Json(await Reader(db).ReadAsync(CancellationToken.None));

        // The seeded rows are there to be found if a query ever selects them.
        Assert.Contains("Alpha Issuing", json);
        foreach (var forbidden in new[]
                 {
                     "BEGIN", "MIIB", "CERTIFICATE-", "X509 CRL", "PRIVATE",
                     SeededUsername, SeededEmail, SeededPasswordHash,
                     SubscriberSubject, "subscriber-device", SubscriberSerial, KeyBlob,
                     "Alpha OCSP Responder", "ca.inventory.example", tls.Thumbprint,
                     "Gone CA", "SSH Users",
                 })
            Assert.DoesNotContain(forbidden, json, StringComparison.OrdinalIgnoreCase);
        // No serial number, subject or thumbprint of any certificate, the CAs' included: names, states, numbers and dates only.
        foreach (var certificate in await db.Certificates.AsNoTracking().ToListAsync())
        {
            Assert.DoesNotContain(certificate.SerialNumber, json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(certificate.SubjectDN, json, StringComparison.OrdinalIgnoreCase);
        }
    }
}

/// <summary>
/// The inventory's queries on a real PostgreSQL instance in the layout a new install has, read as
/// the runtime roles the node runs under: the migration history of both databases, and the CA
/// query with its newest-CRL and responder look-ups as the provider translates them. Opt-in
/// through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.One)]
public sealed class PostgresHubInventoryTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_runtime_roles_read_the_schema_versions_and_the_cas_without_writing_a_row()
    {
        await using var f = await OwnershipFixture.CreateAsync(Environment.GetEnvironmentVariable(ServerVariable)!, OwnershipLayout.Fresh);
        await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql(f.RuntimeConnectionString(f.App, f.AppDatabase)).Options);
        await using var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(f.RuntimeConnectionString(f.Audit, f.AuditDatabase)).Options);

        var seeded = await PostgresCaFixture.SeedCaAsync(db, "inventory-ca");
        var task = await db.CrlConfigurations.SingleAsync(c => c.CaCertificateId == seeded.CaCertificateId);
        var nextUpdate = new DateTime(2026, 11, 12, 18, 0, 0, DateTimeKind.Utc);
        CrlEntity Crl(long number, bool delta, DateTime next) => new()
        {
            Id = Guid.NewGuid(), IssuerName = seeded.Material.SubjectDn, CrlNumber = number, IsDelta = delta, TaskId = task.TaskId,
            ThisUpdate = next.AddHours(-6), NextUpdate = next, GeneratedAt = next.AddHours(-6), PemData = "-----BEGIN X509 CRL-----", RawData = [0x30],
        };
        db.Crls.AddRange(Crl(7, false, nextUpdate.AddHours(-6)), Crl(8, false, nextUpdate), Crl(9, true, nextUpdate.AddHours(1)));
        var ocspId = Guid.NewGuid();
        var ocspExpiry = new DateTime(2027, 3, 1, 0, 0, 0, DateTimeKind.Utc);
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = ocspId, SerialNumber = "0C5B0C5B", SubjectDN = "CN=inventory OCSP", Issuer = seeded.Material.SubjectDn,
            NotBefore = ocspExpiry.AddYears(-1), NotAfter = ocspExpiry, Pem = "-----BEGIN CERTIFICATE-----", RawCertificate = [0x30],
        });
        (await db.CertificateAuthorities.SingleAsync(c => c.Id == seeded.CaId)).OcspResponderCertificateId = ocspId;
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Name = "inventory-gone", Label = "inventory-gone", IsDeleted = true, DeletedAt = DateTime.UtcNow });
        db.SchedulerJobStates.Add(new SchedulerJobStateEntity { JobName = "AuditRetention", LastRunUtc = nextUpdate, LastResult = "failed", LastError = "first\nsecond" });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var crlsBefore = await db.Crls.AsNoTracking().OrderBy(c => c.CrlNumber).Select(c => c.CrlNumber).ToListAsync();
        var numberBefore = (await db.CrlConfigurations.AsNoTracking().SingleAsync(c => c.TaskId == task.TaskId)).LastCrlNumber;

        var reader = new NodeInventoryReader(db, audit, new SignerContactState(), new ApiCertificateProvider(),
            Path.Combine(Path.GetTempPath(), "mhi-none-" + Guid.NewGuid().ToString("N")), "0.4.5-test", NullLogger.Instance);
        var inventory = await reader.ReadAsync(CancellationToken.None);

        var appMigrations = db.Database.GetMigrations().ToList();
        var auditMigrations = audit.Database.GetMigrations().ToList();
        Assert.Equal(new HubInventoryMigrations(appMigrations[^1], appMigrations.Count), inventory.Schema.Application);
        Assert.Equal(new HubInventoryMigrations(auditMigrations[^1], auditMigrations.Count), inventory.Schema.Audit);

        var ca = Assert.Single(inventory.CertificateAuthorities, c => c.Name == "inventory-ca");
        Assert.Equal(HubInventoryCertificateAuthority.Active, ca.State);
        Assert.Equal("inventory-ca", ca.Label);
        Assert.Equal(seeded.Material.Certificate.NotAfter.ToUniversalTime(), ca.CertificateExpiresAtUtc);
        Assert.Equal(new HubInventoryCrl(8, nextUpdate), ca.Crl);
        Assert.Equal(ocspExpiry, ca.OcspResponderCertificateExpiresAtUtc);
        Assert.Equal(DateTimeKind.Utc, ca.CertificateExpiresAtUtc!.Value.Kind);
        Assert.DoesNotContain(inventory.CertificateAuthorities, c => c.Name == "inventory-gone");
        Assert.Contains(new HubInventoryFailingJob("AuditRetention", "AuditRetention", nextUpdate), inventory.FailingJobs);
        Assert.Null(inventory.NewestBackup);

        Assert.Equal(crlsBefore, await db.Crls.AsNoTracking().OrderBy(c => c.CrlNumber).Select(c => c.CrlNumber).ToListAsync());
        Assert.Equal(numberBefore, (await db.CrlConfigurations.AsNoTracking().SingleAsync(c => c.TaskId == task.TaskId)).LastCrlNumber);
        Assert.DoesNotContain("BEGIN", JsonSerializer.Serialize(inventory, HubLocalContract.Json));
    }
}
