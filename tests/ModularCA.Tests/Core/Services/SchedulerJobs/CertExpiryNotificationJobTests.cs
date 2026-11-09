using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// <see cref="CertExpiryNotificationJob.ProcessCertificatesAsync"/>: one message when a
/// certificate's soft warning starts, one at each reminder inside the warning, one when its alert
/// starts, each at most once per certificate however often the job runs (it used to mail every
/// certificate inside each threshold every day). Never-warn, dismissed, retired, revoked and CA
/// certificates get nothing, nor do certificates already replaced. Replaces the 0.4.2 midnight tests: the log is keyed by the
/// certificate's expiry date now, not the day the job ran.
/// </summary>
public sealed class CertExpiryNotificationJobTests
{
    private static readonly DateTime T0 = new(2026, 4, 1, 0, 0, 0, DateTimeKind.Utc);

    private sealed class Clock(DateTime now) : TimeProvider
    {
        public DateTime Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => new(Now, TimeSpan.Zero);
    }

    private sealed class Recorder : NoopNotificationService
    {
        public List<(string Serial, string Stage)> Sent { get; } = [];
        public override Task NotifyCertExpiryStageAsync(CertificateEntity cert, string stage, DateTime now)
        {
            Sent.Add((cert.SerialNumber, stage));
            return Task.CompletedTask;
        }
    }

    private sealed record World(CertExpiryNotificationJob Job, Clock Clock, Recorder Mail, RecordingAlertService Alerts, IServiceProvider Sp)
    {
        public Task<int> RunAtAsync(DateTime at)
        {
            Clock.Now = at;
            return Job.ProcessCertificatesAsync(CancellationToken.None);
        }

        public async Task<List<NotificationLogEntity>> LogsAsync()
        {
            await using var scope = Sp.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<ModularCADbContext>().NotificationLogs.AsNoTracking().ToListAsync();
        }
    }

    private static World Build(List<int> reminderDays, params CertificateEntity[] certs) => Build(reminderDays, null, certs);

    private static World Build(List<int> reminderDays, Action<ModularCADbContext>? seedMore, params CertificateEntity[] certs)
    {
        var services = new ServiceCollection();
        var dbName = $"expiry-{Guid.NewGuid():N}";
        services.AddDbContext<ModularCADbContext>(o => o.UseInMemoryDatabase(dbName).ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning)));
        var sp = services.BuildServiceProvider();
        using (var seed = sp.CreateScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<ModularCADbContext>();
            db.Certificates.AddRange(certs);
            seedMore?.Invoke(db);
            db.SaveChanges();
        }

        var config = new SystemConfig();
        config.CertExpiryNotification.Enabled = true;
        config.Email.Enabled = true;
        config.CertExpiryNotification.WarningDaysBeforeExpiry = reminderDays;
        var clock = new Clock(T0);
        var mail = new Recorder();
        var alerts = new RecordingAlertService();
        var jobDb = sp.CreateScope().ServiceProvider.GetRequiredService<ModularCADbContext>();
        var job = new CertExpiryNotificationJob(sp, jobDb, mail, alerts, config, NullLogger<CertExpiryNotificationJob>.Instance,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test", clock), timeProvider: clock);
        return new World(job, clock, mail, alerts, sp);
    }

    /// <summary>A certificate valid from <paramref name="from"/> for <paramref name="lifetime"/>; the save gives it the default instants (30 %, 10 %).</summary>
    private static CertificateEntity Cert(string serial, DateTime from, TimeSpan lifetime, Action<CertificateEntity>? configure = null)
    {
        var cert = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = serial, SubjectDN = $"CN={serial}.example", Issuer = "CN=Test CA",
            NotBefore = from, NotAfter = from + lifetime,
        };
        configure?.Invoke(cert);
        return cert;
    }

    [Fact]
    public async Task The_warning_each_reminder_inside_it_and_the_alert_are_sent_once_and_never_repeated_daily()
    {
        // 100 days: warning at day 70, alert at day 90. The 30-day reminder falls on the warning
        // itself and is not sent; 14, 7 and 1 days fall inside it.
        var w = Build([30, 14, 7, 1], Cert("hundred", T0, TimeSpan.FromDays(100)));

        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(60)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(71)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(72)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(73)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(87)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(91)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(92)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(94)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(99.5)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(99.9)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(101)));

        Assert.Equal(
            new[] { CertExpiryStage.Warning, CertExpiryStage.Reminder, CertExpiryStage.Alert, CertExpiryStage.Reminder, CertExpiryStage.Reminder },
            w.Mail.Sent.Select(s => s.Stage).ToArray());
        Assert.Equal(
            new[] { AlertSeverity.Warning, AlertSeverity.Warning, AlertSeverity.Critical, AlertSeverity.Warning, AlertSeverity.Warning },
            w.Alerts.Raised.Select(a => a.Severity).ToArray());

        var logs = await w.LogsAsync();
        Assert.Equal(
            new[] { "CertExpiryAlert", "CertExpiryReminder_14d", "CertExpiryReminder_1d", "CertExpiryReminder_7d", "CertExpiryWarning" },
            logs.Select(l => l.EventType).Order(StringComparer.Ordinal).ToArray());
        Assert.All(logs, l => Assert.Equal(T0.AddDays(100).Date, l.NotificationDate));
    }

    [Fact]
    public async Task A_certificate_first_seen_past_several_steps_gets_one_message_for_the_latest()
    {
        var w = Build([14, 7], Cert("late", T0, TimeSpan.FromDays(100)));

        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(95)));
        Assert.Equal((("late", CertExpiryStage.Reminder)), Assert.Single(w.Mail.Sent));
        Assert.Equal(4, (await w.LogsAsync()).Count);
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(96)));
    }

    [Fact]
    public async Task A_short_lived_certificate_warns_hours_before_it_expires_not_from_birth()
    {
        var w = Build([30, 7, 1], Cert("ten-hours", T0, TimeSpan.FromHours(10)));

        Assert.Equal(0, await w.RunAtAsync(T0.AddMinutes(5)));
        Assert.Equal(0, await w.RunAtAsync(T0.AddHours(6.5)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddHours(7.5)));
        Assert.Equal(1, await w.RunAtAsync(T0.AddHours(9.5)));
        Assert.Equal(new[] { CertExpiryStage.Warning, CertExpiryStage.Alert }, w.Mail.Sent.Select(s => s.Stage).ToArray());
    }

    [Fact]
    public async Task Crossing_midnight_does_not_send_again()
    {
        var w = Build([], Cert("midnight", T0, TimeSpan.FromDays(100)));
        var evening = T0.AddDays(75).AddHours(23).AddMinutes(59);

        Assert.Equal(1, await w.RunAtAsync(evening));
        Assert.Equal(0, await w.RunAtAsync(evening.AddMinutes(2)));
        Assert.Equal(T0.AddDays(100).Date, Assert.Single(await w.LogsAsync()).NotificationDate);
    }

    [Fact]
    public async Task Never_warn_dismissed_retired_revoked_and_ca_certificates_get_nothing()
    {
        var lifetime = TimeSpan.FromDays(100);
        var w = Build([7],
            Cert("never", T0, lifetime, c => (c.ExpiryWarningAt, c.ExpiryAlertAt) = (c.NotAfter, c.NotAfter)),
            Cert("dismissed", T0, lifetime, c => c.ExpiryWarningDismissedAt = T0),
            Cert("retired", T0, lifetime, c => c.RetiredAt = T0),
            Cert("revoked", T0, lifetime, c => c.Revoked = true),
            Cert("ca", T0, lifetime, c => c.IsCA = true),
            Cert("open", T0, lifetime));

        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(95)));
        Assert.Equal("open", Assert.Single(w.Mail.Sent).Serial);
        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(99.99)));
    }

    [Fact]
    public async Task Replaced_certificates_get_no_warning_reminder_or_critical_alert()
    {
        // At day 95 every 100-day certificate below is in its alert. "renewed" has a newer
        // certificate with its subject and SANs, "relinked" a renewal request that issued one,
        // "reissued" the reissue flag: the lifecycle summary counts all three as replaced.
        var lifetime = TimeSpan.FromDays(100);
        var renewed = Cert("renewed", T0, lifetime);
        var successor = Cert("successor", T0.AddDays(60), lifetime, c => c.SubjectDN = renewed.SubjectDN);
        var relinked = Cert("relinked", T0, lifetime);
        var relinkSuccessor = Cert("relink-successor", T0.AddDays(60), lifetime);
        var reissued = Cert("reissued", T0, lifetime, c => c.IsReissued = true);
        var open = Cert("open", T0, lifetime);
        var w = Build([],
            db => db.CertificateRequests.Add(new CertRequestEntity
            {
                Subject = relinkSuccessor.SubjectDN, Status = "Issued", IssuedCertificateId = relinkSuccessor.CertificateId,
                RenewalOfCertificateId = relinked.CertificateId,
            }),
            renewed, successor, relinked, relinkSuccessor, reissued, open);

        Assert.Equal(1, await w.RunAtAsync(T0.AddDays(95)));
        Assert.Equal(("open", CertExpiryStage.Alert), Assert.Single(w.Mail.Sent));
        Assert.Equal(AlertSeverity.Critical, Assert.Single(w.Alerts.Raised).Severity);
        Assert.All(await w.LogsAsync(), l => Assert.Equal(open.CertificateId.ToString(), l.TargetEntityId));

        Assert.Equal(0, await w.RunAtAsync(T0.AddDays(99.5)));
        Assert.Single(w.Mail.Sent);
    }
}
