using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.SchedulerJobs;

/// <summary>
/// Pins which request rows the protocol cleanup removes and, more importantly, which it leaves
/// alone: a person's upload, an approval-gated request, an issued one, one an ACME order still
/// points at, and anything younger than the grace window.
/// </summary>
/// <remarks>
/// The job exists because a refused protocol enrollment (a Windows client's SHA-1-signed request
/// on the staging host, for one) leaves a <c>Pending</c> row nobody will act on. The SCEP and
/// CMP transaction sweeps are pinned here too, because they used to run only when ACME had
/// work of its own, which on a host without ACME traffic meant never.
/// </remarks>
public class ProtocolCleanupJobTests
{
    private sealed class RecordingAudit : IAuditService
    {
        public List<(string Action, object? Details)> Entries { get; } = [];
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? tenantId = null)
        {
            Entries.Add((actionType, details));
            return Task.CompletedTask;
        }
    }

    private static readonly DateTime Now = new(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc);

    private static (ProtocolCleanupJob Job, ModularCADbContext Db, RecordingAudit Audit) Build(int graceMinutes = 60)
    {
        var db = InMemoryDbContextFactory.Create();
        var config = new SystemConfig();
        config.ProtocolCleanup.OrphanRequestGraceMinutes = graceMinutes;
        var sp = new ServiceCollection().BuildServiceProvider();
        var time = new FixedTimeProvider(new DateTimeOffset(Now));
        var audit = new RecordingAudit();
        var job = new ProtocolCleanupJob(NullLogger<ProtocolCleanupJob>.Instance, db, audit, config, sp,
            new SchedulerJobRunner(sp, NullLogger<SchedulerJobRunner>.Instance, config, "test", time), time);
        return (job, db, audit);
    }

    private static CertRequestEntity Request(string status = "Pending", int ageMinutes = 120, Guid? requestor = null, Guid? issued = null)
        => new()
        {
            Id = Guid.NewGuid(), Subject = $"CN={Guid.NewGuid():N}", CSR = "-----BEGIN CERTIFICATE REQUEST-----",
            Status = status, SubmittedAt = Now.AddMinutes(-ageMinutes), RequestorUserId = requestor, IssuedCertificateId = issued,
        };

    [Fact]
    public async Task An_old_pending_protocol_request_with_nothing_to_issue_it_is_removed()
    {
        var (job, db, audit) = Build();
        var orphan = Request();
        db.CertificateRequests.Add(orphan);
        await db.SaveChangesAsync();

        var result = await job.RunOnceAsync(CancellationToken.None);

        Assert.Equal(1, result.OrphanedRequests);
        Assert.Empty(db.CertificateRequests);
        Assert.Equal("ProtocolCleanupCompleted", Assert.Single(audit.Entries).Action);
    }

    [Fact]
    public async Task Rows_that_someone_or_something_still_owns_are_kept()
    {
        var (job, db, _) = Build();
        var person = Request(requestor: Guid.NewGuid());                 // an operator's upload awaiting issuance
        var awaitingApproval = Request(status: "PendingApproval");         // an approver owns it
        var issued = Request(issued: Guid.NewGuid());                      // already has its certificate
        var approved = Request();                                          // has approval records
        var acmeBacked = Request();                                        // an ACME order still points at it
        db.CertificateRequests.AddRange(person, awaitingApproval, issued, approved, acmeBacked);
        db.CsrApprovals.Add(new CsrApprovalEntity { Id = Guid.NewGuid(), CertRequestId = approved.Id, CertRequest = approved });
        db.AcmeOrders.Add(new AcmeOrderEntity { Id = Guid.NewGuid(), FinalizedCsrId = acmeBacked.Id, AccountId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var result = await job.RunOnceAsync(CancellationToken.None);

        Assert.Equal(0, result.OrphanedRequests);
        Assert.Equal(5, db.CertificateRequests.Count());
    }

    [Fact]
    public async Task A_request_inside_the_grace_window_is_left_for_issuance_to_finish()
    {
        var (job, db, _) = Build(graceMinutes: 60);
        var fresh = Request(ageMinutes: 59);
        var stale = Request(ageMinutes: 61);
        db.CertificateRequests.AddRange(fresh, stale);
        await db.SaveChangesAsync();

        var result = await job.RunOnceAsync(CancellationToken.None);

        Assert.Equal(1, result.OrphanedRequests);
        Assert.Equal(fresh.Id, Assert.Single(db.CertificateRequests).Id);
    }

    [Fact]
    public async Task Expired_scep_and_cmp_transactions_are_swept_even_when_no_request_is_orphaned()
    {
        // The sweeps ran after an early return in the ACME job before; here they must run
        // unconditionally.
        var (job, db, audit) = Build();
        db.ScepTransactions.AddRange(
            new ScepTransactionEntity { Id = Guid.NewGuid(), TransactionId = "expired", ExpiresAt = Now.AddMinutes(-1) },
            new ScepTransactionEntity { Id = Guid.NewGuid(), TransactionId = "live", ExpiresAt = Now.AddMinutes(5) });
        db.CmpTransactions.AddRange(
            new CmpTransactionEntity { Id = Guid.NewGuid(), TransactionId = "old", CreatedAt = Now.AddHours(-2) },
            new CmpTransactionEntity { Id = Guid.NewGuid(), TransactionId = "recent", CreatedAt = Now.AddMinutes(-30) });
        await db.SaveChangesAsync();

        var result = await job.RunOnceAsync(CancellationToken.None);

        Assert.Equal((0, 1, 1), (result.OrphanedRequests, result.ScepTransactions, result.CmpTransactions));
        Assert.Equal("live", Assert.Single(db.ScepTransactions).TransactionId);
        Assert.Equal("recent", Assert.Single(db.CmpTransactions).TransactionId);
        Assert.Single(audit.Entries);
    }

    [Fact]
    public async Task A_pass_with_nothing_to_do_writes_no_audit_entry()
    {
        var (job, db, audit) = Build();
        db.CertificateRequests.Add(Request(ageMinutes: 1));
        await db.SaveChangesAsync();

        var result = await job.RunOnceAsync(CancellationToken.None);

        Assert.Equal(0, result.Total);
        Assert.Empty(audit.Entries);
    }
}
