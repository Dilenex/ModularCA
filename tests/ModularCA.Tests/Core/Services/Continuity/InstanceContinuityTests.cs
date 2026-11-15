using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Continuity;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Continuity;

/// <summary>
/// The incarnation comparison of a start (rollback-continuity.md, sections 1 and 2): each row of
/// the table, the CRL number floor a change applies, the one audit row, and the standing notice
/// that stays in <c>/health/ready</c> until an administrator acknowledges it with step-up.
/// </summary>
public sealed class InstanceContinuityTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);
    private static readonly IncarnationReading A = IncarnationReading.From(InjectedIncarnationSource.SourceName, "timeline-a");
    private static readonly IncarnationReading B = IncarnationReading.From(InjectedIncarnationSource.SourceName, "timeline-b");

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public RecordingAuditService Audit { get; } = new();
        public CrlConfigurationEntity Full { get; }
        public CrlConfigurationEntity Delta { get; }
        public CrlConfigurationEntity Ahead { get; }

        public World()
        {
            Full = Config("full", false, 40);
            Delta = Config("delta", true, 41);
            // A CA restored once before: its counter already stands above any floor of today.
            Ahead = Config("ahead", false, 5_000_000_000);
            Db.CrlConfigurations.AddRange(Full, Delta, Ahead);
            Db.SaveChanges();
        }

        private static CrlConfigurationEntity Config(string name, bool isDelta, long last) => new()
        {
            Name = name, IsDelta = isDelta, IssuerDN = "CN=Issuing CA", CaCertificateId = Guid.NewGuid(),
            UpdateInterval = "0 * * * *", LastCrlNumber = last, NextUpdateUtc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };

        public Task<IncarnationCheckResult> Start(IncarnationReading reading, DateTimeOffset? at = null)
            => InstanceContinuity.CheckIncarnationAsync(Db, null, Audit, reading, at ?? Now, NullLogger.Instance);

        public InstanceIncarnationEntity Stored => Db.InstanceIncarnation.AsNoTracking().Single();
        public long[] Counters => [.. Db.CrlConfigurations.AsNoTracking().OrderBy(c => c.Name).Select(c => c.LastCrlNumber)];
    }

    // ── The injected source ──────────────────────────────────────────────

    [Fact]
    public void The_injected_source_reads_the_environment_variable_and_nothing_means_none()
    {
        Assert.Equal("MODULARCA__INSTANCE__INCARNATION", InjectedIncarnationSource.Variable);
        var set = new InjectedIncarnationSource(name => name == InjectedIncarnationSource.Variable ? "restore-2026-11-11" : null);
        var unset = new InjectedIncarnationSource(_ => null);
        var blank = new InjectedIncarnationSource(_ => "   ");

        var reading = IncarnationSources.Read([set]);
        Assert.Equal("injected", reading.Source);
        Assert.False(reading.IsNone);
        Assert.Equal(64, reading.ValueHash!.Length);
        Assert.Equal(16, reading.Tag!.Length);
        Assert.DoesNotContain("restore", reading.ValueHash, StringComparison.OrdinalIgnoreCase);

        Assert.Same(IncarnationReading.None, IncarnationSources.Read([unset]));
        Assert.Same(IncarnationReading.None, IncarnationSources.Read([blank]));
        Assert.Same(IncarnationReading.None, IncarnationSources.Read([]));
    }

    [Fact]
    public void The_first_source_that_answers_wins_and_a_source_that_throws_is_skipped()
    {
        var throwing = new ThrowingSource();
        var first = new FixedSource("first", "one");
        var second = new FixedSource("second", "two");

        Assert.Equal("first", IncarnationSources.Read([throwing, new FixedSource("empty", null), first, second]).Source);
        // White space around the value is not part of it.
        Assert.Equal(IncarnationReading.From("x", "one"), IncarnationReading.From("x", " one\n"));
        Assert.NotEqual(IncarnationReading.From("x", "one").ValueHash, IncarnationReading.From("x", "two").ValueHash);
    }

    private sealed class FixedSource(string name, string? value) : IIncarnationSource
    {
        public string Name => name;
        public string? Read() => value;
    }

    private sealed class ThrowingSource : IIncarnationSource
    {
        public string Name => "throwing";
        public string? Read() => throw new IOException("no such file");
    }

    // ── The four cases of the table ──────────────────────────────────────

    [Fact]
    public async Task Nothing_stored_is_the_first_start_the_incarnation_is_stored_and_nothing_else_happens()
    {
        var w = new World();

        var result = await w.Start(A);

        Assert.Equal(IncarnationCase.FirstSeen, result.Case);
        Assert.Null(result.Event);
        Assert.Equal(A.ValueHash, w.Stored.ValueHash);
        Assert.Equal("injected", w.Stored.Source);
        Assert.Equal([5_000_000_000, 41, 40], w.Counters);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
    }

    [Fact]
    public async Task The_first_start_of_a_machine_with_no_source_stores_none()
    {
        var w = new World();

        Assert.Equal(IncarnationCase.FirstSeen, (await w.Start(IncarnationReading.None)).Case);
        Assert.Equal("none", w.Stored.Source);
        Assert.Null(w.Stored.ValueHash);

        // And every later start with still no source is the same timeline as far as it can tell.
        Assert.Equal(IncarnationCase.Same, (await w.Start(IncarnationReading.None)).Case);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
    }

    [Fact]
    public async Task The_same_incarnation_is_the_same_timeline_and_changes_nothing()
    {
        var w = new World();
        await w.Start(A);
        var storedAt = w.Stored.RecordedAt;

        var result = await w.Start(A, Now.AddDays(3));

        Assert.Equal(IncarnationCase.Same, result.Case);
        Assert.Null(result.Event);
        Assert.Equal(storedAt, w.Stored.RecordedAt);
        Assert.Equal([5_000_000_000, 41, 40], w.Counters);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
    }

    [Fact]
    public async Task A_changed_incarnation_raises_the_crl_numbers_records_one_event_and_one_audit_row_and_stores_the_new_value()
    {
        var w = new World();
        await w.Start(A);
        var newestCertificate = new DateTime(2026, 11, 10, 9, 30, 0, DateTimeKind.Utc);
        w.Db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "0A", SubjectDN = "CN=x", Issuer = "CN=Issuing CA", Pem = "x",
            NotBefore = newestCertificate, NotAfter = newestCertificate.AddDays(30), CreatedAt = newestCertificate,
        });
        w.Db.CertificateRequests.Add(new CertRequestEntity { SubmittedAt = newestCertificate.AddHours(-2) });
        w.Db.SaveChanges();

        var result = await w.Start(B);

        Assert.Equal(IncarnationCase.Changed, result.Case);
        var floor = Now.ToUnixTimeSeconds();
        // The floor is applied to full and delta alike, and never lowers a counter above it.
        Assert.Equal([5_000_000_000, floor, floor], w.Counters);
        Assert.Equal(2, result.Raised.Count);
        // Every configuration is due, so a CRL above the floor is published at once.
        Assert.All(w.Db.CrlConfigurations.AsNoTracking(), c => Assert.Equal(DateTime.MinValue, c.NextUpdateUtc));

        var recorded = Assert.Single(w.Db.InstanceContinuityEvents.AsNoTracking());
        Assert.Equal(ContinuityEventKind.IncarnationChanged, recorded.Kind);
        Assert.Equal(A.Tag, recorded.OldTag);
        Assert.Equal(B.Tag, recorded.NewTag);
        Assert.Equal(newestCertificate, recorded.EdgeOfMemoryUtc);
        Assert.Equal(floor, recorded.CrlNumberFloor);
        Assert.Equal(2, recorded.CrlCountersRaised);
        Assert.Null(recorded.AcknowledgedAt);
        Assert.Contains("nothing was replayed", recorded.DetailsJson);

        var audit = Assert.Single(w.Audit.Entries);
        Assert.Equal(AuditActionType.InstanceIncarnationChanged, audit.Action);
        Assert.Equal(recorded.Id.ToString(), audit.TargetId);
        var details = JsonSerializer.Serialize(audit.Details);
        Assert.Contains(A.Tag!, details);
        Assert.Contains(B.Tag!, details);
        Assert.Contains("2026-11-10T09:30:00", details);
        Assert.Contains($"\"Floor\":{floor}", details);
        Assert.Contains("nothing was replayed", details);

        Assert.Equal(B.ValueHash, w.Stored.ValueHash);

        var message = InstanceContinuity.MessageFor(recorded);
        Assert.StartsWith("This instance is running from an earlier or copied state.", message);
        Assert.Contains("after 2026-11-10 09:30:00 UTC on the earlier timeline are not known here", message);
        Assert.Contains("nothing was replayed", message);
    }

    [Fact]
    public async Task A_change_is_reported_once_the_next_start_on_the_new_timeline_is_quiet()
    {
        var w = new World();
        await w.Start(A);
        await w.Start(B);
        var after = w.Counters;

        var again = await w.Start(B, Now.AddHours(1));

        Assert.Equal(IncarnationCase.Same, again.Case);
        Assert.Equal(after, w.Counters);
        Assert.Single(w.Db.InstanceContinuityEvents);
        Assert.Single(w.Audit.Entries);
    }

    [Fact]
    public async Task A_second_change_never_lowers_what_the_first_raised()
    {
        var w = new World();
        await w.Start(A);
        await w.Start(B, Now);
        var raised = w.Counters;

        // The clock of the machine the database lands on is an hour behind.
        await w.Start(A, Now.AddHours(-1));

        Assert.Equal(raised, w.Counters);
        Assert.Equal(2, w.Db.InstanceContinuityEvents.Count());
    }

    [Fact]
    public async Task A_source_that_went_away_warns_once_and_stores_none()
    {
        var w = new World();
        await w.Start(A);

        var result = await w.Start(IncarnationReading.None);

        Assert.Equal(IncarnationCase.SourceLost, result.Case);
        Assert.Equal("none", w.Stored.Source);
        Assert.Null(w.Stored.ValueHash);
        // No rollback is known, so the CRL numbers stay.
        Assert.Equal([5_000_000_000, 41, 40], w.Counters);
        var recorded = Assert.Single(w.Db.InstanceContinuityEvents.AsNoTracking());
        Assert.Equal(ContinuityEventKind.IncarnationSourceLost, recorded.Kind);
        Assert.Equal(A.Tag, recorded.OldTag);
        Assert.Null(recorded.NewTag);
        Assert.Null(recorded.CrlNumberFloor);
        Assert.Equal(AuditActionType.InstanceIncarnationSourceLost, Assert.Single(w.Audit.Entries).Action);
        Assert.Contains("no longer reports an incarnation ID", InstanceContinuity.MessageFor(recorded));

        // Once: the next start with still no source says nothing more.
        Assert.Equal(IncarnationCase.Same, (await w.Start(IncarnationReading.None)).Case);
        Assert.Single(w.Db.InstanceContinuityEvents);
        Assert.Single(w.Audit.Entries);
    }

    [Fact]
    public async Task A_source_that_appears_where_none_was_stored_is_stored_without_an_event()
    {
        var w = new World();
        await w.Start(IncarnationReading.None);

        var result = await w.Start(A);

        Assert.Equal(IncarnationCase.SourceAppeared, result.Case);
        Assert.Equal(A.ValueHash, w.Stored.ValueHash);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
        Assert.Equal([5_000_000_000, 41, 40], w.Counters);
    }

    [Fact]
    public async Task An_audit_trail_that_cannot_be_written_does_not_undo_the_repair_or_the_notice()
    {
        var w = new World();
        await w.Start(A);

        var result = await InstanceContinuity.CheckIncarnationAsync(w.Db, null, new FailingAudit(), B, Now, NullLogger.Instance);

        Assert.Equal(IncarnationCase.Changed, result.Case);
        Assert.Single(w.Db.InstanceContinuityEvents);
        Assert.Equal(B.ValueHash, w.Stored.ValueHash);
    }

    private sealed class FailingAudit : ModularCA.Shared.Interfaces.IAuditService
    {
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new InvalidOperationException("audit database is down");
    }

    // ── The edge of memory ───────────────────────────────────────────────

    [Fact]
    public async Task The_edge_of_memory_is_the_latest_record_the_application_database_holds()
    {
        using var db = InMemoryDbContextFactory.Create();
        Assert.Null((await InstanceContinuity.EdgeOfMemoryAsync(db)).Edge);

        var t = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "01", SubjectDN = "CN=a", Issuer = "CN=i", Pem = "x", CreatedAt = t,
            NotBefore = t, NotAfter = t.AddDays(30), Revoked = true, RevocationReason = "Superseded", RevocationDate = t.AddDays(5),
        });
        db.CertificateRequests.Add(new CertRequestEntity { SubmittedAt = t.AddDays(2) });
        db.SaveChanges();

        var edge = await InstanceContinuity.EdgeOfMemoryAsync(db);

        Assert.Equal(t, edge.NewestCertificate);
        Assert.Equal(t.AddDays(2), edge.NewestRequest);
        Assert.Equal(t.AddDays(5), edge.NewestRevocation);
        Assert.Equal(t.AddDays(5), edge.Edge);

        // The scheduler renewed its lease at every tick until the database was last written:
        // on an instance that was running, that is the edge.
        db.SchedulerLeases.Add(new SchedulerLeaseEntity { Name = "scheduler", OwnerInstanceId = "node-1", AcquiredAtUtc = t.AddDays(9), ExpiresAtUtc = t.AddDays(9).AddMinutes(2) });
        db.SchedulerJobStates.Add(new SchedulerJobStateEntity { JobName = "CrlExportJob", LastRunUtc = t.AddDays(8) });
        db.SaveChanges();

        edge = await InstanceContinuity.EdgeOfMemoryAsync(db);

        Assert.Equal(t.AddDays(9), edge.NewestSchedulerActivity);
        Assert.Equal(t.AddDays(9), edge.Edge);
    }

    // ── The product's own restore ────────────────────────────────────────

    [Fact]
    public async Task A_restore_that_stores_the_incarnation_leaves_the_next_start_with_nothing_to_report()
    {
        var w = new World();
        await w.Start(A);                // the backup is taken on timeline A
        var restored = w.Counters;

        // --restore on another machine: it stores that machine's incarnation in the restored database.
        await InstanceContinuity.StoreIncarnationAsync(w.Db, B, "restore");

        Assert.Equal("restore", w.Stored.RecordedBy);
        var next = await w.Start(B);
        Assert.Equal(IncarnationCase.Same, next.Case);
        Assert.Empty(w.Db.InstanceContinuityEvents);
        Assert.Empty(w.Audit.Entries);
        Assert.Equal(restored, w.Counters);
    }

    [Fact]
    public async Task A_restore_onto_a_machine_with_no_source_stores_none_so_no_source_lost_warning_follows()
    {
        var w = new World();
        await w.Start(A);

        await InstanceContinuity.StoreIncarnationAsync(w.Db, IncarnationReading.None, "restore");

        Assert.Equal(IncarnationCase.Same, (await w.Start(IncarnationReading.None)).Case);
        Assert.Empty(w.Db.InstanceContinuityEvents);
    }

    // ── The standing notice: /health/ready and the acknowledgement ───────

    private static async Task<JsonElement> HealthAsync(ModularCADbContext db, object? state = null)
    {
        state ??= Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Startup.ContinuityStartState"))!;
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.ContinuityHealthCheck"), db, state)!;
        var result = await check.CheckHealthAsync(new HealthCheckContext());
        // Never a reason to stop serving: the instance came back and must stay in rotation.
        Assert.Equal(HealthStatus.Healthy, result.Status);
        return JsonDocument.Parse(JsonSerializer.Serialize(result.Data["continuity"])).RootElement;
    }

    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminContinuityController";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "root-admin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>Sends the acknowledgement as the pipeline would: the step-up filter first, the action only when it lets the request through.</summary>
    private static async Task<int> AcknowledgeAsync(World w, Guid actor, Guid eventId, IDistributedCache cache, string? token)
    {
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", actor.ToString())], "test")),
            RequestServices = new ServiceCollection().AddSingleton(cache).BuildServiceProvider(),
        };
        http.Request.Method = "POST";
        if (token != null)
            http.Request.Headers["X-MFA-Token"] = token;

        var type = ApiAssembly.TypeNamed(ControllerName);
        var method = type.GetMethod("Acknowledge")!;
        var filter = Assert.Single(method.GetCustomAttributes(true).OfType<ActionFilterAttribute>(), a => a.GetType().Name == "RequireStepUpAttribute");
        var route = new RouteData();
        route.Values["id"] = eventId.ToString();
        var executing = new ActionExecutingContext(new ActionContext(http, route, new ActionDescriptor()), [],
            new Dictionary<string, object?> { ["id"] = eventId }, new object());
        IActionResult? result = null;
        await filter.OnActionExecutionAsync(executing, async () =>
        {
            var controller = (ControllerBase)Activator.CreateInstance(type, w.Db, new CurrentUserStub(actor), w.Audit)!;
            controller.ControllerContext = new ControllerContext { HttpContext = http };
            result = await (Task<IActionResult>)method.Invoke(controller, [eventId])!;
            return new ActionExecutedContext(executing, [], controller);
        });
        return (executing.Result ?? result) switch
        {
            ObjectResult o => o.StatusCode ?? 200,
            StatusCodeResult s => s.StatusCode,
            _ => 0,
        };
    }

    [Fact]
    public async Task The_notice_stands_in_health_ready_until_it_is_acknowledged_with_step_up()
    {
        var w = new World();
        await w.Start(A);
        var quiet = await HealthAsync(w.Db);
        Assert.Equal("ok", quiet.GetProperty("status").GetString());
        Assert.Equal(0, quiet.GetProperty("unacknowledged").GetInt32());

        var changed = await w.Start(B);
        var eventId = changed.Event!.Id;

        var standing = await HealthAsync(w.Db);
        Assert.Equal("notice", standing.GetProperty("status").GetString());
        Assert.Equal(1, standing.GetProperty("unacknowledged").GetInt32());
        Assert.False(standing.GetProperty("journalReplayed").GetBoolean());
        var shown = Assert.Single(standing.GetProperty("events").EnumerateArray());
        Assert.Equal(eventId, shown.GetProperty("id").GetGuid());
        Assert.Equal(A.Tag, shown.GetProperty("oldTag").GetString());
        Assert.Equal(B.Tag, shown.GetProperty("newTag").GetString());
        Assert.StartsWith("This instance is running from an earlier or copied state.", shown.GetProperty("message").GetString());

        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        // Without a step-up token the request is refused and the notice stands.
        Assert.Equal(403, await AcknowledgeAsync(w, actor, eventId, cache, null));
        // A token for another operation, or for another event, is no better.
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.Restart}:{eventId}", "token");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.AcknowledgeContinuityEvent}:{Guid.NewGuid()}", "token");
        Assert.Equal(403, await AcknowledgeAsync(w, actor, eventId, cache, "token"));
        Assert.Equal("notice", (await HealthAsync(w.Db)).GetProperty("status").GetString());
        Assert.Single(w.Audit.Entries); // only the change itself

        // With a token for this operation on this event it is acknowledged, audited, and gone.
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.AcknowledgeContinuityEvent}:{eventId}", "token");
        Assert.Equal(200, await AcknowledgeAsync(w, actor, eventId, cache, "token"));

        var cleared = await HealthAsync(w.Db);
        Assert.Equal("ok", cleared.GetProperty("status").GetString());
        Assert.Empty(cleared.GetProperty("events").EnumerateArray());
        var row = w.Db.InstanceContinuityEvents.AsNoTracking().Single();
        Assert.NotNull(row.AcknowledgedAt);
        Assert.Equal(actor, row.AcknowledgedByUserId);
        Assert.Equal("root-admin", row.AcknowledgedByUsername);
        Assert.Equal(AuditActionType.InstanceContinuityAcknowledged, w.Audit.Entries[^1].Action);
        Assert.Equal(2, w.Audit.Entries.Count);
    }

    [Fact]
    public async Task The_acknowledgement_is_for_a_system_administrator_and_reading_for_a_system_auditor()
    {
        var type = ApiAssembly.TypeNamed(ControllerName);
        string? PolicyOf(string action) => type.GetMethod(action)!.GetCustomAttributes(true)
            .OfType<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>().Single().Policy;

        Assert.Equal("SystemAdmin", PolicyOf("Acknowledge"));
        Assert.Equal("SystemAuditor", PolicyOf("GetNotice"));
        Assert.Equal("SystemAuditor", PolicyOf("GetEvents"));

        var w = new World();
        var controller = (ControllerBase)Activator.CreateInstance(type, w.Db, new CurrentUserStub(Guid.NewGuid()), w.Audit)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        var missing = await (Task<IActionResult>)type.GetMethod("Acknowledge")!.Invoke(controller, [Guid.NewGuid()])!;
        Assert.IsType<NotFoundObjectResult>(missing);
    }

    [Fact]
    public async Task The_notice_endpoint_shows_the_unacknowledged_events_and_the_stored_incarnation_but_never_its_value()
    {
        var w = new World();
        await w.Start(A);
        await w.Start(B);
        var type = ApiAssembly.TypeNamed(ControllerName);
        var controller = (ControllerBase)Activator.CreateInstance(type, w.Db, new CurrentUserStub(Guid.NewGuid()), w.Audit)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        var result = await (Task<IActionResult>)type.GetMethod("GetNotice")!.Invoke(controller, [])!;

        var json = JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value);
        var body = JsonDocument.Parse(json).RootElement;
        Assert.True(body.GetProperty("applies").GetBoolean());
        Assert.Single(body.GetProperty("events").EnumerateArray());
        Assert.Equal("injected", body.GetProperty("incarnation").GetProperty("source").GetString());
        Assert.Equal(B.Tag, body.GetProperty("incarnation").GetProperty("tag").GetString());
        Assert.DoesNotContain(B.ValueHash!, json);
        Assert.DoesNotContain("timeline-b", json);
    }

    [Fact]
    public async Task A_comparison_that_failed_shows_in_health_ready_without_failing_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var state = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Startup.ContinuityStartState"))!;
        state.GetType().GetMethod("Failed")!.Invoke(state, ["NpgsqlException: connection refused"]);

        var health = await HealthAsync(db, state);

        Assert.Equal("check_failed", health.GetProperty("status").GetString());
        Assert.Equal("NpgsqlException: connection refused", health.GetProperty("checkFault").GetString());
    }
}
