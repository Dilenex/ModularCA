using System.Collections;
using System.Reflection;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using Xunit;

namespace ModularCA.Tests.Roles;

/// <summary>
/// Seals the job-to-role table: every concrete <see cref="ISchedulerJob"/> in Core has exactly
/// one owning node role in the API's <c>SchedulerJobRoles</c>, the table names nothing that is
/// not a job, and the decisions the design records hold. A job added without an owner, or an
/// owner removed, fails here before startup would refuse it.
/// </summary>
public sealed class SchedulerJobRolesTests
{
    private const string Table = "ModularCA.API.Startup.SchedulerJobRoles";
    private const string ActiveRolesType = "ModularCA.API.Startup.ActiveRoles";

    /// <summary>Every concrete job Core declares, by full name.</summary>
    private static IReadOnlyList<Type> JobTypes()
        => typeof(SingletonCronJob).Assembly.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(ISchedulerJob).IsAssignableFrom(t))
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .ToList();

    /// <summary>The table as (job full name, owner enum name).</summary>
    private static Dictionary<string, string> Owners()
    {
        var table = ApiAssembly.TypeNamed(Table);
        var owners = (IDictionary)table.GetField("Owners", BindingFlags.Public | BindingFlags.Static)!.GetValue(null)!;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (DictionaryEntry entry in owners)
            result[((Type)entry.Key).FullName!] = entry.Value!.ToString()!;
        return result;
    }

    [Fact]
    public void The_walk_finds_the_jobs()
    {
        var jobs = JobTypes();
        Assert.True(jobs.Count >= 13, $"Only {jobs.Count} jobs were found; the walk is wrong.");
        Assert.Contains(jobs, j => j == typeof(CrlExportJob));
        Assert.Contains(jobs, j => j == typeof(AcmeCleanupJob));
    }

    [Fact]
    public void Every_registered_job_has_exactly_one_owning_node_role()
    {
        var owners = Owners();
        var single = NodeRoleArchitectureTests.SingleNodeRoles();
        var roleType = ApiAssembly.TypeNamed("ModularCA.API.Startup.ProcessRole");

        var failures = new List<string>();
        foreach (var job in JobTypes())
        {
            if (!owners.TryGetValue(job.FullName!, out var owner))
            {
                failures.Add($"{job.FullName}: no owning role");
                continue;
            }
            if (!single.Contains(Convert.ToInt32(Enum.Parse(roleType, owner))))
                failures.Add($"{job.FullName}: owner {owner} is not exactly one node role");
        }

        Assert.True(failures.Count == 0, "Every scheduled job has one owning role:\n  " + string.Join("\n  ", failures));
    }

    [Fact]
    public void The_table_names_only_jobs()
    {
        var jobs = JobTypes().Select(j => j.FullName!).ToHashSet();
        foreach (var name in Owners().Keys)
            Assert.Contains(name, jobs);
    }

    [Theory]
    [InlineData(typeof(AcmeCleanupJob), "Enrollment")]
    [InlineData(typeof(ProtocolCleanupJob), "Enrollment")]
    [InlineData(typeof(CrlExportJob), "Control")]
    [InlineData(typeof(LdapPublisherJob), "Control")]
    [InlineData(typeof(LdapGroupSyncJob), "Control")]
    [InlineData(typeof(CertExpiryNotificationJob), "Control")]
    [InlineData(typeof(ComplianceScanJob), "Control")]
    [InlineData(typeof(AutoRenewalJob), "Control")]
    [InlineData(typeof(CertExpireJob), "Control")]
    [InlineData(typeof(BackupCreationJob), "Control")]
    [InlineData(typeof(BackupVerificationJob), "Control")]
    [InlineData(typeof(AuditRetentionJob), "Control")]
    [InlineData(typeof(TlsRenewalJob), "Control")]
    public void The_decisions_hold(Type job, string owner)
    {
        Assert.Equal(owner, Owners()[job.FullName!]);
    }

    [Fact]
    public void Nothing_scheduled_belongs_to_validation()
    {
        Assert.DoesNotContain("Validation", Owners().Values);
    }

    [Fact]
    public void An_unlisted_job_type_is_refused()
    {
        var table = ApiAssembly.TypeNamed(Table);
        var ownerOf = table.GetMethod("OwnerOf", BindingFlags.Public | BindingFlags.Static)!;
        var ex = Assert.Throws<TargetInvocationException>(() => ownerOf.Invoke(null, new object[] { typeof(object) }));
        var inner = Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("System.Object", inner.Message);
        Assert.Contains("SchedulerJobRoles", inner.Message);
    }

    [Theory]
    [InlineData("Control", true, "scheduler")]
    [InlineData("All", true, "scheduler")]
    [InlineData("Node", true, "scheduler")]
    [InlineData("Enrollment,Control", true, "scheduler")]
    [InlineData("Enrollment", true, "scheduler:enrollment")]
    [InlineData("Enrollment,Validation", true, "scheduler:enrollment")]
    [InlineData("Validation", false, "scheduler:enrollment")]
    public void The_scheduler_runs_where_a_job_owner_runs_and_the_lease_follows_control(string roles, bool runs, string lease)
    {
        var table = ApiAssembly.TypeNamed(Table);
        var active = Activator.CreateInstance(ApiAssembly.TypeNamed(ActiveRolesType), NodeRoleConventionTests.RoleValue(roles))!;

        var runsScheduler = (bool)table.GetMethod("RunsScheduler", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, new[] { active })!;
        var leaseName = (string)table.GetMethod("LeaseNameFor", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, new[] { active })!;

        Assert.Equal(runs, runsScheduler);
        Assert.Equal(lease, leaseName);
    }
}
