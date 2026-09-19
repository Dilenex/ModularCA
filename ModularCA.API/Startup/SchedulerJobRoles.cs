using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Startup;

/// <summary>
/// Which role owns each scheduled job, one declaration per job. The scheduler ticks only the
/// jobs of the roles this process runs, so a validation-only process runs none and an
/// enrollment-only process runs the protocol sweeps and nothing that mutates. The control
/// plane owns everything else: CRL generation and publishing, LDAP publishing and group sync,
/// renewals, expiry, notifications, compliance, backups, audit retention and the TLS renewal.
/// A job with no owner stops startup, and the architecture test over this table fails first.
/// </summary>
public static class SchedulerJobRoles
{
    /// <summary>The lease the control plane's scheduler holds; the name every install has used.</summary>
    public const string ControlLeaseName = "scheduler";

    /// <summary>The lease an enrollment process without the control role holds, so the two do not starve each other.</summary>
    public const string EnrollmentLeaseName = "scheduler:enrollment";

    /// <summary>The owner of every registered job.</summary>
    public static readonly IReadOnlyDictionary<Type, ProcessRole> Owners = new Dictionary<Type, ProcessRole>
    {
        // Enrollment: sweeps of the protocols' own state, nothing the control plane publishes.
        [typeof(AcmeCleanupJob)] = ProcessRole.Enrollment,
        [typeof(ProtocolCleanupJob)] = ProcessRole.Enrollment,

        // Control: every job that generates, publishes, issues, deletes, backs up or notifies.
        [typeof(CrlExportJob)] = ProcessRole.Control,
        [typeof(LdapPublisherJob)] = ProcessRole.Control,
        [typeof(LdapGroupSyncJob)] = ProcessRole.Control,
        [typeof(CertExpiryNotificationJob)] = ProcessRole.Control,
        [typeof(ComplianceScanJob)] = ProcessRole.Control,
        [typeof(AutoRenewalJob)] = ProcessRole.Control,
        [typeof(CertExpireJob)] = ProcessRole.Control,
        [typeof(BackupCreationJob)] = ProcessRole.Control,
        [typeof(BackupVerificationJob)] = ProcessRole.Control,
        [typeof(AuditRetentionJob)] = ProcessRole.Control,
        [typeof(TlsRenewalJob)] = ProcessRole.Control,
    };

    /// <summary>
    /// The role that owns <paramref name="jobType"/>. Throws <see cref="InvalidOperationException"/>
    /// naming the type when the table does not list it.
    /// </summary>
    public static ProcessRole OwnerOf(Type jobType)
    {
        ArgumentNullException.ThrowIfNull(jobType);
        return Owners.TryGetValue(jobType, out var role)
            ? role
            : throw new InvalidOperationException($"{jobType.FullName} is a scheduled job with no owning role; add it to SchedulerJobRoles.");
    }

    /// <summary>Whether this process runs any role that owns a job, so whether it hosts the scheduler at all.</summary>
    public static bool RunsScheduler(ActiveRoles roles)
        => roles.Has(ProcessRole.Control) || roles.Has(ProcessRole.Enrollment);

    /// <summary>
    /// The lease name this process's scheduler contends for. The control plane keeps the name
    /// every install has used, so a single process is unchanged; an enrollment process without
    /// the control role takes its own, because two processes with different job sets sharing one
    /// lease would leave the loser's jobs unrun for as long as the winner refreshed it.
    /// </summary>
    public static string LeaseNameFor(ActiveRoles roles)
        => roles.Has(ProcessRole.Control) ? ControlLeaseName : EnrollmentLeaseName;

    /// <summary>
    /// Registers a scheduled job: the concrete type always, so the admin scheduler's manual run
    /// can resolve it, and the <see cref="ISchedulerJob"/> binding the scheduler ticks only when
    /// this process runs the job's owning role.
    /// </summary>
    public static IServiceCollection AddSchedulerJob<TJob>(this IServiceCollection services, ActiveRoles roles)
        where TJob : class, ISchedulerJob
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(roles);
        services.AddScoped<TJob>();
        if (roles.Has(OwnerOf(typeof(TJob))))
            services.AddScoped<ISchedulerJob, TJob>(sp => sp.GetRequiredService<TJob>());
        return services;
    }
}
