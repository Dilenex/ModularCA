using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;

namespace ModularCA.API.Startup;

/// <summary>
/// Which role owns each scheduled job, one declaration per job. The scheduler ticks only the
/// jobs of the roles this process runs, so a validation-only process runs none and an
/// enrollment-only process runs the protocol sweeps and nothing that mutates. The control
/// plane owns everything else: CRL generation and publishing, LDAP publishing and group sync,
/// renewals, expiry, notifications, compliance, backups, audit retention, the TLS renewal and
/// the SSH login name sweep, which revokes SSH certificates beside the SSH admin API.
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
        [typeof(SshLoginNameSweepJob)] = ProcessRole.Control,
    };

    /// <summary>
    /// The mode class of every registered job, which decides the modes the scheduler runs it in
    /// (<see cref="InstanceModeGate.Allows"/>). Scheduled issuance, CRL signing, publishing and
    /// the sweeps are facts or restrictions: they go on while the instance is restricted and are
    /// held in DR mode. The directory group sync changes grants and the audit retention deletes,
    /// so both wait for full mode. Backups change no instance data and run in every mode.
    /// A job with no class stops startup, and the architecture test over this table fails first.
    /// </summary>
    public static readonly IReadOnlyDictionary<Type, ModeOperation> ModeOperations = new Dictionary<Type, ModeOperation>
    {
        [typeof(AcmeCleanupJob)] = ModeOperation.Fact,
        [typeof(ProtocolCleanupJob)] = ModeOperation.Fact,
        [typeof(CrlExportJob)] = ModeOperation.Fact,
        [typeof(LdapPublisherJob)] = ModeOperation.Fact,
        [typeof(LdapGroupSyncJob)] = ModeOperation.Frozen,
        [typeof(CertExpiryNotificationJob)] = ModeOperation.Fact,
        [typeof(ComplianceScanJob)] = ModeOperation.Fact,
        [typeof(AutoRenewalJob)] = ModeOperation.Issue,
        [typeof(CertExpireJob)] = ModeOperation.Fact,
        [typeof(BackupCreationJob)] = ModeOperation.Manage,
        [typeof(BackupVerificationJob)] = ModeOperation.Manage,
        [typeof(AuditRetentionJob)] = ModeOperation.Frozen,
        [typeof(TlsRenewalJob)] = ModeOperation.Fact,
        [typeof(SshLoginNameSweepJob)] = ModeOperation.Restriction,
    };

    /// <summary>
    /// The mode class of <paramref name="jobType"/>. Throws <see cref="InvalidOperationException"/>
    /// naming the type when the table does not list it.
    /// </summary>
    public static ModeOperation ModeOperationOf(Type jobType)
    {
        ArgumentNullException.ThrowIfNull(jobType);
        return ModeOperations.TryGetValue(jobType, out var operation)
            ? operation
            : throw new InvalidOperationException($"{jobType.FullName} is a scheduled job with no mode class; add it to SchedulerJobRoles.ModeOperations.");
    }

    /// <summary>
    /// The mode class of the job a manual run names (<c>AutoRenewal</c>, <c>Compliance</c>):
    /// the job type's name without its <c>Job</c> suffix, and <c>Compliance</c> for the compliance
    /// scan. A name that is no job's is <see cref="ModeOperation.Frozen"/>, the most restrictive.
    /// </summary>
    public static ModeOperation ModeOperationOfName(string jobName)
    {
        foreach (var (type, operation) in ModeOperations)
        {
            var name = type == typeof(ComplianceScanJob) ? "Compliance" : type.Name[..^"Job".Length];
            if (string.Equals(name, jobName, StringComparison.Ordinal))
                return operation;
        }
        return ModeOperation.Frozen;
    }

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
        _ = ModeOperationOf(typeof(TJob));
        services.AddScoped<TJob>();
        if (roles.Has(OwnerOf(typeof(TJob))))
            services.AddScoped<ISchedulerJob, TJob>(sp => sp.GetRequiredService<TJob>());
        return services;
    }
}
