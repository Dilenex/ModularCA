using System.Collections.Concurrent;
using System.Text.Json.Serialization;

namespace ModularCA.Shared.Models.Config
{

    public class SystemConfig
    {
        public DbConfig DB { get; set; } = new();
        public JwtConfig JWT { get; set; } = new();
        public SecurityConfig Security { get; set; } = new();
        public LdapAuthConfig LdapAuth { get; set; } = new();
        public LoggingConfig Logging { get; set; } = new();
        public HttpConfig Http { get; set; } = new();
        public SchedulerConfig Scheduler { get; set; } = new();
        public TokenConfig Tokens { get; set; } = new();
        public SshCaConfig SshCa { get; set; } = new();
        public MetricsConfig Metrics { get; set; } = new();
        public EmailConfig Email { get; set; } = new();
        public HttpsConfig Https { get; set; } = new();
        public HsmConfig Hsm { get; set; } = new();
        public IpWhitelistConfig IpWhitelist { get; set; } = new();
        public NetworkAuditConfig NetworkAudit { get; set; } = new();
        public WebhookConfig Webhook { get; set; } = new();
        public MtlsConfig Mtls { get; set; } = new();
        public AcmeConfig Acme { get; set; } = new();
        public EstConfig Est { get; set; } = new();
        public BackupConfig Backup { get; set; } = new();
        public WebAuthnConfig WebAuthn { get; set; } = new();
        public AlertConfig Alert { get; set; } = new();
        public CertExpiryNotificationConfig CertExpiryNotification { get; set; } = new();
        public ComplianceScanConfig ComplianceScan { get; set; } = new();
        public CertPolicyConfig CertPolicy { get; set; } = new();
        public AutoRenewalConfig AutoRenewal { get; set; } = new();

        public IntegrationApiConfig IntegrationApi { get; set; } = new();
        public PolicySyncConfig PolicySync { get; set; } = new();
        public CertManagerConfig CertManager { get; set; } = new();

        /// <summary>
        /// Where this deployment's source can be obtained, for the AGPL section 13 offer.
        /// </summary>
        public SourceCodeConfig SourceCode { get; set; } = new();

        /// <summary>
        /// ICF-07 / ICF-08: optional Redis backend for distributed cache and Data Protection
        /// keyring. When enabled, MFA step-up tokens, WebAuthn challenges, and Data Protection
        /// keys are stored in Redis instead of node-local memory/filesystem, enabling multi-node
        /// deployments without sticky sessions.
        /// </summary>
        public RedisConfig Redis { get; set; } = new();

        /// <summary>
        /// Audit logging policy (retention, rotation,
        /// fail-mode). Bucketed into its own section because audit is a cross-cutting
        /// compliance surface and the retention story needs to live apart from the
        /// other control knobs.
        /// </summary>
        public AuditConfig Audit { get; set; } = new();
    }

    /// <summary>
    /// Centralized audit logging policy. Holds the retention/rotation schedule,
    /// archive policy, and the new fail-mode knob that controls what happens when the
    /// audit database is unreachable.
    /// </summary>
    public class AuditConfig
    {
        /// <summary>
        /// Retention policy. Controls the scheduled
        /// <c>AuditRetentionJob</c> which batches deletes past-due rows from the
        /// AuditLogs/AuditEst/AuditScep/AuditCmp/AuditAcme/AuditNetwork tables.
        /// </summary>
        public AuditRetentionConfig Retention { get; set; } = new();

        /// <summary>
        /// Fail-mode for audit write failures. Controls what happens
        /// when <see cref="ModularCA.Core.Services.AuditService.LogAsync"/> cannot
        /// persist a row. Default is <see cref="AuditFailMode.LogAndAlert"/> — logs,
        /// raises a <c>Critical</c> <c>ISecurityAlertService</c> alert on the first
        /// failure per rolling window, and lets the business op continue. High-assurance
        /// deployments can flip to <see cref="AuditFailMode.FailClosed"/> to refuse the
        /// business operation when the audit row cannot be written.
        /// </summary>
        public AuditFailMode FailMode { get; set; } = AuditFailMode.LogAndAlert;

        /// <summary>
        /// Minimum seconds between successive audit-failure alerts
        /// raised to <see cref="ModularCA.Core.Services.ISecurityAlertService"/>. Prevents
        /// alert storms when the audit DB is down. Default 600 s (10 min).
        /// </summary>
        public int FailureAlertCooldownSeconds { get; set; } = 600;

    }

    /// <summary>
    /// Audit retention policy. Default cadence is daily at 03:00 UTC.
    /// Separate windows for the "general" tables (AuditLogs, AuditEst, AuditScep,
    /// AuditCmp, AuditAcme) and the much noisier AuditNetwork table.
    /// </summary>
    public class AuditRetentionConfig
    {
        /// <summary>
        /// Master enable flag. When false, the retention job runs no deletes and
        /// the archive step is also skipped — audit tables grow unbounded. Only
        /// flip this to false in short-lived forensic investigations.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Retention window in days for the "general" audit tables (AuditLogs,
        /// AuditEst, AuditScep, AuditCmp, AuditAcme). Default 365 days keeps a
        /// full year of forensics online while still bounding disk. Set to 0 to
        /// disable retention for these tables without touching the job itself.
        /// </summary>
        public int GeneralRetentionDays { get; set; } = 365;

        /// <summary>
        /// Retention window in days for <c>AuditNetwork</c>, which the
        /// <c>RequestAuditMiddleware</c> writes on every monitored HTTP request.
        /// Default 90 days — busy CAs (ACME / OCSP fan-out) can easily produce
        /// millions of rows per week so the shorter window is load-bearing.
        /// </summary>
        public int NetworkRetentionDays { get; set; } = 90;

        /// <summary>
        /// When true, matching rows are streamed to
        /// <c>{ArchivePath}/audit-{table}-{yyyyMMdd}.jsonl.gz</c> before they are
        /// deleted, giving operators an off-path record for compliance export.
        /// Default false — no archive is produced and rows are deleted directly.
        /// </summary>
        public bool ArchiveBeforeDelete { get; set; } = false;

        /// <summary>
        /// Absolute directory where the archive job writes gzip-jsonl files.
        /// Required when <see cref="ArchiveBeforeDelete"/> is true. Relative paths
        /// are resolved against <c>AppContext.BaseDirectory</c>.
        /// </summary>
        public string ArchivePath { get; set; } = "backups/audit-archive";

        /// <summary>
        /// Cron expression controlling when <c>AuditRetentionJob</c> fires.
        /// Default <c>0 3 * * *</c> — daily at 03:00 UTC. Keep this off-peak so
        /// the chunked delete doesn't overlap with CRL / OCSP traffic bursts.
        /// </summary>
        public string Schedule { get; set; } = "0 3 * * *";

        /// <summary>
        /// Maximum rows deleted per <c>DELETE ... LIMIT</c> chunk per table. Keeps
        /// any single statement short so row-level locks don't starve concurrent
        /// writers. Default 10 000. The job loops until no rows remain or the
        /// per-cycle cancellation deadline fires.
        /// </summary>
        public int DeleteBatchSize { get; set; } = 10_000;
    }

    /// <summary>
    /// Behaviour when <see cref="ModularCA.Core.Services.AuditService.LogAsync"/>
    /// cannot persist a row (audit DB unreachable, EF error, connection pool exhausted).
    /// </summary>
    public enum AuditFailMode
    {
        /// <summary>
        /// Log the failure via <see cref="Microsoft.Extensions.Logging.ILogger"/>, increment
        /// the <c>modularca_audit_writes_failed_total</c> counter, and let the business
        /// operation continue. Historical default; kept for operators who cannot tolerate
        /// a fail-closed surface.
        /// </summary>
        LogAndContinue = 0,

        /// <summary>
        /// <see cref="LogAndContinue"/> plus a critical <c>ISecurityAlertService</c> alert
        /// on the first failure per rolling cooldown window. The business operation still
        /// completes. This is the new default.
        /// </summary>
        LogAndAlert = 1,

        /// <summary>
        /// Throw <c>AuditWriteFailedException</c> so the calling controller can return
        /// 503. High-assurance deployments use this to guarantee that no sensitive
        /// operation completes without a corresponding audit row. Be aware that a
        /// localized audit DB outage will translate into a broader platform outage.
        /// </summary>
        FailClosed = 2,
    }

    /// <summary>
    /// System-wide IP whitelist configuration master kill switch and path exemptions.
    /// CIDR allow-lists themselves live in the centralized <c>Whitelists</c> DB table
    /// and are managed via the admin API; only the enable flag and exempt path list
    /// remain in YAML.
    /// </summary>
    public class IpWhitelistConfig
    {
        /// <summary>Whether IP whitelisting is enforced. Enabled by default — only private IPs can access protocol endpoints.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Paths exempt from IP whitelisting. Auth must be reachable for login,
        /// and the public CA list for the portal. The admin UI and API are
        /// covered by the whitelist alongside protocol endpoints.
        /// </summary>
        public List<string> ExemptPaths { get; set; } = new()
        {
            "/api/v1/auth", "/api/v1/public/ca"
        };
    }

    /// <summary>
    /// Configuration for the request audit middleware that logs all protocol/admin requests.
    /// </summary>
    public class NetworkAuditConfig
    {
        /// <summary>Whether request audit logging is enabled.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>When false, only log protocol/admin endpoints. When true, log everything.</summary>
        public bool LogAllRequests { get; set; } = false;

        /// <summary>Paths to exclude from logging (e.g., health checks, metrics).</summary>
        public List<string> ExcludePaths { get; set; } = new() { "/health", "/metrics" };
    }

    public class LoggingConfig
    {
        public string MinLevel { get; set; } = "Information";
        public string FilePath { get; set; } = "logs/modularca-.log";
        public int RetentionDays { get; set; } = 30;

        /// <summary>Maximum log file size in megabytes before rolling to a new file. Default 100 MB.</summary>
        public int MaxFileSizeMb { get; set; } = 100;

        /// <summary>
        /// When true, EF Core and ASP.NET log full stack traces on errors (useful for
        /// development and staging). When false (default), framework error logging is
        /// clamped so only warnings and above appear — your application code logs a clean
        /// one-liner instead of a multi-page stack trace. Can also be set via the
        /// <c>MODULARCA_VERBOSE_ERRORS</c> environment variable.
        /// </summary>
        public bool VerboseErrors { get; set; } = false;

        /// <summary>
        /// How events are rendered to stdout: <c>"Auto"</c> (default), <c>"Systemd"</c>,
        /// <c>"Json"</c>, or <c>"Text"</c>.
        /// </summary>
        /// <remarks>
        /// Auto picks by what is consuming stdout — journald gets one priority-prefixed line
        /// per event so <c>journalctl -p err</c> works, a container gets CLEF JSON for its log
        /// shipper, and an interactive terminal gets the readable template. Override only when
        /// something other than the obvious consumer is reading stdout — e.g. a systemd unit
        /// whose journal is scraped into Loki, which wants <c>"Json"</c>. The file sink is
        /// always CLEF JSON regardless of this setting.
        /// </remarks>
        public string? ConsoleFormat { get; set; } = "Auto";

        public SyslogConfig Syslog { get; set; } = new();
        public EventLogConfig EventLog { get; set; } = new();
        public NetworkLogConfig Network { get; set; } = new();
    }

    /// <summary>
    /// RFC 5424 syslog forwarding configuration. Activation is controlled by the
    /// <c>Syslog.Enabled</c> feature flag (admin UI toggle / <c>FeatureFlags</c>
    /// table); this class carries only the sink-specific parameters. An empty
    /// <see cref="Host"/> still short-circuits the sink even when the flag is on,
    /// so a flag-enabled-but-unconfigured deployment is a no-op rather than a
    /// startup crash.
    /// </summary>
    public class SyslogConfig
    {
        /// <summary>Target syslog relay host (IP or DNS name).</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Target syslog port. Default 514 (RFC 5424 UDP).</summary>
        public int Port { get; set; } = 514;
        /// <summary>Transport: <c>"UDP"</c> (default) or <c>"TCP"</c>.</summary>
        public string Protocol { get; set; } = "UDP";
        /// <summary>App-name field embedded in each RFC 5424 record. Default <c>"ModularCA"</c>.</summary>
        public string AppName { get; set; } = "ModularCA";
        /// <summary>
        /// RFC 5424 syslog facility label. Parsed against
        /// <c>Serilog.Sinks.Syslog.Facility</c> (case-insensitive). Accepted
        /// values include <c>Kernel</c>, <c>User</c>, <c>Mail</c>, <c>Daemons</c>,
        /// <c>Auth</c>, <c>Syslog</c>, <c>LPR</c>, <c>News</c>, <c>UUCP</c>,
        /// <c>Cron</c>, <c>Auth2</c>, <c>FTP</c>, <c>NTP</c>, <c>LogAudit</c>,
        /// <c>LogAlert</c>, <c>Cron2</c>, and <c>Local0</c>..<c>Local7</c>.
        /// Malformed or unknown values fall back to <c>Local0</c>.
        /// </summary>
        public string Facility { get; set; } = "Local0";
    }

    /// <summary>
    /// Windows Event Log sink configuration. Activation is controlled by the
    /// <c>EventLog.Enabled</c> feature flag (admin UI toggle / <c>FeatureFlags</c>
    /// table); this class carries only the sink-specific parameters and is a no-op
    /// on non-Windows hosts regardless of the flag state.
    /// </summary>
    public class EventLogConfig
    {
        /// <summary>Event source name registered in the Windows Event Log.</summary>
        public string Source { get; set; } = "ModularCA";
        /// <summary>Log name to write records into. Default <c>"Application"</c>.</summary>
        public string LogName { get; set; } = "Application";
    }

    /// <summary>
    /// Network log forwarding configuration for the CEF/SIEM formatter
    /// (<see cref="ModularCA.Core.Services.SiemLogFormatter"/>). Unlike the Syslog /
    /// EventLog sinks, this forwarder is not dual-gated against a
    /// <c>FeatureFlags</c> row — it is consumed directly by
    /// <see cref="ModularCA.Core.Services.SiemLogFormatter"/> and activation is
    /// controlled entirely by <see cref="Enabled"/> plus a non-empty
    /// <see cref="Host"/>.
    /// </summary>
    public class NetworkLogConfig
    {
        /// <summary>
        /// Whether CEF/SIEM forwarding is enabled. Read by
        /// <see cref="ModularCA.Core.Services.SiemLogFormatter.FormatAndSendAsync"/>
        /// — this is the sole gate for the forwarder, there is no corresponding
        /// row in the <c>FeatureFlags</c> table.
        /// </summary>
        public bool Enabled { get; set; } = false;
        /// <summary>Target SIEM host (IP or DNS name).</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Target SIEM port. Default 5514.</summary>
        public int Port { get; set; } = 5514;
        /// <summary>Transport: <c>"TCP"</c> (default) or <c>"UDP"</c>.</summary>
        public string Protocol { get; set; } = "TCP";
    }

    public class HttpConfig
    {
        public int Port { get; set; } = 8080;

        /// <summary>
        /// Public-facing HTTP port that external clients connect to for CRL/OCSP/AIA.
        /// May differ from <see cref="Port"/> when behind a reverse proxy (e.g., proxy
        /// on 80, Kestrel on 8080). When null, falls back to <see cref="Port"/>.
        /// </summary>
        public int? PublicPort { get; set; }

        public string CorsOrigins { get; set; } = "";
        /// <summary>
        /// ICF-02: Swagger UI enable flag. Default <c>false</c> — Swagger is not
        /// exposed in production unless the operator explicitly opts in.
        /// </summary>
        public bool SwaggerEnabled { get; set; } = false;

        /// <summary>
        /// Explicit enable-flag for the restricted CORS policy.
        /// Default is <c>false</c> — misset <c>ASPNETCORE_ENVIRONMENT=Development</c>
        /// is NOT sufficient to enable CORS in production. An operator must
        /// explicitly set <c>Http.EnableCors=true</c> AND populate
        /// <c>Http.CorsOrigins</c> with an allow-list of HTTPS origins. When
        /// enabled, methods are restricted to <c>GET, POST, PUT, DELETE, PATCH,
        /// OPTIONS</c> and headers to
        /// <c>Authorization, Content-Type, X-Requested-With, X-MFA-Token,
        /// X-CSRF-Token, X-Correlation-Id</c>. <c>AllowCredentials</c> is NEVER
        /// attached to this policy.
        /// </summary>
        public bool EnableCors { get; set; } = false;

        /// <summary>
        /// Optional CIDRs of trusted reverse proxies. Only populated
        /// when the deployment sits behind a proxy. Consumed by the forwarded-headers
        /// pipeline in conjunction with <see cref="SecurityConfig.BehindReverseProxy"/>.
        /// Example: "10.0.1.0/24,10.0.2.0/24". The default is now
        /// <b>loopback-only</b> — operators who run behind a reverse proxy must
        /// enumerate trusted proxy subnets explicitly. Leaving this empty with
        /// <see cref="SecurityConfig.BehindReverseProxy"/>=true falls back to
        /// loopback-only (the old RFC1918 default has been removed).
        /// </summary>
        public string TrustedProxyCidrs { get; set; } = string.Empty;

        /// <summary>
        /// How many reverse-proxy hops to walk back through when reading
        /// <c>X-Forwarded-For</c>. Default 1.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This was hardcoded to 1, which quietly assumes exactly one proxy. A CDN in front of a
        /// reverse proxy is two, and the difference is not a rounding error: with a chain of
        /// <c>client → Cloudflare → nginx → Kestrel</c>, nginx appends the address it sees — the
        /// CDN edge — so the header arrives as <c>&lt;client&gt;, &lt;edge&gt;</c>. Walking back one
        /// hop yields the CDN's address and calls it the client. The IP whitelist, the audit trail
        /// and per-IP rate limiting then all operate on a value that identifies a datacentre in
        /// another country.
        /// </para>
        /// <para>
        /// Every hop counted here must also appear in <see cref="TrustedProxyCidrs"/>, or ASP.NET
        /// stops walking at the first untrusted address. Raising this without extending that list
        /// changes nothing, which is the failure that looks like the setting being ignored.
        /// </para>
        /// <para>
        /// Prefer collapsing the chain to one hop where you can: a CDN-aware proxy can write the
        /// real client into <c>X-Forwarded-For</c> itself (nginx:
        /// <c>proxy_set_header X-Forwarded-For $http_cf_connecting_ip;</c>), leaving one trusted hop
        /// and no CDN address ranges to track here. That is only safe when the proxy refuses
        /// connections that did not come from the CDN — otherwise anyone reaching it directly can
        /// forge the header and choose their own source address.
        /// </para>
        /// </remarks>
        public int ForwardedHeaderHopLimit { get; set; } = 1;

        /// <summary>
        /// HSTS header tuning for the HTTPS listener. The
        /// <see cref="SecurityHeadersMiddleware"/> emits HSTS only on HTTPS
        /// responses using the values below. Defaults follow the 1-year /
        /// includeSubDomains / no-preload baseline.
        /// </summary>
        public HstsConfig Hsts { get; set; } = new();
    }

    /// <summary>
    /// Operator-tunable HSTS knobs. These values feed
    /// <see cref="ModularCA.API.Middleware.SecurityHeadersMiddleware"/> and
    /// ASP.NET Core's <c>UseHsts</c> builder when the HTTPS listener is active.
    /// </summary>
    public class HstsConfig
    {
        /// <summary>
        /// <c>max-age</c> in seconds. Default <c>31536000</c> (1 year). Lower to
        /// e.g. <c>86400</c> during certificate rollovers. 0 disables HSTS entirely.
        /// </summary>
        public int MaxAgeSeconds { get; set; } = 31536000;

        /// <summary>Emit <c>includeSubDomains</c>. Default <c>true</c>.</summary>
        public bool IncludeSubDomains { get; set; } = true;

        /// <summary>
        /// Emit the <c>preload</c> directive. Default <c>false</c>. Set to
        /// <c>true</c> only after the operator has verified they want the
        /// public hostname submitted to the HSTS preload list.
        /// </summary>
        public bool Preload { get; set; } = false;
    }

    /// <summary>
    /// Scheduler runtime tuning. <c>Enabled</c> and <c>PollIntervalSeconds</c> are no
    /// longer configurable — the scheduler always runs on every replica with a fixed
    /// 30-second poll, and the database-backed leader-election lease (see
    /// <see cref="LeaseTtlSeconds"/>) ensures only one replica actually executes jobs.
    /// </summary>
    public class SchedulerConfig
    {
        /// <summary>
        /// Database lease TTL in seconds. The scheduler takes or
        /// refreshes the lease on every poll cycle. A non-leader process checks the lease
        /// and skips the cycle. Default 60s — long enough to survive one missed poll.
        /// </summary>
        public int LeaseTtlSeconds { get; set; } = 60;

        /// <summary>
        /// Startup missed-run behaviour. <c>SkipMissed</c> ignores
        /// all past-due cron occurrences. <c>RunOnce</c> (default) runs one catch-up
        /// per job whose <c>NextRunUtc</c> is in the past. <c>RunAll</c> emulates
        /// the legacy "run every cron-gated job on first boot" behaviour.
        /// </summary>
        public string MissedRunPolicy { get; set; } = "RunOnce";

        /// <summary>
        /// Per-job timeouts in seconds. Keys are job names
        /// (<c>LdapGroupSync</c>, <c>Compliance</c>, <c>AutoRenewal</c>, etc.).
        /// Any job missing from the dictionary falls back to <see cref="DefaultJobTimeoutSeconds"/>.
        /// <para>
        /// Backed by <see cref="ConcurrentDictionary{TKey,TValue}"/> so concurrent reads from
        /// the scheduler hot path (<c>SchedulerJobRunner</c>, <c>SchedulerJobRegistry</c>) cannot
        /// race on a writer in <c>AdminSchedulerController.UpdateJob</c>. Both
        /// <see cref="ConcurrentDictionary{TKey,TValue}.TryGetValue"/> and indexer assignment
        /// are thread-safe so existing call-sites compile unchanged.
        /// </para>
        /// </summary>
        public ConcurrentDictionary<string, int> JobTimeouts { get; set; } = new(new Dictionary<string, int>
        {
            ["LdapGroupSync"] = 120,
            ["Compliance"] = 600,
            ["AutoRenewal"] = 300,
            ["BackupVerification"] = 120,
            ["AuditRetention"] = 600,
            ["CrlExport"] = 300,
            ["CertExpire"] = 120,
            ["AcmeCleanup"] = 120,
            ["CertExpiryNotification"] = 120,
            ["TlsRenewal"] = 300,
        });

        /// <summary>Fallback timeout in seconds for any job not present in <see cref="JobTimeouts"/>.</summary>
        public int DefaultJobTimeoutSeconds { get; set; } = 120;

        /// <summary>
        /// Number of consecutive failures before the scheduler escalates
        /// the <c>SchedulerJobFailed</c> alert from Warning to Critical. Default 3.
        /// </summary>
        public int ConsecutiveFailureAlertThreshold { get; set; } = 3;
    }

    public class TokenConfig
    {
        public int RefreshTokenDays { get; set; } = 7;
    }

    public class LdapAuthConfig
    {
        public bool Enabled { get; set; } = false;
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; } = 389;
        public bool UseSsl { get; set; } = false;
        public string SearchBaseDn { get; set; } = string.Empty;
        public string SearchFilter { get; set; } = "(&(objectClass=user)(sAMAccountName={0}))";
        public string? BindDn { get; set; }
        public string? BindPassword { get; set; }

        /// <summary>
        /// Cron expression for the periodic LDAP group-membership sync sweep when
        /// <see cref="GroupSyncEnabled"/> is true. Default <c>*/10 * * * *</c> — every 10
        /// minutes. The job is internally rate-limited and idempotent, so a tighter cadence
        /// is safe; default is loose because LDAP membership rarely changes more than once
        /// per business hour in practice.
        /// </summary>
        public string GroupSyncSchedule { get; set; } = "*/10 * * * *";

        public bool GroupSyncEnabled { get; set; } = false;
        public bool AutoProvisionUsers { get; set; } = false;
        public string GroupSearchBaseDn { get; set; } = string.Empty;
        public string GroupSearchFilter { get; set; } = "(&(objectClass=group)(member={0}))";
        public string GroupMemberAttribute { get; set; } = "memberOf";
        /// <summary>
        /// JSON dict mapping LDAP group DNs to CaGroup names.
        /// Example: {"CN=CA-Admins,DC=example,DC=com": "my-ca-admin", "CN=Auditors,DC=example,DC=com": "system-auditor"}
        /// </summary>
        public string? GroupToRoleMappings { get; set; }

        /// <summary>
        /// AUTH-019: when true, rejects LDAP connections that don't use TLS.
        /// Default false for backward compatibility.
        /// </summary>
        public bool RequireTls { get; set; } = false;
    }

    /// <summary>
    /// Middleware-wired security knobs that must be read before the DB is available
    /// (JWT / refresh-token binding, per-username rate limits, reverse-proxy trust).
    /// Runtime-tunable policy knobs — session lockout, MFA TTLs, OCSP posture,
    /// login banner, approval policy — live in the DB-backed <c>SecurityPolicy</c>
    /// table via <see cref="ModularCA.Shared.Entities.SecurityPolicyEntity"/>.
    /// </summary>
    public class SecurityConfig
    {
        /// <summary>
        /// Consolidated JWT IP binding mode. <c>Off</c> disables
        /// embedding and enforcement entirely. <c>Exact</c> requires the issue-time
        /// IP to match exactly on every request. <c>Subnet24</c> allows clients to
        /// move within a /24 (IPv4) or /64 (IPv6) — friendly for mobile NAT reroutes.
        /// </summary>
        public JwtIpBindingMode BindJwtToIp { get; set; } = JwtIpBindingMode.Off;

        /// <summary>Whether to reject refresh token usage from a different IP than where it was issued.</summary>
        public bool BindRefreshTokenToIp { get; set; } = true;

        /// <summary>Whether to reject refresh token usage from a different User-Agent than where it was issued.</summary>
        public bool BindRefreshTokenToFingerprint { get; set; } = true;

        /// <summary>When true, log IP/fingerprint mismatches but allow the refresh (forensic mode).</summary>
        public bool AllowRefreshTokenMismatch { get; set; } = false;

        /// <summary>
        /// Hard-enforce DPoP proof-of-possession on refresh: when a session was bound to a client key
        /// (<c>RefreshTokenEntity.CnfJkt</c>), reject the refresh (401 <c>REFRESH_POP_INVALID</c>) unless
        /// it carries a matching proof. Default <b>false</b> = observe mode: bind + audit-log mismatches
        /// but allow the refresh (rebinding to the presented key), so the binding can be validated in
        /// production before enforcement is switched on. The theft defense is only active once enforced.
        /// </summary>
        public bool EnforceRefreshTokenPoP { get; set; } = false;

        /// <summary>
        /// Per-username rate-limit bucket floor. This is the maximum
        /// number of login/change-password failures allowed from any source for a single
        /// normalized username within the configured window. Complements per-IP limiting
        /// so botnet stuffing with many IPs against one account gets caught. Default 20.
        /// </summary>
        public int MaxPerUsernameLoginFailures { get; set; } = 20;

        /// <summary>
        /// Window in minutes for the per-username failure bucket.
        /// </summary>
        public int PerUsernameLoginFailureWindowMinutes { get; set; } = 30;

        /// <summary>
        /// When true, the runtime trusts X-Forwarded-For / X-Forwarded-Proto
        /// headers from the configured proxy hops. When false (default), forwarded headers
        /// middleware is still wired for loopback compatibility but the per-IP rate-limit
        /// middleware ignores forwarded values — it uses the raw connection remote IP.
        /// Set this to true in reverse-proxy topologies after you've narrowed
        /// <see cref="HttpConfig.TrustedProxyCidrs"/> to the actual proxy subnet.
        /// </summary>
        public bool BehindReverseProxy { get; set; } = false;
    }

    /// <summary>
    /// Tri-state for JWT-to-IP binding. <c>Off</c> disables all IP
    /// binding, <c>Exact</c> requires exact match, <c>Subnet24</c> tolerates /24 or /64 drift.
    /// </summary>
    public enum JwtIpBindingMode
    {
        /// <summary>No IP claim is embedded and no enforcement happens.</summary>
        Off = 0,

        /// <summary>The issue-time IP is embedded and must match exactly.</summary>
        Exact = 1,

        /// <summary>
        /// The issue-time IP is embedded and matches are evaluated at /24 (IPv4) or
        /// /64 (IPv6) subnet granularity — tolerant of mobile NAT reroutes.
        /// </summary>
        Subnet24 = 2
    }

    public class HttpsConfig
    {
        /// <summary>
        /// TLS certificate mode:
        /// <list type="bullet">
        /// <item><c>SelfIssued</c> — certificate is issued by this CA and stored in <c>api-tls.pfx</c> (default)</item>
        /// <item><c>Custom</c> — operator provides their own PFX at <see cref="CertificatePath"/></item>
        /// <item><c>Pending</c> — bootstrap completed but the web TLS cert has not been issued yet;
        /// the app starts on a temporary self-signed cert and issues the real cert on first runtime start
        /// via the standard CSR pipeline, then transitions to <c>SelfIssued</c></item>
        /// </list>
        /// </summary>
        public string Mode { get; set; } = "SelfIssued";
        public string ListenAddress { get; set; } = "0.0.0.0";
        public string CertificatePath { get; set; } = string.Empty;
        public string CertificatePassword { get; set; } = string.Empty;
        public int Port { get; set; } = 8443;
        public string RenewalWindow { get; set; } = "P30D";

        /// <summary>
        /// Cron expression for the periodic Web TLS certificate renewal-window check.
        /// Default <c>0 5 * * *</c> — daily at 05:00 UTC. The actual renewal only fires
        /// when the cert is within <see cref="RenewalWindow"/> of expiry, so the cron is
        /// just a wake-up cadence; setting it tighter doesn't shorten the renewal window.
        /// </summary>
        public string RenewalCheckSchedule { get; set; } = "0 5 * * *";

        /// <summary>Subject DN for the pending web TLS cert. Set during bootstrap, consumed by Stage 2.</summary>
        public string? PendingSubjectDn { get; set; }

        /// <summary>SAN list for the pending web TLS cert (e.g. "DNS:example.com", "IP:10.0.0.1"). Set during bootstrap.</summary>
        public List<string>? PendingSans { get; set; }

        /// <summary>Validity in days for the pending web TLS cert. Defaults to 365.</summary>
        public int? PendingValidityDays { get; set; }

        /// <summary>Key algorithm for the pending web TLS cert (e.g., ECDSA, RSA). Defaults to ECDSA.</summary>
        public string? PendingKeyAlgorithm { get; set; }

        /// <summary>Key size for the pending web TLS cert (e.g., 256, 2048). Defaults to 256.</summary>
        public int? PendingKeySize { get; set; }

        /// <summary>
        /// Public-facing hostname (or IP) used to build HTTPS URLs for management-UI redirects,
        /// ACME directory endpoints, and JWS URL binding. Must be a bare hostname or IP — no
        /// scheme, no port, no trailing slash. Example: <c>ca.example.com</c>.
        /// </summary>
        public string PublicDomain { get; set; } = string.Empty;

        /// <summary>
        /// Public HTTPS port. When null or 443 the port is omitted from built URLs.
        /// </summary>
        public int? PublicPort { get; set; }

        /// <summary>
        /// Builds the canonical public HTTPS base URL (no trailing slash).
        /// Returns <c>https://PublicDomain</c> when <see cref="PublicPort"/> is null or 443,
        /// otherwise <c>https://PublicDomain:PublicPort</c>.
        /// </summary>
        public string GetPublicHttpsBaseUrl()
        {
            // PublicPort is the operator-facing port (may differ from Kestrel's bind port
            // when behind a port-mapping LB). When unset, fall back to the Kestrel HTTPS
            // port so non-443 deployments work without explicit PublicPort configuration.
            var port = PublicPort ?? Port;
            if (port <= 0) port = 443;
            return port == 443
                ? $"https://{PublicDomain}"
                : $"https://{PublicDomain}:{port}";
        }

        /// <summary>
        /// Builds a public HTTP base URL using the <see cref="HttpConfig.Port"/> from a
        /// supplied <paramref name="httpPort"/>. Returns <c>http://PublicDomain</c> when
        /// the port is 80, otherwise <c>http://PublicDomain:port</c>.
        /// </summary>
        public string GetPublicHttpBaseUrl(int httpBindPort, int? httpPublicPort = null)
        {
            var port = httpPublicPort ?? httpBindPort;
            if (port <= 0) port = 80;
            return port == 80
                ? $"http://{PublicDomain}"
                : $"http://{PublicDomain}:{port}";
        }
    }

    public class EmailConfig
    {
        public bool Enabled { get; set; } = false;
        public string SmtpHost { get; set; } = string.Empty;
        public int SmtpPort { get; set; } = 587;
        public bool UseTls { get; set; } = true;

        /// <summary>
        /// Authentication method: "Password" (default), "OAuth2Token", or "OAuth2ClientCredentials".
        /// </summary>
        public string AuthMethod { get; set; } = "Password";

        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Pre-obtained OAuth2 access token. Used when AuthMethod = "OAuth2Token".
        /// </summary>
        public string OAuth2AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// OAuth2 client credentials for automatic token acquisition.
        /// Used when AuthMethod = "OAuth2ClientCredentials".
        /// </summary>
        public string OAuth2ClientId { get; set; } = string.Empty;
        public string OAuth2ClientSecret { get; set; } = string.Empty;

        /// <summary>
        /// OAuth2 token endpoint URL. For Microsoft 365: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        /// For Google: https://oauth2.googleapis.com/token
        /// </summary>
        public string OAuth2TokenUrl { get; set; } = string.Empty;

        /// <summary>
        /// OAuth2 scopes (space-separated). Defaults to Microsoft 365 SMTP scope if empty.
        /// Microsoft 365: "https://outlook.office365.com/.default"
        /// Google: "https://mail.google.com/"
        /// </summary>
        public string OAuth2Scopes { get; set; } = string.Empty;

        public string FromAddress { get; set; } = string.Empty;
        public string FromName { get; set; } = "ModularCA";
        public string AdminRecipients { get; set; } = string.Empty;
    }

    public class DbConfig
    {
        public DbInstance App { get; set; } = new();
        public DbInstance Audit { get; set; } = new();
    }

    public class DbInstance
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 3306;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Database { get; set; } = string.Empty;

        /// <summary>
        /// TLS mode for the MySQL connection. Maps to <c>MySqlConnector.MySqlSslMode</c>.
        /// Valid values: <c>"None"</c>, <c>"Preferred"</c>, <c>"Required"</c>, <c>"VerifyCA"</c>,
        /// <c>"VerifyFull"</c>. Default is <c>"Required"</c> to protect the
        /// confidentiality and integrity of data in transit between ModularCA and
        /// the backing MySQL server. Downgrading to <c>"Preferred"</c> or <c>"None"</c> allows
        /// silent fallback to unencrypted transport; use <c>"VerifyCA"</c> or <c>"VerifyFull"</c> to additionally validate the
        /// server certificate chain. On parse failure the runtime clamps back to
        /// <c>MySqlSslMode.Required</c>.
        /// </summary>
        public string SslMode { get; set; } = "Required";
    }

    public class JwtConfig
    {
        public string Secret { get; set; } = string.Empty;

        /// <summary>
        /// Access-token lifetime in minutes. Default lowered from 120 to 15 —
        /// short lifetimes bound the blast radius of stolen tokens and of admin-initiated
        /// disable/lock/password-reset before the <c>stamp</c>/<c>ghash</c> claim validation
        /// kicks in. Refresh-token rotation handles session extension.
        /// </summary>
        public int ExpirationMinutes { get; set; } = 15;

        public string Issuer { get; set; } = "ModularCA";
        public string Audience { get; set; } = "ModularCA-API";
    }

    /// <summary>
    /// Prometheus metrics endpoint configuration. Activation is controlled by the
    /// <c>Metrics.Enabled</c> feature flag (admin UI toggle / <c>FeatureFlags</c>
    /// table); this class carries only the sink-specific parameters. The endpoint
    /// is always route-registered so scrape jobs see a deterministic 503 when the
    /// feature flag is off rather than a hard 404.
    /// </summary>
    public class MetricsConfig
    {
        /// <summary>HTTP route the metrics endpoint is mapped to. Default <c>/metrics</c>.</summary>
        public string Path { get; set; } = "/metrics";
    }

    /// <summary>
    /// Configuration for outbound webhook notifications triggered by certificate lifecycle events.
    /// </summary>
    public class WebhookConfig
    {
        /// <summary>Whether webhook notifications are enabled.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>List of webhook endpoints to deliver events to.</summary>
        public List<WebhookEndpoint> Endpoints { get; set; } = new();

        /// <summary>Maximum number of retry attempts for failed webhook deliveries.</summary>
        public int MaxRetries { get; set; } = 3;

        /// <summary>Base delay in seconds between retries. Actual delay uses exponential backoff.</summary>
        public int RetryDelaySeconds { get; set; } = 5;
    }

    /// <summary>
    /// Represents a single webhook endpoint that receives event notifications.
    /// </summary>
    public class WebhookEndpoint
    {
        /// <summary>The URL to POST webhook payloads to.</summary>
        public string Url { get; set; } = string.Empty;

        /// <summary>Optional HMAC-SHA256 secret used to sign payloads. The signature is sent in the X-Webhook-Signature header.</summary>
        public string? Secret { get; set; }

        /// <summary>List of event types this endpoint subscribes to. An empty list means all events.</summary>
        public List<string> Events { get; set; } = new();
    }

    /// <summary>
    /// SSH CA configuration. SSH CA is always available — no feature flag needed.
    /// </summary>
    public class SshCaConfig
    {
        public string SshKeygenPath { get; set; } = "ssh-keygen";
        public string KeyStoragePath { get; set; } = "config/ssh-ca-keys";
    }

    /// <summary>
    /// Optional mutual TLS (mTLS) configuration. <see cref="Enabled"/> controls whether the
    /// browser-based mTLS login flow is offered on the SNI-gated <see cref="AuthSubdomain"/>;
    /// it does NOT gate ordinary admin API calls. <see cref="RequiredPaths"/> is a separate
    /// advanced knob for transport-level enforcement (e.g., behind a reverse proxy that
    /// forwards the client cert in a header) and defaults to empty — turning it on without
    /// a matching Kestrel/proxy configuration will 403 every JWT-authenticated admin
    /// request because no cert is requested on the main hostname under SNI gating.
    /// </summary>
    public class MtlsConfig
    {
        /// <summary>
        /// Whether mTLS client-certificate login is offered. When true, the SNI callback
        /// requests a client cert on <see cref="AuthSubdomain"/> and the /auth/mtls/* login
        /// endpoints are active. Ordinary admin API calls under /api/v1/admin are unaffected
        /// — those are gated by JWT + group-role as usual.
        /// <para>
        /// Enabling this together with a non-empty <see cref="AuthSubdomain"/> requires at
        /// least one loadable anchor in <see cref="TrustedCaCertPaths"/>: outside setup mode
        /// the API refuses to start otherwise, because the handshake would request a client
        /// certificate it has no way to validate.
        /// </para>
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Paths that require transport-level client-certificate enforcement via
        /// <c>MtlsMiddleware</c>. Defaults to empty because the SNI-gated design never
        /// requests a cert on the main hostname, so non-empty values here would 403 every
        /// JWT-authenticated request. Only useful behind a reverse proxy that requires a
        /// client cert on the frontend and forwards the verified cert to this app.
        /// </summary>
        public List<string> RequiredPaths { get; set; } = new();

        /// <summary>
        /// PEM/DER file paths of the CA certificates that anchor client-certificate
        /// validation, both at the TLS handshake (Kestrel's SNI-gated client-cert callback)
        /// and in <c>MtlsMiddleware</c>. Relative paths resolve against the application
        /// base directory.
        /// <para>
        /// The handshake fails closed on an empty anchor set — a client certificate cannot
        /// be validated against zero anchors, so every certificate is rejected rather than
        /// waved through. Because the default is empty, <see cref="Enabled"/> must not be
        /// turned on without populating this list; the API fail-fasts at startup on that
        /// combination (see the mTLS block in <c>StartModularCA.cs</c>) instead of serving
        /// a client-cert prompt that can never succeed. Paths that fail to load are reported
        /// and count as absent, so a list of three unreadable paths trips the same fail-fast
        /// as an empty list.
        /// </para>
        /// </summary>
        public List<string> TrustedCaCertPaths { get; set; } = new();

        /// <summary>
        /// Auth subdomain for browser-based mTLS login (e.g., "mtls.ca.example.com",
        /// or the short form "mtls" which is prepended to <see cref="HttpsConfig.PublicDomain"/>).
        /// The main HTTPS listener uses SNI from the TLS ClientHello to decide whether
        /// to request a client certificate — connections to this subdomain get
        /// <c>ClientCertificateRequired=true</c>; every other SNI gets a plain
        /// server-auth handshake with no cert prompt. Requires DNS pointing the
        /// subdomain to this server and the Web TLS cert SAN covering both hostnames.
        /// </summary>
        public string AuthSubdomain { get; set; } = string.Empty;
    }

    /// <summary>
    /// ACME protocol configuration including External Account Binding (EAB) settings.
    /// </summary>
    /// <summary>
    /// Host-level EST (RFC 7030) settings. Per-CA enablement and authentication policy live in
    /// <c>CaProtocolConfigEntity</c>; this covers only what belongs to the listener.
    /// </summary>
    public class EstConfig
    {
        /// <summary>
        /// SNI hostname on which EST enrollment requests are offered a client certificate, either a
        /// short prefix ("est", completed from <see cref="HttpsConfig.PublicDomain"/>) or a
        /// complete FQDN ("est.ca.example.com"). Empty disables the gate.
        /// </summary>
        /// <remarks>
        /// <para>
        /// EST client-certificate authentication cannot work without this. Kestrel emits a TLS
        /// CertificateRequest only for SNI names the handshake callback gates, and the main
        /// hostname is deliberately not one of them — the public portal must not prompt every
        /// browser visitor for a certificate. A CA with <c>EstRequireClientCert</c> set but no EST
        /// subdomain configured therefore refuses every enrollment with "EST enrollment requires a
        /// client certificate (mTLS)" while the client never had the chance to send one. Confirmed
        /// against a live deployment before this setting existed.
        /// </para>
        /// <para>
        /// <b>Distinct from <see cref="MtlsConfig.AuthSubdomain"/>, and deliberately so.</b> That
        /// hostname *requires* a client certificate and validates it against the CAs that issue
        /// human login credentials. This one *requests* a certificate without requiring it, because
        /// RFC 7030 section 4.1 makes <c>/cacerts</c> the bootstrap step and a device has no
        /// certificate until after it enrolls — a required handshake would break the clients the
        /// subdomain exists for. It validates against the EST-enabled CAs' own certificates,
        /// because re-enrollment (section 4.2.2) authenticates with the certificate this CA
        /// previously issued to the device. Pointing both settings at one hostname would let a
        /// human login certificate enroll as a device, and stop a device from re-enrolling at all.
        /// </para>
        /// <para>
        /// The HTTPS server certificate must carry this name in its SANs, or clients get a
        /// hostname-mismatch failure before any of the above applies. Startup checks and reports
        /// this rather than leaving it to be discovered by a client.
        /// </para>
        /// </remarks>
        public string AuthSubdomain { get; set; } = string.Empty;

        /// <summary>
        /// How long the EST client-certificate trust anchors are cached before being re-read from
        /// the database. Defaults to 60 seconds; values below 5 seconds are treated as 5.
        /// </summary>
        /// <remarks>
        /// The anchor set is "the certificates of the CAs that currently have EST enabled", which an
        /// administrator changes at runtime from the admin UI. A startup-only snapshot would mean
        /// enabling EST on a CA appears to work while every device under it fails the handshake
        /// until someone restarts the service — with nothing in the logs connecting the two. The
        /// refresh runs off the handshake path, so a stale-but-present set answers the connection
        /// and the next one sees the new anchors.
        /// </remarks>
        public int TrustAnchorRefreshSeconds { get; set; } = 60;
    }

    public class AcmeConfig
    {
        /// <summary>
        /// Cron expression for the periodic ACME cleanup sweep (stale orders, expired nonces,
        /// stuck challenges, SCEP/CMP transaction sweep). Default <c>*/5 * * * *</c> — every
        /// 5 minutes. The job is internally idempotent and only emits work when there's
        /// something stale to clean, so a tighter cadence is safe; default is loose because
        /// the scheduler poll loop already wakes every 30s.
        /// </summary>
        public string CleanupSchedule { get; set; } = "*/5 * * * *";

        /// <summary>
        /// When true, new ACME account registrations must include a valid externalAccountBinding
        /// field signed with a pre-shared HMAC key (RFC 8555 section 7.3.4).
        /// </summary>
        public bool ExternalAccountRequired { get; set; } = false;

        /// <summary>
        /// Absolute URL of the terms of service ACME clients must accept before registering.
        /// Empty (the default) means this CA publishes no terms and account registration does
        /// not require agreement.
        /// </summary>
        /// <remarks>
        /// This knob drives BOTH halves of RFC 8555 §7.3.3, which are only correct together:
        /// the URL is advertised as <c>meta.termsOfService</c> in the directory, and
        /// <c>new-account</c> rejects registrations whose <c>termsOfServiceAgreed</c> is not
        /// <c>true</c>. Requiring agreement without publishing a URL — which is what this
        /// server used to do — deadlocks every conforming client: they only set the flag when
        /// they see terms to agree to, so registration failed with "Must agree to terms of
        /// service." and no way to comply.
        /// </remarks>
        public string TermsOfServiceUrl { get; set; } = string.Empty;

        /// <summary>
        /// The trimmed terms-of-service URL, or <c>null</c> when this CA publishes no terms.
        /// Both the directory's <c>meta.termsOfService</c> and the <c>new-account</c> agreement
        /// check read this one property, so the advertisement and the requirement cannot drift
        /// apart — which is the failure RFC 8555 §7.3.3 exists to prevent.
        /// </summary>
        [JsonIgnore]
        public string? PublishedTermsOfServiceUrl =>
            string.IsNullOrWhiteSpace(TermsOfServiceUrl) ? null : TermsOfServiceUrl.Trim();

        /// <summary>Whether to enforce CAA DNS record checking before ACME certificate issuance.</summary>
        public bool EnforceCaa { get; set; } = false;

        /// <summary>
        /// Nonce TTL in seconds. Default is 300 (5 minutes) per
        /// RFC 8555 operational guidance. Clamped to [60, 900] at runtime; values
        /// outside that range fall back to 300.
        /// </summary>
        public int NonceLifetimeSeconds { get; set; } = 300;

        /// <summary>
        /// Per-operation config for the http-01 validator.
        /// </summary>
        public AcmeHttp01Config Http01 { get; set; } = new();

        /// <summary>
        /// Max time in minutes a challenge is allowed to stay in
        /// <c>Processing</c> before the cleanup job reclaims it. Default 10.
        /// </summary>
        public int ChallengeProcessingTimeoutMinutes { get; set; } = 10;

        /// <summary>
        /// Max automatic retry attempts for a stuck challenge
        /// before it is transitioned to <c>Invalid</c>. Default 3.
        /// </summary>
        public int ChallengeMaxAttempts { get; set; } = 3;
    }

    /// <summary>
    /// Configuration for the ACME http-01 challenge
    /// validator — iteration caps only. The private-address policy moved to a
    /// per-CA toggle on <c>CaProtocolConfigEntity.AcmeAllowPrivateAddressValidation</c>
    /// so operators can opt individual CAs into internal-network validation
    /// without flipping a global switch.
    /// </summary>
    public class AcmeHttp01Config
    {
        /// <summary>Maximum number of resolved A/AAAA addresses the validator contacts per challenge (default 4).</summary>
        public int MaxAddresses { get; set; } = 4;

        /// <summary>Per-request timeout in seconds for the http-01 fetch. Default 10.</summary>
        public int TimeoutSeconds { get; set; } = 10;
    }

    /// <summary>
    /// Configuration for automated and on-demand database backup operations.
    /// </summary>
    public class BackupConfig
    {
        /// <summary>
        /// Audit Item #11: master gate for all scheduled backup activity. When
        /// <c>false</c>, both <see cref="SchedulerJobs.BackupCreationJob"/> and
        /// <see cref="SchedulerJobs.BackupVerificationJob"/> short-circuit at the
        /// top of <c>RunAsync</c> and the scheduler's <c>isEnabled</c> predicates
        /// for <c>BackupCreation</c> / <c>BackupVerification</c> AND with this flag,
        /// so the cron lines never produce any archives or alerts. Mirrors the
        /// "Enable scheduled backups" checkbox in the setup wizard
        /// (<c>SetupSecurity.BackupEnabled</c>) — operators who uncheck it now
        /// actually get no backups, instead of the previous behaviour where
        /// backups continued because gating only happened on the per-cadence
        /// <see cref="CreateOnSchedule"/> / <see cref="VerifyOnSchedule"/> flags
        /// (both default <c>true</c>). Defaults to <c>true</c> so existing
        /// deployments that predate this field keep running daily backups.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Directory where backup archives are stored. Relative paths resolve from the application base directory.</summary>
        public string OutputPath { get; set; } = "backups";

        /// <summary>Maximum number of backup archives to retain. Older backups are deleted when this limit is exceeded.</summary>
        public int RetentionCount { get; set; } = 10;

        /// <summary>Cron expression for the automatic backup schedule. Default is daily at 2 AM UTC.</summary>
        public string Schedule { get; set; } = "0 2 * * *";

        /// <summary>Maximum age in days before a missing-backup alert is raised. Default is 7 days.</summary>
        public int MaxBackupAgeDays { get; set; } = 7;

        /// <summary>Whether to run automatic backup verification on the scheduler cycle.</summary>
        public bool VerifyOnSchedule { get; set; } = true;

        /// <summary>
        /// Whether the scheduler should actually CREATE a backup archive when
        /// <see cref="Schedule"/> fires. Default <c>true</c> so the cron expression
        /// operators configure in the setup wizard produces real archives rather than
        /// just verification passes. Flip to <c>false</c> to keep verification-only
        /// behaviour (e.g. when an external backup tool owns archive creation).
        /// </summary>
        public bool CreateOnSchedule { get; set; } = true;

        /// <summary>
        /// Number of most-recent backups validated per verification run.
        /// Defaults to 3 so the scheduler catches corruption in the prior archive even if
        /// the latest one is intact. Set to 1 to preserve legacy "latest only" behaviour.
        /// </summary>
        public int VerifyCount { get; set; } = 3;

        /// <summary>Path to the backup encryption key file. Generated during bootstrap.</summary>
        public string EncryptionKeyPath { get; set; } = "config/backup.key";

        /// <summary>
        /// Backup encryption mode. <c>RandomKey</c> (default): uses a random 32-byte key at <see cref="EncryptionKeyPath"/>.
        /// <c>StoredPassword</c>: uses a scrypt-derived KEK at <see cref="PasswordFilePath"/>, enabling password-only disaster recovery.
        /// </summary>
        public string EncryptionMode { get; set; } = "RandomKey";

        /// <summary>
        /// Path to the password-derived KEK file used in StoredPassword mode. Generated when an admin sets a backup
        /// password via the admin API/UI. Contains scrypt params + derived KEK, not the password itself.
        /// </summary>
        public string PasswordFilePath { get; set; } = "config/backup-password.key";

        /// <summary>
        /// Minimum retention floor in days. Backup retention enforcement refuses to
        /// delete any archive whose creation timestamp is younger than this many days, regardless
        /// of <see cref="RetentionCount"/>. Defends against a script-driven flood of CreateBackup
        /// calls that would otherwise purge weeks of legitimate backups in seconds. Default is
        /// 3 days; set to 0 to disable the floor.
        /// </summary>
        public int MinimumRetentionDays { get; set; } = 3;
    }

    /// <summary>
    /// Configuration for FIDO2/WebAuthn second-factor authentication.
    /// When enabled, users with registered security keys must complete a WebAuthn
    /// assertion during login before receiving a JWT token.
    /// <para>
    /// The WebAuthn relying-party identifier (rpId) and origin are NOT separately
    /// configurable. Both values are derived at startup from
    /// <see cref="HttpsConfig.PublicDomain"/> (rpId) and
    /// <see cref="HttpsConfig.GetPublicHttpsBaseUrl"/> (origin, which honors
    /// <see cref="HttpsConfig.PublicPort"/>). This is intentional: the rpId and
    /// origin presented by the server MUST match the TLS certificate the browser
    /// validates against or the user agent will reject the WebAuthn assertion.
    /// Binding them to the same operator-facing public URL used for HTTPS keeps
    /// the three values in lock-step and eliminates an entire class of
    /// silent-misconfiguration login failures.
    /// </para>
    /// </summary>
    public class WebAuthnConfig
    {
        /// <summary>Whether WebAuthn 2FA is enabled globally.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Human-readable relying party name shown to users during registration.</summary>
        public string RelyingPartyName { get; set; } = "ModularCA";

        /// <summary>
        /// Groups or capability templates that must use WebAuthn 2FA. Values are matched against
        /// <see cref="ModularCA.Shared.Entities.CaGroupEntity.TemplateName"/> values (e.g., "Administrator", "Operator")
        /// or specific <see cref="ModularCA.Shared.Entities.CaGroupEntity.Name"/> values
        /// (e.g., "system-admin", "my-ca-operator"). An empty list means WebAuthn is optional for all users.
        /// </summary>
        public List<string> EnforceForGroups { get; set; } = new();
    }

    /// <summary>
    /// Configuration for real-time security alerts dispatched via email and webhooks.
    /// </summary>
    public class AlertConfig
    {
        /// <summary>Whether security alerting is enabled.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Minimum severity to trigger alerts: Critical, Warning, or Info.</summary>
        public string MinimumSeverity { get; set; } = "Warning";

        /// <summary>Cooldown in minutes between duplicate alerts of the same event type to prevent alert fatigue.</summary>
        public int CooldownMinutes { get; set; } = 5;
    }

    /// <summary>
    /// Configuration for certificate expiry notification alerts.
    /// </summary>
    public class CertExpiryNotificationConfig
    {
        /// <summary>Whether expiry notifications are enabled.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Days before expiry to send warnings. Checked in order — first match triggers.</summary>
        public List<int> WarningDaysBeforeExpiry { get; set; } = new() { 90, 60, 30, 14, 7, 3, 1 };

        /// <summary>Cron expression for how often to check. Default: daily at 6 AM UTC.</summary>
        public string Schedule { get; set; } = "0 6 * * *";
    }

    /// <summary>
    /// Configuration for the automated certificate compliance scanner that flags
    /// weak keys, deprecated algorithms, over-long validity, missing SANs, and more.
    /// </summary>
    public class ComplianceScanConfig
    {
        /// <summary>Whether the compliance scanner is enabled.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Cron expression for the scan schedule. Default: daily at 3 AM UTC.</summary>
        public string Schedule { get; set; } = "0 3 * * *";

        /// <summary>Minimum acceptable RSA key size in bits. Keys smaller than this are flagged as weak.</summary>
        public int MinRsaKeySize { get; set; } = 2048;

        /// <summary>Signature algorithms considered deprecated. Certificates using these are flagged.</summary>
        public List<string> DeprecatedAlgorithms { get; set; } = new() { "SHA1WithRSA", "MD5WithRSA" };

        /// <summary>
        /// Validity threshold in days used by the compliance scanner to flag
        /// over-long certificates in its report. This is a <b>warning threshold only</b> —
        /// the scanner emits a finding when a certificate's total validity exceeds this
        /// value, but the certificate remains valid and in use. The enforced ceiling lives on
        /// <see cref="ModularCA.Shared.Entities.TenantEntity.MaxValidityDays"/>; this knob
        /// intentionally does not block anything, and the two are independent on purpose — a
        /// tenant may legitimately issue past a compliance baseline it is not claiming to meet.
        /// Default tracks the CA/Browser Forum baseline at 825 days.
        /// </summary>
        public int WarnOverValidityDays { get; set; } = 825;

        /// <summary>
        /// Days before expiry within which a certificate is flagged as
        /// "expiring soon" by the compliance scan job. Previously hardcoded to 30.
        /// </summary>
        public int ExpiringWithinDays { get; set; } = 30;
    }

    /// <summary>
    /// System-wide certificate policy configuration enforced at issuance time.
    /// Unlike per-request certificate profiles, these rules apply globally to all
    /// certificate issuance regardless of the profile used.
    /// </summary>
    public class CertPolicyConfig
    {
        /// <summary>Whether the certificate policy engine is enabled.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Minimum acceptable RSA key size in bits. Keys smaller than this block issuance.</summary>
        public int MinRsaKeySize { get; set; } = 2048;

        // MaxValidityDays used to live here, defaulting to 825 and blocking every leaf in the
        // installation that exceeded it. It moved to TenantEntity.MaxValidityDays, where the
        // remarks explain why; see also ComplianceConfig.WarnOverValidityDays for the reporting
        // half, which never blocked and did not move. Removing the property outright is safe for
        // existing config files because YamlAppConfigLoader is built with
        // IgnoreUnmatchedProperties, so a leftover `MaxValidityDays:` key is ignored rather than
        // failing the load — but it is also no longer honoured, which is the point.

        /// <summary>Signature algorithms that are forbidden. Certificates using these are blocked at issuance.</summary>
        public List<string> ForbiddenAlgorithms { get; set; } = new() { "SHA1WithRSA", "MD5WithRSA" };

        /// <summary>Whether Subject Alternative Names are required on all issued certificates.</summary>
        public bool RequireSans { get; set; } = true;

        /// <summary>
        /// RSA signature padding mode: "v15" for PKCS#1 v1.5 (legacy), "PSS" for RSA-PSS
        /// (NIST SP 800-131A Rev 2 recommended). Default "PSS" for new deployments. Affects
        /// all RSA certificate, CRL, OCSP, and CMP signatures. ECDSA, EdDSA, and PQC
        /// algorithms are unaffected. When "PSS", BouncyCastle uses SHA-{n}withRSAandMGF1
        /// signers (RSASSA-PSS with MGF1 and matching hash).
        /// </summary>
        public string RsaSignaturePadding { get; set; } = "PSS";

        /// <summary>
        /// Algorithm sunset rules in the format "AlgorithmSpec:YYYY-MM-DD".
        /// After the specified date the algorithm is forbidden. For example,
        /// "RSA-2048:2030-01-01" means RSA-2048 keys are forbidden after 1 Jan 2030.
        /// </summary>
        public List<string> AlgorithmSunsetRules { get; set; } = new();

        /// <summary>
        /// Cron expression controlling when <c>CertExpireJob</c> sweeps for certificates
        /// that have passed their <c>NotAfter</c> and auto-revokes them. Default
        /// <c>0 1 * * *</c> — daily at 01:00 UTC. Previous behaviour (run every poll cycle)
        /// emitted an <c>ExpiredCertificatesRevoked</c> audit row every 30 seconds while
        /// any expired cert was sitting on disk.
        /// </summary>
        public string ExpireCheckSchedule { get; set; } = "0 1 * * *";
    }

    /// <summary>
    /// Configuration for the automatic certificate renewal engine.
    /// When enabled, certificates approaching expiration are automatically renewed
    /// by creating new CSR requests and optionally issuing them without admin approval.
    /// </summary>
    public class AutoRenewalConfig
    {
        /// <summary>Whether the automatic renewal engine is enabled.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>Cron expression for the renewal schedule. Default: daily at 4 AM UTC.</summary>
        public string Schedule { get; set; } = "0 4 * * *";

        /// <summary>Number of days before expiry to trigger automatic renewal.</summary>
        public int RenewDaysBeforeExpiry { get; set; } = 30;

        /// <summary>
        /// When true, renewal requests are auto-issued without admin approval
        /// (unless the associated request profile explicitly requires approval).
        /// </summary>
        public bool AutoApprove { get; set; } = true;

        /// <summary>
        /// When <c>true</c> (the default) auto-renewal generates a
        /// fresh key pair for the renewed certificate instead of carrying forward the
        /// encrypted private-key blob from the original CSR request. Required by most
        /// cryptoperiod-rotation policies (NIST SP 800-57). Set to <c>false</c> to
        /// preserve the legacy "same key, new cert" behaviour for compatibility with
        /// devices that cannot rotate keys.
        /// </summary>
        public bool RequireKeyRotation { get; set; } = true;
    }

    /// <summary>
    /// Configuration for the infrastructure integration API used by Terraform, Ansible,
    /// and other IaC tools. Authenticated via a static API key in the X-API-Key header.
    /// </summary>
    public class IntegrationApiConfig
    {
        /// <summary>Whether the integration API endpoints are enabled.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Shared secret API key that clients must present in the X-API-Key header.
        /// Must be a strong, randomly generated value in production.
        /// </summary>
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>
        /// AUTH-06: optional tenant scope for the API key. When set, the integration API
        /// restricts operations to CAs belonging to this tenant. Requests targeting CAs
        /// in a different tenant are rejected with 403. When null (default), the API key
        /// grants access to all CAs (backward compatible).
        /// </summary>
        public Guid? TenantId { get; set; }
    }

    /// <summary>
    /// Configuration for GitOps-style policy synchronization that imports
    /// profile definitions from YAML files into the database.
    /// </summary>
    public class PolicySyncConfig
    {
        /// <summary>Whether policy sync is enabled.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>Directory path containing YAML policy files. Relative paths resolve from the application base directory.</summary>
        public string PolicyDirectory { get; set; } = "config/policies";

        /// <summary>Whether to automatically sync policies from the directory on application startup.</summary>
        public bool SyncOnStartup { get; set; } = false;
    }

    /// <summary>
    /// Configuration for the Kubernetes cert-manager external issuer integration.
    /// When enabled, cert-manager can submit CSRs via the <c>/api/v1/integration/cert-manager/sign</c>
    /// endpoint, authenticated by a static API key in the <c>X-API-Key</c> header.
    /// </summary>
    public class CertManagerConfig
    {
        /// <summary>Whether the cert-manager integration endpoints are enabled.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Shared secret API key that cert-manager must present in the <c>X-API-Key</c> header.
        /// Must be a strong, randomly generated value in production.
        /// </summary>
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>
        /// Default certificate profile ID used when the signing request does not specify one.
        /// </summary>
        public Guid? DefaultCertProfileId { get; set; }

        /// <summary>
        /// Default signing profile ID that determines which CA signs the certificates.
        /// </summary>
        public Guid? DefaultSigningProfileId { get; set; }

        /// <summary>
        /// AUTH-06: optional tenant scope for the cert-manager API key. When set, the
        /// cert-manager integration restricts signing to CAs belonging to this tenant.
        /// Requests whose signing profile resolves to a CA in a different tenant are
        /// rejected with 403. When null (default), the API key grants access to all
        /// CAs (backward compatible).
        /// </summary>
        public Guid? TenantId { get; set; }
    }

    /// <summary>
    /// ICF-07 / ICF-08: optional Redis configuration for distributed cache and Data Protection
    /// keyring persistence. When <see cref="Enabled"/> is true, the runtime registers
    /// <c>AddStackExchangeRedisCache</c> and <c>PersistKeysToStackExchangeRedis</c> instead of
    /// the node-local in-process memory cache and filesystem keyring.
    /// </summary>
    public class RedisConfig
    {
        /// <summary>Whether Redis is used as the distributed cache and Data Protection backend.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>StackExchange.Redis connection string (e.g. "redis:6379,password=secret").</summary>
        public string ConnectionString { get; set; } = "localhost:6379";

        /// <summary>Key prefix for all cache entries. Prevents collisions in shared Redis instances.</summary>
        public string? InstanceName { get; set; } = "ModularCA:";
    }
}
