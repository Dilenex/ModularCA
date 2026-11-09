using Prometheus;

namespace ModularCA.Core.Services;

/// <summary>
/// Provides Prometheus metrics counters, gauges, and histograms for certificate lifecycle,
/// protocol operations, authentication, and system health monitoring.
/// </summary>
public class MetricsService
{
    // ── Certificate lifecycle ───────────────────────────────────────

    /// <summary>
    /// Total certificates issued, labelled by CA label and certificate profile.
    /// </summary>
    public static readonly Counter CertsIssued = Metrics.CreateCounter(
        "modularca_certificates_issued_total", "Certificates issued", new CounterConfiguration
        { LabelNames = new[] { "ca_label", "profile" } });

    /// <summary>
    /// Total certificates revoked, labelled by CA label and revocation reason.
    /// </summary>
    public static readonly Counter CertsRevoked = Metrics.CreateCounter(
        "modularca_certificates_revoked_total", "Certificates revoked", new CounterConfiguration
        { LabelNames = new[] { "ca_label", "reason" } });

    /// <summary>
    /// Current number of active (non-revoked, non-expired) certificates.
    /// </summary>
    public static readonly Gauge ActiveCertificates = Metrics.CreateGauge(
        "modularca_certificates_active", "Non-revoked, non-expired certificates");

    /// <summary>
    /// Current number of certificates expiring within 30 days.
    /// </summary>
    public static readonly Gauge CertificatesExpiring30d = Metrics.CreateGauge(
        "modularca_certificates_expiring_30d", "Certificates expiring within 30 days");

    /// <summary>
    /// Current number of expired certificates.
    /// </summary>
    public static readonly Gauge CertificatesExpired = Metrics.CreateGauge(
        "modularca_certificates_expired", "Expired certificates");

    // ── Protocol metrics ────────────────────────────────────────────

    /// <summary>
    /// Total protocol requests across all PKI protocols (EST, SCEP, CMP, ACME, OCSP, TSA),
    /// labelled by protocol name and status (ok, error).
    /// </summary>
    public static readonly Counter ProtocolRequestsTotal = Metrics.CreateCounter(
        "modularca_protocol_requests_total", "Total protocol requests", new CounterConfiguration
        { LabelNames = new[] { "protocol", "status" } });

    /// <summary>
    /// Histogram measuring protocol request duration in seconds, labelled by protocol name.
    /// </summary>
    public static readonly Histogram ProtocolRequestDuration = Metrics.CreateHistogram(
        "modularca_protocol_request_duration_seconds", "Protocol request duration in seconds", new HistogramConfiguration
        { LabelNames = new[] { "protocol" } });

    /// <summary>
    /// Total protocol errors, labelled by protocol name and error type.
    /// </summary>
    public static readonly Counter ProtocolErrorsTotal = Metrics.CreateCounter(
        "modularca_protocol_errors_total", "Total protocol errors", new CounterConfiguration
        { LabelNames = new[] { "protocol", "error_type" } });

    // ── Per-protocol request counters (legacy, kept for backward compatibility) ──

    /// <summary>
    /// Total EST (Enrollment over Secure Transport) protocol requests, labelled by operation
    /// (e.g. cacerts, simpleenroll, simplereenroll, csrattrs) and outcome status (ok, error).
    /// </summary>
    public static readonly Counter EstRequestsTotal = Metrics.CreateCounter(
        "modularca_est_requests_total", "Total EST protocol requests", new CounterConfiguration
        { LabelNames = new[] { "operation", "status" } });

    /// <summary>
    /// Total SCEP (Simple Certificate Enrollment Protocol) requests, labelled by operation
    /// (e.g. GetCACert, GetCACaps, PKIOperation) and outcome status (ok, error).
    /// </summary>
    public static readonly Counter ScepRequestsTotal = Metrics.CreateCounter(
        "modularca_scep_requests_total", "Total SCEP protocol requests", new CounterConfiguration
        { LabelNames = new[] { "operation", "status" } });

    /// <summary>
    /// The <c>operation</c> label for a SCEP request: one of the three operations SCEP defines
    /// that this server answers, in their canonical spelling, or <c>other</c>. The query string
    /// used to be the label as given, and every distinct value an unauthenticated client sent
    /// became a time series kept for the life of the process and exported on every scrape.
    /// </summary>
    /// <param name="operation">The <c>operation</c> query parameter as received.</param>
    /// <returns>A label from a fixed, small set.</returns>
    public static string ScepOperationLabel(string? operation) => (operation ?? string.Empty).ToLowerInvariant() switch
    {
        "getcacert" => "GetCACert",
        "getcacaps" => "GetCACaps",
        "pkioperation" => "PKIOperation",
        _ => "other",
    };

    /// <summary>
    /// Total CMP (Certificate Management Protocol) requests, labelled by outcome status (ok, error).
    /// </summary>
    public static readonly Counter CmpRequestsTotal = Metrics.CreateCounter(
        "modularca_cmp_requests_total", "Total CMP protocol requests", new CounterConfiguration
        { LabelNames = new[] { "status" } });

    /// <summary>
    /// Total ACME protocol requests, labelled by operation (e.g. directory, new-nonce)
    /// and outcome status (ok, error).
    /// </summary>
    public static readonly Counter AcmeRequestsTotal = Metrics.CreateCounter(
        "modularca_acme_requests_total", "Total ACME protocol requests", new CounterConfiguration
        { LabelNames = new[] { "operation", "status" } });

    /// <summary>
    /// OCSP requests, labelled by outcome status (ok, error) and responder CA label
    /// (empty string when the request did not resolve to a specific responder).
    /// </summary>
    public static readonly Counter OcspRequests = Metrics.CreateCounter(
        "modularca_ocsp_requests_total", "OCSP requests", new CounterConfiguration
        { LabelNames = new[] { "status", "ca_label" } });

    // TSA
    public static readonly Counter TsaRequests = Metrics.CreateCounter(
        "modularca_tsa_requests_total", "Timestamp requests", new CounterConfiguration
        { LabelNames = new[] { "status" } });

    // ── Auth metrics ────────────────────────────────────────────────

    /// <summary>
    /// Total login attempts, labelled by authentication method (password, certificate, ldap)
    /// and success (true, false).
    /// </summary>
    public static readonly Counter AuthLoginTotal = Metrics.CreateCounter(
        "modularca_auth_login_total", "Login attempts", new CounterConfiguration
        { LabelNames = new[] { "method", "success" } });

    /// <summary>
    /// Total authentication failures, labelled by a controlled reason string
    /// (user_not_found, account_disabled, account_locked, account_temporarily_locked,
    /// invalid_password, password_change_required, password_expired, mfa_required_not_enrolled,
    /// mfa_failed, certificate_invalid, certificate_unknown). Provides reason granularity
    /// beyond the success=false pivot of <see cref="AuthLoginTotal"/>.
    /// </summary>
    public static readonly Counter AuthLoginFailures = Metrics.CreateCounter(
        "modularca_auth_login_failures_total", "Login failures by reason", new CounterConfiguration
        { LabelNames = new[] { "reason" } });

    /// <summary>
    /// Total MFA verification attempts, labelled by method (totp, webauthn, mtls).
    /// </summary>
    public static readonly Counter AuthMfaVerificationsTotal = Metrics.CreateCounter(
        "modularca_auth_mfa_verifications_total", "MFA verifications", new CounterConfiguration
        { LabelNames = new[] { "method" } });

    /// <summary>
    /// MFA verification failures, labelled by method and reason.
    /// Symmetric counterpart of <see cref="AuthMfaVerificationsTotal"/> so
    /// Prometheus alerts can fire on brute-force without needing to parse SIEM
    /// audit logs. Reason labels are controlled (see the call-sites) so cardinality
    /// stays bounded.
    /// </summary>
    public static readonly Counter AuthMfaVerificationFailuresTotal = Metrics.CreateCounter(
        "modularca_mfa_verification_failures_total", "MFA verification failures by method and reason", new CounterConfiguration
        { LabelNames = new[] { "method", "reason" } });

    /// <summary>
    /// Total token revocations (logout, session expiry).
    /// </summary>
    public static readonly Counter AuthTokenRevocationsTotal = Metrics.CreateCounter(
        "modularca_auth_token_revocations_total", "Token revocations");

    // ── Legacy auth counter (kept for backward compatibility) ────────
    public static readonly Counter AuthLogins = Metrics.CreateCounter(
        "modularca_auth_logins_total", "Login attempts", new CounterConfiguration
        { LabelNames = new[] { "result" } });

    // ── System metrics ──────────────────────────────────────────────

    /// <summary>
    /// Total CRL generations, labelled by CA label (issuer DN).
    /// </summary>
    public static readonly Counter CrlGenerations = Metrics.CreateCounter(
        "modularca_crl_generations_total", "CRL generations", new CounterConfiguration
        { LabelNames = new[] { "ca_label" } });

    /// <summary>
    /// Histogram measuring CRL generation duration in seconds.
    /// </summary>
    public static readonly Histogram CrlGenerationDuration = Metrics.CreateHistogram(
        "modularca_crl_generation_duration_seconds", "CRL generation duration in seconds");

    /// <summary>
    /// Total CSR submissions, labelled by status (generated, uploaded).
    /// </summary>
    public static readonly Counter CsrSubmissionsTotal = Metrics.CreateCounter(
        "modularca_csr_submissions_total", "CSR submissions", new CounterConfiguration
        { LabelNames = new[] { "status" } });

    /// <summary>
    /// Current active vulnerability findings, labelled by severity (Critical, Warning, Info).
    /// </summary>
    public static readonly Gauge VulnerabilitiesActive = Metrics.CreateGauge(
        "modularca_vulnerabilities_active", "Active vulnerability findings", new GaugeConfiguration
        { LabelNames = new[] { "severity" } });

    // SSH
    public static readonly Counter SshCertsIssued = Metrics.CreateCounter(
        "modularca_ssh_certs_issued_total", "SSH certificates issued", new CounterConfiguration
        { LabelNames = new[] { "type" } });

    // Request latency (legacy)
    public static readonly Histogram RequestDuration = Metrics.CreateHistogram(
        "modularca_request_duration_seconds", "Request latency", new HistogramConfiguration
        { LabelNames = new[] { "protocol", "method" } });

    // ── DB query instrumentation ──────────────────────────────────────

    /// <summary>
    /// Histogram of EF Core / MySqlConnector command duration in seconds, labelled by
    /// operation (reader, non_query, scalar) and outcome (ok, error). Fed by the
    /// <c>DbCommandDurationInterceptor</c> registered on both the application and audit
    /// DbContexts.
    /// </summary>
    public static readonly Histogram DbQueryDuration = Metrics.CreateHistogram(
        "modularca_db_query_duration_seconds", "Database command duration in seconds",
        new HistogramConfiguration
        {
            LabelNames = new[] { "operation", "status" },
            Buckets = new[] { 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0 }
        });

    // ── Audit pipeline ────────────────────────────────────────────────

    /// <summary>
    /// Total network-audit writes that failed inside <c>RequestAuditMiddleware</c>,
    /// labelled by exception type. Replaces the previous silent-swallow behaviour so
    /// operators can alert on audit-trail loss.
    /// </summary>
    public static readonly Counter AuditWritesFailed = Metrics.CreateCounter(
        "modularca_audit_writes_failed_total", "Audit writes that failed",
        new CounterConfiguration { LabelNames = new[] { "exception" } });

    // ── Scheduler job lifecycle ─────────────────

    /// <summary>
    /// Total scheduler job runs, labelled by job name and result
    /// (<c>success</c>, <c>failed</c>, <c>cancelled</c>, <c>skipped</c>).
    /// </summary>
    public static readonly Counter SchedulerJobRuns = Metrics.CreateCounter(
        "modularca_scheduler_job_runs_total", "Scheduler job runs",
        new CounterConfiguration { LabelNames = new[] { "job", "result" } });

    /// <summary>
    /// Histogram of scheduler job duration in seconds, labelled by job name. Bucketed
    /// to span from fast jobs (CrlExport when there's nothing to do) to long-running
    /// audit-retention or compliance-scan runs.
    /// </summary>
    public static readonly Histogram SchedulerJobDuration = Metrics.CreateHistogram(
        "modularca_scheduler_job_duration_seconds", "Scheduler job duration in seconds",
        new HistogramConfiguration
        {
            LabelNames = new[] { "job" },
            Buckets = new[] { 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0 }
        });

    /// <summary>
    /// Gauge of the Unix timestamp of each job's most recent successful run.
    /// Staleness alerts can compare this value against <c>now - (2 * expected cadence)</c>.
    /// </summary>
    public static readonly Gauge SchedulerJobLastSuccess = Metrics.CreateGauge(
        "modularca_scheduler_job_last_success_unix", "Last successful scheduler job run (unix seconds)",
        new GaugeConfiguration { LabelNames = new[] { "job" } });

    // ── Serilog sink health ───────────────────────────────────────────

    /// <summary>
    /// Total log events dropped by the Serilog pipeline, reported by the SelfLog handler.
    /// A non-zero rate indicates a sink failure (disk full, permission error, async-queue
    /// overflow) that would otherwise be invisible.
    /// </summary>
    public static readonly Counter LogSinkDropped = Metrics.CreateCounter(
        "modularca_log_sink_dropped_total", "Log events dropped by Serilog sinks");
}
