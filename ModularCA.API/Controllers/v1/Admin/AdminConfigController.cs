using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Hosting;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for viewing and modifying runtime configuration.
/// Changes are applied to the in-memory config and persisted to config.yaml.
/// Some changes (logging, HTTPS, scheduler) require a restart to take full effect.
/// </summary>
[ApiController]
[Route("api/v1/admin/config")]
[Authorize(Policy = "SystemOperator")]
public class AdminConfigController(
    SystemConfig config,
    IHostApplicationLifetime appLifetime,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    Serilog.Core.LoggingLevelSwitch loggingLevelSwitch,
    EnvVarConfigOverlay envOverlay,
    ISecurityPolicyService securityPolicyService,
    ILdapPublisherPolicyService ldapPublisherPolicyService) : ControllerBase
{
    private readonly SystemConfig _config = config;
    private readonly IHostApplicationLifetime _appLifetime = appLifetime;
    private readonly IAuditService _audit = audit;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;
    private readonly EnvVarConfigOverlay _envOverlay = envOverlay;
    private readonly Serilog.Core.LoggingLevelSwitch _loggingLevelSwitch = loggingLevelSwitch;
    private readonly ISecurityPolicyService _securityPolicyService = securityPolicyService;
    private readonly ILdapPublisherPolicyService _ldapPublisherPolicyService = ldapPublisherPolicyService;

    /// <summary>
    /// Get the full current configuration (secrets redacted). Response includes
    /// both yaml-backed <c>Security</c> (middleware knobs) and DB-backed
    /// <c>SecurityPolicy</c> (session/MFA/OCSP policy) + <c>LdapPublisherPolicy</c>
    /// so clients see the complete picture in one call.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetConfig()
    {
        var securityPolicy = await _securityPolicyService.GetAsync();
        var ldapPublisherPolicy = await _ldapPublisherPolicyService.GetAsync();
        return Ok(new
        {
            SecurityPolicy = securityPolicy,
            LdapPublisherPolicy = ldapPublisherPolicy,
            Logging = _config.Logging,
            Http = _config.Http,
            Scheduler = _config.Scheduler,
            Tokens = _config.Tokens,
            Security = _config.Security,
            Metrics = _config.Metrics,
            SshCa = _config.SshCa,
            LdapAuth = new
            {
                _config.LdapAuth.Enabled,
                _config.LdapAuth.Host,
                _config.LdapAuth.Port,
                _config.LdapAuth.UseSsl,
                _config.LdapAuth.SearchBaseDn,
                _config.LdapAuth.SearchFilter,
                // The bind DN is a directory identity, not a secret — return it as-is so the UI
                // can display and edit it. It previously received the BindPassword redaction, which
                // is how saving the LDAP card overwrote the real DN with the string "***".
                _config.LdapAuth.BindDn,
                BindPassword = string.IsNullOrEmpty(_config.LdapAuth.BindPassword)
                    ? string.Empty
                    : RedactSecret("LdapAuth.BindPassword"),
                _config.LdapAuth.GroupSyncEnabled,
                _config.LdapAuth.AutoProvisionUsers,
                _config.LdapAuth.GroupSearchBaseDn,
                _config.LdapAuth.GroupSearchFilter,
                _config.LdapAuth.GroupMemberAttribute,
                _config.LdapAuth.GroupToRoleMappings,
            },
            Email = new
            {
                _config.Email.Enabled,
                _config.Email.SmtpHost,
                _config.Email.SmtpPort,
                _config.Email.UseTls,
                _config.Email.AuthMethod,
                _config.Email.Username,
                Password = !string.IsNullOrEmpty(_config.Email.Password) ? RedactSecret("Email.Password") : "",
                OAuth2AccessToken = !string.IsNullOrEmpty(_config.Email.OAuth2AccessToken) ? RedactSecret("Email.OAuth2AccessToken") : "",
                _config.Email.OAuth2ClientId,
                OAuth2ClientSecret = !string.IsNullOrEmpty(_config.Email.OAuth2ClientSecret) ? RedactSecret("Email.OAuth2ClientSecret") : "",
                _config.Email.OAuth2TokenUrl,
                _config.Email.OAuth2Scopes,
                _config.Email.FromAddress,
                _config.Email.FromName,
                _config.Email.AdminRecipients,
            },
            Https = new
            {
                _config.Https.Mode,
                _config.Https.ListenAddress,
                _config.Https.Port,
                _config.Https.PublicDomain,
                _config.Https.PublicPort,
                _config.Https.RenewalWindow,
                CertificatePassword = RedactSecret("Https.CertificatePassword")
            },
            JWT = new
            {
                _config.JWT.ExpirationMinutes,
                _config.JWT.Issuer,
                _config.JWT.Audience,
                Secret = RedactSecret("JWT.Secret")
            },
            IpWhitelist = _config.IpWhitelist,
            NetworkAudit = _config.NetworkAudit,
            Backup = _config.Backup,
            CertPolicy = _config.CertPolicy,
            Mtls = _config.Mtls,
            AutoRenewal = _config.AutoRenewal,
            ComplianceScan = _config.ComplianceScan,
            CertExpiryNotification = _config.CertExpiryNotification,
            Acme = _config.Acme,
            Alert = _config.Alert,
            Webhook = new { _config.Webhook.Enabled, _config.Webhook.MaxRetries, _config.Webhook.RetryDelaySeconds },
            PolicySync = _config.PolicySync,
            CertManager = new { _config.CertManager.Enabled, ApiKey = !string.IsNullOrEmpty(_config.CertManager.ApiKey) ? RedactSecret("CertManager.ApiKey") : "", _config.CertManager.DefaultCertProfileId, _config.CertManager.DefaultSigningProfileId },
            IntegrationApi = new { _config.IntegrationApi.Enabled, ApiKey = !string.IsNullOrEmpty(_config.IntegrationApi.ApiKey) ? RedactSecret("IntegrationApi.ApiKey") : "" },
        });
    }

    /// <summary>
    /// Updates the logging configuration. Min level changes take effect immediately via
    /// the Serilog LoggingLevelSwitch. File path, retention, and size changes require a restart.
    /// </summary>
    [HttpPut("logging")]
    public async Task<IActionResult> UpdateLogging([FromBody] LoggingConfig update)
    {
        // ICF-09: bounds validation
        if (update.RetentionDays < 1)
            return BadRequest(new { error = "RetentionDays must be >= 1." });

        _config.Logging.MinLevel = update.MinLevel ?? _config.Logging.MinLevel;
        _config.Logging.FilePath = update.FilePath ?? _config.Logging.FilePath;
        if (update.RetentionDays > 0) _config.Logging.RetentionDays = update.RetentionDays;
        if (update.MaxFileSizeMb > 0) _config.Logging.MaxFileSizeMb = update.MaxFileSizeMb;

        // Apply log level change immediately at runtime
        if (!string.IsNullOrEmpty(update.MinLevel))
        {
            _loggingLevelSwitch.MinimumLevel = update.MinLevel.ToLowerInvariant() switch
            {
                "debug" => Serilog.Events.LogEventLevel.Debug,
                "warning" => Serilog.Events.LogEventLevel.Warning,
                "error" => Serilog.Events.LogEventLevel.Error,
                _ => Serilog.Events.LogEventLevel.Information
            };
        }

        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Logging", update);
        var restartNote = update.FilePath != null || update.RetentionDays > 0 || update.MaxFileSizeMb > 0
            ? " File/retention/size changes require restart." : "";
        return Ok(new { message = $"Logging config updated. Min level applied immediately.{restartNote}", config = _config.Logging });
    }

    /// <summary>
    /// Updates the HTTP configuration (port, CORS, Swagger, trusted proxies).
    /// Requires a restart to take full effect.
    /// </summary>
    [HttpPut("http")]
    public async Task<IActionResult> UpdateHttp([FromBody] HttpConfig update)
    {
        // ICF-09: bounds validation — port numbers
        if (update.Port < 1 || update.Port > 65535)
            return BadRequest(new { error = "Port must be between 1 and 65535." });
        if (update.PublicPort.HasValue && (update.PublicPort.Value < 1 || update.PublicPort.Value > 65535))
            return BadRequest(new { error = "PublicPort must be between 1 and 65535." });

        _config.Http.CorsOrigins = update.CorsOrigins ?? _config.Http.CorsOrigins;
        _config.Http.SwaggerEnabled = update.SwaggerEnabled;
        if (update.Port >= 0) _config.Http.Port = update.Port;
        if (update.PublicPort.HasValue) _config.Http.PublicPort = update.PublicPort;
        _config.Http.EnableCors = update.EnableCors;
        if (!string.IsNullOrEmpty(update.TrustedProxyCidrs)) _config.Http.TrustedProxyCidrs = update.TrustedProxyCidrs;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Http", new { update.Port, update.PublicPort, update.CorsOrigins, update.SwaggerEnabled, update.EnableCors, update.TrustedProxyCidrs });
        return Ok(new { message = "HTTP config updated (restart required)", config = _config.Http });
    }

    // PUT /config/rate-limiting removed — rate-limit policy now lives in the DB-backed
    // ProtocolRateLimits table, managed via PUT /api/v1/admin/rate-limit-policy.

    /// <summary>
    /// Updates the runtime-tunable scheduler knobs. Note that <c>Enabled</c> and
    /// <c>PollIntervalSeconds</c> are no longer accepted — the scheduler is always
    /// on and polls every 30 seconds; multi-replica safety is handled by the
    /// leader-election lease.
    /// </summary>
    [HttpPut("scheduler")]
    public async Task<IActionResult> UpdateScheduler([FromBody] SchedulerConfig update)
    {
        if (update.LeaseTtlSeconds >= 15) _config.Scheduler.LeaseTtlSeconds = update.LeaseTtlSeconds;
        if (!string.IsNullOrWhiteSpace(update.MissedRunPolicy)) _config.Scheduler.MissedRunPolicy = update.MissedRunPolicy;
        if (update.DefaultJobTimeoutSeconds > 0) _config.Scheduler.DefaultJobTimeoutSeconds = update.DefaultJobTimeoutSeconds;
        if (update.ConsecutiveFailureAlertThreshold > 0) _config.Scheduler.ConsecutiveFailureAlertThreshold = update.ConsecutiveFailureAlertThreshold;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        // Explicit safe projection for audit details.
        await AuditConfigChange("Scheduler", new
        {
            update.LeaseTtlSeconds,
            update.MissedRunPolicy,
            update.DefaultJobTimeoutSeconds,
            update.ConsecutiveFailureAlertThreshold
        });
        return Ok(new { message = "Scheduler config updated (restart required for some changes)", config = _config.Scheduler });
    }

    /// <summary>
    /// Updates the token configuration (refresh token lifetime).
    /// </summary>
    [HttpPut("tokens")]
    public async Task<IActionResult> UpdateTokens([FromBody] TokenConfig update)
    {
        // ICF-09: bounds validation
        if (update.RefreshTokenDays < 1)
            return BadRequest(new { error = "RefreshTokenDays must be >= 1." });

        if (update.RefreshTokenDays > 0) _config.Tokens.RefreshTokenDays = update.RefreshTokenDays;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        // Explicit safe projection.
        await AuditConfigChange("Tokens", new { update.RefreshTokenDays });
        return Ok(new { message = "Token config updated", config = _config.Tokens });
    }

    /// <summary>
    /// Updates the middleware-wired security configuration — JWT / refresh-token binding,
    /// per-username rate limits, and reverse-proxy trust. Requires step-up MFA.
    /// Runtime-tunable policy (lockout, MFA TTLs, OCSP posture, login banner) is
    /// managed via <c>PUT /api/v1/admin/security-policy</c> and lives in the
    /// <c>SecurityPolicy</c> table.
    /// </summary>
    [HttpPut("security")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateSecurity([FromBody] SecurityConfig update)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null)
            return Unauthorized();

        _config.Security.BindJwtToIp = update.BindJwtToIp;
        _config.Security.BindRefreshTokenToIp = update.BindRefreshTokenToIp;
        _config.Security.BindRefreshTokenToFingerprint = update.BindRefreshTokenToFingerprint;
        _config.Security.AllowRefreshTokenMismatch = update.AllowRefreshTokenMismatch;
        _config.Security.MaxPerUsernameLoginFailures = update.MaxPerUsernameLoginFailures;
        _config.Security.PerUsernameLoginFailureWindowMinutes = update.PerUsernameLoginFailureWindowMinutes;
        _config.Security.BehindReverseProxy = update.BehindReverseProxy;

        if (TryPersistOrError() is { } __persistErr) return __persistErr;

        await AuditConfigChange("Security", new
        {
            update.BindJwtToIp,
            update.BindRefreshTokenToIp,
            update.BindRefreshTokenToFingerprint,
            update.AllowRefreshTokenMismatch,
            update.MaxPerUsernameLoginFailures,
            update.PerUsernameLoginFailureWindowMinutes,
            update.BehindReverseProxy,
        });
        _ = _alertService.RaiseAlertAsync("SecurityConfigChanged", AlertSeverity.Warning, $"Security configuration updated by {_currentUser.User?.Username}", new { update.BindJwtToIp, update.BehindReverseProxy });
        return Ok(new { message = "Security config updated", config = _config.Security });
    }

    [HttpPut("ldap-auth")]
    // Step-up parity with every other security-relevant section. Omitting it here was
    // account takeover, not merely an inconsistency: LdapAuthService re-reads this config per
    // call so the change is live without a restart, and AuthController.Login treats a
    // successful LDAP bind as proof of the local password. Pointing Host at an attacker-
    // controlled directory therefore yields any user's JWT.
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateLdapAuth([FromBody] LdapAuthConfig update)
    {
        _config.LdapAuth.Enabled = update.Enabled;
        if (!string.IsNullOrEmpty(update.Host)) _config.LdapAuth.Host = update.Host;
        if (update.Port > 0) _config.LdapAuth.Port = update.Port;
        _config.LdapAuth.UseSsl = update.UseSsl;
        if (!string.IsNullOrEmpty(update.SearchBaseDn)) _config.LdapAuth.SearchBaseDn = update.SearchBaseDn;
        if (!string.IsNullOrEmpty(update.SearchFilter)) _config.LdapAuth.SearchFilter = update.SearchFilter;
        if (update.BindDn != null) _config.LdapAuth.BindDn = update.BindDn;
        if (update.BindPassword != null && !IsRedactionSentinel(update.BindPassword))
            _config.LdapAuth.BindPassword = update.BindPassword;
        _config.LdapAuth.GroupSyncEnabled = update.GroupSyncEnabled;
        _config.LdapAuth.AutoProvisionUsers = update.AutoProvisionUsers;
        if (!string.IsNullOrEmpty(update.GroupSearchBaseDn)) _config.LdapAuth.GroupSearchBaseDn = update.GroupSearchBaseDn;
        if (!string.IsNullOrEmpty(update.GroupSearchFilter)) _config.LdapAuth.GroupSearchFilter = update.GroupSearchFilter;
        if (!string.IsNullOrEmpty(update.GroupMemberAttribute)) _config.LdapAuth.GroupMemberAttribute = update.GroupMemberAttribute;
        if (update.GroupToRoleMappings != null) _config.LdapAuth.GroupToRoleMappings = update.GroupToRoleMappings;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("LdapAuth", new { update.Enabled, update.Host, update.Port });
        return Ok(new { message = "LDAP auth config updated", enabled = _config.LdapAuth.Enabled });
    }

    [HttpPut("email")]
    public async Task<IActionResult> UpdateEmail([FromBody] EmailConfigUpdateRequest update)
    {
        _config.Email.Enabled = update.Enabled;
        if (!string.IsNullOrEmpty(update.SmtpHost)) _config.Email.SmtpHost = update.SmtpHost;
        if (update.SmtpPort > 0) _config.Email.SmtpPort = update.SmtpPort;
        _config.Email.UseTls = update.UseTls;
        if (!string.IsNullOrEmpty(update.AuthMethod)) _config.Email.AuthMethod = update.AuthMethod;
        if (update.Username != null) _config.Email.Username = update.Username;
        if (update.Password != null && !IsRedactionSentinel(update.Password)) _config.Email.Password = update.Password;
        if (update.OAuth2AccessToken != null && !IsRedactionSentinel(update.OAuth2AccessToken)) _config.Email.OAuth2AccessToken = update.OAuth2AccessToken;
        if (update.OAuth2ClientId != null) _config.Email.OAuth2ClientId = update.OAuth2ClientId;
        if (update.OAuth2ClientSecret != null && !IsRedactionSentinel(update.OAuth2ClientSecret)) _config.Email.OAuth2ClientSecret = update.OAuth2ClientSecret;
        if (update.OAuth2TokenUrl != null) _config.Email.OAuth2TokenUrl = update.OAuth2TokenUrl;
        if (update.OAuth2Scopes != null) _config.Email.OAuth2Scopes = update.OAuth2Scopes;
        if (!string.IsNullOrEmpty(update.FromAddress)) _config.Email.FromAddress = update.FromAddress;
        if (update.FromName != null) _config.Email.FromName = update.FromName;
        if (update.AdminRecipients != null) _config.Email.AdminRecipients = update.AdminRecipients;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Email", new { update.Enabled, update.SmtpHost, update.SmtpPort, update.AuthMethod });
        return Ok(new { message = "Email config updated", enabled = _config.Email.Enabled });
    }

    [HttpPut("metrics")]
    public async Task<IActionResult> UpdateMetrics([FromBody] MetricsConfig update)
    {
        // Activation is controlled by the Metrics.Enabled feature flag (admin UI
        // toggle). This endpoint only updates the sink-specific config — currently
        // just the scrape path.
        if (!string.IsNullOrEmpty(update.Path)) _config.Metrics.Path = update.Path;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        // Explicit safe projection.
        await AuditConfigChange("Metrics", new { update.Path });
        return Ok(new { message = "Metrics config updated", config = _config.Metrics });
    }

    [HttpPut("ssh-ca")]
    public async Task<IActionResult> UpdateSshCa([FromBody] SshCaConfig update)
    {
        if (!string.IsNullOrEmpty(update.SshKeygenPath)) _config.SshCa.SshKeygenPath = update.SshKeygenPath;
        if (!string.IsNullOrEmpty(update.KeyStoragePath)) _config.SshCa.KeyStoragePath = update.KeyStoragePath;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        // Explicit safe projection. SshKeygenPath / KeyStoragePath are
        // filesystem locations; any signing-key fields added later would land in the
        // scrubber but are omitted here at the call site too.
        await AuditConfigChange("SshCa", new { update.SshKeygenPath, update.KeyStoragePath });
        return Ok(new { message = "SSH CA config updated", config = _config.SshCa });
    }

    /// <summary>
    /// Updates the HTTPS configuration including the public domain used for management-UI redirects
    /// and ACME URL binding. Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("https")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateHttps([FromBody] HttpsConfig update)
    {
        // ICF-09: bounds validation — port numbers
        if (update.Port < 1 || update.Port > 65535)
            return BadRequest(new { error = "Port must be between 1 and 65535." });
        if (update.PublicPort.HasValue && (update.PublicPort.Value < 1 || update.PublicPort.Value > 65535))
            return BadRequest(new { error = "PublicPort must be between 1 and 65535." });

        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null)
            return Unauthorized();

        if (!string.IsNullOrEmpty(update.PublicDomain)) _config.Https.PublicDomain = update.PublicDomain;
        if (update.PublicPort.HasValue) _config.Https.PublicPort = update.PublicPort;
        if (!string.IsNullOrEmpty(update.Mode)) _config.Https.Mode = update.Mode;
        if (update.Port > 0) _config.Https.Port = update.Port;
        if (!string.IsNullOrEmpty(update.RenewalWindow)) _config.Https.RenewalWindow = update.RenewalWindow;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Https", new { update.PublicDomain, update.PublicPort, update.Port });
        return Ok(new { message = "HTTPS config updated", config = _config.Https });
    }

    /// <summary>
    /// Updates the IP whitelist configuration for protocol endpoint access control.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPut("ip-whitelist")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateIpWhitelist([FromBody] IpWhitelistConfig update)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null)
            return Unauthorized();

        _config.IpWhitelist.Enabled = update.Enabled;
        // CIDR ranges live in the centralized Whitelists DB table; this endpoint only
        // toggles the on/off switch and the exempt-paths list.
        if (update.ExemptPaths != null) _config.IpWhitelist.ExemptPaths = update.ExemptPaths;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("IpWhitelist", new { update.Enabled });
        _ = _alertService.RaiseAlertAsync("IpWhitelistChanged", AlertSeverity.Warning, $"IP whitelist configuration updated by {_currentUser.User?.Username}", new { update.Enabled });
        return Ok(new { message = "IP whitelist config updated (restart required for full effect)", config = _config.IpWhitelist });
    }

    /// <summary>
    /// Restarts the application. Requires the SystemAdmin authorization policy.
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPost("restart")]
    [Authorize(Policy = "SystemAdmin")]
    [RequireStepUp(StepUpOps.Restart)]
    public async Task<IActionResult> Restart()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null)
            return Unauthorized();

        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await _audit.LogAsync(AuditActionType.ApplicationRestarted, _currentUser.User?.Id, _currentUser.User?.Username,
            "Application", null, sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        _ = Task.Run(async () =>
        {
            await Task.Delay(500);
            _appLifetime.StopApplication();
        });
        return Ok(new { message = "Application is restarting. Reconnect in a few seconds." });
    }

    /// <summary>
    /// Updates the backup configuration (schedule, retention, verification).
    /// Requires step-up MFA verification.
    /// </summary>
    [HttpPut("backup")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateBackup([FromBody] BackupConfig update)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (!string.IsNullOrEmpty(update.Schedule)) _config.Backup.Schedule = update.Schedule;
        if (!string.IsNullOrEmpty(update.OutputPath)) _config.Backup.OutputPath = update.OutputPath;
        if (update.RetentionCount > 0) _config.Backup.RetentionCount = update.RetentionCount;
        if (update.MaxBackupAgeDays > 0) _config.Backup.MaxBackupAgeDays = update.MaxBackupAgeDays;
        _config.Backup.VerifyOnSchedule = update.VerifyOnSchedule;
        if (update.VerifyCount > 0) _config.Backup.VerifyCount = update.VerifyCount;
        if (update.MinimumRetentionDays > 0) _config.Backup.MinimumRetentionDays = update.MinimumRetentionDays;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Backup", new { update.Schedule, update.OutputPath, update.RetentionCount, update.MaxBackupAgeDays });
        return Ok(new { message = "Backup config updated", config = _config.Backup });
    }

    /// <summary>
    /// Updates the certificate policy configuration (validity limits, key size requirements, SAN enforcement).
    /// Requires step-up MFA verification.
    /// </summary>
    [HttpPut("certificate-policy")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateCertPolicy([FromBody] CertPolicyConfig update)
    {
        // ICF-09: bounds validation
        if (update.MinRsaKeySize < 2048)
            return BadRequest(new { error = "MinRsaKeySize must be >= 2048." });
        if (update.MaxValidityDays < 1)
            return BadRequest(new { error = "MaxValidityDays must be >= 1." });

        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        _config.CertPolicy.Enabled = update.Enabled;
        if (update.MinRsaKeySize >= 2048) _config.CertPolicy.MinRsaKeySize = update.MinRsaKeySize;
        if (update.MaxValidityDays > 0) _config.CertPolicy.MaxValidityDays = update.MaxValidityDays;
        _config.CertPolicy.RequireSans = update.RequireSans;
        if (update.ForbiddenAlgorithms != null) _config.CertPolicy.ForbiddenAlgorithms = update.ForbiddenAlgorithms;
        if (update.AlgorithmSunsetRules != null) _config.CertPolicy.AlgorithmSunsetRules = update.AlgorithmSunsetRules;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("CertPolicy", new { update.Enabled, update.MinRsaKeySize, update.MaxValidityDays, update.RequireSans });
        return Ok(new { message = "Certificate policy updated", config = _config.CertPolicy });
    }

    /// <summary>
    /// Updates the mTLS configuration (enable/disable, auth subdomain, required paths, trusted CAs).
    /// Requires step-up MFA verification.
    /// <para>
    /// Explicitly-listed <c>TrustedCaCertPaths</c> are verified to resolve and parse before the
    /// config is persisted. The startup path treats an empty effective anchor set as fatal, so a
    /// typo'd or unreadable anchor path written here would not surface until the next restart —
    /// as a server that refuses to boot. Rejecting at write time turns that into an error message
    /// in the admin UI while the operator still has the field in front of them.
    /// </para>
    /// <para>
    /// An empty list is NOT an error: startup falls back to the enrolled mTLS signing CAs recorded
    /// in <c>CaGroups.MtlsSigningCaId</c>, which is the normal configuration for an instance that
    /// issues its own client certificates. Only paths the operator actually named are checked.
    /// </para>
    /// </summary>
    [HttpPut("mtls")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> UpdateMtls([FromBody] MtlsConfig update)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (update.TrustedCaCertPaths is { Count: > 0 })
        {
            var anchorErrors = new List<string>();
            foreach (var path in update.TrustedCaCertPaths)
            {
                if (string.IsNullOrWhiteSpace(path)) continue;

                // Mirror the startup resolution rule: relative paths resolve against the
                // application base directory, not the process working directory.
                var resolved = Path.IsPathRooted(path)
                    ? path
                    : Path.Combine(AppContext.BaseDirectory, path);
                try
                {
                    if (!System.IO.File.Exists(resolved))
                    {
                        anchorErrors.Add($"{path}: file not found (resolved to {resolved})");
                        continue;
                    }
                    using var probe = System.Security.Cryptography.X509Certificates.X509CertificateLoader
                        .LoadCertificateFromFile(resolved);
                }
                catch (Exception ex)
                {
                    anchorErrors.Add($"{path}: not a readable certificate ({ex.GetType().Name})");
                }
            }

            if (anchorErrors.Count > 0)
                return BadRequest(new
                {
                    error = "One or more trusted CA certificate paths could not be loaded. "
                          + "Fix or remove them — the server will refuse to start with an unusable anchor list.",
                    details = anchorErrors
                });
        }

        _config.Mtls.Enabled = update.Enabled;
        if (!string.IsNullOrEmpty(update.AuthSubdomain)) _config.Mtls.AuthSubdomain = update.AuthSubdomain;
        if (update.RequiredPaths != null) _config.Mtls.RequiredPaths = update.RequiredPaths;
        if (update.TrustedCaCertPaths != null) _config.Mtls.TrustedCaCertPaths = update.TrustedCaCertPaths;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Mtls", new { update.Enabled, update.AuthSubdomain });
        return Ok(new { message = "mTLS config updated", config = _config.Mtls });
    }

    /// <summary>
    /// Updates the automatic certificate renewal configuration.
    /// </summary>
    [HttpPut("auto-renewal")]
    public async Task<IActionResult> UpdateAutoRenewal([FromBody] AutoRenewalUpdateRequest request)
    {
        _config.AutoRenewal.Enabled = request.Enabled;
        if (request.RenewDaysBeforeExpiry > 0) _config.AutoRenewal.RenewDaysBeforeExpiry = request.RenewDaysBeforeExpiry;
        _config.AutoRenewal.AutoApprove = request.AutoApprove;
        if (!string.IsNullOrEmpty(request.Schedule)) _config.AutoRenewal.Schedule = request.Schedule;
        _config.AutoRenewal.RequireKeyRotation = request.RequireKeyRotation;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("AutoRenewal", new { request.Enabled, request.RenewDaysBeforeExpiry, request.AutoApprove, request.Schedule, request.RequireKeyRotation });
        return Ok(new { message = "Auto-renewal config updated", config = _config.AutoRenewal });
    }

    /// <summary>
    /// Updates the certificate compliance scan configuration.
    /// </summary>
    [HttpPut("compliance-scan")]
    public async Task<IActionResult> UpdateComplianceScan([FromBody] ComplianceScanUpdateRequest request)
    {
        _config.ComplianceScan.Enabled = request.Enabled;
        if (request.MinRsaKeySize >= 2048) _config.ComplianceScan.MinRsaKeySize = request.MinRsaKeySize;
        if (request.WarnOverValidityDays > 0) _config.ComplianceScan.WarnOverValidityDays = request.WarnOverValidityDays;
        if (!string.IsNullOrEmpty(request.Schedule)) _config.ComplianceScan.Schedule = request.Schedule;
        if (request.DeprecatedAlgorithms != null) _config.ComplianceScan.DeprecatedAlgorithms = request.DeprecatedAlgorithms;
        if (request.ExpiringWithinDays > 0) _config.ComplianceScan.ExpiringWithinDays = request.ExpiringWithinDays;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("ComplianceScan", new { request.Enabled, request.MinRsaKeySize, request.WarnOverValidityDays, request.Schedule, request.ExpiringWithinDays });
        return Ok(new { message = "Compliance scan config updated", config = _config.ComplianceScan });
    }

    /// <summary>
    /// Updates the certificate expiry notification configuration.
    /// </summary>
    [HttpPut("cert-expiry-notifications")]
    public async Task<IActionResult> UpdateCertExpiryNotifications([FromBody] CertExpiryNotificationUpdateRequest request)
    {
        _config.CertExpiryNotification.Enabled = request.Enabled;
        if (request.WarningDays != null) _config.CertExpiryNotification.WarningDaysBeforeExpiry = request.WarningDays;
        if (!string.IsNullOrEmpty(request.Schedule)) _config.CertExpiryNotification.Schedule = request.Schedule;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("CertExpiryNotification", new { request.Enabled, request.WarningDays, request.Schedule });
        return Ok(new { message = "Cert expiry notification config updated", config = _config.CertExpiryNotification });
    }

    /// <summary>
    /// Updates the ACME protocol policy configuration.
    /// </summary>
    [HttpPut("acme-policies")]
    public async Task<IActionResult> UpdateAcmePolicies([FromBody] AcmePoliciesUpdateRequest request)
    {
        _config.Acme.ExternalAccountRequired = request.ExternalAccountRequired;
        _config.Acme.EnforceCaa = request.EnforceCaa;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Acme", new { request.ExternalAccountRequired, request.EnforceCaa });
        return Ok(new { message = "ACME policies updated", config = _config.Acme });
    }

    /// <summary>
    /// Updates the security alert configuration.
    /// </summary>
    [HttpPut("alert")]
    public async Task<IActionResult> UpdateAlert([FromBody] AlertUpdateRequest request)
    {
        _config.Alert.Enabled = request.Enabled;
        if (!string.IsNullOrEmpty(request.MinimumSeverity)) _config.Alert.MinimumSeverity = request.MinimumSeverity;
        if (request.CooldownMinutes > 0) _config.Alert.CooldownMinutes = request.CooldownMinutes;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Alert", new { request.Enabled, request.MinimumSeverity, request.CooldownMinutes });
        return Ok(new { message = "Alert config updated", config = _config.Alert });
    }

    /// <summary>
    /// Updates the webhook notification configuration.
    /// </summary>
    [HttpPut("webhook")]
    public async Task<IActionResult> UpdateWebhook([FromBody] WebhookUpdateRequest request)
    {
        _config.Webhook.Enabled = request.Enabled;
        if (request.MaxRetries > 0) _config.Webhook.MaxRetries = request.MaxRetries;
        if (request.RetryDelaySeconds > 0) _config.Webhook.RetryDelaySeconds = request.RetryDelaySeconds;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("Webhook", new { request.Enabled, request.MaxRetries, request.RetryDelaySeconds });
        return Ok(new { message = "Webhook config updated", config = new { _config.Webhook.Enabled, _config.Webhook.MaxRetries, _config.Webhook.RetryDelaySeconds } });
    }

    /// <summary>
    /// Updates the network audit (request logging) configuration.
    /// </summary>
    [HttpPut("network-audit")]
    public async Task<IActionResult> UpdateNetworkAudit([FromBody] NetworkAuditUpdateRequest request)
    {
        _config.NetworkAudit.Enabled = request.Enabled;
        _config.NetworkAudit.LogAllRequests = request.LogAllRequests;
        if (request.ExcludePaths != null) _config.NetworkAudit.ExcludePaths = request.ExcludePaths;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("NetworkAudit", new { request.Enabled, request.LogAllRequests, request.ExcludePaths });
        return Ok(new { message = "Network audit config updated", config = _config.NetworkAudit });
    }

    /// <summary>
    /// Updates the GitOps-style policy synchronization configuration.
    /// </summary>
    [HttpPut("policy-sync")]
    public async Task<IActionResult> UpdatePolicySync([FromBody] PolicySyncUpdateRequest request)
    {
        _config.PolicySync.Enabled = request.Enabled;
        if (!string.IsNullOrEmpty(request.PolicyDirectory)) _config.PolicySync.PolicyDirectory = request.PolicyDirectory;
        _config.PolicySync.SyncOnStartup = request.SyncOnStartup;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("PolicySync", new { request.Enabled, request.PolicyDirectory, request.SyncOnStartup });
        return Ok(new { message = "Policy sync config updated", config = _config.PolicySync });
    }

    /// <summary>
    /// Updates the Kubernetes cert-manager integration configuration.
    /// Requires a restart to take full effect.
    /// </summary>
    [HttpPut("cert-manager")]
    public async Task<IActionResult> UpdateCertManager([FromBody] CertManagerUpdateRequest request)
    {
        _config.CertManager.Enabled = request.Enabled;
        if (request.ApiKey != null && !IsRedactionSentinel(request.ApiKey))
            _config.CertManager.ApiKey = request.ApiKey;
        if (request.DefaultCertProfileId.HasValue) _config.CertManager.DefaultCertProfileId = request.DefaultCertProfileId;
        if (request.DefaultSigningProfileId.HasValue) _config.CertManager.DefaultSigningProfileId = request.DefaultSigningProfileId;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("CertManager", new { request.Enabled, request.DefaultCertProfileId, request.DefaultSigningProfileId });
        return Ok(new { message = "Cert-manager config updated (restart required)", config = new { _config.CertManager.Enabled, ApiKey = !string.IsNullOrEmpty(_config.CertManager.ApiKey) ? RedactSecret("CertManager.ApiKey") : "", _config.CertManager.DefaultCertProfileId, _config.CertManager.DefaultSigningProfileId } });
    }

    /// <summary>
    /// Updates the infrastructure integration API configuration.
    /// Requires a restart to take full effect.
    /// </summary>
    [HttpPut("integration-api")]
    public async Task<IActionResult> UpdateIntegrationApi([FromBody] IntegrationApiUpdateRequest request)
    {
        _config.IntegrationApi.Enabled = request.Enabled;
        if (request.ApiKey != null && !IsRedactionSentinel(request.ApiKey))
            _config.IntegrationApi.ApiKey = request.ApiKey;
        if (TryPersistOrError() is { } __persistErr) return __persistErr;
        await AuditConfigChange("IntegrationApi", new { request.Enabled });
        return Ok(new { message = "Integration API config updated (restart required)", config = new { _config.IntegrationApi.Enabled, ApiKey = !string.IsNullOrEmpty(_config.IntegrationApi.ApiKey) ? RedactSecret("IntegrationApi.ApiKey") : "" } });
    }

    private async Task AuditConfigChange(string section, object? details = null)
    {
        await _currentUser.EnsureLoadedAsync();
        await _audit.LogAsync(AuditActionType.ConfigUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Config", section, details, HttpContext.Connection.RemoteIpAddress?.ToString());
    }

    /// <summary>
    /// Persists the in-memory config to config.yaml. Env-sourced secrets are temporarily
    /// cleared before serialization (via <see cref="EnvVarConfigOverlay.WithSecretsProtected"/>)
    /// so they are never written to disk. Throws on write failure so callers can surface
    /// the failure as 500 to the operator instead of silently returning 200 — a swallowed
    /// warning produced misleading "saved" UX in earlier revisions where the on-disk YAML
    /// silently diverged from in-memory state. The in-memory mutation is left in place
    /// either way; the operator can retry once the underlying file-permission / disk issue
    /// is resolved.
    /// </summary>
    private void PersistConfig()
    {
        Exception? writeFailure = null;
        _envOverlay.WithSecretsProtected(_config, () =>
        {
            try
            {
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(PascalCaseNamingConvention.Instance)
                    .Build();
                var yaml = serializer.Serialize(_config);
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                System.IO.File.WriteAllText(configPath, yaml);
            }
            catch (Exception ex)
            {
                writeFailure = ex;
            }
        });
        if (writeFailure != null)
            throw writeFailure;
    }

    /// <summary>
    /// Calls <see cref="PersistConfig"/>; on IO failure returns a 500 <see cref="IActionResult"/>
    /// the caller can return directly. Use as <c>if (TryPersistOrError() is { } err) return err;</c>
    /// — keeps the 26-ish PUT handlers terse while still surfacing persist failures as 500
    /// to the operator instead of silently returning 200 with a divergent on-disk YAML.
    /// </summary>
    private IActionResult? TryPersistOrError()
    {
        try
        {
            PersistConfig();
            return null;
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to persist configuration to config.yaml.", details = ex.Message });
        }
    }

    /// <summary>Returns "(env)" for env-sourced secrets, "***" otherwise.</summary>
    private string RedactSecret(string path) =>
        _envOverlay.EnvSourcedPaths.Contains(path) ? "(env)" : "***";

    /// <summary>
    /// True when a submitted value is one of the placeholders <see cref="RedactSecret"/> hands to
    /// the browser, meaning "unchanged" rather than a real new value.
    /// <para>
    /// Every write of a redacted field must go through this. The UI loads a section, renders the
    /// placeholder in the input, and PUTs the whole section back when the operator changes some
    /// unrelated toggle — so an unguarded assignment overwrites the real secret with the literal
    /// string "***". Guards existed but were inconsistent: two call sites checked both
    /// placeholders, three checked only "***" (so an env-sourced secret could be destroyed by
    /// writing back "(env)"), and the LDAP bind DN had no guard at all.
    /// </para>
    /// </summary>
    private static bool IsRedactionSentinel(string? value) => value is "***" or "(env)";
}

/// <summary>Request body for PUT /config/auto-renewal.</summary>
public class AutoRenewalUpdateRequest
{
    public bool Enabled { get; set; }
    public int RenewDaysBeforeExpiry { get; set; }
    public bool AutoApprove { get; set; }
    public string? Schedule { get; set; }
    public bool RequireKeyRotation { get; set; }
}

/// <summary>Request body for PUT /config/compliance-scan.</summary>
public class ComplianceScanUpdateRequest
{
    public bool Enabled { get; set; }
    public int MinRsaKeySize { get; set; }
    /// <summary>
    /// Validity threshold in days above which the scanner emits an "OverLongValidity"
    /// finding. Warning threshold only — does not block issuance.
    /// </summary>
    public int WarnOverValidityDays { get; set; }
    public string? Schedule { get; set; }
    public List<string>? DeprecatedAlgorithms { get; set; }
    public int ExpiringWithinDays { get; set; }
}

/// <summary>Request body for PUT /config/cert-expiry-notifications.</summary>
public class CertExpiryNotificationUpdateRequest
{
    public bool Enabled { get; set; }
    public List<int>? WarningDays { get; set; }
    public string? Schedule { get; set; }
}

/// <summary>Request body for PUT /config/acme-policies.</summary>
public class AcmePoliciesUpdateRequest
{
    public bool ExternalAccountRequired { get; set; }
    public bool EnforceCaa { get; set; }
}

/// <summary>Request body for PUT /config/alert.</summary>
public class AlertUpdateRequest
{
    public bool Enabled { get; set; }
    public string? MinimumSeverity { get; set; }
    public int CooldownMinutes { get; set; }
}

/// <summary>Request body for PUT /config/webhook.</summary>
public class WebhookUpdateRequest
{
    public bool Enabled { get; set; }
    public int MaxRetries { get; set; }
    public int RetryDelaySeconds { get; set; }
}

/// <summary>Request body for PUT /config/network-audit.</summary>
public class NetworkAuditUpdateRequest
{
    public bool Enabled { get; set; }
    public bool LogAllRequests { get; set; }
    public List<string>? ExcludePaths { get; set; }
}

/// <summary>Request body for PUT /config/policy-sync.</summary>
public class PolicySyncUpdateRequest
{
    public bool Enabled { get; set; }
    public string? PolicyDirectory { get; set; }
    public bool SyncOnStartup { get; set; }
}

/// <summary>Request body for PUT /config/cert-manager.</summary>
public class CertManagerUpdateRequest
{
    public bool Enabled { get; set; }
    public string? ApiKey { get; set; }
    public Guid? DefaultCertProfileId { get; set; }
    public Guid? DefaultSigningProfileId { get; set; }
}

/// <summary>Request body for PUT /config/integration-api.</summary>
public class IntegrationApiUpdateRequest
{
    public bool Enabled { get; set; }
    public string? ApiKey { get; set; }
}

public class EmailConfigUpdateRequest
{
    public bool Enabled { get; set; }
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; }
    public bool UseTls { get; set; } = true;
    public string? AuthMethod { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? OAuth2AccessToken { get; set; }
    public string? OAuth2ClientId { get; set; }
    public string? OAuth2ClientSecret { get; set; }
    public string? OAuth2TokenUrl { get; set; }
    public string? OAuth2Scopes { get; set; }
    public string? FromAddress { get; set; }
    public string? FromName { get; set; }
    public string? AdminRecipients { get; set; }
}
