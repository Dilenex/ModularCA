using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Core.Services;

/// <summary>
/// Sends notifications for certificate lifecycle events such as expiration, revocation, and issuance.
/// </summary>
public interface INotificationService
{
    Task NotifyCertExpiringAsync(CertificateEntity cert, int daysRemaining);

    /// <summary>
    /// Sends the <c>CertExpiring</c> notification for one step of a certificate's expiry warning:
    /// its soft warning starting, a reminder inside the window, or its alert starting.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="stage"><see cref="CertExpiryStage.Warning"/>, <see cref="CertExpiryStage.Reminder"/> or <see cref="CertExpiryStage.Alert"/>.</param>
    /// <param name="now">The time the notification is sent, against which the time left is told.</param>
    Task NotifyCertExpiryStageAsync(CertificateEntity cert, string stage, DateTime now);

    Task NotifyCertRevokedAsync(string subjectDN, string serial, string reason);
    Task NotifyCertIssuedAsync(string subjectDN, string serial, string protocol);
    Task NotifyAccountLockedAsync(string username, string reason);
    Task NotifyPasswordResetAsync(string username, string email, string newPassword);
    Task NotifyPasswordExpiringAsync(string username, string email, int daysRemaining);
    Task NotifyCrlGenerationFailedAsync(string caName, string error);
    Task NotifyTlsCertRenewedAsync(string newSerial, DateTime newExpiry);

    /// <summary>
    /// Sends a generic notification to administrators for a given event type.
    /// </summary>
    /// <param name="eventType">A short identifier for the event (e.g. "TlsRenewalFailed").</param>
    /// <param name="message">A human-readable description of the event.</param>
    Task NotifyAsync(string eventType, string message);

    /// <summary>
    /// Notifies administrators that a certificate signing request requires manual approval.
    /// </summary>
    /// <param name="subject">The subject distinguished name from the CSR.</param>
    /// <param name="protocol">The enrollment protocol that received the request (e.g. EST, CMP, SCEP).</param>
    Task NotifyCsrPendingApprovalAsync(string subject, string protocol);
}

public class NotificationService : INotificationService
{
    private readonly ModularCADbContext _db;
    private readonly IEmailService _email;
    private readonly SystemConfig _config;
    private readonly ILogger<NotificationService> _logger;
    private readonly IWebhookService? _webhookService;

    /// <summary>
    /// Initializes a new instance of the <see cref="NotificationService"/> class.
    /// </summary>
    /// <param name="db">Database context for reading notification preferences.</param>
    /// <param name="email">Email delivery service.</param>
    /// <param name="config">System configuration.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="webhookService">Optional webhook service for dispatching event notifications.</param>
    public NotificationService(ModularCADbContext db, IEmailService email, SystemConfig config, ILogger<NotificationService> logger, IWebhookService? webhookService = null)
    {
        _db = db;
        _email = email;
        _config = config;
        _logger = logger;
        _webhookService = webhookService;
    }

    public Task NotifyCertExpiringAsync(CertificateEntity cert, int daysRemaining) =>
        SendNotification("CertExpiring", null,
            $"[ModularCA] Certificate Expiring in {daysRemaining} Days",
            $"""
            ModularCA Notification
            ======================

            Event: Certificate Expiring
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            Certificate Details:
              Serial: {cert.SerialNumber}
              Subject: {cert.SubjectDN}
              Expires: {cert.NotAfter:yyyy-MM-dd HH:mm} UTC
              Days Remaining: {daysRemaining}

            Action Required:
              Renew the certificate before expiration.
            """);

    /// <inheritdoc />
    public Task NotifyCertExpiryStageAsync(CertificateEntity cert, string stage, DateTime now)
    {
        var left = CertExpiryStage.TimeLeft(cert.NotAfter - now);
        var (subject, headline, action) = stage switch
        {
            CertExpiryStage.Alert => ($"[ModularCA] Certificate expiry alert: expires in {left}", "Certificate Expiry Alert",
                "Renew or replace the certificate now; little of its lifetime is left."),
            CertExpiryStage.Reminder => ($"[ModularCA] Reminder: certificate expires in {left}", "Certificate Expiry Reminder",
                "Renew the certificate before it expires."),
            _ => ($"[ModularCA] Certificate expiry warning: expires in {left}", "Certificate Expiry Warning",
                "Renew the certificate before it expires."),
        };
        return SendNotification("CertExpiring", null, subject,
            $"""
            ModularCA Notification
            ======================

            Event: {headline}
            Time: {now:yyyy-MM-dd HH:mm} UTC

            Certificate Details:
              Serial: {cert.SerialNumber}
              Subject: {cert.SubjectDN}
              Expires: {cert.NotAfter:yyyy-MM-dd HH:mm} UTC
              Time Left: {left}

            Action Required:
              {action}
              Dismissing the expiry warning, or retiring the certificate, in the console stops these messages.
            """);
    }

    public Task NotifyCertRevokedAsync(string subjectDN, string serial, string reason) =>
        SendNotification("CertRevoked", null,
            $"[ModularCA] Certificate Revoked: {subjectDN}",
            $"""
            ModularCA Notification
            ======================

            Event: Certificate Revoked
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            Certificate Details:
              Serial: {serial}
              Subject: {subjectDN}
              Reason: {reason}
            """);

    public Task NotifyCertIssuedAsync(string subjectDN, string serial, string protocol) =>
        SendNotification("CertIssued", null,
            $"[ModularCA] Certificate Issued: {subjectDN}",
            $"""
            ModularCA Notification
            ======================

            Event: Certificate Issued
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            Certificate Details:
              Serial: {serial}
              Subject: {subjectDN}
              Protocol: {protocol}
            """);

    public Task NotifyAccountLockedAsync(string username, string reason) =>
        SendNotification("AccountLocked", null,
            $"[ModularCA] Account Locked: {username}",
            $"""
            ModularCA Security Alert
            ========================

            Event: Account Locked
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            Account: {username}
            Reason: {reason}

            Action Required:
              Review the account and unlock if appropriate.
            """);

    public Task NotifyPasswordResetAsync(string username, string email, string newPassword) =>
        SendNotification("PasswordReset", email,
            $"[ModularCA] Password Reset for {username}",
            $"""
            ModularCA Notification
            ======================

            Your password has been reset by an administrator.

            Username: {username}
            New Password: {newPassword}

            Please log in and change your password immediately.
            """);

    public Task NotifyPasswordExpiringAsync(string username, string email, int daysRemaining) =>
        SendNotification("PasswordExpiring", email,
            $"[ModularCA] Password Expiring in {daysRemaining} Days",
            $"""
            ModularCA Notification
            ======================

            Your password will expire in {daysRemaining} days.

            Username: {username}

            Please change your password before it expires.
            """);

    public Task NotifyCrlGenerationFailedAsync(string caName, string error) =>
        SendNotification("CrlGenerationFailed", null,
            $"[ModularCA] CRL Generation Failed: {caName}",
            $"""
            ModularCA Operational Alert
            ===========================

            Event: CRL Generation Failed
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            CA: {caName}
            Error: {error}

            Action Required:
              Investigate and resolve the CRL generation issue.
            """);

    public Task NotifyAsync(string eventType, string message) =>
        SendNotification(eventType, null,
            $"[ModularCA] {eventType}",
            $"""
            ModularCA Notification
            ======================

            Event: {eventType}
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            {message}
            """);

    public Task NotifyCsrPendingApprovalAsync(string subject, string protocol) =>
        SendNotification("CsrPendingApproval", null,
            $"[ModularCA] CSR Pending Approval: {subject}",
            $"""
            ModularCA Notification
            ======================

            Event: Certificate Request Pending Approval
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            Request Details:
              Subject: {subject}
              Protocol: {protocol}

            Action Required:
              Review and approve or deny the certificate request in the admin portal.
            """);

    public Task NotifyTlsCertRenewedAsync(string newSerial, DateTime newExpiry) =>
        SendNotification("TlsCertRenewed", null,
            "[ModularCA] API TLS Certificate Renewed",
            $"""
            ModularCA Notification
            ======================

            Event: API TLS Certificate Renewed
            Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC

            New Certificate:
              Serial: {newSerial}
              Expires: {newExpiry:yyyy-MM-dd HH:mm} UTC
            """);

    private async Task SendNotification(string eventType, string? directRecipient, string subject, string body)
    {
        // Dispatch email notification
        if (_config.Email.Enabled)
        {
            try
            {
                var pref = await _db.NotificationPreferences
                    .AsNoTracking()
                    .FirstOrDefaultAsync(p => p.EventType == eventType);

                if (pref == null || pref.Enabled)
                {
                    if (!string.IsNullOrWhiteSpace(directRecipient))
                    {
                        await _email.SendAsync(directRecipient, subject, body);
                    }
                    else if (pref != null && !string.IsNullOrWhiteSpace(pref.Recipients))
                    {
                        var recipients = pref.Recipients.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        await _email.SendAsync(recipients, subject, body);
                    }
                    else
                    {
                        await _email.SendToAdminsAsync(subject, body);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send notification for event {EventType}", eventType);
            }
        }

        // Dispatch webhook notification (fire-and-forget, failures are logged internally)
        if (_webhookService != null)
        {
            _ = _webhookService.PostEventAsync(eventType, new { subject, body });
        }
    }
}
