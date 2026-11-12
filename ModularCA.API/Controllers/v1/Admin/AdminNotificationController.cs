using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Serilog;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing notification preferences, sending test emails,
/// and testing webhook connectivity.
/// </summary>
[ApiController]
[Route("api/v1/admin/notifications")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminNotificationController(ModularCADbContext db, IEmailService emailService, IWebhookService webhookService, SystemConfig config) : ControllerBase
{
    /// <summary>
    /// Lists the per-event notification preferences (<see cref="NotificationPreferenceView"/>:
    /// enabled flag, recipients, description), ordered by event type. Requires the
    /// <c>SystemOperator</c> policy.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetPreferences()
    {
        var prefs = await db.NotificationPreferences.AsNoTracking().OrderBy(p => p.EventType)
            .Select(p => new NotificationPreferenceView(p.Id, p.EventType, p.Enabled, p.Recipients, p.Description))
            .ToListAsync();
        return Ok(prefs);
    }

    /// <summary>
    /// The outbound email settings the notification page shows: whether sending is on, the SMTP
    /// server, TLS, sender and admin recipients. No credential or token is returned. The full
    /// configuration, alerting included, is <c>GET /api/v1/admin/config</c> (system admin).
    /// </summary>
    [HttpGet("delivery")]
    public IActionResult GetDelivery() => Ok(new
    {
        Email = new
        {
            config.Email.Enabled,
            config.Email.SmtpHost,
            config.Email.SmtpPort,
            config.Email.UseTls,
            config.Email.FromAddress,
            config.Email.AdminRecipients,
        },
    });

    /// <summary>
    /// Updates one notification preference and returns it as <see cref="NotificationPreferenceView"/>.
    /// Recipients, when sent, is a comma-separated list whose entries must each parse as a mail
    /// address (400); empty falls back to the admin recipients.
    /// </summary>
    [HttpPut("{eventType}")]
    public async Task<IActionResult> UpdatePreference(string eventType, [FromBody] UpdateNotificationRequest request)
    {
        var pref = await db.NotificationPreferences.FirstOrDefaultAsync(p => p.EventType == eventType);
        if (pref == null) return NotFound(new { error = $"Notification preference '{eventType}' not found" });

        if (ConfigInputRules.EmailListError(request.Recipients, "Recipients") is { } recipientsError)
            return BadRequest(new { error = recipientsError });

        if (request.Enabled.HasValue) pref.Enabled = request.Enabled.Value;
        if (request.Recipients != null) pref.Recipients = request.Recipients;

        await db.SaveChangesAsync();
        return Ok(new NotificationPreferenceView(pref.Id, pref.EventType, pref.Enabled, pref.Recipients, pref.Description));
    }

    /// <summary>
    /// Sends a test email to the admin recipients through the configured SMTP settings. Answers 500
    /// with a generic message when sending fails; the cause goes to the log only.
    /// </summary>
    [HttpPost("test")]
    public async Task<IActionResult> SendTestEmail()
    {
        try
        {
            await emailService.SendToAdminsAsync(
                "[ModularCA] Test Email",
                $"This is a test email from ModularCA.\nSent at: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\n\nIf you received this, SMTP is configured correctly.");
            return Ok(new { message = "Test email sent to admin recipients" });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to send test email");
            return StatusCode(500, new { error = "Failed to send test email. Please verify SMTP settings and try again." });
        }
    }

    /// <summary>
    /// Sends a clearly-labeled test event to all configured webhook endpoints.
    /// Returns the delivery results for each endpoint (success or failure).
    /// This is a test-only event and should not be confused with real alerts.
    /// </summary>
    [HttpPost("test-webhook")]
    public async Task<IActionResult> TestWebhook()
    {
        var webhookConfig = config.Webhook;
        if (!webhookConfig.Enabled || webhookConfig.Endpoints.Count == 0)
        {
            return BadRequest(new { error = "Webhooks are not enabled or no endpoints are configured." });
        }

        // ALC-09: validate all configured webhook URLs against SSRF before dispatching
        var unsafeEndpoints = new List<string>();
        foreach (var ep in webhookConfig.Endpoints)
        {
            var (isSafe, reason) = await Core.Services.WebhookService.IsUrlSafeForSsrfAsync(ep.Url);
            if (!isSafe)
                unsafeEndpoints.Add($"{ep.Url}: {reason}");
        }
        if (unsafeEndpoints.Count > 0)
        {
            return BadRequest(new
            {
                error = "One or more webhook endpoints failed SSRF validation",
                details = unsafeEndpoints
            });
        }

        var testPayload = new
        {
            test = true,
            message = "This is a test webhook from ModularCA. If you received this, webhook delivery is working correctly.",
            sentAt = DateTime.UtcNow.ToString("o"),
            endpointCount = webhookConfig.Endpoints.Count
        };

        try
        {
            await webhookService.PostEventAsync("TestWebhook", testPayload);
            return Ok(new
            {
                message = "Test webhook dispatched to all configured endpoints",
                endpointCount = webhookConfig.Endpoints.Count,
                endpoints = webhookConfig.Endpoints.Select(e => new { url = e.Url, events = e.Events })
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to dispatch test webhook");
            return StatusCode(500, new { error = "Failed to dispatch test webhook. Please verify webhook configuration and try again." });
        }
    }
}

/// <summary>Request body for updating a notification preference. Each field left null keeps its current value.</summary>
public class UpdateNotificationRequest
{
    /// <summary>Whether email is sent for this event type.</summary>
    public bool? Enabled { get; set; }
    /// <summary>Comma-separated addresses for this event; empty sends to the admin recipients instead.</summary>
    public string? Recipients { get; set; }
    // DaysBeforeExpiry was stored here and never read, and is gone since 0.4.4; a body that still
    // sends it is accepted and the field ignored.
}

/// <summary>One notification preference as the notification endpoints return it.</summary>
/// <param name="Id">Row id.</param>
/// <param name="EventType">The event, e.g. <c>CertExpiring</c>.</param>
/// <param name="Enabled">Whether email is sent for the event.</param>
/// <param name="Recipients">Comma-separated override recipients; null or empty sends to the admin recipients.</param>
/// <param name="Description">What the event is, for the console.</param>
public record NotificationPreferenceView(Guid Id, string EventType, bool Enabled, string? Recipients, string? Description);
