using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
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
    [HttpGet]
    public async Task<IActionResult> GetPreferences()
    {
        var prefs = await db.NotificationPreferences.AsNoTracking().OrderBy(p => p.EventType).ToListAsync();
        return Ok(prefs);
    }

    [HttpPut("{eventType}")]
    public async Task<IActionResult> UpdatePreference(string eventType, [FromBody] UpdateNotificationRequest request)
    {
        var pref = await db.NotificationPreferences.FirstOrDefaultAsync(p => p.EventType == eventType);
        if (pref == null) return NotFound(new { error = $"Notification preference '{eventType}' not found" });

        if (request.Enabled.HasValue) pref.Enabled = request.Enabled.Value;
        if (request.Recipients != null) pref.Recipients = request.Recipients;
        if (request.DaysBeforeExpiry.HasValue) pref.DaysBeforeExpiry = request.DaysBeforeExpiry;

        await db.SaveChangesAsync();
        return Ok(pref);
    }

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

public class UpdateNotificationRequest
{
    public bool? Enabled { get; set; }
    public string? Recipients { get; set; }
    public int? DaysBeforeExpiry { get; set; }
}
