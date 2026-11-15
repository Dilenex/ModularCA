using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Modes;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// The instance's mode in the console: full, restricted or DR mode, who set it and when, and
/// the one place an administrator sets it by hand.
/// </summary>
/// <remarks>
/// <para>
/// Reading is open to every signed-in console user, because the console shows a standing banner
/// whenever the mode is not full. It names no CA and returns nothing a space fences: the mode is
/// the instance's.
/// </para>
/// <para>
/// Setting needs <c>system.manage</c> at system scope and a step-up, and is recorded in the audit
/// trail with who and why. It is declared <see cref="ModeOperation.Manage"/>, so it is allowed in
/// every mode: an administrator can always leave DR mode after signing in, which is how an
/// instance whose hub has gone silent is recovered. The hub sets the mode too, over its local
/// connection; the last writer wins.
/// </para>
/// </remarks>
[ApiController]
[Route("api/v1/admin/instance-mode")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminInstanceModeController(
    IInstanceModeGate gate,
    IAuditService audit,
    ICurrentUserService currentUser,
    InstanceModeStore? store = null,
    ModularCADbContext? db = null) : ControllerBase
{
    /// <summary>The longest reason accepted.</summary>
    public const int MaxReasonLength = 500;

    /// <summary>Returns the mode, who set it and when.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(InstanceModeStatus), 200)]
    public async Task<IActionResult> Get() => Ok(await WithCrlExpiryAsync(Describe(gate.Current, store), gate.Current.Mode));

    /// <summary>
    /// Adds <see cref="InstanceModeStatus.CrlsExpireFromUtc"/> in a mode that signs no new CRL:
    /// the earliest nextUpdate among the newest full CRLs of the enabled X.509 CAs. A read of
    /// what is already stored; it signs nothing. A failure to read leaves the field null.
    /// </summary>
    /// <param name="status">The status to complete.</param>
    /// <param name="mode">The mode the instance is in.</param>
    private async Task<InstanceModeStatus> WithCrlExpiryAsync(InstanceModeStatus status, InstanceMode mode)
    {
        // Only DR mode signs no new CRL; in every other mode the CRLs are replaced on schedule.
        if (db == null || InstanceModeGate.Allows(mode, ModeOperation.Fact))
            return status;
        try
        {
            status.CrlsExpireFromUtc = await ModularCA.Core.Services.CrlDeadline.EarliestNextUpdateAsync(db, HttpContext?.RequestAborted ?? default);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            status.CrlsExpireFromUtc = null;
        }
        return status;
    }

    /// <summary>
    /// Sets the mode. 400 when the mode is not <c>full</c>, <c>restricted</c> or <c>dr</c> or no
    /// reason is given; 409 during the setup wizard, when there is no instance to set a mode on.
    /// </summary>
    /// <param name="request">The mode and the reason.</param>
    [HttpPut]
    [Authorize(Policy = "SystemAdmin")]
    [RequireStepUp(StepUpOps.SetInstanceMode)]
    [ModeGate(ModeOperation.Manage)]
    [ProducesResponseType(typeof(InstanceModeStatus), 200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(409)]
    public async Task<IActionResult> Set([FromBody] SetInstanceModeRequest request)
    {
        if (store == null)
            return Conflict(new { error = "The mode cannot be set while the instance is being set up." });
        if (!InstanceModeGate.TryParse(request?.Mode, out var mode))
            return BadRequest(new { error = $"'{request?.Mode}' is not a mode. Use {InstanceModeGate.NamesForMessages}." });
        var reason = request!.Reason?.Trim() ?? string.Empty;
        if (reason.Length == 0)
            return BadRequest(new { error = "Give a reason; it is recorded with the change." });
        if (reason.Length > MaxReasonLength)
            return BadRequest(new { error = $"The reason is limited to {MaxReasonLength} characters." });

        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();

        var before = gate.Current;
        // Audit first: with a fail-closed audit trail an unrecorded change must not happen.
        await audit.LogAsync(
            AuditActionType.InstanceModeChanged, currentUser.User.Id, currentUser.User.Username,
            "InstanceMode", InstanceModeGate.NameOf(mode),
            new
            {
                From = InstanceModeGate.NameOf(before.Mode),
                To = InstanceModeGate.NameOf(mode),
                Reason = reason,
                SetBy = InstanceModeStore.SourceName(InstanceModeSource.Administrator),
                PreviousSource = InstanceModeStore.SourceName(before.Source),
                PreviousSetBy = before.SetBy,
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        var record = store.Set(mode, InstanceModeSource.Administrator, currentUser.User.Username, reason);
        return Ok(await WithCrlExpiryAsync(Describe(record, store), record.Mode));
    }

    /// <summary>The console's view of a mode record.</summary>
    /// <param name="record">The record.</param>
    /// <param name="store">The store, or null during setup.</param>
    internal static InstanceModeStatus Describe(InstanceModeRecord record, InstanceModeStore? store) => new()
    {
        Mode = InstanceModeGate.NameOf(record.Mode),
        Source = InstanceModeStore.SourceName(record.Source),
        SetBy = record.SetBy,
        Reason = record.Reason,
        SetAtUtc = record.SetAtUtc,
        HubConnection = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(InstanceModeStore.HubSocketVariable)),
        StillWorks = InstanceModeGate.WhatStillWorks(record.Mode),
    };
}
