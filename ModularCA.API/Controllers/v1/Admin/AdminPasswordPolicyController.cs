using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for configuring password complexity and expiration policies.
/// </summary>
[ApiController]
[Route("api/v1/admin/password-policy")]
[Authorize(Policy = "SystemOperator")]
[NodeRole(ProcessRole.Control)]
public class AdminPasswordPolicyController(
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.PasswordPolicies.FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No password policy configured" });
        return Ok(policy);
    }

    [HttpPut]
    public async Task<IActionResult> Update([FromBody] PasswordPolicyUpdateRequest request)
    {
        var policy = await db.PasswordPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new PasswordPolicyEntity();
            db.PasswordPolicies.Add(policy);
        }

        policy.MinLength = request.MinLength ?? policy.MinLength;
        policy.MaxLength = request.MaxLength ?? policy.MaxLength;
        policy.RequireUppercase = request.RequireUppercase ?? policy.RequireUppercase;
        policy.RequireLowercase = request.RequireLowercase ?? policy.RequireLowercase;
        policy.RequireDigit = request.RequireDigit ?? policy.RequireDigit;
        policy.RequireSymbol = request.RequireSymbol ?? policy.RequireSymbol;
        policy.MinUppercase = request.MinUppercase ?? policy.MinUppercase;
        policy.MinLowercase = request.MinLowercase ?? policy.MinLowercase;
        policy.MinDigits = request.MinDigits ?? policy.MinDigits;
        policy.MinSpecial = request.MinSpecial ?? policy.MinSpecial;
        policy.MaxAgeDays = request.MaxAgeDays ?? policy.MaxAgeDays;
        policy.HistoryCount = request.HistoryCount ?? policy.HistoryCount;
        policy.DictionaryPath = request.DictionaryPath ?? policy.DictionaryPath;
        policy.DictionaryIsHashed = request.DictionaryIsHashed ?? policy.DictionaryIsHashed;
        policy.UpdatedAt = DateTime.UtcNow;

        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.PasswordPolicyUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "PasswordPolicy", null, request,
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(policy);
    }
}

public class PasswordPolicyUpdateRequest
{
    public int? MinLength { get; set; }
    public int? MaxLength { get; set; }
    public bool? RequireUppercase { get; set; }
    public bool? RequireLowercase { get; set; }
    public bool? RequireDigit { get; set; }
    public bool? RequireSymbol { get; set; }
    public int? MinUppercase { get; set; }
    public int? MinLowercase { get; set; }
    public int? MinDigits { get; set; }
    public int? MinSpecial { get; set; }
    public int? MaxAgeDays { get; set; }
    public int? HistoryCount { get; set; }
    public string? DictionaryPath { get; set; }
    public bool? DictionaryIsHashed { get; set; }
}
