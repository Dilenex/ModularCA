using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for configuring password complexity and expiration policies. Reading and
/// writing need a system administrator, and a write a step-up token: the policy decides how weak
/// a password every account may have.
/// </summary>
[ApiController]
[Route("api/v1/admin/password-policy")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminPasswordPolicyController(
    ModularCADbContext db,
    IAuditService audit,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>Returns the stored password policy, or 404 when none is configured.</summary>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var policy = await db.PasswordPolicies.FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No password policy configured" });
        return Ok(policy);
    }

    /// <summary>
    /// Applies a partial update to the password policy; null fields are left untouched. Requires
    /// step-up MFA (<see cref="StepUpOps.UpdateConfig"/>). The resulting policy must pass
    /// <see cref="PasswordPolicyBounds.Problem"/> (400 otherwise, nothing saved). A dictionary
    /// names a file in <see cref="PasswordPolicyBounds.DictionaryDirectory"/> by its file name;
    /// an empty string clears it, and the stored value sent back unchanged keeps it.
    /// </summary>
    [HttpPut]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> Update([FromBody] PasswordPolicyUpdateRequest request)
    {
        var policy = await db.PasswordPolicies.FirstOrDefaultAsync();
        var isNew = policy == null;
        policy ??= new PasswordPolicyEntity();

        string? dictionaryPath = policy.DictionaryPath;
        if (request.DictionaryPath != null && request.DictionaryPath != policy.DictionaryPath)
        {
            if (request.DictionaryPath.Length == 0)
                dictionaryPath = null;
            else if (PasswordPolicyBounds.ResolveDictionary(request.DictionaryPath) is { } resolved)
                dictionaryPath = resolved;
            else
                return BadRequest(new { error = $"DictionaryPath must be the name of a file in {PasswordPolicyBounds.DictionaryDirectory}." });
        }

        var proposed = new PasswordPolicyEntity
        {
            MinLength = request.MinLength ?? policy.MinLength,
            MaxLength = request.MaxLength ?? policy.MaxLength,
            MinUppercase = request.MinUppercase ?? policy.MinUppercase,
            MinLowercase = request.MinLowercase ?? policy.MinLowercase,
            MinDigits = request.MinDigits ?? policy.MinDigits,
            MinSpecial = request.MinSpecial ?? policy.MinSpecial,
            MaxAgeDays = request.MaxAgeDays ?? policy.MaxAgeDays,
            HistoryCount = request.HistoryCount ?? policy.HistoryCount,
        };
        if (PasswordPolicyBounds.Problem(proposed) is { } problem)
            return BadRequest(new { error = problem });

        if (isNew)
            db.PasswordPolicies.Add(policy);
        policy.MinLength = proposed.MinLength;
        policy.MaxLength = proposed.MaxLength;
        policy.RequireUppercase = request.RequireUppercase ?? policy.RequireUppercase;
        policy.RequireLowercase = request.RequireLowercase ?? policy.RequireLowercase;
        policy.RequireDigit = request.RequireDigit ?? policy.RequireDigit;
        policy.RequireSymbol = request.RequireSymbol ?? policy.RequireSymbol;
        policy.MinUppercase = proposed.MinUppercase;
        policy.MinLowercase = proposed.MinLowercase;
        policy.MinDigits = proposed.MinDigits;
        policy.MinSpecial = proposed.MinSpecial;
        policy.MaxAgeDays = proposed.MaxAgeDays;
        policy.HistoryCount = proposed.HistoryCount;
        policy.DictionaryPath = dictionaryPath;
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

/// <summary>The limits a password policy written through the admin API must stay within.</summary>
public static class PasswordPolicyBounds
{
    /// <summary>The shortest minimum length accepted (NIST SP 800-63B §5.1.1.2); the default is 12.</summary>
    public const int MinLengthFloor = 8;

    /// <summary>The most prior passwords a policy may remember; each one is a hash verification on every change.</summary>
    public const int MaxHistoryCount = 24;

    /// <summary>
    /// The only directory a password dictionary may be read from: <c>config/password-dictionaries</c>
    /// under the application directory, beside config.yaml. Any other path would let the API read
    /// an arbitrary server file line by line through password checks.
    /// </summary>
    public static string DictionaryDirectory => Path.Combine(AppContext.BaseDirectory, "config", "password-dictionaries");

    /// <summary>
    /// Why <paramref name="policy"/> is out of bounds, or null when it is not: a minimum length below
    /// <see cref="MinLengthFloor"/>, a negative count, a maximum length (0 = no cap) below the
    /// minimum length or the character-class minimums together, or more than
    /// <see cref="MaxHistoryCount"/> remembered passwords.
    /// </summary>
    public static string? Problem(PasswordPolicyEntity policy)
    {
        if (policy.MinLength < MinLengthFloor)
            return $"MinLength must be at least {MinLengthFloor}.";
        if (policy.MaxLength < 0 || policy.MinUppercase < 0 || policy.MinLowercase < 0 || policy.MinDigits < 0
            || policy.MinSpecial < 0 || policy.MaxAgeDays < 0 || policy.HistoryCount < 0)
            return "MaxLength, the character-class minimums, MaxAgeDays and HistoryCount must not be negative.";
        if (policy.MaxLength > 0 && policy.MinLength > policy.MaxLength)
            return "MinLength must not exceed MaxLength (0 means no maximum).";
        var classMinimums = (long)policy.MinUppercase + policy.MinLowercase + policy.MinDigits + policy.MinSpecial;
        if (policy.MaxLength > 0 && classMinimums > policy.MaxLength)
            return "The character-class minimums together must not exceed MaxLength.";
        if (policy.HistoryCount > MaxHistoryCount)
            return $"HistoryCount must not exceed {MaxHistoryCount}.";
        return null;
    }

    /// <summary>
    /// The full path of dictionary <paramref name="fileName"/> in <see cref="DictionaryDirectory"/>,
    /// or null when it is not a bare file name or no such file exists there.
    /// </summary>
    public static string? ResolveDictionary(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName != Path.GetFileName(fileName)
            || fileName.IndexOfAny(['/', '\\']) >= 0 || fileName is "." or "..")
            return null;
        var directory = Path.GetFullPath(DictionaryDirectory);
        var full = Path.GetFullPath(Path.Combine(directory, fileName));
        if (!string.Equals(Path.GetDirectoryName(full), directory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.Ordinal))
            return null;
        return System.IO.File.Exists(full) ? full : null;
    }
}

/// <summary>Request body for PUT /api/v1/admin/password-policy; null fields are left untouched.</summary>
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

    /// <summary>
    /// The file name of a dictionary in <see cref="PasswordPolicyBounds.DictionaryDirectory"/>;
    /// empty clears it. A path is refused.
    /// </summary>
    public string? DictionaryPath { get; set; }
    public bool? DictionaryIsHashed { get; set; }
}
