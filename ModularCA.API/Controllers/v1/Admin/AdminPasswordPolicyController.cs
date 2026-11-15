using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using ModularCA.Auth.Services;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for configuring password complexity and expiration policies. Reading and
/// writing need a system administrator, and a write a step-up token: the policy decides how weak
/// a password every account may have. The policy applies when a password is set or changed; a
/// stored password is never re-checked at sign-in, so no change here locks an account out.
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
    /// How the stored policy compares with NIST SP 800-63B and what the bundled blocklist holds:
    /// <c>nist80063B</c> carries the preset's id and name, <c>meets</c>, and one sentence per
    /// difference (<see cref="PasswordPolicyPresets.DifferencesFromNist80063B"/>);
    /// <c>bundledBlocklist</c> says whether the shipped list was found, how many entries it has,
    /// and its file name. Read-only: the console uses it to offer the preset, never to apply it.
    /// 404 when no policy is configured.
    /// </summary>
    [HttpGet("guidance")]
    public async Task<IActionResult> Guidance()
    {
        var policy = await db.PasswordPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy == null)
            return NotFound(new { error = "No password policy configured" });
        var differences = PasswordPolicyPresets.DifferencesFromNist80063B(policy);
        var bundled = BundledPasswordBlocklist.Current;
        return Ok(new
        {
            nist80063B = new
            {
                preset = PasswordPolicyPresets.Nist80063B,
                name = PasswordPolicyPresets.Nist80063BName,
                meets = differences.Count == 0,
                differences,
            },
            bundledBlocklist = new
            {
                available = bundled.Available,
                entries = bundled.Count,
                fileName = $"{BundledPasswordBlocklist.DirectoryName}/{BundledPasswordBlocklist.FileName}",
                inUse = policy.UseBundledBlocklist,
            },
        });
    }

    /// <summary>
    /// Applies a named preset to the password policy in one action. One preset exists,
    /// <c>nist-sp-800-63b</c> (<see cref="PasswordPolicyPresets.ApplyNist80063B"/>): minimum length
    /// 15, no required character class or count, no expiry, the bundled blocklist on; a maximum
    /// length under 64 becomes 128; history and the administrator's own blocklist are kept.
    /// Every setting stays editable afterwards through <see cref="Update"/>. Requires step-up MFA
    /// (<see cref="StepUpOps.UpdateConfig"/>). 404 for an unknown preset. Passwords already
    /// stored keep working: the policy is applied when a password is next set or changed.
    /// </summary>
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Frozen)]
    [HttpPost("presets/{preset}")]
    [RequireStepUp(StepUpOps.UpdateConfig)]
    public async Task<IActionResult> ApplyPreset(string preset)
    {
        if (!string.Equals(preset, PasswordPolicyPresets.Nist80063B, StringComparison.OrdinalIgnoreCase))
            return NotFound(new { error = $"No such password policy preset. Known presets: {PasswordPolicyPresets.Nist80063B}." });

        var policy = await db.PasswordPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new PasswordPolicyEntity();
            db.PasswordPolicies.Add(policy);
        }
        PasswordPolicyPresets.ApplyNist80063B(policy);
        policy.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        await currentUser.EnsureLoadedAsync();
        await audit.LogAsync(AuditActionType.PasswordPolicyUpdated, currentUser.User?.Id, currentUser.User?.Username,
            "PasswordPolicy", null,
            new
            {
                Preset = PasswordPolicyPresets.Nist80063B,
                policy.MinLength, policy.MaxLength, policy.RequireUppercase, policy.RequireLowercase, policy.RequireDigit,
                policy.RequireSymbol, policy.MinUppercase, policy.MinLowercase, policy.MinDigits, policy.MinSpecial,
                policy.MaxAgeDays, policy.UseBundledBlocklist,
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(policy);
    }

    /// <summary>
    /// Applies a partial update to the password policy; null fields are left untouched. Requires
    /// step-up MFA (<see cref="StepUpOps.UpdateConfig"/>). The resulting policy must pass
    /// <see cref="PasswordPolicyBounds.Problem"/> (400 otherwise, nothing saved). A dictionary
    /// names a file in <see cref="PasswordPolicyBounds.DictionaryDirectory"/> by its file name;
    /// an empty string clears it, and the stored value sent back unchanged keeps it.
    /// <c>UseBundledBlocklist</c> turns the check against the shipped blocklist on or off; the
    /// dictionary, when set, is checked as well either way.
    /// </summary>
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Frozen)]
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
        policy.UseBundledBlocklist = request.UseBundledBlocklist ?? policy.UseBundledBlocklist;
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
    /// <summary>The shortest minimum length accepted (what NIST SP 800-63B allows beside a second factor); a new install's default is 15.</summary>
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
    /// <summary>Shortest password allowed, in characters; at least <see cref="PasswordPolicyBounds.MinLengthFloor"/>.</summary>
    public int? MinLength { get; set; }
    /// <summary>Longest password allowed, in characters; 0 means no cap. Must not be below <see cref="MinLength"/> or the character-class minimums together.</summary>
    public int? MaxLength { get; set; }
    /// <summary>Whether a password needs at least one upper-case letter.</summary>
    public bool? RequireUppercase { get; set; }
    /// <summary>Whether a password needs at least one lower-case letter.</summary>
    public bool? RequireLowercase { get; set; }
    /// <summary>Whether a password needs at least one digit.</summary>
    public bool? RequireDigit { get; set; }
    /// <summary>Whether a password needs at least one character that is neither a letter nor a digit.</summary>
    public bool? RequireSymbol { get; set; }
    /// <summary>Least number of upper-case letters; 0 sets no count.</summary>
    public int? MinUppercase { get; set; }
    /// <summary>Least number of lower-case letters; 0 sets no count.</summary>
    public int? MinLowercase { get; set; }
    /// <summary>Least number of digits; 0 sets no count.</summary>
    public int? MinDigits { get; set; }
    /// <summary>Least number of characters that are neither letters nor digits; 0 sets no count.</summary>
    public int? MinSpecial { get; set; }
    /// <summary>
    /// Days after a password change before the password expires; 0 means passwords never expire:
    /// no account is then treated as expired, whatever date an earlier policy stamped on it.
    /// </summary>
    public int? MaxAgeDays { get; set; }
    /// <summary>How many prior passwords a new one may not repeat, at most <see cref="PasswordPolicyBounds.MaxHistoryCount"/>; 0 keeps no history.</summary>
    public int? HistoryCount { get; set; }

    /// <summary>
    /// Whether a new password is checked against the blocklist shipped with the product
    /// (<c>password-blocklist/bundled-blocklist.txt</c> beside the binaries).
    /// </summary>
    public bool? UseBundledBlocklist { get; set; }

    /// <summary>
    /// The file name of a dictionary in <see cref="PasswordPolicyBounds.DictionaryDirectory"/>;
    /// empty clears it. A path is refused. The administrator's own list: checked in addition to
    /// the bundled blocklist, not instead of it.
    /// </summary>
    public string? DictionaryPath { get; set; }
    /// <summary>Whether the dictionary lists hex SHA-256 hashes (UTF-8, either case) of passwords rather than the passwords themselves.</summary>
    public bool? DictionaryIsHashed { get; set; }
}
