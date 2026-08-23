using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Utils;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Auth.Services;

/// <summary>
/// Validates passwords against the configured password policy (length, complexity, dictionary check)
/// and enforces the SP 800-63B §5.1.1.2 "no reuse of prior N passwords" rule via
/// <see cref="PasswordHistoryEntity"/>.
/// </summary>
public interface IPasswordPolicyService
{
    /// <summary>Returns the active password policy from the database.</summary>
    Task<PasswordPolicyEntity> GetPolicyAsync();

    /// <summary>
    /// Validates a password against the active policy's length/complexity/dictionary rules.
    /// Does NOT perform a history-reuse check — use the <see cref="ValidateAsync(Guid, string)"/>
    /// overload for password-change flows where reuse detection is required.
    /// </summary>
    Task<(bool IsValid, List<string> Errors)> ValidateAsync(string password);

    /// <summary>
    /// Validates a password against the active policy AND, when <c>HistoryCount &gt; 0</c>,
    /// rejects it if it matches any of the user's most recent <c>HistoryCount</c> prior
    /// passwords.
    /// </summary>
    Task<(bool IsValid, List<string> Errors)> ValidateAsync(Guid userId, string password);

    /// <summary>
    /// Records a new password hash in the user's <see cref="PasswordHistoryEntity"/> history
    /// and prunes any rows beyond the policy's <c>HistoryCount</c> so the table cannot grow
    /// unbounded. Must be called on every successful password change BEFORE the final
    /// <c>SaveChangesAsync</c>. When <c>HistoryCount &lt;= 0</c> the method is a no-op —
    /// the deployment has opted out of reuse tracking.
    /// </summary>
    Task RecordPasswordHistoryAsync(Guid userId, string newPasswordHash);
}

/// <summary>
/// EF Core implementation of <see cref="IPasswordPolicyService"/>. Loads the password policy from the database
/// and validates passwords against length, complexity, optional dictionary/breach list checks, and the
/// </summary>
public class PasswordPolicyService : IPasswordPolicyService
{
    private readonly ModularCADbContext _db;

    /// <summary>Initializes a new <see cref="PasswordPolicyService"/> bound to the shared DbContext.</summary>
    public PasswordPolicyService(ModularCADbContext db)
    {
        _db = db;
    }

    /// <inheritdoc />
    public async Task<PasswordPolicyEntity> GetPolicyAsync()
    {
        return await _db.PasswordPolicies.FirstOrDefaultAsync()
            ?? new PasswordPolicyEntity();
    }

    /// <inheritdoc />
    public async Task<(bool IsValid, List<string> Errors)> ValidateAsync(string password)
    {
        var policy = await GetPolicyAsync();
        var errors = Validate(password, policy);
        return (errors.Count == 0, errors);
    }

    /// <inheritdoc />
    public async Task<(bool IsValid, List<string> Errors)> ValidateAsync(Guid userId, string password)
    {
        var policy = await GetPolicyAsync();
        var errors = Validate(password, policy);

        // When HistoryCount <= 0 the deployment has opted out — preserve pre-existing
        // behavior for installs that haven't tuned the policy.
        if (policy.HistoryCount > 0)
        {
            var recent = await _db.PasswordHistory
                .Where(h => h.UserId == userId)
                .OrderByDescending(h => h.ChangedAt)
                .Take(policy.HistoryCount)
                .Select(h => h.PasswordHash)
                .ToListAsync();

            // Also include the user's CURRENT hash so rotating to the same password is rejected
            // even before the first history row has been written. Defensive: the first
            // RecordPasswordHistoryAsync call populates history, but this guard protects
            // installs that enabled HistoryCount after users were already provisioned.
            var currentHash = await _db.Users
                .Where(u => u.Id == userId)
                .Select(u => u.PasswordHash)
                .FirstOrDefaultAsync();
            if (!string.IsNullOrEmpty(currentHash))
            {
                recent.Add(currentHash);
            }

            foreach (var storedHash in recent)
            {
                if (string.IsNullOrEmpty(storedHash)) continue;
                if (PasswordUtil.VerifyPassword(password, storedHash))
                {
                    errors.Add($"Cannot reuse any of the last {policy.HistoryCount} passwords");
                    break;
                }
            }
        }

        return (errors.Count == 0, errors);
    }

    /// <inheritdoc />
    public async Task RecordPasswordHistoryAsync(Guid userId, string newPasswordHash)
    {
        if (string.IsNullOrEmpty(newPasswordHash))
            return;

        var policy = await GetPolicyAsync();
        if (policy.HistoryCount <= 0)
            return;

        _db.PasswordHistory.Add(new PasswordHistoryEntity
        {
            UserId = userId,
            PasswordHash = newPasswordHash,
            ChangedAt = DateTime.UtcNow,
        });

        // Prune rows beyond HistoryCount so the table never grows unbounded. We keep
        // HistoryCount - 1 existing rows because the insert above is the Nth. The new
        // row has not been persisted yet, but EF tracks it as Added so OrderByDescending
        // over the already-persisted rows is correct.
        var keep = Math.Max(0, policy.HistoryCount - 1);
        var oldIds = await _db.PasswordHistory
            .Where(h => h.UserId == userId)
            .OrderByDescending(h => h.ChangedAt)
            .Skip(keep)
            .Select(h => h.Id)
            .ToListAsync();

        if (oldIds.Count > 0)
        {
            await _db.PasswordHistory
                .Where(h => oldIds.Contains(h.Id))
                .ExecuteDeleteAsync();
        }
    }

    /// <summary>
    /// Validates a password against a policy's length, complexity and dictionary rules and
    /// returns one message per violation. Empty means the password is acceptable.
    /// <para>
    /// Public and static because it is the ONLY implementation of these rules. A second one used
    /// to live in <c>BootstrapProfileSeeder.MeetsPolicy</c>, and the drift showed: the bootstrap
    /// wizard's admin password — for the most privileged account in the install — was validated
    /// by neither, because the wizard path called into the copy that its caller never invoked.
    /// </para>
    /// <para>
    /// Takes the policy as a parameter rather than reading the database, so callers that run
    /// before the database exists (the setup wizard) can validate against
    /// <c>new PasswordPolicyEntity()</c> defaults.
    /// </para>
    /// </summary>
    public static List<string> Validate(string password, PasswordPolicyEntity policy)
    {
        var errors = new List<string>();

        if (password.Length < policy.MinLength)
            errors.Add($"Password must be at least {policy.MinLength} characters");

        if (policy.MaxLength > 0 && password.Length > policy.MaxLength)
            errors.Add($"Password must not exceed {policy.MaxLength} characters");

        if (policy.RequireUppercase && !password.Any(char.IsUpper))
            errors.Add("Password must contain at least one uppercase letter");

        if (policy.RequireLowercase && !password.Any(char.IsLower))
            errors.Add("Password must contain at least one lowercase letter");

        if (policy.RequireDigit && !password.Any(char.IsDigit))
            errors.Add("Password must contain at least one digit");

        if (policy.RequireSymbol && password.All(c => char.IsLetterOrDigit(c)))
            errors.Add("Password must contain at least one symbol");

        // Minimum character count enforcement
        var upperCount = password.Count(char.IsUpper);
        var lowerCount = password.Count(char.IsLower);
        var digitCount = password.Count(char.IsDigit);
        var specialCount = password.Count(c => !char.IsLetterOrDigit(c));

        if (policy.MinUppercase > 0 && upperCount < policy.MinUppercase)
            errors.Add($"Password must contain at least {policy.MinUppercase} uppercase letter(s) (found {upperCount})");

        if (policy.MinLowercase > 0 && lowerCount < policy.MinLowercase)
            errors.Add($"Password must contain at least {policy.MinLowercase} lowercase letter(s) (found {lowerCount})");

        if (policy.MinDigits > 0 && digitCount < policy.MinDigits)
            errors.Add($"Password must contain at least {policy.MinDigits} digit(s) (found {digitCount})");

        if (policy.MinSpecial > 0 && specialCount < policy.MinSpecial)
            errors.Add($"Password must contain at least {policy.MinSpecial} special character(s) (found {specialCount})");

        // Dictionary check
        if (!string.IsNullOrWhiteSpace(policy.DictionaryPath) && File.Exists(policy.DictionaryPath))
        {
            if (IsInDictionary(password, policy.DictionaryPath, policy.DictionaryIsHashed))
                errors.Add("Password matches a known weak or compromised password");
        }

        return errors;
    }

    private static bool IsInDictionary(string password, string dictionaryPath, bool isHashed)
    {
        string searchValue;
        if (isHashed)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            searchValue = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
        else
        {
            searchValue = password;
        }

        using var reader = new StreamReader(dictionaryPath);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;

            if (isHashed)
            {
                if (string.Equals(trimmed, searchValue, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else
            {
                if (string.Equals(trimmed, searchValue, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }
}
