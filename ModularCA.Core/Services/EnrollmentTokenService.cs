using ModularCA.Shared.Utils;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Core.Services;

/// <summary>
/// Manages one-time-use enrollment tokens for authenticating certificate enrollment requests.
/// </summary>
public interface IEnrollmentTokenService
{
    /// <summary>
    /// Generates a new enrollment token. <paramref name="tenantId"/> and
    /// <paramref name="certificateAuthorityId"/> stamp the token with its target scope so the
    /// admin list endpoint can filter by tenant without relying on stale creator heuristics.
    /// </summary>
    Task<string> GenerateTokenAsync(Guid userId, TimeSpan expiresIn, int maxUses = 1,
        string? subjectRestriction = null, string? sanRestriction = null, string? protocol = null,
        Guid? requestProfileId = null, Guid? certProfileId = null, Guid? signingProfileId = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null);
    /// <param name="sans">
    /// SAN entries in <c>CertificateUtil.ParseCsr</c>'s <c>TYPE:value</c> form. Optional so
    /// callers that have not parsed them yet keep compiling; when supplied, the token's
    /// SANRestriction is enforced against them.
    /// </param>
    Task<(bool IsValid, string? Error)> ValidateAndConsumeAsync(string token, string? subject, string? protocol, IEnumerable<string>? sans = null);
    /// <summary>
    /// Retrieves a valid (non-revoked, non-expired, uses remaining) enrollment token by its token string.
    /// Returns null if the token is invalid or exhausted.
    /// </summary>
    Task<EnrollmentTokenEntity?> GetByTokenAsync(string token);
    Task<List<EnrollmentTokenEntity>> GetActiveTokensAsync();
    Task<bool> RevokeTokenAsync(Guid id);
    /// <summary>
    /// Retrieves a token by ID for per-call tenant enforcement in the
    /// admin revoke path. Returns null when the id does not exist.
    /// </summary>
    Task<EnrollmentTokenEntity?> GetByIdAsync(Guid id);

    /// <summary>
    /// Provisions a CMP PBMAC shared secret bound to the given
    /// <paramref name="referenceValue"/> (CMP <c>senderKID</c>). Returns the plaintext
    /// secret exactly once — the caller must hand it to the CMP client out of band.
    /// The secret hash is stored in <see cref="EnrollmentTokenEntity.CmpSecretHashBase64"/>
    /// and never returned again.
    /// </summary>
    Task<(EnrollmentTokenEntity Entity, string PlaintextSecret)> GenerateCmpSharedSecretAsync(
        Guid userId, string referenceValue, TimeSpan expiresIn, int maxUses,
        Guid? certificateAuthorityId, Guid? tenantId);

    /// <summary>
    /// Looks up and atomically consumes a CMP PBMAC credential by
    /// <paramref name="referenceValue"/>. Verifies the caller's shared secret against
    /// the stored hash and enforces expiration + uses-remaining. Returns the owning
    /// token entity on success (for audit attribution) or null on failure.
    /// </summary>
    Task<EnrollmentTokenEntity?> ValidateAndConsumeCmpSecretAsync(string referenceValue, byte[] sharedSecret);
}

/// <summary>
/// Database-backed implementation for generating, validating, and revoking enrollment tokens.
/// </summary>
public class EnrollmentTokenService : IEnrollmentTokenService
{
    private readonly ModularCADbContext _db;

    public EnrollmentTokenService(ModularCADbContext db)
    {
        _db = db;
    }

    public async Task<string> GenerateTokenAsync(Guid userId, TimeSpan expiresIn, int maxUses = 1,
        string? subjectRestriction = null, string? sanRestriction = null, string? protocol = null,
        Guid? requestProfileId = null, Guid? certProfileId = null, Guid? signingProfileId = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null)
    {
        var tokenValue = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        var entity = new EnrollmentTokenEntity
        {
            Token = tokenValue,
            CreatedByUserId = userId,
            ExpiresAt = DateTime.UtcNow.Add(expiresIn),
            MaxUses = maxUses,
            UsesRemaining = maxUses,
            SubjectRestriction = subjectRestriction,
            SANRestriction = sanRestriction,
            Protocol = protocol,
            RequestProfileId = requestProfileId,
            CertProfileId = certProfileId,
            SigningProfileId = signingProfileId,
            CertificateAuthorityId = certificateAuthorityId,
            TenantId = tenantId
        };

        _db.EnrollmentTokens.Add(entity);
        await _db.SaveChangesAsync();
        return tokenValue;
    }

    /// <inheritdoc />
    public async Task<EnrollmentTokenEntity?> GetByIdAsync(Guid id)
    {
        return await _db.EnrollmentTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
    }

    /// <summary>
    /// Retrieves a valid enrollment token entity by its token string without consuming a use.
    /// </summary>
    public async Task<EnrollmentTokenEntity?> GetByTokenAsync(string token)
    {
        var entity = await _db.EnrollmentTokens
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsRevoked);

        if (entity == null) return null;
        if (entity.ExpiresAt < DateTime.UtcNow) return null;
        if (entity.MaxUses > 0 && entity.UsesRemaining <= 0) return null;

        return entity;
    }

    public async Task<(bool IsValid, string? Error)> ValidateAndConsumeAsync(string token, string? subject, string? protocol, IEnumerable<string>? sans = null)
    {
        var entity = await _db.EnrollmentTokens
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsRevoked);

        if (entity == null)
            return (false, "Invalid enrollment token");

        if (entity.ExpiresAt < DateTime.UtcNow)
            return (false, "Enrollment token has expired");

        if (entity.MaxUses > 0 && entity.UsesRemaining <= 0)
            return (false, "Enrollment token has been used the maximum number of times");

        // Protocol restriction
        if (!string.IsNullOrWhiteSpace(entity.Protocol) &&
            !string.Equals(entity.Protocol, protocol, StringComparison.OrdinalIgnoreCase))
            return (false, $"Enrollment token is restricted to protocol '{entity.Protocol}'");

        // Name restrictions, through the shared resolver. This was a raw substring test against
        // the whole DN that also skipped itself when the subject was empty — the same pair of
        // holes fixed on the public QR path, still live here. It matters more here: this method
        // is what the SCEP challenge-password path (EnrollmentAuthorizationService) relies on,
        // where it is the ONLY name check.
        if (!EnrollmentNameRestriction.SubjectSatisfies(subject, entity.SubjectRestriction, out var subjectFailure))
            return (false, subjectFailure);

        if (sans != null &&
            !EnrollmentNameRestriction.SansSatisfy(sans, entity.SANRestriction, out var sanFailure))
            return (false, sanFailure);

        // Consume a use LAST, atomically, and only if every other check passed.
        if (!await TryConsumeUseAsync(_db, entity))
            return (false, "Enrollment token has been used the maximum number of times");

        return (true, null);
    }

    /// <summary>
    /// Consumes one use of an enrollment token, atomically. Returns false when the token was
    /// already exhausted — including when a concurrent request took the last use.
    /// <para>
    /// The three call sites that decrement a token used to read <c>UsesRemaining</c>, compare it,
    /// decrement in memory and save — one of them under a comment reading "Atomically decrement
    /// remaining uses". Two concurrent enrollments presenting the same single-use token both read
    /// 1, both pass the check, both write 0, and both get a certificate. On an anonymous
    /// enrollment endpoint that is a duplicate-issuance vector, and the window is exactly the
    /// round trip between the read and the write.
    /// </para>
    /// <para>
    /// This is a single <c>UPDATE ... WHERE UsesRemaining &gt; 0</c>; the database decides the
    /// winner and rows-affected reports it. No <c>RowVersion</c> column and no retry loop: there
    /// is nothing to retry, since losing the race means the token is genuinely spent.
    /// </para>
    /// </summary>
    /// <param name="db">Context to issue the update on.</param>
    /// <param name="token">
    /// The token being consumed. Its <c>MaxUses</c> is read locally — that value never changes
    /// for a token's lifetime, so it is not part of the race.
    /// </param>
    public static async Task<bool> TryConsumeUseAsync(ModularCADbContext db, EnrollmentTokenEntity token)
    {
        // MaxUses <= 0 means unlimited: nothing to consume, nothing to race on.
        if (token.MaxUses <= 0)
            return true;

        var affected = await db.EnrollmentTokens
            .Where(t => t.Id == token.Id && t.UsesRemaining > 0)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.UsesRemaining, t => t.UsesRemaining - 1));

        // The tracked copy is deliberately NOT updated. ExecuteUpdateAsync bypasses the change
        // tracker, so writing to the entity here would make a later SaveChanges re-issue a stale
        // absolute value and undo the atomicity this method exists to provide.
        return affected == 1;
    }

    public async Task<List<EnrollmentTokenEntity>> GetActiveTokensAsync()
    {
        return await _db.EnrollmentTokens
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow &&
                        (t.MaxUses == 0 || t.UsesRemaining > 0))
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync();
    }

    public async Task<bool> RevokeTokenAsync(Guid id)
    {
        var entity = await _db.EnrollmentTokens.FindAsync(id);
        if (entity == null) return false;
        entity.IsRevoked = true;
        await _db.SaveChangesAsync();
        return true;
    }

    // PBKDF2-SHA256 secret hashing mirroring the password-hash format string
    // (versioned so future iteration-count bumps can be
    // rolled forward without a DB migration).
    private const int Pbkdf2Iterations = 100_000;
    private const int Pbkdf2SaltLen = 16;
    private const int Pbkdf2HashLen = 32;
    private const string Pbkdf2Prefix = "pbkdf2-sha256-v1";

    /// <inheritdoc />
    public async Task<(EnrollmentTokenEntity Entity, string PlaintextSecret)> GenerateCmpSharedSecretAsync(
        Guid userId, string referenceValue, TimeSpan expiresIn, int maxUses,
        Guid? certificateAuthorityId, Guid? tenantId)
    {
        if (string.IsNullOrWhiteSpace(referenceValue))
            throw new ArgumentException("CMP reference value must be non-empty", nameof(referenceValue));
        referenceValue = referenceValue.Trim();

        var existing = await _db.EnrollmentTokens
            .AnyAsync(t => t.CmpReferenceValue == referenceValue && t.UsedForCmp && !t.IsRevoked);
        if (existing)
            throw new InvalidOperationException(
                $"A CMP PBMAC credential already exists for referenceValue '{referenceValue}'. Revoke it before issuing a new one.");

        var secretBytes = RandomNumberGenerator.GetBytes(32);
        var plaintext = Convert.ToBase64String(secretBytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        var salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltLen);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(plaintext), salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, Pbkdf2HashLen);

        // Also use the plaintext bytes as the "Token" column (required/unique) so existing
        // token-style admin list endpoints don't need to special-case CMP rows.
        var entity = new EnrollmentTokenEntity
        {
            Token = plaintext,
            CreatedByUserId = userId,
            ExpiresAt = DateTime.UtcNow.Add(expiresIn),
            MaxUses = maxUses,
            UsesRemaining = maxUses,
            Protocol = "CMP",
            CertificateAuthorityId = certificateAuthorityId,
            TenantId = tenantId,
            UsedForCmp = true,
            CmpReferenceValue = referenceValue,
            CmpSecretHashBase64 =
                $"{Pbkdf2Prefix}${Pbkdf2Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}"
        };

        _db.EnrollmentTokens.Add(entity);
        await _db.SaveChangesAsync();

        // Zero the raw byte buffer now that we've base64-encoded the plaintext into a string.
        CryptographicOperations.ZeroMemory(secretBytes);

        return (entity, plaintext);
    }

    /// <inheritdoc />
    public async Task<EnrollmentTokenEntity?> ValidateAndConsumeCmpSecretAsync(string referenceValue, byte[] sharedSecret)
    {
        if (string.IsNullOrWhiteSpace(referenceValue) || sharedSecret == null)
            return null;

        var entity = await _db.EnrollmentTokens
            .FirstOrDefaultAsync(t =>
                t.CmpReferenceValue == referenceValue &&
                t.UsedForCmp &&
                !t.IsRevoked);
        if (entity == null) return null;
        if (entity.ExpiresAt < DateTime.UtcNow) return null;
        if (entity.MaxUses > 0 && entity.UsesRemaining <= 0) return null;
        if (string.IsNullOrEmpty(entity.CmpSecretHashBase64)) return null;

        // Parse stored hash: pbkdf2-sha256-v1$iter$salt$hash
        var parts = entity.CmpSecretHashBase64.Split('$');
        if (parts.Length != 4 || parts[0] != Pbkdf2Prefix) return null;
        if (!int.TryParse(parts[1], out var iter)) return null;

        byte[] salt, storedHash;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            storedHash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException) { return null; }

        var computed = Rfc2898DeriveBytes.Pbkdf2(sharedSecret, salt, iter, HashAlgorithmName.SHA256, storedHash.Length);
        var matches = CryptographicOperations.FixedTimeEquals(computed, storedHash);
        CryptographicOperations.ZeroMemory(computed);
        if (!matches) return null;

        // Consume atomically. The comment here used to promise this while the code below it did
        // a read-modify-write, which is the shape that let two concurrent CMP requests spend the
        // same single-use shared secret.
        if (!await TryConsumeUseAsync(_db, entity))
            return null;
        return entity;
    }
}
