using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Database-backed ACME authorization management for domain validation workflows.
/// </summary>
public class AcmeAuthorizationService(ModularCADbContext db) : IAcmeAuthorizationService
{
    private readonly ModularCADbContext _db = db;

    public async Task<AcmeAuthorizationDto?> GetByIdAsync(Guid authzId, string baseUrl)
    {
        var entity = await _db.AcmeAuthorizations.FindAsync(authzId);
        if (entity == null) return null;

        var challenges = await _db.AcmeChallenges
            .Where(c => c.AuthorizationId == authzId)
            .ToListAsync();

        return MapToDto(entity, challenges, baseUrl);
    }

    public async Task<List<AcmeAuthorizationDto>> GetByOrderIdAsync(Guid orderId, string baseUrl)
    {
        var authzs = await _db.AcmeAuthorizations
            .Where(a => a.OrderId == orderId)
            .ToListAsync();

        var authzIds = authzs.Select(a => a.Id).ToList();
        var challenges = await _db.AcmeChallenges
            .Where(c => authzIds.Contains(c.AuthorizationId))
            .ToListAsync();

        return authzs.Select(a => MapToDto(a, challenges.Where(c => c.AuthorizationId == a.Id).ToList(), baseUrl)).ToList();
    }

    public async Task DeactivateAsync(Guid authzId)
    {
        var entity = await _db.AcmeAuthorizations.FindAsync(authzId)
            ?? throw new InvalidOperationException("Authorization not found.");

        entity.Status = nameof(AcmeAuthorizationStatus.Deactivated);

        var challenges = await _db.AcmeChallenges
            .Where(c => c.AuthorizationId == authzId)
            .ToListAsync();

        foreach (var challenge in challenges)
        {
            if (challenge.Status == nameof(AcmeChallengeStatus.Pending) ||
                challenge.Status == nameof(AcmeChallengeStatus.Processing))
            {
                challenge.Status = nameof(AcmeChallengeStatus.Invalid);
            }
        }

        await _db.SaveChangesAsync();
    }

    public async Task EvaluateAsync(Guid authzId)
    {
        var entity = await _db.AcmeAuthorizations.FindAsync(authzId)
            ?? throw new InvalidOperationException("Authorization not found.");

        if (entity.Status != nameof(AcmeAuthorizationStatus.Pending))
            return;

        var challenges = await _db.AcmeChallenges
            .Where(c => c.AuthorizationId == authzId)
            .ToListAsync();

        var anyValid = challenges.Any(c => c.Status == nameof(AcmeChallengeStatus.Valid));
        var allInvalid = challenges.All(c => c.Status == nameof(AcmeChallengeStatus.Invalid));

        if (anyValid)
        {
            entity.Status = nameof(AcmeAuthorizationStatus.Valid);
            await _db.SaveChangesAsync();

            // Check if the parent order is now ready
            await EvaluateParentOrderAsync(entity.OrderId);
        }
        else if (allInvalid)
        {
            entity.Status = nameof(AcmeAuthorizationStatus.Invalid);
            await _db.SaveChangesAsync();

            // Invalidate the parent order
            var order = await _db.AcmeOrders.FindAsync(entity.OrderId);
            if (order != null && order.Status == nameof(AcmeOrderStatus.Pending))
            {
                order.Status = nameof(AcmeOrderStatus.Invalid);
                await _db.SaveChangesAsync();
            }
        }
    }

    /// <summary>
    /// Retrieves the account ID that owns the order containing this authorization.
    /// </summary>
    public async Task<Guid?> GetAccountIdForAuthorizationAsync(Guid authzId)
    {
        var authz = await _db.AcmeAuthorizations
            .Include(a => a.Order)
            .FirstOrDefaultAsync(a => a.Id == authzId);
        return authz?.Order?.AccountId;
    }

    /// <summary>
    /// Creates an ACME authorization entity for the given identifier.
    /// For wildcard identifiers (e.g. *.example.com), the authorization stores
    /// the base domain (example.com) with <see cref="AcmeAuthorizationEntity.IsWildcard"/> set
    /// to true, per RFC 8555 section 7.1.4.
    /// </summary>
    internal static AcmeAuthorizationEntity CreateAuthorizationWithChallenges(Guid orderId, AcmeIdentifier identifier)
    {
        var isWildcard = identifier.Value.StartsWith("*.");
        // Per RFC 8555 §7.1.4, the authorization identifier is the base domain without the wildcard prefix
        var baseDomain = isWildcard ? identifier.Value[2..] : identifier.Value;

        var authz = new AcmeAuthorizationEntity
        {
            OrderId = orderId,
            IdentifierType = identifier.Type,
            IdentifierValue = baseDomain,
            IsWildcard = isWildcard,
            Status = nameof(AcmeAuthorizationStatus.Pending),
            ExpiresAt = DateTime.UtcNow.AddHours(24)
        };

        return authz;
    }

    /// <summary>
    /// Creates challenge entities for an authorization. Wildcard authorizations only receive
    /// a dns-01 challenge (per RFC 8555 §7.4.1); non-wildcard authorizations receive both
    /// http-01 and dns-01 challenges.
    /// </summary>
    internal static List<AcmeChallengeEntity> CreateChallengesForAuthorization(Guid authzId, bool isWildcard)
    {
        var challenges = new List<AcmeChallengeEntity>();

        // Wildcards only support dns-01
        if (isWildcard)
        {
            challenges.Add(new AcmeChallengeEntity
            {
                AuthorizationId = authzId,
                Type = "dns-01",
                Token = GenerateToken(),
                Status = nameof(AcmeChallengeStatus.Pending)
            });
        }
        else
        {
            challenges.Add(new AcmeChallengeEntity
            {
                AuthorizationId = authzId,
                Type = "http-01",
                Token = GenerateToken(),
                Status = nameof(AcmeChallengeStatus.Pending)
            });
            challenges.Add(new AcmeChallengeEntity
            {
                AuthorizationId = authzId,
                Type = "dns-01",
                Token = GenerateToken(),
                Status = nameof(AcmeChallengeStatus.Pending)
            });
        }

        return challenges;
    }

    private async Task EvaluateParentOrderAsync(Guid orderId)
    {
        var allAuthzs = await _db.AcmeAuthorizations
            .Where(a => a.OrderId == orderId)
            .ToListAsync();

        if (allAuthzs.All(a => a.Status == nameof(AcmeAuthorizationStatus.Valid)))
        {
            var order = await _db.AcmeOrders.FindAsync(orderId);
            if (order != null && order.Status == nameof(AcmeOrderStatus.Pending))
            {
                order.Status = nameof(AcmeOrderStatus.Ready);
                await _db.SaveChangesAsync();
            }
        }
    }

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Deserializes a challenge's stored <c>ErrorJson</c> into an
    /// <see cref="AcmeErrorResponse"/> for inclusion in the challenge object.
    /// Returns null when there is no stored error or the payload is unparseable,
    /// so a malformed record never breaks the authorization response.
    /// </summary>
    private static AcmeErrorResponse? DeserializeError(string? errorJson)
    {
        if (string.IsNullOrWhiteSpace(errorJson)) return null;
        try { return JsonSerializer.Deserialize<AcmeErrorResponse>(errorJson); }
        catch (JsonException) { return null; }
    }

    private static AcmeAuthorizationDto MapToDto(
        AcmeAuthorizationEntity entity,
        List<AcmeChallengeEntity> challenges,
        string baseUrl) => new()
        {
            Id = entity.Id,
            Identifier = new AcmeIdentifier { Type = entity.IdentifierType, Value = entity.IdentifierValue },
            Status = entity.Status.ToLowerInvariant(),
            ExpiresAt = entity.ExpiresAt,
            IsWildcard = entity.IsWildcard,
            Challenges = challenges.Select(c => new AcmeChallengeDto
            {
                Id = c.Id,
                Type = c.Type,
                Url = $"{baseUrl}/api/v1/acme/challenge/{c.Id}",
                Token = c.Token,
                Status = c.Status.ToLowerInvariant(),
                ValidatedAt = c.ValidatedAt,
                // Surface the stored validation-failure problem document (RFC 8555 §8)
                // so polling clients can display why the challenge went invalid.
                Error = DeserializeError(c.ErrorJson)
            }).ToList()
        };
}
