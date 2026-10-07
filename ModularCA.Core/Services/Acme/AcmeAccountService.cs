using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;

namespace ModularCA.Core.Services.Acme;

/// <summary>
/// Database-backed ACME account management including creation, lookup, deactivation, and key change.
/// </summary>
public class AcmeAccountService(ModularCADbContext db) : IAcmeAccountService
{
    private readonly ModularCADbContext _db = db;

    /// <summary>
    /// Creates a new ACME account bound to <paramref name="certificateAuthorityId"/>, the CA its
    /// new-account request addressed. <paramref name="caLabel"/> is the route label it came in
    /// under, kept for display and audit.
    /// </summary>
    public async Task<AcmeAccountDto> CreateAsync(string jwkJson, string thumbprint, List<string>? contacts, bool termsAgreed, Guid certificateAuthorityId, string? caLabel = null)
    {
        var entity = new AcmeAccountEntity
        {
            JwkJson = jwkJson,
            JwkThumbprint = thumbprint,
            ContactsJson = JsonSerializer.Serialize(contacts ?? []),
            TermsOfServiceAgreed = termsAgreed,
            Status = nameof(AcmeAccountStatus.Valid),
            CreatedAt = DateTime.UtcNow,
            CaLabel = string.IsNullOrWhiteSpace(caLabel) ? null : caLabel,
            CertificateAuthorityId = certificateAuthorityId,
        };

        _db.AcmeAccounts.Add(entity);
        await _db.SaveChangesAsync();
        return MapToDto(entity);
    }

    /// <summary>
    /// Returns the raw account status string so the
    /// <c>new-account</c> fast path can reject deactivated accounts with
    /// <c>urn:ietf:params:acme:error:unauthorized</c>.
    /// </summary>
    public async Task<string?> GetStatusByThumbprintAsync(string thumbprint)
    {
        return await _db.AcmeAccounts
            .Where(a => a.JwkThumbprint == thumbprint)
            .Select(a => a.Status)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public async Task<Guid?> GetBoundCaIdAsync(Guid id)
    {
        return await _db.AcmeAccounts
            .Where(a => a.Id == id)
            .Select(a => a.CertificateAuthorityId)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public async Task<CertificateAuthorityEntity?> GetBoundCaAsync(Guid id)
    {
        var caId = await GetBoundCaIdAsync(id);
        if (caId == null)
            return null;
        return await _db.CertificateAuthorities.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == caId && c.IsEnabled);
    }

    /// <inheritdoc />
    public async Task<bool> BindAsync(Guid id, Guid certificateAuthorityId, string? caLabel)
    {
        var entity = await _db.AcmeAccounts.FindAsync(id);
        if (entity == null || entity.CertificateAuthorityId != null)
            return false;

        entity.CertificateAuthorityId = certificateAuthorityId;
        entity.CaLabel = string.IsNullOrWhiteSpace(caLabel) ? null : caLabel;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<AcmeAccountDto?> GetByIdAsync(Guid id)
    {
        var entity = await _db.AcmeAccounts.FindAsync(id);
        return entity == null ? null : MapToDto(entity);
    }

    public async Task<string?> GetJwkByIdAsync(Guid id)
    {
        var entity = await _db.AcmeAccounts.FindAsync(id);
        return entity?.JwkJson;
    }

    public async Task<AcmeAccountDto?> GetByThumbprintAsync(string thumbprint)
    {
        var entity = await _db.AcmeAccounts
            .Where(a => a.JwkThumbprint == thumbprint)
            .FirstOrDefaultAsync();
        return entity == null ? null : MapToDto(entity);
    }

    public async Task<AcmeAccountDto> UpdateAsync(Guid id, UpdateAcmeAccountRequest request)
    {
        var entity = await _db.AcmeAccounts.FindAsync(id)
            ?? throw new InvalidOperationException("Account not found.");

        if (entity.Status != nameof(AcmeAccountStatus.Valid))
            throw new InvalidOperationException("Account is not active.");

        if (request.Contact != null)
            entity.ContactsJson = JsonSerializer.Serialize(request.Contact);

        await _db.SaveChangesAsync();
        return MapToDto(entity);
    }

    public async Task<AcmeAccountDto> DeactivateAsync(Guid id)
    {
        var entity = await _db.AcmeAccounts.FindAsync(id)
            ?? throw new InvalidOperationException("Account not found.");

        entity.Status = nameof(AcmeAccountStatus.Deactivated);
        await _db.SaveChangesAsync();
        return MapToDto(entity);
    }

    public async Task KeyChangeAsync(Guid accountId, string newJwkJson, string newThumbprint)
    {
        var entity = await _db.AcmeAccounts.FindAsync(accountId)
            ?? throw new InvalidOperationException("Account not found.");

        if (entity.Status != nameof(AcmeAccountStatus.Valid))
            throw new InvalidOperationException("Account is not active.");

        // Ensure the new thumbprint isn't already in use
        var existing = await _db.AcmeAccounts
            .Where(a => a.JwkThumbprint == newThumbprint)
            .FirstOrDefaultAsync();

        if (existing != null)
            throw new InvalidOperationException("New key is already associated with another account.");

        entity.JwkJson = newJwkJson;
        entity.JwkThumbprint = newThumbprint;
        await _db.SaveChangesAsync();
    }

    private static AcmeAccountDto MapToDto(AcmeAccountEntity entity) => new()
    {
        Id = entity.Id,
        Status = entity.Status.ToLowerInvariant(),
        Contact = JsonSerializer.Deserialize<List<string>>(entity.ContactsJson) ?? [],
        TermsOfServiceAgreed = entity.TermsOfServiceAgreed,
        CreatedAt = entity.CreatedAt
    };
}
