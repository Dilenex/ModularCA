using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.SigningProfiles;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Database-backed service for managing signing profiles (algorithm constraints,
    /// name constraints, policy OIDs) and their allowed cert profile associations.
    /// </summary>
    public class SigningProfileService(ModularCADbContext db) : ISigningProfileService
    {
        private readonly ModularCADbContext _db = db;

        /// <summary>
        /// Returns all signing profiles with their allowed cert profile IDs populated.
        /// </summary>
        public async Task<List<SigningProfileDto>> GetAllAsync()
        {
            var profiles = await _db.SigningProfiles
                .AsNoTracking()
                .ToListAsync();

            var allLinks = await _db.AllowedCertProfileSigningProfiles
                .AsNoTracking()
                .ToListAsync();

            return profiles.Select(x => MapToDto(x, allLinks
                .Where(l => l.SigningProfileId == x.Id)
                .Select(l => l.CertProfileId)
                .ToList()))
                .ToList();
        }

        /// <summary>
        /// Creates a new signing profile entity and its allowed cert profile links.
        /// </summary>
        public async Task<SigningProfileDto> CreateAsync(CreateSigningProfileRequest r)
        {
            var entity = new SigningProfileEntity
            {
                Name = r.Name,
                Description = r.Description,
                AllowedAlgorithms = r.AllowedAlgorithms,
                AllowedEKUs = NormalizeJsonStringArray(r.AllowedEKUs),
                ExtendedKeyUsageCritical = r.ExtendedKeyUsageCritical,
                PolicyQualifiersJson = r.PolicyQualifiersJson,
                IsDefault = r.IsDefault,
                IssuerId = r.IssuerId,
                MaxPathLength = r.MaxPathLength,
                NameConstraintsPermitted = r.NameConstraintsPermitted,
                NameConstraintsExcluded = r.NameConstraintsExcluded,
                PolicyOids = r.PolicyOids,
                InhibitAnyPolicy = r.InhibitAnyPolicy,
                InheritsFromId = r.InheritsFromId,
                InheritanceEnabled = r.InheritanceEnabled
            };

            _db.SigningProfiles.Add(entity);
            await _db.SaveChangesAsync();

            if (r.AllowedCertProfileIds.Count > 0)
            {
                await SetAllowedCertProfilesAsync(entity.Id, r.AllowedCertProfileIds);
            }

            return MapToDto(entity, r.AllowedCertProfileIds);
        }

        /// <summary>
        /// Updates an existing signing profile and replaces its allowed cert profile links.
        /// </summary>
        public async Task UpdateAsync(Guid id, UpdateSigningProfileRequest r)
        {
            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity == null) throw new KeyNotFoundException("Signing profile not found.");

            entity.Name = r.Name;
            entity.Description = r.Description;
            entity.AllowedAlgorithms = r.AllowedAlgorithms;
            entity.AllowedEKUs = NormalizeJsonStringArray(r.AllowedEKUs);
            entity.ExtendedKeyUsageCritical = r.ExtendedKeyUsageCritical;
            entity.PolicyQualifiersJson = r.PolicyQualifiersJson;
            entity.IsDefault = r.IsDefault;
            entity.IssuerId = r.IssuerId;
            entity.MaxPathLength = r.MaxPathLength;
            entity.NameConstraintsPermitted = r.NameConstraintsPermitted;
            entity.NameConstraintsExcluded = r.NameConstraintsExcluded;
            entity.PolicyOids = r.PolicyOids;
            entity.InhibitAnyPolicy = r.InhibitAnyPolicy;
            entity.InheritsFromId = r.InheritsFromId;
            entity.InheritanceEnabled = r.InheritanceEnabled;
            entity.UpdatedAt = DateTime.UtcNow;

            await _db.SaveChangesAsync();
            await SetAllowedCertProfilesAsync(id, r.AllowedCertProfileIds);
        }

        /// <summary>
        /// Deletes a signing profile and its associated cert profile links.
        /// </summary>
        public async Task DeleteAsync(Guid id)
        {
            var links = await _db.AllowedCertProfileSigningProfiles
                .Where(l => l.SigningProfileId == id)
                .ToListAsync();
            _db.AllowedCertProfileSigningProfiles.RemoveRange(links);

            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity != null)
            {
                _db.SigningProfiles.Remove(entity);
            }

            await _db.SaveChangesAsync();
        }

        /// <summary>
        /// Retrieves a single signing profile by GUID, including its allowed cert profile IDs.
        /// Returns null if not found.
        /// </summary>
        public async Task<SigningProfileDto?> GetByIdAsync(Guid id)
        {
            var entity = await _db.SigningProfiles.FindAsync(id);
            if (entity == null)
                return null;

            var certProfileIds = await GetAllowedCertProfileIdsAsync(id);
            return MapToDto(entity, certProfileIds);
        }

        /// <summary>
        /// Replaces the full set of allowed cert profile IDs for the given signing profile.
        /// Removes existing links and inserts the new set.
        /// </summary>
        public async Task SetAllowedCertProfilesAsync(Guid signingProfileId, List<Guid> certProfileIds)
        {
            var existing = await _db.AllowedCertProfileSigningProfiles
                .Where(l => l.SigningProfileId == signingProfileId)
                .ToListAsync();

            _db.AllowedCertProfileSigningProfiles.RemoveRange(existing);

            foreach (var cpId in certProfileIds)
            {
                _db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity
                {
                    CertProfileId = cpId,
                    SigningProfileId = signingProfileId
                });
            }

            await _db.SaveChangesAsync();
        }

        /// <summary>
        /// Returns the list of cert profile IDs allowed for the given signing profile.
        /// </summary>
        public async Task<List<Guid>> GetAllowedCertProfileIdsAsync(Guid signingProfileId)
        {
            return await _db.AllowedCertProfileSigningProfiles
                .Where(l => l.SigningProfileId == signingProfileId)
                .Select(l => l.CertProfileId)
                .ToListAsync();
        }

        /// <summary>
        /// Canonicalises a JSON string array before persisting it.
        /// <para>
        /// This write path used to store whatever the client sent, verbatim — unlike
        /// <c>CertProfileService</c>, which has always normalised. That let malformed values
        /// accumulate: a client round-tripping a mis-parsed field could persist fragments of a JSON
        /// array (<c>["[]"</c>, <c>"Server Auth"</c>) or a double-encoded array, and each save
        /// compounded it. Normalising here makes the next save of an affected profile repair it.
        /// </para>
        /// <para>
        /// Accepts a JSON array (kept as-is), a comma-separated list (converted), or an array whose
        /// elements are themselves encoded arrays (flattened one level). Entries are trimmed of
        /// stray brackets and quotes so a fragment resolves to its bare value.
        /// </para>
        /// </summary>
        private static string NormalizeJsonStringArray(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "[]";

            List<string> items;
            try
            {
                items = JsonSerializer.Deserialize<List<string>>(value) ?? new List<string>();
            }
            catch (JsonException)
            {
                items = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            }

            var flattened = new List<string>();
            foreach (var item in items)
            {
                var trimmed = (item ?? string.Empty).Trim();
                if (trimmed.StartsWith('[') && trimmed.EndsWith(']'))
                {
                    try
                    {
                        var inner = JsonSerializer.Deserialize<List<string>>(trimmed);
                        if (inner != null) { flattened.AddRange(inner); continue; }
                    }
                    catch (JsonException) { /* fall through to scrubbing below */ }
                }
                flattened.Add(trimmed);
            }

            var cleaned = flattened
                .Select(v => v.Trim('[', ']', '"', ' '))
                .Where(v => v.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            return JsonSerializer.Serialize(cleaned);
        }

        /// <summary>
        /// Maps a <see cref="SigningProfileEntity"/> and its associated cert profile IDs to a <see cref="SigningProfileDto"/>.
        /// </summary>
        private static SigningProfileDto MapToDto(SigningProfileEntity entity, List<Guid> certProfileIds) => new()
        {
            Id = entity.Id,
            Name = entity.Name,
            Description = entity.Description,
            AllowedAlgorithms = entity.AllowedAlgorithms,
            AllowedEKUs = entity.AllowedEKUs,
            ExtendedKeyUsageCritical = entity.ExtendedKeyUsageCritical,
            PolicyQualifiersJson = entity.PolicyQualifiersJson,
            IsDefault = entity.IsDefault,
            IssuerId = entity.IssuerId,
            MaxPathLength = entity.MaxPathLength,
            NameConstraintsPermitted = entity.NameConstraintsPermitted,
            NameConstraintsExcluded = entity.NameConstraintsExcluded,
            PolicyOids = entity.PolicyOids,
            InhibitAnyPolicy = entity.InhibitAnyPolicy,
            AllowedCertProfileIds = certProfileIds,
            InheritsFromId = entity.InheritsFromId,
            InheritanceEnabled = entity.InheritanceEnabled
        };
    }
}
