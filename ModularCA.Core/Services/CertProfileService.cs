using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.CertProfiles;
using System.Text.Json;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Database-backed service for managing certificate profiles (extension templates,
    /// validity constraints, algorithm restrictions, and CT log configuration).
    /// </summary>
    public class CertProfileService : ICertProfileService
    {
        private readonly ModularCADbContext _db;

        public CertProfileService(ModularCADbContext db)
        {
            _db = db;
        }

        /// <summary>
        /// Returns all certificate profiles with resolved EKU friendly names.
        /// </summary>
        public async Task<List<CertProfileDto>> GetAllAsync()
        {
            var profiles = await _db.CertProfiles
                .AsNoTracking()
                .ToListAsync();

            var profilesDto = new List<CertProfileDto>();
            foreach (var profile in profiles)
            {
                var ekuList = TryDeserializeStringList(profile.ExtendedKeyUsages);
                var ekuFriendlyNames = ekuList.Count > 0
                    ? await OidHelper.ResolveOidFriendlyNamesAsync(_db, ekuList)
                    : new List<string>();
                profilesDto.Add(MapToDto(profile, ekuFriendlyNames));
            }

            return profilesDto;
        }

        /// <summary>
        /// Creates a new certificate profile entity from the given request.
        /// <paramref name="tenantId"/> stamps the profile with the owning tenant
        /// so the EF global query filter fences it to callers with access to that tenant.
        /// </summary>
        public async Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request, Guid? tenantId = null)
        {
            var profile = new CertProfileEntity
            {
                Name = request.Name,
                Description = request.Description,
                IsCaProfile = request.IsCaProfile,
                KeyUsages = EnforceCaKeyUsages(NormalizeJsonStringArray(request.KeyUsages), request.IsCaProfile),
                ExtendedKeyUsages = NormalizeJsonStringArray(request.ExtendedKeyUsages),
                AllowWildcard = request.AllowWildcard,
                CtEnabled = request.CtEnabled,
                CtLogIds = request.CtLogIds,
                ValidityPeriodMin = request.ValidityPeriodMin,
                ValidityPeriodMax = request.ValidityPeriodMax,
                AllowedKeyAlgorithms = request.AllowedKeyAlgorithms,
                AllowedKeySizes = request.AllowedKeySizes,
                AllowedSignatureAlgorithms = request.AllowedSignatureAlgorithms,
                CertificateAuthorityId = request.CertificateAuthorityId,
                TenantId = tenantId,
                InheritsFromId = request.InheritsFromId,
                InheritanceEnabled = request.InheritanceEnabled
            };

            _db.CertProfiles.Add(profile);
            await _db.SaveChangesAsync();

            return MapToDto(profile, new List<string>());
        }

        /// <summary>
        /// Updates an existing certificate profile by ID with the supplied request values.
        /// </summary>
        public async Task UpdateAsync(Guid id, UpdateCertProfileRequest request)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) throw new KeyNotFoundException("Profile not found");

            profile.Name = request.Name;
            profile.Description = request.Description;
            profile.IsCaProfile = request.IsCaProfile;
            profile.KeyUsages = EnforceCaKeyUsages(NormalizeJsonStringArray(request.KeyUsages), request.IsCaProfile);
            profile.ExtendedKeyUsages = NormalizeJsonStringArray(request.ExtendedKeyUsages);
            profile.AllowWildcard = request.AllowWildcard;
            profile.CtEnabled = request.CtEnabled;
            profile.CtLogIds = request.CtLogIds;
            profile.ValidityPeriodMin = request.ValidityPeriodMin;
            profile.ValidityPeriodMax = request.ValidityPeriodMax;
            profile.AllowedKeyAlgorithms = request.AllowedKeyAlgorithms;
            profile.AllowedKeySizes = request.AllowedKeySizes;
            profile.AllowedSignatureAlgorithms = request.AllowedSignatureAlgorithms;
            profile.CertificateAuthorityId = request.CertificateAuthorityId;
            profile.InheritsFromId = request.InheritsFromId;
            profile.InheritanceEnabled = request.InheritanceEnabled;
            profile.UpdatedAt = DateTime.UtcNow;

            await _db.SaveChangesAsync();
        }

        /// <summary>
        /// Deletes a certificate profile by its integer ID. No-op if not found.
        /// </summary>
        public async Task DeleteAsync(Guid id)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) return;

            _db.CertProfiles.Remove(profile);
            await _db.SaveChangesAsync();
        }

        /// <summary>
        /// Retrieves a single certificate profile by GUID, including resolved EKU names.
        /// Returns null if not found.
        /// </summary>
        public async Task<CertProfileDto?> GetByIdAsync(Guid id)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null)
                return null;

            var ekuList = TryDeserializeStringList(profile.ExtendedKeyUsages);
            var ekuFriendlyNames = ekuList.Count > 0
                ? await OidHelper.ResolveOidFriendlyNamesAsync(_db, ekuList)
                : new List<string>();
            return MapToDto(profile, ekuFriendlyNames);
        }

        /// <summary>
        /// Maps a <see cref="CertProfileEntity"/> and its resolved EKU names to a <see cref="CertProfileDto"/>.
        /// </summary>
        private static List<string> TryDeserializeStringList(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return new List<string>();
            try
            {
                return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            }
            catch (JsonException)
            {
                return json.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .ToList();
            }
        }

        /// <summary>
        /// Save-time guard for CA certificate profiles: keyCertSign and cRLSign are MANDATORY on any
        /// cA=TRUE certificate (RFC 5280 §4.2.1.3), so a CA profile must always carry the matching
        /// "Key Certificate Signing" / "CRL Signing" key usages. Rather than reject the save (which
        /// would just push the burden onto the caller), we normalise the missing bits in so the stored
        /// profile is correct on its own and the certificate builder never has to fall back on its
        /// force-add safety net. No-op for non-CA profiles and for CA profiles that already list them.
        /// KeyUsages are stored as a JSON array of friendly names (e.g. "Key Certificate Signing").
        /// </summary>
        private static string EnforceCaKeyUsages(string keyUsagesJson, bool isCaProfile)
        {
            if (!isCaProfile)
                return keyUsagesJson;

            var list = TryDeserializeStringList(keyUsagesJson);
            bool Has(string name) => list.Any(u => string.Equals(u, name, StringComparison.OrdinalIgnoreCase));

            // Exact friendly-name strings as seeded in OIDOptions and understood by KeyUsageFriendlyNames.
            if (!Has("Key Certificate Signing"))
                list.Add("Key Certificate Signing");
            if (!Has("CRL Signing"))
                list.Add("CRL Signing");

            return JsonSerializer.Serialize(list);
        }

        /// <summary>
        /// Ensures a value is a valid JSON string array. If the input is a
        /// comma-separated string, it is split and serialized as a JSON array.
        /// </summary>
        private static string NormalizeJsonStringArray(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "[]";
            try
            {
                JsonSerializer.Deserialize<List<string>>(value);
                return value;
            }
            catch (JsonException)
            {
                var items = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                return JsonSerializer.Serialize(items);
            }
        }

        private static CertProfileDto MapToDto(CertProfileEntity profile, List<string> ekuFriendlyNames) => new()
        {
            Id = profile.Id,
            Name = profile.Name,
            Description = profile.Description,
            IsCaProfile = profile.IsCaProfile,
            KeyUsages = profile.KeyUsages,
            ExtendedKeyUsages = profile.ExtendedKeyUsages,
            AllowWildcard = profile.AllowWildcard,
            CtEnabled = profile.CtEnabled,
            CtLogIds = profile.CtLogIds,
            ExtendedKeyUsageNames = ekuFriendlyNames,
            ValidityPeriodMin = profile.ValidityPeriodMin,
            ValidityPeriodMax = profile.ValidityPeriodMax,
            AllowedKeyAlgorithms = profile.AllowedKeyAlgorithms,
            AllowedKeySizes = profile.AllowedKeySizes,
            AllowedSignatureAlgorithms = profile.AllowedSignatureAlgorithms,
            CertificateAuthorityId = profile.CertificateAuthorityId,
            InheritsFromId = profile.InheritsFromId,
            InheritanceEnabled = profile.InheritanceEnabled
        };
    }
}
