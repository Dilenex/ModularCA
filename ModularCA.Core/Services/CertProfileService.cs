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
        /// <paramref name="spaceId"/> stamps the profile with its space (null for the instance).
        /// The inheritance parent is checked by <see cref="EnsureParentAllowedAsync"/>.
        /// </summary>
        public async Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request, Guid? spaceId = null, Func<Guid?, Guid?, bool>? parentAllowed = null)
        {
            await EnsureParentAllowedAsync(request.InheritsFromId, null, spaceId, request.CertificateAuthorityId, parentAllowed);
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
                SpaceId = spaceId,
                InheritsFromId = request.InheritsFromId,
                InheritanceEnabled = request.InheritanceEnabled
            };

            _db.CertProfiles.Add(profile);
            await _db.SaveChangesAsync();

            return MapToDto(profile, new List<string>());
        }

        /// <summary>
        /// Updates an existing certificate profile by ID with the supplied request values. A changed
        /// inheritance parent, or a changed CA binding, is checked by <see cref="EnsureParentAllowedAsync"/>.
        /// </summary>
        public async Task UpdateAsync(Guid id, UpdateCertProfileRequest request, Func<Guid?, Guid?, bool>? parentAllowed = null)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) throw new KeyNotFoundException("Profile not found");
            if (request.InheritsFromId != profile.InheritsFromId || request.CertificateAuthorityId != profile.CertificateAuthorityId)
                await EnsureParentAllowedAsync(request.InheritsFromId, id, profile.SpaceId, request.CertificateAuthorityId, parentAllowed);

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
        /// Refuses an inheritance parent the caller may not see: one that does not exist, is the
        /// child itself, or fails <paramref name="parentAllowed"/> (the caller's fence over the
        /// parent's space and CA) is not found. A parent the caller sees must also be in the
        /// child's own scope (<paramref name="childSpaceId"/>, null for the instance) or be
        /// instance-wide (no space, no CA), and a parent bound to a CA must be bound to the child's
        /// CA (<paramref name="childCaId"/>), so a caller in two spaces cannot make one space's
        /// profile inherit from the other's
        /// (<see cref="ModularCA.Shared.Errors.ConfigurationValidationException"/>).
        /// </summary>
        private async Task EnsureParentAllowedAsync(Guid? parentId, Guid? childId, Guid? childSpaceId, Guid? childCaId, Func<Guid?, Guid?, bool>? parentAllowed)
        {
            if (parentId is not Guid id)
                return;
            var parent = id == childId ? null : await _db.CertProfiles.AsNoTracking()
                .Where(p => p.Id == id)
                .Select(p => new { p.SpaceId, p.CertificateAuthorityId })
                .FirstOrDefaultAsync();
            if (parent == null || (parentAllowed != null && !parentAllowed(parent.SpaceId, parent.CertificateAuthorityId)))
                throw new ModularCA.Shared.Errors.ResourceNotFoundException(
                    "Certificate profile", $"Parent certificate profile '{id}' not found.", id.ToString());
            if (parent.SpaceId != childSpaceId && !(parent.SpaceId == null && parent.CertificateAuthorityId == null))
                throw new ModularCA.Shared.Errors.ConfigurationValidationException(
                    $"Parent certificate profile '{id}' belongs to another scope; a profile inherits only from its own scope's profiles or an instance-wide one.");
            if (parent.CertificateAuthorityId != null && parent.CertificateAuthorityId != childCaId)
                throw new ModularCA.Shared.Errors.ConfigurationValidationException(
                    $"Parent certificate profile '{id}' is bound to another CA; a profile inherits from a CA-bound profile only when bound to the same CA.");
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
            SpaceId = profile.SpaceId,
            InheritsFromId = profile.InheritsFromId,
            InheritanceEnabled = profile.InheritanceEnabled
        };
    }
}
