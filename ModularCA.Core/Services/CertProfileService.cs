using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Utils;
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

            var usedBy = await InfrastructureUsesAsync(null);
            var profilesDto = new List<CertProfileDto>();
            foreach (var profile in profiles)
            {
                var ekuList = TryDeserializeStringList(profile.ExtendedKeyUsages);
                var ekuFriendlyNames = ekuList.Count > 0
                    ? await OidHelper.ResolveOidFriendlyNamesAsync(_db, ekuList)
                    : new List<string>();
                var dto = MapToDto(profile, ekuFriendlyNames);
                if (usedBy.TryGetValue(profile.Id, out var uses))
                    dto.InfrastructureUses = uses;
                profilesDto.Add(dto);
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
            await EnsureUsesSurviveAsync(profile, request);

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
        /// Refuses a change that would leave something unable to be issued
        /// (<see cref="ResourceConflictException"/>, <see cref="ErrorCodes.CertProfileInUse"/>). A
        /// profile the application finds by name (<see cref="SystemCertProfiles"/>) keeps its
        /// name, its kind and its instance-wide scope. A profile a CA issues its timestamp signer,
        /// OCSP responder or CMP signer from, by name as the default or because the CA names it,
        /// stays an end-entity profile that lists the usage that certificate exists for, and is
        /// not bound to another CA.
        /// </summary>
        private async Task EnsureUsesSurviveAsync(CertProfileEntity profile, UpdateCertProfileRequest request)
        {
            var purpose = SystemCertProfiles.PurposeOf(profile.Name);
            if (purpose != null)
            {
                var refused = request.Name != profile.Name ? "renamed"
                    : request.IsCaProfile != profile.IsCaProfile ? (profile.IsCaProfile ? "turned into an end-entity profile" : "turned into a CA profile")
                    : request.CertificateAuthorityId != null && request.CertificateAuthorityId != profile.CertificateAuthorityId ? "bound to one CA"
                    : null;
                if (refused != null)
                    throw new ResourceConflictException(
                        $"The certificate profile '{profile.Name}' cannot be {refused}: {purpose}, and it is found by this name.",
                        ErrorCodes.CertProfileInUse, "Create a certificate profile of your own for any other use.");
            }

            var uses = await InfrastructureCertProfiles.UsesAsync(_db, profile.Id);
            if (request.CertificateAuthorityId is Guid boundTo && boundTo != profile.CertificateAuthorityId)
            {
                var others = uses.Where(u => u.CaId != boundTo).Select(u => u.CaName).Distinct().ToList();
                if (others.Count > 0)
                    throw new ResourceConflictException(
                        $"The certificate profile '{profile.Name}' cannot be bound to that CA: {string.Join(", ", others)} "
                        + (others.Count == 1 ? "issues a certificate of its own from it." : "issue certificates of their own from it."),
                        ErrorCodes.CertProfileInUse, "Name another profile on the CA's page first.");
            }

            var roles = uses.Select(u => u.Role)
                .Concat(InfrastructureCertProfiles.All.Where(r => r.DefaultProfileName == profile.Name))
                .Distinct()
                .ToList();
            if (roles.Count == 0)
                return;
            var changed = new CertProfileEntity
            {
                Name = profile.Name,
                IsCaProfile = request.IsCaProfile,
                KeyUsages = EnforceCaKeyUsages(NormalizeJsonStringArray(request.KeyUsages), request.IsCaProfile),
                ExtendedKeyUsages = NormalizeJsonStringArray(request.ExtendedKeyUsages),
            };
            foreach (var role in roles)
            {
                if (InfrastructureCertProfiles.WhyUnsuitable(changed, role) is not string reason)
                    continue;
                var users = uses.Where(u => u.Role == role).Select(u => u.CaName).ToList();
                var who = users.Count > 0
                    ? $"{string.Join(", ", users)} " + (users.Count == 1 ? "issues its" : "issue their") + $" {role.CertType} certificate from it."
                    : $"Every CA that names no other profile issues its {role.CertType} certificate from it.";
                throw new ResourceConflictException($"{reason} {who}", ErrorCodes.CertProfileInUse);
            }
        }

        /// <summary>
        /// Deletes a certificate profile by ID. No-op if not found. A profile the application
        /// finds by name, or one a CA names for a certificate of its own, is refused
        /// (<see cref="ResourceConflictException"/>, <see cref="ErrorCodes.CertProfileInUse"/>).
        /// </summary>
        public async Task DeleteAsync(Guid id)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) return;

            if (SystemCertProfiles.PurposeOf(profile.Name) is string purpose)
                throw new ResourceConflictException(
                    $"The certificate profile '{profile.Name}' cannot be deleted: {purpose}.", ErrorCodes.CertProfileInUse);
            var uses = await InfrastructureCertProfiles.UsesAsync(_db, id);
            if (uses.Count > 0)
                throw new ResourceConflictException(
                    $"The certificate profile '{profile.Name}' cannot be deleted: "
                    + string.Join("; ", uses.Select(u => $"{u.CaName} issues its {u.Role.CertType} certificate from it")) + ".",
                    ErrorCodes.CertProfileInUse, "Name another profile on the CA's page first.");

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
            var dto = MapToDto(profile, ekuFriendlyNames);
            if ((await InfrastructureUsesAsync(id)).TryGetValue(id, out var uses))
                dto.InfrastructureUses = uses;
            return dto;
        }

        /// <summary>
        /// For each certificate profile a CA names for a certificate of its own (one profile when
        /// <paramref name="profileId"/> is given), a line per use: the CA and the certificate.
        /// </summary>
        private async Task<Dictionary<Guid, List<string>>> InfrastructureUsesAsync(Guid? profileId)
        {
            var cas = await _db.CertificateAuthorities.AsNoTracking()
                .Where(ca => profileId == null
                    ? ca.TsaCertProfileId != null || ca.OcspResponderCertProfileId != null || ca.CmpSignerCertProfileId != null
                    : ca.TsaCertProfileId == profileId || ca.OcspResponderCertProfileId == profileId || ca.CmpSignerCertProfileId == profileId)
                .OrderBy(ca => ca.Name)
                .ToListAsync();
            var uses = new Dictionary<Guid, List<string>>();
            foreach (var ca in cas)
                foreach (var role in InfrastructureCertProfiles.All)
                    if (InfrastructureCertProfiles.ChosenId(ca, role) is Guid used && (profileId == null || used == profileId))
                    {
                        if (!uses.TryGetValue(used, out var lines))
                            uses[used] = lines = new List<string>();
                        lines.Add($"{ca.Name}: {role.CertType}");
                    }
            return uses;
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
            InheritanceEnabled = profile.InheritanceEnabled,
            SystemPurpose = SystemCertProfiles.PurposeOf(profile.Name)
        };
    }
}
