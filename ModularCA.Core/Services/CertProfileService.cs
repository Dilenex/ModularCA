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
        /// Returns all certificate profiles with resolved EKU friendly names. With
        /// <paramref name="caVisible"/>, a profile's uses by CAs the caller may not see are
        /// counted rather than named.
        /// </summary>
        /// <param name="caVisible">Whether the caller may see a CA of the given space (null for the instance); null to name every CA.</param>
        public async Task<List<CertProfileDto>> GetAllAsync(Func<Guid?, bool>? caVisible = null)
        {
            var profiles = await _db.CertProfiles
                .AsNoTracking()
                .ToListAsync();

            var usedBy = await InfrastructureUsesAsync(null, caVisible);
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
        /// The inheritance parent is checked by <see cref="EnsureParentAllowedAsync"/>, and invalid
        /// expiry warning settings are refused (<see cref="ErrorCodes.ExpiryWarningSettingsInvalid"/>).
        /// A key usage or extended key usage the OID catalog does not hold is refused
        /// (<see cref="EnsureUsagesInCatalogAsync"/>, <see cref="ErrorCodes.CertProfileUsageNotInCatalog"/>).
        /// </summary>
        public async Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request, Guid? spaceId = null, Func<Guid?, Guid?, bool>? parentAllowed = null)
        {
            await EnsureParentAllowedAsync(request.InheritsFromId, null, spaceId, request.CertificateAuthorityId, parentAllowed);
            EnsureExpiryWarningsValid(request);
            await EnsureUsagesInCatalogAsync(request, null);
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
            ApplyExpiryWarnings(profile, request);

            _db.CertProfiles.Add(profile);
            await _db.SaveChangesAsync();

            return MapToDto(profile, new List<string>());
        }

        /// <summary>
        /// Updates an existing certificate profile by ID with the supplied request values. A changed
        /// inheritance parent, or a changed CA binding, is checked by <see cref="EnsureParentAllowedAsync"/>.
        /// Invalid expiry warning settings are refused (<see cref="ConfigurationValidationException"/>,
        /// <see cref="ErrorCodes.ExpiryWarningSettingsInvalid"/>). When the expiry warning settings
        /// or the inheritance change, the warning instants of the live certificates of this profile
        /// and of the profiles inheriting from it are re-computed in the same transaction as the save
        /// (<see cref="CertificateExpiry.SaveAndRecomputeAsync"/>): if the re-compute fails, the
        /// profile is left as it was. A key usage or extended key usage the update adds that the
        /// OID catalog does not hold is refused (<see cref="EnsureUsagesInCatalogAsync"/>,
        /// <see cref="ErrorCodes.CertProfileUsageNotInCatalog"/>).
        /// </summary>
        /// <returns>How many certificates had their expiry warning instants re-computed.</returns>
        public async Task<int> UpdateAsync(Guid id, UpdateCertProfileRequest request, Func<Guid?, Guid?, bool>? parentAllowed = null)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null) throw new KeyNotFoundException("Profile not found");
            if (request.InheritsFromId != profile.InheritsFromId || request.CertificateAuthorityId != profile.CertificateAuthorityId)
                await EnsureParentAllowedAsync(request.InheritsFromId, id, profile.SpaceId, request.CertificateAuthorityId, parentAllowed);
            await EnsureUsesSurviveAsync(profile, request);
            EnsureExpiryWarningsValid(request);
            await EnsureUsagesInCatalogAsync(request, profile);
            var before = ExpiryInputs(profile);

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
            ApplyExpiryWarnings(profile, request);
            profile.UpdatedAt = DateTime.UtcNow;

            return await CertificateExpiry.SaveAndRecomputeAsync(_db,
                before == ExpiryInputs(profile) ? [] : [id], DateTime.UtcNow);
        }

        /// <summary>Everything on a profile that decides its certificates' expiry warning instants.</summary>
        internal static string ExpiryInputs(CertProfileEntity p) =>
            $"{p.ExpiryWarningPercent}|{p.ExpiryWarningMaxWindow}|{p.ExpiryAlertPercent}|{p.ExpiryAlertMaxWindow}|{p.ExpiryNeverWarn}"
            + $"|{p.ExpiryWarningOverridesParent}|{p.InheritanceEnabled}|{p.InheritsFromId}";

        /// <summary>
        /// Refuses expiry warning settings <see cref="ExpiryWarningRule.Problem"/> finds fault with
        /// (<see cref="ConfigurationValidationException"/>, <see cref="ErrorCodes.ExpiryWarningSettingsInvalid"/>).
        /// </summary>
        private static void EnsureExpiryWarningsValid(CreateCertProfileRequest request)
        {
            if (ExpiryWarningRule.Problem(request.ExpiryWarningPercent, Blank(request.ExpiryWarningMaxWindow),
                    request.ExpiryAlertPercent, Blank(request.ExpiryAlertMaxWindow)) is string problem)
                throw new ConfigurationValidationException(problem, ErrorCodes.ExpiryWarningSettingsInvalid,
                    "Use percents from 1 to 100 with the alert no larger than the warning, and windows such as P30D or PT6H.");
        }

        /// <summary>
        /// Refuses a request whose key usages or extended key usages the OID catalog cannot
        /// resolve, by friendly name or OID in any spelling issuance resolves, or that name
        /// <c>anyExtendedKeyUsage</c> (<see cref="CertProfileUsageValidation"/>). Issuance leaves
        /// such a usage out of the certificate, so it is refused here with a message naming it
        /// (<see cref="ConfigurationValidationException"/>,
        /// <see cref="ErrorCodes.CertProfileUsageNotInCatalog"/>). The fields are read as a JSON
        /// array or a comma-separated list, the two forms this service stores from. On an update,
        /// the entries <paramref name="existing"/> already stores are not checked again, so a
        /// profile written before this check can still be edited; only what the update adds is.
        /// The check itself is <see cref="CertProfileUsageCatalog"/>, which the policy sync runs too.
        /// </summary>
        /// <param name="request">The create or update request.</param>
        /// <param name="existing">The profile being updated, or null on a create.</param>
        private async Task EnsureUsagesInCatalogAsync(CreateCertProfileRequest request, CertProfileEntity? existing)
        {
            // Nothing new to resolve: no catalog read for the common save that changes no usage.
            if (CertProfileUsageCatalog.NothingToResolve(
                    request.KeyUsages, request.ExtendedKeyUsages, existing?.KeyUsages, existing?.ExtendedKeyUsages))
                return;

            var catalog = await CertProfileUsageCatalog.LoadAsync(_db);
            if (catalog.Problem(request.KeyUsages, request.ExtendedKeyUsages, existing?.KeyUsages, existing?.ExtendedKeyUsages) is string problem)
                throw new ConfigurationValidationException(problem, ErrorCodes.CertProfileUsageNotInCatalog);
        }

        /// <summary>Copies the expiry warning settings of <paramref name="request"/> onto <paramref name="profile"/>, blank windows as null.</summary>
        private static void ApplyExpiryWarnings(CertProfileEntity profile, CreateCertProfileRequest request)
        {
            profile.ExpiryWarningPercent = request.ExpiryWarningPercent;
            profile.ExpiryWarningMaxWindow = Blank(request.ExpiryWarningMaxWindow);
            profile.ExpiryAlertPercent = request.ExpiryAlertPercent;
            profile.ExpiryAlertMaxWindow = Blank(request.ExpiryAlertMaxWindow);
            profile.ExpiryNeverWarn = request.ExpiryNeverWarn;
            profile.ExpiryWarningOverridesParent = request.ExpiryWarningOverridesParent;
        }

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

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
        /// not bound to another CA. Usages are judged after inheritance, as issuance reads them,
        /// and a profile that inherits from this one is judged with this change in place.
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

            var changed = new CertProfileEntity
            {
                Id = profile.Id,
                Name = profile.Name,
                IsCaProfile = request.IsCaProfile,
                KeyUsages = EnforceCaKeyUsages(NormalizeJsonStringArray(request.KeyUsages), request.IsCaProfile),
                ExtendedKeyUsages = NormalizeJsonStringArray(request.ExtendedKeyUsages),
                InheritsFromId = request.InheritsFromId,
                InheritanceEnabled = request.InheritanceEnabled,
            };
            if (await InfrastructureCertProfiles.WhyUsagesWouldBeLostAsync(_db, profile, changed) is string why)
                throw new ResourceConflictException(why, ErrorCodes.CertProfileInUse);
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
        /// <param name="id">The profile.</param>
        /// <param name="caVisible">Whether the caller may see a CA of the given space (null for the instance); null to name every CA.</param>
        public async Task<CertProfileDto?> GetByIdAsync(Guid id, Func<Guid?, bool>? caVisible = null)
        {
            var profile = await _db.CertProfiles.FindAsync(id);
            if (profile == null)
                return null;

            var ekuList = TryDeserializeStringList(profile.ExtendedKeyUsages);
            var ekuFriendlyNames = ekuList.Count > 0
                ? await OidHelper.ResolveOidFriendlyNamesAsync(_db, ekuList)
                : new List<string>();
            var dto = MapToDto(profile, ekuFriendlyNames);
            if ((await InfrastructureUsesAsync(id, caVisible)).TryGetValue(id, out var uses))
                dto.InfrastructureUses = uses;
            return dto;
        }

        /// <summary>
        /// For each certificate profile a CA names for a certificate of its own (one profile when
        /// <paramref name="profileId"/> is given), a line per use: the CA and the certificate. Uses
        /// by CAs <paramref name="caVisible"/> refuses are counted in one last line, unnamed.
        /// </summary>
        private async Task<Dictionary<Guid, List<string>>> InfrastructureUsesAsync(Guid? profileId, Func<Guid?, bool>? caVisible)
        {
            var cas = await _db.CertificateAuthorities.AsNoTracking()
                .Where(ca => profileId == null
                    ? ca.TsaCertProfileId != null || ca.OcspResponderCertProfileId != null || ca.CmpSignerCertProfileId != null
                    : ca.TsaCertProfileId == profileId || ca.OcspResponderCertProfileId == profileId || ca.CmpSignerCertProfileId == profileId)
                .OrderBy(ca => ca.Name)
                .ToListAsync();
            var uses = new Dictionary<Guid, List<string>>();
            var hidden = new Dictionary<Guid, int>();
            foreach (var ca in cas)
                foreach (var role in InfrastructureCertProfiles.All)
                    if (InfrastructureCertProfiles.ChosenId(ca, role) is Guid used && (profileId == null || used == profileId))
                    {
                        if (caVisible != null && !caVisible(ca.SpaceId))
                        {
                            hidden[used] = hidden.GetValueOrDefault(used) + 1;
                            continue;
                        }
                        if (!uses.TryGetValue(used, out var lines))
                            uses[used] = lines = new List<string>();
                        lines.Add($"{ca.Name}: {role.CertType}");
                    }
            foreach (var (used, count) in hidden)
            {
                if (!uses.TryGetValue(used, out var lines))
                    uses[used] = lines = new List<string>();
                lines.Add(count == 1 ? "1 use by a CA outside your scope" : $"{count} uses by CAs outside your scope");
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
            ExpiryWarningPercent = profile.ExpiryWarningPercent,
            ExpiryWarningMaxWindow = profile.ExpiryWarningMaxWindow,
            ExpiryAlertPercent = profile.ExpiryAlertPercent,
            ExpiryAlertMaxWindow = profile.ExpiryAlertMaxWindow,
            ExpiryNeverWarn = profile.ExpiryNeverWarn,
            ExpiryWarningOverridesParent = profile.ExpiryWarningOverridesParent,
            SystemPurpose = SystemCertProfiles.PurposeOf(profile.Name)
        };
    }
}
