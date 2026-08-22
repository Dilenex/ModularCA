using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Authorization;
using ModularCA.Core.Implementations;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// Creates Certificate Authorities at runtime: generates key pairs, signs CA certs
/// (self-signed for root, parent-signed for intermediate), persists to DB and keystore,
/// and registers in the in-memory CA registry.
/// </summary>
public class CaCreationService(
    ModularCADbContext db,
    IKeystoreCertificates keystore,
    ICrlService crlService,
    ICaServiceUrlService caServiceUrls,
    ICsrService csrService,
    ICertificateIssuanceService issuanceService,
    SystemConfig systemConfig,
    ILogger<CaCreationService> logger,
    IQuotaService quotaService,
    IAuditService? audit = null)
{
    /// <summary>
    /// Blocks CA creation when the owning tenant has reached its
    /// <c>MaxCertificateAuthorities</c> limit. Previously the value was stored on the
    /// tenant and echoed by the admin UI but never consulted by either creation path,
    /// so operators thought they had a cap when in fact there wasn't one.
    /// </summary>
    private async Task EnforceTenantCaQuotaAsync(Guid tenantId)
    {
        if (!await quotaService.CanCreateCaInTenantAsync(tenantId))
            throw new InvalidOperationException("Tenant CA quota exceeded.");
    }

    // Shared helper used by the root/intermediate builders below to
    // synthesize the CDP / AIA URL lists a new CA will carry in its own cert.
    // For roots (self-signed) we don't emit any — there is no issuer to point at.
    // For intermediates we resolve the PARENT CA's service URLs so the cert's AIA
    // points back at the issuing CA and its CDP references the parent's CRL. The
    // list is then deduped and sanitized before being injected into the generator.
    private async Task<ResolvedCaServiceUrls> ResolveParentServiceUrlsAsync(Guid parentCaCertificateId)
    {
        try
        {
            return await caServiceUrls.ResolveForCaAsync(parentCaCertificateId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to resolve parent CA service URLs for CDP/AIA; skipping extensions.");
            return new ResolvedCaServiceUrls(new List<string>(), new List<string>(), new List<string>());
        }
    }

    private static void AddCdpAndAiaFromResolved(X509V3CertificateGenerator certGen, ResolvedCaServiceUrls resolved)
    {
        var cdpUrls = resolved.CdpUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var ocspUrls = resolved.OcspUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var caIssuerUrls = resolved.CaIssuerUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (cdpUrls.Count > 0)
        {
            var distributionPoints = cdpUrls.Select(url =>
                new DistributionPoint(
                    new DistributionPointName(
                        new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, url))),
                    null, null))
                .ToArray();
            certGen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(distributionPoints));
        }

        var accessDescriptions = new List<AccessDescription>();
        foreach (var ocspUrl in ocspUrls)
        {
            accessDescriptions.Add(new AccessDescription(
                AccessDescription.IdADOcsp,
                new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl)));
        }
        foreach (var caIssuerUrl in caIssuerUrls)
        {
            accessDescriptions.Add(new AccessDescription(
                AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, caIssuerUrl)));
        }

        if (accessDescriptions.Count > 0)
        {
            certGen.AddExtension(X509Extensions.AuthorityInfoAccess, false,
                new AuthorityInformationAccess(accessDescriptions.ToArray()));
        }
    }

    /// <summary>
    /// Creates a new self-signed root CA. Generates a key pair, builds and self-signs the
    /// CA certificate, stores it in DB and keystore, creates the CertificateAuthorityEntity,
    /// seeds protocol configs, and registers the new CA in the runtime registry.
    /// Optional <paramref name="nameConstraintsPermittedJson"/> and
    /// <paramref name="nameConstraintsExcludedJson"/> are baked into the cert via the
    /// NameConstraints extension AND copied onto the per-CA signing profile so the same
    /// constraints flow through to every leaf the CA later issues.
    /// </summary>
    public async Task<CertificateAuthorityEntity> CreateRootAsync(
        string subjectCN, string? subjectO, string? subjectOU,
        string? subjectL, string? subjectST, string? subjectC,
        string keyAlgorithm, int keySize, int validityYears, string? label,
        Guid tenantId,
        string? publicBaseUrl = null,
        string? nameConstraintsPermittedJson = null,
        string? nameConstraintsExcludedJson = null)
    {
        await EnforceTenantCaQuotaAsync(tenantId);

        var newKeyPair = GenerateKeyPair(keyAlgorithm, keySize);
        var subjectDN = BuildSubjectDN(subjectCN, subjectO, subjectOU, subjectL, subjectST, subjectC);

        // 17 bytes with a forced 0x00 high byte guarantees a positive
        // BigInteger while preserving a full 128 bits of randomness in the magnitude.
        var serialBytes = new byte[17];
        serialBytes[0] = 0x00;
        RandomNumberGenerator.Fill(serialBytes.AsSpan(1));
        var serial = new BigInteger(1, serialBytes);
        var notBefore = DateTime.UtcNow;
        var notAfter = DateTime.UtcNow.AddYears(validityYears);

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(subjectDN);   // Self-signed: issuer = subject
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(newKeyPair.Public);

        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

        var subPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(newKeyPair.Public);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(subPubKeyInfo));

        // AKI = own SKI for self-signed
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(subPubKeyInfo));

        certGen.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));

        // NameConstraints (critical) — bake the operator-supplied permitted /
        // excluded subtree lists into the CA cert at build time. The same JSON payloads
        // are also copied onto the per-CA signing profile in PersistAndRegisterAsync so
        // downstream issuance honours the same constraints.
        var nameConstraints = CertificateBuilderService.BuildNameConstraints(nameConstraintsPermittedJson, nameConstraintsExcludedJson);
        if (nameConstraints != null)
        {
            certGen.AddExtension(X509Extensions.NameConstraints, true, nameConstraints);
        }

        // Self-sign with the new key pair's private key. Route through KeyAlgorithmPolicy so
        // the curve/hash pairing is centralised (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
        var sigAlgName = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySize);
        var signer = new Asn1SignatureFactory(sigAlgName, newKeyPair.Private, new SecureRandom());
        var newCaCert = certGen.Generate(signer);

        // Self-signed roots can't go through the pipeline (no parent signing profile).
        // Build and store the cert entity directly, then register the CA.
        var certEntity = BuildCaCertEntity(newCaCert, parentCertificateId: null);
        db.Certificates.Add(certEntity);
        await db.SaveChangesAsync();

        return await PersistAndRegisterAsync(
            certEntity, newCaCert, newKeyPair, subjectCN, label,
            tenantId: tenantId,
            caType: "Root", parentCaId: null,
            parentCertificateId: null,
            publicBaseUrl: publicBaseUrl,
            nameConstraintsPermittedJson: nameConstraintsPermittedJson,
            nameConstraintsExcludedJson: nameConstraintsExcludedJson);
    }

    /// <summary>
    /// Creates a new intermediate CA signed by the specified parent CA. Generates a key pair,
    /// builds the CA certificate signed by the parent, stores it in DB and keystore,
    /// creates the CertificateAuthorityEntity, seeds protocol configs, and registers at runtime.
    /// Optional <paramref name="nameConstraintsPermittedJson"/> /
    /// <paramref name="nameConstraintsExcludedJson"/> are baked into the cert's NameConstraints
    /// extension AND copied onto the per-CA signing profile so downstream issuance honours
    /// the same constraints.
    /// </summary>
    public async Task<CertificateAuthorityEntity> CreateIntermediateAsync(
        CertificateAuthorityEntity parentCa, CertificateEntity parentCert,
        string subjectCN, string? subjectO, string? subjectOU,
        string? subjectL, string? subjectST, string? subjectC,
        string keyAlgorithm, int keySize, int validityYears, string? label,
        Guid tenantId,
        string? publicBaseUrl = null,
        Guid? certProfileId = null,
        string? nameConstraintsPermittedJson = null,
        string? nameConstraintsExcludedJson = null)
    {
        await EnforceTenantCaQuotaAsync(tenantId);

        var parentBcCert = CertificateUtil.ParseFromPem(parentCert.Pem);
        var parentKeyHandle = keystore.GetPrivateKeyFor(parentBcCert)
            ?? throw new InvalidOperationException("Parent CA private key not found in keystore");

        // Resolve parent CA's signing profile for the issuance pipeline
        var parentSigningProfile = await db.SigningProfiles
            .FirstOrDefaultAsync(sp => sp.IssuerId == parentCert.CertificateId)
            ?? throw new InvalidOperationException("Parent CA signing profile not found.");

        // Look up the CA cert profile — use the operator-selected profile or fall back to default
        CertProfileEntity caCertProfile;
        if (certProfileId.HasValue)
        {
            caCertProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => cp.Id == certProfileId.Value && cp.IsCaProfile)
                ?? throw new InvalidOperationException($"CA Certificate Profile '{certProfileId}' not found or is not a CA profile.");
        }
        else
        {
            caCertProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => cp.IsCaProfile && cp.Name == "Main CA Certificate Profile")
                ?? throw new InvalidOperationException("Default CA Certificate Profile not found. Run bootstrap to seed profiles.");
        }

        // The issuance pipeline reads the signing profile from the database by id, so the only
        // way to hand it the intermediate's name constraints and pathLen is to stamp them onto
        // the parent's profile for the duration of the call.
        //
        // This was described as "in-memory only", and it was not. parentSigningProfile is tracked
        // (no AsNoTracking above), and both GenerateInfrastructureCsrAsync and
        // IssueCertificateAsync call SaveChangesAsync on this same scoped context — so the
        // temporary values were committed. The old restore then set the fields back in memory and
        // marked the entry Unchanged, which tells EF there is nothing to write, so the correct
        // values were never persisted. Creating a single intermediate therefore left the parent
        // CA's signing profile permanently holding MaxPathLength = 0 and the intermediate's name
        // constraints, silently changing policy for every certificate that profile signed
        // afterwards.
        //
        // The restore is now in a finally block and is actually saved, so a failure part-way
        // through issuance cannot leave the mutation behind either.
        //
        // A window remains: between the stamp and the restore, a concurrent request reading this
        // profile from its own DbContext sees the temporary values. Closing that properly means
        // threading the constraints through the issuance pipeline as explicit parameters rather
        // than smuggling them via a shared row — worth doing, but a wider change than this fix.
        var origPermitted = parentSigningProfile.NameConstraintsPermitted;
        var origExcluded = parentSigningProfile.NameConstraintsExcluded;
        var origMaxPath = parentSigningProfile.MaxPathLength;

        IssuanceResult result;
        Guid csrId;
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair newKeyPair;
        try
        {
            if (!string.IsNullOrWhiteSpace(nameConstraintsPermittedJson))
                parentSigningProfile.NameConstraintsPermitted = nameConstraintsPermittedJson;
            if (!string.IsNullOrWhiteSpace(nameConstraintsExcludedJson))
                parentSigningProfile.NameConstraintsExcluded = nameConstraintsExcludedJson;
            parentSigningProfile.MaxPathLength = 0; // pathLenConstraint=0 for intermediates

            // Build subject DN
            var subjectDnStr = BuildSubjectDN(subjectCN, subjectO, subjectOU, subjectL, subjectST, subjectC).ToString();

            // Generate CSR and issue through the standard pipeline
            (csrId, newKeyPair) = await csrService.GenerateInfrastructureCsrAsync(
                subjectDnStr, keyAlgorithm, keySize, caCertProfile.Id, parentSigningProfile.Id);

            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddYears(validityYears);
            if (notAfter > parentBcCert.NotAfter)
            {
                logger.LogWarning(
                    "Intermediate CA '{Name}' requested validity until {Requested:O} but parent CA expires {ParentExpiry:O}; clamping to parent expiry.",
                    subjectCN, notAfter, parentBcCert.NotAfter);
                notAfter = parentBcCert.NotAfter;
            }

            result = await issuanceService.IssueCertificateAsync(
                csrId, notBefore, notAfter, parentBcCert, parentKeyHandle);
        }
        finally
        {
            // Restore AND persist. Marking the entry Unchanged (the old behaviour) discards the
            // restore instead of writing it.
            parentSigningProfile.NameConstraintsPermitted = origPermitted;
            parentSigningProfile.NameConstraintsExcluded = origExcluded;
            parentSigningProfile.MaxPathLength = origMaxPath;
            await db.SaveChangesAsync();
        }

        // Retrieve the stored cert entity via the CSR
        var csrEntity = await db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == csrId);
        var certEntity = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == csrEntity!.IssuedCertificateId);
        if (certEntity == null)
            throw new InvalidOperationException("Issued intermediate CA certificate not found in database.");

        var newCaCert = CertificateUtil.ParseFromPem(result.Pem);

        return await PersistAndRegisterAsync(
            certEntity, newCaCert, newKeyPair, subjectCN, label,
            tenantId: tenantId,
            caType: "Intermediate", parentCaId: parentCa.Id,
            parentCertificateId: parentCert.CertificateId,
            publicBaseUrl: publicBaseUrl,
            nameConstraintsPermittedJson: nameConstraintsPermittedJson,
            nameConstraintsExcludedJson: nameConstraintsExcludedJson);
    }

    // ---- Shared helpers ----

    /// <summary>
    /// Persists the signed CA certificate to DB and keystore, creates the CA entity,
    /// creates a per-CA signing profile linked to existing cert profiles, seeds default
    /// protocol configs using that signing profile, creates a CRL schedule, generates
    /// and stores a TSA signer certificate, and registers in the runtime registry.
    /// When <paramref name="nameConstraintsPermittedJson"/> or
    /// <paramref name="nameConstraintsExcludedJson"/> are provided, the per-CA signing
    /// profile is created with those columns populated so leaf issuance through this CA
    /// inherits the same name constraints that were baked into the CA cert itself.
    /// </summary>
    /// <summary>
    /// Creates a CA entity, per-CA signing profile, authorization groups, CRL schedule,
    /// service URLs, TSA/OCSP certs, and protocol configs for an already-issued CA certificate.
    /// The cert must already be stored in the database (via the issuance pipeline or direct
    /// insert for self-signed roots). Keystore writes are deferred to after DB commit.
    /// </summary>
    private async Task<CertificateAuthorityEntity> PersistAndRegisterAsync(
        CertificateEntity certEntity,
        X509Certificate newCaCert,
        AsymmetricCipherKeyPair newKeyPair,
        string name,
        string? label,
        Guid tenantId,
        string caType,
        Guid? parentCaId,
        Guid? parentCertificateId,
        string? publicBaseUrl = null,
        string? nameConstraintsPermittedJson = null,
        string? nameConstraintsExcludedJson = null)
    {
        // Validate tenant exists and is enabled
        var tenant = await db.Tenants.FindAsync(tenantId);
        if (tenant == null || !tenant.IsEnabled)
            throw new InvalidOperationException($"Tenant '{tenantId}' not found or is disabled");

        // Validate the label against a strict char set BEFORE any DB work so we
        // never persist a CA whose label can escape CDP/AIA URLs or the /ca/{label} route.
        var caLabel = label ?? ToSafeLabel(name);
        ValidateLabel(caLabel);
        if (caLabel.StartsWith("system-", StringComparison.OrdinalIgnoreCase) ||
            caLabel.StartsWith("org-", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"CA label '{caLabel}' uses a reserved prefix (system- / org-). Choose a different label.",
                nameof(label));
        }

        var existingInTenant = await db.CertificateAuthorities
            .AnyAsync(c => c.TenantId == tenantId && c.Label == caLabel);
        if (existingInTenant)
        {
            throw new InvalidOperationException(
                $"A CA with label '{caLabel}' already exists in this tenant.");
        }

        // Export the new child-CA private key ONCE, into a buffer we own and will
        // zero in the finally block. The parent-CA private key is NOT exported here — it is
        // held by the in-registry key handle and signed through a BouncyCastle ISignatureFactory
        // adapter in CreateIntermediateAsync above.
        var newPrivKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(newKeyPair.Private).GetDerEncoded();

        var ksPath = Path.Combine(AppContext.BaseDirectory, "keystores");
        var yamlPath = Path.Combine(AppContext.BaseDirectory, "config", "keystore.yaml");

        var signers = keystore.GetSigners();
        if (signers.Count < 1)
            throw new InvalidOperationException("Need at least 1 signer in registry for keystore operations");

        // Resolve the signer whose public key matches the pinned SPKI for ca-certs.keystore.
        // Bootstrap signs the keystore with the System Signing CA and pins its SPKI. signers[0]
        // is NOT guaranteed to be that CA (it's whatever was first in the keystore file, usually
        // the Root CA). Using the wrong signer causes the post-write verification to fail because
        // the new file's signature doesn't match the pinned SPKI.
        var pinnedSpki = KeystoreService.GetPinnedSignerSpki(db, "ca-certs.keystore");
        CertificateAuthorityIdentity? matchedSigner = null;
        if (pinnedSpki != null)
        {
            foreach (var s in signers)
            {
                var spki = KeystoreService.ComputeSpkiSha256Hex(s.PublicCertificate);
                if (string.Equals(spki, pinnedSpki, StringComparison.OrdinalIgnoreCase))
                {
                    matchedSigner = s;
                    break;
                }
            }
        }
        matchedSigner ??= signers[0];

        var systemSignerKeyHandle = matchedSigner.PrivateKeyHandle ?? throw new InvalidOperationException("System signer private key handle is null");
        // Mirror the CanExport guard used by every other export
        // site so an HSM-backed system signer produces a clear error instead of an opaque
        // NotSupportedException from ExportPrivateKeyDer. Until KeystoreService.AppendEntries
        // accepts an IPrivateKeyHandle directly (deferred refactor), the system signer must
        // be exportable for runtime keystore writes to succeed.
        if (!systemSignerKeyHandle.CanExport)
            throw new NotSupportedException(
                "The system CA signer is backed by a non-exportable key handle (e.g. HSM). " +
                "Runtime keystore signing currently requires an exportable signer — " +
                "a deferred refactor will let KeystoreService.AppendEntries " +
                "accept an IPrivateKeyHandle to support HSM-backed system signers.");
        var systemSignerDer = systemSignerKeyHandle.ExportPrivateKeyDer()
            ?? throw new InvalidOperationException("System signer private key DER export returned null");
        AsymmetricKeyParameter systemSigner;
        try
        {
            systemSigner = PrivateKeyFactory.CreateKey(systemSignerDer);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(systemSignerDer);
            throw;
        }

        CertificateAuthorityEntity caEntity;
        SigningProfileEntity signingProfile;
        X509Certificate tsaCertForKeystore;
        byte[]? tsaPrivKeyDer = null;
        X509Certificate ocspCertForKeystore;
        byte[]? ocspPrivKeyDer = null;

        // Wrap every DB write in a single transaction so a mid-flight failure
        // leaves no orphan rows. Keystore writes must remain OUTSIDE the transaction (file
        // I/O is not transactional) so we defer all AppendEntries calls until after commit.
        // A commit failure rolls back the DB and the keystore is never touched. If the DB
        // commit succeeds but the keystore writes fail, KeystoreFileWriter leaves a .bak of
        // the prior file in place and the catch-handler below unwinds the DB rows.
        await using var tx = await db.Database.BeginTransactionAsync();
        try
        {
            // For self-signed roots, link IssuerCertificateId back to the cert's own row.
            // For intermediates (issued via the pipeline), IssuerCertificateId is already set
            // by CertificateIssuanceService.
            if (parentCertificateId == null)
            {
                certEntity.IssuerCertificateId = certEntity.CertificateId;
                await db.SaveChangesAsync();
            }

            // Create a per-CA signing profile. NameConstraints are populated from the operator-
            // supplied JSON arrays so leaf issuance through this CA carries the same constraints
            // that were just baked into the CA cert above.
            signingProfile = new SigningProfileEntity
            {
                Name = $"{name} Signing Profile",
                Description = $"Default signing profile for {name}",
                IssuerId = certEntity.CertificateId,
                AllowedAlgorithms = JsonSerializer.Serialize(new[] { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" }),
                AllowedEKUs = JsonSerializer.Serialize(new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" }), // ServerAuth, ClientAuth
                NameConstraintsPermitted = string.IsNullOrWhiteSpace(nameConstraintsPermittedJson) ? null : nameConstraintsPermittedJson,
                NameConstraintsExcluded = string.IsNullOrWhiteSpace(nameConstraintsExcludedJson) ? null : nameConstraintsExcludedJson,
                IsDefault = true,
            };
            db.SigningProfiles.Add(signingProfile);
            await db.SaveChangesAsync();

            // [CA-CREATE-DIAG] Capture certEntity.CertificateId and the signing profile's IssuerId at the
            // moment the profile is written, so we can see whether certEntity.CertificateId later changes
            // before it's assigned to the CA entity (which would explain IssuerId != CA.CertificateId).
            logger.LogWarning(
                "[CA-CREATE-DIAG] After signing-profile save for '{Name}': certEntity.CertificateId={CertId} signingProfile.Id={SpId} signingProfile.IssuerId={IssuerId}",
                name, certEntity.CertificateId, signingProfile.Id, signingProfile.IssuerId);

            // Tenant-isolate the signing-profile-to-cert-profile link.
            // Now that CertProfileEntity.TenantId is a real column, only link profiles that
            // (a) are not CA profiles and (b) are either system-wide (TenantId == null) or
            // owned by the same tenant as the new CA. This closes the cross-tenant profile
            // leak.
            var eligibleCertProfiles = await db.CertProfiles
                .IgnoreQueryFilters()
                .Where(cp => !cp.IsCaProfile && (cp.TenantId == null || cp.TenantId == tenantId))
                .ToListAsync();
            foreach (var cp in eligibleCertProfiles)
            {
                db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity
                {
                    CertProfileId = cp.Id,
                    SigningProfileId = signingProfile.Id,
                });
            }
            await db.SaveChangesAsync();

            // Create CertificateAuthorityEntity
            caEntity = new CertificateAuthorityEntity
            {
                CertificateId = certEntity.CertificateId,
                Name = name,
                Label = caLabel,
                Type = caType,
                IsDefault = false,
                IsEnabled = true,
                ParentCaId = parentCaId,
                TenantId = tenantId,
            };
            db.CertificateAuthorities.Add(caEntity);
            await db.SaveChangesAsync();

            // Auto-generate per-CA authorization groups for all capability templates
            var templates = new[]
            {
                ("admin", "Administrator"),
                ("operator", "Operator"),
                ("auditor", "Auditor"),
                ("user", "Requester")
            };

            // Namespace group names with the tenant slug so two tenants can
            // have CAs with the same label without colliding on the CaGroups.Name index.
            var tenantSlug = tenant.Slug;
            var groupsCreated = 0;
            foreach (var (suffix, templateName) in templates)
            {
                // `{tenantSlug}_{caLabel}_{role}` — underscore separators
                // between the three segments remove the hyphen-boundary ambiguity in names
                // like `modularca_modularca-root-cert-1_admin`.
                var groupName = $"{tenantSlug}_{caLabel}_{suffix}";
                // Collisions here are NOT a silent skip anymore — they indicate
                // leftover groups or a reserved-name clash and must abort the creation so
                // the transaction rolls back rather than leaving a CA with fewer auth groups
                // than expected.
                if (await db.CaGroups.AnyAsync(g => g.Name == groupName))
                {
                    throw new InvalidOperationException(
                        $"Auto-generated group name '{groupName}' already exists. " +
                        $"Refusing to create CA '{name}' with fewer than {templates.Length} authorization groups.");
                }

                var group = new CaGroupEntity
                {
                    Name = groupName,
                    DisplayName = $"{name} {templateName}",
                    CertificateAuthorityId = caEntity.Id,
                    TemplateName = templateName,
                    IsSystemGroup = false,
                    IsAutoGenerated = true,
                    RequiredQuorum = 1,
                    TenantId = tenantId,
                    CreatedAt = DateTime.UtcNow
                };
                db.CaGroups.Add(group);
                groupsCreated++;
            }
            if (groupsCreated > 0)
                await db.SaveChangesAsync();

            // Seed capability grants and role assignments for each auto-generated group
            var autoGroups = await db.CaGroups
                .Where(g => g.CertificateAuthorityId == caEntity.Id && g.IsAutoGenerated)
                .ToListAsync();
            foreach (var group in autoGroups)
            {
                RoleAssignmentHelper.AssignBuiltInRoleToGroup(db, group, group.TemplateName!);
            }

            logger.LogInformation("Auto-generated {Count} authorization groups for CA '{Name}' (label={Label})", groupsCreated, name, caLabel);

            // Create CRL schedule for this CA (initial CRL generated after registry registration below)
            await CreateCrlScheduleAsync(certEntity, newCaCert, generateInitial: false);

            // Persist the per-CA public base URL; CDP/OCSP/AIA are auto-generated at cert-build time.
            // Intermediates inherit the parent CA's base URL when the operator didn't supply one.
            await CreateServiceUrlsAsync(certEntity, publicBaseUrl, parentCertificateId);

            // Issue TSA signer and OCSP responder certs through the standard CSR pipeline.
            // Uses the CA-override issuance overload since the CA isn't in the keystore yet.
            var caKeyHandle = new SoftwarePrivateKeyHandle(newKeyPair.Private);

            (tsaCertForKeystore, tsaPrivKeyDer) = await IssueInfrastructureCertAsync(
                newCaCert, newKeyPair.Private, caKeyHandle, caEntity, signingProfile,
                "TSA Certificate Profile", "TSA", logger);

            (ocspCertForKeystore, ocspPrivKeyDer) = await IssueInfrastructureCertAsync(
                newCaCert, newKeyPair.Private, caKeyHandle, caEntity, signingProfile,
                "OCSP Responder Certificate Profile", "OCSP Responder", logger);

            // Seed default protocol configs using the per-CA signing profile
            var defaultCertProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => !cp.IsCaProfile);
            if (defaultCertProfile != null)
            {
                foreach (var protocol in new[] { "ACME", "EST", "SCEP", "CMP", "OCSP" })
                {
                    db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
                    {
                        CaId = caEntity.Id,
                        Protocol = protocol,
                        IsEnabled = true,
                        SigningProfileId = signingProfile.Id,
                        CertProfileId = defaultCertProfile.Id,
                    });
                }
                await db.SaveChangesAsync();
            }

            await tx.CommitAsync();
        }
        catch
        {
            // Roll back the DB transaction. The scrubbed tsaPrivKeyDer buffer (if we got that
            // far) is zeroed in the outer finally block. Keystore files were never touched.
            try { await tx.RollbackAsync(); } catch { /* best-effort */ }
            CryptographicOperations.ZeroMemory(newPrivKeyDer);
            if (tsaPrivKeyDer != null) CryptographicOperations.ZeroMemory(tsaPrivKeyDer);
            if (ocspPrivKeyDer != null) CryptographicOperations.ZeroMemory(ocspPrivKeyDer);
            CryptographicOperations.ZeroMemory(systemSignerDer);
            throw;
        }

        // DB is committed. Now stage the keystore writes outside the transaction.
        // Batch both the new CA key + the TSA key into a single AppendEntries call per keystore
        // file so we only pay one decrypt/re-encrypt/signature-rewrite cost for each store
        // instead of four, and the per-file lock is held exactly once.
        try
        {
            KeystoreService.AppendEntries(
                Path.Combine(ksPath, "ca-certs.keystore"), yamlPath, "ca-certs.keystore",
                new[] { newPrivKeyDer, tsaPrivKeyDer!, ocspPrivKeyDer! }, systemSigner, db);

            KeystoreService.AppendEntries(
                Path.Combine(ksPath, "ca-trust.keystore"), yamlPath, "ca-trust.keystore",
                new[] { newCaCert.GetEncoded(), tsaCertForKeystore.GetEncoded(), ocspCertForKeystore.GetEncoded() }, systemSigner, db);

            logger.LogInformation("Keystore updated with {Type} CA key and cert for {Subject}", caType, name);

            // Emit keystore-mutation audit events. Two entries land in the
            // audit log — one for ca-certs.keystore (new CA private key + TSA private key)
            // and one for ca-trust.keystore (new CA cert + TSA cert). Actor defaults to the
            // system process because CA creation may run under a scheduled workflow or the
            // bootstrap path where there is no authenticated user. Forensic responders need
            // a reliable "who touched the keystore, and when" signal and this is the only
            // runtime emission point for the private-key store.
            if (audit != null)
            {
                try
                {
                    await audit.LogAsync(
                        AuditActionType.KeystoreKeyAdded,
                        actorUserId: null,
                        actorUsername: "system",
                        targetEntityType: "Keystore",
                        targetEntityId: "ca-certs.keystore",
                        details: new
                        {
                            Action = "AppendEntries",
                            CaLabel = caLabel,
                            CaSubject = newCaCert.SubjectDN?.ToString(),
                            CaType = caType,
                            EntryCount = 3,
                            IncludesTsaKey = tsaPrivKeyDer != null,
                            IncludesOcspKey = ocspPrivKeyDer != null,
                        },
                        certificateAuthorityId: caEntity.Id,
                        tenantId: caEntity.TenantId);

                    await audit.LogAsync(
                        AuditActionType.KeystoreKeyAdded,
                        actorUserId: null,
                        actorUsername: "system",
                        targetEntityType: "Keystore",
                        targetEntityId: "ca-trust.keystore",
                        details: new
                        {
                            Action = "AppendEntries",
                            CaLabel = caLabel,
                            CaSubject = newCaCert.SubjectDN?.ToString(),
                            CaType = caType,
                            EntryCount = 3,
                        },
                        certificateAuthorityId: caEntity.Id,
                        tenantId: caEntity.TenantId);
                }
                catch (Exception auditEx)
                {
                    // Audit failure must not break CA creation; AuditService already applies
                    // the FailMode policy. Log-and-continue here is intentional.
                    logger.LogWarning(auditEx,
                        "Keystore audit emission failed for CA '{Name}' (keystore mutation already succeeded)", name);
                }
            }
        }
        catch (Exception ksEx)
        {
            // Keystore write failed after DB commit. Best-effort unwind of the DB
            // rows we just committed so the operator can retry. The .bak file(s) from the
            // atomic-rename path above preserve the pre-image even if the ca-certs.keystore
            // write partially succeeded and the ca-trust.keystore write failed.
            logger.LogError(ksEx,
                "Keystore append failed after DB commit for CA '{Name}'; attempting compensating DB cleanup", name);
            try
            {
                await CompensatePostCommitFailureAsync(certEntity.CertificateId, caEntity.Id, signingProfile.Id);
            }
            catch (Exception compEx)
            {
                logger.LogError(compEx,
                    "Compensating cleanup after keystore failure also failed for CA '{Name}' — manual intervention required", name);
            }
            CryptographicOperations.ZeroMemory(newPrivKeyDer);
            if (tsaPrivKeyDer != null) CryptographicOperations.ZeroMemory(tsaPrivKeyDer);
            if (ocspPrivKeyDer != null) CryptographicOperations.ZeroMemory(ocspPrivKeyDer);
            CryptographicOperations.ZeroMemory(systemSignerDer);
            throw;
        }
        finally
        {
            // Zero the DER buffers we materialised. The AsymmetricKeyParameter systemSigner
            // still holds the decoded scalar in-heap but at least the DER transport copy is gone.
            CryptographicOperations.ZeroMemory(newPrivKeyDer);
            if (tsaPrivKeyDer != null) CryptographicOperations.ZeroMemory(tsaPrivKeyDer);
            if (ocspPrivKeyDer != null) CryptographicOperations.ZeroMemory(ocspPrivKeyDer);
            CryptographicOperations.ZeroMemory(systemSignerDer);
        }

        // Register in runtime registry (must happen after DB commit so a failed commit doesn't
        // leave a stale entry in the registry). CRL generation below needs the key in place.
        var privKeyHandle = new SoftwarePrivateKeyHandle(newKeyPair.Private);
        var identity = new CertificateAuthorityIdentity(newCaCert, privKeyHandle);
        if (keystore is MultiCARegistry registry)
            registry.RegisterSigner(identity);

        // Generate the initial CRL now that the CA key is in the registry.
        try
        {
            await crlService.GenerateCrlAsync(certEntity.CertificateId);
            logger.LogInformation("Initial CRL generated for CA '{Name}'", name);
        }
        catch (Exception ex)
        {
            // A failed INITIAL CRL is non-fatal: the CA is fully persisted, its key is registered,
            // and the CRL scheduler will render one on its next run. We deliberately do NOT unregister
            // the signer here. Unregistering removes a perfectly usable CA key from the runtime
            // registry, which makes the brand-new CA immediately unusable as a signing parent
            // ("Parent CA private key not found in keystore" when creating a sub-CA under it) until the
            // app restarts and reloads the key from the keystore file. A missing first CRL is the far
            // smaller problem and self-heals; an unusable CA does not.
            logger.LogWarning(ex, "Could not generate initial CRL for CA '{Name}' (will be generated on next scheduler run; signer remains registered)", name);
        }

        logger.LogInformation("{Type} CA '{Name}' (label={Label}) created and registered at runtime", caType, name, caLabel);

        // [CA-CREATE-DIAG] Temporary: prove whether the signing profile we just wrote is findable by the
        // SAME predicate the intermediate-creation path uses (sp.IssuerId == parentCert.CertificateId).
        // In memory IssuerId and caEntity.CertificateId are the identical GUID (see assignments above), so
        // if this round-trip lookup against the DB returns FOUND=false, the two char(36) columns compare
        // unequal despite identical text — i.e. a GUID-storage / collation mismatch — which is the systemic
        // cause of "Parent CA signing profile not found". AsNoTracking forces a real DB round-trip rather
        // than an identity-map hit. Remove once the cause is confirmed.
        try
        {
            var roundTripProfileId = await db.SigningProfiles.AsNoTracking()
                .Where(sp => sp.IssuerId == caEntity.CertificateId)
                .Select(sp => (Guid?)sp.Id)
                .FirstOrDefaultAsync();
            logger.LogWarning(
                "[CA-CREATE-DIAG] CA '{Name}': wrote signingProfile.Id={SpId} IssuerId={IssuerId}; caEntity.Id={CaId} CertificateId={CaCertId}. " +
                "Round-trip lookup by (IssuerId == CertificateId) FOUND={Found} (matchedProfileId={Matched}).",
                name, signingProfile.Id, signingProfile.IssuerId, caEntity.Id, caEntity.CertificateId,
                roundTripProfileId != null, roundTripProfileId);
        }
        catch (Exception diagEx)
        {
            logger.LogWarning(diagEx, "[CA-CREATE-DIAG] round-trip signing-profile lookup threw for CA '{Name}'", name);
        }

        return caEntity;
    }

    /// <summary>
    /// Validate a CA label against a strict alphabet before it is ever embedded
    /// in a URL, filesystem path, or DB row. Allowed: lowercase letters, digits, hyphens,
    /// must start with a letter or digit, 1-63 chars.
    /// </summary>
    /// <summary>
    /// Builds a CertificateEntity for a CA certificate (root or intermediate).
    /// Does NOT add to DB — caller is responsible for persisting.
    /// </summary>
    private static CertificateEntity BuildCaCertEntity(X509Certificate cert, Guid? parentCertificateId)
    {
        byte[] sha1hash = SHA1.HashData(cert.GetEncoded());
        byte[] sha256hash = SHA256.HashData(cert.GetEncoded());
        var thumbprints = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            { "SHA 1", BitConverter.ToString(sha1hash).Replace("-", "").ToUpperInvariant() },
            { "SHA 256", BitConverter.ToString(sha256hash).Replace("-", "").ToUpperInvariant() }
        });

        return new CertificateEntity
        {
            SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
            SubjectDN = cert.SubjectDN.ToString(),
            Pem = CertificateUtil.ExportCertificateToPem(cert),
            Issuer = cert.IssuerDN.ToString(),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprints = thumbprints,
            IsCA = true,
            Revoked = false,
            RevocationReason = string.Empty,
            SubjectAlternativeNamesJson = "[]",
            KeyUsagesJson = JsonSerializer.Serialize(new[] { "Digital Signature", "Key Certificate Signing", "CRL Signing" }),
            ExtendedKeyUsagesJson = "[]",
            RawCertificate = cert.GetEncoded(),
            IssuerCertificateId = parentCertificateId,
        };
    }

    private static readonly System.Text.RegularExpressions.Regex LabelPattern =
        new(@"^[a-z0-9][a-z0-9-]{0,62}$", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static void ValidateLabel(string label)
    {
        if (string.IsNullOrEmpty(label) || !LabelPattern.IsMatch(label))
        {
            throw new ArgumentException(
                $"Invalid CA label '{label}'. Labels must match ^[a-z0-9][a-z0-9-]{{0,62}}$.",
                nameof(label));
        }
    }

    private static string ToSafeLabel(string name)
    {
        // Replace spaces with hyphens, lowercase, strip anything outside the allowed set,
        // collapse consecutive hyphens and trim leading/trailing hyphens to match the pattern.
        var lowered = name.ToLowerInvariant().Replace(' ', '-');
        var filtered = new string(lowered.Where(c => char.IsLetterOrDigit(c) || c == '-').ToArray());
        while (filtered.Contains("--"))
            filtered = filtered.Replace("--", "-");
        return filtered.Trim('-');
    }

    /// <summary>
    /// Compensation helper used when the keystore write fails after the DB
    /// transaction has already committed. Deletes the CA row, its signing profile, any
    /// per-CA groups we auto-created, the CRL schedule, and the service URL row. Best
    /// effort: if any step fails the caller logs it for manual cleanup.
    /// </summary>
    private async Task CompensatePostCommitFailureAsync(Guid certificateId, Guid caEntityId, Guid signingProfileId)
    {
        // Remove auto-generated CA groups
        var groups = await db.CaGroups.Where(g => g.CertificateAuthorityId == caEntityId).ToListAsync();
        if (groups.Count > 0) db.CaGroups.RemoveRange(groups);

        // Remove protocol configs
        var protoConfigs = await db.CaProtocolConfigs.Where(p => p.CaId == caEntityId).ToListAsync();
        if (protoConfigs.Count > 0) db.CaProtocolConfigs.RemoveRange(protoConfigs);

        // Remove CRL config
        var crlConfigs = await db.CrlConfigurations.Where(c => c.CaCertificateId == certificateId).ToListAsync();
        if (crlConfigs.Count > 0) db.CrlConfigurations.RemoveRange(crlConfigs);

        // Remove service URLs
        var serviceUrls = await db.CaServiceUrls.Where(s => s.CaCertificateId == certificateId).ToListAsync();
        if (serviceUrls.Count > 0) db.CaServiceUrls.RemoveRange(serviceUrls);

        // Remove cert-profile links
        var links = await db.AllowedCertProfileSigningProfiles.Where(l => l.SigningProfileId == signingProfileId).ToListAsync();
        if (links.Count > 0) db.AllowedCertProfileSigningProfiles.RemoveRange(links);

        // Remove TSA cert row if any
        var ca = await db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == caEntityId);
        Guid? tsaCertId = ca?.TsaCertificateId;

        // Remove CA entity + signing profile + cert row
        if (ca != null) db.CertificateAuthorities.Remove(ca);

        var profile = await db.SigningProfiles.FirstOrDefaultAsync(p => p.Id == signingProfileId);
        if (profile != null) db.SigningProfiles.Remove(profile);

        if (tsaCertId != null)
        {
            var tsaCert = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == tsaCertId.Value);
            if (tsaCert != null) db.Certificates.Remove(tsaCert);
        }

        var cert = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == certificateId);
        if (cert != null) db.Certificates.Remove(cert);

        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Creates a CRL (Certificate Revocation List) schedule for the given CA certificate.
    /// Configures a full CRL generated every 6 hours with a 1-hour overlap period,
    /// plus a delta CRL interval of every hour.
    /// </summary>
    /// <summary>
    /// Creates the CRL schedule configuration for a new CA.
    /// The initial CRL is generated separately after the CA key is registered in the runtime registry.
    /// </summary>
    private async Task CreateCrlScheduleAsync(CertificateEntity caCertEntity, X509Certificate newCaCert, bool generateInitial = false)
    {
        db.CrlConfigurations.Add(new CrlConfigurationEntity
        {
            Name = $"{caCertEntity.SubjectDN} CRL Schedule",
            Description = "Auto-created CRL schedule for new CA",
            IssuerDN = newCaCert.SubjectDN.ToString(),
            CaCertificateId = caCertEntity.CertificateId,
            UpdateInterval = "0 */6 * * *",
            DeltaInterval = "0 * * * *",
            IsDelta = false,
            Enabled = true,
            OverlapPeriod = TimeSpan.FromHours(1),
            LastGenerated = DateTime.UtcNow,
        });
        await db.SaveChangesAsync();
        logger.LogInformation("CRL schedule created for CA '{Subject}'", caCertEntity.SubjectDN);

        if (generateInitial)
        {
            try
            {
                await crlService.GenerateCrlAsync(caCertEntity.CertificateId);
                logger.LogInformation("Initial CRL generated for CA '{Subject}'", caCertEntity.SubjectDN);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Could not generate initial CRL for CA '{Subject}'", caCertEntity.SubjectDN);
            }
        }
    }

    /// <summary>
    /// Persists the per-CA public base URL. CDP, OCSP, and AIA endpoints are always computed on
    /// the fly by <see cref="ICaServiceUrlService.ResolveForCaAsync"/> (<c>{base}/crl/{label}</c>,
    /// <c>{base}/ocsp</c>, <c>{base}/ca/{label}</c>), so the admin can swap the host later
    /// without touching anything else. The base URL is resolved with the following precedence so
    /// that a new CA never silently ends up with no service URLs (and therefore no CDP/AIA in the
    /// certs it issues):
    /// <list type="number">
    ///   <item>the operator-supplied <paramref name="publicBaseUrl"/>, when present;</item>
    ///   <item>for intermediates, the <b>parent CA's</b> public base URL (resolved via
    ///         <paramref name="parentCertificateId"/>) — a child CA shares its parent's
    ///         distribution host by default rather than appearing "lacking" next to its root;</item>
    ///   <item>the default derived from <c>SystemConfig.Https.PublicDomain</c> + <c>Http.PublicPort</c>.</item>
    /// </list>
    /// Roots have no parent, so step 2 is skipped for them.
    /// </summary>
    private async Task CreateServiceUrlsAsync(CertificateEntity caCertEntity, string? publicBaseUrl, Guid? parentCertificateId)
    {
        if (await db.CaServiceUrls.AnyAsync(s => s.CaCertificateId == caCertEntity.CertificateId))
            return;

        string? normalizedBase;
        if (!string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            normalizedBase = publicBaseUrl.TrimEnd('/');
        }
        else
        {
            // Intermediates inherit the parent CA's public base URL when the operator left it blank,
            // so a child CA gets the same CDP/OCSP/AIA host as its root instead of no service URLs.
            string? inherited = null;
            if (parentCertificateId != null)
            {
                inherited = await db.CaServiceUrls
                    .Where(s => s.CaCertificateId == parentCertificateId.Value)
                    .Select(s => s.PublicBaseUrl)
                    .FirstOrDefaultAsync();
            }

            normalizedBase = !string.IsNullOrWhiteSpace(inherited)
                ? inherited.TrimEnd('/')
                : DeriveDefaultPublicBaseUrl();
        }

        db.CaServiceUrls.Add(new CaServiceUrlEntity
        {
            CaCertificateId = caCertEntity.CertificateId,
            PublicBaseUrl = normalizedBase,
        });
        await db.SaveChangesAsync();
        logger.LogInformation(
            "Service URLs created for CA '{Subject}' (base={BaseUrl}, CDP/OCSP/AIA auto-generated at build time)",
            caCertEntity.SubjectDN,
            normalizedBase ?? "<none>");
    }

    /// <summary>
    /// Issues an infrastructure certificate (TSA or OCSP responder) through the standard CSR
    /// pipeline. Generates a CSR, validates against the named cert profile, and issues the cert
    /// via <see cref="ICertificateIssuanceService"/> with the CA-override path.
    /// Returns the signed cert (for keystore) and the DER-encoded private key.
    /// Also links the issued cert to the CA entity via TsaCertificateId or OcspResponderCertificateId.
    /// </summary>
    private async Task<(X509Certificate cert, byte[] privKeyDer)> IssueInfrastructureCertAsync(
        X509Certificate caCert,
        AsymmetricKeyParameter caPrivKey,
        IPrivateKeyHandle caKeyHandle,
        CertificateAuthorityEntity caEntity,
        SigningProfileEntity signingProfile,
        string certProfileName,
        string certType,
        ILogger logger)
    {
        // Resolve key algorithm to match the parent CA
        var (alg, sizeOrCurve) = ResolveTsaKeyAlgorithmForParent(caPrivKey);

        // Extract parent CN for the subject
        var parentCn = certType;
        var parentOids = caCert.SubjectDN.GetOidList();
        var parentValues = caCert.SubjectDN.GetValueList();
        for (int i = 0; i < parentOids.Count; i++)
        {
            if (parentOids[i] is Org.BouncyCastle.Asn1.DerObjectIdentifier oid && oid.Equals(X509Name.CN))
            {
                parentCn = parentValues[i]?.ToString() ?? certType;
                break;
            }
        }
        var subjectDn = $"CN={parentCn} {certType}";

        // Look up the infrastructure cert profile
        var certProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => cp.Name == certProfileName)
            ?? throw new InvalidOperationException($"Infrastructure cert profile '{certProfileName}' not found. Run bootstrap to seed it.");

        // Generate CSR through the standard pipeline
        var (csrId, keyPair) = await csrService.GenerateInfrastructureCsrAsync(
            subjectDn, alg, sizeOrCurve, certProfile.Id, signingProfile.Id);

        // Issue through the standard pipeline with pre-resolved CA
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.AddYears(10);
        if (notAfter > caCert.NotAfter)
            notAfter = caCert.NotAfter;

        var result = await issuanceService.IssueCertificateAsync(
            csrId, notBefore, notAfter, caCert, caKeyHandle);

        // Parse the issued cert PEM for keystore writing
        var issuedCert = CertificateUtil.ParseFromPem(result.Pem);

        // Link to the CA entity
        var csrEntity = await db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == csrId);
        if (csrEntity?.IssuedCertificateId != null)
        {
            if (certType == "TSA")
                caEntity.TsaCertificateId = csrEntity.IssuedCertificateId;
            else if (certType == "OCSP Responder")
                caEntity.OcspResponderCertificateId = csrEntity.IssuedCertificateId;
            await db.SaveChangesAsync();
        }

        // {Subject} is the full Subject DN, which already begins with "CN=" — don't prefix another
        // "CN=" here or the log reads "(CN=CN=... TSA)".
        logger.LogInformation("{CertType} certificate issued for CA '{CaName}' via standard pipeline (subject={Subject})",
            certType, caEntity.Name, issuedCert.SubjectDN);

        var privKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded();
        return (issuedCert, privKeyDer);
    }

    /// <summary>
    /// Derives the default public base URL from <c>SystemConfig.Https.PublicDomain</c> and
    /// <c>Http.Port</c>/<c>Http.PublicPort</c>. CDP/OCSP/AIA are served over HTTP, so the
    /// base URL uses the HTTP scheme. Returns null when PublicDomain is not configured.
    /// </summary>
    private string? DeriveDefaultPublicBaseUrl()
    {
        if (string.IsNullOrWhiteSpace(systemConfig.Https.PublicDomain))
            return null;

        return systemConfig.Https.GetPublicHttpBaseUrl(
            systemConfig.Http.Port,
            systemConfig.Http.PublicPort);
    }

    // NOTE: CreateAndStoreTsaCertificateAsync and CreateAndStoreOcspResponderCertificateAsync
    // have been replaced by IssueInfrastructureCertAsync which routes through the standard
    // CSR → profile validation → CertificateIssuanceService pipeline.

    /// <summary>
    /// Choose an infrastructure key algorithm compatible with the parent CA. For classical CAs
    /// (RSA, ECDSA, Ed25519, Ed448) the TSA gets the same family. For PQC CAs (ML-DSA, SLH-DSA)
    /// the TSA also uses a PQC key so the time-stamp chain remains PQ-secure end-to-end.
    /// </summary>
    private static (string alg, int sizeOrCurve) ResolveTsaKeyAlgorithmForParent(AsymmetricKeyParameter parentKey)
    {
        return parentKey switch
        {
            RsaPrivateCrtKeyParameters or RsaKeyParameters => ("RSA", 3072),
            ECPrivateKeyParameters => ("ECDSA", 256), // P-256
            Ed25519PrivateKeyParameters => ("Ed25519", 0),
            Ed448PrivateKeyParameters => ("Ed448", 0),
            MLDsaPrivateKeyParameters => ("ML-DSA-65", 0),
            SlhDsaPrivateKeyParameters => ("SLH-DSA-SHA2-128F", 0),
            // Safe default for any key type not enumerated above.
            _ => ("ECDSA", 256)
        };
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(string keyAlgorithm, int keySize)
        => KeyAlgorithmPolicy.GenerateKeyPair(keyAlgorithm, keySize);

    private static X509Name BuildSubjectDN(string cn, string? o, string? ou, string? l, string? st, string? c)
    {
        var parts = new List<string> { $"CN={cn}" };
        if (!string.IsNullOrWhiteSpace(o)) parts.Add($"O={o}");
        if (!string.IsNullOrWhiteSpace(ou)) parts.Add($"OU={ou}");
        if (!string.IsNullOrWhiteSpace(l)) parts.Add($"L={l}");
        if (!string.IsNullOrWhiteSpace(st)) parts.Add($"ST={st}");
        if (!string.IsNullOrWhiteSpace(c)) parts.Add($"C={c}");
        return new X509Name(string.Join(",", parts));
    }

}
