using ModularCA.Shared.Errors;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
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
/// Creates Certificate Authorities at runtime: has the signer generate the key, signs the CA
/// certificate through it (self-signed for a root, by the parent for an intermediate), persists
/// the rows, and commits the key to its certificate so the signer holds and registers it.
/// </summary>
/// <remarks>
/// No private key passes through this service. A new key is generated inside the signer under
/// the ceremony context and held pending there: it signs the CA certificate or CSR and the
/// CA's infrastructure certificates under that context only, and is written nowhere. Once the
/// database transaction that names the CA has committed, each key is committed to its
/// certificate row, which is when the signer appends it to the keystore and registers the
/// identity. A failure anywhere before that retires the pending keys, so nothing usable is left
/// behind; a failure while committing compensates the rows as a failed keystore write always has.
/// </remarks>
public class CaCreationService(
    ModularCADbContext db,
    ICrlService crlService,
    ICaServiceUrlService caServiceUrls,
    ICsrService csrService,
    ICertificateIssuanceService issuanceService,
    SystemConfig systemConfig,
    ILogger<CaCreationService> logger,
    IQuotaService quotaService,
    ISigningService signer,
    IAuditService? audit = null)
{
    /// <summary>The caller identity CA creation asks the signer under; the signer audits it with every decision.</summary>
    private const string SignerCaller = nameof(CaCreationService);

    /// <summary>
    /// Whether the signer holds the key of certificate <paramref name="certificateId"/> among
    /// the keys of <paramref name="ca"/>. Asked before a CA is used as a parent or as the issuer
    /// of a new infrastructure certificate, so a missing key is reported as it was when the
    /// keystore was consulted directly.
    /// </summary>
    private async Task<bool> SignerHoldsKeyAsync(CertificateAuthorityEntity ca, Guid certificateId)
    {
        var keys = await signer.ListKeysAsync(SigningContext.ForCa(SignerCaller, SigningPurpose.Certificate, ca.Id, ca.TenantId));
        return keys.Any(k => k.Key.CertificateId == certificateId);
    }

    /// <summary>
    /// Retires pending keys after a failure, best-effort: the failure that is being unwound is
    /// the one to report, and a key that cannot be retired is logged, not thrown.
    /// </summary>
    private async Task RetireQuietlyAsync(SigningContext ceremony, params KeyRef?[] keys)
    {
        foreach (var key in keys)
        {
            if (key == null) continue;
            try
            {
                await signer.RetireKeyAsync(key, ceremony);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Pending key {Key} could not be retired after a failed CA operation.", key);
            }
        }
    }

    /// <summary>
    /// Commits each generated key to its certificate in order. If one fails, the keys not yet
    /// committed are retired, and the failure propagates for the caller to compensate.
    /// </summary>
    private async Task CommitKeysAsync(SigningContext ceremony, IReadOnlyList<(KeyRef Key, Guid CertificateId)> keys)
    {
        for (var i = 0; i < keys.Count; i++)
        {
            try
            {
                await signer.CommitKeyAsync(keys[i].Key, keys[i].CertificateId, ceremony);
            }
            catch
            {
                await RetireQuietlyAsync(ceremony, keys.Skip(i).Select(k => (KeyRef?)k.Key).ToArray());
                throw;
            }
        }
    }
    /// <summary>
    /// Blocks CA creation when the owning tenant has reached its
    /// <c>MaxCertificateAuthorities</c> limit. Previously the value was stored on the
    /// tenant and echoed by the admin UI but never consulted by either creation path,
    /// so operators thought they had a cap when in fact there wasn't one.
    /// </summary>
    private async Task EnforceTenantCaQuotaAsync(Guid tenantId)
    {
        if (!await quotaService.CanCreateCaInTenantAsync(tenantId))
            throw new ResourceConflictException("Tenant CA quota exceeded.", ErrorCodes.QuotaExceeded);
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
    /// <paramref name="ceremonyId"/> is the approved key ceremony this creation executes, when
    /// the tenant required one; the signer verifies it before it generates or commits a key.
    /// </summary>
    public async Task<CertificateAuthorityEntity> CreateRootAsync(
        string subjectCN, string? subjectO, string? subjectOU,
        string? subjectL, string? subjectST, string? subjectC,
        string keyAlgorithm, int keySize, int validityYears, string? label,
        Guid tenantId,
        string? publicBaseUrl = null,
        string? nameConstraintsPermittedJson = null,
        string? nameConstraintsExcludedJson = null,
        Guid? ceremonyId = null)
    {
        await EnforceTenantCaQuotaAsync(tenantId);

        // The key is generated inside the signer and held pending under this ceremony context:
        // it signs only under it until it is committed to the certificate row, and is retired
        // if anything fails before then. The ceremony's id rides the context so the signer can
        // verify the approval itself.
        var ceremony = new SigningContext(SignerCaller, SigningPurpose.Ceremony, tenantId, null, ceremonyId);
        var generated = await signer.GenerateKeyAsync(
            new KeySpec(keyAlgorithm, KeyAlgorithmPolicy.FormatKeySizeForProfile(keyAlgorithm, keySize)), ceremony);
        X509Certificate newCaCert;
        CertificateEntity certEntity;
        try
        {
            (newCaCert, certEntity) = await SelfSignRootAsync(generated, ceremony,
                subjectCN, subjectO, subjectOU, subjectL, subjectST, subjectC,
                keyAlgorithm, keySize, validityYears, nameConstraintsPermittedJson, nameConstraintsExcludedJson);
        }
        catch
        {
            await RetireQuietlyAsync(ceremony, generated.Key);
            throw;
        }

        return await PersistAndRegisterAsync(
            certEntity, newCaCert, generated.Key, ceremony, subjectCN, label,
            tenantId: tenantId,
            caType: "Root", parentCaId: null,
            parentCertificateId: null,
            publicBaseUrl: publicBaseUrl,
            nameConstraintsPermittedJson: nameConstraintsPermittedJson,
            nameConstraintsExcludedJson: nameConstraintsExcludedJson);
    }

    /// <summary>
    /// Builds the self-signed root certificate over the public half of the generated key, signs
    /// it through the signer with the pending key under the ceremony context, and stores its
    /// row. Self-signed roots cannot go through the pipeline (no parent signing profile).
    /// </summary>
    private async Task<(X509Certificate Certificate, CertificateEntity Entity)> SelfSignRootAsync(
        GeneratedKey generated, SigningContext ceremony,
        string subjectCN, string? subjectO, string? subjectOU,
        string? subjectL, string? subjectST, string? subjectC,
        string keyAlgorithm, int keySize, int validityYears,
        string? nameConstraintsPermittedJson, string? nameConstraintsExcludedJson)
    {
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var subjectDN = BuildSubjectDN(subjectCN, subjectO, subjectOU, subjectL, subjectST, subjectC);

        // 17 bytes with a forced 0x00 high byte guarantees a positive
        // BigInteger while preserving a full 128 bits of randomness in the magnitude.
        var serialBytes = new byte[17];
        serialBytes[0] = 0x00;
        RandomNumberGenerator.Fill(serialBytes.AsSpan(1));
        var serial = new BigInteger(1, serialBytes);
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var notAfter = DateTime.UtcNow.AddYears(validityYears);

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(subjectDN);   // Self-signed: issuer = subject
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(publicKey);

        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

        var subPubKeyInfo = SubjectPublicKeyInfo.GetInstance(generated.PublicKeyDer);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(subPubKeyInfo));

        // AKI = own SKI for self-signed
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(subPubKeyInfo));

        // Routed through the shared rules rather than trusting the literal above. This is the
        // third place in the solution that builds a cA=TRUE certificate (the others being
        // BouncyCastleCertificateAuthority for the bootstrap root and CertificateBuilderService
        // for intermediates), and it is the path an operator actually takes to create a root at
        // runtime. The bits here are hardcoded and correct today, so both calls are no-ops — the
        // point is that a later edit to this list cannot silently produce a non-compliant root.
        const string rootUsageDescription = "digitalSignature, keyCertSign, cRLSign";
        var rootUsageFlags = CaCertificateRules.ApplyRequiredKeyUsages(
            isCa: true,
            KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature,
            out _);
        CaCertificateRules.EnsureKeyUsagesPermitted(true, rootUsageFlags, new[] { rootUsageDescription });

        certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(rootUsageFlags));

        // NameConstraints (critical) — bake the operator-supplied permitted /
        // excluded subtree lists into the CA cert at build time. The same JSON payloads
        // are also copied onto the per-CA signing profile in PersistAndRegisterAsync so
        // downstream issuance honours the same constraints.
        var nameConstraints = CertificateBuilderService.BuildNameConstraints(nameConstraintsPermittedJson, nameConstraintsExcludedJson);
        if (nameConstraints != null)
        {
            certGen.AddExtension(X509Extensions.NameConstraints, true, nameConstraints);
        }

        // Self-sign through the signer with the pending key. Route through KeyAlgorithmPolicy so
        // the curve/hash pairing is centralised (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
        var sigAlgName = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySize);
        var signatureFactory = new SigningServiceSignatureFactory(signer, generated.Key, SignatureAlgorithm.FromName(sigAlgName), ceremony);
        var newCaCert = certGen.Generate(signatureFactory);

        // Build and store the cert entity directly, then register the CA.
        var certEntity = BuildCaCertEntity(newCaCert, parentCertificateId: null);
        db.Certificates.Add(certEntity);
        await db.SaveChangesAsync();
        return (newCaCert, certEntity);
    }

    /// <summary>
    /// Creates a new intermediate CA signed by the specified parent CA. Generates a key pair,
    /// builds the CA certificate signed by the parent, stores it in DB and keystore,
    /// creates the CertificateAuthorityEntity, seeds protocol configs, and registers at runtime.
    /// Optional <paramref name="nameConstraintsPermittedJson"/> /
    /// <paramref name="nameConstraintsExcludedJson"/> are baked into the cert's NameConstraints
    /// extension AND copied onto the per-CA signing profile so downstream issuance honours
    /// the same constraints. <paramref name="ceremonyId"/> is the approved key ceremony this
    /// creation executes, when the tenant required one; the signer verifies it before it
    /// generates or commits a key.
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
        string? nameConstraintsExcludedJson = null,
        Guid? ceremonyId = null)
    {
        await EnforceTenantCaQuotaAsync(tenantId);

        var parentBcCert = CertificateUtil.ParseFromPem(parentCert.Pem);
        if (!await SignerHoldsKeyAsync(parentCa, parentCert.CertificateId))
            throw new InvalidOperationException("Parent CA private key not found in keystore");

        // Resolve parent CA's signing profile for the issuance pipeline
        var parentSigningProfile = await db.SigningProfiles
            .FirstOrDefaultAsync(sp => sp.IssuerId == parentCert.CertificateId)
            ?? throw new InvalidOperationException("Parent CA signing profile not found.");

        // Look up the CA cert profile — use the operator-selected profile or fall back to default
        CertProfileEntity caCertProfile;
        if (certProfileId.HasValue)
        {
            caCertProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => cp.Id == certProfileId.Value && cp.IsCaProfile)
                ?? throw new ResourceNotFoundException(
                    "Certificate profile",
                    $"CA Certificate Profile '{certProfileId}' not found or is not a CA profile.",
                    certProfileId?.ToString());
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

        // The intermediate's key is generated inside the signer and held pending under this
        // ceremony context; it signs the CSR under it, and is retired if anything fails before
        // it is committed to the issued certificate. The ceremony's id rides the context so the
        // signer can verify the approval itself.
        var ceremony = new SigningContext(SignerCaller, SigningPurpose.Ceremony, tenantId, null, ceremonyId);
        var generated = await signer.GenerateKeyAsync(
            new KeySpec(keyAlgorithm, KeyAlgorithmPolicy.FormatKeySizeForProfile(keyAlgorithm, keySize)), ceremony);

        IssuanceResult result;
        Guid csrId;
        CertificateEntity? certEntity;
        try
        {
        try
        {
            if (!string.IsNullOrWhiteSpace(nameConstraintsPermittedJson))
                parentSigningProfile.NameConstraintsPermitted = nameConstraintsPermittedJson;
            if (!string.IsNullOrWhiteSpace(nameConstraintsExcludedJson))
                parentSigningProfile.NameConstraintsExcluded = nameConstraintsExcludedJson;
            parentSigningProfile.MaxPathLength = 0; // pathLenConstraint=0 for intermediates

            // Build subject DN
            var subjectDnStr = BuildSubjectDN(subjectCN, subjectO, subjectOU, subjectL, subjectST, subjectC).ToString();

            // Generate the CSR over the pending key, signed through the signer, and issue it
            // through the standard pipeline: the parent is a registered CA whose key the signer
            // holds, so issuance resolves it by row like any other certificate.
            var csrSigner = new SigningServiceSignatureFactory(signer, generated.Key,
                SignatureAlgorithm.FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySize)), ceremony);
            csrId = await csrService.GenerateInfrastructureCsrAsync(
                subjectDnStr, keyAlgorithm, keySize, caCertProfile.Id, parentSigningProfile.Id,
                PublicKeyFactory.CreateKey(generated.PublicKeyDer), csrSigner);

            var notBefore = CertificateValidityUtil.DefaultNotBefore();
            var notAfter = notBefore.AddYears(validityYears);
            if (notAfter > parentBcCert.NotAfter)
            {
                logger.LogWarning(
                    "Intermediate CA '{Name}' requested validity until {Requested:O} but parent CA expires {ParentExpiry:O}; clamping to parent expiry.",
                    subjectCN, notAfter, parentBcCert.NotAfter);
                notAfter = parentBcCert.NotAfter;
            }

            result = await issuanceService.IssueCaCertificateAsync(csrId, notBefore, notAfter);
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
        certEntity = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == csrEntity!.IssuedCertificateId);
        if (certEntity == null)
            throw new InvalidOperationException("Issued intermediate CA certificate not found in database.");
        }
        catch
        {
            await RetireQuietlyAsync(ceremony, generated.Key);
            throw;
        }

        var newCaCert = CertificateUtil.ParseFromPem(result.Pem);

        return await PersistAndRegisterAsync(
            certEntity, newCaCert, generated.Key, ceremony, subjectCN, label,
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
    /// insert for self-signed roots). The keys are committed to the signer after DB commit:
    /// <paramref name="caKey"/> is the pending key the signer generated under
    /// <paramref name="ceremony"/>, and the infrastructure keys are generated the same way here.
    /// </summary>
    private async Task<CertificateAuthorityEntity> PersistAndRegisterAsync(
        CertificateEntity certEntity,
        X509Certificate newCaCert,
        KeyRef caKey,
        SigningContext ceremony,
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
            throw new ResourceNotFoundException(
                "Tenant", $"Tenant '{tenantId}' not found or is disabled.", tenantId.ToString());

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
            throw new ResourceConflictException(
                $"A CA with label '{caLabel}' already exists in this tenant.", ErrorCodes.NameAlreadyTaken);
        }

        CertificateAuthorityEntity caEntity;
        SigningProfileEntity signingProfile;
        X509Certificate tsaCert;
        Guid tsaCertificateId;
        X509Certificate ocspCert;
        Guid ocspCertificateId;
        KeyRef? tsaKey = null;
        KeyRef? ocspKey = null;

        // Wrap every DB write in a single transaction so a mid-flight failure
        // leaves no orphan rows. The keys stay pending in the signer (file I/O is not
        // transactional) until after commit, when each is committed to its certificate. A
        // commit failure rolls back the DB and retires the pending keys, so the keystore is never
        // touched. If the DB commit succeeds but a key cannot be committed, the signer's append
        // path leaves a .bak of the prior file in place and the catch-handler below unwinds the
        // DB rows.
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
                // ServerAuth, ClientAuth — plus the two EKUs this CA needs to issue its OWN
                // infrastructure certificates.
                //
                // IssueInfrastructureCertAsync issues this CA's OCSP responder and TSA
                // certificates through this very signing profile, and issuance intersects the
                // cert profile's requested EKU against this allow-list. With only ServerAuth and
                // ClientAuth here, the intersection for "OCSP Responder Certificate Profile"
                // (which asks for OCSPSigning) was empty, the EKU was silently dropped, and the
                // CA issued itself a responder certificate lacking id-kp-OCSPSigning — which
                // OcspResponderService then refuses to use. Every CA created at runtime answered
                // OCSP with "unauthorized" as a result. Bootstrap-created CAs were unaffected
                // because their signing profile is seeded from the full EKU list.
                // Matches the six EKUs the bootstrap seeder grants its root
                // (BootstrapModularCA.cs: allowedRootCaExtendedOids). A CA created through the
                // admin UI should be able to issue exactly what a bootstrap-created CA can —
                // anything narrower silently drops usages the cert profile asked for, which the
                // operator only discovers when a certificate turns out to lack them.
                AllowedEKUs = JsonSerializer.Serialize(new[]
                {
                    "1.3.6.1.5.5.7.3.1",  // serverAuth
                    "1.3.6.1.5.5.7.3.2",  // clientAuth
                    "1.3.6.1.5.5.7.3.3",  // codeSigning
                    "1.3.6.1.5.5.7.3.4",  // emailProtection
                    "1.3.6.1.5.5.7.3.8",  // timeStamping   — also this CA's own TSA certificate
                    "1.3.6.1.5.5.7.3.9",  // OCSPSigning    — also this CA's own OCSP responder
                }),
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
                    throw new ResourceConflictException(
                        $"Auto-generated group name '{groupName}' already exists. " +
                        $"Refusing to create CA '{name}' with fewer than {templates.Length} authorization groups.", ErrorCodes.NameAlreadyTaken);
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

            // Issue TSA signer and OCSP responder certs through the standard CSR pipeline. The
            // new CA signs them with its pending key under the ceremony context: its row is not
            // committed yet, so the signer could not attribute a signature to it by row.
            (tsaCert, tsaCertificateId, tsaKey) = await IssueInfrastructureCertAsync(
                newCaCert, caKey, ceremony, caEntity, signingProfile,
                "TSA Certificate Profile", "TSA", logger);

            (ocspCert, ocspCertificateId, ocspKey) = await IssueInfrastructureCertAsync(
                newCaCert, caKey, ceremony, caEntity, signingProfile,
                "OCSP Responder Certificate Profile", "OCSP Responder", logger);

            // Seed default protocol configs using the per-CA signing profile
            var defaultCertProfile = await db.CertProfiles.FirstOrDefaultAsync(cp => !cp.IsCaProfile);
            if (defaultCertProfile != null)
            {
                foreach (var protocol in new[] { "ACME", "EST", "SCEP", "CMP", "MSAE", "OCSP" })
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
            // Roll back the DB transaction and discard every pending key: nothing was written to
            // the keystore, and a pending key signs under nothing but this ceremony.
            try { await tx.RollbackAsync(); } catch { /* best-effort */ }
            await RetireQuietlyAsync(ceremony, caKey, tsaKey, ocspKey);
            throw;
        }

        // DB is committed. Now commit the keys to their certificates: the signer appends each
        // key and certificate to the keystore files and registers the identity, so the CA signs
        // and its responder and TSA answer without a restart.
        try
        {
            await CommitKeysAsync(ceremony, new[]
            {
                (caKey, certEntity.CertificateId),
                (tsaKey, tsaCertificateId),
                (ocspKey, ocspCertificateId),
            });

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
                            IncludesTsaKey = true,
                            IncludesOcspKey = true,
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
            throw;
        }

        // Committing each key registered its identity with the runtime registry, so the CA signs
        // and its responder and TSA answer without a restart; the initial CRL below needs that.
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


    /// <summary>
    /// Reissues a CA's delegated OCSP responder and/or TSA certificate, repoints the CA at the
    /// new certificate, writes the new key into the keystore, and registers the identity with the
    /// runtime registry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This capability was missing, and its absence turned an ordinary maintenance action into an
    /// outage. <c>CertificateAuthorityEntity.OcspResponderCertificateId</c> and
    /// <c>TsaCertificateId</c> were written in exactly two places — bootstrap, and CA creation —
    /// so reissuing a responder through the GENERIC certificate-reissue flow revoked the old
    /// certificate, issued a replacement, and left the CA still pointing at the revoked one.
    /// </para>
    /// <para>
    /// The OCSP resolver loads the responder with a query that filters on <c>!c.Revoked</c>, gets
    /// null, and returns <c>ResponderInvalid</c> — which deliberately refuses to fall back to
    /// CA-direct signing, because a configured responder means the operator intended it to be
    /// used. Every OCSP request for that CA then answers <c>unauthorized</c>, and a restart does
    /// not help: the stale pointer is in the database, not in the in-memory registry.
    /// </para>
    /// <para>
    /// Reissue is therefore the whole operation — issue, repoint, persist the key, register — not
    /// just the issuance. Each of those four steps is a way this has already gone wrong.
    /// </para>
    /// </remarks>
    /// <param name="caId">The CA whose infrastructure certificates should be reissued.</param>
    /// <param name="reissueOcsp">Reissue the delegated OCSP responder.</param>
    /// <param name="reissueTsa">Reissue the TSA signer.</param>
    /// <param name="reissueCmpSigner">
    /// Issue or reissue the dedicated CMP message-signing certificate. Unlike the other two this
    /// is not issued at CA creation: most CAs never serve CMP, and a signer that exists is a
    /// signer that must be rotated. Without one, signature-protected CMP responses are signed
    /// with the CA certificate, which OpenSSL rejects as a message signer.
    /// </param>
    /// <param name="revokeSuperseded">
    /// Revoke the certificate being replaced when it is still valid. Default true: two
    /// simultaneously-valid responders for one CA is not a state worth having to reason about.
    /// An already-revoked predecessor is left alone, because re-revoking would overwrite a real
    /// revocation date and reason with "Superseded" and lose why it was revoked.
    /// </param>
    public async Task<InfrastructureReissueResult> ReissueInfrastructureCertsAsync(
        Guid caId,
        bool reissueOcsp,
        bool reissueTsa,
        bool revokeSuperseded = true,
        bool reissueCmpSigner = false)
    {
        if (!reissueOcsp && !reissueTsa && !reissueCmpSigner)
            throw new ArgumentException("Nothing to reissue: select the OCSP responder, the TSA, the CMP signer, or any combination.");

        var caEntity = await db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == caId && !c.IsDeleted)
            ?? throw new ResourceNotFoundException(
                "Certificate authority", "Certificate authority not found.", caId.ToString());

        if (caEntity.IsSshCa)
            throw new ConfigurationValidationException("SSH CAs have no OCSP responder, TSA or CMP signer certificate.");

        var caCertEntity = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == caEntity.CertificateId)
            ?? throw new InvalidOperationException("CA certificate row not found.");
        if (caCertEntity.Revoked)
            throw new ConfigurationValidationException(
                "This CA is revoked. Reissuing its responder would produce a certificate no relying party will accept.", ErrorCodes.IssuingCaRevoked);

        var caCert = CertificateUtil.ParseFromPem(caCertEntity.Pem);

        // The CA's own signing key must be held by the signer — the new certificates are signed
        // with it.
        if (!await SignerHoldsKeyAsync(caEntity, caCertEntity.CertificateId))
            throw new ConfigurationValidationException(
                "No private key is available for this CA, so it cannot sign a new responder certificate.", ErrorCodes.IssuingCaKeyUnavailable);
        var caKey = new KeyRef(caCertEntity.CertificateId);
        var caSigningContext = SigningContext.ForCa(SignerCaller, SigningPurpose.Certificate, caEntity.Id, caEntity.TenantId);
        // Reissuing a CA's delegated signers is an operator's action on an existing CA, not a
        // ceremony: the keys are generated under the infrastructure context and can never become CA keys.
        var ceremony = new SigningContext(SignerCaller, SigningPurpose.Infrastructure, caEntity.TenantId, caEntity.Id);

        // A CA's signing profile is linked by IssuerId pointing at the CA's certificate, the same
        // way the creation path resolves a parent's profile.
        var signingProfile = await db.SigningProfiles
            .FirstOrDefaultAsync(sp => sp.IssuerId == caEntity.CertificateId)
            ?? throw new ConfigurationValidationException(
                "Signing profile for this CA not found. The CA cannot issue an infrastructure "
                + "certificate until a signing profile is linked to it.");

        // Check the profile permits what we are about to mint BEFORE issuing or revoking
        // anything. Reissuing into a profile that forbids the usage produced a certificate that
        // could never work, having already revoked the one it replaced.
        EnsureSigningProfilePermitsInfrastructureEkus(signingProfile, reissueOcsp, reissueTsa);

        // The CMP signer profile is created on first use so installs that predate it need no
        // migration; the seeder creates the same row on fresh installs.
        if (reissueCmpSigner)
            await EnsureCmpSignerProfileAsync();

        // Captured before IssueInfrastructureCertAsync overwrites them.
        var previousOcspId = caEntity.OcspResponderCertificateId;
        var previousTsaId = caEntity.TsaCertificateId;
        var previousCmpId = caEntity.CmpSigningCertificateId;

        X509Certificate? newTsaCert = null, newOcspCert = null, newCmpCert = null;
        var newKeys = new List<(KeyRef Key, Guid CertificateId)>();

        try
        {
            // IssueInfrastructureCertAsync chooses the new subject key's algorithm from the CA
            // certificate's public key; the CA key itself stays with the signer.
            if (reissueTsa)
            {
                var (cert, certificateId, key) = await IssueInfrastructureCertAsync(
                    caCert, caKey, caSigningContext, caEntity, signingProfile,
                    "TSA Certificate Profile", "TSA", logger);
                newTsaCert = cert;
                newKeys.Add((key, certificateId));
            }

            if (reissueOcsp)
            {
                var (cert, certificateId, key) = await IssueInfrastructureCertAsync(
                    caCert, caKey, caSigningContext, caEntity, signingProfile,
                    "OCSP Responder Certificate Profile", "OCSP Responder", logger);
                newOcspCert = cert;
                newKeys.Add((key, certificateId));
            }
            if (reissueCmpSigner)
            {
                var (cert, certificateId, key) = await IssueInfrastructureCertAsync(
                    caCert, caKey, caSigningContext, caEntity, signingProfile,
                    CmpSignerProfileName, CmpSignerCertType, logger);
                newCmpCert = cert;
                newKeys.Add((key, certificateId));
            }

            // What came out of issuance is the only thing that matters to a relying party, so
            // check the certificate itself and not just the profile it was issued under.
            if (newTsaCert != null) EnsureIssuedCertCarriesEku(newTsaCert, IdKpTimeStampingOid, "TSA");
            if (newOcspCert != null) EnsureIssuedCertCarriesEku(newOcspCert, IdKpOcspSigningOid, "OCSP Responder");
            // The CMP signer needs no EKU, but it is useless without digitalSignature: that bit is
            // the whole reason it exists rather than the CA certificate signing directly.
            if (newCmpCert != null) EnsureIssuedCertCarriesDigitalSignature(newCmpCert, CmpSignerCertType);
        }
        catch
        {
            // A failure above leaves no orphaned key: the pending keys are retired and were never
            // written anywhere.
            await RetireQuietlyAsync(ceremony, newKeys.Select(k => (KeyRef?)k.Key).ToArray());
            throw;
        }

        // Commit the keys to their certificates after issuance. The signer appends each key and
        // certificate to the keystore files and registers the identity, so the responder works
        // immediately: without the registration the key would be in the keystore FILE but not in
        // the singleton the resolver consults, and OCSP would answer unauthorized until a restart.
        await CommitKeysAsync(ceremony, newKeys);

        var supersededRevoked = new List<string>();
        if (revokeSuperseded)
        {
            foreach (var (oldId, wasReissued) in new[] { (previousOcspId, reissueOcsp), (previousTsaId, reissueTsa), (previousCmpId, reissueCmpSigner) })
            {
                if (!wasReissued || oldId == null) continue;
                var old = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == oldId);
                if (old == null || old.Revoked) continue;
                old.Revoked = true;
                old.RevocationDate = DateTime.UtcNow;
                old.RevocationReason = nameof(RevocationReason.Superseded);
                supersededRevoked.Add(old.SerialNumber);
            }
            if (supersededRevoked.Count > 0)
                await db.SaveChangesAsync();
        }

        logger.LogInformation(
            "Infrastructure certificates reissued for CA {Label}: ocsp={Ocsp} tsa={Tsa} cmp={Cmp} supersededRevoked={Count}",
            caEntity.Label, reissueOcsp, reissueTsa, reissueCmpSigner, supersededRevoked.Count);

        return new InfrastructureReissueResult(
            caEntity.Label ?? caEntity.Name,
            newOcspCert == null ? null : CertificateUtil.FormatSerialNumber(newOcspCert.SerialNumber),
            newTsaCert == null ? null : CertificateUtil.FormatSerialNumber(newTsaCert.SerialNumber),
            supersededRevoked,
            newCmpCert == null ? null : CertificateUtil.FormatSerialNumber(newCmpCert.SerialNumber));
    }

    /// <summary>
    /// Outcome of <see cref="CaCreationService.ReissueInfrastructureCertsAsync"/>.
    /// </summary>
    /// <param name="CaLabel">The CA that was operated on.</param>
    /// <param name="NewOcspResponderSerial">Serial of the new OCSP responder, or null if not reissued.</param>
    /// <param name="NewTsaSerial">Serial of the new TSA certificate, or null if not reissued.</param>
    /// <param name="SupersededSerialsRevoked">
    /// Serials of predecessors revoked as Superseded. Excludes ones that were already revoked.
    /// </param>
    /// <param name="NewCmpSignerSerial">Serial of the new CMP signer, or null if not reissued.</param>
    public record InfrastructureReissueResult(
        string CaLabel,
        string? NewOcspResponderSerial,
        string? NewTsaSerial,
        IReadOnlyList<string> SupersededSerialsRevoked,
        string? NewCmpSignerSerial = null);



    // OIDs the infrastructure certificates are useless without.
    private const string IdKpOcspSigningOid = "1.3.6.1.5.5.7.3.9";
    private const string IdKpTimeStampingOid = "1.3.6.1.5.5.7.3.8";

    /// <summary>Name of the seeded certificate profile the CMP signer is issued under.</summary>
    public const string CmpSignerProfileName = "CMP Signer Certificate Profile";

    /// <summary>The certType tag that routes an issued infrastructure certificate to <c>CmpSigningCertificateId</c>.</summary>
    internal const string CmpSignerCertType = "CMP Signer";

    /// <summary>
    /// Creates the CMP signer certificate profile when an install predates it.
    /// </summary>
    /// <remarks>
    /// The seeder creates this row on fresh installs; existing installs would otherwise need a
    /// data migration that hand-writes a CertProfiles row, and every column that row needs is
    /// easier to get right here, with the same catalog lookup the seeder uses. Keep the two in
    /// step: <c>BootstrapProfileSeeder</c> is the other copy.
    /// </remarks>
    private async Task EnsureCmpSignerProfileAsync()
    {
        if (await db.CertProfiles.AnyAsync(cp => cp.Name == CmpSignerProfileName))
            return;

        var catalog = (await db.OIDOptions
                .Where(o => o.KeyUsage == "Standard")
                .Select(o => new { o.OID, o.FriendlyName })
                .ToListAsync())
            .Select(o => ((string?)o.OID, (string?)o.FriendlyName));
        var lookup = UsageCatalogResolver.BuildLookup(catalog, e => e.FriendlyName!);
        var digitalSignature = UsageCatalogResolver.Resolve(lookup, "Digital Signature")
            ?? throw new ConfigurationValidationException(
                "The OID catalog has no 'digitalSignature' key usage, so the CMP signer profile cannot be created. " +
                "Apply the OID catalog backfill migration and try again.");

        // Mirrors the OCSP responder profile the seeder writes, minus the EKU.
        var ocspTemplate = await db.CertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(cp => cp.Name == "OCSP Responder Certificate Profile");

        db.CertProfiles.Add(new CertProfileEntity
        {
            Name = CmpSignerProfileName,
            Description = "Profile for dedicated CMP message-signing certificates (RFC 4210 section 5.1.3.3). digitalSignature only; no EKU.",
            IsCaProfile = false,
            KeyUsages = JsonSerializer.Serialize(new[] { digitalSignature }),
            ExtendedKeyUsages = "[]",
            AllowedKeyAlgorithms = ocspTemplate?.AllowedKeyAlgorithms ?? "[]",
            AllowedKeySizes = ocspTemplate?.AllowedKeySizes ?? "[]",
            AllowedSignatureAlgorithms = ocspTemplate?.AllowedSignatureAlgorithms ?? "[]",
            ValidityPeriodMin = "P1D",
            ValidityPeriodMax = "P10Y",
            CanBeDeleted = false,
            CreatedAt = DateTime.UtcNow,
        });
        await db.SaveChangesAsync();
        logger.LogInformation("Certificate profile '{Name}' created on first use.", CmpSignerProfileName);
    }

    /// <summary>
    /// Confirms an issued CMP signer carries the digitalSignature key usage, without which no
    /// client will accept it as a message signer. Same failure shape as the EKU check: the
    /// predecessor is left in place and the operator is told what to fix.
    /// </summary>
    internal static void EnsureIssuedCertCarriesDigitalSignature(X509Certificate cert, string certType)
    {
        var keyUsage = cert.GetKeyUsage();
        // BouncyCastle returns the KeyUsage bits as a bool array indexed by bit position;
        // digitalSignature is bit 0.
        if (keyUsage != null && keyUsage.Length > 0 && keyUsage[0])
            return;
        throw new ConfigurationValidationException(
            $"The reissued {certType} certificate was created without the digitalSignature key usage, " +
            "so no CMP client would accept it as a message signer. The previous certificate has been " +
            $"left in place. Check the '{CmpSignerProfileName}' certificate profile and the signing " +
            "profile's allowed key usages, then reissue again.", ErrorCodes.SigningProfileMissingRequiredEku);
    }

    /// <summary>
    /// Confirms the CA's signing profile actually permits the EKU an infrastructure certificate
    /// needs, before anything is issued or revoked.
    /// <para>
    /// Issuance intersects the certificate profile's EKUs with the signing profile's
    /// <c>AllowedEKUs</c> (see <c>IssuanceValidationService.SetupAllowedExtendedOids</c>), and a
    /// usage absent from the signing profile is silently dropped rather than refused. A CA whose
    /// signing profile omits <c>id-kp-OCSPSigning</c> therefore yields a responder certificate
    /// with no OCSP-signing EKU — which the OCSP resolver rejects, so the CA answers
    /// <c>unauthorized</c> exactly as if it had no responder at all.
    /// </para>
    /// <para>
    /// This check exists because reissue without it made things worse, not better: the
    /// predecessors were revoked and replaced with a certificate that could never work. Verifying
    /// first means a CA in this state is left exactly as it was, with a message saying what to fix.
    /// </para>
    /// </summary>
    private static void EnsureSigningProfilePermitsInfrastructureEkus(
        SigningProfileEntity signingProfile, bool needsOcsp, bool needsTsa)
    {
        // An empty AllowedEKUs means "no restriction" downstream, so it is not a failure here.
        List<string> allowed;
        try
        {
            allowed = JsonSerializer.Deserialize<List<string>>(
                string.IsNullOrWhiteSpace(signingProfile.AllowedEKUs) ? "[]" : signingProfile.AllowedEKUs,
                SafeJsonOptions.Default) ?? new List<string>();
        }
        catch (JsonException)
        {
            // A profile we cannot parse is not one we can clear, and guessing here would put us
            // back to issuing a certificate that might not work.
            throw new ConfigurationValidationException(
                "This CA's signing profile has an unreadable AllowedEKUs value, so it cannot be " +
                "confirmed to permit the extended key usages an OCSP responder or TSA needs. " +
                "Fix the profile before reissuing.", ErrorCodes.SigningProfileEkusUnreadable);
        }

        if (allowed.Count == 0)
            return;

        var missing = new List<string>();
        // Compare canonically: the same usage is stored as an OID by the seeder, as a camelCase
        // catalog name by the UI, and as a display name by older bootstrap paths.
        bool Permits(string oid, string friendly) =>
            allowed.Any(a => UsageCatalogResolver.Canonicalize(a) == UsageCatalogResolver.Canonicalize(oid)
                          || UsageCatalogResolver.Canonicalize(a) == UsageCatalogResolver.Canonicalize(friendly)
                          || string.Equals(a.Trim(), oid, StringComparison.Ordinal));

        if (needsOcsp && !Permits(IdKpOcspSigningOid, "OCSPSigning"))
            missing.Add($"OCSP signing ({IdKpOcspSigningOid})");
        if (needsTsa && !Permits(IdKpTimeStampingOid, "timeStamping"))
            missing.Add($"time stamping ({IdKpTimeStampingOid})");

        if (missing.Count > 0)
        {
            throw new ConfigurationValidationException(
                $"This CA's signing profile does not permit {string.Join(" or ", missing)}, so a reissued " +
                "certificate would be issued without that extended key usage and would not work — " +
                "OCSP would keep answering 'unauthorized'. Nothing has been changed. Add the usage to " +
                $"the signing profile '{signingProfile.Name}' (Allowed EKUs) and reissue again. " +
                "CAs created before this was corrected carry a narrower AllowedEKUs list than the " +
                "bootstrap default and hit this.", ErrorCodes.SigningProfileMissingRequiredEku);
        }
    }

    /// <summary>
    /// Confirms a freshly issued infrastructure certificate carries the EKU it needs.
    /// <para>
    /// The pre-flight check above reads the signing profile; this reads the certificate that
    /// actually came out. They are not the same assertion — issuance also consults the OIDOptions
    /// catalog and the effective certificate profile, either of which can drop a usage — and the
    /// only one that matters to a relying party is what is in the certificate.
    /// </para>
    /// </summary>
    private static void EnsureIssuedCertCarriesEku(X509Certificate cert, string requiredOid, string certType)
    {
        // BouncyCastle returns IList of DerObjectIdentifier here, not strings.
        var ekus = cert.GetExtendedKeyUsage();
        if (ekus != null && ekus.Cast<object>().Any(o => string.Equals(o?.ToString(), requiredOid, StringComparison.Ordinal)))
            return;

        throw new ConfigurationValidationException(
            $"The reissued {certType} certificate was created without the required extended key usage " +
            $"({requiredOid}), so it would not work. The previous certificate has been left in place " +
            "and still points at this CA. Check the signing profile's Allowed EKUs and the " +
            $"'{certType}' certificate profile, then reissue again.", ErrorCodes.SigningProfileMissingRequiredEku);
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
        Guid? cmpCertId = ca?.CmpSigningCertificateId;

        // Remove CA entity + signing profile + cert row
        if (ca != null) db.CertificateAuthorities.Remove(ca);

        var profile = await db.SigningProfiles.FirstOrDefaultAsync(p => p.Id == signingProfileId);
        if (profile != null) db.SigningProfiles.Remove(profile);

        if (tsaCertId != null)
        {
            var tsaCert = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == tsaCertId.Value);
            if (tsaCert != null) db.Certificates.Remove(tsaCert);
        }
        if (cmpCertId != null)
        {
            var cmpCert = await db.Certificates.FirstOrDefaultAsync(c => c.CertificateId == cmpCertId.Value);
            if (cmpCert != null) db.Certificates.Remove(cmpCert);
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
    /// Issues an infrastructure certificate (TSA, OCSP responder or CMP signer) through the
    /// standard CSR pipeline. The subject key is generated inside the signer under a ceremony
    /// context naming the CA and held pending; the CSR is signed through the signer with it;
    /// the certificate is issued via <see cref="ICertificateIssuanceService"/> with the CA
    /// named explicitly (<paramref name="caKey"/> under <paramref name="caSigningContext"/>),
    /// since at CA creation the CA's row is not committed yet. Links the issued certificate to
    /// the CA entity and returns it with its row id and the pending key's reference, for the
    /// caller to commit once its rows are committed. The pending key is retired if issuance fails.
    /// </summary>
    private async Task<(X509Certificate cert, Guid certificateId, KeyRef key)> IssueInfrastructureCertAsync(
        X509Certificate caCert,
        KeyRef caKey,
        SigningContext caSigningContext,
        CertificateAuthorityEntity caEntity,
        SigningProfileEntity signingProfile,
        string certProfileName,
        string certType,
        ILogger logger)
    {
        // Resolve key algorithm to match the parent CA
        var (alg, sizeOrCurve) = ResolveTsaKeyAlgorithmForParent(caCert.GetPublicKey());

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

        // The subject key is the signer's: generated there, pending under a ceremony context
        // naming this CA, and signing the CSR through the signer. At CA creation the CA's own
        // context is the ceremony's, and its ceremony id carries over; a reissue has none.
        var keyContext = new SigningContext(SignerCaller, SigningPurpose.Ceremony, caEntity.TenantId, caEntity.Id, caSigningContext.CeremonyId);
        var generated = await signer.GenerateKeyAsync(
            new KeySpec(alg, KeyAlgorithmPolicy.FormatKeySizeForProfile(alg, sizeOrCurve)), keyContext);
        try
        {
            var csrSigner = new SigningServiceSignatureFactory(signer, generated.Key,
                SignatureAlgorithm.FromName(KeyAlgorithmPolicy.ResolveSignatureAlgorithm(alg, sizeOrCurve)), keyContext);
            var csrId = await csrService.GenerateInfrastructureCsrAsync(
                subjectDn, alg, sizeOrCurve, certProfile.Id, signingProfile.Id,
                PublicKeyFactory.CreateKey(generated.PublicKeyDer), csrSigner);

            // Issue through the standard pipeline with the CA named explicitly
            var notBefore = CertificateValidityUtil.DefaultNotBefore();
            var notAfter = notBefore.AddYears(10);
            if (notAfter > caCert.NotAfter)
                notAfter = caCert.NotAfter;

            var result = await issuanceService.IssueCertificateAsync(
                csrId, notBefore, notAfter, caCert, caKey, caSigningContext);

            var issuedCert = CertificateUtil.ParseFromPem(result.Pem);

            // Link to the CA entity
            var csrEntity = await db.CertificateRequests.FirstOrDefaultAsync(c => c.Id == csrId);
            var issuedCertificateId = csrEntity?.IssuedCertificateId
                ?? throw new InvalidOperationException($"Issued {certType} certificate is not recorded on its request.");
            if (certType == "TSA")
                caEntity.TsaCertificateId = issuedCertificateId;
            else if (certType == "OCSP Responder")
                caEntity.OcspResponderCertificateId = issuedCertificateId;
            else if (certType == CmpSignerCertType)
                caEntity.CmpSigningCertificateId = issuedCertificateId;
            await db.SaveChangesAsync();

            // {Subject} is the full Subject DN, which already begins with "CN=" — don't prefix another
            // "CN=" here or the log reads "(CN=CN=... TSA)".
            logger.LogInformation("{CertType} certificate issued for CA '{CaName}' via standard pipeline (subject={Subject})",
                certType, caEntity.Name, issuedCert.SubjectDN);

            return (issuedCert, issuedCertificateId, generated.Key);
        }
        catch
        {
            await RetireQuietlyAsync(keyContext, generated.Key);
            throw;
        }
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
    /// Choose an infrastructure key algorithm compatible with the parent CA, from the parent
    /// certificate's public key (the private key stays with the signer). For classical CAs
    /// (RSA, ECDSA, Ed25519, Ed448) the TSA gets the same family. For PQC CAs (ML-DSA, SLH-DSA)
    /// the TSA also uses a PQC key so the time-stamp chain remains PQ-secure end-to-end.
    /// </summary>
    private static (string alg, int sizeOrCurve) ResolveTsaKeyAlgorithmForParent(AsymmetricKeyParameter parentKey)
    {
        return parentKey switch
        {
            RsaKeyParameters => ("RSA", 3072),
            ECPublicKeyParameters or ECPrivateKeyParameters => ("ECDSA", 256), // P-256
            Ed25519PublicKeyParameters or Ed25519PrivateKeyParameters => ("Ed25519", 0),
            Ed448PublicKeyParameters or Ed448PrivateKeyParameters => ("Ed448", 0),
            MLDsaPublicKeyParameters or MLDsaPrivateKeyParameters => ("ML-DSA-65", 0),
            SlhDsaPublicKeyParameters or SlhDsaPrivateKeyParameters => ("SLH-DSA-SHA2-128F", 0),
            // Safe default for any key type not enumerated above.
            _ => ("ECDSA", 256)
        };
    }

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
