using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Text.Json;
using ModularCA.Shared.Errors;

namespace ModularCA.Core.Services;

/// <summary>
/// Manages CSR generation, upload, and retrieval with key pair creation and database storage.
/// </summary>
public class CsrService : ICsrService
{
    private readonly ModularCADbContext _dbContext;

    /// <summary>
    /// Initializes a new instance of <see cref="CsrService"/>.
    /// </summary>
    public CsrService(ModularCADbContext dbContext)
    {
        _dbContext = dbContext;
    }

    /// <summary>
    /// Generates a new CSR with a fresh key pair based on the requested parameters, validates the key
    /// parameters against the signing and certificate profiles, and stores the CSR entity in the
    /// database. The private key is returned with the CSR and is not stored: it is delivered once.
    /// </summary>
    public async Task<GeneratedCsr> GenerateCsrAsync(CreateCsrRequest request, Guid userId)
    {
        // Load cert and signing profiles
        var certProfile = await _dbContext.CertProfiles.FindAsync(request.CertificateProfileId);
        var signingProfile = await _dbContext.SigningProfiles.FindAsync(request.SigningProfileId);

        if (certProfile == null)
            throw new Exception("Certificate profile not found.");
        if (signingProfile == null)
            throw new Exception("Signing profile not found.");

        var user = await _dbContext.Users
            .Where(c => c.Id == userId)
            .FirstOrDefaultAsync();
        if (user == null)
            throw new Exception($"User with ID {userId} not found for assignment to CSR.");

        if (!IsValidKeyParameters(request.KeyAlgorithm, request.KeySize, request.SignatureAlgorithm, signingProfile, certProfile))
            throw new Exception("Invalid key parameters.");

        // Enforce global key-algorithm policy (RSA ≥ 2048, NIST curves, approved PQC).
        // This is defence-in-depth on top of the profile validator above.
        if (!KeyAlgorithmPolicy.IsAllowed(request.KeyAlgorithm, request.KeySize))
            throw new Exception($"Key algorithm '{request.KeyAlgorithm}' with size/curve '{request.KeySize}' is not permitted by KeyAlgorithmPolicy.");

        // Generate keypair
        var keyPair = KeyGenerationUtil.GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

        // Build subject
        var subject = new X509Name(request.SubjectName);

        // Prepare extension list
        var extGen = new X509ExtensionsGenerator();

        // Key Usage
        if (!string.IsNullOrWhiteSpace(certProfile.KeyUsages))
        {
            var usageFlags = X509KeyUsageUtil.ParseKeyUsages(certProfile.KeyUsages);
            extGen.AddExtension(X509Extensions.KeyUsage, true, new X509KeyUsage(usageFlags));
        }

        List<string> ekuOidsFromJson = JsonSerializer.Deserialize<List<string>>(certProfile.ExtendedKeyUsages)!;

        var ekuDbOids = _dbContext.OIDOptions
            .ToList()
            .Where(o => ekuOidsFromJson.Contains(o.OID))
            .Select(o => o.OID)
            .Select(o =>

            new DerObjectIdentifier(o)
            )
            .ToArray();

        var ekuSeq = new DerSequence(ekuDbOids);
        extGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, ekuSeq);
        var extensions = extGen.Generate();

        // Wrap extensions in a CSR attribute
        var attr = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var attributes = new DerSet(attr);

        // Do NOT silently fall back to SHA256WITHRSA when the caller omits the signature
        // algorithm — that causes algorithm confusion for non-RSA keys. Require the caller to
        // supply a signature algorithm (the profile validator above already requires it to be
        // non-empty), otherwise derive the canonical one from the key algorithm + size/curve.
        var signatureAlgorithm = !string.IsNullOrWhiteSpace(request.SignatureAlgorithm)
            ? request.SignatureAlgorithm
            : KeyAlgorithmPolicy.ResolveSignatureAlgorithm(request.KeyAlgorithm, request.KeySize);

        // Create CSR
        var csr = new Pkcs10CertificationRequest(
            signatureAlgorithm,
            subject,
            keyPair.Public,
            attributes,
            keyPair.Private
        );

        // PEM encode CSR
        string csrPem;
        using (var sw = new StringWriter())
        {
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(csr);
            csrPem = sw.ToString();
        }

        // The key goes back to the requester with the CSR and is not stored: re-download ended,
        // so the CA keeps no copy to hand out later. The PEM is made before the key pair goes
        // out of scope and is the only place the key exists once this method returns.
        var privateKeyPem = CertificateUtil.ExportPrivateKeyToPem(keyPair.Private);

        // Convert SAN dictionary to JSON
        var sanJson = JsonSerializer.Serialize(request.SubjectAlternativeNames);


        // Store CSR and references to cert/signing profiles
        var entity = new CertRequestEntity
        {
            Subject = request.SubjectName,
            SubjectAlternativeNames = sanJson,
            CSR = csrPem,
            KeyAlgorithm = request.KeyAlgorithm,
            KeySize = request.KeySize,
            SignatureAlgorithm = signatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
            RequestorUserId = user.Id,
            RequestorUser = user
        };

        _dbContext.CertificateRequests.Add(entity);
        await _dbContext.SaveChangesAsync();

        MetricsService.CsrSubmissionsTotal.WithLabels("generated").Inc();

        // entity.Id is populated by SaveChangesAsync above, so the row needs no re-query.
        //
        // This used to re-select the row by matching on the CSR PEM and then block on the Task with
        // .Result — which stalled a thread-pool thread inside an async method, evaluated the task
        // twice, and, because the same PEM can legitimately appear on more than one row, could
        // return the id of a different request than the one just written.
        return new GeneratedCsr(csrPem, entity.Id, privateKeyPem);
    }

    /// <summary>
    /// Generates a CSR for an infrastructure certificate (TSA signer, OCSP responder).
    /// The private key is NOT encrypted onto the CSR entity — the caller writes it to the keystore.
    /// The CSR is auto-approved and marked as infrastructure so it bypasses quota enforcement.
    /// </summary>
    public async Task<(Guid csrId, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)> GenerateInfrastructureCsrAsync(
        string subjectDn, string keyAlgorithm, int keySizeOrCurve,
        Guid certProfileId, Guid signingProfileId,
        List<string>? sans = null,
        bool isInfrastructure = true,
        Guid? requestorUserId = null)
    {
        var (certProfile, signingProfile, signatureAlgorithm, keySizeStr) =
            await ValidateInfrastructureKeyParametersAsync(keyAlgorithm, keySizeOrCurve, certProfileId, signingProfileId);

        var keyPair = KeyAlgorithmPolicy.GenerateKeyPair(keyAlgorithm, keySizeOrCurve);
        var csrSigner = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, new SecureRandom());
        var csrId = await StoreInfrastructureCsrAsync(subjectDn, keyAlgorithm, keySizeStr, signatureAlgorithm,
            certProfile, signingProfile, keyPair.Public, csrSigner, sans, isInfrastructure, requestorUserId);
        return (csrId, keyPair);
    }

    /// <inheritdoc />
    public async Task<Guid> GenerateInfrastructureCsrAsync(
        string subjectDn, string keyAlgorithm, int keySizeOrCurve,
        Guid certProfileId, Guid signingProfileId,
        AsymmetricKeyParameter publicKey, ISignatureFactory csrSigner,
        List<string>? sans = null,
        bool isInfrastructure = true,
        Guid? requestorUserId = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(csrSigner);
        var (certProfile, signingProfile, signatureAlgorithm, keySizeStr) =
            await ValidateInfrastructureKeyParametersAsync(keyAlgorithm, keySizeOrCurve, certProfileId, signingProfileId);
        return await StoreInfrastructureCsrAsync(subjectDn, keyAlgorithm, keySizeStr, signatureAlgorithm,
            certProfile, signingProfile, publicKey, csrSigner, sans, isInfrastructure, requestorUserId);
    }

    /// <summary>
    /// Resolves the profiles an infrastructure CSR is issued under and checks the key algorithm
    /// and size against the key policy and both profiles, as the CSR generators share it.
    /// </summary>
    private async Task<(CertProfileEntity CertProfile, SigningProfileEntity SigningProfile, string SignatureAlgorithm, string KeySizeStr)>
        ValidateInfrastructureKeyParametersAsync(string keyAlgorithm, int keySizeOrCurve, Guid certProfileId, Guid signingProfileId)
    {
        var certProfile = await _dbContext.CertProfiles.FindAsync(certProfileId)
            ?? throw new InvalidOperationException("Infrastructure cert profile not found.");
        var signingProfile = await _dbContext.SigningProfiles.FindAsync(signingProfileId)
            ?? throw new InvalidOperationException("Signing profile not found.");

        // Resolve the string key size for profile validation (e.g. 256 → "P-256" for ECDSA)
        var keySizeStr = KeyAlgorithmPolicy.FormatKeySizeForProfile(keyAlgorithm, keySizeOrCurve);

        if (!KeyAlgorithmPolicy.IsAllowed(keyAlgorithm, keySizeOrCurve))
            throw new InvalidOperationException($"Key algorithm '{keyAlgorithm}' with size '{keySizeOrCurve}' is not permitted.");

        var signatureAlgorithm = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySizeOrCurve);

        if (!IsValidKeyParameters(keyAlgorithm, keySizeStr, signatureAlgorithm, signingProfile, certProfile))
            throw new InvalidOperationException($"Key parameters ({keyAlgorithm}/{keySizeStr}) not allowed by profiles.");

        return (certProfile, signingProfile, signatureAlgorithm, keySizeStr);
    }

    /// <summary>
    /// Builds the PKCS#10 request for <paramref name="publicKey"/> with the cert profile's
    /// extensions and the SANs, signs it with <paramref name="csrSigner"/>, and stores it
    /// approved. Shared by the key-generating and signer-backed generators.
    /// </summary>
    private async Task<Guid> StoreInfrastructureCsrAsync(
        string subjectDn, string keyAlgorithm, string keySizeStr, string signatureAlgorithm,
        CertProfileEntity certProfile, SigningProfileEntity signingProfile,
        AsymmetricKeyParameter publicKey, ISignatureFactory csrSigner,
        List<string>? sans, bool isInfrastructure, Guid? requestorUserId)
    {
        // Build PKCS#10 CSR with extensions from the cert profile
        var subject = new X509Name(subjectDn);
        var extGen = new X509ExtensionsGenerator();

        if (!string.IsNullOrWhiteSpace(certProfile.KeyUsages))
        {
            var usageFlags = X509KeyUsageUtil.ParseKeyUsages(certProfile.KeyUsages);
            extGen.AddExtension(X509Extensions.KeyUsage, true, new X509KeyUsage(usageFlags));
        }

        var ekuOidsFromJson = JsonSerializer.Deserialize<List<string>>(certProfile.ExtendedKeyUsages) ?? new();
        if (ekuOidsFromJson.Count > 0)
        {
            var ekuDerOids = ekuOidsFromJson.Select(o => new DerObjectIdentifier(o)).ToArray();
            extGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new DerSequence(ekuDerOids));
        }

        // Add SANs if provided (e.g. for Web TLS certs)
        var sanList = new List<string>();
        if (sans != null && sans.Count > 0)
        {
            var sanNames = new List<Org.BouncyCastle.Asn1.X509.GeneralName>();
            foreach (var entry in sans)
            {
                var colonIdx = entry.IndexOf(':');
                if (colonIdx < 0) continue;
                var prefix = entry[..colonIdx].Trim().ToUpperInvariant();
                var value = entry[(colonIdx + 1)..].Trim();
                switch (prefix)
                {
                    case "DNS":
                        sanNames.Add(new Org.BouncyCastle.Asn1.X509.GeneralName(Org.BouncyCastle.Asn1.X509.GeneralName.DnsName, value));
                        sanList.Add($"DNS:{value}");
                        break;
                    case "IP":
                        sanNames.Add(new Org.BouncyCastle.Asn1.X509.GeneralName(Org.BouncyCastle.Asn1.X509.GeneralName.IPAddress, value));
                        sanList.Add($"IP:{value}");
                        break;
                }
            }
            if (sanNames.Count > 0)
            {
                extGen.AddExtension(X509Extensions.SubjectAlternativeName, false,
                    new Org.BouncyCastle.Asn1.X509.GeneralNames(sanNames.ToArray()));
            }
        }

        var extensions = extGen.Generate();
        var attr = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var attributes = new DerSet(attr);

        var csr = new Pkcs10CertificationRequest(csrSigner, subject, publicKey, attributes);

        string csrPem;
        using (var sw = new StringWriter())
        {
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(csr);
            csrPem = sw.ToString();
        }

        var entity = new CertRequestEntity
        {
            Subject = subjectDn,
            SubjectAlternativeNames = sanList.Count > 0 ? JsonSerializer.Serialize(sanList) : "[]",
            CSR = csrPem,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySizeStr,
            SignatureAlgorithm = signatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = "Approved",
            // The infrastructure flag is a POLICY EXEMPTION, not a bookkeeping label: at
            // issuance it skips the tenant/CA quota, the minimum-validity check, and the
            // tenant validity ceiling. Auto-renewal used this method for ordinary
            // subscriber certificates and therefore renewed them straight past limits their
            // original issuance had been held to — a profile capped at 398 days renewing to its
            // P3Y profile maximum — while also detaching the certificate from its owner, who
            // then lost self-service on it (CertificateAccessEvaluator excludes infrastructure
            // requests). Callers must now say so explicitly.
            IsInfrastructureCert = isInfrastructure,
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
            RequestorUserId = requestorUserId,
        };

        _dbContext.CertificateRequests.Add(entity);
        await _dbContext.SaveChangesAsync();

        return entity.Id;
    }

    /// <summary>
    /// Uploads an externally-generated PEM-encoded CSR, validates its key parameters against the
    /// signing and certificate profiles, and stores the CSR entity in the database.
    /// </summary>
    public async Task<string> UploadCsrAsync(string pem, Guid certProfileId, Guid signingProfileId, Guid userId)
    {
        return await UploadCsrAsync(pem, certProfileId, signingProfileId, userId, null, null);
    }

    /// <summary>
    /// Uploads an externally-generated PEM-encoded CSR with optional subject and SAN overrides,
    /// validates its key parameters against the signing and certificate profiles, and stores the
    /// CSR entity in the database with override metadata for use during issuance.
    /// </summary>
    public async Task<string> UploadCsrAsync(string pem, Guid certProfileId, Guid signingProfileId, Guid userId,
        Dictionary<string, string>? subjectOverrides, List<Shared.Models.Csr.SanOverride>? sanOverrides,
        DateTime? requestedNotBefore = null, DateTime? requestedNotAfter = null)
    {
        // Load cert and signing profiles
        var certProfile = await _dbContext.CertProfiles.FindAsync(certProfileId);
        var signingProfile = await _dbContext.SigningProfiles.FindAsync(signingProfileId);

        if (certProfile == null)
            throw new Exception($"Certificate profile not found (ID: {certProfileId}).");
        if (signingProfile == null)
            throw new Exception($"Signing profile not found (ID: {signingProfileId}).");
        // Parse CSR
        var user = await _dbContext.Users
            .Where(c => c.Id == userId)
            .FirstOrDefaultAsync();
        if (user == null)
            throw new Exception($"User associated with ID {userId} not found for assignment to CSR.");

        var parsedCsr = CertificateUtil.ParseCsr(pem);

        // Verify the CSR signature to detect corruption or tampering
        using var csrReader = new StringReader(pem);
        var csrPemReader = new PemReader(csrReader);
        if (csrPemReader.ReadObject() is Pkcs10CertificationRequest csrObj && !csrObj.Verify())
            throw new InvalidOperationException("CSR signature verification failed. The CSR may be corrupted or tampered with.");

        if (!IsValidKeyParameters(parsedCsr.KeyAlgorithm, parsedCsr.KeySize, parsedCsr.SignatureAlgorithm, signingProfile, certProfile))
            throw new Exception("Invalid key parameters.");

        // CLM-017: enforce global key-algorithm policy on uploaded CSRs (defence-in-depth
        // matching the check in GenerateCsrAsync). Without this, an externally-generated
        // CSR with a weak or disallowed key algorithm could bypass the system policy.
        if (!KeyAlgorithmPolicy.IsAllowed(parsedCsr.KeyAlgorithm, parsedCsr.KeySize))
            throw new InvalidOperationException(
                $"The CSR's key algorithm ({parsedCsr.KeyAlgorithm} {parsedCsr.KeySize}-bit) is not permitted by the system key policy.");

        var sanList = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);

        // Store CSR and references to cert/signing profiles
        var entity = new CertRequestEntity
        {
            Subject = parsedCsr.SubjectName,
            SubjectAlternativeNames = sanList,
            CSR = pem,
            KeyAlgorithm = parsedCsr.KeyAlgorithm,
            KeySize = parsedCsr.KeySize,
            SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
            RequestorUserId = user.Id,
            RequestorUser = user,
            RequestedNotBefore = requestedNotBefore,
            RequestedNotAfter = requestedNotAfter
        };

        // Store overrides if provided
        if (subjectOverrides != null && subjectOverrides.Count > 0)
            entity.SubjectOverrides = JsonSerializer.Serialize(subjectOverrides);
        if (sanOverrides != null && sanOverrides.Count > 0)
            entity.SanOverrides = JsonSerializer.Serialize(sanOverrides);

        _dbContext.CertificateRequests.Add(entity);
        await _dbContext.SaveChangesAsync();

        MetricsService.CsrSubmissionsTotal.WithLabels("uploaded").Inc();

        return pem;
    }

    /// <summary>
    /// Validates that the requested key algorithm, key size, and signature algorithm are permitted
    /// by the signing profile's allowed algorithms and the certificate profile's allowed key sizes
    /// and signature algorithms.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> rather than <c>private</c> so the empty-allow-list semantic can be pinned
    /// directly; ModularCA.Core already grants InternalsVisibleTo to the test assembly.
    /// </remarks>
    internal static bool IsValidKeyParameters(string algorithm, string keySize, string signatureAlgorithm, SigningProfileEntity signingProfile, CertProfileEntity certProfile)
    {
        // Deserialize allowed values from signing profile and cert profile
        var validKeyAlgorithms = JsonSerializer.Deserialize<List<string>>(signingProfile.AllowedAlgorithms);
        var validKeySizes = JsonSerializer.Deserialize<List<string>>(certProfile.AllowedKeySizes);
        var validSignatureAlgorithms = JsonSerializer.Deserialize<List<string>>(certProfile.AllowedSignatureAlgorithms);

        // Check presence
        if (validKeyAlgorithms == null || validKeySizes == null || validSignatureAlgorithms == null)
            return false;

        // An EMPTY allow-list means "unrestricted", not "permit nothing".
        //
        // That is the semantic every other reader of these three columns applies — see
        // IssuanceValidationService.ValidateAgainstCertProfile / ValidateAgainstSigningProfile,
        // which gate each check on `?.Count > 0`. This method did not, so an empty list rejected
        // every CSR while issuance would have accepted anything: a profile could not be submitted
        // against at all, and the error named an empty allow-list. The two paths now agree.
        if (validKeyAlgorithms.Count > 0
            && !validKeyAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
            throw new ProfileValidationException("Key algorithm", algorithm, validKeyAlgorithms, "signing profile");

        // keySize validation only applies to RSA and ECDSA; EdDSA/PQC ignore it
        if (!IsKeySizeIgnored(algorithm) && validKeySizes.Count > 0 && !validKeySizes.Contains(keySize))
            throw new ProfileValidationException("Key size", keySize, validKeySizes, "certificate profile");

        if (validSignatureAlgorithms.Count > 0
            && !validSignatureAlgorithms.Contains(signatureAlgorithm, StringComparer.OrdinalIgnoreCase))
            throw new ProfileValidationException("Signature algorithm", signatureAlgorithm, validSignatureAlgorithms, "certificate profile");

        // Compatibility: for hash-then-sign (RSA/ECDSA) sig alg contains key alg name.
        // For EdDSA/PQC the signature algorithm IS the key algorithm.
        if (!IsSignatureAlgorithmCompatible(algorithm, signatureAlgorithm))
            throw new ProfileValidationException("Signature algorithm", signatureAlgorithm, [algorithm], "key algorithm it must match");

        if (!IsKeyAlgorithmAndSizeCompatible(algorithm, keySize))
            throw new ProfileValidationException("Key size", keySize, [algorithm], "key algorithm it must match");

        return true;
    }
    private static bool IsKeyAlgorithmAndSizeCompatible(string algorithm, string keySizeOrCurve)
    {
        switch (algorithm.ToUpperInvariant())
        {
            case "RSA":
                return keySizeOrCurve is "2048" or "3072" or "4096" or "7680" or "8192";
            case "ECDSA":
                var validCurves = new[] { "P-256", "P-384", "P-521", "secp256r1", "secp384r1", "secp521r1" };
                return validCurves.Contains(keySizeOrCurve, StringComparer.OrdinalIgnoreCase);
            case "ED25519":
            case "ED448":
            case "ML-DSA" or "ML-DSA-44" or "ML-DSA-65" or "ML-DSA-87" or "DILITHIUM":
            case "SLH-DSA" or "SPHINCSPLUS":
            case var a when a.StartsWith("SLH-DSA-"):
                return true;
            default:
                return false;
        }
    }

    private static bool IsKeySizeIgnored(string algorithm) =>
        algorithm.ToUpperInvariant() switch
        {
            "ED25519" or "ED448" => true,
            "ML-DSA" or "ML-DSA-44" or "ML-DSA-65" or "ML-DSA-87" or "DILITHIUM" => true,
            "SLH-DSA" or "SPHINCSPLUS" => true,
            var a when a.StartsWith("SLH-DSA-") => true,
            _ => false
        };

    private static bool IsSignatureAlgorithmCompatible(string algorithm, string signatureAlgorithm) =>
        algorithm.ToUpperInvariant() switch
        {
            // Hash-then-sign: sig alg contains key alg name (e.g., "SHA256withRSA" contains "RSA")
            "RSA" or "ECDSA" => signatureAlgorithm.Contains(algorithm, StringComparison.OrdinalIgnoreCase),
            // For EdDSA/PQC the signature algorithm IS the key algorithm
            _ => signatureAlgorithm.Equals(algorithm, StringComparison.OrdinalIgnoreCase)
        };

    /// <summary>
    /// Returns all pending (unapproved) certificate signing requests. When
    /// <paramref name="accessibleCaIds"/> is provided, results are filtered to CSRs whose
    /// signing profile's issuer certificate belongs to one of the accessible CAs (CLM-022).
    /// </summary>
    public async Task<List<CertRequestDto>> GetPendingRequests(List<Guid>? accessibleCaIds = null)
    {
        // When scoping is requested, pre-compute the set of signing profile IDs whose
        // issuer certificate belongs to one of the accessible CAs. A non-null empty set means
        // "no CA at all" and must yield nothing; it used to be read as "no scoping", which
        // handed a caller with no accessible CA every request in the system.
        HashSet<Guid>? allowedSigningProfileIds = null;
        if (accessibleCaIds != null)
        {
            // Resolve which certificate IDs belong to the accessible CAs.
            var caCertIds = await _dbContext.CertificateAuthorities
                .AsNoTracking()
                .Where(ca => accessibleCaIds.Contains(ca.Id) && ca.CertificateId != null)
                .Select(ca => ca.CertificateId!.Value)
                .ToListAsync();
            var caCertIdSet = new HashSet<Guid>(caCertIds);

            // Match signing profiles whose IssuerId (certificate FK) is in the set.
            var spIds = await _dbContext.Set<SigningProfileEntity>()
                .AsNoTracking()
                .Where(sp => sp.IssuerId != null && caCertIdSet.Contains(sp.IssuerId.Value))
                .Select(sp => sp.Id)
                .ToListAsync();
            allowedSigningProfileIds = new HashSet<Guid>(spIds);
        }

        var query = _dbContext.CertificateRequests
            .Include(r => r.RequestorUser)
            .Where(r => !r.IsInfrastructureCert);

        if (allowedSigningProfileIds != null)
        {
            query = query.Where(r => r.SigningProfileId.HasValue
                && allowedSigningProfileIds.Contains(r.SigningProfileId.Value));
        }

        var pendingRequests = await query
            .OrderByDescending(r => r.SubmittedAt)
            .ToListAsync();

        var results = new List<CertRequestDto>();
        foreach (var pendingRequest in pendingRequests)
        {
            // SubjectAlternativeNames can be null/empty (a CSR with no SANs) or, rarely, malformed —
            // an empty string is NOT valid JSON, so deserializing it throws and 500s the whole list.
            // Treat null/empty/invalid as "no SANs" rather than failing the request.
            List<string> sans;
            if (string.IsNullOrWhiteSpace(pendingRequest.SubjectAlternativeNames))
            {
                sans = new List<string>();
            }
            else
            {
                try { sans = JsonSerializer.Deserialize<List<string>>(pendingRequest.SubjectAlternativeNames) ?? new List<string>(); }
                catch (JsonException) { sans = new List<string>(); }
            }

            var request = new CertRequestDto
            {
                RequestId = pendingRequest.Id,
                SubjectName = pendingRequest.Subject,
                SubjectAlternativeNames = sans,
                SignatureAlgorithm = pendingRequest.SignatureAlgorithm,
                KeyAlgorithm = pendingRequest.KeyAlgorithm,
                KeySize = pendingRequest.KeySize,
                Status = pendingRequest.Status,
                SubmittedAt = pendingRequest.SubmittedAt,
                RequestedNotBefore = pendingRequest.RequestedNotBefore,
                RequestedNotAfter = pendingRequest.RequestedNotAfter,
                SigningProfileId = pendingRequest.SigningProfileId ?? Guid.Empty,
                CertificateProfileId = pendingRequest.CertProfileId ?? Guid.Empty,
                RequestorUserId = pendingRequest.RequestorUserId ?? Guid.Empty,
                RequestorUsername = pendingRequest.RequestorUser?.Username,
                RejectionReason = pendingRequest.RejectionReason,
                IssuedCertificateId = pendingRequest.IssuedCertificateId,
            };

            results.Add(request);
        }
        return results;
    }

}
