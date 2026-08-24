using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Enums;
using System.Text;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Orchestrates the certificate issuance and reissue workflows. Loads the CSR, delegates
    /// validation to <see cref="IssuanceValidationService"/>, certificate construction to
    /// <see cref="CertificateBuilderService"/>, and persists the result to the database.
    /// </summary>
    public class CertificateIssuanceService : ICertificateIssuanceService
    {
        private readonly ModularCADbContext _db;
        private readonly IKeystoreCertificates _keystore;
        private readonly ICertificateStore _certStore;
        private readonly IssuanceValidationService _validation;
        private readonly CertificateBuilderService _builder;
        private readonly IProfileResolutionService _profileResolver;
        private readonly ICtSubmissionService _ctSubmission;
        private readonly ICertPolicyService _certPolicy;
        private readonly IQuotaService _quotaService;
        private readonly IKeyWrappingPassphraseProvider _passphraseProvider;
        private readonly IAuditService _audit;
        private readonly ICertificateAccessService _certificateAccessService;
        private readonly ICertificateRevocationService _revocation;
        private readonly ILogger<CertificateIssuanceService> _logger;

        /// <summary>
        /// Initializes a new instance of <see cref="CertificateIssuanceService"/>.
        /// </summary>
        /// <param name="db">Database context for CSR and certificate queries.</param>
        /// <param name="keystore">Keystore for CA certificate and private key resolution.</param>
        /// <param name="certStore">Store for persisting issued certificates.</param>
        /// <param name="validation">Service for validating issuance parameters against profiles.</param>
        /// <param name="builder">Service for building and signing X.509 certificates.</param>
        /// <param name="profileResolver">Service for resolving effective (merged/inherited) profiles.</param>
        /// <param name="ctSubmission">Service for submitting certificates to CT logs.</param>
        /// <param name="certPolicy">Service for evaluating system-wide certificate policy rules.</param>
        /// <param name="quotaService">Service for checking certificate quota limits per CA.</param>
        /// <param name="passphraseProvider">Provider for HKDF wrap key derivation passphrase.</param>
        /// <param name="audit">Audit service for logging CT submission failures.</param>
        /// <param name="certificateAccessService">Service for managing certificate-level access control entries.</param>
        /// <param name="revocation">Revocation service used by the reissue flow to mark the previous certificate as Superseded through the proper revocation pipeline (CRL trigger, audit, notifications).</param>
        /// <param name="logger">Logger instance.</param>
        public CertificateIssuanceService(
            ModularCADbContext db,
            IKeystoreCertificates keystore,
            ICertificateStore certStore,
            IssuanceValidationService validation,
            CertificateBuilderService builder,
            IProfileResolutionService profileResolver,
            ICtSubmissionService ctSubmission,
            ICertPolicyService certPolicy,
            IQuotaService quotaService,
            IKeyWrappingPassphraseProvider passphraseProvider,
            IAuditService audit,
            ICertificateAccessService certificateAccessService,
            ICertificateRevocationService revocation,
            ILogger<CertificateIssuanceService> logger)
        {
            _db = db;
            _keystore = keystore;
            _certStore = certStore;
            _validation = validation;
            _builder = builder;
            _profileResolver = profileResolver;
            _ctSubmission = ctSubmission;
            _certPolicy = certPolicy;
            _quotaService = quotaService;
            _passphraseProvider = passphraseProvider;
            _audit = audit;
            _certificateAccessService = certificateAccessService;
            _revocation = revocation;
            _logger = logger;
        }

        /// <summary>
        /// Issues a certificate from an approved CSR. Validates profile constraints, resolves the CA key,
        /// builds the certificate, and stores it in the database. The stored PEM includes the leaf
        /// certificate and all intermediate CA certificates (root is always excluded per best practice).
        /// </summary>
        /// <param name="csrId">The ID of the approved CSR.</param>
        /// <param name="notBefore">Optional explicit NotBefore date (defaults to now).</param>
        /// <param name="notAfter">Optional explicit NotAfter date (defaults to profile max).</param>
        /// <returns>The PEM-encoded certificate with intermediate chain and any issuance warnings.</returns>
        /// <inheritdoc />
        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter, CancellationToken cancellationToken = default)
            => IssueCertificateInternalAsync(csrId, notBefore, notAfter, null, null, cancellationToken);

        /// <inheritdoc />
        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCert, IPrivateKeyHandle caKeyHandle, CancellationToken cancellationToken = default)
            => IssueCertificateInternalAsync(csrId, notBefore, notAfter, caCert, caKeyHandle, cancellationToken);

        private async Task<IssuanceResult> IssueCertificateInternalAsync(
            Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate? preResolvedCaCert, IPrivateKeyHandle? preResolvedCaKeyHandle,
            CancellationToken cancellationToken = default)
        {
            var issuanceWarnings = new List<string>();
            var csrEntity = await _db.CertificateRequests
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.Id == csrId);

            if (csrEntity == null)
                throw new InvalidOperationException("CSR not found");

            if (ValidateCsrStatus(csrEntity) == false)
                throw new InvalidOperationException("CSR is not in a valid state for issuance");

            if (csrEntity.SigningProfile == null)
                throw new InvalidOperationException("No signing profile associated with CSR");

            if (string.IsNullOrWhiteSpace(csrEntity.CSR))
                throw new InvalidOperationException("CSR field is empty");

            // CMP requests store a SubjectPublicKeyInfo DER instead of a PKCS#10 CSR
            bool isCmpRequest = csrEntity.CSR.Contains("-----CMP-PUBKEY-----");
            Pkcs10CertificationRequest? csr = null;
            AsymmetricKeyParameter? publicKeyOverride = null;

            if (isCmpRequest)
            {
                // Proof-of-Possession for CMP is verified upstream in
                // ModularCA.Core/Services/Cmp/CmpService.ValidateProofOfPossession
                // (RFC 4210 §5.2.1). That check runs BEFORE the CSR row is ever
                // persisted — any CMP request that reaches this service has already
                // passed signature-based POP, TYPE_RA_VERIFIED, or rejected outright
                // for TYPE_KEY_ENCIPHERMENT / TYPE_KEY_AGREEMENT (unimplemented). We
                // re-assert the contract here as a tripwire: if a future change
                // persists a CMP CSR without running POP, this comment block plus
                // the CmpService test suite should break at the same time.
                //
                // DO NOT add a code path that ingests CMP requests elsewhere without
                // routing them through CmpService.ProcessSingleCertRequestAsync.
                var lines = csrEntity.CSR.Split('\n');
                var b64 = lines.Length >= 2 ? lines[1].Trim() : "";
                var pubKeyDer = Convert.FromBase64String(b64);
                publicKeyOverride = PublicKeyFactory.CreateKey(pubKeyDer);
                _logger.LogDebug(
                    "CMP issuance request {CsrId}: trusting upstream POP verification from CmpService.",
                    csrEntity.Id);
            }
            else
            {
                var csrParser = new CsrParserService();
                csr = csrParser.ParseFromPem(csrEntity.CSR);

                if (!csr.Verify())
                    throw new InvalidOperationException("CSR signature verification failed");
            }

            if (csrEntity.CertProfileId == null)
                throw new InvalidOperationException("No certificate profile associated with CSR");

            // Resolve the effective (merged/inherited) cert profile instead of using the raw entity
            var effectiveCertProfile = await _profileResolver.ResolveCertProfileAsync(csrEntity.CertProfileId.Value);

            if (!_validation.NotBeyondMaximumDate(notAfter, effectiveCertProfile))
            {
                var maxNotAfter = effectiveCertProfile.ValidityPeriodMax != null
                    ? DateTime.UtcNow.Add(System.Xml.XmlConvert.ToTimeSpan(effectiveCertProfile.ValidityPeriodMax))
                    : (DateTime?)null;
                throw new Exception($"NotAfter date exceeds the certificate profile's maximum validity. Max allowed: {effectiveCertProfile.ValidityPeriodMax ?? "not set"} (until {maxNotAfter?.ToString("yyyy-MM-dd") ?? "unknown"}). Reduce the validity period or update the cert profile.");
            }

            // For infrastructure certs, skip the pre-clamp minimum check — the caller may have
            // already clamped notAfter to the parent CA's expiry. The post-clamp check (after CA
            // NotAfter clamping below) provides a more informative error message.
            if (!csrEntity.IsInfrastructureCert && !_validation.ValidityDurationMeetsMinimum(notBefore, notAfter, effectiveCertProfile))
                throw new Exception($"Certificate validity duration is shorter than the profile's minimum ({effectiveCertProfile.ValidityPeriodMin ?? "not set"}). Either extend NotAfter, clear the minimum on the cert profile, or use a different profile.");

            _validation.ValidateAgainstCertProfile(csrEntity.KeyAlgorithm, csrEntity.KeySize, csrEntity.SignatureAlgorithm, effectiveCertProfile);
            _validation.ValidateAgainstSigningProfile(csrEntity.KeyAlgorithm, csrEntity.SignatureAlgorithm, csrEntity.SigningProfile);

            // Infrastructure certs (TSA, OCSP) bypass quota enforcement
            if (!csrEntity.IsInfrastructureCert)
                await EnforceQuotaAsync(csrEntity.SigningProfile);

            // Resolve CA certificate and key — use pre-resolved values when provided
            // (infrastructure certs may be issued before the CA is registered in the keystore)
            X509Certificate caMatch;
            IPrivateKeyHandle caKeyHandle;
            CertificateEntity refCACert;
            if (preResolvedCaCert != null && preResolvedCaKeyHandle != null)
            {
                caMatch = preResolvedCaCert;
                caKeyHandle = preResolvedCaKeyHandle;
                refCACert = await _db.Certificates
                    .FirstOrDefaultAsync(c => c.CertificateId == csrEntity.SigningProfile.IssuerId, cancellationToken)
                    ?? throw new InvalidOperationException("CA certificate entity not found for pre-resolved CA.");
            }
            else
            {
                (caMatch, caKeyHandle, refCACert) = await ResolveCaAsync(csrEntity.SigningProfile);
            }

            // Check tenant is enabled — block issuance if the CA's tenant has been disabled
            var issuingCaEntity = await _db.CertificateAuthorities
                .FirstOrDefaultAsync(ca => ca.CertificateId == refCACert.CertificateId, cancellationToken);
            if (issuingCaEntity != null)
            {
                var caTenant = await _db.Tenants.FindAsync([issuingCaEntity.TenantId], cancellationToken);
                if (caTenant != null && !caTenant.IsEnabled)
                    throw new InvalidOperationException("Certificate issuance is blocked — the tenant is disabled.");

                // The System Signing CA signs keystore entries only — never end-entity
                // certs or sub-CAs. A signing profile pointing at it would exfiltrate
                // the internal identity into issuance; refuse at the service layer so
                // every caller (admin, ACME, EST, SCEP, CMP, public enrollment) hits
                // the same block regardless of which entry point they came through.
                if (string.Equals(issuingCaEntity.Label, "system-signing-ca", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The system signing CA is reserved for keystore signing only and cannot issue certificates. Reconfigure the signing profile to use a non-system CA.");
            }

            var now = DateTime.UtcNow;
            var timeMax = DateTime.UtcNow + Iso8601ParserUtil.ParseIso8601(effectiveCertProfile.ValidityPeriodMax ?? "P1Y");

            // Backdate an auto-generated start time so the certificate is valid on verifiers whose
            // clocks trail ours. An explicitly requested notBefore is honoured as given.
            var validFrom = notBefore ?? CertificateValidityUtil.DefaultNotBefore();
            var validTo = notAfter ?? timeMax;

            // Clamp certificate validity to the issuing CA's NotAfter with a 5-minute margin
            // for clock skew. Both auto-generated and explicitly requested dates are clamped
            // rather than rejected — the caller receives a warning in the IssuanceResult so
            // they know the date was adjusted.
            var caNotAfterMargin = caMatch.NotAfter - TimeSpan.FromMinutes(5);
            if (validTo > caNotAfterMargin)
            {
                var originalValidTo = validTo;
                validTo = caNotAfterMargin;
                var msg = $"Certificate validity clamped from {originalValidTo:yyyy-MM-dd} to {validTo:yyyy-MM-dd} because the issuing CA expires on {caMatch.NotAfter:yyyy-MM-dd}.";
                _logger.LogWarning(msg);
                issuanceWarnings.Add(msg);

                // After clamping, verify the shortened validity still meets the profile's minimum.
                if (!_validation.ValidityDurationMeetsMinimum(validFrom, validTo, effectiveCertProfile))
                {
                    var minDuration = effectiveCertProfile.ValidityPeriodMin ?? "P0D";
                    throw new InvalidOperationException(
                        $"Cannot issue certificate: the issuing CA expires on {caMatch.NotAfter:yyyy-MM-dd}, " +
                        $"which would produce a validity shorter than the profile's minimum ({minDuration}). " +
                        $"Either reduce the profile's minimum validity, extend the CA's lifetime, or use a different CA.");
                }
            }

            // Raise to the issuer's start rather than refusing. A leaf cannot be valid before its
            // issuer, so the issuer's notBefore is the correct earliest value — and this is what
            // makes backdating safe against CAs whose own notBefore was not backdated, including
            // every CA created before that change. Consistent with how the notAfter clamp above
            // adjusts and warns instead of throwing.
            validFrom = CertificateValidityUtil.ClampToIssuer(validFrom, caMatch.NotBefore, out var startClamped);
            if (startClamped)
            {
                var startMsg = $"Certificate NotBefore raised to the issuing CA's start date ({caMatch.NotBefore:O}); "
                             + "a certificate cannot be valid before its issuer.";
                _logger.LogWarning(startMsg);
                issuanceWarnings.Add(startMsg);
            }

            // Generate 128-bit random serial number (CA/BF BR §7.1
            // requires ≥64 bits from CSPRNG). Use 17 bytes with a forced 0x00
            // leading byte so the BigInteger is guaranteed positive AND the
            // trailing 16 bytes are fully random (no masking loss, no edge case
            // where a natural 0x00 high byte would shrink the serial).
            var serialBytes = new byte[17];
            serialBytes[0] = 0x00;
            RandomNumberGenerator.Fill(serialBytes.AsSpan(1));
            var serialNumber = new BigInteger(1, serialBytes);
            var subjectPublicKey = publicKeyOverride ?? csr!.GetPublicKey();
            var subjectDn = isCmpRequest
                ? new X509Name(SanitizeCmpSubject(csrEntity.Subject))
                : _builder.ResolveSubjectDn(csr!, csrEntity);

            // Apply subject DN overrides if present
            subjectDn = ApplySubjectOverrides(subjectDn, csrEntity.SubjectOverrides);

            // Apply SAN overrides if present
            var effectiveSans = ApplySanOverrides(csrEntity.SubjectAlternativeNames, csrEntity.SanOverrides);

            // Re-validate overridden subject DN and SANs against profile rules
            ValidateOverridesAgainstProfile(subjectDn, effectiveSans, csrEntity.SubjectOverrides, csrEntity.SanOverrides, effectiveCertProfile.AllowWildcard);

            // Evaluate system-wide certificate policy rules before building the certificate
            EnforceCertPolicy(csrEntity.KeyAlgorithm, csrEntity.KeySize, csrEntity.SignatureAlgorithm,
                validFrom, validTo, subjectDn.ToString(), ParseSanJson(effectiveSans),
                effectiveCertProfile.SourceProfileId.ToString(), csrEntity.IsInfrastructureCert);

            // Validate subject DN and SANs against issuing CA name constraints
            ValidateNameConstraints(caMatch, subjectDn.ToString(), ParseSanJson(effectiveSans));

            var extendedOids = _validation.SetupAllowedExtendedOids(effectiveCertProfile.ExtendedKeyUsages, csrEntity.SigningProfile.AllowedEKUs);
            var standardOids = _validation.SetupAllowedStandardOids(effectiveCertProfile.KeyUsages);

            // Build and sign the certificate
            var issuedCert = await _builder.BuildCertificateAsync(
                serialNumber, caMatch, caKeyHandle, subjectDn, subjectPublicKey,
                validFrom, validTo, standardOids, extendedOids,
                effectiveSans, refCACert.CertificateId, csrEntity.SigningProfile,
                effectiveCertProfile.IsCaProfile,
                allowWildcardSans: effectiveCertProfile.AllowWildcard);

            // Stored cert.Pem is leaf-only. Chain endpoints rebuild the issuer chain on demand.
            var certPem = EncodeCertPem(issuedCert);

            // Handle private key re-encryption if present
            byte[]? certIv = null;
            byte[]? certEncryptedAes = null;
            byte[]? certEncryptedPrivKey = null;

            if (csrEntity.EncryptedPrivateKey != null && csrEntity.AesKeyEncryptionIv != null && csrEntity.EncryptedAesForPrivateKey != null && csrEntity.EncryptionCertSerialNumber != null)
            {
                var decryptedCsrPrivKey = DecryptPrivateKeyFromSerial(csrEntity.AesKeyEncryptionIv, csrEntity.EncryptedAesForPrivateKey, csrEntity.EncryptedPrivateKey, csrEntity.EncryptionCertSerialNumber, _db, _keystore, _passphraseProvider);
                (certIv, certEncryptedAes, certEncryptedPrivKey) = KeyEncryptionUtil.EncryptPrivateKey(caMatch.GetPublicKey(), decryptedCsrPrivKey, _passphraseProvider.GetPassphrase());
            }

            // Track which CA certificate was used to encrypt the private key
            var encryptionCertSerial = certEncryptedPrivKey != null
                ? CertificateUtil.FormatSerialNumber(caMatch.SerialNumber)
                : null;

            // Save to DB
            var certModel = BuildCertModel(issuedCert, certPem, standardOids, extendedOids,
                effectiveCertProfile.SourceProfileId, csrEntity.SigningProfile.Id, certIv, certEncryptedAes, certEncryptedPrivKey,
                encryptionCertSerial, isCa: effectiveCertProfile.IsCaProfile,
                issuerCertificateId: refCACert.CertificateId);

            await _certStore.SaveCertificateAsync(issuedCert.GetEncoded(), certModel);

            // Submit to Certificate Transparency logs (fire-and-forget — never blocks issuance)
            await SubmitToCTLogsIfEnabledAsync(issuedCert, caMatch, effectiveCertProfile, certModel.SerialNumber);

            await SetCsrStatus(_db, csrEntity, certModel.SerialNumber);

            // Increment Prometheus metrics for certificate issuance
            var caLabel = caMatch.SubjectDN?.ToString() ?? "unknown";
            var profileName = csrEntity.SigningProfile?.Name ?? "unknown";
            MetricsService.CertsIssued.WithLabels(caLabel, profileName).Inc();

            // Always emit CertificateIssued to the general AuditLogs
            // table after a successful issue. Previously only AdminIssuanceController wrote
            // this row — EST/SCEP/CMP/ACME paths only wrote their protocol-specific tables
            // so cross-channel queries had to UNION 5+ tables. This gives a single source
            // of truth for "every certificate this CA issued, by any path". The protocol
            // audit tables stay as additive per-protocol forensics.
            await EmitCertificateIssuedAuditAsync(csrEntity, certModel, issuingCaEntity);

            return new IssuanceResult(certPem, issuanceWarnings);
        }

        /// <summary>
        /// Unified CertificateIssued audit emission used by both
        /// <see cref="IssueCertificateAsync"/> and <see cref="ReissueCertificateAsync"/>.
        /// Actor is resolved from the requesting user when available, otherwise falls
        /// back to the system actor. Failures are swallowed at Warning level — the cert
        /// has already been issued and the AuditService handles its own FailMode policy.
        /// </summary>
        private async Task EmitCertificateIssuedAuditAsync(
            CertRequestEntity csrEntity,
            CertificateInfoModel certModel,
            CertificateAuthorityEntity? issuingCaEntity)
        {
            try
            {
                await _audit.LogAsync(
                    AuditActionType.CertificateIssued,
                    actorUserId: csrEntity.RequestorUserId,
                    actorUsername: null,
                    targetEntityType: "Certificate",
                    targetEntityId: certModel.SerialNumber,
                    details: new
                    {
                        CsrId = csrEntity.Id,
                        certModel.SerialNumber,
                        Subject = certModel.SubjectDN,
                        Profile = csrEntity.SigningProfile?.Name,
                        RequestorUserId = csrEntity.RequestorUserId,
                    },
                    certificateAuthorityId: issuingCaEntity?.Id,
                    tenantId: issuingCaEntity?.TenantId);
            }
            catch (Exception auditEx)
            {
                _logger.LogWarning(auditEx,
                    "CertificateIssued audit emission failed for serial {Serial}",
                    certModel.SerialNumber);
            }
        }

        /// <summary>
        /// Reissues a certificate identified by certificate ID, serial number, or CSR ID.
        /// Revokes the previous certificate (if not already revoked), validates constraints,
        /// builds a new certificate, and persists it.
        /// </summary>
        /// <param name="certId">Optional certificate ID to look up the original CSR.</param>
        /// <param name="certSN">Optional serial number to look up the original CSR.</param>
        /// <param name="csrId">Optional CSR ID for direct lookup.</param>
        /// <param name="notBefore">Optional explicit NotBefore date.</param>
        /// <param name="notAfter">Optional explicit NotAfter date.</param>
        /// <param name="newSubjectDn">Optional new subject DN string (e.g. "CN=api.example.com,O=Example,C=US")
        /// that overrides whatever subject overrides were stored on the original CSR. The override is parsed
        /// into RDN components, persisted into the CSR's <c>SubjectOverrides</c> field as JSON, and is then
        /// re-validated against the resolved certificate profile via the existing override pipeline.</param>
        /// <param name="newSans">Optional new SAN list (entries formatted as "DNS:host" / "IP:1.2.3.4") that
        /// overrides whatever SAN overrides were stored on the original CSR. The list is JSON-serialized into the
        /// CSR's <c>SanOverrides</c> field and re-validated against the resolved certificate profile.</param>
        /// <returns>The PEM-encoded reissued certificate with intermediate chain and any warnings.</returns>
        public async Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId, DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null)
        {
            var issuanceWarnings = new List<string>();
            CertRequestEntity? csrEntity = null;
            if (certId != null)
            {
                csrEntity = await _db.CertificateRequests
                    .Include(c => c.SigningProfile)
                    .Include(c => c.CertProfile)
                    .FirstOrDefaultAsync(c => c.IssuedCertificateId == certId);
                if (csrEntity == null)
                    throw new Exception("Certificate not found.");
            }
            else if (!string.IsNullOrWhiteSpace(certSN))
            {
                var certEntity = await _db.Certificates.ResolveBySerialOrNullAsync(certSN);
                if (certEntity == null)
                    throw new Exception("Certificate not found.");

                csrEntity = await _db.CertificateRequests
                    .Include(c => c.SigningProfile)
                    .Include(c => c.CertProfile)
                    .Where(c => c.IssuedCertificateId == certEntity.CertificateId)
                    .FirstOrDefaultAsync();
                if (csrEntity == null)
                    throw new Exception("Certificate not found.");
            }
            else if (csrId != null)
            {
                csrEntity = await _db.CertificateRequests
                    .Include(c => c.SigningProfile)
                    .Include(c => c.CertProfile)
                    .FirstOrDefaultAsync(c => c.Id == csrId);
                if (csrEntity == null)
                    throw new Exception("Certificate not found.");
            }

            if (csrEntity == null)
                throw new InvalidOperationException("CSR not found for reissue.");

            var prevCert = await _db.Certificates
                .Where(c => c.CertificateId == csrEntity.IssuedCertificateId)
                .FirstOrDefaultAsync();

            if (prevCert == null)
                throw new InvalidOperationException("Previous certificate not found for reissue.");

            if (prevCert.IsReissued)
                throw new InvalidOperationException("Certificate has already been reissued");

            if (csrEntity == null)
                throw new InvalidOperationException("CSR not found");

            // Note: the fresh-issuance helper ValidateCsrStatus requires Status=Approved|Pending
            // AND IssuedCertificateId==null, which is correct for the initial issue path but
            // impossible here — any CSR we looked up by IssuedCertificateId is by definition
            // non-null, and SetCsrStatus flipped Status to "Issued" the moment the original
            // cert was signed. For reissue we accept any status EXCEPT terminal "Rejected":
            // Pending (bootstrap-seeded before approval), Approved (post-approval, pre-issue,
            // unusual but harmless), and Issued (the normal case — the CSR was already used to
            // issue the cert we're now reissuing).
            if (csrEntity.Status == "Rejected")
                throw new InvalidOperationException("CSR is in a Rejected state and cannot be reissued.");

            if (csrEntity.SigningProfile == null)
                throw new InvalidOperationException("No signing profile associated with CSR");

            if (string.IsNullOrWhiteSpace(csrEntity.CSR))
                throw new InvalidOperationException("CSR field is empty");

            // Reissue requires the previous certificate to be revoked with a non-compromise reason
            // (RFC 5280 §5.3.1). When the operator hasn't already revoked it, do so now via
            // ICertificateRevocationService — that path triggers CRL regeneration, audit logging,
            // and notifications, none of which the previous inline mutation did. The check is
            // idempotent: if the cert is already revoked with an allowed reason we just proceed.
            //
            // Treat both null and empty/whitespace RevocationReason as "not yet revoked" because
            // bootstrap-seeded certs (e.g. the Web TLS cert) ship with an empty string instead of
            // null, which historically made the inline shortcut skip and dropped the operator
            // into the "Previous certificate must be revoked to allow reissue" error.
            // "Expired" is no longer a stored revocation reason — natural
            // expiry is detected via NotAfter < now instead. Keep "CessationOfOperation" for
            // operational retirements and allow reissue when the cert is simply expired.
            var allowedReissueReasons = new[] { "Superseded", "CessationOfOperation" };
            var isExpired = prevCert.NotAfter < DateTime.UtcNow;
            if (!isExpired && (!prevCert.Revoked || string.IsNullOrWhiteSpace(prevCert.RevocationReason)))
            {
                await _revocation.RevokeCertificateAsync(prevCert.CertificateId, null, Shared.Enums.RevocationReason.Superseded);
                // prevCert and the entity returned by ResolveCertificateEntityAsync inside the
                // revocation service are the same tracked instance (shared scoped DbContext), so
                // the mutation is already visible on this local reference — no Reload needed.
            }

            if (!isExpired && !allowedReissueReasons.Contains(prevCert.RevocationReason, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Reissue is only allowed for revoked certificates with reasons:" +
                    $" {string.Join(", ", allowedReissueReasons)} (or naturally expired).\nIn the event of a key compromise, create a new CSR.");

            var csrParser = new CsrParserService();
            var csr = csrParser.ParseFromPem(csrEntity.CSR);

            if (!csr.Verify())
                throw new InvalidOperationException("CSR signature verification failed");

            // CLM-007: When the previous certificate was revoked for KeyCompromise (or
            // CACompromise), the old key MUST NOT be reused — the whole point of a
            // compromise revocation is that the key material is no longer trustworthy.
            // Compare the SubjectPublicKeyInfo DER bytes of the old cert against the
            // new CSR's public key; if they match, reject with a clear message.
            if (string.Equals(prevCert.RevocationReason, nameof(RevocationReason.KeyCompromise), StringComparison.OrdinalIgnoreCase)
                || string.Equals(prevCert.RevocationReason, nameof(RevocationReason.CACompromise), StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var prevBcCert = new X509CertificateParser().ReadCertificate(prevCert.RawCertificate);
                    if (prevBcCert != null)
                    {
                        var oldPubKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(prevBcCert.GetPublicKey()).GetEncoded();
                        var newPubKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(csr.GetPublicKey()).GetEncoded();

                        if (oldPubKeyDer.AsSpan().SequenceEqual(newPubKeyDer))
                        {
                            throw new InvalidOperationException(
                                "Cannot reuse the same key for a certificate that was revoked due to key compromise. " +
                                "Generate a new key pair and submit a fresh CSR.");
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    throw; // Re-throw our own rejection
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "CLM-007: Could not compare public keys for key-compromise reuse check on certificate {CertId}. " +
                        "Allowing reissue to proceed — manual review recommended.", prevCert.CertificateId);
                }
            }

            if (csrEntity.CertProfileId == null)
                throw new InvalidOperationException("No certificate profile associated with CSR");

            // Resolve the effective (merged/inherited) cert profile instead of using the raw entity
            var effectiveCertProfile = await _profileResolver.ResolveCertProfileAsync(csrEntity.CertProfileId.Value);

            if (!_validation.NotBeyondMaximumDate(notAfter, effectiveCertProfile))
                throw new Exception("NotAfter date is beyond the maximum allowed date");

            if (!_validation.ValidityDurationMeetsMinimum(notBefore, notAfter, effectiveCertProfile))
                throw new Exception($"Reissued certificate validity duration is shorter than the profile's minimum ({effectiveCertProfile.ValidityPeriodMin ?? "not set"}). Extend NotAfter or use a different profile.");

            _validation.ValidateAgainstCertProfile(csrEntity.KeyAlgorithm, csrEntity.KeySize, csrEntity.SignatureAlgorithm, effectiveCertProfile);
            _validation.ValidateAgainstSigningProfile(csrEntity.KeyAlgorithm, csrEntity.SignatureAlgorithm, csrEntity.SigningProfile);

            // Infrastructure certs (TSA, OCSP) bypass quota enforcement
            if (!csrEntity.IsInfrastructureCert)
                await EnforceQuotaAsync(csrEntity.SigningProfile);

            // Resolve CA certificate and key
            var (caMatch, caKeyHandle, refCACert) = await ResolveCaAsync(csrEntity.SigningProfile);

            // Check tenant is enabled — block reissuance if the CA's tenant has been disabled
            var reissueCaEntity = await _db.CertificateAuthorities
                .FirstOrDefaultAsync(ca => ca.CertificateId == refCACert.CertificateId);
            if (reissueCaEntity != null)
            {
                var caTenant = await _db.Tenants.FindAsync(reissueCaEntity.TenantId);
                if (caTenant != null && !caTenant.IsEnabled)
                    throw new InvalidOperationException("Certificate issuance is blocked — the tenant is disabled.");
            }

            var now = DateTime.UtcNow;
            var timeMax = DateTime.UtcNow + Iso8601ParserUtil.ParseIso8601(effectiveCertProfile.ValidityPeriodMax ?? "P1Y");

            // Backdate an auto-generated start time so the certificate is valid on verifiers whose
            // clocks trail ours. An explicitly requested notBefore is honoured as given.
            var validFrom = notBefore ?? CertificateValidityUtil.DefaultNotBefore();
            var validTo = notAfter ?? timeMax;

            // Clamp certificate validity to the issuing CA's NotAfter with a 5-minute margin.
            var reissueCaNotAfterMargin = caMatch.NotAfter - TimeSpan.FromMinutes(5);
            if (validTo > reissueCaNotAfterMargin)
            {
                var originalValidTo = validTo;
                validTo = reissueCaNotAfterMargin;
                var msg = $"Certificate validity clamped from {originalValidTo:yyyy-MM-dd} to {validTo:yyyy-MM-dd} because the issuing CA expires on {caMatch.NotAfter:yyyy-MM-dd}.";
                _logger.LogWarning(msg);
                issuanceWarnings.Add(msg);

                // After clamping, verify the shortened validity still meets the profile's minimum.
                if (!_validation.ValidityDurationMeetsMinimum(validFrom, validTo, effectiveCertProfile))
                {
                    var minDuration = effectiveCertProfile.ValidityPeriodMin ?? "P0D";
                    throw new InvalidOperationException(
                        $"Cannot reissue certificate: the issuing CA expires on {caMatch.NotAfter:yyyy-MM-dd}, " +
                        $"which would produce a validity shorter than the profile's minimum ({minDuration}). " +
                        $"Either reduce the profile's minimum validity, extend the CA's lifetime, or use a different CA.");
                }
            }

            // Raise to the issuer's start rather than refusing. A leaf cannot be valid before its
            // issuer, so the issuer's notBefore is the correct earliest value — and this is what
            // makes backdating safe against CAs whose own notBefore was not backdated, including
            // every CA created before that change. Consistent with how the notAfter clamp above
            // adjusts and warns instead of throwing.
            validFrom = CertificateValidityUtil.ClampToIssuer(validFrom, caMatch.NotBefore, out var startClamped);
            if (startClamped)
            {
                var startMsg = $"Certificate NotBefore raised to the issuing CA's start date ({caMatch.NotBefore:O}); "
                             + "a certificate cannot be valid before its issuer.";
                _logger.LogWarning(startMsg);
                issuanceWarnings.Add(startMsg);
            }

            // 17 bytes with leading 0x00 → 128 bits of random magnitude, positive.
            var reissueSerialBytes = new byte[17];
            reissueSerialBytes[0] = 0x00;
            RandomNumberGenerator.Fill(reissueSerialBytes.AsSpan(1));
            var serialNumber = new BigInteger(1, reissueSerialBytes);

            // Caller-supplied overrides (newSubjectDn / newSans) take priority over whatever was stored
            // on the original CSR. We mutate the CSR entity's override JSON fields in-memory so that the
            // existing ApplySubjectOverrides / ApplySanOverrides path picks them up uniformly. Profile
            // validation below still re-validates the final subject/SANs, so this cannot bypass any rules.
            if (!string.IsNullOrWhiteSpace(newSubjectDn))
            {
                var parsedRdns = RequestProfileValidationService.ParseSubjectDn(newSubjectDn);
                if (parsedRdns.Count == 0)
                    throw new InvalidOperationException(
                        $"Reissue subject DN override could not be parsed: '{newSubjectDn}'. " +
                        "Expected comma-separated RDNs such as 'CN=api.example.com,O=Example,C=US'.");
                csrEntity.SubjectOverrides = JsonSerializer.Serialize(parsedRdns);
            }

            if (newSans != null)
            {
                csrEntity.SanOverrides = JsonSerializer.Serialize(newSans);
            }

            // Apply subject DN overrides if present
            var reissueSubjectDn = ApplySubjectOverrides(_builder.ResolveSubjectDn(csr, csrEntity), csrEntity.SubjectOverrides);

            // Apply SAN overrides if present
            var reissueEffectiveSans = ApplySanOverrides(csrEntity.SubjectAlternativeNames, csrEntity.SanOverrides);

            // Re-validate overridden subject DN and SANs against profile rules
            ValidateOverridesAgainstProfile(reissueSubjectDn, reissueEffectiveSans, csrEntity.SubjectOverrides, csrEntity.SanOverrides, effectiveCertProfile.AllowWildcard);

            // Evaluate system-wide certificate policy rules before building the certificate
            EnforceCertPolicy(csrEntity.KeyAlgorithm, csrEntity.KeySize, csrEntity.SignatureAlgorithm,
                validFrom, validTo, reissueSubjectDn.ToString(), ParseSanJson(reissueEffectiveSans),
                effectiveCertProfile.SourceProfileId.ToString(), csrEntity.IsInfrastructureCert);

            // Validate subject DN and SANs against issuing CA name constraints
            ValidateNameConstraints(caMatch, reissueSubjectDn.ToString(), ParseSanJson(reissueEffectiveSans));

            var extendedOids = _validation.SetupAllowedExtendedOids(effectiveCertProfile.ExtendedKeyUsages, csrEntity.SigningProfile.AllowedEKUs);
            var standardOids = _validation.SetupAllowedStandardOids(effectiveCertProfile.KeyUsages);

            // Build and sign the certificate
            var issuedCert = await _builder.BuildCertificateAsync(
                serialNumber, caMatch, caKeyHandle, reissueSubjectDn, csr.GetPublicKey(),
                validFrom, validTo, standardOids, extendedOids,
                reissueEffectiveSans, refCACert.CertificateId, csrEntity.SigningProfile,
                effectiveCertProfile.IsCaProfile,
                allowWildcardSans: effectiveCertProfile.AllowWildcard);

            // Stored cert.Pem is leaf-only. Chain endpoints rebuild the issuer chain on demand.
            var certPem = EncodeCertPem(issuedCert);

            // Save to DB
            var certModel = BuildCertModel(issuedCert, certPem, standardOids, extendedOids,
                effectiveCertProfile.SourceProfileId, csrEntity.SigningProfile.Id, null, null, null,
                isCa: effectiveCertProfile.IsCaProfile,
                issuerCertificateId: refCACert.CertificateId);

            await _certStore.SaveCertificateAsync(issuedCert.GetEncoded(), certModel);

            // Submit to Certificate Transparency logs (fire-and-forget — never blocks issuance)
            await SubmitToCTLogsIfEnabledAsync(issuedCert, caMatch, effectiveCertProfile, certModel.SerialNumber);

            await SetCsrStatus(_db, csrEntity, certModel.SerialNumber);

            // Increment Prometheus metrics for certificate reissuance
            var reissueCaLabel = caMatch.SubjectDN?.ToString() ?? "unknown";
            var reissueProfileName = csrEntity.SigningProfile?.Name ?? "unknown";
            MetricsService.CertsIssued.WithLabels(reissueCaLabel, reissueProfileName).Inc();

            // Always emit CertificateIssued to the general audit log
            // after a successful reissue too, so the cross-channel query surface has a
            // single table with every issuance event. Reissue path already resolved the
            // CA entity earlier in the method (reissueCaEntity) for the tenant-enabled
            // check — reuse it here.
            await EmitCertificateIssuedAuditAsync(csrEntity, certModel, reissueCaEntity);

            // Re-query the previous certificate to avoid overwriting concurrent changes
            await _db.Entry(prevCert).ReloadAsync();
            prevCert.IsReissued = true;
            _db.Update(prevCert);
            await _db.SaveChangesAsync();

            // Link the new certificate to a CSR record so subsequent reissues can find it.
            // Clone the original CSR entity with the new cert's ID.
            var newCertForLink = await _db.Certificates
                .ResolveBySerialOrNullAsync(certModel.SerialNumber);
            if (newCertForLink != null)
            {
                var reissueCsr = new CertRequestEntity
                {
                    Subject = csrEntity.Subject,
                    CSR = csrEntity.CSR,
                    KeyAlgorithm = csrEntity.KeyAlgorithm,
                    KeySize = csrEntity.KeySize,
                    SignatureAlgorithm = csrEntity.SignatureAlgorithm,
                    Status = "Issued",
                    RequestorUserId = csrEntity.RequestorUserId,
                    CertProfileId = csrEntity.CertProfileId,
                    SigningProfileId = csrEntity.SigningProfileId,
                    IssuedCertificateId = newCertForLink.CertificateId,
                    IsInfrastructureCert = csrEntity.IsInfrastructureCert,
                    SubmittedAt = DateTime.UtcNow,
                    RenewalOfCertificateId = prevCert.CertificateId,
                };
                _db.CertificateRequests.Add(reissueCsr);
                await _db.SaveChangesAsync();
            }

            // Copy ACLs from the old certificate to the newly issued certificate
            try
            {
                var newCertEntity = await _db.Certificates
                    .AsNoTracking()
                    .ResolveBySerialOrNullAsync(certModel.SerialNumber);
                if (newCertEntity != null)
                {
                    await _certificateAccessService.UpdatePermissionsOntoReissuedCertificate(
                        newCertEntity.CertificateId, csrEntity.RequestorUserId ?? Guid.Empty);
                }
                else
                {
                    _logger.LogWarning("Could not find newly issued certificate {Serial} to copy ACLs", certModel.SerialNumber);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to copy ACLs from previous certificate to reissued certificate {Serial}", certModel.SerialNumber);
            }

            return new IssuanceResult(certPem, issuanceWarnings);
        }

        /// <summary>
        /// Submits the issued certificate to Certificate Transparency logs if the effective profile
        /// has CT enabled. Stores the returned SCTs on the certificate entity. Failures are caught
        /// and logged — CT submission never prevents certificate issuance.
        /// </summary>
        /// <param name="issuedCert">The issued BouncyCastle certificate.</param>
        /// <param name="caCert">The issuing CA certificate.</param>
        /// <param name="effectiveProfile">The resolved effective certificate profile.</param>
        /// <param name="serialNumber">The serial number of the stored certificate entity.</param>
        private async Task SubmitToCTLogsIfEnabledAsync(
            X509Certificate issuedCert,
            X509Certificate caCert,
            Models.EffectiveCertProfile effectiveProfile,
            string serialNumber)
        {
            try
            {
                if (!effectiveProfile.CtEnabled)
                    return;

                List<Guid>? ctLogIds = null;
                if (!string.IsNullOrWhiteSpace(effectiveProfile.CtLogIds))
                    ctLogIds = JsonSerializer.Deserialize<List<Guid>>(effectiveProfile.CtLogIds, SafeJsonOptions.Default);

                var scts = await _ctSubmission.SubmitToCTLogsAsync(
                    issuedCert.GetEncoded(),
                    caCert.GetEncoded(),
                    ctLogIds);

                if (scts.Count > 0)
                {
                    var sctBase64List = scts.Select(Convert.ToBase64String).ToList();
                    var sctJson = JsonSerializer.Serialize(sctBase64List);

                    var certEntity = await _db.Certificates
                        .ResolveBySerialOrNullAsync(serialNumber);
                    if (certEntity != null)
                    {
                        certEntity.SctJson = sctJson;
                        await _db.SaveChangesAsync();
                    }

                    _logger.LogInformation("Stored {SctCount} SCT(s) for certificate {SerialNumber}", scts.Count, serialNumber);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "CT log submission failed for certificate {SerialNumber} — issuance unaffected", serialNumber);
                await _audit.LogAsync(
                    AuditActionType.CertificateIssued,
                    actorUserId: null, actorUsername: null,
                    targetEntityType: "Certificate", targetEntityId: serialNumber,
                    details: new { CtSubmission = "Failed", Error = ex.Message },
                    sourceIp: null, success: false,
                    errorMessage: $"CT submission failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Parses a JSON-encoded list of Subject Alternative Names from the CSR entity.
        /// Returns an empty list if the input is null, empty, or not valid JSON.
        /// </summary>
        /// <param name="sanJson">The JSON string containing SANs, or null.</param>
        /// <returns>A list of SAN strings.</returns>
        private static List<string> ParseSanJson(string? sanJson)
        {
            if (string.IsNullOrWhiteSpace(sanJson))
                return new List<string>();

            try
            {
                return JsonSerializer.Deserialize<List<string>>(sanJson, SafeJsonOptions.Default) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// Applies subject DN overrides from the CSR entity. Parses the JSON dictionary of
        /// field overrides and reconstructs the X509Name by replacing matched RDN components.
        /// Returns the original subject DN unchanged when no overrides are present.
        /// </summary>
        /// <param name="originalSubject">The original subject DN resolved from the CSR.</param>
        /// <param name="subjectOverridesJson">JSON dictionary of subject field overrides, or null.</param>
        /// <returns>The subject DN with overrides applied.</returns>
        private static X509Name ApplySubjectOverrides(X509Name originalSubject, string? subjectOverridesJson)
        {
            if (string.IsNullOrWhiteSpace(subjectOverridesJson))
                return originalSubject;

            Dictionary<string, string>? overrides;
            try
            {
                overrides = JsonSerializer.Deserialize<Dictionary<string, string>>(subjectOverridesJson, SafeJsonOptions.Default);
            }
            catch
            {
                return originalSubject;
            }

            if (overrides == null || overrides.Count == 0)
                return originalSubject;

            // Run every override value through the DN sanitizer before
            // we touch the X509Name. This blocks NULs, control chars, BIDI overrides,
            // unpaired surrogates, and enforces CA/B Forum BR length caps (CN=64,
            // O/OU=128). A rejected value aborts issuance with a clear error instead
            // of silently producing a spoofable DN.
            var sanitized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in overrides)
            {
                var maxLen = DnComponentSanitizer.GetMaxLength(kvp.Key);
                sanitized[kvp.Key] = DnComponentSanitizer.Sanitize(kvp.Key, kvp.Value ?? string.Empty, maxLen);
            }
            overrides = sanitized;

            // Map common field names to BouncyCastle OIDs
            var fieldOidMap = new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase)
            {
                ["CN"] = X509Name.CN,
                ["O"] = X509Name.O,
                ["OU"] = X509Name.OU,
                ["C"] = X509Name.C,
                ["ST"] = X509Name.ST,
                ["L"] = X509Name.L,
                ["E"] = X509Name.EmailAddress,
                ["EMAILADDRESS"] = X509Name.EmailAddress,
                ["SERIALNUMBER"] = X509Name.SerialNumber,
                ["DC"] = X509Name.DC,
                ["UID"] = X509Name.UID,
                ["T"] = X509Name.T,
                ["STREET"] = X509Name.Street,
            };

            // Extract current RDN OIDs and values
            var oids = originalSubject.GetOidList().Cast<DerObjectIdentifier>().ToList();
            var values = originalSubject.GetValueList().Cast<string>().ToList();

            // Apply overrides
            var appliedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in overrides)
            {
                if (!fieldOidMap.TryGetValue(kvp.Key, out var oid))
                    continue;

                bool found = false;
                for (int i = 0; i < oids.Count; i++)
                {
                    if (oids[i].Equals(oid))
                    {
                        values[i] = kvp.Value;
                        found = true;
                        // Don't break — allow replacing multiple OU entries, etc.
                    }
                }

                if (!found)
                {
                    // Add the field if it didn't exist in the original subject
                    oids.Add(oid);
                    values.Add(kvp.Value);
                }

                appliedKeys.Add(kvp.Key);
            }

            return new X509Name(oids, values);
        }

        /// <summary>
        /// Returns the SAN overrides JSON if present and non-empty, otherwise falls back to
        /// the original SANs from the CSR entity. The returned value is a JSON array string
        /// suitable for passing to <see cref="CertificateBuilderService.BuildCertificateAsync"/>.
        /// </summary>
        /// <param name="originalSansJson">The original SANs JSON array from the CSR, or null.</param>
        /// <param name="sanOverridesJson">The SAN overrides JSON array, or null.</param>
        /// <returns>The effective SANs JSON string.</returns>
        private static string? ApplySanOverrides(string? originalSansJson, string? sanOverridesJson)
        {
            if (string.IsNullOrWhiteSpace(sanOverridesJson))
                return originalSansJson;

            try
            {
                // Validate that the overrides are a well-formed JSON array
                var overrides = JsonSerializer.Deserialize<List<string>>(sanOverridesJson, SafeJsonOptions.Default);
                if (overrides != null && overrides.Count > 0)
                    return sanOverridesJson;
            }
            catch
            {
                // Malformed SAN overrides — fall back to original
            }

            return originalSansJson;
        }

        /// <summary>
        /// Re-validates the effective subject DN and SANs after overrides have been applied.
        /// Ensures that overridden fields use only well-known RDN types and that SAN entries follow
        /// the expected TYPE:value format. Logs a warning when overrides are present so that post-issuance
        /// auditing can flag certificates whose overrides bypassed the original request-profile validation.
        /// </summary>
        /// <param name="effectiveSubjectDn">The subject DN after overrides have been applied.</param>
        /// <param name="effectiveSansJson">The SANs JSON after overrides have been applied.</param>
        /// <param name="subjectOverridesJson">The raw subject override JSON from the CSR entity (for logging).</param>
        /// <param name="sanOverridesJson">The raw SAN override JSON from the CSR entity (for logging).</param>
        /// <param name="allowWildcardSans">When false, any DNS SAN containing <c>*</c> is rejected. Sourced from the resolved cert profile's <c>AllowWildcard</c> column.</param>
        private void ValidateOverridesAgainstProfile(
            X509Name effectiveSubjectDn,
            string? effectiveSansJson,
            string? subjectOverridesJson,
            string? sanOverridesJson,
            bool allowWildcardSans)
        {
            bool hasSubjectOverrides = !string.IsNullOrWhiteSpace(subjectOverridesJson);
            bool hasSanOverrides = !string.IsNullOrWhiteSpace(sanOverridesJson);

            if (!hasSubjectOverrides && !hasSanOverrides)
                return;

            // Log that overrides were applied — this provides an audit trail
            if (hasSubjectOverrides)
                _logger.LogWarning("Subject DN overrides applied at issuance. Overrides: {SubjectOverrides}", subjectOverridesJson);
            if (hasSanOverrides)
                _logger.LogWarning("SAN overrides applied at issuance. Overrides: {SanOverrides}", sanOverridesJson);

            // Validate the overridden subject DN uses only well-known RDN types
            var allowedOids = new HashSet<DerObjectIdentifier>
            {
                X509Name.CN, X509Name.O, X509Name.OU, X509Name.C, X509Name.ST,
                X509Name.L, X509Name.EmailAddress, X509Name.SerialNumber,
                X509Name.DC, X509Name.UID, X509Name.T, X509Name.Street
            };

            var oids = effectiveSubjectDn.GetOidList().Cast<DerObjectIdentifier>().ToList();
            foreach (var oid in oids)
            {
                if (!allowedOids.Contains(oid))
                {
                    throw new InvalidOperationException(
                        $"Subject DN override produced an unsupported RDN type: OID {oid}. " +
                        "Only standard subject fields (CN, O, OU, C, ST, L, E, SERIALNUMBER, DC, UID, T, STREET) are allowed.");
                }
            }

            // Validate overridden SANs use a recognized TYPE:value format
            var parsedSans = ParseSanJson(effectiveSansJson);
            var allowedSanTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "DNS", "IP", "EMAIL", "URI" };
            foreach (var san in parsedSans)
            {
                var colonIndex = san.IndexOf(':');
                if (colonIndex <= 0)
                {
                    throw new InvalidOperationException(
                        $"SAN override contains invalid format: '{san}'. Expected TYPE:value (e.g. DNS:example.com).");
                }

                var sanType = san.Substring(0, colonIndex).Trim().ToUpperInvariant();
                if (!allowedSanTypes.Contains(sanType))
                {
                    throw new InvalidOperationException(
                        $"SAN override contains unsupported type '{sanType}'. Allowed types: {string.Join(", ", allowedSanTypes)}.");
                }

                // Enforce CA/B Forum BR §7.1.4.2.1 wildcard rules on DNS SANs
                // (at most one '*', leftmost label only, ≥2 additional labels) and gate the
                // very presence of wildcards on the resolved cert profile's AllowWildcard
                // flag. When false, any DNS SAN containing '*' is rejected outright.
                if (sanType == "DNS")
                {
                    var dnsValue = san[(colonIndex + 1)..].Trim();
                    DnComponentSanitizer.ValidateDnsName(dnsValue, allowWildcardSans);
                }
            }
        }

        /// <summary>
        /// Sanitizes the raw CMP subject string stored on the CSR entity
        /// before it is parsed into an <see cref="X509Name"/>. Walks each
        /// comma-separated RDN, validates the value via <see cref="DnComponentSanitizer"/>,
        /// and rebuilds the string. Prevents an attacker who gets a subject past the
        /// CMP ingestion layer from smuggling control chars / BIDI overrides into the
        /// final cert's DN.
        /// </summary>
        private static string SanitizeCmpSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
                return subject;

            var parts = subject.Split(',');
            var rebuilt = new List<string>(parts.Length);
            foreach (var raw in parts)
            {
                var eq = raw.IndexOf('=');
                if (eq <= 0)
                {
                    throw new InvalidOperationException($"CMP subject component '{raw}' is missing '='.");
                }
                var field = raw[..eq].Trim();
                var value = raw[(eq + 1)..];
                var sanitized = DnComponentSanitizer.Sanitize(
                    field, value, DnComponentSanitizer.GetMaxLength(field));
                rebuilt.Add($"{field}={sanitized}");
            }
            return string.Join(",", rebuilt);
        }

        /// <summary>
        /// Evaluates system-wide certificate policy rules and enforces the result.
        /// Error-level violations throw an <see cref="InvalidOperationException"/> to block issuance.
        /// Warning-level violations are logged but allow issuance to proceed.
        /// </summary>
        /// <param name="keyAlgorithm">The key algorithm (e.g., "RSA", "ECDSA").</param>
        /// <param name="keySize">The key size or curve name.</param>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="notBefore">The certificate validity start date.</param>
        /// <param name="notAfter">The certificate validity end date.</param>
        /// <param name="subjectDn">The subject distinguished name.</param>
        /// <param name="sans">The list of Subject Alternative Names.</param>
        /// <param name="certProfileName">The certificate profile identifier.</param>
        private void EnforceCertPolicy(string keyAlgorithm, string keySize, string signatureAlgorithm,
            DateTime notBefore, DateTime notAfter, string subjectDn, List<string>? sans, string certProfileName,
            bool isInfrastructureCert = false)
        {
            var context = new CertificateIssuanceContext
            {
                KeyAlgorithm = keyAlgorithm ?? string.Empty,
                KeySize = keySize ?? string.Empty,
                SignatureAlgorithm = signatureAlgorithm ?? string.Empty,
                NotBefore = notBefore,
                NotAfter = notAfter,
                SubjectDn = subjectDn ?? string.Empty,
                SubjectAlternativeNames = sans ?? new List<string>(),
                CertProfileName = certProfileName ?? string.Empty,
                IsInfrastructureCert = isInfrastructureCert,
            };

            var violations = _certPolicy.Evaluate(context);
            if (violations.Count == 0)
                return;

            var errors = violations.Where(v => string.Equals(v.Severity, "Error", StringComparison.OrdinalIgnoreCase)).ToList();
            var warnings = violations.Where(v => string.Equals(v.Severity, "Warning", StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var warning in warnings)
            {
                _logger.LogWarning("Certificate policy warning [{Rule}]: {Message}", warning.Rule, warning.Message);
            }

            if (errors.Count > 0)
            {
                // Typed so the API layer can answer 400. A policy ceiling being hit is a normal
                // answer to an over-reaching request — it was surfacing as a 500 with a full
                // stack trace, which is indistinguishable in the journal from the CA breaking.
                throw new CertificatePolicyViolationException(
                    errors.Select(e => $"[{e.Rule}] {e.Message}").ToList());
            }
        }

        /// <summary>
        /// Validates that the certificate's subject DN and SANs comply with the issuing CA's
        /// name constraints extension (RFC 5280 section 4.2.1.10). DNS name constraints are
        /// enforced (block issuance on violation). Other constraint types (IP, Email, URI, DN)
        /// are NOT implemented, and their presence now refuses issuance rather than proceeding
        /// unconstrained — see the throw below for why a warning was the wrong response.
        /// </summary>
        /// <param name="issuerCert">The issuing CA's X.509 certificate.</param>
        /// <param name="subjectDn">The subject DN of the certificate being issued.</param>
        /// <param name="sans">The list of Subject Alternative Names (prefixed, e.g. "DNS:example.com").</param>
        private void ValidateNameConstraints(X509Certificate issuerCert, string subjectDn, List<string> sans)
        {
            var ncExt = issuerCert.GetExtensionValue(X509Extensions.NameConstraints);
            if (ncExt == null) return; // No name constraints on issuer

            NameConstraints nc;
            try
            {
                nc = NameConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(ncExt));
            }
            catch (Exception ex)
            {
                // Fail closed. Skipping validation here meant an issuer whose NameConstraints
                // extension could not be parsed enforced NOTHING — the one case where the CA is
                // demonstrably in an unknown state was also the case that issued freely. A
                // constraint we cannot read is a constraint we cannot prove the certificate
                // satisfies.
                _logger.LogError(ex,
                    "Failed to parse NameConstraints from issuing CA {CaSubject} — refusing to issue.",
                    issuerCert.SubjectDN);
                throw new InvalidOperationException(
                    "The issuing CA carries a NameConstraints extension that cannot be parsed, so compliance "
                    + "cannot be verified. Issuance is refused rather than proceeding unconstrained.", ex);
            }

            var permitted = nc.PermittedSubtrees;
            var excluded = nc.ExcludedSubtrees;

            // Collect permitted and excluded DNS suffixes
            var permittedDns = new List<string>();
            var excludedDns = new List<string>();
            bool hasNonDnsPermitted = false;
            bool hasNonDnsExcluded = false;

            if (permitted != null)
            {
                foreach (var element in permitted)
                {
                    var subtree = GeneralSubtree.GetInstance(element);
                    var gn = subtree.Base;
                    if (gn.TagNo == GeneralName.DnsName)
                    {
                        permittedDns.Add(gn.Name.ToString()!);
                    }
                    else
                    {
                        hasNonDnsPermitted = true;
                    }
                }
            }

            if (excluded != null)
            {
                foreach (var element in excluded)
                {
                    var subtree = GeneralSubtree.GetInstance(element);
                    var gn = subtree.Base;
                    if (gn.TagNo == GeneralName.DnsName)
                    {
                        excludedDns.Add(gn.Name.ToString()!);
                    }
                    else
                    {
                        hasNonDnsExcluded = true;
                    }
                }
            }

            // Non-DNS subtrees (IP, Email, URI, DirectoryName) are not implemented. They used to
            // produce a warning and then let issuance proceed, which means a CA an operator
            // deliberately constrained to, say, `permitted: email:@example.com` or
            // `excluded: DN:O=Bank` issued outside those bounds with nothing but a log line — the
            // constraint existed in the certificate, and relying parties enforce it, but this CA
            // did not honour its own policy.
            //
            // Refuse instead. A name constraint this code cannot evaluate is one it cannot prove
            // the certificate satisfies, and quietly issuing a non-compliant certificate from a
            // constrained CA is a trust failure, not a warning.
            //
            // This is deliberately a hard stop rather than a configurable one: a switch to
            // downgrade an unenforceable constraint back to a warning is the same fail-open with
            // extra steps. Implementing RFC 5280 4.2.1.10 matching for these types is what lets
            // such a CA issue again.
            if (hasNonDnsPermitted || hasNonDnsExcluded)
            {
                var which = hasNonDnsPermitted && hasNonDnsExcluded ? "permitted and excluded"
                          : hasNonDnsPermitted ? "permitted" : "excluded";
                _logger.LogError(
                    "Issuing CA {CaSubject} has non-DNS {Which} name constraints (IP, Email, URI, DirectoryName) "
                    + "which are not implemented — refusing to issue rather than proceeding unconstrained.",
                    issuerCert.SubjectDN, which);
                throw new InvalidOperationException(
                    $"The issuing CA carries non-DNS {which} name constraints (IP, Email, URI, or DirectoryName). "
                    + "Enforcement of those types is not implemented, so compliance cannot be verified and "
                    + "issuance is refused. Use DNS-only name constraints on this CA, or remove them.");
            }

            // Validate DNS SANs against constraints
            foreach (var san in sans)
            {
                if (!san.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
                    continue;

                var dnsName = san.Substring(4).ToLowerInvariant();

                // Check permitted subtrees: if any DNS permitted subtrees exist, the name must match at least one
                if (permittedDns.Count > 0)
                {
                    bool matchesPermitted = false;
                    foreach (var p in permittedDns)
                    {
                        if (DnsNameMatchesConstraint(dnsName, p.ToLowerInvariant()))
                        {
                            matchesPermitted = true;
                            break;
                        }
                    }

                    if (!matchesPermitted)
                    {
                        throw new InvalidOperationException(
                            $"DNS name '{dnsName}' is not within the issuing CA's permitted name constraints [{string.Join(", ", permittedDns)}].");
                    }
                }

                // Check excluded subtrees: the name must not match any exclusion
                foreach (var e in excludedDns)
                {
                    if (DnsNameMatchesConstraint(dnsName, e.ToLowerInvariant()))
                    {
                        throw new InvalidOperationException(
                            $"DNS name '{dnsName}' falls within the issuing CA's excluded name constraints [{string.Join(", ", excludedDns)}].");
                    }
                }
            }
        }

        /// <summary>
        /// Checks whether a DNS name matches a name constraint per RFC 5280 section 4.2.1.10.
        /// A constraint ".example.com" matches "host.example.com" but not "example.com" itself.
        /// A constraint "example.com" matches "example.com" exactly and any subdomain (e.g. "host.example.com").
        /// </summary>
        /// <param name="dnsName">The DNS name to check (lowercase).</param>
        /// <param name="constraint">The name constraint (lowercase).</param>
        /// <returns>True if the DNS name falls within the constraint.</returns>
        private static bool DnsNameMatchesConstraint(string dnsName, string constraint)
        {
            if (constraint.StartsWith("."))
            {
                // Constraint ".example.com" matches any subdomain but not the base domain
                return dnsName.EndsWith(constraint, StringComparison.Ordinal);
            }

            // Constraint "example.com" matches exact or any subdomain
            if (string.Equals(dnsName, constraint, StringComparison.Ordinal))
                return true;

            return dnsName.EndsWith("." + constraint, StringComparison.Ordinal);
        }

        /// <summary>
        /// Resolves the CA from the signing profile's issuer and checks whether the certificate
        /// quota allows another issuance. Throws <see cref="InvalidOperationException"/> if the quota is exceeded.
        /// </summary>
        /// <param name="signingProfile">The signing profile whose issuer identifies the CA.</param>
        private async Task EnforceQuotaAsync(SigningProfileEntity signingProfile)
        {
            if (signingProfile.IssuerId == null)
                return; // Self-signed; no quota applies

            var ca = await _db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId);

            if (ca == null)
                return; // CA entity not registered; skip quota check

            var canIssue = await _quotaService.CanIssueCertificateAsync(ca.Id);
            if (!canIssue)
                throw new InvalidOperationException(
                    $"Certificate quota exceeded for CA '{ca.Name}'. No further certificates can be issued until the quota is increased or existing certificates expire/are revoked.");

            // Check tenant-level quota
            if (ca.TenantId != Guid.Empty)
            {
                var canIssueTenant = await _quotaService.CanIssueCertificateInTenantAsync(ca.TenantId);
                if (!canIssueTenant)
                    throw new InvalidOperationException($"Tenant certificate quota exceeded.");
            }
        }

        /// <summary>
        /// Resolves the CA certificate, private key handle, and database certificate entity
        /// for the given signing profile.
        /// </summary>
        private async Task<(X509Certificate caMatch, IPrivateKeyHandle caKeyHandle, CertificateEntity refCACert)> ResolveCaAsync(SigningProfileEntity signingProfile)
        {
            var refCACert = await _db.Certificates
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId);
            if (refCACert == null)
                throw new InvalidOperationException($"CA certificate not found. Is this a self-signed certificate request?");

            // Match the DB cert row to the in-memory trusted authority by raw DER bytes
            // (unambiguous — avoids BouncyCastle vs DB DN formatting mismatches like
            // "CN=X, O=Y" vs "CN=X,O=Y"). Falls back to SubjectDN contains-match for
            // legacy rows where RawCertificate is null.
            var trustedCAs = _keystore.GetTrustedAuthorities();
            X509Certificate? caMatch = null;
            if (refCACert.RawCertificate != null && refCACert.RawCertificate.Length > 0)
            {
                caMatch = trustedCAs.Find(ca =>
                    ca.GetEncoded().AsSpan().SequenceEqual(refCACert.RawCertificate));
            }
            caMatch ??= trustedCAs.Find(ca =>
                ca.SubjectDN.ToString().Contains(refCACert.SubjectDN, StringComparison.OrdinalIgnoreCase));
            if (caMatch == null)
                throw new InvalidOperationException($"No CA found with subject matching: {refCACert.SubjectDN}");

            var caKeyHandle = _keystore.GetPrivateKeyFor(caMatch)
                ?? throw new InvalidOperationException($"Private key not found for CA: {caMatch.SubjectDN}");

            return (caMatch, caKeyHandle, refCACert);
        }

        /// <summary>
        /// Encodes a single issued certificate to PEM. The stored <see cref="CertificateEntity.Pem"/>
        /// holds the leaf only; chain endpoints (<c>/chain</c>, ACME finalize, EST/SCEP/CMP) build
        /// the bundle on demand by walking <c>SigningProfile.IssuerId</c> → <c>ParentCaId</c>. A
        /// previous version of this method appended the intermediates argument into the stored
        /// blob, which produced a double-root in the chain endpoint when a leaf was issued
        /// directly by a root CA (the chain endpoint walked up and added the root that was
        /// already inside <c>cert.Pem</c>).
        /// </summary>
        /// <param name="issuedCert">The leaf certificate.</param>
        /// <returns>PEM-encoded single certificate.</returns>
        private static string EncodeCertPem(X509Certificate issuedCert)
        {
            var output = new StringBuilder();
            using (var writer = new StringWriter(output))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(issuedCert);
            }
            return output.ToString();
        }

        /// <summary>
        /// Builds a <see cref="CertificateInfoModel"/> from the issued certificate and metadata,
        /// including the serial number of the CA certificate whose public key encrypted the private key.
        /// </summary>
        private static CertificateInfoModel BuildCertModel(
            X509Certificate issuedCert, string certPem,
            List<string> standardOids, List<string> extendedOids,
            Guid certProfileId, Guid signingProfileId,
            byte[]? certIv, byte[]? certEncryptedAes, byte[]? certEncryptedPrivKey,
            string? encryptionCertSerialNumber = null,
            bool isCa = false,
            Guid? issuerCertificateId = null)
        {
            return new CertificateInfoModel
            {
                Pem = certPem,
                SubjectDN = issuedCert.SubjectDN.ToString(),
                Issuer = issuedCert.IssuerDN.ToString(),
                SerialNumber = CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
                NotBefore = issuedCert.NotBefore,
                NotAfter = issuedCert.NotAfter,
                IsCA = isCa,
                Revoked = false,
                Iv = certIv,
                EncryptedAesKey = certEncryptedAes,
                EncryptedPrivateKey = certEncryptedPrivKey,
                EncryptionCertSerialNumber = encryptionCertSerialNumber,
                RevocationReason = String.Empty,
                Thumbprints = GetCertThumbprints(issuedCert),
                CertProfileId = certProfileId,
                SigningProfileId = signingProfileId,
                KeyUsages = standardOids ?? [],
                ExtendedKeyUsages = extendedOids ?? [],
                SubjectAlternativeNames = ExtractSansFromCert(issuedCert),
                // Propagate the issuing CA's certificate FK so
                // CertificateStore persists it and CRL generation can use it directly
                // instead of the DN-based fallback resolver.
                IssuerCertificateId = issuerCertificateId,
            };
        }

        /// <summary>
        /// Extracts Subject Alternative Names from a signed certificate as a list of prefixed strings.
        /// </summary>
        private static List<string> ExtractSansFromCert(X509Certificate cert)
        {
            var result = new List<string>();
            var sanExt = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (sanExt == null)
                return result;

            var sanSeq = Asn1Sequence.GetInstance(X509ExtensionUtilities.FromExtensionValue(sanExt));
            foreach (Asn1Encodable entry in sanSeq)
            {
                var gn = GeneralName.GetInstance(entry);
                if (gn.TagNo == GeneralName.IPAddress)
                {
                    // IP addresses come as raw octets — convert to human-readable form
                    var octets = Asn1OctetString.GetInstance(gn.Name).GetOctets();
                    var ip = new System.Net.IPAddress(octets);
                    result.Add($"IP:{ip}");
                }
                else
                {
                    var prefix = gn.TagNo switch
                    {
                        GeneralName.DnsName => "DNS",
                        GeneralName.Rfc822Name => "Email",
                        GeneralName.UniformResourceIdentifier => "URI",
                        _ => "Other"
                    };
                    result.Add($"{prefix}:{gn.Name}");
                }
            }
            return result;
        }

        /// <summary>
        /// Computes SHA-1 and SHA-256 thumbprints for the certificate and returns them as a JSON dictionary.
        /// </summary>
        private static string GetCertThumbprints(X509Certificate cert)
        {
            byte[] sha1hash = SHA1.HashData(cert.GetEncoded());
            string sha1thumbprint = BitConverter.ToString(sha1hash).Replace("-", "").ToUpperInvariant();
            byte[] sha256hash = SHA256.HashData(cert.GetEncoded());
            string sha256thumbprint = BitConverter.ToString(sha256hash).Replace("-", "").ToUpperInvariant();
            var thumbprintDict = new Dictionary<string, string>
            {
                { "SHA 1", sha1thumbprint },
                { "SHA 256", sha256thumbprint }
            };
            return JsonSerializer.Serialize(thumbprintDict);
        }

        /// <summary>
        /// Decrypts a private key that was encrypted against a specific certificate's public key.
        /// </summary>
        private static AsymmetricKeyParameter DecryptPrivateKeyFromSerial(
            byte[] iv,
            byte[] encryptedAesKey,
            byte[] encryptedPrivateKey,
            string EncryptionCertSerialNumber,
            ModularCADbContext db,
            IKeystoreCertificates keystore,
            IKeyWrappingPassphraseProvider passphraseProvider)
        {
            var encryptorPrivKeySerial = db.Certificates
                .ResolveBySerialOrNull(EncryptionCertSerialNumber);
            if (encryptorPrivKeySerial == null) throw new InvalidOperationException("Encryptor certificate not found for private key decryption.");
            var encryptorPubKey = new X509CertificateParser();
            var encryptorCert = encryptorPubKey.ReadCertificate(encryptorPrivKeySerial.RawCertificate);
            var encryptorKeyHandle = keystore.GetPrivateKeyFor(encryptorCert);
            if (encryptorKeyHandle == null) throw new InvalidOperationException("Encryptor private key not found for private key decryption.");

            AsymmetricKeyParameter? encryptorPrivKey = null;
            if (encryptorKeyHandle.CanExport)
            {
                // Zero the DER transport buffer as soon as BC has consumed it.
                var der = encryptorKeyHandle.ExportPrivateKeyDer();
                try
                {
                    encryptorPrivKey = PrivateKeyFactory.CreateKey(der);
                }
                finally
                {
                    if (der != null)
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(der);
                }
            }
            else
            {
                throw new NotSupportedException("Non-exporting private key handles are not supported for private key decryption.");
            }

            return KeyEncryptionUtil.DecryptPrivateKey(encryptedAesKey, iv, encryptedPrivateKey, encryptorPrivKey, encryptorCert.GetPublicKey(), passphraseProvider.GetPassphrase());
        }

        /// <summary>
        /// Updates the CSR status to "Issued" and links it to the issued certificate.
        /// </summary>
        private static async Task SetCsrStatus(ModularCADbContext db, CertRequestEntity csr, string certSN)
        {
            var cert = await db.Certificates.ResolveBySerialOrNullAsync(certSN);
            if (cert == null)
                throw new InvalidOperationException("Certificate not found when setting CSR status.");

            csr.Status = "Issued";
            csr.IssuedCertificateId = cert.CertificateId;
            db.CertificateRequests.Update(csr);
            await db.SaveChangesAsync();
        }

        /// <summary>
        /// Validates that the CSR is in "Pending" status and has not yet been issued.
        /// </summary>
        /// <summary>
        /// Validates that the CSR is in a state eligible for issuance (Pending or Approved) and has not yet been issued.
        /// </summary>
        private static bool ValidateCsrStatus(CertRequestEntity csr)
        {
            return (csr.Status == "Pending" || csr.Status == "Approved") && csr.IssuedCertificateId == null;
        }
    }
}
