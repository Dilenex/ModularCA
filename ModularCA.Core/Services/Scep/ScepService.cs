using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System.Security.Cryptography;
using System.Text.Json;

using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using PkcsOids = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
// Aliased rather than imported: this file's unqualified X509Certificate is BouncyCastle's, and
// pulling in System.Security.Cryptography.X509Certificates would make that name ambiguous.
using X509Loader = System.Security.Cryptography.X509Certificates.X509CertificateLoader;

namespace ModularCA.Core.Services.Scep;

/// <summary>
/// SCEP responder service implementing the Simple Certificate Enrollment Protocol (RFC 8894).
/// Handles GetCACert, GetCACaps, and PKIOperation messages.
/// </summary>
public class ScepService : IScepService
{
    // SCEP-defined OIDs for transaction attributes
    private static readonly DerObjectIdentifier IdTransactionId = new("2.16.840.1.113733.1.9.7");
    private static readonly DerObjectIdentifier IdMessageType = new("2.16.840.1.113733.1.9.2");
    private static readonly DerObjectIdentifier IdPkiStatus = new("2.16.840.1.113733.1.9.3");
    private static readonly DerObjectIdentifier IdFailInfo = new("2.16.840.1.113733.1.9.4");
    private static readonly DerObjectIdentifier IdSenderNonce = new("2.16.840.1.113733.1.9.5");
    private static readonly DerObjectIdentifier IdRecipientNonce = new("2.16.840.1.113733.1.9.6");

    // SCEP messageType values
    private const string MessageTypePkcsReq = "19";
    private const string MessageTypeGetCertInitial = "20";
    private const string MessageTypeCertRep = "3";

    // SCEP pkiStatus values
    private const string PkiStatusSuccess = "0";
    private const string PkiStatusFailure = "2";
    private const string PkiStatusPending = "3";

    // SCEP failInfo values per RFC 8894 §3.2.1.4
    private const string FailInfoBadAlg = "0";
    private const string FailInfoBadMessageCheck = "1";
    private const string FailInfoBadRequest = "2";
    private const string FailInfoBadTime = "3";
    private const string FailInfoBadCertId = "4";

    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ICertificateIssuanceService _issuanceService;
    private readonly ICaResolverService _caResolver;
    private readonly IProtocolAuditService _protocolAudit;
    private readonly IEnrollmentAuthorizationService _enrollmentAuth;
    private readonly RequestProfileValidationService _requestProfileValidation;
    private readonly ILogger<ScepService> _logger;

    public ScepService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ICertificateIssuanceService issuanceService,
        ICaResolverService caResolver,
        IProtocolAuditService protocolAudit,
        IEnrollmentAuthorizationService enrollmentAuth,
        RequestProfileValidationService requestProfileValidation,
        ILogger<ScepService> logger)
    {
        _db = db;
        _keystore = keystore;
        _issuanceService = issuanceService;
        _caResolver = caResolver;
        _protocolAudit = protocolAudit;
        _enrollmentAuth = enrollmentAuth;
        _requestProfileValidation = requestProfileValidation;
        _logger = logger;
    }

    public async Task<(byte[] data, bool isPkcs7)> GetCaCertAsync(string? caLabel = null)
    {
        var context = await _caResolver.ResolveAsync(caLabel, "SCEP");

        // If a CA entity is resolved, return its certificate chain
        if (context.Ca != null)
        {
            var certEntity = await _db.Certificates.FindAsync(context.Ca.CertificateId);
            if (certEntity != null)
            {
                var caCert = CertificateUtil.ParseFromPem(certEntity.Pem);
                var caCerts = new List<X509Certificate> { caCert };

                var signingProfile = await _db.SigningProfiles.FindAsync(context.SigningProfileId);
                if (signingProfile?.IssuerId != null)
                {
                    var visited = new HashSet<Guid>();
                    var issuerId = signingProfile.IssuerId;
                    while (issuerId.HasValue && visited.Add(issuerId.Value))
                    {
                        var issuerEntity = await _db.Certificates
                            .Include(c => c.SigningProfile)
                            .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
                        if (issuerEntity == null) break;
                        caCerts.Add(CertificateUtil.ParseFromPem(issuerEntity.Pem));
                        issuerId = issuerEntity.SigningProfile?.IssuerId;
                    }
                }

                // Deduplicate by serial number (self-signed root appears as both leaf and issuer)
                var seen = new HashSet<string>();
                var uniqueCerts = new List<X509Certificate>();
                foreach (var c in caCerts)
                {
                    var serial = c.SerialNumber.ToString(16);
                    if (seen.Add(serial))
                        uniqueCerts.Add(c);
                }

                if (uniqueCerts.Count == 1)
                    return (uniqueCerts[0].GetEncoded(), false);
                return (BuildCertsOnlyPkcs7(uniqueCerts), true);
            }
        }

        // Fallback: return all trusted authorities
        var allCerts = _keystore.GetTrustedAuthorities();
        if (allCerts.Count == 1)
            return (allCerts[0].GetEncoded(), false);
        return (BuildCertsOnlyPkcs7(allCerts), true);
    }

    public string GetCaCaps()
    {
        // Return capabilities one per line (RFC 8894 §3.5.2)
        return string.Join("\n",
        [
            "POSTPKIOperation",
            "SHA-256",
            "SHA-512",
            "AES",
            "SCEPStandard",
            "Renewal"
        ]);
    }

    /// <summary>
    /// Processes a SCEP PKIOperation request. Parses the CMS SignedData envelope, verifies
    /// the message signature, dispatches by message type, and returns a properly-signed
    /// CMS response with appropriate SCEP failInfo codes on error.
    /// </summary>
    public async Task<byte[]> PkiOperationAsync(byte[] cmsRequest, string? caLabel = null, string? sourceIp = null)
    {
        var context = await _caResolver.ResolveAsync(caLabel, "SCEP");

        // Resolve the CA signer that will sign SCEP responses
        var (caCert, caKeyHandle) = await ResolveSignerForCaAsync(context)
            ?? throw new InvalidOperationException("No CA signer available for SCEP.");

        try
        {
            // Parse the outer CMS SignedData to extract SCEP transaction attributes
            CmsSignedData signedData;
            try
            {
                signedData = new CmsSignedData(cmsRequest);
            }
            catch (Exception)
            {
                return BuildFailureResponse(caCert, caKeyHandle, null, null, FailInfoBadMessageCheck);
            }

            var signerInfos = signedData.GetSignerInfos();
            var signerEnum = signerInfos.GetSigners().GetEnumerator();
            if (!signerEnum.MoveNext())
                return BuildFailureResponse(caCert, caKeyHandle, null, null, FailInfoBadMessageCheck);

            var signerInfo = (SignerInformation)signerEnum.Current;
            var signedAttrs = signerInfo.SignedAttributes;

            var transactionId = GetAttributeString(signedAttrs, IdTransactionId);
            var messageType = GetAttributeString(signedAttrs, IdMessageType);
            var senderNonce = GetAttributeBytes(signedAttrs, IdSenderNonce);

            // Validate senderNonce length is within RFC 8894 §3.2.1.5 bounds.
            if (senderNonce != null && (senderNonce.Length < 16 || senderNonce.Length > 32))
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadMessageCheck);

            // Verify the CMS signature on the request and capture the signer cert for
            // trust-chain analysis (High #5 renewal binding).
            X509Certificate? cmsSignerCert = null;
            try
            {
                bool verified = false;
                var signerCerts = signedData.GetCertificates();
                var certStore = signerCerts.EnumerateMatches(signerInfo.SignerID);
                foreach (X509Certificate signerCertCandidate in certStore)
                {
                    if (signerInfo.Verify(signerCertCandidate))
                    {
                        verified = true;
                        cmsSignerCert = signerCertCandidate;
                        break;
                    }
                }
                if (!verified)
                    return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadMessageCheck);
            }
            catch (Exception)
            {
                // Signature verification failure — badMessageCheck
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadMessageCheck);
            }

            if (messageType == MessageTypePkcsReq)
            {
                return await HandlePkcsReqAsync(signedData, caCert, caKeyHandle, transactionId, senderNonce, context, sourceIp, cmsSignerCert);
            }

            if (messageType == MessageTypeGetCertInitial)
            {
                return await HandleGetCertInitialAsync(caCert, caKeyHandle, transactionId, senderNonce, context, cmsSignerCert);
            }

            // Unsupported message type — return failure
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
        }
        catch (Exception)
        {
            return BuildFailureResponse(caCert, caKeyHandle, null, null, FailInfoBadRequest);
        }
    }

    /// <summary>
    /// Handles a SCEP PKCSReq message by decrypting the enveloped CSR, validating enrollment
    /// authorization, issuing the certificate, and building a signed SCEP success response.
    /// </summary>
    private async Task<byte[]> HandlePkcsReqAsync(
        CmsSignedData signedData,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        string? transactionId,
        byte[]? senderNonce,
        ResolvedCaContext context,
        string? sourceIp,
        X509Certificate? cmsSignerCert)
    {
        // The inner content of the SignedData is an EnvelopedData containing the PKCS#10 CSR
        var contentBytes = ((CmsProcessableByteArray)signedData.SignedContent).GetInputStream();
        byte[] envelopedBytes;
        using (var ms = new MemoryStream())
        {
            contentBytes.CopyTo(ms);
            envelopedBytes = ms.ToArray();
        }

        // Decrypt the EnvelopedData using the CA's private key
        var envelopedData = new CmsEnvelopedData(envelopedBytes);
        var recipients = envelopedData.GetRecipientInfos();
        byte[]? csrDer = null;

        foreach (RecipientInformation recipient in recipients.GetRecipients())
        {
            try
            {
                // CMS decryption requires raw key — export from handle
                // TODO: PKCS#11 Phase 3 — add decrypt support to IPrivateKeyHandle
                if (!caKeyHandle.CanExport)
                    throw new NotSupportedException("SCEP CMS decryption requires exportable keys (HSM decrypt not yet supported)");
                // Zero the DER transport buffer once BC has finished with it.
                var derBytes = caKeyHandle.ExportPrivateKeyDer();
                AsymmetricKeyParameter decryptKey;
                try
                {
                    decryptKey = PrivateKeyFactory.CreateKey(derBytes);
                }
                finally
                {
                    if (derBytes != null)
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(derBytes);
                }
                csrDer = recipient.GetContent(decryptKey);
                if (csrDer != null) break;
            }
            catch
            {
                // Try next recipient
            }
        }

        if (csrDer == null)
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);

        // Convert DER CSR to PEM and parse
        var csrPem = CertificateUtil.ConvertDerToPem(csrDer, "CERTIFICATE REQUEST");

        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception)
        {
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
        }

        // Split initial vs renewal (RFC 8894 §3.2.2). A renewal is authenticated by the CMS
        // signer certificate instead of the challenge password, so what counts as "issued by
        // this CA" is the whole security boundary of the SCEP endpoint.
        //
        // This used to be a DN *string* comparison: it read cmsSignerCert.IssuerDN and looked for
        // any CA row whose SubjectDN matched. Nothing about that proves issuance — the Issuer
        // field is attacker-authored text in a certificate the attacker generates. Fetching the
        // CA DN from the anonymous GetCACert endpoint, self-signing a certificate that carries it
        // as Issuer and the victim's name as Subject, and signing the PKCSReq with that key
        // satisfied every gate: signerInfo.Verify() passes (it is self-signed and the attacker
        // holds the key), issuedByUs was true, and the subject-match check compared two
        // attacker-chosen values. The challenge password was then skipped entirely, so the CA
        // issued to an unauthenticated caller. EstService.SimpleReenrollAsync documents this same
        // anti-pattern as closed in its own path; this is the SCEP half of that fix.
        //
        // A signer that fails to chain is NOT rejected outright — it falls through to initial
        // enrollment, which requires the challenge password. That keeps legitimate first-time
        // enrollment (self-signed signer, per RFC 8894 §2.3) working while removing the bypass.
        bool isRenewal = false;
        if (cmsSignerCert != null)
        {
            try
            {
                using var signerCert2 = X509Loader.LoadCertificate(cmsSignerCert.GetEncoded());
                using var anchorCert2 = X509Loader.LoadCertificate(caCert.GetEncoded());

                // Revocation is checked against our own database below rather than online here:
                // an unreachable OCSP responder must not turn a renewal into a hard failure on
                // an enrollment path, and the DB gate is authoritative for certificates we issued.
                if (X509ChainValidationUtil.ValidateAgainstAnchor(
                        signerCert2, anchorCert2, requireRevocationCheck: false, out var chainErrors))
                {
                    isRenewal = true;

                    // The signer must not be revoked. Scope by the issuer we just proved, because
                    // serial numbers are unique only within one issuer's namespace — an unscoped
                    // lookup can land on an unrelated CA's row and either miss a revocation or
                    // reject a healthy renewal. Rows with no IssuerCertificateId (legacy, pre-FK)
                    // are still considered so the check fails closed for them.
                    var signerSerial = CertificateUtil.FormatSerialNumber(cmsSignerCert.SerialNumber);
                    var issuerCertId = context.Ca?.CertificateId;
                    var revoked = await _db.Certificates.AsNoTracking().AnyAsync(c =>
                        c.SerialNumber == signerSerial &&
                        c.Revoked &&
                        (c.IssuerCertificateId == null || c.IssuerCertificateId == issuerCertId));
                    if (revoked)
                    {
                        _logger.LogWarning(
                            "SCEP renewal rejected — signer certificate {Serial} is revoked.", signerSerial);
                        await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                            "Renewal signer certificate is revoked.");
                        return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
                    }

                    var signerSubject = cmsSignerCert.SubjectDN.ToString();
                    if (!string.Equals(NormalizeDn(signerSubject), NormalizeDn(parsedCsr.SubjectName), StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogWarning("SCEP renewal rejected — signer subject does not match CSR subject. signer='{Signer}' csr='{Csr}'",
                            signerSubject, parsedCsr.SubjectName);
                        await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                            "Renewal signer subject does not match CSR subject.");
                        return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
                    }
                }
                else
                {
                    _logger.LogInformation(
                        "SCEP PKCSReq signer (subject={Subject}) does not chain to CA '{CaSubject}' ({ChainErrors}) — treating as initial enrollment; challenge password required.",
                        cmsSignerCert.SubjectDN.ToString(), caCert.SubjectDN.ToString(), chainErrors);
                }
            }
            catch (Exception ex)
            {
                // Fail closed: any failure to *prove* issuance leaves isRenewal false, so the
                // request must satisfy the challenge password like any initial enrollment.
                isRenewal = false;
                _logger.LogWarning(ex, "SCEP signer certificate chain validation failed — treating as initial enrollment.");
            }
        }

        // Enrollment authorization check (includes SCEP challenge password validation).
        // Renewals skip the challenge password requirement — the CA-trusted signer cert
        // is the authentication factor.
        if (!isRenewal)
        {
            var (authAllowed, authError) = await _enrollmentAuth.ValidateAsync("SCEP", context.Ca?.Label, csrPem, null, false);
            if (!authAllowed)
            {
                await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                    authError ?? "Enrollment not authorized (challenge password or policy).");
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
            }
        }

        // Persist SCEP transaction before issuance. Unique index
        // on (CaId, TransactionId) means a replayed PKCSReq hits DbUpdateException which
        // we translate to FailInfoBadRequest.
        ScepTransactionEntity? txRow = null;
        if (!string.IsNullOrEmpty(transactionId))
        {
            // SHA-256 the requester public key so GetCertInitial can
            // verify the polling client matches the original PKCSReq.
            var pubKeyHash = Convert.ToHexString(
                SHA256.HashData(parsedCsr.PublicKeyDer ?? Array.Empty<byte>()));
            txRow = new ScepTransactionEntity
            {
                CaId = context.Ca?.Id,
                TransactionId = transactionId,
                Subject = parsedCsr.SubjectName,
                RequesterPublicKeyHash = pubKeyHash,
                Status = "Pending",
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };
            _db.ScepTransactions.Add(txRow);
            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // Duplicate transaction id → replay.
                await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                    "Duplicate SCEP transaction id (replay).");
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
            }
        }

        // Use resolved profiles from the CA context
        var signingProfileId = context.SigningProfileId;

        // Resolve cert profile: SCEP doesn't support requester choice → protocol default → request profile default
        var (resolvedCertProfileId, certProfileError) = await _requestProfileValidation
            .ResolveCertProfileIdAsync(null, context.CertProfileId, context.RequestProfileId);
        if (resolvedCertProfileId == null)
            throw new InvalidOperationException(certProfileError ?? "No certificate profile available for SCEP");
        var certProfileId = resolvedCertProfileId.Value;

        var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId)
            ?? throw new InvalidOperationException("Configured SCEP signing profile not found.");
        var certProfile = await _db.CertProfiles.FindAsync(certProfileId)
            ?? throw new InvalidOperationException("Configured SCEP certificate profile not found.");

        // Validate CSR key algorithm against the cert profile's allowed algorithms
        if (!string.IsNullOrEmpty(certProfile.AllowedKeyAlgorithms))
        {
            var allowedAlgs = certProfile.AllowedKeyAlgorithms
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (allowedAlgs.Length > 0 && !allowedAlgs.Any(a =>
                string.Equals(a, parsedCsr.KeyAlgorithm, StringComparison.OrdinalIgnoreCase)))
            {
                await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                    $"CSR key algorithm '{parsedCsr.KeyAlgorithm}' not permitted by certificate profile.");
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadAlg);
            }
        }

        var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);
        var subject = parsedCsr.SubjectName;

        // Validate against request profile if one is configured for this protocol
        if (context.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await _requestProfileValidation
                .ValidateAsync(context.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
            {
                await LogPkcsReqRejectedAsync(subject, context, transactionId, sourceIp,
                    error ?? "Request profile validation failed.");
                return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadRequest);
            }
            if (modifiedSubject != null)
                subject = modifiedSubject;
        }

        var csrEntity = new CertRequestEntity
        {
            Subject = subject,
            SubjectAlternativeNames = sanJson,
            CSR = csrPem,
            KeyAlgorithm = parsedCsr.KeyAlgorithm,
            KeySize = parsedCsr.KeySize,
            SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = "Pending",
            CertProfileId = certProfileId,
            CertProfile = certProfile,
            SigningProfileId = signingProfileId,
            SigningProfile = signingProfile
        };

        _db.CertificateRequests.Add(csrEntity);
        await _db.SaveChangesAsync();

        var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var notAfter = notBefore.Add(maxValidity);

        var issuanceResult = await _issuanceService.IssueCertificateAsync(
            csrEntity.Id, notBefore, notAfter);
        var certPem = issuanceResult.Pem;

        // Build the issued cert chain as PKCS#7
        var issuedCert = CertificateUtil.ParseFromPem(certPem);

        // Update the SCEP transaction row with the issued cert id
        // so GetCertInitial can return it to the legitimate polling client.
        if (txRow != null)
        {
            var issuedEntity = await _db.Certificates.AsNoTracking().FirstOrDefaultAsync(c =>
                c.SerialNumber == CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber));
            txRow.IssuedCertificateId = issuedEntity?.CertificateId;
            txRow.Status = "Issued";
            await _db.SaveChangesAsync();
        }

        var callerPrincipal = isRenewal && cmsSignerCert != null
            ? $"scep-renewal:{CertificateUtil.FormatSerialNumber(cmsSignerCert.SerialNumber)}"
            : "scep-initial";

        await _protocolAudit.LogScepAsync("PKCSReq", csrEntity.Subject,
            CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
            csrEntity.KeyAlgorithm, csrEntity.KeySize, context.Ca?.Label, transactionId, sourceIp,
            callerPrincipal: callerPrincipal);
        var certChain = new List<X509Certificate> { issuedCert };

        // Walk issuer chain
        var reloadedCsr = await _db.CertificateRequests
            .Include(c => c.SigningProfile)
            .FirstOrDefaultAsync(c => c.Id == csrEntity.Id);

        if (reloadedCsr?.SigningProfile?.IssuerId != null)
        {
            var visited = new HashSet<Guid>();
            var issuerId = reloadedCsr.SigningProfile.IssuerId;
            while (issuerId.HasValue && visited.Add(issuerId.Value))
            {
                var issuerEntity = await _db.Certificates
                    .Include(c => c.SigningProfile)
                    .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
                if (issuerEntity == null) break;

                certChain.Add(CertificateUtil.ParseFromPem(issuerEntity.Pem));
                issuerId = issuerEntity.SigningProfile?.IssuerId;
            }
        }

        var certsPkcs7 = BuildCertsOnlyPkcs7(certChain);

        return BuildSuccessResponse(caCert, caKeyHandle, transactionId, senderNonce, certsPkcs7);
    }

    /// <summary>
    /// Handles GetCertInitial (RFC 8894 §4.5) by looking up the
    /// stored SCEP transaction row, verifying the polling client's CMS signer public key
    /// hash matches the original requester's hash, and returning the associated cert.
    /// No match → <c>FailInfoBadCertId</c> (no more "most recent cert" leak across tenants).
    /// </summary>
    private async Task<byte[]> HandleGetCertInitialAsync(
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        string? transactionId,
        byte[]? senderNonce,
        ResolvedCaContext context,
        X509Certificate? cmsSignerCert)
    {
        if (string.IsNullOrEmpty(transactionId))
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadCertId);

        var tx = await _db.ScepTransactions
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.CaId == context.Ca!.Id && t.TransactionId == transactionId);
        if (tx == null || tx.IssuedCertificateId == null)
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadCertId);

        if (tx.ExpiresAt < DateTime.UtcNow)
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadCertId);

        // Verify the polling client's CMS signer public key matches
        // the one recorded at PKCSReq time. Prevents a random caller with a captured
        // transactionId from collecting someone else's cert.
        if (cmsSignerCert != null)
        {
            var signerPubKeyDer = cmsSignerCert.CertificateStructure
                .SubjectPublicKeyInfo?.GetDerEncoded();
            if (signerPubKeyDer != null)
            {
                var signerHash = Convert.ToHexString(SHA256.HashData(signerPubKeyDer));
                if (!string.Equals(signerHash, tx.RequesterPublicKeyHash, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "SCEP GetCertInitial rejected — CMS signer key hash does not match stored requester hash (txId={TxId}).",
                        transactionId);
                    return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadCertId);
                }
            }
        }

        var recentCertEntity = await _db.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == tx.IssuedCertificateId.Value);
        if (recentCertEntity == null)
            return BuildFailureResponse(caCert, caKeyHandle, transactionId, senderNonce, FailInfoBadCertId);

        var signingProfileId = context.SigningProfileId;

        // Build success response with the certificate
        var issuedCert = CertificateUtil.ParseFromPem(recentCertEntity.Pem);
        var certChain = new List<X509Certificate> { issuedCert };

        // Walk issuer chain
        var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId);
        if (signingProfile?.IssuerId != null)
        {
            var visited = new HashSet<Guid>();
            var issuerId = signingProfile.IssuerId;
            while (issuerId.HasValue && visited.Add(issuerId.Value))
            {
                var issuerEntity = await _db.Certificates
                    .Include(c => c.SigningProfile)
                    .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
                if (issuerEntity == null) break;
                certChain.Add(CertificateUtil.ParseFromPem(issuerEntity.Pem));
                issuerId = issuerEntity.SigningProfile?.IssuerId;
            }
        }

        var pkcs7Bytes = BuildCertsOnlyPkcs7(certChain);
        return BuildSuccessResponse(caCert, caKeyHandle, transactionId, senderNonce, pkcs7Bytes);
    }

    private async Task<(X509Certificate cert, IPrivateKeyHandle keyHandle)?> ResolveSignerForCaAsync(ResolvedCaContext context)
    {
        if (context.Ca != null)
        {
            var certEntity = await _db.Certificates.FindAsync(context.Ca.CertificateId);
            if (certEntity != null)
            {
                var caCert = CertificateUtil.ParseFromPem(certEntity.Pem);
                var keyHandle = _keystore.GetPrivateKeyFor(caCert);
                if (keyHandle != null)
                    return (caCert, keyHandle);
            }
        }

        // Fallback: pick first available signer
        foreach (var signer in _keystore.GetSigners())
        {
            var cert = signer.PublicCertificate;
            var keyHandle = _keystore.GetPrivateKeyFor(cert);
            if (keyHandle != null)
                return (cert, keyHandle);
        }
        return null;
    }

    /// <summary>
    /// Records a SCEP PKCSReq rejection on the protocol audit tab. SCEP previously logged
    /// only successful enrollments, so rejected requests (bad challenge, bad algorithm,
    /// profile violation, replay, renewal-binding mismatch) never appeared on the SCEP tab.
    /// </summary>
    private Task LogPkcsReqRejectedAsync(string? subject, ResolvedCaContext context,
        string? transactionId, string? sourceIp, string reason)
        => _protocolAudit.LogScepAsync("PKCSReq", subject, certSerial: null,
            keyAlgorithm: null, keySize: null, caLabel: context.Ca?.Label,
            transactionId: transactionId, sourceIp: sourceIp,
            success: false, errorMessage: reason);

    private static byte[] BuildSuccessResponse(
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        string? transactionId,
        byte[]? senderNonce,
        byte[] certsPkcs7Content)
    {
        return BuildScepResponse(caCert, caKeyHandle, transactionId, senderNonce,
            PkiStatusSuccess, null, certsPkcs7Content);
    }

    private static byte[] BuildFailureResponse(
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        string? transactionId,
        byte[]? senderNonce,
        string failInfo)
    {
        return BuildScepResponse(caCert, caKeyHandle, transactionId, senderNonce,
            PkiStatusFailure, failInfo, null);
    }

    private static byte[] BuildScepResponse(
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        string? transactionId,
        byte[]? senderNonce,
        string pkiStatus,
        string? failInfo,
        byte[]? encapsulatedContent)
    {
        // Build signed attributes
        var signedAttrs = new Asn1EncodableVector();

        // messageType = CertRep (3)
        signedAttrs.Add(new CmsAttribute(
            IdMessageType, new DerSet(new DerPrintableString(MessageTypeCertRep))));

        // pkiStatus
        signedAttrs.Add(new CmsAttribute(
            IdPkiStatus, new DerSet(new DerPrintableString(pkiStatus))));

        // transactionID (echo back)
        if (transactionId != null)
        {
            signedAttrs.Add(new CmsAttribute(
                IdTransactionId, new DerSet(new DerPrintableString(transactionId))));
        }

        // recipientNonce = senderNonce from request
        if (senderNonce != null)
        {
            signedAttrs.Add(new CmsAttribute(
                IdRecipientNonce, new DerSet(new DerOctetString(senderNonce))));
        }

        // senderNonce (new random nonce for the response)
        var responseNonce = new byte[16];
        new SecureRandom().NextBytes(responseNonce);
        signedAttrs.Add(new CmsAttribute(
            IdSenderNonce, new DerSet(new DerOctetString(responseNonce))));

        // failInfo (if failure)
        if (failInfo != null)
        {
            signedAttrs.Add(new CmsAttribute(
                IdFailInfo, new DerSet(new DerPrintableString(failInfo))));
        }

        // Build a CMS SignedData with the SCEP attributes.
        // The encapsulated content is the certs-only PKCS#7 (on success) or empty (on failure).
        var content = encapsulatedContent ?? [];
        var cmsContentInfo = new Org.BouncyCastle.Asn1.Cms.ContentInfo(PkcsOids.Data, new DerOctetString(content));

        var sigAlgOid = caCert.SigAlgOid;
        var resolvedSigAlg = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey()));
        var digestAlgOid = GetDigestAlgOid(resolvedSigAlg);

        // Compute digest of the content
        var digest = DigestUtilities.GetDigest(digestAlgOid);
        var contentDigest = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(content, 0, content.Length);
        digest.DoFinal(contentDigest, 0);

        // Add content-type and message-digest to signed attributes
        signedAttrs.Add(new CmsAttribute(
            CmsAttributes.ContentType, new DerSet(PkcsOids.Data)));
        signedAttrs.Add(new CmsAttribute(
            CmsAttributes.MessageDigest, new DerSet(new DerOctetString(contentDigest))));

        var signedAttrSet = new DerSet(signedAttrs);

        // Sign the signed attributes (via key handle — supports HSM)
        var sigAlgName = resolvedSigAlg;
        var encodedSignedAttrs = signedAttrSet.GetDerEncoded();
        var signature = caKeyHandle.Sign(encodedSignedAttrs, sigAlgName);

        // Build IssuerAndSerialNumber for the SignerInfo
        var issuerAndSerial = new Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber(
            caCert.IssuerDN, caCert.SerialNumber);

        var signerInfoObj = new Org.BouncyCastle.Asn1.Cms.SignerInfo(
            new SignerIdentifier(issuerAndSerial),
            new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgOid)),
            signedAttrSet,
            new AlgorithmIdentifier(new DerObjectIdentifier(sigAlgOid)),
            new DerOctetString(signature),
            null); // unsignedAttributes

        // Build the CA cert ASN1 for inclusion
        var caCertAsn1 = Asn1Object.FromByteArray(caCert.GetEncoded());

        // Build the outer SignedData
        var outerSignedData = new Org.BouncyCastle.Asn1.Cms.SignedData(
            new DerSet(new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgOid))),
            cmsContentInfo,
            new DerSet(caCertAsn1),
            null, // crls
            new DerSet(signerInfoObj));

        var outerContentInfo = new Org.BouncyCastle.Asn1.Cms.ContentInfo(PkcsOids.SignedData, outerSignedData);
        return outerContentInfo.GetDerEncoded();
    }

    /// <summary>
    /// Maps a CA certificate's signature algorithm name to the digest OID used for the
    /// outer SCEP SignedData. SHA-1 and other deprecated digests are rejected — ModularCA
    /// will not downgrade SCEP responses to a legacy digest even if a legacy CA somehow
    /// slips into the pipeline. Defaults to SHA-256 when the signature algorithm name
    /// does not carry an explicit digest (e.g. Ed25519, ML-DSA, SLH-DSA — these build the
    /// outer signed-data with SHA-256 as the message digest).
    /// </summary>
    private static string GetDigestAlgOid(string sigAlgName)
    {
        var upper = (sigAlgName ?? string.Empty).ToUpperInvariant();
        if (upper.Contains("SHA-256") || upper.Contains("SHA256"))
            return "2.16.840.1.101.3.4.2.1"; // SHA-256
        if (upper.Contains("SHA-384") || upper.Contains("SHA384"))
            return "2.16.840.1.101.3.4.2.2"; // SHA-384
        if (upper.Contains("SHA-512") || upper.Contains("SHA512"))
            return "2.16.840.1.101.3.4.2.3"; // SHA-512

        // Refuse to build SCEP responses over SHA-1 or MD5 signed CAs. If a
        // SHA-1/MD5 CA somehow reaches this path it is a configuration error and SCEP
        // must fail loudly rather than silently downgrade the outer signed-data digest.
        if (upper.Contains("SHA-1") || upper.Contains("SHA1") || upper.Contains("MD5"))
            throw new NotSupportedException($"SCEP refuses to operate over a CA signature algorithm '{sigAlgName}': legacy digests are not permitted.");

        // Default to SHA-256 for non-hash-then-sign algorithms (EdDSA, ML-DSA, SLH-DSA).
        return "2.16.840.1.101.3.4.2.1";
    }

    /// <summary>
    /// Retrieves a string value from a CMS attribute table by OID, returning null if not found or empty.
    /// </summary>
    private static string? GetAttributeString(Org.BouncyCastle.Asn1.Cms.AttributeTable? attrs, DerObjectIdentifier oid)
    {
        var attr = attrs?[oid];
        if (attr == null || attr.AttrValues == null || attr.AttrValues.Count == 0) return null;
        var val = attr.AttrValues[0];
        if (val is DerPrintableString ps) return ps.GetString();
        if (val is DerUtf8String us) return us.GetString();
        return val.ToString();
    }

    /// <summary>
    /// Retrieves a byte array value from a CMS attribute table by OID, returning null if not found or empty.
    /// </summary>
    private static byte[]? GetAttributeBytes(Org.BouncyCastle.Asn1.Cms.AttributeTable? attrs, DerObjectIdentifier oid)
    {
        var attr = attrs?[oid];
        if (attr == null || attr.AttrValues == null || attr.AttrValues.Count == 0) return null;
        var val = attr.AttrValues[0];
        if (val is Asn1OctetString os) return os.GetOctets();
        return null;
    }

    /// <summary>
    /// Use BouncyCastle's <see cref="CmsSignedDataGenerator"/> to
    /// produce a canonical degenerate PKCS#7 (certs-only, empty signerInfos/digestAlgorithms).
    /// BC handles the ASN.1 tagging corner cases that strict clients (sscep, Cisco IOS) need.
    /// </summary>
    private static byte[] BuildCertsOnlyPkcs7(IList<X509Certificate> certificates)
    {
        var generator = new CmsSignedDataGenerator();
        var store = CollectionUtilities.CreateStore(certificates);
        generator.AddCertificates(store);
        var signed = generator.Generate(
            new CmsProcessableByteArray(Array.Empty<byte>()), encapsulate: false);
        return signed.GetEncoded();
    }

    /// <summary>
    /// Helper: normalize a DN string for RFC 8894 renewal-binding
    /// comparison. Not ideal — a future follow-up should use X500Name canonical form.
    /// </summary>
    private static string NormalizeDn(string dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return string.Empty;
        var parts = dn.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim().ToUpperInvariant())
            .OrderBy(p => p)
            .ToArray();
        return string.Join(",", parts);
    }
}

/// <summary>
/// Minimal helper so <see cref="ScepService"/> can pass an <see cref="IList{X509Certificate}"/>
/// to <see cref="Org.BouncyCastle.Cms.CmsSignedDataGenerator.AddCertificates"/>. BC expects an
/// <see cref="Org.BouncyCastle.Utilities.Collections.IStore{T}"/>; this shim wraps a list.
/// </summary>
internal static class CollectionUtilities
{
    public static Org.BouncyCastle.Utilities.Collections.IStore<X509Certificate> CreateStore(
        IList<X509Certificate> certs)
        => Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(certs);
}
