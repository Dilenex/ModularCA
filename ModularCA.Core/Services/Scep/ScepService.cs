using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
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
/// <remarks>
/// <para>
/// The middle of a PKCSReq — the CA, SCEP's enablement on it, the caller's authorization, the
/// effective profiles, the names against the request profile, the request row, issuance or
/// submission for approval, and the audit row — is <see cref="IEnrollmentPipeline"/>, the same
/// sequence every protocol runs. What stays here is SCEP's own: the CMS envelope on both sides,
/// the challenge password and the renewal signer checks that decide which credential is asking,
/// the transaction row and the replay detection keyed on it, <c>GetCertInitial</c>, and the
/// rendering of every answer as a signed CertRep.
/// </para>
/// <para>
/// Only PKCSReq goes through the pipeline. <c>GetCACert</c> and <c>GetCACaps</c> publish
/// configuration, and <c>GetCertInitial</c> asks after a request that has already been through it;
/// none of the three issues, so none has a middle to share.
/// </para>
/// </remarks>
public class ScepService : IScepService, IEnrollmentProtocol
{
    /// <summary>The protocol name as per-CA protocol configuration and audit rows record it.</summary>
    public const string Protocol = "SCEP";

    /// <inheritdoc />
    string IEnrollmentProtocol.Name => Protocol;

    /// <summary>
    /// What SCEP offers here: first issuance against a challenge password, re-enrollment where the
    /// PKCSReq is signed by the certificate being replaced (RFC 8894 §3.2.2), and
    /// <c>GetCertInitial</c>, which both asks after a request and fetches the certificate once
    /// there is one.
    /// </summary>
    /// <remarks>
    /// <see cref="EnrollmentCapabilities.Poll"/> and <see cref="EnrollmentCapabilities.Collect"/>
    /// are one message here, which is why both are declared: RFC 8894 §4.5 has the client re-send
    /// its subject and transaction id, and the answer is PENDING or the certificate. Not
    /// <see cref="EnrollmentCapabilities.Renew"/>: a SCEP renewal is credentialed by the
    /// certificate it replaces and carries no separate evidence naming one, which is
    /// re-enrollment. No revocation — RFC 8894 dropped it — and no server-side key generation.
    /// </remarks>
    EnrollmentCapabilities IEnrollmentProtocol.Capabilities =>
        EnrollmentCapabilities.Enroll | EnrollmentCapabilities.ReEnroll
        | EnrollmentCapabilities.Poll | EnrollmentCapabilities.Collect;


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
    private readonly ICaResolverService _caResolver;
    private readonly IProtocolAuditService _protocolAudit;

    /// <summary>The shared middle every PKCSReq runs; see <see cref="IEnrollmentPipeline"/>.</summary>
    private readonly IEnrollmentPipeline _pipeline;
    private readonly ILogger<ScepService> _logger;

    /// <summary>
    /// Signs every response and opens every envelope. The service holds a <see cref="KeyRef"/>
    /// to the CA certificate and a context naming the CA; the key stays with the signer.
    /// </summary>
    private readonly ISigningService _signer;

    /// <summary>The caller identity SCEP signs under; the signer audits it with every decision.</summary>
    private const string SignerCaller = nameof(ScepService);

    /// <summary>
    /// The CA key a SCEP exchange signs and decrypts with, as the signer knows it: the reference
    /// to the CA certificate and the context holding the key to the CA the exchange is for.
    /// </summary>
    private sealed record ScepSignerKey(KeyRef Key, SigningContext Context);

    /// <summary>
    /// Constructs the responder over the database, the runtime registry (for the trusted
    /// certificates it publishes), the shared enrollment middle and the signer that holds the CA
    /// key.
    /// </summary>
    /// <remarks>
    /// Takes <see cref="IEnrollmentPipeline"/> rather than issuance, enrollment authorization and
    /// profile resolution separately: the middle of an enrollment is the same work in every
    /// protocol, and this service now supplies only what is SCEP's own — the CMS envelopes, the
    /// credential that decides whether a challenge password is required, the transaction row, and
    /// the CertRep rendering.
    /// </remarks>
    /// <param name="db">Database, for the transaction rows and the certificates a response carries.</param>
    /// <param name="keystore">The runtime registry, for the trusted authorities GetCACert publishes.</param>
    /// <param name="caResolver">Resolves the CA and profiles an exchange addresses.</param>
    /// <param name="protocolAudit">Writes the SCEP audit rows the protocol tab shows.</param>
    /// <param name="pipeline">The shared enrollment middle; see <see cref="IEnrollmentPipeline"/>.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="signer">Holds the CA key every response is signed with and every envelope opened with.</param>
    public ScepService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ICaResolverService caResolver,
        IProtocolAuditService protocolAudit,
        IEnrollmentPipeline pipeline,
        ILogger<ScepService> logger,
        ISigningService signer)
    {
        _db = db;
        _keystore = keystore;
        _caResolver = caResolver;
        _protocolAudit = protocolAudit;
        _pipeline = pipeline;
        _logger = logger;
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
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
        var (caCert, caKey) = await ResolveSignerForCaAsync(context)
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
                return await BuildFailureResponse(caCert, caKey, null, null, FailInfoBadMessageCheck);
            }

            var signerInfos = signedData.GetSignerInfos();
            var signerEnum = signerInfos.GetSigners().GetEnumerator();
            if (!signerEnum.MoveNext())
                return await BuildFailureResponse(caCert, caKey, null, null, FailInfoBadMessageCheck);

            var signerInfo = (SignerInformation)signerEnum.Current;
            var signedAttrs = signerInfo.SignedAttributes;

            var transactionId = GetAttributeString(signedAttrs, IdTransactionId);
            var messageType = GetAttributeString(signedAttrs, IdMessageType);
            var senderNonce = GetAttributeBytes(signedAttrs, IdSenderNonce);

            // Validate senderNonce length is within RFC 8894 §3.2.1.5 bounds.
            if (senderNonce != null && (senderNonce.Length < 16 || senderNonce.Length > 32))
                return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadMessageCheck);

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
                    return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadMessageCheck);
            }
            catch (Exception)
            {
                // Signature verification failure — badMessageCheck
                return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadMessageCheck);
            }

            if (messageType == MessageTypePkcsReq)
            {
                return await HandlePkcsReqAsync(signedData, caCert, caKey, transactionId, senderNonce, context, sourceIp, cmsSignerCert);
            }

            if (messageType == MessageTypeGetCertInitial)
            {
                return await HandleGetCertInitialAsync(caCert, caKey, transactionId, senderNonce, context, cmsSignerCert);
            }

            // Unsupported message type — return failure
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);
        }
        catch (Exception)
        {
            return await BuildFailureResponse(caCert, caKey, null, null, FailInfoBadRequest);
        }
    }

    /// <summary>
    /// Handles a SCEP PKCSReq message by decrypting the enveloped CSR, validating enrollment
    /// authorization, issuing the certificate, and building a signed SCEP success response.
    /// </summary>
    private async Task<byte[]> HandlePkcsReqAsync(
        CmsSignedData signedData,
        X509Certificate caCert,
        ScepSignerKey caKey,
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

        // Open the EnvelopedData with the CA key, which the signer holds. The signer tries every
        // recipient the envelope names; an envelope none of them opens, a key the signer refuses
        // for this CA, or a backend that cannot decrypt all end the same way they did when the
        // key was opened here: badRequest.
        byte[]? csrDer;
        try
        {
            csrDer = await _signer.DecryptAsync(caKey.Key, envelopedBytes, caKey.Context);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SCEP PKCSReq envelope could not be opened with the CA key.");
            csrDer = null;
        }

        if (csrDer == null)
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);

        // Convert DER CSR to PEM and parse
        var csrPem = CertificateUtil.ConvertDerToPem(csrDer, "CERTIFICATE REQUEST");

        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(csrPem);
        }
        catch (Exception)
        {
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);
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

        // The certificate a renewal replaces, once the signer has been proven to be one this CA
        // issued. SCEP's renewal checks are the protocol's own and stay where they are, ahead of
        // the middle, because they decide which credential is asking and therefore whether a
        // challenge password is required at all; what the middle is handed is the conclusion. See
        // EnrollmentRenewal.
        EnrollmentRenewal? renewal = null;
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
                        return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);
                    }

                    var signerSubject = cmsSignerCert.SubjectDN.ToString();
                    if (!string.Equals(NormalizeDn(signerSubject), NormalizeDn(parsedCsr.SubjectName), StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogWarning("SCEP renewal rejected — signer subject does not match CSR subject. signer='{Signer}' csr='{Csr}'",
                            signerSubject, parsedCsr.SubjectName);
                        await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                            "Renewal signer subject does not match CSR subject.");
                        return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);
                    }

                    // The subject match alone does not bound a renewal — SANs are where a TLS
                    // certificate's real identity lives, and nothing was checking them.
                    //
                    // A renewal skips the challenge password precisely because the signer
                    // certificate stands in for it; that makes the signer's own names the whole
                    // authorization. With only the DN compared, the holder of any certificate this
                    // CA issued could renew "itself" while adding DNS:vpn.example.com — or
                    // DNS:* where the profile permits wildcards — and the initial-enrollment
                    // SANRestriction that would have stopped it never runs on this path. A printer
                    // with a device certificate was one renewal away from a certificate for the
                    // CA's own web front end.
                    //
                    // Rule: every name asked for must already be a name the signer holds. Renewal
                    // preserves an identity; it does not extend one. Compared on values so the
                    // certificate parser's "Email:" and the CSR parser's prefix spelling cannot
                    // make two identical names look different. This mirrors the SAN subset check
                    // EstService.SimpleEnrollAsync applies to its mTLS clients.
                    var unheldSan = FirstSanNotHeldBySigner(
                        parsedCsr.SubjectAlternativeNames,
                        CertificateUtil.ParseCertificate(cmsSignerCert).SubjectAlternativeNames);
                    if (unheldSan != null)
                    {
                        _logger.LogWarning(
                            "SCEP renewal rejected — CSR requests SAN '{San}' that the signer certificate does not hold. signer='{Signer}'",
                            unheldSan, signerSubject);
                        await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                            "Renewal CSR requests a SAN the signer certificate does not hold.");
                        return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);
                    }

                    // The signer's own row, so the new request row is linked to the certificate it
                    // replaces. Nothing recorded that link before: a SCEP renewal produced a
                    // request indistinguishable from a first enrollment, and the certificate it
                    // superseded could only be inferred from the subject. Scoped by the issuer for
                    // the same reason the revocation lookup above is.
                    var renewedId = await _db.Certificates.AsNoTracking()
                        .Where(c => c.SerialNumber == signerSerial &&
                            (c.IssuerCertificateId == null || c.IssuerCertificateId == issuerCertId))
                        .Select(c => (Guid?)c.CertificateId)
                        .FirstOrDefaultAsync();
                    if (renewedId != null)
                        renewal = new EnrollmentRenewal(renewedId.Value, signerSerial);
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

        var callerPrincipal = isRenewal && cmsSignerCert != null
            ? $"scep-renewal:{CertificateUtil.FormatSerialNumber(cmsSignerCert.SerialNumber)}"
            : "scep-initial";

        // The transaction row, written by the post-authorization check below and read again once
        // the middle has answered.
        ScepTransactionEntity? txRow = null;

        var submission = BuildSubmission(
            parsedCsr, csrPem, context, transactionId, sourceIp, callerPrincipal, isRenewal, renewal);
        submission = submission with
        {
            AfterAuthorization = authorized =>
            {
                txRow = null;
                return PersistTransactionAsync(
                    authorized, parsedCsr, context, transactionId, sourceIp, row => txRow = row);
            },
            AfterProfileValidation = policy => EnforceKeyAlgorithmAsync(
                parsedCsr, policy, context, transactionId, sourceIp),
            Audit = record => WriteScepAuditAsync(record, sourceIp, callerPrincipal),
        };

        EnrollmentOutcome outcome;
        try
        {
            outcome = await _pipeline.SubmitAsync(submission);
        }
        catch (ScepRefusalException refusal)
        {
            // A check of SCEP's own refused, having already written its audit row: the replay
            // detection or the key-algorithm rule. Each carries the failInfo it has always
            // rendered, which is why it is thrown rather than returned — the middle has no failInfo
            // to carry and must not learn one.
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, refusal.FailInfo);
        }

        switch (outcome)
        {
            case EnrollmentOutcome.Issued issued:
            {
                var issuedCert = CertificateUtil.ParseFromPem(issued.CertificatePem);

                // Update the SCEP transaction row with the issued cert id
                // so GetCertInitial can return it to the legitimate polling client.
                if (txRow != null)
                {
                    var issuedEntity = await _db.Certificates.AsNoTracking().FirstOrDefaultAsync(c =>
                        c.SerialNumber == CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber));
                    txRow.IssuedCertificateId = issuedEntity?.CertificateId;
                    txRow.Status = TransactionIssued;
                    await _db.SaveChangesAsync();
                }

                // The chain the middle walked through the signing profile's issuer links, which is
                // the same walk this method used to make for itself, in the same order.
                var certChain = new List<X509Certificate> { issuedCert };
                foreach (var issuerPem in issued.ChainPem)
                    certChain.Add(CertificateUtil.ParseFromPem(issuerPem));

                return await BuildSuccessResponse(
                    caCert, caKey, transactionId, senderNonce, BuildCertsOnlyPkcs7(certChain));
            }

            // The request profile requires an approver. SCEP is the one protocol whose wire format
            // has always been able to say so — pkiStatus PENDING, RFC 8894 §3.2.1.2 — and the one
            // that never did: nothing on this path read RequireApproval, so a CA whose console
            // showed the gate as set issued to SCEP clients with no approver at all. The constant
            // for PENDING has been declared here since the responder was written and was never
            // used once.
            case EnrollmentOutcome.Pending pending:
            {
                if (txRow != null)
                {
                    // The link the poll follows once an approver acts. Written in the same save as
                    // the status and the extended TTL, because a row marked PendingApproval with
                    // no request named on it is a transaction nothing can ever complete.
                    txRow.CertRequestId = pending.RequestId;
                    txRow.Status = TransactionPendingApproval;
                    txRow.ExpiresAt = DateTime.UtcNow.Add(PendingApprovalTransactionTtl);
                    await _db.SaveChangesAsync();
                }
                _logger.LogInformation(
                    "SCEP PKCSReq at CA {CaLabel} awaits approval; answering PENDING (txId={TxId}).",
                    context.Ca?.Label, transactionId);
                return await BuildPendingResponse(caCert, caKey, transactionId, senderNonce);
            }

            // Already audited, by the writer above. The sentence reaches the audit row and the log
            // and never the client: SCEP answers a numeric failInfo and carries no text at all,
            // which is the strongest scrubbing of the five and needs no help to stay that way.
            case EnrollmentOutcome.Refused:
                return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);

            // A configuration fault, not a decision about the request. Thrown because that is how
            // this method has always answered one — the caller catches it and renders badRequest.
            case EnrollmentOutcome.Failed failed:
                throw new InvalidOperationException(failed.Message);

            default:
                throw new InvalidOperationException("Unrecognised enrollment outcome.");
        }
    }

    /// <summary>
    /// Turns a parsed PKCSReq into the normalized submission the shared middle takes: what the CSR
    /// asks for, and which credential is asking.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Static, and separate from <see cref="HandlePkcsReqAsync"/>, because everything a SCEP
    /// request becomes on its way into the middle is decided here and none of it was reachable in
    /// a test while it sat inside a method that also opened a CMS envelope. The three hooks and
    /// the audit writer need the service and are attached by the caller.
    /// </para>
    /// <para>
    /// The credential is the whole of what <paramref name="isRenewal"/> changes. An initial
    /// enrollment carries a challenge password inside the certification request and is not verified
    /// by SCEP itself, so <see cref="EnrollmentCaller.IsVerified"/> is false and the shared
    /// authorization step finds the password in <see cref="EnrollmentRequestMaterial.CsrPem"/> and
    /// consumes it — the same check, on the same CSR, at the same point in the order it has always
    /// run at. A renewal is verified here, by the signer checks above, and carries no password;
    /// it is verified, and the authorization step takes the signature for what it is.
    /// </para>
    /// </remarks>
    /// <param name="parsedCsr">The certification request, already parsed.</param>
    /// <param name="csrPem">The same request as PEM, which is what the request row stores.</param>
    /// <param name="context">The CA and profiles this exchange resolved before dispatching.</param>
    /// <param name="transactionId">The SCEP transaction id, carried into the audit row.</param>
    /// <param name="sourceIp">Caller address.</param>
    /// <param name="callerPrincipal">How the audit row names the caller.</param>
    /// <param name="isRenewal">Whether the PKCSReq was signed by a certificate this CA issued.</param>
    /// <param name="renewal">The certificate that signature names, when it is one this CA has a row for.</param>
    internal static EnrollmentSubmission BuildSubmission(
        CertificateUtil.ParsedCsrInfo parsedCsr,
        string csrPem,
        ResolvedCaContext context,
        string? transactionId,
        string? sourceIp,
        string callerPrincipal,
        bool isRenewal,
        EnrollmentRenewal? renewal)
        => new()
        {
            Protocol = Protocol,
            CaLabel = context.Ca?.Label,
            SourceIp = sourceIp,
            Correlation = transactionId,
            ResolvedContext = context,
            Renewal = renewal,
            Caller = new EnrollmentCaller(
                Principal: callerPrincipal,
                AuthMethod: isRenewal
                    ? EnrollmentAuthMethod.MessageSignature
                    : EnrollmentAuthMethod.SharedSecret,
                IsVerified: isRenewal),
            Request = new EnrollmentRequestMaterial
            {
                CsrPem = csrPem,
                Subject = parsedCsr.SubjectName,
                SubjectAlternativeNames = parsedCsr.SubjectAlternativeNames,
                KeyAlgorithm = parsedCsr.KeyAlgorithm,
                KeySize = parsedCsr.KeySize,
                SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            },
        };

    /// <summary>
    /// Writes the SCEP transaction row, which is also the replay check: the unique index on
    /// (CaId, TransactionId) is what a replayed PKCSReq collides with.
    /// </summary>
    /// <remarks>
    /// Runs from the pipeline's post-authorization hook, which is the place in the order it already
    /// had — after the caller is authorized, before any profile is read — so a caller who fails
    /// both is told about the credential and not about the replay. It settles nothing about the
    /// request and returns what it was given.
    /// </remarks>
    /// <param name="authorized">The request as the middle now holds it.</param>
    /// <param name="parsedCsr">The parsed request, for the subject and the public key hash.</param>
    /// <param name="context">The CA this exchange addresses.</param>
    /// <param name="transactionId">The client's transaction id; no row is written without one.</param>
    /// <param name="sourceIp">Caller address, for the audit row a replay writes.</param>
    /// <param name="captured">Receives the row, so the caller can complete it once the middle answers.</param>
    private async Task<EnrollmentAuthorizedRequest> PersistTransactionAsync(
        EnrollmentAuthorizedRequest authorized,
        CertificateUtil.ParsedCsrInfo parsedCsr,
        ResolvedCaContext context,
        string? transactionId,
        string? sourceIp,
        Action<ScepTransactionEntity> captured)
    {
        if (string.IsNullOrEmpty(transactionId))
            return authorized;

        // SHA-256 the requester public key so GetCertInitial can
        // verify the polling client matches the original PKCSReq.
        var pubKeyHash = Convert.ToHexString(
            SHA256.HashData(parsedCsr.PublicKeyDer ?? Array.Empty<byte>()));
        var txRow = new ScepTransactionEntity
        {
            CaId = context.Ca?.Id,
            TransactionId = transactionId,
            Subject = parsedCsr.SubjectName,
            RequesterPublicKeyHash = pubKeyHash,
            Status = TransactionPending,
            ExpiresAt = DateTime.UtcNow.Add(TransactionTtl)
        };
        _db.ScepTransactions.Add(txRow);
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // Duplicate transaction id → replay.
            _db.Entry(txRow).State = EntityState.Detached;
            await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp,
                "Duplicate SCEP transaction id (replay).");
            throw new ScepRefusalException(FailInfoBadRequest, "Duplicate SCEP transaction id (replay).");
        }

        captured(txRow);
        return authorized;
    }

    /// <summary>
    /// Holds the CSR's key algorithm to what the certificate profile the request resolved to
    /// permits, refusing with <c>badAlg</c> as SCEP always has.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kept as SCEP's own check rather than handed to the middle because no other protocol makes
    /// one before issuance, and because <c>badAlg</c> is the only failInfo SCEP renders that a
    /// shared refusal reason could ever reach: every other refusal the middle can produce comes
    /// out as <c>badRequest</c>. Issuance applies the same rule again, against the effective
    /// profile, for every protocol including this one.
    /// </para>
    /// <para>
    /// The list is JSON — <c>["RSA","ECDSA"]</c> — and this check used to split the raw column on
    /// commas. Nothing then matched: a profile left at its default <c>[]</c> produced the single
    /// token <c>[]</c>, which equals no key algorithm, so the check refused every PKCSReq that
    /// reached it with <c>badAlg</c>. No test covered the SCEP enrollment path at all, so it held.
    /// Reading the list as what it is means the rule now refuses what the profile actually forbids
    /// and permits everything else, which is a deliberate change to what a client is answered.
    /// </para>
    /// </remarks>
    /// <param name="parsedCsr">The parsed request, for the key algorithm and the subject.</param>
    /// <param name="policy">What the middle settled: the CA, the profiles, the names.</param>
    /// <param name="context">The CA this exchange addresses, for the audit row.</param>
    /// <param name="transactionId">The client's transaction id, for the audit row.</param>
    /// <param name="sourceIp">Caller address, for the audit row.</param>
    private async Task EnforceKeyAlgorithmAsync(
        CertificateUtil.ParsedCsrInfo parsedCsr,
        EnrollmentPolicyContext policy,
        ResolvedCaContext context,
        string? transactionId,
        string? sourceIp)
    {
        var allowed = await _db.CertProfiles.AsNoTracking()
            .Where(p => p.Id == policy.CertProfileId)
            .Select(p => p.AllowedKeyAlgorithms)
            .FirstOrDefaultAsync();
        if (KeyAlgorithmPermitted(allowed, parsedCsr.KeyAlgorithm))
            return;

        var message = $"CSR key algorithm '{parsedCsr.KeyAlgorithm}' not permitted by certificate profile.";
        await LogPkcsReqRejectedAsync(parsedCsr.SubjectName, context, transactionId, sourceIp, message);
        throw new ScepRefusalException(FailInfoBadAlg, message);
    }

    /// <summary>
    /// Whether a certificate profile's allowed-key-algorithm list permits an algorithm. An empty
    /// or absent list permits everything, which is what an unconstrained profile means.
    /// </summary>
    /// <remarks>
    /// The column holds a JSON array. A value that is not JSON is read as a comma-separated list
    /// instead, so a profile edited by hand into <c>RSA,ECDSA</c> is understood rather than
    /// silently refusing every request — which is what the comma-only reading did to every profile
    /// the application itself writes.
    /// </remarks>
    /// <param name="allowedKeyAlgorithms">The profile's list, as stored.</param>
    /// <param name="keyAlgorithm">The CSR's key algorithm.</param>
    internal static bool KeyAlgorithmPermitted(string? allowedKeyAlgorithms, string? keyAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(allowedKeyAlgorithms))
            return true;

        string[] allowed;
        var trimmed = allowedKeyAlgorithms.Trim();
        if (trimmed.StartsWith('['))
        {
            try
            {
                allowed = JsonSerializer.Deserialize<string[]>(trimmed) ?? [];
            }
            catch (JsonException)
            {
                return true;
            }
        }
        else
        {
            allowed = trimmed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        if (allowed.Length == 0)
            return true;
        return allowed.Any(a => string.Equals(a, keyAlgorithm, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Writes the shared audit fields the pipeline supplies as a SCEP row, in SCEP's own message
    /// types.
    /// </summary>
    /// <param name="record">The shared fields; see <see cref="EnrollmentAuditRecord"/>.</param>
    /// <param name="sourceIp">Caller address.</param>
    /// <param name="callerPrincipal">How the row names the caller.</param>
    private Task WriteScepAuditAsync(EnrollmentAuditRecord record, string? sourceIp, string callerPrincipal)
        => record.Event switch
        {
            EnrollmentAuditEvent.Issued => _protocolAudit.LogScepAsync(
                PkcsReqOperation, record.Subject, record.SerialNumber,
                record.KeyAlgorithm, record.KeySize, record.CaLabel, record.Correlation, sourceIp,
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: callerPrincipal),

            // Not a failure: the client is answered PENDING and may come back for it. Recorded
            // under its own message type so the SCEP tab tells a request awaiting an approver from
            // one that was issued and from one that was refused.
            EnrollmentAuditEvent.Pending => _protocolAudit.LogScepAsync(
                PkcsReqPendingOperation, record.Subject, null,
                record.KeyAlgorithm, record.KeySize, record.CaLabel, record.Correlation, sourceIp,
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: callerPrincipal),

            _ => _protocolAudit.LogScepAsync(
                PkcsReqOperation, record.Subject, null,
                record.KeyAlgorithm, record.KeySize, record.CaLabel, record.Correlation, sourceIp,
                success: false, errorMessage: record.Message ?? "Enrollment refused.",
                certificateAuthorityId: record.CaId, tenantId: record.TenantId,
                callerPrincipal: callerPrincipal),
        };

    /// <summary>
    /// A refusal one of SCEP's own checks made, carrying the failInfo that check has always
    /// rendered. Thrown rather than returned because the pipeline's hooks refuse by throwing, and
    /// caught immediately around the pipeline call.
    /// </summary>
    private sealed class ScepRefusalException : Exception
    {
        /// <summary>Constructs a refusal carrying a SCEP failInfo code.</summary>
        /// <param name="failInfo">The failInfo value, per RFC 8894 §3.2.1.4.</param>
        /// <param name="message">The sentence, for the log; it never reaches the client.</param>
        public ScepRefusalException(string failInfo, string message) : base(message)
        {
            FailInfo = failInfo;
        }

        /// <summary>The failInfo the response carries.</summary>
        public string FailInfo { get; }
    }

    /// <summary>Audit message type recorded for a PKCSReq that was issued or refused.</summary>
    private const string PkcsReqOperation = "PKCSReq";

    /// <summary>Audit message type recorded for a PKCSReq an approver now owns.</summary>
    private const string PkcsReqPendingOperation = "PKCSReqPending";

    /// <summary>Transaction status while the request is in flight.</summary>
    private const string TransactionPending = "Pending";

    /// <summary>Transaction status once the certificate exists and the client may collect it.</summary>
    private const string TransactionIssued = "Issued";

    /// <summary>
    /// Transaction status while an approver owns the request row, so <c>GetCertInitial</c> answers
    /// PENDING rather than badCertId.
    /// </summary>
    private const string TransactionPendingApproval = "PendingApproval";

    /// <summary>How long a transaction row is kept for a client that will poll within the exchange.</summary>
    private static readonly TimeSpan TransactionTtl = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long a transaction row is kept once an approver owns the request. Ten minutes is a
    /// client's retry window; an approval is a person's, and a row swept before they act would
    /// turn a PENDING answer into badCertId with nothing having gone wrong.
    /// </summary>
    private static readonly TimeSpan PendingApprovalTransactionTtl = TimeSpan.FromDays(7);

    /// <summary>
    /// Handles GetCertInitial (RFC 8894 §4.5) by looking up the
    /// stored SCEP transaction row, verifying the polling client's CMS signer public key
    /// hash matches the original requester's hash, and returning the associated cert.
    /// No match → <c>FailInfoBadCertId</c> (no more "most recent cert" leak across tenants).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a poll and a collection in one message, and it is not the shared middle. The design
    /// carried a <c>PollAsync</c> on the pipeline and it was dropped while migrating Windows
    /// autoenrollment; SCEP is the second poller and confirms the drop rather than reversing it.
    /// The two are keyed on different things — a request row identifier there, a CA and a
    /// transaction id here — and prove ownership differently: autoenrollment checks the account
    /// that submitted the row, and SCEP checks that the polling client holds the key that signed
    /// the original PKCSReq, because a SCEP client has no account. What is left over once both are
    /// removed is "has this row been issued yet", which is a database read and not a middle.
    /// </para>
    /// <para>
    /// A request an approver owns is followed through <see cref="ScepTransactionEntity.CertRequestId"/>,
    /// written when the PKCSReq was answered PENDING: still waiting is PENDING again, approved and
    /// issued is the certificate rendered exactly as an immediate enrollment renders it, and
    /// rejected or cancelled is the failInfo a refused PKCSReq already carries. The ownership proof
    /// runs before any of that is read, so the approval state is only ever disclosed to the client
    /// that made the request.
    /// </para>
    /// </remarks>
    /// <param name="caCert">The CA certificate the response is signed under.</param>
    /// <param name="caKey">The key the signer holds for it.</param>
    /// <param name="transactionId">The transaction id the client is asking after.</param>
    /// <param name="senderNonce">The client's nonce, echoed as the recipient nonce.</param>
    /// <param name="context">The CA and profiles this exchange addresses.</param>
    /// <param name="cmsSignerCert">The certificate that signed the poll, when the CMS carried one.</param>
    private async Task<byte[]> HandleGetCertInitialAsync(
        X509Certificate caCert,
        ScepSignerKey caKey,
        string? transactionId,
        byte[]? senderNonce,
        ResolvedCaContext context,
        X509Certificate? cmsSignerCert)
    {
        if (string.IsNullOrEmpty(transactionId))
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);

        var tx = await _db.ScepTransactions
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.CaId == context.Ca!.Id && t.TransactionId == transactionId);

        // A request an approver owns is answered PENDING again, not badCertId: nothing has gone
        // wrong and the client is right to keep asking. This branch exists only because the
        // PKCSReq path now reads the approval gate at all; before that no transaction row could
        // ever be in this state.
        var underApproval = tx != null
            && tx.Status == TransactionPendingApproval
            && tx.IssuedCertificateId == null
            && tx.ExpiresAt >= DateTime.UtcNow;

        if (tx == null || (tx.IssuedCertificateId == null && !underApproval))
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);

        if (tx.ExpiresAt < DateTime.UtcNow)
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);

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
                    return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);
                }
            }
        }

        // Proven to be the client that made the request. What the approver has since done with the
        // request row is the whole of what is left to answer, and it is only asked after the proof
        // above: a caller who guessed the transaction id learns nothing about its state.
        var certificateId = tx.IssuedCertificateId;
        if (underApproval)
        {
            var (state, approvedCertificateId) = await ResolveApprovalAsync(tx, transactionId);
            switch (state)
            {
                // Nobody has acted yet: PENDING again, which is what the client is asking for.
                case ApprovalPollState.StillPending:
                    return await BuildPendingResponse(caCert, caKey, transactionId, senderNonce);

                // An operator refused it. badRequest is the failInfo a refused PKCSReq already
                // renders, so a refusal reads the same whether it arrived at submission or later.
                case ApprovalPollState.Refused:
                    return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadRequest);

                // Approved and issued — fall through to the rendering every successful poll uses.
                case ApprovalPollState.Issued:
                    certificateId = approvedCertificateId;
                    break;

                // The link is missing or the row it named is gone: nothing to collect and nothing
                // to wait for, which is what badCertId says.
                default:
                    return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);
            }
        }

        var recentCertEntity = await _db.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == certificateId!.Value);
        if (recentCertEntity == null)
            return await BuildFailureResponse(caCert, caKey, transactionId, senderNonce, FailInfoBadCertId);

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
        return await BuildSuccessResponse(caCert, caKey, transactionId, senderNonce, pkcs7Bytes);
    }

    /// <summary>What a poll found had become of the request an approver owns.</summary>
    private enum ApprovalPollState
    {
        /// <summary>The request row is still waiting for an approver, or approved but not yet issued.</summary>
        StillPending,

        /// <summary>The request was issued; the certificate is named alongside this state.</summary>
        Issued,

        /// <summary>An operator rejected or cancelled the request.</summary>
        Refused,

        /// <summary>
        /// Nothing can be resolved: the transaction names no request row, or names one the database
        /// no longer has.
        /// </summary>
        Unresolvable,
    }

    /// <summary>
    /// Follows a pending transaction's <see cref="ScepTransactionEntity.CertRequestId"/> to what the
    /// approver did with it, and completes the transaction row when a certificate exists.
    /// </summary>
    /// <remarks>
    /// The completion is the same bookkeeping an immediate enrollment does in
    /// <c>HandlePkcsReqAsync</c> — the issued certificate recorded on the transaction and the status
    /// moved to <c>Issued</c> — so a second poll is answered by the ordinary collection path and
    /// returns the same certificate rather than re-resolving the approval. A rejection leaves the
    /// row as it is: every further poll then reads the refusal the same way, until the row reaches
    /// its TTL and the sweep removes it.
    /// </remarks>
    /// <param name="tx">The transaction row, as read for the poll.</param>
    /// <param name="transactionId">The transaction id, for the log.</param>
    /// <returns>The state, and the issued certificate's id when there is one.</returns>
    private async Task<(ApprovalPollState State, Guid? CertificateId)> ResolveApprovalAsync(
        ScepTransactionEntity tx, string transactionId)
    {
        if (tx.CertRequestId == null)
        {
            // A row written before this link existed. It can never be completed, and saying so is
            // better than answering PENDING to a client that would poll until its TTL for nothing.
            _logger.LogWarning(
                "SCEP GetCertInitial cannot complete transaction {TxId}: it names no request row.",
                transactionId);
            return (ApprovalPollState.Unresolvable, null);
        }

        var request = await _db.CertificateRequests
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == tx.CertRequestId.Value);
        if (request == null)
            return (ApprovalPollState.Unresolvable, null);

        if (request.IssuedCertificateId != null)
        {
            var completed = await _db.ScepTransactions.FirstOrDefaultAsync(t => t.Id == tx.Id);
            if (completed != null)
            {
                completed.IssuedCertificateId = request.IssuedCertificateId;
                completed.Status = TransactionIssued;
                await _db.SaveChangesAsync();
            }
            _logger.LogInformation(
                "SCEP GetCertInitial collected the approved certificate for transaction {TxId}.",
                transactionId);
            return (ApprovalPollState.Issued, request.IssuedCertificateId);
        }

        return request.Status switch
        {
            RequestRejectedStatus or RequestCancelledStatus => (ApprovalPollState.Refused, null),
            _ => (ApprovalPollState.StillPending, null),
        };
    }

    /// <summary>Request-row status an operator's refusal writes.</summary>
    private const string RequestRejectedStatus = "Rejected";

    /// <summary>Request-row status an operator's withdrawal writes.</summary>
    private const string RequestCancelledStatus = "Cancelled";

    /// <summary>
    /// Chooses the CA that signs this exchange: the resolved CA when it has one and the signer
    /// holds its key, else the first registered signer the signer holds a CA key for. Whether
    /// the key is present is asked of the signer while choosing, so a CA without its key is
    /// passed over exactly as when the keystore was consulted directly.
    /// </summary>
    private async Task<(X509Certificate cert, ScepSignerKey key)?> ResolveSignerForCaAsync(ResolvedCaContext context)
    {
        if (context.Ca != null)
        {
            var certEntity = await _db.Certificates.FindAsync(context.Ca.CertificateId);
            if (certEntity != null)
            {
                var caCert = CertificateUtil.ParseFromPem(certEntity.Pem);
                var key = new ScepSignerKey(
                    new KeyRef(certEntity.CertificateId),
                    SigningContext.ForCa(SignerCaller, SigningPurpose.Scep, context.Ca.Id, context.Ca.TenantId));
                var held = await _signer.ListKeysAsync(key.Context);
                if (held.Any(k => k.Key.CertificateId == key.Key.CertificateId))
                    return (caCert, key);
            }
        }

        // Fallback: the first registered signer that is a CA key the signer holds
        var caKeys = await _signer.ListKeysAsync(new SigningContext(SignerCaller, SigningPurpose.Scep, null, null));
        foreach (var signer in _keystore.GetSigners())
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signer.PublicCertificate.GetPublicKey()).GetDerEncoded();
            var info = caKeys.FirstOrDefault(k => k.Kind == KeyKind.Ca && k.CaId != null && k.PublicKeyDer.AsSpan().SequenceEqual(spki));
            if (info != null)
                return (signer.PublicCertificate, new ScepSignerKey(info.Key, new SigningContext(SignerCaller, SigningPurpose.Scep, info.TenantId, info.CaId)));
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

    /// <summary>Builds a signed CertRep carrying SUCCESS and the certs-only PKCS#7.</summary>
    private Task<byte[]> BuildSuccessResponse(
        X509Certificate caCert,
        ScepSignerKey caKey,
        string? transactionId,
        byte[]? senderNonce,
        byte[] certsPkcs7Content)
    {
        return BuildScepResponse(caCert, caKey, transactionId, senderNonce,
            PkiStatusSuccess, null, certsPkcs7Content);
    }

    /// <summary>
    /// Builds a signed CertRep carrying PENDING: the request exists and an approver owns it, and
    /// the client should ask after it with <c>GetCertInitial</c> (RFC 8894 §3.2.1.2).
    /// </summary>
    /// <param name="caCert">The CA certificate the response is signed under.</param>
    /// <param name="caKey">The key the signer holds for it.</param>
    /// <param name="transactionId">The client's transaction id, echoed back.</param>
    /// <param name="senderNonce">The client's nonce, echoed as the recipient nonce.</param>
    private Task<byte[]> BuildPendingResponse(
        X509Certificate caCert,
        ScepSignerKey caKey,
        string? transactionId,
        byte[]? senderNonce)
    {
        return BuildScepResponse(caCert, caKey, transactionId, senderNonce,
            PkiStatusPending, null, null);
    }

    /// <summary>Builds a signed CertRep carrying FAILURE and the given failInfo.</summary>
    private Task<byte[]> BuildFailureResponse(
        X509Certificate caCert,
        ScepSignerKey caKey,
        string? transactionId,
        byte[]? senderNonce,
        string failInfo)
    {
        return BuildScepResponse(caCert, caKey, transactionId, senderNonce,
            PkiStatusFailure, failInfo, null);
    }

    /// <summary>
    /// Builds the CMS SignedData of a CertRep: the SCEP attributes, the content digest, and a
    /// signature over the signed attributes made by the signer with the CA key.
    /// </summary>
    private async Task<byte[]> BuildScepResponse(
        X509Certificate caCert,
        ScepSignerKey caKey,
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

        // Sign the signed attributes through the signer, which holds the CA key
        var sigAlgName = resolvedSigAlg;
        var encodedSignedAttrs = signedAttrSet.GetDerEncoded();
        var signature = await _signer.SignAsync(caKey.Key, SignatureAlgorithm.FromName(sigAlgName), encodedSignedAttrs, caKey.Context);

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
    /// <summary>
    /// Returns the first requested SAN that the renewal signer's certificate does not already
    /// carry, or <c>null</c> when every requested name is one the signer holds.
    /// </summary>
    /// <remarks>
    /// A renewal preserves an identity; it does not extend one. This is the SAN half of that rule,
    /// alongside the subject-DN match — and it was missing, so a renewal could add any name the
    /// request profile happened to tolerate while skipping the challenge password that would
    /// otherwise have bounded it.
    /// <para>
    /// Compared on values with the <c>TYPE:</c> prefix stripped: the certificate parser and the CSR
    /// parser spell the prefixes differently ("Email" vs "EMAIL", "Other" for anything they do not
    /// recognise), so comparing whole entries would report two identical names as different and
    /// reject healthy renewals. The value is the identity; the prefix is a label.
    /// </para>
    /// </remarks>
    internal static string? FirstSanNotHeldBySigner(
        IEnumerable<string> requestedSans, IEnumerable<string> signerSans)
    {
        var held = signerSans.Select(SanValue).ToList();
        foreach (var requested in requestedSans)
        {
            var value = SanValue(requested);
            if (string.IsNullOrWhiteSpace(value)) continue;
            if (!held.Any(h => string.Equals(h, value, StringComparison.OrdinalIgnoreCase)))
                return requested;
        }
        return null;
    }

    private static string SanValue(string entry)
    {
        var idx = entry.IndexOf(':');
        return idx > 0 ? entry[(idx + 1)..].Trim() : entry.Trim();
    }

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
