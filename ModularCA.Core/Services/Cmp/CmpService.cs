using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cmp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services.Cmp;

/// <summary>
/// CMP responder service implementing the Certificate Management Protocol (RFC 4210).
/// Handles ir (initialization), cr (certification), kur (key update),
/// rr (revocation), certConf (certificate confirm), and genm (general message).
/// Transport per RFC 6712 (CMP over HTTP).
/// </summary>
public class CmpService : ICmpService
{
    // PKIBody type tags per RFC 4210 §5.1.2
    private const int TypeIr = 0;   // Initialization Request
    private const int TypeIp = 1;   // Initialization Response
    private const int TypeCr = 2;   // Certification Request
    private const int TypeCp = 3;   // Certification Response
    private const int TypeKur = 7;  // Key Update Request
    private const int TypeKup = 8;  // Key Update Response
    private const int TypeRr = 11;  // Revocation Request
    private const int TypeRp = 12;  // Revocation Response
    private const int TypeCertConf = 24;  // Certificate Confirm
    private const int TypePkiConf = 19;   // PKI Confirm (empty response)
    private const int TypeGenm = 21; // General Message
    private const int TypeGenp = 22; // General Response
    private const int TypeError = 23; // Error Message

    // PKIStatus values per RFC 4210 §5.2.3
    private const int StatusGranted = 0;
    private const int StatusGrantedWithMods = 1;
    private const int StatusRejection = 2;

    // PKIFailureInfo bits per RFC 4210 §5.2.3
    private const int FailBadAlg = 0;
    private const int FailBadMessageCheck = 1;
    private const int FailBadRequest = 2;
    private const int FailBadTime = 3;
    private const int FailBadDataFormat = 5;
    private const int FailNotAuthorized = 6;
    private const int FailBadPop = 9;
    private const int FailSystemFailure = 25;

    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ICertificateIssuanceService _issuanceService;
    private readonly ICertificateRevocationService _revocationService;
    private readonly ICaResolverService _caResolver;
    private readonly IProtocolAuditService _protocolAudit;
    private readonly IEnrollmentAuthorizationService _enrollmentAuth;
    private readonly RequestProfileValidationService _requestProfileValidation;
    private readonly IEnrollmentTokenService _enrollmentTokens;
    private readonly Microsoft.Extensions.Logging.ILogger<CmpService> _logger;

    /// <summary>
    /// Initializes a new instance. Per-request state (source IP, CA label, protection mode,
    /// PBMAC artifacts) flows through <see cref="CmpRequestContext"/> rather than instance
    /// fields so the per-request data lives on the call stack and cannot cross-contaminate
    /// concurrent requests through accidentally-shared mutable state.
    /// </summary>
    public CmpService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ICertificateIssuanceService issuanceService,
        ICertificateRevocationService revocationService,
        ICaResolverService caResolver,
        IProtocolAuditService protocolAudit,
        IEnrollmentAuthorizationService enrollmentAuth,
        RequestProfileValidationService requestProfileValidation,
        IEnrollmentTokenService enrollmentTokens,
        Microsoft.Extensions.Logging.ILogger<CmpService> logger)
    {
        _db = db;
        _keystore = keystore;
        _issuanceService = issuanceService;
        _revocationService = revocationService;
        _caResolver = caResolver;
        _protocolAudit = protocolAudit;
        _enrollmentAuth = enrollmentAuth;
        _requestProfileValidation = requestProfileValidation;
        _enrollmentTokens = enrollmentTokens;
        _logger = logger;
    }

    /// <summary>
    /// Per-request CMP context. Replaces the old
    /// <c>_sourceIp</c>/<c>_caLabel</c> instance fields so a singleton DI flip
    /// doesn't cross-contaminate concurrent requests. Carries the detected protection
    /// mode so responses can echo the client's selection (High #6).
    /// </summary>
    internal sealed class CmpRequestContext
    {
        public string? SourceIp { get; init; }
        public string? CaLabel { get; init; }
        public CmpProtectionMode ProtectionMode { get; set; } = CmpProtectionMode.None;

        /// <summary>
        /// The CA certificate, when responses are signed by a dedicated CMP signer rather than the
        /// CA itself. Attached to <c>extraCerts</c> so a client holding only the CA as its trust
        /// anchor can chain the signer. Null when the CA signs directly.
        /// </summary>
        public X509Certificate? SignerIssuerCert { get; set; }

        /// <summary>
        /// SANs held by the signing certificate, in <c>TYPE:value</c> form, for signature-protected
        /// requests. What a request may ask for is bounded by these.
        /// </summary>
        public List<string> SignerSans { get; set; } = [];

        /// <summary>For PBMAC responses: reference value to echo in senderKID (bytes).</summary>
        public byte[]? PbmReferenceValue { get; set; }

        /// <summary>
        /// The raw shared secret that verified the request's PBMAC, retained so the response MAC
        /// key can be derived correctly.
        /// <para>
        /// RFC 4210 §5.1.3.1 derives the MAC key as <c>OWF^iterations(secret || salt)</c>. The
        /// response carries its own freshly generated salt, so the response key must be derived
        /// from the SAME secret against the NEW salt. Deriving it from the request's derived key
        /// instead — which is what the response builder used to do, for want of the secret at that
        /// point — produces a key no conforming client can reproduce, because the client only ever
        /// has the secret. Every PBMAC-protected response was therefore unverifiable.
        /// </para>
        /// <para>Zeroed by <see cref="ProcessRequestAsync"/> once the response has been built.</para>
        /// </summary>
        public byte[]? PbmSecret { get; set; }

        /// <summary>
        /// The one-way function, MAC algorithm and iteration count the client selected. Echoed on
        /// the response instead of the hardcoded SHA-1 / HMAC-SHA1 pair, so a client that
        /// negotiated SHA-256 is not handed a SHA-1 MAC it will not check for.
        /// </summary>
        public AlgorithmIdentifier? PbmOwf { get; set; }
        public AlgorithmIdentifier? PbmMac { get; set; }
        public int PbmIterationCount { get; set; } = 1024;

        /// <summary>
        /// The enrollment-token row whose shared secret authenticated a PBMAC request. Carries the
        /// credential's <c>SubjectRestriction</c> / <c>SANRestriction</c>, which bound what this
        /// credential may enroll and revoke.
        /// </summary>
        public EnrollmentTokenEntity? PbmToken { get; set; }

        /// <summary>
        /// Subject DN of the certificate that signed a signature-protected request, and its serial.
        /// These are the requester's identity: revocation is authorized against them so a peer
        /// cannot revoke certificates that are not its own.
        /// </summary>
        public string? SignerSubjectDn { get; set; }
        public string? SignerSerialHex { get; set; }

        /// <summary>Owner of the matched CMP PBMAC credential, used in audit as callerPrincipal.</summary>
        public string? CallerPrincipal { get; set; }

        /// <summary>
        /// RFC 4210 §5.2.8.2: <c>raVerified</c> POP is only acceptable when the CMP message
        /// itself has been authenticated AND the authenticated principal is explicitly
        /// recognized as an RA authorized to attest POP on behalf of end-entities. Default is
        /// <c>false</c> (fail-closed): no code path currently elevates an authenticated peer
        /// to RA status, so <c>raVerified</c> is uniformly refused until an RA-authorization
        /// mechanism (e.g. thumbprint allowlist or group-based check) is added. This prevents
        /// attackers who can reach the CMP endpoint with an unprotected — or weakly protected
        /// — IR from skipping proof-of-possession by asserting <c>raVerified</c>.
        /// </summary>
        public bool IsAuthorizedRa { get; set; } = false;
    }

    internal enum CmpProtectionMode
    {
        None = 0,
        PbMac = 1,
        Signature = 2,
    }

    public async Task<byte[]> ProcessRequestAsync(byte[] derRequest, string? caLabel = null, string? sourceIp = null)
    {
        var reqCtx = new CmpRequestContext { SourceIp = sourceIp, CaLabel = caLabel };
        var context = await _caResolver.ResolveAsync(caLabel, "CMP");
        var (caCert, caKeyHandle, signerIssuer) = await ResolveSignerForCaAsync(context)
            ?? throw new InvalidOperationException("No CA signer available for CMP.");
        reqCtx.SignerIssuerCert = signerIssuer;

        PkiMessage request;
        try
        {
            request = PkiMessage.GetInstance(Asn1Object.FromByteArray(derRequest));
        }
        catch (Exception)
        {
            return BuildErrorResponse(caCert, caKeyHandle, null, reqCtx, StatusRejection, FailBadDataFormat,
                "Invalid CMP PKIMessage encoding.");
        }

        var header = request.Header;
        var body = request.Body;

        // MessageTime freshness window (±300s). Clients with clocks
        // drifting more than five minutes get FailBadTime so captured messages can't be
        // replayed once the legit requestor notices and bumps their clock.
        if (header.MessageTime != null)
        {
            try
            {
                var clientTime = header.MessageTime.ToDateTime();
                var skew = Math.Abs((DateTime.UtcNow - clientTime).TotalSeconds);
                if (skew > 300)
                {
                    return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadTime,
                        "messageTime outside the acceptable freshness window.");
                }
            }
            catch
            {
                return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadTime,
                    "messageTime could not be parsed.");
            }
        }

        // RFC 9483 section 3.1 (Lightweight CMP Profile) requires transactionID, senderNonce and
        // messageTime in every message; RFC 4210 left them optional. Both checks were therefore
        // opt-in by the attacker: omit messageTime and there was no freshness window, omit
        // transactionID and no replay record was kept. A captured protected request that left
        // both out replayed indefinitely. They are required here for every request.
        if (header.MessageTime == null)
        {
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadTime,
                "messageTime is required (RFC 9483 section 3.1).");
        }
        if (header.TransactionID == null)
        {
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadRequest,
                "transactionID is required (RFC 9483 section 3.1).");
        }

        // Sender/transaction nonce length minimums (RFC 4210 §5.1.1; the same
        // invariant is carried into SCEP). Reject absurdly short
        // nonces outright.
        if (header.SenderNonce != null && header.SenderNonce.GetOctets().Length < 16)
        {
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadMessageCheck,
                "senderNonce must be at least 16 octets.");
        }

        // ───────── Protection validation ──────────────────────────────────
        // OID 1.2.840.113533.7.66.13 = id-PasswordBasedMac
        if (header.ProtectionAlg != null && request.Protection != null
            && header.ProtectionAlg.Algorithm.Id == "1.2.840.113533.7.66.13")
        {
            reqCtx.ProtectionMode = CmpProtectionMode.PbMac;

            // Lookup per-reference-value secret via enrollment tokens.
            var pbmVerified = await TryVerifyPbmAsync(header, request, body, context.Ca?.Id, caLabel, reqCtx);
            if (!pbmVerified)
            {
                return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadRequest,
                    "PBMAC verification failed — unknown reference value or invalid shared secret.");
            }
        }
        else if (header.ProtectionAlg != null && request.Protection != null)
        {
            // Signature-based protection (RFC 4210 §5.1.3.3).
            reqCtx.ProtectionMode = CmpProtectionMode.Signature;
            var sigError = await VerifySignatureProtectionAsync(request, header, body, caCert, reqCtx);
            if (sigError != null)
            {
                return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadMessageCheck,
                    sigError);
            }
        }
        else if (header.ProtectionAlg != null)
        {
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadMessageCheck,
                "Message protection is required but verification failed.");
        }
        else
        {
            // No protectionAlg at all. Every branch above is gated on `header.ProtectionAlg != null`,
            // so without this final else an entirely unprotected PKIMessage matched none of them and
            // fell straight through to PersistOrCheckTransactionAsync and HandleCertRequestAsync with
            // ProtectionMode == None. Downstream, ValidateCmp returned success whenever
            // CmpRequireSignature was false — and it defaults to false — leaving POP as the only
            // remaining gate, which an attacker satisfies by signing the CertRequest with their own
            // key. The result was that an unauthenticated remote could POST an unprotected `ir` and
            // receive a certificate. RFC 4210 §5.1.3 requires protection; reject outright.
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadMessageCheck,
                "CMP messages must carry signature-based or password-based MAC protection (RFC 4210 5.1.3).");
        }

        // CmpRequireSignature means "signature protection specifically", not merely "protected".
        // This is enforced here rather than in EnrollmentAuthorizationService because the concrete
        // protection mode is only known at this layer — the authorization service receives a bare
        // bool and a null client certificate, which is why its own check could never work.
        if (reqCtx.ProtectionMode == CmpProtectionMode.PbMac)
        {
            var sigRequired = await _db.CaProtocolConfigs
                .AsNoTracking()
                .Where(c => c.Protocol == "CMP" && (reqCtx.CaLabel == null || c.Ca.Label == reqCtx.CaLabel))
                .Select(c => (bool?)c.CmpRequireSignature)
                .FirstOrDefaultAsync() ?? false;

            if (sigRequired)
            {
                return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadMessageCheck,
                    "This CA requires signature-based CMP protection; PBMAC is not accepted.");
            }
        }

        // TransactionId replay protection. Reject duplicates for IR/CR/KUR.
        // Insert before dispatching so reads of existing transactions on certConf work.
        var replayCheck = await PersistOrCheckTransactionAsync(header, body.Type, context.Ca?.Id, reqCtx);
        if (replayCheck != null)
        {
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadRequest,
                replayCheck);
        }

        try
        {
            return body.Type switch
            {
                TypeIr => await HandleCertRequestAsync(body, header, caCert, caKeyHandle, TypeIp, context, reqCtx),
                TypeCr => await HandleCertRequestAsync(body, header, caCert, caKeyHandle, TypeCp, context, reqCtx),
                TypeKur => await HandleCertRequestAsync(body, header, caCert, caKeyHandle, TypeKup, context, reqCtx),
                TypeRr => await HandleRevocationRequestAsync(body, header, caCert, caKeyHandle, reqCtx),
                TypeCertConf => HandleCertConfirm(body, header, caCert, caKeyHandle, reqCtx),
                TypeGenm => HandleGeneralMessage(header, caCert, caKeyHandle, reqCtx),
                _ => BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailBadRequest,
                    $"Unsupported PKIBody type: {body.Type}.")
            };
        }
        catch (Exception ex)
        {
            // Never leak exception text to unauthenticated remotes.
            var correlationId = Guid.NewGuid().ToString("N")[..12];
            _logger.LogError(ex, "CMP processing failure [{CorrelationId}] caLabel={CaLabel}", correlationId, caLabel);
            return BuildErrorResponse(caCert, caKeyHandle, header, reqCtx, StatusRejection, FailSystemFailure,
                $"Certificate issuance failed; contact administrator (ref {correlationId})");
        }
        finally
        {
            // The shared secret lives only as long as it takes to protect the response.
            if (reqCtx.PbmSecret != null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(reqCtx.PbmSecret);
                reqCtx.PbmSecret = null;
            }
        }
    }

    /// <summary>
    /// Verify a PBMAC-protected CMP request by looking up the
    /// client's senderKID against an EnrollmentToken row. Returns true on success
    /// and populates <paramref name="reqCtx"/> with the derived key so the response can
    /// be PBMAC-protected as well (High #6).
    /// </summary>
    private async Task<bool> TryVerifyPbmAsync(PkiHeader header, PkiMessage request, PkiBody body,
        Guid? caId, string? caLabel, CmpRequestContext reqCtx)
    {
        try
        {
            var pbmParam = PbmParameter.GetInstance(header.ProtectionAlg.Parameters);
            var salt = pbmParam.Salt.GetOctets();
            var iterCount = pbmParam.IterationCount.IntValueExact;
            var owf = pbmParam.Owf;
            var macAlg = pbmParam.Mac;

            // Reject absurd iteration counts — protects against DoS via
            // attacker-controlled iteration parameter.
            if (iterCount < 1 || iterCount > 500_000)
                return false;

            // Resolve candidate secret(s): senderKID → EnrollmentToken.CmpReferenceValue.
            var candidates = new List<(byte[] secret, string principal, EnrollmentTokenEntity? token)>();

            string? senderKidHex = null;
            if (header.SenderKID != null)
            {
                var senderKidBytes = header.SenderKID.GetOctets();
                senderKidHex = Convert.ToHexString(senderKidBytes);
                var referenceValue = System.Text.Encoding.UTF8.GetString(senderKidBytes);
                var tokenEntity = await _db.EnrollmentTokens
                    .FirstOrDefaultAsync(t =>
                        t.CmpReferenceValue == referenceValue &&
                        t.UsedForCmp && !t.IsRevoked);

                // A CMP shared secret authenticates to the CA it was minted for and to no other.
                //
                // This lookup used to match on the reference value alone, and `caLabel` — the only
                // CA context the method received — was never read. Every CMP-enabled CA in the
                // deployment therefore accepted every CMP credential in the deployment: a secret
                // issued for a lab CA authenticated ir/cr/kur/rr against the production CA simply
                // by POSTing to the production CA's URL. Tenancy made no difference, because the
                // token table was never consulted for one.
                //
                // A token with no CertificateAuthorityId is a system-wide enrollment token, not a
                // CA credential; it is refused here rather than treated as a wildcard. The refusal
                // is logged distinctly so an operator can tell "wrong CA" from "wrong secret",
                // which the generic PBMAC failure response deliberately does not reveal.
                if (tokenEntity != null && tokenEntity.CertificateAuthorityId != caId)
                {
                    _logger.LogWarning(
                        "CMP PBMAC credential {TokenId} presented to CA '{CaLabel}' but is scoped to {ScopedCa} — rejected.",
                        tokenEntity.Id, caLabel ?? "(default)",
                        tokenEntity.CertificateAuthorityId?.ToString() ?? "(no CA)");
                    tokenEntity = null;
                }

                if (tokenEntity != null && tokenEntity.ExpiresAt >= DateTime.UtcNow
                    && (tokenEntity.MaxUses <= 0 || tokenEntity.UsesRemaining > 0))
                {
                    // We already hash in EnrollmentTokenService; here we need a
                    // byte-wise secret for PBMAC. The stored plaintext `Token` column
                    // IS the plaintext shared secret (issued once at admin creation).
                    // It is never returned from admin GET endpoints (see
                    // AdminProtocolConfigController).
                    candidates.Add((System.Text.Encoding.UTF8.GetBytes(tokenEntity.Token), referenceValue, tokenEntity));
                }
            }

            if (candidates.Count == 0) return false;

            // BouncyCastle's ProtectedPkiMessage.Verify is the canonical PBMAC verification path,
            // but it only accepts a PKMacBuilder, so the MAC is computed here directly.
            var receivedMac = request.Protection.GetBytes();
            var protectedPartBytes = new DerSequence(header, body).GetDerEncoded();

            foreach (var (secret, principal, token) in candidates)
            {
                // Same derivation the response builder uses — see DerivePbmKey.
                var dk = DerivePbmKey(secret, salt, owf, iterCount);

                var mac = MacUtilities.GetMac(macAlg.Algorithm);
                mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(dk));
                mac.BlockUpdate(protectedPartBytes, 0, protectedPartBytes.Length);
                var computedMac = new byte[mac.GetMacSize()];
                mac.DoFinal(computedMac, 0);

                if (Org.BouncyCastle.Utilities.Arrays.FixedTimeEquals(computedMac, receivedMac))
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(dk);
                    reqCtx.PbmReferenceValue = header.SenderKID?.GetOctets();
                    reqCtx.CallerPrincipal = $"cmp-pbmac:{principal}";

                    // Carry the secret and the client's negotiated parameters forward: the response
                    // MAC key has to be derived from the secret against the response's own salt.
                    reqCtx.PbmSecret = (byte[])secret.Clone();
                    reqCtx.PbmOwf = owf;
                    reqCtx.PbmMac = macAlg;
                    reqCtx.PbmIterationCount = iterCount;
                    reqCtx.PbmToken = token;

                    // Atomic consume — see EnrollmentTokenService.TryConsumeUseAsync. A losing
                    // race here means another request already spent the token's last use, so the
                    // PBMAC that just verified must not authorize an issuance.
                    if (token != null &&
                        !await EnrollmentTokenService.TryConsumeUseAsync(_db, token))
                    {
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(reqCtx.PbmSecret);
                        reqCtx.PbmSecret = null;
                        return false;
                    }
                    return true;
                }

                // Zero the rejected key.
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(dk);
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PBMAC verification error");
            return false;
        }
    }

    /// <summary>
    /// Minimal RFC 4210 §5.1.3.3 signature-based protection.
    /// Locates the signing cert in <c>extraCerts</c>, verifies it is issued by one of
    /// our CAs, enforces NotBefore/NotAfter + revocation, then verifies the protected-part
    /// signature (SEQUENCE(header, body)) against the signing cert's public key using an
    /// allow-list of signature algorithms. For <c>kur</c>, additionally requires the
    /// signing cert's subject to match the CertTemplate subject (key-identity binding).
    /// Returns null on success or a public-safe error string on failure.
    /// </summary>
    private async Task<string?> VerifySignatureProtectionAsync(
        PkiMessage request, PkiHeader header, PkiBody body, X509Certificate caCert, CmpRequestContext reqCtx)
    {
        var allowedSigAlgs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "1.2.840.113549.1.1.11", // sha256WithRSA
            "1.2.840.113549.1.1.12", // sha384WithRSA
            "1.2.840.113549.1.1.13", // sha512WithRSA
            "1.2.840.10045.4.3.2",   // ecdsa-with-SHA256
            "1.2.840.10045.4.3.3",   // ecdsa-with-SHA384
            "1.2.840.10045.4.3.4",   // ecdsa-with-SHA512
            "1.2.840.113549.1.1.10", // id-RSASSA-PSS
            "1.3.101.112",           // Ed25519
            "1.3.101.113",           // Ed448
        };

        var sigOid = header.ProtectionAlg.Algorithm.Id;
        if (!allowedSigAlgs.Contains(sigOid))
            return $"Unsupported CMP signature algorithm: {sigOid}";

        // Extract signing cert from extraCerts. BouncyCastle's PkiMessage exposes extraCerts
        // as CmpCertificate[] — the first entry is the signing cert per RFC 4210.
        var extraCerts = request.GetExtraCerts();
        if (extraCerts == null || extraCerts.Length == 0)
            return "Signed CMP request missing signing certificate in extraCerts.";

        X509Certificate signingCert;
        try
        {
            var signingCmpCert = extraCerts[0];
            // CmpCertificate wraps an X509CertificateStructure (choice 0).
            var x509Struct = signingCmpCert.X509v3PKCert;
            if (x509Struct == null)
                return "extraCerts[0] does not contain a v3 X.509 certificate.";
            signingCert = new X509Certificate(x509Struct);
        }
        catch
        {
            return "Invalid signing certificate in extraCerts.";
        }

        var now = DateTime.UtcNow;
        if (now < signingCert.NotBefore || now > signingCert.NotAfter)
            return "Signing certificate is not within its validity window.";

        // Chain validation — the signing certificate must have been issued by THE CA THIS
        // REQUEST ADDRESSES, not merely by some CA in the deployment.
        //
        // This used to search every CA row whose subject matched the signer's issuer DN and accept
        // a signature that verified against any of them. A certificate issued by a lab or tenant CA
        // therefore authenticated CMP requests to the production CA: the caller picked the target
        // by URL, and nothing tied the credential to it. Combined with revocation being authorized
        // for anything the addressed CA had issued, that was a cross-CA revocation primitive.
        //
        // There is no RA concept here (CmpRequestContext.IsAuthorizedRa is hardwired false), so
        // there is no legitimate case for a credential from another CA — a client that enrolled
        // against this CA holds a certificate from this CA.
        if (!DnEquals(signingCert.IssuerDN.ToString(), caCert.SubjectDN.ToString()))
            return "Signing certificate was not issued by the CA this request addresses.";

        try
        {
            signingCert.Verify(caCert.GetPublicKey());
        }
        catch
        {
            return "Signing certificate signature does not verify against this CA.";
        }

        var signingCertSerial = CertificateUtil.FormatSerialNumber(signingCert.SerialNumber);
        var revokedCheck = await _db.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(signingCertSerial);
        if (revokedCheck != null && revokedCheck.Revoked)
            return "Signing certificate has been revoked.";

        // Verify the actual protected-part signature. Per RFC 4210 §5.1.3 the protected
        // bytes are the DER encoding of SEQUENCE { header, body }. We use BC's signer
        // utilities with the allow-listed algorithm OID.
        try
        {
            var sigAlgName = CertificateUtil.NormalizeSigAlgName(sigOid);
            var signer = SignerUtilities.GetSigner(sigAlgName);
            signer.Init(false, signingCert.GetPublicKey());

            var protectedPart = new DerSequence(header, body).GetDerEncoded();
            signer.BlockUpdate(protectedPart, 0, protectedPart.Length);

            var sigBytes = request.Protection.GetBytes();
            if (!signer.VerifySignature(sigBytes))
                return "Protected-part signature did not verify.";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CMP signature verification failed");
            return "Protected-part signature could not be verified.";
        }

        reqCtx.CallerPrincipal = $"cmp-sig:{signingCertSerial}";
        reqCtx.SignerSubjectDn = signingCert.SubjectDN.ToString();
        reqCtx.SignerSerialHex = signingCertSerial;

        // The names this signer may request are the names it holds. Captured here; enforced per
        // CertRequest in ProcessSingleCertRequestAsync, for ir, cr and kur alike. This replaces
        // a kur-only subject comparison that left ir and cr unbound, so any device with any
        // unrevoked certificate from this CA could sign a request for any name.
        try
        {
            reqCtx.SignerSans = ExtractSans(signingCert.CertificateStructure.TbsCertificate.Extensions, lenient: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CMP signing certificate SANs could not be parsed");
            return "Signing certificate SANs could not be parsed.";
        }

        return null;
    }

    /// <summary>
    /// Reads a SubjectAlternativeName extension into the <c>TYPE:value</c> strings the issuance
    /// pipeline and the name-restriction checks use.
    /// </summary>
    /// <param name="extensions">The extension block, or null.</param>
    /// <param name="lenient">
    /// When false, an entry type the builder cannot re-encode (otherName, dirName, registeredID)
    /// is an error, because accepting it into a request only produces a confusing failure at
    /// issuance. When true such entries are skipped, which is right for a signing certificate:
    /// this product issues UPN otherNames routinely, and a signer carrying one must still be able
    /// to sign.
    /// </param>
    private static List<string> ExtractSans(X509Extensions? extensions, bool lenient)
    {
        var sans = new List<string>();
        var sanExtension = extensions?.GetExtension(X509Extensions.SubjectAlternativeName);
        if (sanExtension == null)
            return sans;

        var generalNames = GeneralNames.GetInstance(sanExtension.GetParsedValue());
        foreach (var gn in generalNames.GetNames())
        {
            if (gn.TagNo == GeneralName.IPAddress && gn.Name is Asn1OctetString ipOctets)
            {
                sans.Add($"IP:{new System.Net.IPAddress(ipOctets.GetOctets())}");
                continue;
            }

            var prefix = gn.TagNo switch
            {
                GeneralName.DnsName => "DNS",
                GeneralName.Rfc822Name => "EMAIL",
                GeneralName.UniformResourceIdentifier => "URI",
                _ => null
            };
            if (prefix == null)
            {
                if (lenient)
                    continue;
                throw new InvalidOperationException(
                    $"Unsupported SAN type in CMP certTemplate (GeneralName tag {gn.TagNo}). " +
                    "Supported types: DNS, IP, URI, EMAIL.");
            }
            sans.Add($"{prefix}:{gn.Name}");
        }
        return sans;
    }

    private static string NormalizeForCompare(string dn) =>
        string.Join(",", dn.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim().ToUpperInvariant())
            .OrderBy(p => p));

    /// <summary>
    /// Compares two X.500 DN strings for equality with tolerance for whitespace and RDN-order
    /// differences. Tries exact case-insensitive equality first (cheap fast-path for the
    /// common case), then falls back to BouncyCastle's <see cref="X509Name"/> structural
    /// comparison via <c>Equivalent(other, inOrder: false)</c> which correctly honors RFC 4514
    /// escape sequences (<c>CN=Smith\, John</c> is one RDN with a comma in the value, not two
    /// fragments). The previous fallback used a naive comma-split that mis-parsed escaped
    /// commas and could let two distinct DNs collide. Returns false if either string fails to
    /// parse as an X.500 name — fail closed.
    /// </summary>
    /// <summary>
    /// Whether a CA whose subject is <paramref name="caSubjectDn"/> is permitted to revoke a
    /// certificate whose stored issuer DN is <paramref name="certIssuerDn"/>.
    /// </summary>
    /// <remarks>
    /// Fails closed on a missing or blank issuer: an unknown owner is not a matching owner. The
    /// CMP revocation path looks the target certificate up by serial across ALL certificates,
    /// so this is what stops one CA revoking another CA's certificate.
    /// </remarks>
    internal static bool IsRevocableByCa(string? certIssuerDn, string caSubjectDn) =>
        !string.IsNullOrWhiteSpace(certIssuerDn)
        && !string.IsNullOrWhiteSpace(caSubjectDn)
        && DnEquals(certIssuerDn, caSubjectDn);

    /// <summary>
    /// Decides whether the authenticated CMP peer may revoke <paramref name="certEntity"/>.
    /// Returns the denial reason for the log when it may not; the wire response stays generic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Signature-protected requests.</b> The peer is the subject of its signing certificate, so
    /// it may revoke that certificate itself and any other certificate carrying the same subject
    /// DN — which is what makes "revoke my old certificate after rekey" work. It may not reach a
    /// different subject.
    /// </para>
    /// <para>
    /// <b>PBMAC-protected requests.</b> The peer is a shared secret, whose scope is exactly the
    /// name restrictions recorded on its enrollment-token row. A credential with no restrictions
    /// has no scope to speak of, so it is refused rather than treated as unlimited: a bare shared
    /// secret must not be a CA-wide revocation key. Give the credential a
    /// <c>SubjectRestriction</c> covering the names it is meant to manage.
    /// </para>
    /// <para>RFC 4210 §5.3.9 leaves this policy to the CA; leaving it unstated meant "anyone".</para>
    /// </remarks>
    private static (bool Allowed, string Reason) AuthorizeRevocation(
        CertificateEntity certEntity, CmpRequestContext reqCtx)
    {
        if (reqCtx.ProtectionMode == CmpProtectionMode.Signature)
        {
            return SignerMayRevoke(
                reqCtx.SignerSerialHex, reqCtx.SignerSubjectDn,
                certEntity.SerialNumber, certEntity.SubjectDN);
        }

        if (reqCtx.ProtectionMode == CmpProtectionMode.PbMac)
        {
            var token = reqCtx.PbmToken;
            if (token == null)
                return (false, "no PBMAC credential recorded for this request");

            List<string> targetSans;
            try
            {
                targetSans = string.IsNullOrWhiteSpace(certEntity.SubjectAlternativeNamesJson)
                    ? []
                    : JsonSerializer.Deserialize<List<string>>(certEntity.SubjectAlternativeNamesJson) ?? [];
            }
            catch (JsonException)
            {
                // An unreadable SAN column cannot be shown to satisfy a restriction.
                return (false, "target SAN list could not be parsed");
            }

            return CredentialMayRevoke(
                token.SubjectRestriction, token.SANRestriction, certEntity.SubjectDN, targetSans);
        }

        return (false, "request carried no verified protection");
    }

    /// <summary>
    /// Whether the holder of a signature-protection certificate may revoke a given target.
    /// It may revoke that certificate itself, and any other certificate carrying the same subject
    /// DN — which is what makes "revoke my previous certificate after rekey" work — and nothing
    /// beyond that.
    /// </summary>
    internal static (bool Allowed, string Reason) SignerMayRevoke(
        string? signerSerialHex, string? signerSubjectDn, string targetSerial, string? targetSubjectDn)
    {
        if (!string.IsNullOrWhiteSpace(signerSerialHex)
            && string.Equals(
                CertificateUtil.NormalizeSerialForLookup(signerSerialHex),
                CertificateUtil.NormalizeSerialForLookup(targetSerial),
                StringComparison.OrdinalIgnoreCase))
        {
            return (true, string.Empty);
        }

        if (!string.IsNullOrWhiteSpace(signerSubjectDn)
            && !string.IsNullOrWhiteSpace(targetSubjectDn)
            && DnEquals(signerSubjectDn!, targetSubjectDn!))
        {
            return (true, string.Empty);
        }

        return (false, "signing certificate is neither the target nor shares its subject DN");
    }

    /// <summary>
    /// Whether a PBMAC shared-secret credential may revoke a given target. The credential's scope
    /// is exactly the name restrictions recorded on its enrollment-token row; a credential with no
    /// restrictions has no scope, and is refused rather than treated as unlimited.
    /// </summary>
    internal static (bool Allowed, string Reason) CredentialMayRevoke(
        string? subjectRestriction, string? sanRestriction,
        string? targetSubjectDn, IEnumerable<string> targetSans)
    {
        var hasScope = EnrollmentNameRestriction.ParsePatterns(subjectRestriction).Count > 0
            || EnrollmentNameRestriction.ParsePatterns(sanRestriction).Count > 0;
        if (!hasScope)
            return (false, "PBMAC credential carries no subject or SAN restriction to scope it");

        if (!EnrollmentNameRestriction.SubjectSatisfies(targetSubjectDn, subjectRestriction, out var subjectFailure))
            return (false, $"target subject outside credential scope: {subjectFailure}");

        if (!EnrollmentNameRestriction.SansSatisfy(targetSans, sanRestriction, out var sanFailure))
            return (false, $"target SANs outside credential scope: {sanFailure}");

        return (true, string.Empty);
    }

    internal static bool DnEquals(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;
        try
        {
            var nameA = new X509Name(a);
            var nameB = new X509Name(b);
            return nameA.Equivalent(nameB, inOrder: false);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Persists CMP transaction state and returns an error string when
    /// replay is detected. For ir/cr/kur, inserts a new row and relies on the unique
    /// (CaId, TransactionId) index to reject duplicates. For certConf, verifies that a
    /// matching row exists and was recent.
    /// </summary>
    private async Task<string?> PersistOrCheckTransactionAsync(
        PkiHeader header, int bodyType, Guid? caId, CmpRequestContext reqCtx)
    {
        if (header.TransactionID == null) return null;
        var txidBytes = header.TransactionID.GetOctets();
        var txidHex = Convert.ToHexString(txidBytes);
        // Reject (don't truncate) when the txid exceeds the persisted column width.
        // Truncating would silently collide two distinct transactionIDs that share a
        // 128-byte (256 hex char) prefix on the unique (CaId, TransactionId) index,
        // making the second one look like a replay.
        if (txidHex.Length > 256)
            return "CMP transactionId exceeds maximum length (128 octets) — rejected.";

        if (bodyType == TypeIr || bodyType == TypeCr || bodyType == TypeKur)
        {
            var existing = await _db.CmpTransactions
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.CaId == caId && t.TransactionId == txidHex);
            if (existing != null)
                return "CMP transactionId already processed — replay rejected.";

            var row = new CmpTransactionEntity
            {
                CaId = caId,
                TransactionId = txidHex,
                SenderNonce = header.SenderNonce != null ? Convert.ToHexString(header.SenderNonce.GetOctets()) : null,
                MessageTime = header.MessageTime?.ToDateTime(),
                Status = "Pending",
                PbmReferenceValue = reqCtx.PbmReferenceValue != null ? Convert.ToHexString(reqCtx.PbmReferenceValue) : null
            };
            _db.CmpTransactions.Add(row);
            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException ex) when (MySqlErrorUtil.IsUniqueViolation(ex))
            {
                // MySQL ER_DUP_ENTRY (1062) on the unique (CaId, TransactionId) index from a
                // concurrent insert race — the canonical replay signal. Other DbUpdateException
                // variants (transient connection drops, schema mismatches) bubble so the
                // operator sees a real error instead of a misleading "replay rejected".
                return "CMP transactionId already processed — replay rejected.";
            }
        }
        else if (bodyType == TypeCertConf)
        {
            var existing = await _db.CmpTransactions
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.CaId == caId && t.TransactionId == txidHex);
            if (existing == null)
                return "certConf does not match any prior ip/cp transaction.";

            // Atomic conditional update: only one concurrent certConf can flip Status from
            // anything-but-Confirmed to Confirmed. The second caller gets rows == 0 and we
            // reject so the audit trail reflects exactly one confirmation per txid.
            var rows = await _db.CmpTransactions
                .Where(t => t.CaId == caId && t.TransactionId == txidHex && t.Status != "Confirmed")
                .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.Status, "Confirmed"));
            if (rows == 0)
                return "CMP certConf already processed for this transactionId.";
        }
        return null;
    }

    private async Task<byte[]> HandleCertRequestAsync(
        PkiBody body,
        PkiHeader requestHeader,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        int responseType,
        ResolvedCaContext context,
        CmpRequestContext reqCtx)
    {
        // Parse CertReqMessages from the body
        var certReqMessages = CertReqMessages.GetInstance(body.Content);
        var reqMsgs = certReqMessages.ToCertReqMsgArray();

        if (reqMsgs.Length == 0)
        {
            return BuildErrorResponse(caCert, caKeyHandle, requestHeader, reqCtx, StatusRejection, FailBadRequest,
                "No certificate request messages in PKIBody.");
        }

        var responses = new List<CertResponse>();

        foreach (var reqMsg in reqMsgs)
        {
            var certReq = reqMsg.CertReq;
            var certReqId = certReq.CertReqID;

            try
            {
                // Validate Proof of Possession (RFC 4210 §5.2.1 / §5.2.8.2). reqCtx is
                // consulted so raVerified can be refused on unprotected messages or
                // messages authenticated as a non-RA peer (fail-closed; see
                // CmpRequestContext.IsAuthorizedRa).
                var (popOk, popError, popFailInfo) = ValidateProofOfPossession(reqMsg, certReq, reqCtx);
                if (!popOk)
                {
                    var popFail = new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String(popError ?? "Invalid or missing Proof of Possession")),
                        new PkiFailureInfo(popFailInfo));
                    responses.Add(new CertResponse(certReqId, popFail));
                    continue;
                }

                var certResponse = await ProcessSingleCertRequestAsync(certReq, caCert, context, reqCtx);
                responses.Add(certResponse);
            }
            catch (Exception ex)
            {
                // Scrub exception text from per-entry errors too.
                var correlationId = Guid.NewGuid().ToString("N")[..12];
                _logger.LogError(ex, "CMP cert request failure [{CorrelationId}]", correlationId);
                var failStatus = new PkiStatusInfo(
                    StatusRejection,
                    new PkiFreeText(new DerUtf8String($"Certificate issuance failed; contact administrator (ref {correlationId})")),
                    new PkiFailureInfo(FailSystemFailure));
                responses.Add(new CertResponse(certReqId, failStatus));
            }
        }

        // Build the CertRepMessage body
        // Include the CA cert so the client can build the chain
        var caCertBc = Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(
            Asn1Object.FromByteArray(caCert.GetEncoded()));
        var caPkiCert = new CmpCertificate(caCertBc);

        var certRepMessage = new CertRepMessage(
            [caPkiCert],
            responses.ToArray());

        var responseBody = new PkiBody(responseType, certRepMessage);
        return BuildPkiMessage(requestHeader, responseBody, caCert, caKeyHandle, reqCtx);
    }

    /// <summary>
    /// Processes a single CMP certificate request by extracting subject and SAN information from the
    /// cert template, creating a CSR entity, and issuing the certificate using the resolved cert and signing profiles.
    /// </summary>
    private async Task<CertResponse> ProcessSingleCertRequestAsync(
        CertRequest certReq,
        X509Certificate caCert,
        ResolvedCaContext context,
        CmpRequestContext reqCtx)
    {
        var certReqId = certReq.CertReqID;
        var certTemplate = certReq.CertTemplate;

        // Enrollment authorization check (CMP has no PKCS#10 CSR for challenge password).
        // When the request arrived with signature or PBMAC protection we already validated
        // the caller — pass isAuthenticated=true so CmpRequireSignature gates correctly.
        var alreadyAuthenticated = reqCtx.ProtectionMode != CmpProtectionMode.None;
        var (authAllowed, authError) = await _enrollmentAuth.ValidateAsync("CMP", reqCtx.CaLabel, null, null, alreadyAuthenticated);
        if (!authAllowed)
            throw new InvalidOperationException(authError ?? "Enrollment not authorized");

        // Extract subject from the template
        var subject = certTemplate.Subject?.ToString() ?? string.Empty;

        // Extract SANs from extensions if present, in the TYPE:value form the rest of the
        // pipeline speaks.
        var sans = ExtractSans(certTemplate.Extensions, lenient: false);

        // Determine key algorithm from the template's public key
        var publicKeyInfo = certTemplate.PublicKey;
        var keyAlgorithm = "RSA";
        var keySize = "2048";

        if (publicKeyInfo != null)
        {
            var algOid = publicKeyInfo.Algorithm.Algorithm.Id;
            (keyAlgorithm, keySize) = MapKeyAlgorithm(algOid, publicKeyInfo);
        }

        var signingProfileId = context.SigningProfileId;

        // Resolve cert profile: CMP doesn't support requester choice → protocol default → request profile default
        var (resolvedCertProfileId, certProfileError) = await _requestProfileValidation
            .ResolveCertProfileIdAsync(null, context.CertProfileId, context.RequestProfileId);
        if (resolvedCertProfileId == null)
            throw new InvalidOperationException(certProfileError ?? "No certificate profile available for CMP");
        var certProfileId = resolvedCertProfileId.Value;

        var signingProfile = await _db.SigningProfiles.FindAsync(signingProfileId)
            ?? throw new InvalidOperationException("Configured CMP signing profile not found.");
        var certProfile = await _db.CertProfiles.FindAsync(certProfileId)
            ?? throw new InvalidOperationException("Configured CMP certificate profile not found.");

        // CMP uses CertTemplate (not PKCS#10 CSR). Store the public key as a
        // base64-encoded SubjectPublicKeyInfo DER so the issuance pipeline can
        // extract it without needing a real CSR signature.
        var sanJson = JsonSerializer.Serialize(sans);

        // A PBMAC credential may only enroll the names it is scoped to.
        //
        // Enrollment tokens carry SubjectRestriction / SANRestriction, and every other consumer of
        // them — the public enrollment controller and the SCEP challenge path — enforces both. CMP
        // read the row only to verify the MAC and consume a use, so the restrictions were inert
        // here: a shared secret issued to enroll one device could name any subject and any SAN the
        // request profile happened to permit, up to and including the CA's own service names.
        if (reqCtx.PbmToken is { } pbmToken)
        {
            if (!EnrollmentNameRestriction.SubjectSatisfies(subject, pbmToken.SubjectRestriction, out var subjFailure))
                throw new InvalidOperationException($"Subject not permitted for this CMP credential: {subjFailure}");
            if (!EnrollmentNameRestriction.SansSatisfy(sans, pbmToken.SANRestriction, out var sanFailure))
                throw new InvalidOperationException($"SAN not permitted for this CMP credential: {sanFailure}");
        }

        // A signature-protected request may only name its signer. See CmpSignerNameBinding for
        // why this is the rule and how an RA gets wider scope.
        if (reqCtx.ProtectionMode == CmpProtectionMode.Signature)
        {
            var bindingError = CmpSignerNameBinding.Check(subject, sans, reqCtx.SignerSubjectDn, reqCtx.SignerSans, DnEquals);
            if (bindingError != null)
                throw new InvalidOperationException($"Request not permitted for this signing certificate: {bindingError}");
        }

        // Validate against request profile if one is configured for this protocol
        if (context.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await _requestProfileValidation
                .ValidateAsync(context.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
                throw new InvalidOperationException(error ?? "Request profile validation failed");
            if (modifiedSubject != null)
                subject = modifiedSubject;
        }
        var pubKeyDer = publicKeyInfo?.GetDerEncoded() ?? Array.Empty<byte>();
        var csrPlaceholder = $"-----CMP-PUBKEY-----\n{Convert.ToBase64String(pubKeyDer)}\n-----END CMP-PUBKEY-----";

        // Pick the appropriate signature algorithm based on key algorithm + curve (centralised
        // in KeyAlgorithmPolicy so ECDSA curves are paired with NIST-recommended hashes).
        var sigAlgorithm = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySize);

        var csrEntity = new CertRequestEntity
        {
            Subject = subject,
            SubjectAlternativeNames = sanJson,
            CSR = csrPlaceholder,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            SignatureAlgorithm = sigAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = "Pending",
            CertProfileId = certProfileId,
            CertProfile = certProfile,
            SigningProfileId = signingProfileId,
            SigningProfile = signingProfile
        };

        _db.CertificateRequests.Add(csrEntity);
        await _db.SaveChangesAsync();

        // Determine validity from template or defaults
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var notAfter = notBefore.Add(Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y"));

        if (certTemplate.Validity != null)
        {
            var optValidity = certTemplate.Validity;
            if (optValidity.NotBefore != null)
            {
                notBefore = CertificateValidityUtil.ClampRequestedNotBefore(
                    optValidity.NotBefore.ToDateTime(), out var notBeforeRaised);
                if (notBeforeRaised)
                    _logger.LogInformation("CMP requested a notBefore in the past; raised to the issuance floor.");
            }
            if (optValidity.NotAfter != null)
                notAfter = optValidity.NotAfter.ToDateTime();

            // Clamp to the signing profile's max validity
            var maxSpan = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
            if (notAfter > notBefore.Add(maxSpan))
                notAfter = notBefore.Add(maxSpan);
        }

        var issuanceResult = await _issuanceService.IssueCertificateAsync(
            csrEntity.Id, notBefore, notAfter);
        var certPem = issuanceResult.Pem;

        // Parse the issued certificate
        var issuedCert = CertificateUtil.ParseFromPem(certPem);
        var issuedCertStructure = Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(
            Asn1Object.FromByteArray(issuedCert.GetEncoded()));

        await _protocolAudit.LogCmpAsync("IR", csrEntity.Subject,
            CertificateUtil.FormatSerialNumber(issuedCert.SerialNumber),
            csrEntity.KeyAlgorithm, csrEntity.KeySize, reqCtx.CaLabel, null, null, reqCtx.SourceIp,
            callerPrincipal: reqCtx.CallerPrincipal);

        var status = new PkiStatusInfo(StatusGranted);
        var certifiedKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(new CmpCertificate(issuedCertStructure)));

        return new CertResponse(certReqId, status, certifiedKeyPair, null);
    }

    /// <summary>
    /// Handles CMP revocation requests (rr). Validates that each certificate exists,
    /// was issued by the current CA (issuer DN check), and is not already revoked
    /// before performing the revocation. Returns per-request PKIStatus codes.
    /// </summary>
    private async Task<byte[]> HandleRevocationRequestAsync(
        PkiBody body,
        PkiHeader requestHeader,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        CmpRequestContext reqCtx)
    {
        RevReqContent revReqContent;
        try
        {
            revReqContent = RevReqContent.GetInstance(body.Content);
        }
        catch (Exception)
        {
            return BuildErrorResponse(caCert, caKeyHandle, requestHeader, reqCtx, StatusRejection, FailBadDataFormat,
                "Invalid revocation request content.");
        }

        var revDetails = revReqContent.ToRevDetailsArray();

        if (revDetails.Length == 0)
        {
            return BuildErrorResponse(caCert, caKeyHandle, requestHeader, reqCtx, StatusRejection, FailBadRequest,
                "Empty revocation request — no RevDetails provided.");
        }

        var statusList = new List<PkiStatusInfo>();

        foreach (var detail in revDetails)
        {
            try
            {
                var certTemplate = detail.CertDetails;
                var serialNumber = certTemplate.SerialNumber?.Value;
                var issuerName = certTemplate.Issuer?.ToString();

                if (serialNumber == null)
                {
                    statusList.Add(new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String("Missing serial number in revocation request.")),
                        new PkiFailureInfo(FailBadRequest)));
                    continue;
                }

                // Look up the certificate by serial number
                var serialHex = CertificateUtil.FormatSerialNumber(serialNumber);
                var certEntity = await _db.Certificates
                    .ResolveBySerialOrNullAsync(serialHex);

                if (certEntity == null)
                {
                    statusList.Add(new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String($"Certificate with serial {serialHex} not found.")),
                        new PkiFailureInfo(FailBadRequest)));
                    continue;
                }

                // Validate the certificate belongs to the requesting entity: the issuer DN
                // in the revocation request must match the CA's subject DN. Use exact +
                // RDN-normalized comparison so a CA with subject "CN=Foo" cannot revoke
                // certs issued by a CA with subject "CN=FooBar" (the prior Contains-based
                // fallback was a substring match and matched any superstring).
                if (!string.IsNullOrEmpty(issuerName))
                {
                    var caSubject = caCert.SubjectDN.ToString();
                    if (!DnEquals(issuerName, caSubject))
                    {
                        statusList.Add(new PkiStatusInfo(
                            StatusRejection,
                            new PkiFreeText(new DerUtf8String(
                                $"Certificate issuer does not match this CA. Cannot revoke certificates issued by another CA.")),
                            new PkiFailureInfo(FailBadRequest)));
                        continue;
                    }
                }

                // The authoritative ownership check: the stored issuer DN must match this CA.
                // UNCONDITIONAL and fail-closed. It used to be wrapped in
                // `if (!string.IsNullOrEmpty(certEntity.Issuer))`, so a row with a blank issuer
                // skipped the check entirely and became revocable by ANY CMP-enabled CA. The
                // preceding check reads the issuer out of the request, which the caller
                // controls and can simply omit, so this is the only guard that can be trusted.
                if (!IsRevocableByCa(certEntity.Issuer, caCert.SubjectDN.ToString()))
                {
                    statusList.Add(new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String(
                            $"Certificate with serial {serialHex} was not issued by this CA.")),
                        new PkiFailureInfo(FailBadRequest)));
                    continue;
                }

                // Ownership by CA is not authorization. Everything above proves only that THIS CA
                // issued the target; it says nothing about whether THIS CALLER may revoke it.
                //
                // Without the check below, any peer able to authenticate a CMP message to a CA
                // could revoke every certificate that CA had ever issued, one serial at a time —
                // including the operator's mTLS admin credential and the Web TLS certificate
                // serving the admin UI, since those are ordinary rows with the CA's issuer DN. A
                // single device shared secret was a deployment-wide denial of service, and the
                // audit row recorded it as a well-formed revocation.
                var (revAllowed, revDenial) = AuthorizeRevocation(certEntity, reqCtx);
                if (!revAllowed)
                {
                    _logger.LogWarning(
                        "CMP revocation refused for serial {Serial} — {Reason} (caller {Caller}).",
                        serialHex, revDenial, reqCtx.CallerPrincipal ?? "unknown");
                    statusList.Add(new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String(
                            "Not authorized to revoke this certificate.")),
                        new PkiFailureInfo(FailNotAuthorized)));
                    continue;
                }

                // Check if the certificate is already revoked
                if (certEntity.Revoked)
                {
                    statusList.Add(new PkiStatusInfo(
                        StatusRejection,
                        new PkiFreeText(new DerUtf8String(
                            $"Certificate with serial {serialHex} is already revoked.")),
                        new PkiFailureInfo(FailBadRequest)));
                    continue;
                }

                // Extract revocation reason from CRL entry extensions if present.
                // The revocation service now takes a strongly-typed RevocationReason enum.
                var reason = ModularCA.Shared.Enums.RevocationReason.Unspecified;
                var crlEntryExts = detail.CrlEntryDetails;
                if (crlEntryExts != null)
                {
                    var reasonExt = crlEntryExts.GetExtension(X509Extensions.ReasonCode);
                    if (reasonExt != null)
                    {
                        var reasonEnum = DerEnumerated.GetInstance(reasonExt.GetParsedValue());
                        reason = MapCrlReason(reasonEnum.IntValueExact);
                    }
                }

                await _revocationService.RevokeCertificateAsync(
                    certEntity.CertificateId, null, reason);

                await _protocolAudit.LogCmpAsync("RR", certEntity.SubjectDN,
                    serialHex, null, null, reqCtx.CaLabel, null, reason.ToString(), reqCtx.SourceIp,
                    callerPrincipal: reqCtx.CallerPrincipal);

                statusList.Add(new PkiStatusInfo(StatusGranted));
            }
            catch (Exception ex)
            {
                // Keep exception text out of wire responses.
                var correlationId = Guid.NewGuid().ToString("N")[..12];
                _logger.LogError(ex, "CMP revocation failure [{CorrelationId}]", correlationId);
                statusList.Add(new PkiStatusInfo(
                    StatusRejection,
                    new PkiFreeText(new DerUtf8String($"Revocation failed; contact administrator (ref {correlationId})")),
                    new PkiFailureInfo(FailSystemFailure)));
            }
        }

        // RevRepContent has no public constructor in BC 2.x — build via ASN.1
        var statusSeq = new DerSequence(statusList.ToArray());
        var revRepContent = RevRepContent.GetInstance(new DerSequence((Asn1Encodable)statusSeq));
        var responseBody = new PkiBody(TypeRp, revRepContent);
        return BuildPkiMessage(requestHeader, responseBody, caCert, caKeyHandle, reqCtx);
    }

    /// <summary>
    /// Handles CMP CertConf (certificate confirmation, type 24) per RFC 4210 §5.3.18.
    /// Parses the CertStatus entries to verify the client accepted or rejected each issued
    /// certificate. If a certificate is rejected (non-zero PKIStatus), it is logged.
    /// Always responds with PKIConfirm (empty body, type 19) to prevent client retries.
    /// </summary>
    private byte[] HandleCertConfirm(
        PkiBody body,
        PkiHeader requestHeader,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        CmpRequestContext reqCtx)
    {
        // CertConfirm is an acknowledgement from the client that it received
        // and accepted (or rejected) the certificate.
        try
        {
            // Parse the CertConfirmContent — a SEQUENCE of CertStatus entries
            var certConfirmContent = CertConfirmContent.GetInstance(body.Content);
            var statusArray = certConfirmContent.ToCertStatusArray();

            foreach (var certStatus in statusArray)
            {
                var certReqId = certStatus.CertReqID?.IntValueExact ?? -1;
                var statusInfo = certStatus.StatusInfo;

                // If the client reports a non-granted status, log the rejection
                if (statusInfo != null)
                {
                    var status = statusInfo.Status?.IntValueExact ?? 0;
                    if (status != StatusGranted && status != StatusGrantedWithMods)
                    {
                        // Client rejected the certificate — log this event. Fire-and-forget
                        // (the response must not wait on audit DB), but a faulted audit must
                        // still surface in logs so we don't silently lose rejection records.
                        var statusText = statusInfo.StatusString?.ToString() ?? "rejected";
                        _ = _protocolAudit.LogCmpAsync("CertConf-Rejected", $"certReqId={certReqId}",
                            null, null, null, reqCtx.CaLabel, null, statusText, reqCtx.SourceIp,
                            callerPrincipal: reqCtx.CallerPrincipal)
                            .ContinueWith(t =>
                            {
                                if (t.Exception != null)
                                    _logger.LogWarning(t.Exception,
                                        "CMP CertConf-Rejected audit failed (certReqId={CertReqId}, status={Status})",
                                        certReqId, statusText);
                            }, TaskContinuationOptions.OnlyOnFaulted);
                    }
                }
            }
        }
        catch (Exception)
        {
            // Even if parsing fails, RFC 4210 says we must respond with PKIConfirm
            // to prevent the client from retrying indefinitely.
        }

        var responseBody = new PkiBody(TypePkiConf, DerNull.Instance);
        return BuildPkiMessage(requestHeader, responseBody, caCert, caKeyHandle, reqCtx);
    }

    private byte[] HandleGeneralMessage(
        PkiHeader requestHeader,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        CmpRequestContext reqCtx)
    {
        // General Message — respond with the CA certificates (GenRepContent).
        // The most common genm request is for CA certs (id-it-caCerts).
        var caCerts = _keystore.GetSigners();
        var certVector = new Asn1EncodableVector();

        foreach (var signer in caCerts)
        {
            var certStructure = Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(
                Asn1Object.FromByteArray(signer.PublicCertificate.GetEncoded()));
            certVector.Add(new CmpCertificate(certStructure));
        }

        // Build InfoTypeAndValue with id-it-caCerts (1.3.6.1.5.5.7.4.17)
        var caCertsOid = new DerObjectIdentifier("1.3.6.1.5.5.7.4.17");
        var caCertsSeq = new DerSequence(certVector);
        var infoTypeAndValue = new InfoTypeAndValue(caCertsOid, caCertsSeq);

        var genRepContent = new GenRepContent(infoTypeAndValue);
        var responseBody = new PkiBody(TypeGenp, genRepContent);
        return BuildPkiMessage(requestHeader, responseBody, caCert, caKeyHandle, reqCtx);
    }

    /// <summary>
    /// Builds a protected CMP response. When the inbound request used
    /// PBMAC, the response is also PBMAC-protected using the same derived key so clients
    /// that have not yet bootstrapped the CA's certificate can still validate.
    /// </summary>
    private byte[] BuildPkiMessage(
        PkiHeader requestHeader,
        PkiBody responseBody,
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        CmpRequestContext reqCtx)
    {
        var sender = new GeneralName(caCert.SubjectDN);
        var recipient = requestHeader.Sender;
        var transactionId = requestHeader.TransactionID;
        var senderNonce = requestHeader.SenderNonce;

        var responseNonce = new byte[16];
        new SecureRandom().NextBytes(responseNonce);

        // Mirror the inbound protection mode. PBMAC-in → PBMAC-out
        // with the same derived key so clients bootstrapping without the CA cert can
        // still validate. Signature-in / None-in → signature-out with the CA key.
        if (reqCtx.ProtectionMode == CmpProtectionMode.PbMac && reqCtx.PbmSecret != null)
        {
            return BuildPbmProtectedMessage(sender, recipient, responseBody, transactionId,
                senderNonce, responseNonce, reqCtx);
        }

        // Use BouncyCastle's ProtectedPkiMessageBuilder which correctly computes
        // the signature over ProtectedPart per RFC 4210 §5.1.3
        var builder = new ProtectedPkiMessageBuilder(sender, recipient);
        builder.SetBody(responseBody);

        if (transactionId != null)
            builder.SetTransactionId(transactionId.GetOctets());
        if (senderNonce != null)
            builder.SetRecipNonce(senderNonce.GetOctets());
        builder.SetSenderNonce(responseNonce);
        builder.SetMessageTime(DateTime.UtcNow);

        // Include the CA cert in extraCerts so the client can verify the signature
        builder.AddCmpCertificate(caCert);
        // With a delegated signer, the client needs the issuer as well to chain it to the trust
        // anchor it holds (RFC 4210 section 5.1.3.3 asks the sender to include what the recipient
        // needs to verify).
        if (reqCtx.SignerIssuerCert != null)
            builder.AddCmpCertificate(reqCtx.SignerIssuerCert);

        // Sign with the CA private key using the same algorithm as the CA cert
        var sigAlg = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey()));
        var sigFactory = new PrivateKeyHandleSignatureFactory(sigAlg, caKeyHandle);
        var protectedMsg = builder.Build(sigFactory);

        return protectedMsg.ToAsn1Message().GetDerEncoded();
    }

    /// <summary>
    /// Builds a PBMAC-protected response, deriving the response MAC key from the shared secret
    /// that authenticated the request.
    /// <para>
    /// The response carries a freshly generated salt, and RFC 4210 §5.1.3.1 defines the MAC key as
    /// <c>OWF^iterations(secret || salt)</c> — so the client will derive the response key from the
    /// secret it holds and the salt it reads out of this header. This method must do the same.
    /// </para>
    /// <para>
    /// It previously derived the response key from the <em>request's</em> derived key instead of
    /// from the secret, because the secret was not carried past verification. Its own comment
    /// claimed "clients that implement PBM verify correctly will accept this"; they cannot. The
    /// client computes <c>OWF^n(secret || salt')</c>, the responder computed
    /// <c>OWF^1024(OWF^n(secret || salt) || salt')</c>, and the two never agree — so every
    /// PBMAC-protected response failed verification at every conforming client, which is the
    /// bootstrap case PBMAC exists to serve. It also hardcoded SHA-1 and HMAC-SHA1 regardless of
    /// what the client selected; the client's own algorithms are echoed now.
    /// </para>
    /// </summary>
    internal static byte[] BuildPbmProtectedMessage(
        GeneralName sender, GeneralName recipient, PkiBody body,
        Asn1OctetString? transactionId, Asn1OctetString? requestNonce,
        byte[] responseNonce, CmpRequestContext reqCtx)
    {
        var secret = reqCtx.PbmSecret
            ?? throw new InvalidOperationException("PBMAC response requested without a verified shared secret.");
        var owfAlg = reqCtx.PbmOwf
            ?? new AlgorithmIdentifier(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, DerNull.Instance);
        var macAlg = reqCtx.PbmMac
            ?? new AlgorithmIdentifier(new DerObjectIdentifier("1.3.6.1.5.5.8.1.2"), DerNull.Instance);
        var iterCount = reqCtx.PbmIterationCount > 0 ? reqCtx.PbmIterationCount : 1024;

        var headerBuilder = new PkiHeaderBuilder(PkiHeader.CMP_2000, sender, recipient);
        headerBuilder.SetMessageTime(new DerGeneralizedTime(DateTime.UtcNow));
        if (transactionId != null) headerBuilder.SetTransactionID(transactionId);
        if (requestNonce != null) headerBuilder.SetRecipNonce(requestNonce);
        headerBuilder.SetSenderNonce(new DerOctetString(responseNonce));
        // Same senderKID as the request, so the client knows which credential validates this.
        if (reqCtx.PbmReferenceValue != null)
            headerBuilder.SetSenderKID(new DerOctetString(reqCtx.PbmReferenceValue));

        // Fresh salt: response protection stays independent of the request's.
        var salt = new byte[16];
        new SecureRandom().NextBytes(salt);
        var pbm = new PbmParameter(salt, owfAlg, iterCount, macAlg);
        var protectionAlg = new AlgorithmIdentifier(
            new DerObjectIdentifier("1.2.840.113533.7.66.13"), pbm);
        headerBuilder.SetProtectionAlg(protectionAlg);

        var header = headerBuilder.Build();

        var dk = DerivePbmKey(secret, salt, owfAlg, iterCount);
        try
        {
            var protectedPartBytes = new DerSequence(header, body).GetDerEncoded();
            var mac = MacUtilities.GetMac(macAlg.Algorithm);
            mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(dk));
            mac.BlockUpdate(protectedPartBytes, 0, protectedPartBytes.Length);
            var macBytes = new byte[mac.GetMacSize()];
            mac.DoFinal(macBytes, 0);

            var pkiMessage = new PkiMessage(header, body, new DerBitString(macBytes));
            return pkiMessage.GetDerEncoded();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(dk);
        }
    }

    /// <summary>
    /// RFC 4210 §5.1.3.1 password-based MAC key derivation:
    /// <c>K = OWF^iterations(secret || salt)</c>, where each iteration after the first hashes the
    /// previous digest. Shared by request verification and response generation so the two cannot
    /// drift apart — they did, and PBMAC responses were unverifiable as a result.
    /// </summary>
    internal static byte[] DerivePbmKey(byte[] secret, byte[] salt, AlgorithmIdentifier owf, int iterations)
    {
        var digest = DigestUtilities.GetDigest(owf.Algorithm);
        var baseKey = new byte[secret.Length + salt.Length];
        try
        {
            Array.Copy(secret, 0, baseKey, 0, secret.Length);
            Array.Copy(salt, 0, baseKey, secret.Length, salt.Length);

            var dk = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(baseKey, 0, baseKey.Length);
            digest.DoFinal(dk, 0);
            for (int i = 1; i < iterations; i++)
            {
                digest.Reset();
                digest.BlockUpdate(dk, 0, dk.Length);
                digest.DoFinal(dk, 0);
            }
            return dk;
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(baseKey);
        }
    }

    private byte[] BuildErrorResponse(
        X509Certificate caCert,
        IPrivateKeyHandle caKeyHandle,
        PkiHeader? requestHeader,
        CmpRequestContext reqCtx,
        int pkiStatus,
        int failInfo,
        string errorText)
    {
        var statusInfo = new PkiStatusInfo(
            pkiStatus,
            new PkiFreeText(new DerUtf8String(errorText)),
            new PkiFailureInfo(failInfo));

        var errorMsgContent = new ErrorMsgContent(statusInfo);
        var responseBody = new PkiBody(TypeError, errorMsgContent);

        if (requestHeader != null)
        {
            return BuildPkiMessage(requestHeader, responseBody, caCert, caKeyHandle, reqCtx);
        }

        // No request header available — build a minimal header
        var sender = new GeneralName(caCert.SubjectDN);
        var recipient = new GeneralName(new X509Name("CN=unknown"));

        var headerBuilder = new PkiHeaderBuilder(
            PkiHeader.CMP_2000,
            sender,
            recipient);
        headerBuilder.SetMessageTime(new DerGeneralizedTime(DateTime.UtcNow));

        var header = headerBuilder.Build();
        var pkiMessage = new PkiMessage(header, responseBody);
        return pkiMessage.GetDerEncoded();
    }

    // CAs already warned about signing CMP responses directly, so the warning is once per CA per
    // process rather than once per request. A CA can serve thousands of requests an hour.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> DirectSignerWarned = new();

    /// <summary>
    /// Resolves the certificate and private key that sign CMP responses for the addressed CA:
    /// the dedicated CMP signer when one is configured and usable, otherwise the CA itself.
    /// Returns the key handle directly (supports HSM-backed keys).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The CA certificate's key usage is <c>keyCertSign, cRLSign</c>; it does not carry
    /// <c>digitalSignature</c>, and OpenSSL refuses such a certificate as a CMP message signer
    /// ("no suitable sender cert"). Every signature-protected exchange therefore failed at the
    /// client while PBMAC exchanges, whose responses are MAC-protected, worked. A dedicated signer
    /// issued from the CA detail page carries the right bit and is rotated without touching the
    /// CA certificate. The CA-direct path is kept as the fallback so an unconfigured CA still
    /// answers PBMAC clients; it warns once per process so the gap is visible.
    /// </para>
    /// <para>
    /// The third element is the CA certificate when a delegated signer is in use, for
    /// <c>extraCerts</c>: a client that trusts only the CA needs the issuer alongside the signer
    /// to build the chain.
    /// </para>
    /// </remarks>
    private async Task<(X509Certificate cert, IPrivateKeyHandle keyHandle, X509Certificate? signerIssuer)?> ResolveSignerForCaAsync(ResolvedCaContext context)
    {
        if (context.Ca != null)
        {
            var certEntity = await _db.Certificates.FindAsync(context.Ca.CertificateId);
            if (certEntity != null)
            {
                var caCert = CertificateUtil.ParseFromPem(certEntity.Pem);

                if (context.Ca.CmpSigningCertificateId != null)
                {
                    var signerEntity = await _db.Certificates.AsNoTracking()
                        .FirstOrDefaultAsync(c => c.CertificateId == context.Ca.CmpSigningCertificateId && !c.Revoked);
                    if (signerEntity != null)
                    {
                        var signerCert = CertificateUtil.ParseFromPem(signerEntity.Pem);
                        var now = DateTime.UtcNow;
                        var signerKey = now >= signerCert.NotBefore && now <= signerCert.NotAfter
                            ? _keystore.GetPrivateKeyFor(signerCert)
                            : null;
                        if (signerKey != null)
                            return (signerCert, signerKey, caCert);

                        _logger.LogWarning(
                            "CMP signer {SignerId} for CA {CaLabel} is expired or its key is not registered; signing responses with the CA certificate instead.",
                            context.Ca.CmpSigningCertificateId, context.Ca.Label);
                    }
                    else
                    {
                        _logger.LogWarning(
                            "CMP signer {SignerId} for CA {CaLabel} is missing or revoked; signing responses with the CA certificate instead.",
                            context.Ca.CmpSigningCertificateId, context.Ca.Label);
                    }
                }
                else if (DirectSignerWarned.TryAdd(context.Ca.Id, 0))
                {
                    _logger.LogWarning(
                        "CA {CaLabel} has no CMP signing certificate. Signature-protected CMP responses will be signed with the CA certificate, " +
                        "which lacks digitalSignature and is rejected by OpenSSL-based clients. Issue one from the CA detail page.",
                        context.Ca.Label);
                }

                var keyHandle = _keystore.GetPrivateKeyFor(caCert);
                if (keyHandle != null)
                    return (caCert, keyHandle, null);
            }
        }

        // Fallback: pick first available signer
        foreach (var signer in _keystore.GetSigners())
        {
            var cert = signer.PublicCertificate;
            var keyHandle = _keystore.GetPrivateKeyFor(cert);
            if (keyHandle != null)
                return (cert, keyHandle, null);
        }
        return null;
    }

    private (string algorithm, string size) MapKeyAlgorithm(string algOid, SubjectPublicKeyInfo publicKeyInfo)
    {
        return algOid switch
        {
            "1.2.840.113549.1.1.1" => ("RSA", EstimateRsaKeySize(publicKeyInfo)),
            "1.2.840.10045.2.1" => ("ECDSA", EstimateEcKeySize(publicKeyInfo)),
            "1.3.101.112" => ("Ed25519", "256"),
            "1.3.101.113" => ("Ed448", "456"),
            _ => throw new InvalidOperationException($"Unsupported key algorithm OID '{algOid}' in CMP request")
        };
    }

    /// <summary>
    /// Extracts the RSA modulus bit-length from a <see cref="SubjectPublicKeyInfo"/>.
    /// Previously a parse failure was swallowed and the method
    /// defaulted to "2048", which let sub-2048-bit keys slip past key-strength policy.
    /// Now throws <see cref="InvalidOperationException"/> on parse failure so the caller
    /// rejects the enrollment rather than silently accepting a weak key.
    /// </summary>
    private string EstimateRsaKeySize(SubjectPublicKeyInfo publicKeyInfo)
    {
        try
        {
            var keyParams = PublicKeyFactory.CreateKey(publicKeyInfo);
            if (keyParams is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
                return rsa.Modulus.BitLength.ToString();
            throw new InvalidOperationException(
                $"CMP public key parsed as non-RSA type '{keyParams?.GetType().Name ?? "null"}' under RSA OID.");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            _logger.LogWarning(ex,
                "CMP EstimateRsaKeySize failed to parse SubjectPublicKeyInfo; rejecting request to fail closed on key-size policy.");
            throw new InvalidOperationException(
                "Unable to determine RSA key size from CMP request; rejecting to enforce key-strength policy.", ex);
        }
    }

    /// <summary>
    /// Extracts the named EC curve from a <see cref="SubjectPublicKeyInfo"/>.
    /// Previously a parse failure was swallowed and the method
    /// defaulted to "P-256", which could allow non-compliant curves to bypass policy.
    /// Now throws <see cref="InvalidOperationException"/> on parse failure so the caller
    /// rejects the enrollment rather than silently accepting an unknown curve.
    /// </summary>
    private string EstimateEcKeySize(SubjectPublicKeyInfo publicKeyInfo)
    {
        try
        {
            var algParams = publicKeyInfo.Algorithm.Parameters;
            if (algParams is DerObjectIdentifier oid)
            {
                return oid.Id switch
                {
                    "1.2.840.10045.3.1.7" => "P-256",
                    "1.3.132.0.34" => "P-384",
                    "1.3.132.0.35" => "P-521",
                    _ => throw new InvalidOperationException(
                        $"Unsupported EC curve OID '{oid.Id}' in CMP request")
                };
            }
            throw new InvalidOperationException(
                "EC SubjectPublicKeyInfo missing named-curve OID parameters; rejecting CMP request.");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            _logger.LogWarning(ex,
                "CMP EstimateEcKeySize failed to parse SubjectPublicKeyInfo; rejecting request to fail closed on curve policy.");
            throw new InvalidOperationException(
                "Unable to determine EC curve from CMP request; rejecting to enforce curve policy.", ex);
        }
    }

    private static ModularCA.Shared.Enums.RevocationReason MapCrlReason(int reason)
    {
        return reason switch
        {
            0 => ModularCA.Shared.Enums.RevocationReason.Unspecified,
            1 => ModularCA.Shared.Enums.RevocationReason.KeyCompromise,
            2 => ModularCA.Shared.Enums.RevocationReason.CACompromise,
            3 => ModularCA.Shared.Enums.RevocationReason.AffiliationChanged,
            4 => ModularCA.Shared.Enums.RevocationReason.Superseded,
            5 => ModularCA.Shared.Enums.RevocationReason.CessationOfOperation,
            6 => ModularCA.Shared.Enums.RevocationReason.CertificateHold,
            9 => ModularCA.Shared.Enums.RevocationReason.PrivilegeWithdrawn,
            10 => ModularCA.Shared.Enums.RevocationReason.AaCompromise,
            _ => ModularCA.Shared.Enums.RevocationReason.Unspecified
        };
    }

    /// <summary>
    /// Validates Proof of Possession per RFC 4210 §5.2.1 / §5.2.8.2. POP types:
    /// raVerified(0), signature(1), keyEncipherment(2), keyAgreement(3).
    /// Encryption-only POP (keyEncipherment / keyAgreement) returns a clear error
    /// string instead of a silent reject — full challenge/response POP is deferred.
    /// Security fix (RFC 4210 §5.2.8.2): <c>raVerified</c> is now only accepted when
    /// the surrounding CMP message was authenticated AND the authenticated principal is
    /// explicitly flagged as an authorized RA on the request context. Prior behavior
    /// unconditionally trusted <c>raVerified</c>, letting an attacker with access to an
    /// unprotected-IR-accepting endpoint skip POP entirely and obtain a certificate for
    /// a public key they did not control. Caller receives a
    /// <see cref="FailBadPop"/> PKIFailureInfo so the wire-level failure matches the
    /// semantic reason (bad proof-of-possession) rather than a generic bad-request.
    /// </summary>
    /// <returns>
    /// Tuple of (Ok, Error, PkiFailureInfo). <c>PkiFailureInfo</c> is the RFC 4210
    /// §5.2.3 bit to set when <c>Ok</c> is <c>false</c>. Defaults to <see cref="FailBadRequest"/>
    /// for legacy parity; POP-specific failures emit <see cref="FailBadPop"/>.
    /// </returns>
    private static (bool Ok, string? Error, int PkiFailureInfo) ValidateProofOfPossession(
        CertReqMsg reqMsg, CertRequest certReq, CmpRequestContext reqCtx)
    {
        var popo = reqMsg.Pop;

        if (popo == null)
            return (false, "Missing proof-of-possession (POP) structure.", FailBadPop);

        var popType = popo.Type;

        switch (popType)
        {
            case ProofOfPossession.TYPE_RA_VERIFIED:
                // RFC 4210 §5.2.8.2: raVerified is an RA vouching for POP on behalf of
                // the end-entity. Accepting it on an unprotected message lets anyone
                // bypass POP entirely. Require (a) the message itself was authenticated
                // and (b) the authenticated principal is explicitly flagged as an RA.
                if (reqCtx.ProtectionMode == CmpProtectionMode.None)
                {
                    return (false,
                        "raVerified proof-of-possession requires an authenticated CMP message.",
                        FailBadPop);
                }
                if (!reqCtx.IsAuthorizedRa)
                {
                    // No RA-authorization mechanism is wired up yet (no thumbprint
                    // allowlist, no RA group membership check). Fail closed rather than
                    // letting any signed/PBMAC peer assert raVerified for arbitrary keys.
                    return (false,
                        "raVerified proof-of-possession is only accepted from an authorized RA principal.",
                        FailBadPop);
                }
                return (true, null, 0);

            case ProofOfPossession.TYPE_SIGNING_KEY:
                try
                {
                    var popSigning = PopoSigningKey.GetInstance(popo.Object);
                    var algId = popSigning.AlgorithmIdentifier;
                    var signature = popSigning.Signature.GetBytes();

                    var certReqDer = certReq.GetDerEncoded();

                    var certTemplate = certReq.CertTemplate;
                    var pubKeyInfo = certTemplate.PublicKey;
                    if (pubKeyInfo == null)
                        return (false, "CertTemplate has no public key for POP verification.", FailBadPop);

                    var pubKey = PublicKeyFactory.CreateKey(pubKeyInfo);
                    var sigAlgName = CertificateUtil.NormalizeSigAlgName(algId.Algorithm.Id);

                    var signer = SignerUtilities.GetSigner(sigAlgName);
                    signer.Init(false, pubKey);
                    signer.BlockUpdate(certReqDer, 0, certReqDer.Length);
                    return signer.VerifySignature(signature)
                        ? (true, null, 0)
                        : (false, "POP signature verification failed.", FailBadPop);
                }
                catch
                {
                    return (false, "POP signature could not be verified.", FailBadPop);
                }

            case ProofOfPossession.TYPE_KEY_ENCIPHERMENT:
            case ProofOfPossession.TYPE_KEY_AGREEMENT:
                // Deferred — explicit error instead of silent reject.
                return (false, "encryption-only CMP enrollment is not yet supported; use key-with-signing-capability for now", FailBadPop);

            default:
                return (false, $"Unsupported POP type: {popType}", FailBadPop);
        }
    }
}
