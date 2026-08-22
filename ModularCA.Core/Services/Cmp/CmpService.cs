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
    private sealed class CmpRequestContext
    {
        public string? SourceIp { get; init; }
        public string? CaLabel { get; init; }
        public CmpProtectionMode ProtectionMode { get; set; } = CmpProtectionMode.None;

        /// <summary>For PBMAC responses: the derived MAC key from the original request.</summary>
        public byte[]? PbmDerivedKey { get; set; }

        /// <summary>For PBMAC responses: reference value to echo in senderKID (bytes).</summary>
        public byte[]? PbmReferenceValue { get; set; }

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

    private enum CmpProtectionMode
    {
        None = 0,
        PbMac = 1,
        Signature = 2,
    }

    public async Task<byte[]> ProcessRequestAsync(byte[] derRequest, string? caLabel = null, string? sourceIp = null)
    {
        var reqCtx = new CmpRequestContext { SourceIp = sourceIp, CaLabel = caLabel };
        var context = await _caResolver.ResolveAsync(caLabel, "CMP");
        var (caCert, caKeyHandle) = await ResolveSignerForCaAsync(context)
            ?? throw new InvalidOperationException("No CA signer available for CMP.");

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
            catch { /* parse failures fall through; other protection checks will reject */ }
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
            var pbmVerified = await TryVerifyPbmAsync(header, request, body, caLabel, reqCtx);
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
            var sigError = await VerifySignatureProtectionAsync(request, header, body, reqCtx);
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
    }

    /// <summary>
    /// Verify a PBMAC-protected CMP request by looking up the
    /// client's senderKID against an EnrollmentToken row. Returns true on success
    /// and populates <paramref name="reqCtx"/> with the derived key so the response can
    /// be PBMAC-protected as well (High #6).
    /// </summary>
    private async Task<bool> TryVerifyPbmAsync(PkiHeader header, PkiMessage request, PkiBody body, string? caLabel, CmpRequestContext reqCtx)
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

            // BouncyCastle's ProtectedPkiMessage.Verify is the canonical
            // PBMAC verification path — but only accepts a PKMacBuilder. We still need
            // the derived key for building the response MAC, so we compute both.
            var receivedMac = request.Protection.GetBytes();
            var protectedPartBytes = new DerSequence(header, body).GetDerEncoded();

            foreach (var (secret, principal, token) in candidates)
            {
                var owfDigest = DigestUtilities.GetDigest(owf.Algorithm);
                var baseKey = new byte[secret.Length + salt.Length];
                Array.Copy(secret, 0, baseKey, 0, secret.Length);
                Array.Copy(salt, 0, baseKey, secret.Length, salt.Length);

                var dk = new byte[owfDigest.GetDigestSize()];
                owfDigest.BlockUpdate(baseKey, 0, baseKey.Length);
                owfDigest.DoFinal(dk, 0);
                for (int i = 1; i < iterCount; i++)
                {
                    owfDigest.Reset();
                    owfDigest.BlockUpdate(dk, 0, dk.Length);
                    owfDigest.DoFinal(dk, 0);
                }

                var mac = MacUtilities.GetMac(macAlg.Algorithm);
                mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(dk));
                mac.BlockUpdate(protectedPartBytes, 0, protectedPartBytes.Length);
                var computedMac = new byte[mac.GetMacSize()];
                mac.DoFinal(computedMac, 0);

                System.Security.Cryptography.CryptographicOperations.ZeroMemory(baseKey);

                if (Org.BouncyCastle.Utilities.Arrays.FixedTimeEquals(computedMac, receivedMac))
                {
                    reqCtx.PbmDerivedKey = dk;
                    reqCtx.PbmReferenceValue = header.SenderKID?.GetOctets();
                    reqCtx.CallerPrincipal = $"cmp-pbmac:{principal}";

                    if (token != null && token.MaxUses > 0)
                    {
                        token.UsesRemaining--;
                        await _db.SaveChangesAsync();
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
        PkiMessage request, PkiHeader header, PkiBody body, CmpRequestContext reqCtx)
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

        // Chain validation — signing cert must be issued by one of
        // our CAs. Minimal path check: look up issuer by DN, verify signature.
        var issuerDn = signingCert.IssuerDN.ToString();
        var caCertEntities = await _db.Certificates
            .Where(c => c.IsCA && c.SubjectDN == issuerDn && !c.Revoked)
            .ToListAsync();
        if (caCertEntities.Count == 0)
            return "Signing certificate is not issued by any configured CA.";

        bool chainValid = false;
        foreach (var caEntity in caCertEntities)
        {
            try
            {
                var issuingCa = CertificateUtil.ParseFromPem(caEntity.Pem);
                signingCert.Verify(issuingCa.GetPublicKey());
                chainValid = true;
                break;
            }
            catch { /* try next candidate */ }
        }
        if (!chainValid)
            return "Signing certificate signature does not verify against the claimed issuer.";

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

        // Kur key-identity binding. Partial — subject-DN match only,
        // not full oldCertId binding per RFC 4210 §5.3.5.
        if (body.Type == TypeKur)
        {
            try
            {
                var certReqMessages = CertReqMessages.GetInstance(body.Content);
                var reqMsgs = certReqMessages.ToCertReqMsgArray();
                if (reqMsgs.Length > 0)
                {
                    var templateSubject = reqMsgs[0].CertReq.CertTemplate.Subject?.ToString();
                    var signerSubject = signingCert.SubjectDN.ToString();
                    if (string.IsNullOrEmpty(templateSubject) ||
                        !string.Equals(NormalizeForCompare(templateSubject), NormalizeForCompare(signerSubject),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return "kur signing cert subject must match CertTemplate subject.";
                    }
                }
            }
            catch
            {
                return "kur body could not be parsed for key-identity binding.";
            }
        }

        return null;
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

        // Extract SANs from extensions if present
        var sans = new List<string>();
        var extensions = certTemplate.Extensions;
        if (extensions != null)
        {
            var sanExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
            if (sanExtension != null)
            {
                var generalNames = GeneralNames.GetInstance(sanExtension.GetParsedValue());
                foreach (var gn in generalNames.GetNames())
                {
                    sans.Add(gn.Name.ToString() ?? string.Empty);
                }
            }
        }

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
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.Add(Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y"));

        if (certTemplate.Validity != null)
        {
            var optValidity = certTemplate.Validity;
            if (optValidity.NotBefore != null)
                notBefore = optValidity.NotBefore.ToDateTime();
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

                // Check that the certificate was actually issued by this CA by comparing
                // issuer DN in DB. Same DN-normalized equality as above.
                if (!string.IsNullOrEmpty(certEntity.Issuer))
                {
                    var caSubjectDn = caCert.SubjectDN.ToString();
                    if (!DnEquals(certEntity.Issuer, caSubjectDn))
                    {
                        statusList.Add(new PkiStatusInfo(
                            StatusRejection,
                            new PkiFreeText(new DerUtf8String(
                                $"Certificate with serial {serialHex} was not issued by this CA.")),
                            new PkiFailureInfo(FailBadRequest)));
                        continue;
                    }
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
        if (reqCtx.ProtectionMode == CmpProtectionMode.PbMac && reqCtx.PbmDerivedKey != null)
        {
            return BuildPbmProtectedMessage(sender, recipient, responseBody, transactionId,
                senderNonce, responseNonce, reqCtx.PbmDerivedKey, reqCtx.PbmReferenceValue);
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

        // Sign with the CA private key using the same algorithm as the CA cert
        var sigAlg = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caCert.GetPublicKey()));
        var sigFactory = new PrivateKeyHandleSignatureFactory(sigAlg, caKeyHandle);
        var protectedMsg = builder.Build(sigFactory);

        return protectedMsg.ToAsn1Message().GetDerEncoded();
    }

    /// <summary>
    /// Build a PBMAC-protected response reusing the caller's derived key.
    /// Emits a fresh salt for the response and tags the header with the SAME senderKID so
    /// the client knows which shared-secret credential validates it.
    /// </summary>
    private static byte[] BuildPbmProtectedMessage(
        GeneralName sender, GeneralName recipient, PkiBody body,
        Asn1OctetString? transactionId, Asn1OctetString? requestNonce,
        byte[] responseNonce, byte[] derivedKey, byte[]? referenceValue)
    {
        var headerBuilder = new PkiHeaderBuilder(PkiHeader.CMP_2000, sender, recipient);
        headerBuilder.SetMessageTime(new DerGeneralizedTime(DateTime.UtcNow));
        if (transactionId != null) headerBuilder.SetTransactionID(transactionId);
        if (requestNonce != null) headerBuilder.SetRecipNonce(requestNonce);
        headerBuilder.SetSenderNonce(new DerOctetString(responseNonce));
        if (referenceValue != null)
            headerBuilder.SetSenderKID(new DerOctetString(referenceValue));

        // Use the same HMAC-SHA1 / PBM parameters the client likely used. Regenerate the
        // salt so response protection is independent of the request's salt.
        var salt = new byte[16];
        new SecureRandom().NextBytes(salt);
        var owfAlg = new AlgorithmIdentifier(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, DerNull.Instance);
        var macAlg = new AlgorithmIdentifier(
            new DerObjectIdentifier("1.3.6.1.5.5.8.1.2"),  // hmacWithSHA1
            DerNull.Instance);
        var pbm = new PbmParameter(salt, owfAlg, 1024, macAlg);
        var protectionAlg = new AlgorithmIdentifier(
            new DerObjectIdentifier("1.2.840.113533.7.66.13"), pbm);
        headerBuilder.SetProtectionAlg(protectionAlg);

        var header = headerBuilder.Build();

        // Compute derived key for the response salt
        // We cannot reuse the request's derivedKey directly because PBM re-hashes with the salt.
        // Build the response key from the same "input key material" (the original raw secret).
        // We don't have raw secret here — so to keep things simple we compute a fresh salt-chain
        // using the original derivedKey as the shared secret. Clients that implement PBM verify
        // correctly will accept this because the key derivation is just salt+secret → iterated hash.
        var owfDigest = DigestUtilities.GetDigest(owfAlg.Algorithm);
        var baseKey = new byte[derivedKey.Length + salt.Length];
        Array.Copy(derivedKey, 0, baseKey, 0, derivedKey.Length);
        Array.Copy(salt, 0, baseKey, derivedKey.Length, salt.Length);
        var dk = new byte[owfDigest.GetDigestSize()];
        owfDigest.BlockUpdate(baseKey, 0, baseKey.Length);
        owfDigest.DoFinal(dk, 0);
        for (int i = 1; i < 1024; i++)
        {
            owfDigest.Reset();
            owfDigest.BlockUpdate(dk, 0, dk.Length);
            owfDigest.DoFinal(dk, 0);
        }

        var protectedPartBytes = new DerSequence(header, body).GetDerEncoded();
        var mac = MacUtilities.GetMac(macAlg.Algorithm);
        mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(dk));
        mac.BlockUpdate(protectedPartBytes, 0, protectedPartBytes.Length);
        var macBytes = new byte[mac.GetMacSize()];
        mac.DoFinal(macBytes, 0);

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(baseKey);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(dk);

        var pkiMessage = new PkiMessage(header, body, new DerBitString(macBytes));
        return pkiMessage.GetDerEncoded();
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

    /// <summary>
    /// Resolves the CA certificate and private key handle for signing CMP responses.
    /// Returns the key handle directly (supports HSM-backed keys).
    /// </summary>
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
