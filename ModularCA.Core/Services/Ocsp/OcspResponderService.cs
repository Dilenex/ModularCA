using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace ModularCA.Core.Services.Ocsp;

/// <summary>
/// Processes OCSP requests and returns signed OCSP responses indicating certificate revocation status.
/// Enforces per-item policies — delegated-responder-only signing, validity
/// and revocation checks on the signing chain, explicit thisUpdate/nextUpdate, extended-revoked
/// for serials the CA never issued, issuer-scoped cert lookup, nonce length bounds, signed-request
/// verification, hash-algorithm allowlist, and CA-label route binding.
/// </summary>
public class OcspResponderService : IOcspService
{
    // RFC 6960 §4.2.2.2.1 / RFC 2560: id-pkix-ocsp-nocheck
    private static readonly DerObjectIdentifier IdPkixOcspNoCheck = new("1.3.6.1.5.5.7.48.1.5");
    // RFC 6960 §4.4.8: id-pkix-ocsp-extended-revoke
    private static readonly DerObjectIdentifier IdPkixOcspExtendedRevoke = new("1.3.6.1.5.5.7.48.1.9");
    // RFC 6960 §4.4.7: id-pkix-ocsp-nonce (in case constants library drifts)
    private static readonly DerObjectIdentifier IdPkixOcspNonce = OcspObjectIdentifiers.PkixOcspNonce;
    // RFC 5280 §4.2.1.12: id-kp-OCSPSigning
    private static readonly DerObjectIdentifier IdKpOcspSigning = new("1.3.6.1.5.5.7.3.9");

    // Hash-algorithm allowlist for CertID.hashAlgorithm.
    // SHA-1 is still RFC-sanctioned for OCSP per §4.3; block MD5 and
    // everything more obscure.
    private static readonly HashSet<string> AllowedCertIdHashAlgOids = new(StringComparer.Ordinal)
    {
        "1.3.14.3.2.26",                                       // SHA-1
        NistObjectIdentifiers.IdSha256.Id,                     // SHA-256
        NistObjectIdentifiers.IdSha384.Id,                     // SHA-384
        NistObjectIdentifiers.IdSha512.Id,                     // SHA-512
    };

    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly ILogger<OcspResponderService> _logger;
    private readonly ISecurityPolicyService _securityPolicy;

    /// <summary>
    /// Signs every response. The responder holds a <see cref="KeyRef"/> to the delegated
    /// responder certificate, or to the CA certificate when CA-direct signing is allowed, and a
    /// context naming the CA; the key stays with the signer.
    /// </summary>
    private readonly ISigningService _signer;

    /// <summary>The caller identity the responder signs under; the signer audits it with every decision.</summary>
    private const string SignerCaller = nameof(OcspResponderService);

    /// <summary>
    /// Constructs the responder. Takes <see cref="ISecurityPolicyService"/> so
    /// the per-response TTL defaults, CA-direct-signing gate and signed-request policy
    /// come from the DB-backed <see cref="SecurityPolicyEntity"/>, and the signer that holds
    /// the responder and CA keys.
    /// </summary>
    public OcspResponderService(
        ModularCADbContext db,
        IKeystoreCertificates keystore,
        ILogger<OcspResponderService> logger,
        ISecurityPolicyService securityPolicy,
        ISigningService signer)
    {
        _db = db;
        _keystore = keystore;
        _logger = logger;
        _securityPolicy = securityPolicy;
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    /// <summary>The context every OCSP signature for <paramref name="caEntity"/> is asked under.</summary>
    private static SigningContext ContextFor(CertificateAuthorityEntity caEntity)
        => SigningContext.ForCa(SignerCaller, SigningPurpose.Ocsp, caEntity.Id, caEntity.TenantId);

    /// <summary>
    /// Whether the signer holds the key <paramref name="key"/> among the keys of
    /// <paramref name="caEntity"/>. Asked while choosing the responder so a missing key is
    /// reported as it was when the keystore was consulted directly (unauthorized, or the next
    /// candidate), rather than surfacing as a failure at signing time.
    /// </summary>
    private async Task<bool> SignerHoldsKeyAsync(CertificateAuthorityEntity caEntity, KeyRef key, CancellationToken ct)
    {
        var keys = await _signer.ListKeysAsync(ContextFor(caEntity), ct);
        return keys.Any(k => k.Key.CertificateId == key.CertificateId);
    }

    /// <summary>
    /// Processes a DER-encoded OCSPRequest and returns the signed DER response.
    /// Bails out with <c>malformedRequest</c> / <c>unauthorized</c>
    /// / <c>internalError</c> before ever touching the keystore on all known
    /// abuse paths (oversized nonce, duplicate extensions, unknown hash alg,
    /// etc.) so DoS amplification cannot force an HSM operation.
    /// </summary>
    public async Task<byte[]> ProcessOcspRequestAsync(
        byte[] derRequest,
        string? caLabel,
        OcspProcessingResult result,
        CancellationToken cancellationToken = default)
    {
        result.Status = "unknown";
        result.CaLabel = caLabel ?? string.Empty;
        result.CacheMaxAgeSeconds = 0;

        // Single load of the runtime security policy — cache in the service for
        // the rest of the request scope.
        var ocspPolicy = await _securityPolicy.GetAsync();

        OcspReq ocspReq;
        try
        {
            ocspReq = new OcspReq(derRequest);
        }
        catch (Exception)
        {
            return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);
        }

        var requests = ocspReq.GetRequestList();
        if (requests.Length == 0)
            return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);

        // Reject oversized request lists before
        // any DB / keystore work. Legitimate OCSP clients query one cert at a
        // time; a request carrying dozens of single-requests is either
        // malformed or an amplification attempt.
        if (requests.Length > Math.Max(1, ocspPolicy.MaxSingleRequestsPerRequest))
        {
            _logger.LogWarning("OCSP: request carries {Count} single-requests, cap is {Cap}",
                requests.Length, ocspPolicy.MaxSingleRequestsPerRequest);
            return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);
        }

        // Reject duplicate or oversized nonce extensions.
        if (!TryValidateNonce(ocspReq, out var nonceOctets, out var nonceExtValue, out var nonceReason))
        {
            _logger.LogWarning("OCSP: nonce validation failed ({Reason})", nonceReason);
            return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);
        }

        // Allowlist hash algorithms up front.
        foreach (var req in requests)
        {
            var hashAlgOid = req.GetCertID().HashAlgOid;
            if (!AllowedCertIdHashAlgOids.Contains(hashAlgOid))
            {
                _logger.LogWarning("OCSP: request uses disallowed hash OID {Oid}", hashAlgOid);
                return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);
            }
        }

        // Signed-request policy. When the request has an
        // attached signer, verify it; when the policy demands signed requests,
        // reject unsigned ones with SigRequired.
        if (ocspReq.IsSigned)
        {
            X509Certificate? signerCert = null;
            try
            {
                var signerCerts = ocspReq.GetCerts();
                signerCert = signerCerts?.Length > 0 ? signerCerts[0] : null;
            }
            catch
            {
                return BuildStatusResponse(OcspRespStatus.MalformedRequest, result);
            }
            if (signerCert == null)
                return BuildStatusResponse(OcspRespStatus.Unauthorized, result);

            bool verified;
            try
            {
                verified = ocspReq.Verify(signerCert.GetPublicKey());
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "OCSP: signed-request signature verification threw");
                return BuildStatusResponse(OcspRespStatus.Unauthorized, result);
            }
            if (!verified)
            {
                _logger.LogWarning("OCSP: signed request failed signature verification");
                return BuildStatusResponse(OcspRespStatus.Unauthorized, result);
            }
        }
        else if (ocspPolicy.RequireSignedRequests)
        {
            _logger.LogInformation("OCSP: unsigned request rejected by policy (RequireSignedRequests=true)");
            return BuildStatusResponse(OcspRespStatus.SigRequired, result);
        }

        // Use the first request's issuer info to locate the signing CA.
        var firstReqId = requests[0].GetCertID();
        var resolved = await ResolveSigningCaAsync(firstReqId, caLabel, cancellationToken);

        if (resolved.Status == ResolveOutcome.NotFound)
            return BuildStatusResponse(OcspRespStatus.Unauthorized, result);
        if (resolved.Status == ResolveOutcome.LabelMismatch)
            return BuildStatusResponse(OcspRespStatus.Unauthorized, result);
        if (resolved.Status == ResolveOutcome.CaRevoked || resolved.Status == ResolveOutcome.CaExpired || resolved.Status == ResolveOutcome.CaDisabled)
            return BuildStatusResponse(OcspRespStatus.TryLater, result);
        if (resolved.Status == ResolveOutcome.ResponderMisconfigured)
            return BuildStatusResponse(OcspRespStatus.Unauthorized, result);
        if (resolved.Status != ResolveOutcome.Ok || resolved.SignerCert == null || resolved.SignerKey == null
            || resolved.SigningContext == null || resolved.CaCert == null)
            return BuildStatusResponse(OcspRespStatus.InternalError, result);

        result.CaLabel = resolved.CaLabel ?? caLabel ?? string.Empty;

        var caCert = resolved.CaCert;
        var signerCert2 = resolved.SignerCert;
        var signerKey = resolved.SignerKey;
        var signingContext = resolved.SigningContext;
        var signingCaEntity = resolved.CaEntity;
        var isOurIssuer = resolved.IsOurIssuer;

        // Explicit thisUpdate/nextUpdate. Backdate thisUpdate
        // slightly for clock skew.
        var now = DateTime.UtcNow;
        var thisUpdate = now.AddSeconds(-30);
        var goodTtlMinutes = signingCaEntity?.OcspResponseTtlGoodMinutes ?? ocspPolicy.DefaultGoodResponseTtlMinutes;
        var revokedTtlMinutes = signingCaEntity?.OcspResponseTtlRevokedMinutes ?? ocspPolicy.DefaultRevokedResponseTtlMinutes;
        if (goodTtlMinutes < 1) goodTtlMinutes = 1;
        if (revokedTtlMinutes < 1) revokedTtlMinutes = 1;

        var respGen = new BasicOcspRespGenerator(signerCert2.GetPublicKey());
        var signingCaCertId = resolved.CaCertificateId;
        var anyExtendedRevoke = false;
        var minNextUpdate = now.AddMinutes(goodTtlMinutes);

        foreach (var req in requests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var certId = req.GetCertID();
            var serialHex = CertificateUtil.FormatSerialNumber(certId.SerialNumber);

            // Scope lookup by resolved issuer FK with DN
            // fallback for legacy rows where IssuerCertificateId has not been
            // backfilled.
            //
            // CA rows are deliberately NOT excluded. The lookup used to carry a
            // `.Where(c => !c.IsCA)` on the premise that "OCSP is for subscriber certs", but RFC
            // 6960 covers every certificate an issuer has issued, and intermediates are precisely
            // what relying parties check: a TLS client following the AIA on a leaf walks up and
            // queries the issuing CA's status too. Excluding those rows meant the query found
            // nothing, fell into the certEntity == null branch, and — because isOurIssuer is true
            // for a matched signer — returned RevokedStatus(epoch, certificateHold) with the
            // extended-revoke extension. Every unrevoked intermediate was therefore reported as
            // revoked, and any client that checked one rejected the entire chain.
            //
            // Issuer scoping below already restricts answers to certificates this CA issued, so
            // dropping the filter does not widen what the responder speaks for.
            var caIdLocal = signingCaCertId;
            var issuerDn = caCert.SubjectDN.ToString();
            var certEntity = await _db.Certificates
                .AsNoTracking()
                .Where(c => c.SerialNumber == serialHex)
                .Where(c => (caIdLocal != null && c.IssuerCertificateId == caIdLocal)
                         || (c.IssuerCertificateId == null && c.Issuer == issuerDn))
                .FirstOrDefaultAsync(cancellationToken);

            var singleThisUpdate = thisUpdate;
            DateTime singleNextUpdate;

            if (certEntity == null)
            {
                // RFC 6960 §4.4.8 extended revoked definition.
                // Only respond "revoked at epoch" when we are authoritative for
                // this issuer. Otherwise fall through to classic "unknown".
                if (isOurIssuer)
                {
                    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    var neverIssued = new RevokedStatus(epoch, CrlReason.CertificateHold);
                    singleNextUpdate = now.AddMinutes(revokedTtlMinutes);
                    respGen.AddResponse(certId, neverIssued, singleThisUpdate, singleNextUpdate, null);
                    anyExtendedRevoke = true;
                }
                else
                {
                    singleNextUpdate = now.AddMinutes(goodTtlMinutes);
                    respGen.AddResponse(certId, new UnknownStatus(), singleThisUpdate, singleNextUpdate, null);
                }
            }
            else if (certEntity.Revoked)
            {
                // Data-integrity — reject the whole response
                // with internalError if the DB row has no RevocationDate. The
                // prior behaviour ("default to now") let backdated signatures
                // look valid post-revoke.
                if (certEntity.RevocationDate == null)
                {
                    _logger.LogError(
                        "OCSP: revoked certificate {Serial} for issuer {Issuer} has no RevocationDate — refusing to synthesize one",
                        serialHex, issuerDn);
                    return BuildStatusResponse(OcspRespStatus.InternalError, result);
                }
                var revokedDate = certEntity.RevocationDate.Value;
                var reason = MapRevocationReason(certEntity.RevocationReason);
                var revokedStatus = new RevokedStatus(revokedDate, reason);
                singleNextUpdate = now.AddMinutes(revokedTtlMinutes);
                respGen.AddResponse(certId, revokedStatus, singleThisUpdate, singleNextUpdate, null);
            }
            else
            {
                singleNextUpdate = now.AddMinutes(goodTtlMinutes);
                respGen.AddResponse(certId, CertificateStatus.Good, singleThisUpdate, singleNextUpdate, null);
            }

            if (singleNextUpdate < minNextUpdate) minNextUpdate = singleNextUpdate;
        }

        // RFC 6960 §4.4.1 nonce echo + §4.4.8 extended-revoke response
        // extensions.
        var responseExts = new Dictionary<DerObjectIdentifier, X509Extension>();
        if (nonceExtValue != null)
        {
            // Echo the request's extension value verbatim. RFC 6960 §4.4.1 requires the response
            // nonce to equal the request's, and clients compare the extension values byte for
            // byte — OpenSSL's OCSP_check_nonce does exactly that.
            //
            // This used to rebuild the extension as `new DerOctetString(nonceOctets)` from the
            // UNWRAPPED nonce. The extension value is an OCTET STRING wrapping the DER encoding
            // of another OCTET STRING, so rebuilding from the inner bytes emitted one layer too
            // few: a request nonce of 0410CF03… came back as CF03… . Every client that sends a
            // nonce and verifies the response — which is the default for `openssl ocsp` — got
            // "Nonce Verify error" and treated the response as untrustworthy. Only clients
            // passing -no_nonce saw it work, which is why it survived earlier testing.
            responseExts[IdPkixOcspNonce] = new X509Extension(false, nonceExtValue);
        }
        if (anyExtendedRevoke)
        {
            responseExts[IdPkixOcspExtendedRevoke] = new X509Extension(false, new DerOctetString(DerNull.Instance.GetEncoded()));
        }
        if (responseExts.Count > 0)
        {
            respGen.SetResponseExtensions(new X509Extensions(responseExts));
        }

        try
        {
            var sigAlgName = KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(signerCert2.GetPublicKey());
            var normalizedSigAlg = CertificateUtil.NormalizeSigAlgName(sigAlgName);
            var sigFactory = new SigningServiceSignatureFactory(_signer, signerKey, SignatureAlgorithm.FromName(normalizedSigAlg), signingContext);

            // Include the responder cert chain. When the delegated
            // responder is in use, append the signing CA so strict clients can
            // build the path without a second AIA fetch.
            var chain = resolved.UsedDelegatedResponder
                ? new[] { signerCert2, caCert }
                : new[] { signerCert2 };
            var basicResp = respGen.Generate(sigFactory, chain, now);
            var ocspRespGen = new OCSPRespGenerator();
            var ocspResp = ocspRespGen.Generate(OcspRespStatus.Successful, basicResp);
            result.Status = "ok";
            var maxAge = (int)Math.Max(0, (minNextUpdate - now).TotalSeconds);
            result.CacheMaxAgeSeconds = maxAge;
            return ocspResp.GetEncoded();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OCSP: failed to sign response");
            return BuildStatusResponse(OcspRespStatus.InternalError, result);
        }
    }

    /// <summary>
    /// Nonce extension sanity — reject duplicate
    /// extensions, reject oversized nonces (RFC 8954 §3 caps at 32 octets),
    /// return the inner OCTET STRING content when present.
    /// </summary>
    private static bool TryValidateNonce(
        OcspReq ocspReq, out byte[]? nonceOctets, out Asn1OctetString? nonceExtValue, out string? reason)
    {
        nonceOctets = null;
        nonceExtValue = null;
        reason = null;
        var exts = ocspReq.RequestExtensions;
        if (exts == null) return true;

        int count = 0;
        foreach (DerObjectIdentifier oid in exts.ExtensionOids)
        {
            if (oid.Equals(IdPkixOcspNonce)) count++;
        }
        if (count == 0) return true;
        if (count > 1)
        {
            reason = "duplicate nonce extensions";
            return false;
        }

        var ext = exts.GetExtension(IdPkixOcspNonce);
        if (ext == null) return true;

        byte[] raw;
        try
        {
            // ext.Value is an OCTET STRING wrapping another OCTET STRING (the
            // actual nonce payload). Unwrap once so we get the inner bytes.
            var outer = ext.Value.GetOctets();
            try
            {
                var inner = Asn1OctetString.GetInstance(Asn1Object.FromByteArray(outer));
                raw = inner.GetOctets();
            }
            catch
            {
                // Some clients send the nonce as a raw OCTET STRING body
                // without the outer wrapping — accept that form too.
                raw = outer;
            }
        }
        catch
        {
            reason = "malformed nonce extension";
            return false;
        }

        if (raw.Length < 1 || raw.Length > 32)
        {
            reason = $"nonce length {raw.Length} outside RFC 8954 [1, 32]";
            return false;
        }
        nonceOctets = raw;
        // Kept so the response can echo the request's extension value BYTE FOR BYTE.
        // `raw` above is the unwrapped nonce, which is the right thing to length-check and
        // the wrong thing to echo: rebuilding the extension from it drops a DER layer.
        nonceExtValue = ext.Value;
        return true;
    }

    /// <summary>
    /// Resolves the signing CA for an
    /// OCSP request. Enforces validity, revocation, and enabled-state checks
    /// on the issuing CA + its certificate; honours the per-route
    /// <paramref name="caLabel"/>; falls back to CA-direct signing only when
    /// <see cref="SecurityPolicyEntity.AllowCaDirectSigning"/> is on.
    /// </summary>
    private async Task<ResolveResult> ResolveSigningCaAsync(CertificateID certId, string? caLabel, CancellationToken ct)
    {
        var issuerKeyHash = certId.GetIssuerKeyHash();
        var issuerNameHash = certId.GetIssuerNameHash();
        var hashAlg = certId.HashAlgOid;

        var signers = _keystore.GetSigners();
        _logger.LogDebug("OCSP ResolveSigningCa: hashAlg={HashAlg}, signers count={Count}, reqKeyHash={KeyHash}, reqNameHash={NameHash}, caLabel={CaLabel}",
            hashAlg, signers.Count, Convert.ToHexString(issuerKeyHash), Convert.ToHexString(issuerNameHash), caLabel ?? "(none)");

        var now = DateTime.UtcNow;
        bool sawLabelMismatch = false;

        foreach (var signer in signers)
        {
            ct.ThrowIfCancellationRequested();
            var caCert = signer.PublicCertificate;

            try
            {
#pragma warning disable CS0618 // CertificateID string constructor — no non-deprecated overload available
                var computedId = new CertificateID(certId.HashAlgOid, caCert, certId.SerialNumber);
#pragma warning restore CS0618
                var compKeyHash = computedId.GetIssuerKeyHash();
                var compNameHash = computedId.GetIssuerNameHash();

                if (!AreEqual(compKeyHash, issuerKeyHash) || !AreEqual(compNameHash, issuerNameHash))
                    continue;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "OCSP: error computing CertificateID for signer '{Subject}'", caCert.SubjectDN);
                continue;
            }

            // Validity window.
            if (now < caCert.NotBefore.ToUniversalTime() || now > caCert.NotAfter.ToUniversalTime())
            {
                _logger.LogWarning("OCSP: matched signer '{Subject}' is outside validity window", caCert.SubjectDN);
                return new ResolveResult(ResolveOutcome.CaExpired);
            }

            // Load the CA entity and verify it's enabled + its
            // own cert is not revoked.
            var caEntity = await _db.CertificateAuthorities
                .AsNoTracking()
                .Include(ca => ca.Certificate)
                .FirstOrDefaultAsync(ca => ca.Certificate != null && ca.Certificate.SubjectDN == caCert.SubjectDN.ToString(), ct);

            if (caEntity == null)
            {
                _logger.LogWarning("OCSP: matched signer '{Subject}' has no CertificateAuthority DB row", caCert.SubjectDN);
                continue;
            }

            if (!caEntity.IsEnabled)
            {
                _logger.LogWarning("OCSP: CA '{Label}' is disabled — refusing to answer", caEntity.Label ?? caEntity.Name);
                return new ResolveResult(ResolveOutcome.CaDisabled);
            }

            // Check per-CA OCSP protocol config
            var ocspConfig = await _db.CaProtocolConfigs
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CaId == caEntity.Id && c.Protocol == "OCSP", ct);
            if (ocspConfig != null && !ocspConfig.IsEnabled)
            {
                _logger.LogWarning("OCSP: protocol disabled for CA '{Label}' via per-CA config", caEntity.Label ?? caEntity.Name);
                return new ResolveResult(ResolveOutcome.CaDisabled);
            }

            if (caEntity.Certificate != null && caEntity.Certificate.Revoked)
            {
                _logger.LogWarning("OCSP: CA '{Label}' certificate is revoked — refusing to answer", caEntity.Label ?? caEntity.Name);
                return new ResolveResult(ResolveOutcome.CaRevoked);
            }

            // Enforce the route-level CA label binding.
            if (!string.IsNullOrWhiteSpace(caLabel))
            {
                if (!string.Equals(caEntity.Label, caLabel, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("OCSP: route label '{RouteLabel}' does not match resolved CA '{ActualLabel}'",
                        caLabel, caEntity.Label);
                    sawLabelMismatch = true;
                    continue;
                }
            }

            // Prefer delegated responder;
            // fall back to CA-direct only when the config allows it.
            var delegatedResult = await TryResolveDelegatedResponderAsync(caCert, caEntity, ct);
            if (delegatedResult.Outcome == DelegatedOutcome.Ok)
            {
                return new ResolveResult(ResolveOutcome.Ok)
                {
                    CaCert = caCert,
                    SignerCert = delegatedResult.ResponderCert,
                    SignerKey = delegatedResult.ResponderKey,
                    SigningContext = ContextFor(caEntity),
                    CaEntity = caEntity,
                    CaCertificateId = caEntity.CertificateId,
                    IsOurIssuer = true,
                    UsedDelegatedResponder = true,
                    CaLabel = caEntity.Label,
                };
            }
            if (delegatedResult.Outcome == DelegatedOutcome.ResponderInvalid)
            {
                // A responder is configured but fails policy checks. Refuse to
                // fall through to CA-direct even when it's enabled — the
                // operator's intent was "use this responder".
                return new ResolveResult(ResolveOutcome.ResponderMisconfigured) { CaEntity = caEntity };
            }

            // DelegatedOutcome.NotConfigured
            var resolvePolicy = await _securityPolicy.GetAsync();
            if (!resolvePolicy.AllowCaDirectSigning)
            {
                _logger.LogWarning(
                    "OCSP: CA '{Label}' has no delegated OCSP responder configured and SecurityPolicy.AllowCaDirectSigning=false — returning Unauthorized",
                    caEntity.Label ?? caEntity.Name);
                return new ResolveResult(ResolveOutcome.ResponderMisconfigured) { CaEntity = caEntity };
            }

            var caKey = new KeyRef(caEntity.CertificateId.GetValueOrDefault());
            if (!await SignerHoldsKeyAsync(caEntity, caKey, ct))
            {
                _logger.LogWarning("OCSP: matched signer '{Subject}' but the signer holds no key for CA-direct signing", caCert.SubjectDN);
                continue;
            }
            _logger.LogWarning(
                "OCSP: CA '{Label}' is signing directly with the CA private key because SecurityPolicy.AllowCaDirectSigning=true — provision a delegated responder ASAP",
                caEntity.Label ?? caEntity.Name);
            return new ResolveResult(ResolveOutcome.Ok)
            {
                CaCert = caCert,
                SignerCert = caCert,
                SignerKey = caKey,
                SigningContext = ContextFor(caEntity),
                CaEntity = caEntity,
                CaCertificateId = caEntity.CertificateId,
                IsOurIssuer = true,
                UsedDelegatedResponder = false,
                CaLabel = caEntity.Label,
            };
        }

        if (sawLabelMismatch)
        {
            return new ResolveResult(ResolveOutcome.LabelMismatch);
        }
        _logger.LogWarning("OCSP: no signing CA found for request. Returning unauthorized.");
        return new ResolveResult(ResolveOutcome.NotFound);
    }

    /// <summary>
    /// Loads the delegated responder cert,
    /// verifies id-kp-OCSPSigning EKU, id-pkix-ocsp-nocheck extension (gated
    /// by <see cref="SecurityPolicyEntity.RequireNoCheckExtension"/>), validity
    /// window, and the parent CA chain state (validity + revoked + enabled).
    /// </summary>
    private async Task<DelegatedResolveResult> TryResolveDelegatedResponderAsync(X509Certificate caCert, CertificateAuthorityEntity caEntity, CancellationToken ct)
    {
        if (caEntity.OcspResponderCertificateId == null)
            return new DelegatedResolveResult(DelegatedOutcome.NotConfigured);

        var responderCertEntity = await _db.Certificates
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == caEntity.OcspResponderCertificateId && !c.Revoked, ct);

        if (responderCertEntity == null)
        {
            _logger.LogWarning("OCSP: delegated responder cert {Id} not found or revoked", caEntity.OcspResponderCertificateId);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        X509Certificate responderCert;
        try
        {
            responderCert = CertificateUtil.ParseFromPem(responderCertEntity.Pem);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OCSP: failed to parse delegated responder cert PEM for CA '{Label}'", caEntity.Label);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        // Validate id-kp-OCSPSigning EKU (RFC 6960 §4.2.2.2)
        var ekuExt = responderCert.GetExtendedKeyUsage();
        if (ekuExt == null || !ekuExt.Contains(IdKpOcspSigning))
        {
            _logger.LogWarning("OCSP responder certificate {Subject} lacks id-kp-OCSPSigning EKU", responderCert.SubjectDN);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        // Id-pkix-ocsp-nocheck enforcement.
        var hasNoCheck = responderCert.GetCriticalExtensionOids()?.Contains(IdPkixOcspNoCheck.Id) == true
                      || responderCert.GetNonCriticalExtensionOids()?.Contains(IdPkixOcspNoCheck.Id) == true;
        if (!hasNoCheck)
        {
            var delegatedPolicy = await _securityPolicy.GetAsync();
            if (delegatedPolicy.RequireNoCheckExtension)
            {
                _logger.LogWarning(
                    "OCSP: delegated responder '{Subject}' lacks id-pkix-ocsp-nocheck — refusing to use (SecurityPolicy.RequireNoCheckExtension=true)",
                    responderCert.SubjectDN);
                return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
            }
            _logger.LogWarning(
                "OCSP: delegated responder '{Subject}' lacks id-pkix-ocsp-nocheck — RFC 6960 §4.2.2.2.1 SHOULD. Continuing anyway; flip SecurityPolicy.RequireNoCheckExtension=true to refuse.",
                responderCert.SubjectDN);
        }

        // Validate responder certificate is within its validity period
        var now = DateTime.UtcNow;
        if (now > responderCert.NotAfter.ToUniversalTime() || now < responderCert.NotBefore.ToUniversalTime())
        {
            _logger.LogWarning("OCSP responder certificate {Subject} is not within validity period", responderCert.SubjectDN);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        // Also verify the issuer CA's own cert is within its
        // window and is not revoked/disabled. (caEntity checks already ran in
        // the caller; here we re-verify the cert chain state for the CA that
        // actually signed the responder cert — they should match.)
        if (now > caCert.NotAfter.ToUniversalTime() || now < caCert.NotBefore.ToUniversalTime())
        {
            _logger.LogWarning("OCSP: responder's issuer CA '{Subject}' is outside validity window", caCert.SubjectDN);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }
        if (caEntity.Certificate != null && caEntity.Certificate.Revoked)
        {
            _logger.LogWarning("OCSP: responder's issuer CA '{Subject}' is revoked", caCert.SubjectDN);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        var responderKey = new KeyRef(caEntity.OcspResponderCertificateId.Value);
        if (!await SignerHoldsKeyAsync(caEntity, responderKey, ct))
        {
            _logger.LogWarning("OCSP: delegated responder cert '{Subject}' has no private key in the signer", responderCert.SubjectDN);
            return new DelegatedResolveResult(DelegatedOutcome.ResponderInvalid);
        }

        _logger.LogInformation("OCSP: using delegated responder '{Subject}' for CA '{CaSubject}'",
            responderCert.SubjectDN, caCert.SubjectDN);
        return new DelegatedResolveResult(DelegatedOutcome.Ok)
        {
            ResponderCert = responderCert,
            ResponderKey = responderKey,
        };
    }

    private static bool AreEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    /// <summary>
    /// Revocation reasons are stored as RevocationReason enum names.
    /// Unknown values fall through to Unspecified rather than throwing, since OCSP responses
    /// must still be produced even for legacy free-text rows. The CrlService chokepoint is
    /// strict; OCSP must degrade gracefully.
    /// </summary>
    private static int MapRevocationReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason)) return CrlReason.Unspecified;

        if (Enum.TryParse<ModularCA.Shared.Enums.RevocationReason>(reason, ignoreCase: true, out var parsed))
        {
            return parsed switch
            {
                ModularCA.Shared.Enums.RevocationReason.Unspecified => CrlReason.Unspecified,
                ModularCA.Shared.Enums.RevocationReason.KeyCompromise => CrlReason.KeyCompromise,
                ModularCA.Shared.Enums.RevocationReason.CACompromise => CrlReason.CACompromise,
                ModularCA.Shared.Enums.RevocationReason.AffiliationChanged => CrlReason.AffiliationChanged,
                ModularCA.Shared.Enums.RevocationReason.Superseded => CrlReason.Superseded,
                ModularCA.Shared.Enums.RevocationReason.CessationOfOperation => CrlReason.CessationOfOperation,
                ModularCA.Shared.Enums.RevocationReason.CertificateHold => CrlReason.CertificateHold,
                ModularCA.Shared.Enums.RevocationReason.PrivilegeWithdrawn => CrlReason.PrivilegeWithdrawn,
                ModularCA.Shared.Enums.RevocationReason.AaCompromise => CrlReason.AACompromise,
                _ => CrlReason.Unspecified,
            };
        }
        return CrlReason.Unspecified;
    }

    /// <summary>
    /// Builds a DER-encoded OCSPResponse with no body for the given non-Successful
    /// status and records the outcome into <paramref name="result"/> so the
    /// controller can label the metric correctly.
    /// </summary>
    private static byte[] BuildStatusResponse(int status, OcspProcessingResult result)
    {
        result.Status = status switch
        {
            OcspRespStatus.Successful => "ok",
            OcspRespStatus.MalformedRequest => "malformedRequest",
            OcspRespStatus.InternalError => "internalError",
            OcspRespStatus.TryLater => "tryLater",
            OcspRespStatus.SigRequired => "sigRequired",
            OcspRespStatus.Unauthorized => "unauthorized",
            _ => $"status{status}",
        };
        var gen = new OCSPRespGenerator();
        var resp = gen.Generate(status, null);
        return resp.GetEncoded();
    }

    // Internal resolve bookkeeping — split out so the main handler
    // can clearly distinguish "couldn't find the signer" from "policy refused
    // it" from "infrastructure error".
    private enum ResolveOutcome
    {
        Ok,
        NotFound,
        CaExpired,
        CaRevoked,
        CaDisabled,
        ResponderMisconfigured,
        LabelMismatch,
    }

    private enum DelegatedOutcome
    {
        NotConfigured,
        ResponderInvalid,
        Ok,
    }

    private sealed class ResolveResult
    {
        public ResolveOutcome Status { get; }
        public X509Certificate? CaCert { get; set; }
        public X509Certificate? SignerCert { get; set; }
        public KeyRef? SignerKey { get; set; }
        public SigningContext? SigningContext { get; set; }
        public CertificateAuthorityEntity? CaEntity { get; set; }
        public Guid? CaCertificateId { get; set; }
        public bool IsOurIssuer { get; set; }
        public bool UsedDelegatedResponder { get; set; }
        public string? CaLabel { get; set; }
        public ResolveResult(ResolveOutcome status) { Status = status; }
    }

    private sealed class DelegatedResolveResult
    {
        public DelegatedOutcome Outcome { get; }
        public X509Certificate? ResponderCert { get; set; }
        public KeyRef? ResponderKey { get; set; }
        public DelegatedResolveResult(DelegatedOutcome outcome) { Outcome = outcome; }
    }
}
