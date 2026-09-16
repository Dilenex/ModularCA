using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Auth.Authorization;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Text;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.API.Controllers.v1.Admin
{
    /// <summary>
    /// Admin endpoints for issuing and reissuing certificates from approved CSRs.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/certificates")]
    [Authorize]

    public class AdminIssuanceController(ModularCADbContext dbContext,
        ICertificateIssuanceService certificateIssuanceService,
        ICurrentUserService currentUser,
        ICertificateStore certificateStore,
        ICertificateAccessService certificateAccessService,
        IAuditService auditService,
        ICsrService csrService,
        IKeyWrappingPassphraseProvider passphraseProvider,
        IDistributedCache cache,
        ICaGroupAuthorizationService authService,
        IValidityCeilingService validityCeiling) : ControllerBase
    {
        private readonly ModularCADbContext _dbContext = dbContext;
        private readonly ICertificateIssuanceService _certificateIssuanceService = certificateIssuanceService;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly ICertificateStore _certificateStore = certificateStore;
        private readonly ICertificateAccessService _certificateAccessService = certificateAccessService;
        private readonly IAuditService _audit = auditService;
        private readonly ICsrService _csrService = csrService;
        private readonly IKeyWrappingPassphraseProvider _passphraseProvider = passphraseProvider;
        private readonly IDistributedCache _cache = cache;
        private readonly ICaGroupAuthorizationService _authService = authService;
        private readonly IValidityCeilingService _validityCeiling = validityCeiling;

        /// <summary>
        /// Resolve the CA via CSR → SigningProfile → IssuerId → CA, then
        /// enforce that the caller's <see cref="ICurrentUserService"/> accessible tenant
        /// set contains the CA's tenant. Returns null on allow, an <see cref="IActionResult"/>
        /// (404) on deny. Collapses cross-tenant mismatches to 404 to avoid existence oracles.
        /// </summary>
        private async Task<IActionResult?> EnforceTenantFenceForCsrAsync(Guid csrId)
        {
            var csr = await _dbContext.CertificateRequests
                .AsNoTracking()
                .Include(c => c.SigningProfile)
                .FirstOrDefaultAsync(c => c.Id == csrId);
            if (csr == null)
                return NotFound();
            var info = await ResolveCaFromSigningProfileAsync(csr.SigningProfileId);
            return EnforceTenantFence(info);
        }

        /// <summary>
        /// Resolve the CA via Certificate → SigningProfile → IssuerId → CA,
        /// then enforce tenant access. Handles both cert-id and serial-number variants.
        /// </summary>
        private async Task<IActionResult?> EnforceTenantFenceForCertAsync(Guid? certId, string? serial)
        {
            Shared.Entities.CertificateEntity? cert = null;
            if (certId.HasValue)
            {
                cert = await _dbContext.Certificates
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CertificateId == certId.Value);
            }
            else if (!string.IsNullOrWhiteSpace(serial))
            {
                cert = await _dbContext.Certificates
                    .AsNoTracking()
                    .ResolveBySerialOrNullAsync(serial);
            }
            if (cert == null)
                return NotFound();
            var info = await ResolveCaFromSigningProfileAsync(cert.SigningProfileId);
            return EnforceTenantFence(info);
        }

        private IActionResult? EnforceTenantFence((Guid CaId, Guid TenantId)? info)
        {
            // System-wide signing profile with no CA link — treat as system-admin-only.
            if (info == null)
            {
                if (HttpContext.Items["IsSystemAdmin"] is true)
                    return null;
                return NotFound();
            }
            if (HttpContext.Items["IsSystemAdmin"] is true)
                return null;
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null || !tenantIds.Contains(info.Value.TenantId))
                return NotFound();
            return null;
        }

        /// <summary>
        /// Pre-flight: reports the longest validity a given signing profile / certificate profile
        /// pairing could actually issue for, and which of the three layers — certificate profile,
        /// tenant, issuing CA — is the one setting it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This exists so that the clamp never fires for an operator at a keyboard. Until now
        /// nothing told them about any ceiling: they picked profiles, typed a Not After, submitted,
        /// and found out afterwards — from an <c>MCA-ISS-004</c> advisory attached to a certificate
        /// that already exists and already has a serial — that they got something shorter. Fixing
        /// that means revoke and reissue. Answering the same question before submission costs three
        /// indexed reads.
        /// </para>
        /// <para>
        /// It names the binding layer because the number alone is not actionable. "Max 730 days"
        /// sends an operator to whichever screen they guess first, and the wrong guess costs a
        /// profile edit, a reload, and the same 730 days.
        /// </para>
        /// <para>
        /// Same tenant fence and the same <c>profile.use</c> checks as issuance: the answer reveals
        /// a tenant's configured ceiling and a CA's expiry, so it must not be readable by someone
        /// who could not have issued under those profiles anyway.
        /// </para>
        /// <para>
        /// Returns <see cref="ValidityCeilingPreflight"/> unmapped. The shared-type generator emits
        /// a matching TypeScript interface from that record, so a hand-written projection here
        /// would be a second contract able to drift from the one the browser compiles against.
        /// </para>
        /// </remarks>
        /// <param name="signingProfileId">The signing profile, which determines the issuing CA and tenant.</param>
        /// <param name="certProfileId">The certificate profile whose maximum validity is the baseline.</param>
        /// <param name="notBefore">Optional proposed start; defaults to what issuance would use.</param>
        [HttpGet("validity-ceiling")]
        [Authorize(Policy = "CaOperator")]
        public async Task<IActionResult> GetValidityCeiling(
            [FromQuery] Guid signingProfileId,
            [FromQuery] Guid certProfileId,
            [FromQuery] DateTime? notBefore = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var fence = EnforceTenantFence(await ResolveCaFromSigningProfileAsync(signingProfileId));
            if (fence != null)
                return fence;

            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "SigningProfile", signingProfileId))
                return StatusCode(403, new { error = "You do not have profile.use access on this signing profile." });
            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "CertProfile", certProfileId))
                return StatusCode(403, new { error = "You do not have profile.use access on this certificate profile." });

            var preflight = await _validityCeiling.ResolveAsync(signingProfileId, certProfileId, notBefore, HttpContext.RequestAborted);
            if (preflight == null)
                return NotFound(new { error = "Signing profile or certificate profile not found." });

            return Ok(preflight);
        }

        /// <summary>
        /// Issues a certificate from an approved CSR. Enforces tenant access and profile.use
        /// capability checks before delegating to the issuance service.
        /// </summary>
        [HttpPost("issue")]
        [Authorize]
        [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Csr, "req.CsrId")]
        public async Task<IActionResult> IssueCertificate([FromBody] IssueCertificateRequest req)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Enforce tenant access on the target CSR's CA before issuance.
            var fenceResult = await EnforceTenantFenceForCsrAsync(req.CsrId);
            if (fenceResult != null)
                return fenceResult;

            // Enforce profile.use capability on both the cert profile and signing profile
            var profileCheck = await EnforceProfileUseForCsrAsync(_currentUser.User.Id, req.CsrId);
            if (profileCheck != null)
                return profileCheck;

            // Fall back to the window recorded when the request was submitted. An issuer who
            // passes an explicit window still wins; this only fills in what was asked for.
            var requested = await _dbContext.CertificateRequests
                .AsNoTracking()
                .Where(c => c.Id == req.CsrId)
                .Select(c => new { c.RequestedNotBefore, c.RequestedNotAfter })
                .FirstOrDefaultAsync();

            // HonourTenantPolicy: this is the interactive admin path, so a tenant configured to
            // refuse over-long validity refuses here rather than handing back a certificate quietly
            // shorter than the operator asked for. They can see the ceiling (the pre-flight endpoint
            // below tells them before they submit) and they can act on the refusal — neither of
            // which is true of ACME, EST, SCEP, CMP or the renewal jobs, which always shorten.
            var result = await _certificateIssuanceService.IssueCertificateAsync(
                req.CsrId,
                req.NotBefore ?? requested?.RequestedNotBefore,
                req.NotAfter ?? requested?.RequestedNotAfter,
                ValidityCeilingEnforcement.HonourTenantPolicy);
            var cert = result.Pem;
            var certDer = CertificateUtil.ParseFromPem(cert);
            var certName = CertificateUtil.ParseCnFromPem(cert);
            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            var certSerial = CertificateUtil.FormatSerialNumber(certDer.SerialNumber);
            var certEntry = await _dbContext.Certificates.ResolveBySerialOrNullAsync(certSerial);

            if (certEntry == null)
            {
                return NotFound("Newly generated certificate not found in the database.");
            }

            await _certificateAccessService.SetPermissionsOnNewCertificate(certEntry.CertificateId, _currentUser.User.Id);

            var caInfo = await ResolveCaFromSigningProfileAsync(certEntry.SigningProfileId);
            await _audit.LogAsync(AuditActionType.CertificateIssued, _currentUser.User.Id, _currentUser.User.Username,
                "Certificate", certEntry.SerialNumber,
                new { CsrId = req.CsrId, SubjectDN = certEntry.SubjectDN },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfo?.CaId, tenantId: caInfo?.TenantId);

            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else if (accept.Contains("application/x-pem-file"))
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(cert), "application/x-pem-file", fileName);
            }
            else
            {
                // One shape, chosen by content negotiation rather than by whether this
                // particular issuance happened to raise a diagnostic. The previous split —
                // JSON when warnings existed, a bare PEM file otherwise — meant the client
                // could not know what it was about to parse, so callers read .newSerialNumber
                // off a string on the common path and silently reported "serial unknown".
                return Ok(new
                {
                    pem = cert,
                    // The console links straight to the certificate it just issued; without the
                    // serial here it had to parse the PEM's DER to find it.
                    serialNumber = certSerial,
                    certificateId = certEntry.CertificateId,
                    warnings = result.Warnings,
                    diagnostics = result.Diagnostics,
                });
            }



        }

        /// <summary>
        /// Issues a certificate with a server-generated key pair. Generates the keypair based on the
        /// requested algorithm and size, builds a PKCS#10 CSR server-side, uploads it through the
        /// standard CSR pipeline, and immediately issues the certificate. The private key is stored
        /// encrypted on the certificate entity and can be exported via the PFX export endpoint.
        /// </summary>
        /// <param name="req">The request body containing subject, SANs, key algorithm, profiles, and validity dates.</param>
        /// <returns>Certificate serial, subject DN, validity dates, and a message directing to the export endpoint.</returns>
        [HttpPost("issue-with-key")]
        [Authorize]
        [RequireCaCapability(Capabilities.CertRevoke, CaTarget.SigningProfile, "req.SigningProfileId")]
        public async Task<IActionResult> IssueWithServerKey([FromBody] IssueWithKeyRequest req)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Validate required fields
            if (req.Subject == null || req.Subject.Count == 0)
                return BadRequest(new { error = "Subject fields are required." });
            if (req.CertProfileId == Guid.Empty)
                return BadRequest(new { error = "Certificate profile ID is required." });
            if (req.SigningProfileId == Guid.Empty)
                return BadRequest(new { error = "Signing profile ID is required." });

            // Enforce tenant access against the chosen signing profile's CA.
            var caInfoForFence = await ResolveCaFromSigningProfileAsync(req.SigningProfileId);
            var fence = EnforceTenantFence(caInfoForFence);
            if (fence != null) return fence;

            // Enforce profile.use capability on both profiles
            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "CertProfile", req.CertProfileId))
                return StatusCode(403, new { error = "You do not have profile.use access on this certificate profile." });
            if (!await _authService.HasResourceCapabilityAsync(_currentUser.User.Id, Capabilities.ProfileUse, "SigningProfile", req.SigningProfileId))
                return StatusCode(403, new { error = "You do not have profile.use access on this signing profile." });

            // Determine the signature algorithm from the key algorithm
            var signatureAlgorithm = ResolveSignatureAlgorithm(req.KeyAlgorithm, req.KeySize);
            if (signatureAlgorithm == null)
                return BadRequest(new { error = $"Unsupported key algorithm: {req.KeyAlgorithm}" });

            // Build the subject DN string from the dictionary
            var subjectDn = BuildSubjectDn(req.Subject);
            if (string.IsNullOrWhiteSpace(subjectDn))
                return BadRequest(new { error = "Subject DN must contain at least one field." });

            // Resolve key size string for the CSR service
            var keySize = req.KeyAlgorithm.ToUpperInvariant() == "ED25519" ? "Ed25519" : req.KeySize;

            // Generate key pair
            var keyPair = KeyGenerationUtil.GenerateKeyPair(req.KeyAlgorithm, keySize);

            // Build PKCS#10 CSR with SANs
            var subject = new X509Name(subjectDn);
            DerSet? attributes = null;

            if (req.Sans != null && req.Sans.Count > 0)
            {
                var sanGeneralNames = new List<GeneralName>();
                foreach (var san in req.Sans)
                {
                    // Shared with the runtime and bootstrap builders. The local switch this
                    // replaces fell back to DnsName for any unrecognised type, so a UPN — or a
                    // typo — was signed into the certificate as a DNS name with nothing reported.
                    sanGeneralNames.Add(SanGeneralNames.Build(san.Type, san.Value));
                }

                var sanExtension = new GeneralNames(sanGeneralNames.ToArray());
                var extGen = new X509ExtensionsGenerator();
                extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, sanExtension);
                var extensions = extGen.Generate();
                var attr = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
                attributes = new DerSet(attr);
            }

            var csr = new Pkcs10CertificationRequest(
                signatureAlgorithm,
                subject,
                keyPair.Public,
                attributes,
                keyPair.Private
            );

            // PEM encode the CSR
            string csrPem;
            using (var sw = new StringWriter())
            {
                var pemWriter = new PemWriter(sw);
                pemWriter.WriteObject(csr);
                csrPem = sw.ToString();
            }

            // Build subject and SAN overrides for the upload
            var sanOverrides = req.Sans?
                .Where(s => !string.IsNullOrWhiteSpace(s.Value))
                .Select(s => new SanOverride { Type = s.Type, Value = s.Value })
                .ToList();

            // Upload the CSR through the standard pipeline (validates against profiles, encrypts key, stores entity)
            await _csrService.UploadCsrAsync(
                csrPem,
                req.CertProfileId,
                req.SigningProfileId,
                _currentUser.User.Id,
                req.Subject,
                sanOverrides,
                // Carry the requested validity window onto the request. Issuance happens later
                // from the Requests page, so without persisting these the operator's Not Before
                // / Not After choices were accepted by the DTO and then discarded.
                req.NotBefore,
                req.NotAfter);

            // Find the CSR entity that was just created
            var csrEntity = await _dbContext.CertificateRequests
                .Where(c => c.CSR == csrPem && c.RequestorUserId == _currentUser.User.Id)
                .OrderByDescending(c => c.SubmittedAt)
                .FirstOrDefaultAsync();

            if (csrEntity == null)
                return StatusCode(500, new { error = "Failed to locate the uploaded CSR entity." });

            // Store the encrypted private key on the CSR entity (UploadCsr doesn't have the private key)
            var encryptionCert = _dbContext.Certificates
                .AsNoTracking()
                .Where(c => c.SubjectDN.Contains("ModularCA System Signing CA") && c.IsCA)
                .FirstOrDefault();

            if (encryptionCert != null)
            {
                var bcCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(encryptionCert.RawCertificate);
                var encrypted = KeyEncryptionUtil.EncryptPrivateKey(bcCert.GetPublicKey(), keyPair.Private, _passphraseProvider.GetPassphrase());
                csrEntity.EncryptedPrivateKey = encrypted.encryptedPrivateKey;
                csrEntity.EncryptedAesForPrivateKey = encrypted.aesKeyEncrypted;
                csrEntity.AesKeyEncryptionIv = encrypted.iv;
                csrEntity.EncryptionCertSerialNumber = encryptionCert.SerialNumber;
                await _dbContext.SaveChangesAsync();
            }

            // Do NOT issue immediately — the request stays pending for approval/issuance
            await _audit.LogAsync(AuditActionType.CsrSubmitted, _currentUser.User.Id, _currentUser.User.Username,
                "CertificateRequest", csrEntity.Id.ToString(),
                new { Source = "ServerKeyGen", KeyAlgorithm = req.KeyAlgorithm, KeySize = req.KeySize },
                HttpContext.Connection.RemoteIpAddress?.ToString());

            return Ok(new
            {
                requestId = csrEntity.Id,
                hasPrivateKey = true,
                message = "Certificate request submitted with server-generated key pair. Approve and issue from the Requests page. PFX export will be available after issuance."
            });
        }

        /// <summary>
        /// Resolves the CA ID and tenant ID from a signing profile via the CaProtocolConfig linkage.
        /// Returns null if the signing profile is not linked to a CA.
        /// </summary>
        private async Task<(Guid CaId, Guid TenantId)?> ResolveCaFromSigningProfileAsync(Guid? signingProfileId)
        {
            if (signingProfileId == null) return null;
            var config = await _dbContext.CaProtocolConfigs
                .Include(pc => pc.Ca)
                .AsNoTracking()
                .FirstOrDefaultAsync(pc => pc.SigningProfileId == signingProfileId);
            if (config?.Ca == null) return null;
            return (config.Ca.Id, config.Ca.TenantId);
        }

        /// <summary>
        /// Resolves the appropriate signature algorithm string for BouncyCastle CSR signing
        /// based on the key algorithm and key size. Delegates to
        /// <see cref="KeyAlgorithmPolicy.ResolveSignatureAlgorithm(string, string?)"/> so
        /// the RSA-PSS padding mode from <see cref="KeyAlgorithmPolicy.UseRsaPss"/> is honoured.
        /// </summary>
        private static string? ResolveSignatureAlgorithm(string keyAlgorithm, string keySize)
        {
            try
            {
                return KeyAlgorithmPolicy.ResolveSignatureAlgorithm(keyAlgorithm, keySize);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <summary>
        /// Escapes DN special characters in a value per RFC 4514.
        /// </summary>
        private static string EscapeDnValue(string value)
        {
            return value
                .Replace("\\", "\\\\")
                .Replace(",", "\\,")
                .Replace("+", "\\+")
                .Replace("\"", "\\\"")
                .Replace("<", "\\<")
                .Replace(">", "\\>")
                .Replace(";", "\\;");
        }

        /// <summary>
        /// Builds a distinguished name string from a dictionary of subject DN field values.
        /// Values are escaped per RFC 4514 to prevent DN injection.
        /// </summary>
        private static string BuildSubjectDn(Dictionary<string, string> fields)
        {
            var parts = new List<string>();
            // Process in standard order
            var orderedKeys = new[] { "CN", "O", "OU", "L", "ST", "C" };
            foreach (var key in orderedKeys)
            {
                if (fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                    parts.Add($"{key}={EscapeDnValue(value)}");
            }
            // Include any additional fields not in the standard set
            foreach (var kvp in fields)
            {
                if (!orderedKeys.Contains(kvp.Key, StringComparer.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(kvp.Value))
                    parts.Add($"{kvp.Key}={EscapeDnValue(kvp.Value)}");
            }
            return string.Join(",", parts);
        }

        [HttpPost("{certId:guid}/reissue")]
        [Authorize(Policy = "CaOperator")]
        public async Task<IActionResult> ReissueCertId([FromBody] ReissueCertificateRequestByCertId request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Tenant fence.
            var fence = await EnforceTenantFenceForCertAsync(request.CertificateId, null);
            if (fence != null) return fence;

            // Enforce profile.use capability on the profiles referenced by the original CSR
            var profileCheckReissue = await EnforceProfileUseForCertAsync(_currentUser.User.Id, request.CertificateId, null);
            if (profileCheckReissue != null)
                return profileCheckReissue;

            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ReissueCert, request.CertificateId.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

            // Interactive admin reissue: same reasoning as the issue path above — an operator who
            // can see the tenant ceiling is refused by it rather than handed a shorter certificate.
            var reissueResult = await _certificateIssuanceService.ReissueCertificateAsync(
                request.CertificateId,
                null,
                null,
                request.NotBefore,
                request.NotAfter,
                request.NewSubjectDn,
                request.NewSans,
                ValidityCeilingEnforcement.HonourTenantPolicy);
            var newCertPem = reissueResult.Pem;

            var certDer = CertificateUtil.ParseFromPem(newCertPem);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var certSerial2 = CertificateUtil.FormatSerialNumber(certDer.SerialNumber);
            var certEntry = await _dbContext.Certificates.ResolveBySerialOrNullAsync(certSerial2);

            if (certEntry == null)
            {
                return NotFound("Newly generated certificate not found in the database.");
            }

            // ACL inheritance is done inside ReissueCertificateAsync, which is the only place
            // that still knows which certificate was replaced. Calling it again from here was a
            // duplicate of the same operation, and it had no way to identify the predecessor —
            // which is why the service used to guess by subject DN.

            var caInfoReissue = await ResolveCaFromSigningProfileAsync(certEntry.SigningProfileId);
            await _audit.LogAsync(AuditActionType.CertificateReissued, _currentUser.User.Id, _currentUser.User.Username,
                "Certificate", certEntry.SerialNumber,
                new
                {
                    OriginalCertId = request.CertificateId,
                    SubjectDN = certEntry.SubjectDN,
                    NewSubjectDn = request.NewSubjectDn,
                    NewSans = request.NewSans,
                    OverridesApplied = request.NewSubjectDn != null || request.NewSans != null
                },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfoReissue?.CaId, tenantId: caInfoReissue?.TenantId);

            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else if (accept.Contains("application/x-pem-file"))
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
            else
            {
                // One shape, chosen by content negotiation rather than by whether this
                // particular issuance happened to raise a diagnostic. The previous split —
                // JSON when warnings existed, a bare PEM file otherwise — meant the client
                // could not know what it was about to parse, so callers read .newSerialNumber
                // off a string on the common path and silently reported "serial unknown".
                return Ok(new
                {
                    pem = newCertPem,
                    warnings = reissueResult.Warnings,
                    diagnostics = reissueResult.Diagnostics,
                });
            }
        }
        /// <summary>
        /// Reissues a certificate identified by serial number. Emits a
        /// <see cref="AuditActionType.CertificateReissued"/> record after the new cert is
        /// persisted, mirroring <see cref="ReissueCertId"/>. Enforces tenant fence,
        /// profile.use capability, and step-up MFA before delegating to the issuance service.
        /// </summary>
        [HttpPost("serial/{serial}/reissue")]
        [Authorize(Policy = "CaOperator")]
        public async Task<IActionResult> ReissueCertSn([FromBody] ReissueCertificateRequestByCertSn request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Tenant fence.
            var fence = await EnforceTenantFenceForCertAsync(null, request.SerialNumber);
            if (fence != null) return fence;

            // Enforce profile.use capability on the profiles referenced by the original CSR
            var profileCheckReissueSn = await EnforceProfileUseForCertAsync(_currentUser.User.Id, null, request.SerialNumber);
            if (profileCheckReissueSn != null)
                return profileCheckReissueSn;

            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ReissueCert, request.SerialNumber))
                return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

            // Interactive admin reissue; see ReissueCertId.
            var reissueResult = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                request.SerialNumber,
                null,
                request.NotBefore,
                request.NotAfter,
                request.NewSubjectDn,
                request.NewSans,
                ValidityCeilingEnforcement.HonourTenantPolicy);
            var newCertPem = reissueResult.Pem;
            var certDer = CertificateUtil.ParseFromPem(newCertPem);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var certEntry = await _dbContext.Certificates.ResolveBySerialOrNullAsync(CertificateUtil.FormatSerialNumber(certDer.SerialNumber));

            if (certEntry == null)
            {
                return NotFound("Newly generated certificate not found in the database.");
            }

            // ACL inheritance is done inside ReissueCertificateAsync, which is the only place
            // that still knows which certificate was replaced. Calling it again from here was a
            // duplicate of the same operation, and it had no way to identify the predecessor —
            // which is why the service used to guess by subject DN.

            // Emit CertificateReissued so reissue-by-serial
            // matches the audit coverage already present on reissue-by-id.
            var caInfoReissueSn = await ResolveCaFromSigningProfileAsync(certEntry.SigningProfileId);
            await _audit.LogAsync(AuditActionType.CertificateReissued, _currentUser.User.Id, _currentUser.User.Username,
                "Certificate", certEntry.SerialNumber,
                new
                {
                    OriginalSerial = request.SerialNumber,
                    SubjectDN = certEntry.SubjectDN,
                    NewSubjectDn = request.NewSubjectDn,
                    NewSans = request.NewSans,
                    OverridesApplied = request.NewSubjectDn != null || request.NewSans != null
                },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfoReissueSn?.CaId, tenantId: caInfoReissueSn?.TenantId);

            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else if (accept.Contains("application/x-pem-file"))
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
            else
            {
                // One shape, chosen by content negotiation rather than by whether this
                // particular issuance happened to raise a diagnostic. The previous split —
                // JSON when warnings existed, a bare PEM file otherwise — meant the client
                // could not know what it was about to parse, so callers read .newSerialNumber
                // off a string on the common path and silently reported "serial unknown".
                return Ok(new
                {
                    pem = newCertPem,
                    warnings = reissueResult.Warnings,
                    diagnostics = reissueResult.Diagnostics,
                });
            }
        }

        /// <summary>
        /// Reissues a certificate from an existing CSR. Emits a
        /// <see cref="AuditActionType.CertificateReissued"/> record (target type
        /// <c>CertificateRequest</c>) after the new cert is persisted. Enforces tenant fence,
        /// profile.use capability, and step-up MFA before delegating to the issuance service.
        /// </summary>
        [HttpPost("csr/{csrId:guid}/reissue")]
        [Authorize(Policy = "CaOperator")]
        public async Task<IActionResult> ReissueCsrId([FromBody] ReissueCertificateRequestByCsrId request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
        {

            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            // Tenant fence.
            var fence = await EnforceTenantFenceForCsrAsync(request.CsrId);
            if (fence != null) return fence;

            // Enforce profile.use capability on the profiles referenced by the CSR
            var profileCheckReissueCsr = await EnforceProfileUseForCsrAsync(_currentUser.User.Id, request.CsrId);
            if (profileCheckReissueCsr != null)
                return profileCheckReissueCsr;

            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.ReissueCert, request.CsrId.ToString()))
                return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

            // Interactive admin reissue; see ReissueCertId.
            var reissueResult = await _certificateIssuanceService.ReissueCertificateAsync(
                null,
                null,
                request.CsrId,
                request.NotBefore,
                request.NotAfter,
                request.NewSubjectDn,
                request.NewSans,
                ValidityCeilingEnforcement.HonourTenantPolicy);
            var newCertPem = reissueResult.Pem;
            var certDer = CertificateUtil.ParseFromPem(newCertPem);
            var certName = CertificateUtil.ParseCnFromPem(newCertPem);
            var certEntry = await _dbContext.Certificates.ResolveBySerialOrNullAsync(CertificateUtil.FormatSerialNumber(certDer.SerialNumber));

            if (certEntry == null)
            {
                return NotFound("Newly generated certificate not found in the database.");
            }

            // ACL inheritance is done inside ReissueCertificateAsync, which is the only place
            // that still knows which certificate was replaced. Calling it again from here was a
            // duplicate of the same operation, and it had no way to identify the predecessor —
            // which is why the service used to guess by subject DN.

            // Emit CertificateReissued for the CSR-id reissue
            // path. Target entity is the CertificateRequest because that is the input
            // identifier the operator chose; the issued cert serial appears in the details
            // payload for cross-reference.
            var caInfoReissueCsr = await ResolveCaFromSigningProfileAsync(certEntry.SigningProfileId);
            await _audit.LogAsync(AuditActionType.CertificateReissued, _currentUser.User.Id, _currentUser.User.Username,
                "CertificateRequest", request.CsrId.ToString(),
                new
                {
                    CsrId = request.CsrId,
                    IssuedSerial = certEntry.SerialNumber,
                    SubjectDN = certEntry.SubjectDN,
                    NewSubjectDn = request.NewSubjectDn,
                    NewSans = request.NewSans,
                    OverridesApplied = request.NewSubjectDn != null || request.NewSans != null
                },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                certificateAuthorityId: caInfoReissueCsr?.CaId, tenantId: caInfoReissueCsr?.TenantId);

            var accept = Request.Headers.Accept.ToString().ToLowerInvariant();
            if (accept.Contains("application/x-x509-cert") || accept.Contains("application/pkix-cert") || accept.Contains("application/octet-stream") || accept.Contains(".der") || accept.Contains(".cer"))
            {
                var fileName = $"{certName}.cer";
                return File(certDer.GetEncoded(), "application/x-x509-cert", fileName);
            }
            else if (accept.Contains("application/x-pem-file"))
            {
                var fileName = $"{certName}.pem";
                return File(Encoding.UTF8.GetBytes(newCertPem), "application/x-pem-file", fileName);
            }
            else
            {
                // One shape, chosen by content negotiation rather than by whether this
                // particular issuance happened to raise a diagnostic. The previous split —
                // JSON when warnings existed, a bare PEM file otherwise — meant the client
                // could not know what it was about to parse, so callers read .newSerialNumber
                // off a string on the common path and silently reported "serial unknown".
                return Ok(new
                {
                    pem = newCertPem,
                    warnings = reissueResult.Warnings,
                    diagnostics = reissueResult.Diagnostics,
                });
            }
        }

        /// <summary>
        /// Enforces profile.use capability on both the CertProfile and SigningProfile
        /// referenced by a CSR. Returns null on allow, a 403 result on deny.
        /// </summary>
        private async Task<IActionResult?> EnforceProfileUseForCsrAsync(Guid userId, Guid csrId)
        {
            var csr = await _dbContext.CertificateRequests
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == csrId);
            if (csr == null)
                return NotFound();

            if (csr.CertProfileId.HasValue)
            {
                if (!await _authService.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "CertProfile", csr.CertProfileId.Value))
                    return StatusCode(403, new { error = "You do not have profile.use access on this certificate profile." });
            }

            if (csr.SigningProfileId.HasValue)
            {
                if (!await _authService.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "SigningProfile", csr.SigningProfileId.Value))
                    return StatusCode(403, new { error = "You do not have profile.use access on this signing profile." });
            }

            return null;
        }

        /// <summary>
        /// Enforces profile.use capability on both profiles referenced by a certificate's
        /// original CSR. Looks up the certificate by ID or serial number, then finds the
        /// associated CSR. Returns null on allow, a 403 result on deny.
        /// </summary>
        private async Task<IActionResult?> EnforceProfileUseForCertAsync(Guid userId, Guid? certId, string? serial)
        {
            Shared.Entities.CertificateEntity? cert = null;
            if (certId.HasValue)
                cert = await _dbContext.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == certId.Value);
            else if (!string.IsNullOrWhiteSpace(serial))
                cert = await _dbContext.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
            if (cert == null)
                return NotFound();

            var csr = await _dbContext.CertificateRequests
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.IssuedCertificateId == cert.CertificateId);
            if (csr == null)
                return NotFound();

            if (csr.CertProfileId.HasValue)
            {
                if (!await _authService.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "CertProfile", csr.CertProfileId.Value))
                    return StatusCode(403, new { error = "You do not have profile.use access on this certificate profile." });
            }

            if (csr.SigningProfileId.HasValue)
            {
                if (!await _authService.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "SigningProfile", csr.SigningProfileId.Value))
                    return StatusCode(403, new { error = "You do not have profile.use access on this signing profile." });
            }

            return null;
        }
    }
}
