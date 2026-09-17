using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using Serilog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;

namespace ModularCA.API.Controllers.v1.User;

/// <summary>
/// User endpoints for submitting and viewing certificate signing requests,
/// including CSR parsing and profile validation.
/// </summary>
[ApiController]
[Route("api/v1/user/requests")]
[Authorize]
public class UserCertSignRequestController(
    ICsrService csrService,
    ICertificateStore certService,
    ICurrentUserService currentUser,
    ModularCADbContext db
) : ControllerBase
{
    private readonly ICsrService _csrService = csrService;
    private readonly ICertificateStore _certService = certService;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly ModularCADbContext _db = db;

    /// <summary>
    /// Lists all certificate signing requests submitted by the authenticated user, ordered by most recent first.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaUser")]
    public async Task<IActionResult> GetMyRequests()
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        var requests = await _db.CertificateRequests
            .Where(r => r.RequestorUserId == _currentUser.User.Id)
            .OrderByDescending(r => r.SubmittedAt)
            .Select(r => new
            {
                r.Id,
                SubjectDN = r.Subject,
                r.Status,
                r.SubmittedAt,
                r.CertProfileId,
                r.SigningProfileId,
                IssuedCertificateSerial = r.IssuedCertificate != null ? r.IssuedCertificate.SerialNumber : null
            })
            .ToListAsync();

        return Ok(requests);
    }

    /// <summary>
    /// Generates a certificate signing request with a key pair the server generates. The
    /// private key is returned in this response, once, and is not stored by the CA.
    /// </summary>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRequest, CaTarget.SigningProfile, "request.SigningProfileId")]
    public async Task<IActionResult> Generate([FromBody] CreateCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();
        var generated = await _csrService.GenerateCsrAsync(request, _currentUser.User.Id);
        return Ok(new { csrId = generated.RequestId, csr = generated.CsrPem, privateKey = generated.PrivateKeyPem });
    }

    [HttpPost("upload")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRequest, CaTarget.SigningProfile, "request.SigningProfileId")]
    public async Task<IActionResult> UploadCsrRequest([FromBody] UploadCsrRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();
        var pem = await _csrService.UploadCsrAsync(request.Pem, request.CertificateProfileId, request.SigningProfileId, _currentUser.User.Id,
            request.SubjectOverrides, request.SanOverrides);
        if (pem == null)
            return BadRequest(new { error = "Failed to upload CSR" });
        return Ok();
    }

    /// <summary>
    /// Requests a certificate with a server-generated key pair. The server generates the key,
    /// builds a PKCS#10 CSR and submits it for approval; the certificate is NOT issued
    /// immediately, an admin must approve and issue it. The private key is returned in this
    /// response, once, and is not stored by the CA: the requester keeps it and pairs it with the
    /// certificate when the request is issued.
    /// </summary>
    [HttpPost("request-with-key")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRequest, CaTarget.SigningProfile, "req.SigningProfileId")]
    public async Task<IActionResult> RequestWithServerKey([FromBody] IssueWithKeyRequest req)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        if (req.Subject == null || req.Subject.Count == 0)
            return BadRequest(new { error = "Subject fields are required." });
        if (req.CertProfileId == Guid.Empty)
            return BadRequest(new { error = "Certificate profile ID is required." });
        if (req.SigningProfileId == Guid.Empty)
            return BadRequest(new { error = "Signing profile ID is required." });

        // Validate signing profile exists and user has access to its CA
        var signingProfile = await _db.SigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(sp => sp.Id == req.SigningProfileId);
        if (signingProfile == null)
            return BadRequest(new { error = "Signing profile not found." });

        if (signingProfile.IssuerId != null)
        {
            var ca = await _db.CertificateAuthorities.AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == signingProfile.IssuerId);
            if (ca != null)
            {
                var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
                if (tenantIds != null && !tenantIds.Contains(ca.TenantId))
                    return BadRequest(new { error = "You do not have access to the CA associated with this signing profile." });
            }
        }

        string? signatureAlgorithm;
        try
        {
            signatureAlgorithm = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(req.KeyAlgorithm, req.KeySize);
        }
        catch (ArgumentException)
        {
            signatureAlgorithm = null;
        }
        if (signatureAlgorithm == null)
            return BadRequest(new { error = $"Unsupported key algorithm: {req.KeyAlgorithm}" });

        // Build subject DN (escape values per RFC 4514 to prevent DN injection)
        var dnParts = req.Subject.Where(kvp => !string.IsNullOrWhiteSpace(kvp.Value))
            .Select(kvp => $"{kvp.Key}={EscapeDnValue(kvp.Value)}");
        var subjectDn = string.Join(",", dnParts);
        if (string.IsNullOrWhiteSpace(subjectDn))
            return BadRequest(new { error = "Subject DN must contain at least one field." });

        var keySize = req.KeyAlgorithm.ToUpperInvariant() == "ED25519" ? "Ed25519" : req.KeySize;
        var keyPair = KeyGenerationUtil.GenerateKeyPair(req.KeyAlgorithm, keySize);

        // Build PKCS#10 CSR
        var subject = new X509Name(subjectDn);
        DerSet? attributes = null;

        if (req.Sans != null && req.Sans.Count > 0)
        {
            var sanGeneralNames = new List<GeneralName>();
            foreach (var san in req.Sans)
            {
                var gn = san.Type.ToUpperInvariant() switch
                {
                    "DNS" => new GeneralName(GeneralName.DnsName, san.Value),
                    "IP" => new GeneralName(GeneralName.IPAddress, san.Value),
                    "EMAIL" => new GeneralName(GeneralName.Rfc822Name, san.Value),
                    "URI" => new GeneralName(GeneralName.UniformResourceIdentifier, san.Value),
                    _ => new GeneralName(GeneralName.DnsName, san.Value)
                };
                sanGeneralNames.Add(gn);
            }
            var sanExtension = new GeneralNames(sanGeneralNames.ToArray());
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, sanExtension);
            var attr = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate()));
            attributes = new DerSet(attr);
        }

        var csr = new Pkcs10CertificationRequest(signatureAlgorithm, subject, keyPair.Public, attributes, keyPair.Private);

        string csrPem;
        using (var sw = new StringWriter())
        {
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(csr);
            csrPem = sw.ToString();
        }

        var sanOverrides = req.Sans?.Where(s => !string.IsNullOrWhiteSpace(s.Value))
            .Select(s => new SanOverride { Type = s.Type, Value = s.Value }).ToList();

        // Upload through the standard CSR pipeline (validates, stores entity)
        await _csrService.UploadCsrAsync(csrPem, req.CertProfileId, req.SigningProfileId,
            _currentUser.User.Id, req.Subject, sanOverrides);

        var csrEntity = await _db.CertificateRequests
            .Where(c => c.CSR == csrPem && c.RequestorUserId == _currentUser.User.Id)
            .OrderByDescending(c => c.SubmittedAt)
            .FirstOrDefaultAsync();

        // The key is in this response and nowhere else: the CA does not keep it.
        return Ok(new
        {
            message = "Certificate request submitted with a server-generated key pair. The private key is delivered once, in this response, and is not kept; store it now and pair it with the certificate once the request is issued.",
            requestId = csrEntity?.Id,
            hasPrivateKey = true,
            csr = csrPem,
            privateKey = CertificateUtil.ExportPrivateKeyToPem(keyPair.Private),
        });
    }

    /// <summary>
    /// Parses a PEM-encoded CSR and returns subject, SANs, key info, and signature validation.
    /// </summary>
    [HttpPost("parse-csr")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRequest, CaTarget.AnyCa)]
    public IActionResult ParseCsr([FromBody] ParseCsrRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Pem))
            return BadRequest(new { error = "PEM CSR string is required." });

        try
        {
            var result = CertificateUtil.ParseCsrDetailed(request.Pem);
            if (result.ValidationErrors.Count > 0 && !result.Valid)
                return BadRequest(new { error = "Failed to parse CSR", details = result.ValidationErrors });
            return Ok(result);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to parse CSR in user CSR detail endpoint");
            return BadRequest(new { error = "Failed to parse CSR. The submitted data may be malformed." });
        }
    }

    /// <summary>
    /// Validates parsed CSR subject and SAN fields against a request profile's rules.
    /// Preview only (nothing is stored), but the patterns are operator-authored and the values are
    /// caller-supplied, so matching goes through <see cref="ProfileRegex"/> under a bounded timeout.
    /// A pattern that times out or does not compile is reported as an error against the profile —
    /// never as "valid" — so a broken profile is visible here instead of previewing as a pass.
    /// </summary>
    [HttpPost("validate-against-profile")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRequest, CaTarget.AnyCa)]
    public async Task<IActionResult> ValidateAgainstProfile([FromBody] ValidateAgainstProfileRequest request)
    {
        var profile = await _db.RequestProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == request.RequestProfileId);
        if (profile == null)
            return NotFound(new { error = "Request profile not found." });

        var dnRules = JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(profile.SubjectDnRules) ?? new();
        var sanRules = JsonSerializer.Deserialize<SanRules>(profile.SanRules) ?? new();

        var response = new ValidateAgainstProfileResponse { Valid = true };

        foreach (var rule in dnRules)
        {
            var hasValue = request.Subject.TryGetValue(rule.Field, out var value) && !string.IsNullOrWhiteSpace(value);
            var result = new FieldValidationResult { Field = rule.Field };

            if (rule.Requirement == "Forbidden")
            {
                result.Status = hasValue ? "error" : "valid";
                result.Message = hasValue ? "This field is not allowed by the profile." : "Forbidden (correctly absent).";
                if (hasValue) response.Valid = false;
            }
            else if (rule.Requirement == "Required")
            {
                if (!hasValue) { result.Status = "error"; result.Message = "This field is required."; response.Valid = false; }
                else { result = ValidateFieldValue(rule, value!); if (result.Status == "error") response.Valid = false; }
            }
            else
            {
                if (!hasValue) { result.Status = "warning"; result.Message = "Optional field, not provided."; }
                else { result = ValidateFieldValue(rule, value!); if (result.Status == "error") response.Valid = false; }
            }
            response.FieldResults.Add(result);
        }

        foreach (var kvp in request.Subject)
        {
            if (!string.IsNullOrWhiteSpace(kvp.Value) && !dnRules.Any(r => r.Field == kvp.Key))
                response.FieldResults.Add(new FieldValidationResult { Field = kvp.Key, Status = "warning", Message = "No rule defined for this field in the profile." });
        }

        var sanCountsByType = new Dictionary<string, int>();
        foreach (var san in request.Sans)
        {
            var sanResult = new SanValidationResult { Type = san.Type, Value = san.Value };
            if (!sanRules.AllowedTypes.Contains(san.Type, StringComparer.OrdinalIgnoreCase))
            {
                sanResult.Status = "error"; sanResult.Message = $"SAN type '{san.Type}' is not allowed."; response.Valid = false;
            }
            else if (sanRules.Rules.TryGetValue(san.Type, out var typeRule) && !string.IsNullOrWhiteSpace(typeRule.Regex))
            {
                // Bounded, fail-closed match. A pattern that cannot be evaluated used to report
                // "valid" so as not to penalise the user; that presented a broken profile as a
                // passing one, so it is now an error that names the profile as the cause.
                switch (ProfileRegex.Evaluate(san.Value, typeRule.Regex))
                {
                    case ProfileRegexOutcome.Match:
                        sanResult.Status = "valid";
                        break;
                    case ProfileRegexOutcome.NoMatch:
                        sanResult.Status = "error";
                        sanResult.Message = $"Does not match pattern: {typeRule.Regex}";
                        response.Valid = false;
                        break;
                    default:
                        Log.Warning(
                            "ValidateAgainstProfile: SAN pattern for type '{SanType}' in profile {ProfileId} could not be evaluated ('{Pattern}'); reporting as unevaluable.",
                            san.Type, request.RequestProfileId, typeRule.Regex);
                        sanResult.Status = "error";
                        sanResult.Message = $"The profile's pattern for SAN type '{san.Type}' could not be evaluated (invalid or too slow); this value could not be validated. Ask an administrator to review the profile.";
                        response.Valid = false;
                        break;
                }
            }
            else { sanResult.Status = "valid"; }

            // Type-shape gate: see Admin controller comment. Catches IP/DNS swaps so
            // BouncyCastle's GeneralName ctor doesn't throw at issuance time.
            if (sanResult.Status != "error")
            {
                var shapeError = SanShapeValidator.ValidateShape(san.Type, san.Value);
                if (shapeError != null)
                {
                    sanResult.Status = "error";
                    sanResult.Message = shapeError;
                    response.Valid = false;
                }
            }

            sanCountsByType.TryGetValue(san.Type, out var count);
            sanCountsByType[san.Type] = count + 1;
            response.SanResults.Add(sanResult);
        }

        foreach (var kvp in sanCountsByType)
        {
            if (sanRules.Rules.TryGetValue(kvp.Key, out var typeRule) && kvp.Value > typeRule.MaxCount)
            {
                foreach (var sr in response.SanResults.Where(s => s.Type == kvp.Key).Reverse().Take(kvp.Value - typeRule.MaxCount))
                { sr.Status = "error"; sr.Message = $"Exceeds max count of {typeRule.MaxCount} for {kvp.Key}."; response.Valid = false; }
            }
        }

        if (sanRules.Required && request.Sans.Count == 0)
        {
            response.SanResults.Add(new SanValidationResult { Type = "", Value = "", Status = "error", Message = "At least one SAN is required." });
            response.Valid = false;
        }

        return Ok(response);
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
    /// Validates a subject DN field value against its profile rule.
    /// A malformed admin-supplied regex (bad escape, unterminated group) previously had its
    /// <see cref="ArgumentException"/> swallowed, which meant the rule was treated as passing —
    /// effectively matching everything. The fail-closed contract is: any pattern that cannot be
    /// evaluated marks the field as an error so the profile author can fix it.
    /// Matching goes through <see cref="ProfileRegex"/>, which also bounds the match with a
    /// timeout — without one, an operator pattern with nested quantifiers plus a crafted field
    /// value pins a CPU core (ReDoS), and a timeout now lands in the same fail-closed branch as an
    /// uncompilable pattern rather than being reported as a pass.
    /// </summary>
    private static FieldValidationResult ValidateFieldValue(SubjectDnFieldRule rule, string value)
    {
        var result = new FieldValidationResult { Field = rule.Field, Status = "valid" };
        if (rule.MaxLength.HasValue && value.Length > rule.MaxLength.Value)
        { result.Status = "error"; result.Message = $"Exceeds max length of {rule.MaxLength.Value}."; return result; }
        if (!string.IsNullOrWhiteSpace(rule.Regex))
        {
            switch (ProfileRegex.Evaluate(value, rule.Regex))
            {
                case ProfileRegexOutcome.Match:
                    break;
                case ProfileRegexOutcome.NoMatch:
                    result.Status = "error";
                    result.Message = $"Does not match pattern: {rule.Regex}";
                    return result;
                default:
                    Log.Warning(
                        "ValidateFieldValue: profile regex for field '{Field}' pattern '{Pattern}' could not be evaluated (invalid or timed out); failing closed (rejecting value).",
                        rule.Field, rule.Regex);
                    result.Status = "error";
                    result.Message = $"Profile regex for field '{rule.Field}' could not be evaluated; value cannot be validated.";
                    return result;
            }
        }
        if (!string.IsNullOrWhiteSpace(rule.FixedValue) && value != rule.FixedValue)
        { result.Status = "error"; result.Message = $"Must be '{rule.FixedValue}' (fixed by profile)."; return result; }
        return result;
    }
}

/// <summary>Request body for the CSR parse endpoint.</summary>
public class ParseCsrRequest
{
    [Required, MaxLength(65536)]
    public string Pem { get; set; } = string.Empty;
}
