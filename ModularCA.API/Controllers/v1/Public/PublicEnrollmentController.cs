using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Serilog;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Public endpoints for QR code and link-based certificate enrollment.
/// The enrollment token embedded in the URL serves as authentication — no login required.
/// </summary>
[ApiController]
[Route("api/v1/public/enroll")]
[AllowAnonymous]
public class PublicEnrollmentController(
    IEnrollmentTokenService tokenService,
    ICertificateIssuanceService issuanceService,
    RequestProfileValidationService requestProfileValidation,
    IProfileResolutionService profileResolution,
    ModularCADbContext db,
    IAuditService audit) : ControllerBase
{
    /// <summary>
    /// Validates an enrollment token and returns the enrollment context (CA name, cert profile info,
    /// subject restrictions) so the client can render an enrollment form.
    /// </summary>
    [HttpGet("{token}")]
    public async Task<IActionResult> GetEnrollmentInfo(string token)
    {
        var entity = await tokenService.GetByTokenAsync(token);
        if (entity == null)
            return NotFound(new { error = "Invalid, expired, or exhausted enrollment token." });

        // Resolve profile names for display
        string? certProfileName = null;
        string? certProfileDescription = null;
        string? signingProfileName = null;
        string? caName = null;

        if (entity.CertProfileId != null)
        {
            var cp = await db.CertProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == entity.CertProfileId);
            certProfileName = cp?.Name;
            certProfileDescription = cp?.Description;
        }

        if (entity.SigningProfileId != null)
        {
            var sp = await db.SigningProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == entity.SigningProfileId);
            signingProfileName = sp?.Name;

            // Try to resolve the CA name from the signing profile's issuer
            if (sp?.IssuerId != null)
            {
                var caCert = await db.Certificates.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CertificateId == sp.IssuerId);
                if (caCert != null)
                {
                    var caEntity = await db.CertificateAuthorities.AsNoTracking()
                        .FirstOrDefaultAsync(ca => ca.CertificateId == caCert.CertificateId);
                    caName = caEntity?.Name;
                }
            }
        }

        // Fall back to default CA name
        if (caName == null)
        {
            var defaultCa = await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.IsEnabled)
                .OrderByDescending(ca => ca.IsDefault)
                .FirstOrDefaultAsync();
            caName = defaultCa?.Name ?? "ModularCA";
        }

        return Ok(new
        {
            caName,
            certProfileName,
            certProfileDescription,
            signingProfileName,
            subjectRestriction = entity.SubjectRestriction,
            sanRestriction = entity.SANRestriction,
            expiresAt = entity.ExpiresAt,
            usesRemaining = entity.MaxUses > 0 ? entity.UsesRemaining : (int?)null
        });
    }

    /// <summary>
    /// Accepts a PEM-encoded CSR, validates it against the enrollment token's profile constraints,
    /// issues the certificate (or queues it for approval), and returns the PEM certificate chain.
    /// The enrollment token is consumed (one use deducted) on successful submission.
    /// Returns 400 on invalid token or CSR input, 503 when the operator has not finished
    /// configuring a CA or enrollment profile (setup incomplete), and 500 on unknown
    /// server-side issuance failures.
    /// </summary>
    [HttpPost("{token}")]
    public async Task<IActionResult> SubmitEnrollment(string token, [FromBody] QrEnrollmentRequest request)
    {
        // Validate the token exists and is still usable
        var entity = await tokenService.GetByTokenAsync(token);
        if (entity == null)
            return BadRequest(new { error = "Invalid, expired, or exhausted enrollment token." });

        if (string.IsNullOrWhiteSpace(request.CsrPem))
            return BadRequest(new { error = "CSR (PEM-encoded PKCS#10) is required." });

        // Parse the CSR
        CertificateUtil.ParsedCsrInfo parsedCsr;
        try
        {
            parsedCsr = CertificateUtil.ParseCsr(request.CsrPem);
        }
        catch (Exception ex)
        {
            // Anonymous endpoint: do NOT log raw CSR content or exception message, since a hostile
            // caller could otherwise grow the log with attacker-chosen bytes. Log a short fingerprint
            // of the CSR plus caller IP + exception class for correlation only.
            var csrHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(request.CsrPem ?? string.Empty)))[..16];
            var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            Log.Warning(
                "Public enrollment received invalid CSR. ExceptionType={ExceptionType} RemoteIp={RemoteIp} CsrHash={CsrHash}",
                ex.GetType().Name, remoteIp, csrHash);
            return BadRequest(new { error = "Enrollment failed. Contact administrator if the problem persists." });
        }

        var subject = parsedCsr.SubjectName;
        var sanJson = JsonSerializer.Serialize(parsedCsr.SubjectAlternativeNames);

        // Validate subject restriction from the token
        if (!string.IsNullOrWhiteSpace(entity.SubjectRestriction) &&
            !string.IsNullOrWhiteSpace(subject) &&
            !subject.Contains(entity.SubjectRestriction, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new { error = $"CSR subject does not match token restriction '{entity.SubjectRestriction}'." });
        }

        // Resolve profiles: token's explicit profiles take priority, then fall back to default CA config
        Guid signingProfileId;
        Guid certProfileId;

        if (entity.SigningProfileId != null && entity.CertProfileId != null)
        {
            signingProfileId = entity.SigningProfileId.Value;
            certProfileId = entity.CertProfileId.Value;
        }
        else
        {
            // Fall back to the default CA's configuration for the "QR" pseudo-protocol
            // Use the default CA to find a suitable protocol config, or fall back to any enabled config
            var defaultCa = await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.IsEnabled)
                .OrderByDescending(ca => ca.IsDefault)
                .FirstOrDefaultAsync();

            if (defaultCa == null)
                return StatusCode(503, new { error = "No enabled Certificate Authority is configured. The system is not ready to accept enrollments." });

            // Try to find a protocol config with profiles, preferring EST as the most common enrollment protocol
            var protocolConfig = await db.CaProtocolConfigs.AsNoTracking()
                .Where(c => c.CaId == defaultCa.Id && c.IsEnabled &&
                            c.SigningProfileId != null && c.CertProfileId != null)
                .OrderByDescending(c => c.Protocol == "EST")
                .FirstOrDefaultAsync();

            if (protocolConfig?.SigningProfileId == null || protocolConfig?.CertProfileId == null)
                return StatusCode(503, new { error = "No signing or certificate profile is configured for enrollment. The system is not ready to accept enrollments." });

            signingProfileId = entity.SigningProfileId ?? protocolConfig.SigningProfileId.Value;
            certProfileId = entity.CertProfileId ?? protocolConfig.CertProfileId.Value;
        }

        var signingProfile = await db.SigningProfiles.FindAsync(signingProfileId);
        if (signingProfile == null)
            return StatusCode(503, new { error = "Configured signing profile not found. The system is not ready to accept enrollments." });

        var certProfile = await db.CertProfiles.FindAsync(certProfileId);
        if (certProfile == null)
            return StatusCode(503, new { error = "Configured certificate profile not found. The system is not ready to accept enrollments." });

        // Validate against request profile if one is configured on the token
        bool requireApproval = false;
        if (entity.RequestProfileId != null)
        {
            var (isValid, error, modifiedSubject) = await requestProfileValidation
                .ValidateAsync(entity.RequestProfileId.Value, subject, sanJson);
            if (!isValid)
                return BadRequest(new { error = error ?? "Request profile validation failed." });
            if (modifiedSubject != null)
                subject = modifiedSubject;

            // Read RequireApproval from the RESOLVED profile. Against the raw row, a CA-scoped
            // child can set RequireApproval=false under a parent that requires it, and the
            // inheritance clamp never runs — so anonymous token enrollment would issue without
            // the approval the parent policy mandates.
            var requestProfile = await profileResolution.ResolveRequestProfileAsync(entity.RequestProfileId.Value);
            if (requestProfile.RequireApproval)
                requireApproval = true;
        }

        // Consume the token (validate + decrement uses)
        var (consumed, consumeError) = await tokenService.ValidateAndConsumeAsync(token, subject, entity.Protocol);
        if (!consumed)
            return BadRequest(new { error = consumeError ?? "Token validation failed." });

        // Create the CSR entity
        var csrEntity = new CertRequestEntity
        {
            Subject = subject,
            SubjectAlternativeNames = sanJson,
            CSR = request.CsrPem,
            KeyAlgorithm = parsedCsr.KeyAlgorithm,
            KeySize = parsedCsr.KeySize,
            SignatureAlgorithm = parsedCsr.SignatureAlgorithm,
            SubmittedAt = DateTime.UtcNow,
            Status = requireApproval ? "PendingApproval" : "Pending",
            CertProfileId = certProfileId,
            CertProfile = certProfile,
            SigningProfileId = signingProfileId,
            SigningProfile = signingProfile
        };

        db.CertificateRequests.Add(csrEntity);
        await db.SaveChangesAsync();

        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        if (requireApproval)
        {
            await audit.LogAsync(AuditActionType.CsrSubmitted, null, "QR-Enrollment",
                "CertificateRequest", csrEntity.Id.ToString(),
                new { Subject = subject, Protocol = "QR", Status = "PendingApproval" },
                sourceIp);

            return Accepted(new
            {
                status = "pending_approval",
                message = "Your certificate request has been submitted and requires administrator approval.",
                csrId = csrEntity.Id
            });
        }

        // Issue the certificate immediately
        var maxValidity = Iso8601ParserUtil.ParseIso8601(certProfile.ValidityPeriodMax ?? "P1Y");
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.Add(maxValidity);

        string certPem;
        try
        {
            var issuanceResult = await issuanceService.IssueCertificateAsync(
                csrEntity.Id, notBefore, notAfter);
            certPem = issuanceResult.Pem;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Public enrollment certificate issuance failed for CSR {CsrId}", csrEntity.Id);
            await audit.LogAsync(AuditActionType.QrEnrollmentCompleted, null, "QR-Enrollment",
                "CertificateRequest", csrEntity.Id.ToString(),
                new { Subject = subject, Error = "Certificate issuance failed" },
                sourceIp, success: false, errorMessage: "Certificate issuance failed");

            return StatusCode(500, new { error = "Enrollment failed. Contact administrator if the problem persists." });
        }

        // Retrieve the issued cert info for audit
        var issuedCert = await db.CertificateRequests
            .Where(c => c.Id == csrEntity.Id)
            .Select(c => c.IssuedCertificate)
            .FirstOrDefaultAsync();

        await audit.LogAsync(AuditActionType.QrEnrollmentCompleted, null, "QR-Enrollment",
            "Certificate", issuedCert?.SerialNumber,
            new { Subject = subject, Protocol = "QR", TokenId = entity.Id },
            sourceIp);

        return Ok(new
        {
            status = "issued",
            certificatePem = certPem,
            serialNumber = issuedCert?.SerialNumber,
            subject = issuedCert?.SubjectDN,
            notBefore,
            notAfter
        });
    }

    /// <summary>
    /// Serves a minimal, mobile-friendly HTML enrollment page for the given token.
    /// This standalone page validates the token, accepts a CSR paste, and returns the issued certificate.
    /// </summary>
    [HttpGet("{token}/page")]
    [Produces("text/html")]
    public async Task<IActionResult> GetEnrollmentPage(string token)
    {
        var entity = await tokenService.GetByTokenAsync(token);
        if (entity == null)
            return Content(BuildErrorPage("Invalid, expired, or exhausted enrollment token."), "text/html");

        // Resolve CA name for display
        string caName = "ModularCA";
        string certType = "Certificate";

        if (entity.CertProfileId != null)
        {
            var cp = await db.CertProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == entity.CertProfileId);
            certType = cp?.Name ?? "Certificate";
        }

        if (entity.SigningProfileId != null)
        {
            var sp = await db.SigningProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == entity.SigningProfileId);
            if (sp?.IssuerId != null)
            {
                var caCert = await db.Certificates.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.CertificateId == sp.IssuerId);
                if (caCert != null)
                {
                    var caEntity = await db.CertificateAuthorities.AsNoTracking()
                        .FirstOrDefaultAsync(ca => ca.CertificateId == caCert.CertificateId);
                    if (caEntity != null) caName = caEntity.Name;
                }
            }
        }

        if (caName == "ModularCA")
        {
            var defaultCa = await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.IsEnabled)
                .OrderByDescending(ca => ca.IsDefault)
                .FirstOrDefaultAsync();
            if (defaultCa != null) caName = defaultCa.Name;
        }

        var html = BuildEnrollmentPage(token, caName, certType, entity.SubjectRestriction);
        return Content(html, "text/html");
    }

    /// <summary>
    /// Builds a minimal responsive HTML enrollment page that works on mobile browsers.
    /// </summary>
    private static string BuildEnrollmentPage(string token, string caName, string certType, string? subjectHint)
    {
        var apiBase = $"api/v1/public/enroll/{Uri.EscapeDataString(token)}";
        return $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Certificate Enrollment - {{System.Net.WebUtility.HtmlEncode(caName)}}</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                       background: #0f172a; color: #e2e8f0; min-height: 100vh;
                       display: flex; align-items: center; justify-content: center; padding: 1rem; }
                .card { background: #1e293b; border-radius: 12px; padding: 2rem; max-width: 500px;
                        width: 100%; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
                h1 { font-size: 1.25rem; margin-bottom: 0.25rem; color: #f1f5f9; }
                .subtitle { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }
                .badge { display: inline-block; background: #1d4ed8; color: #dbeafe; font-size: 0.75rem;
                         padding: 2px 8px; border-radius: 4px; margin-bottom: 1rem; }
                label { display: block; font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.25rem; }
                textarea { width: 100%; min-height: 160px; background: #0f172a; border: 1px solid #334155;
                           color: #e2e8f0; border-radius: 8px; padding: 0.75rem; font-family: monospace;
                           font-size: 0.8rem; resize: vertical; }
                textarea:focus { outline: none; border-color: #3b82f6; }
                .hint { font-size: 0.75rem; color: #64748b; margin-top: 0.25rem; margin-bottom: 1rem; }
                .btn { width: 100%; padding: 0.75rem; border: none; border-radius: 8px; font-size: 1rem;
                       font-weight: 600; cursor: pointer; transition: background 0.2s; }
                .btn-primary { background: #2563eb; color: white; }
                .btn-primary:hover { background: #1d4ed8; }
                .btn-primary:disabled { background: #334155; color: #64748b; cursor: not-allowed; }
                .btn-download { background: #059669; color: white; margin-top: 0.75rem; }
                .btn-download:hover { background: #047857; }
                .result { margin-top: 1.5rem; }
                .result-success { background: #064e3b; border: 1px solid #059669; border-radius: 8px; padding: 1rem; }
                .result-error { background: #450a0a; border: 1px solid #dc2626; border-radius: 8px; padding: 1rem; }
                .result textarea { min-height: 120px; background: #022c22; border-color: #065f46; }
                .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid #64748b;
                           border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite;
                           vertical-align: middle; margin-right: 0.5rem; }
                @keyframes spin { to { transform: rotate(360deg); } }
                .info-row { display: flex; justify-content: space-between; font-size: 0.8rem;
                            padding: 0.25rem 0; border-bottom: 1px solid #1e293b; }
                .info-label { color: #64748b; }
                .info-value { color: #e2e8f0; font-family: monospace; font-size: 0.75rem; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>{{System.Net.WebUtility.HtmlEncode(caName)}}</h1>
                <p class="subtitle">Certificate Enrollment</p>
                <span class="badge">{{System.Net.WebUtility.HtmlEncode(certType)}}</span>
                {{(subjectHint != null ? $"<p class=\"hint\">Subject must include: <strong>{System.Net.WebUtility.HtmlEncode(subjectHint)}</strong></p>" : "")}}

                <div id="form-section">
                    <label for="csr">Paste your CSR (PEM format)</label>
                    <textarea id="csr" placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"></textarea>
                    <p class="hint">Generate a CSR using: openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem</p>
                    <button class="btn btn-primary" id="submit-btn" onclick="submitCSR()">Submit CSR &amp; Get Certificate</button>
                </div>

                <div id="result-section" class="result" style="display:none;"></div>
            </div>
            <script>
                function el(tag, attrs, children) {
                    const e = document.createElement(tag);
                    if (attrs) Object.entries(attrs).forEach(([k, v]) => {
                        if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
                        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
                        else e.setAttribute(k, v);
                    });
                    if (children) (Array.isArray(children) ? children : [children]).forEach(c => {
                        e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
                    });
                    return e;
                }
                function infoRow(label, value, extraStyle) {
                    const row = el('div', { class: 'info-row', style: extraStyle || {} });
                    row.appendChild(el('span', { class: 'info-label' }, label));
                    row.appendChild(el('span', { class: 'info-value' }, value));
                    return row;
                }
                async function submitCSR() {
                    const csrPem = document.getElementById('csr').value.trim();
                    if (!csrPem) { alert('Please paste a PEM-encoded CSR.'); return; }
                    if (!csrPem.includes('BEGIN CERTIFICATE REQUEST')) {
                        alert('CSR must be in PEM format (BEGIN CERTIFICATE REQUEST).'); return;
                    }
                    const btn = document.getElementById('submit-btn');
                    btn.disabled = true;
                    btn.textContent = '';
                    const spinner = el('span', { class: 'spinner' });
                    btn.appendChild(spinner);
                    btn.appendChild(document.createTextNode('Submitting...'));
                    try {
                        const resp = await fetch('/{{apiBase}}', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ csrPem: csrPem })
                        });
                        const data = await resp.json();
                        const section = document.getElementById('result-section');
                        section.style.display = 'block';
                        section.textContent = '';
                        if (resp.ok && data.status === 'issued') {
                            const wrapper = el('div', { class: 'result-success' });
                            wrapper.appendChild(el('p', { style: { fontWeight: '600', color: '#34d399', marginBottom: '0.5rem' } }, 'Certificate Issued'));
                            wrapper.appendChild(infoRow('Serial', data.serialNumber || '-'));
                            wrapper.appendChild(infoRow('Subject', data.subject || '-'));
                            wrapper.appendChild(infoRow('Valid Until', new Date(data.notAfter).toLocaleDateString(), { marginBottom: '0.75rem' }));
                            wrapper.appendChild(el('label', null, 'Certificate (PEM)'));
                            const ta = el('textarea', { readonly: 'readonly' });
                            ta.value = data.certificatePem || '';
                            ta.addEventListener('click', function() { this.select(); });
                            wrapper.appendChild(ta);
                            const dlBtn = el('button', { class: 'btn btn-download', onclick: function() { downloadCert(); } }, 'Download Certificate');
                            wrapper.appendChild(dlBtn);
                            const cpBtn = el('button', { class: 'btn btn-primary', style: { marginTop: '0.5rem' } }, 'Copy to Clipboard');
                            cpBtn.addEventListener('click', function() { copyCert(this); });
                            wrapper.appendChild(cpBtn);
                            section.appendChild(wrapper);
                            window._certPem = data.certificatePem;
                            window._certSubject = data.subject || 'certificate';
                        } else if (resp.status === 202) {
                            const wrapper = el('div', { class: 'result-success' });
                            wrapper.appendChild(el('p', { style: { fontWeight: '600', color: '#fbbf24' } }, 'Pending Approval'));
                            wrapper.appendChild(el('p', { style: { fontSize: '0.875rem', color: '#94a3b8', marginTop: '0.5rem' } }, data.message || ''));
                            section.appendChild(wrapper);
                        } else {
                            const wrapper = el('div', { class: 'result-error' });
                            wrapper.appendChild(el('p', { style: { fontWeight: '600', color: '#f87171' } }, 'Error'));
                            wrapper.appendChild(el('p', { style: { fontSize: '0.875rem', color: '#fca5a5', marginTop: '0.5rem' } }, data.error || 'Unknown error'));
                            section.appendChild(wrapper);
                        }
                    } catch (e) {
                        const section = document.getElementById('result-section');
                        section.style.display = 'block';
                        section.textContent = '';
                        const wrapper = el('div', { class: 'result-error' });
                        wrapper.appendChild(el('p', { style: { color: '#f87171' } }, 'Network error: ' + e.message));
                        section.appendChild(wrapper);
                    }
                    btn.disabled = false;
                    btn.textContent = 'Submit CSR & Get Certificate';
                }
                function downloadCert() {
                    if (!window._certPem) return;
                    const cn = (window._certSubject || 'certificate').replace(/.*CN=([^,]+).*/, '$1').trim();
                    const blob = new Blob([window._certPem], { type: 'application/x-pem-file' });
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = cn + '.pem';
                    a.click();
                }
                function copyCert(btnEl) {
                    if (!window._certPem) return;
                    navigator.clipboard.writeText(window._certPem).then(() => {
                        btnEl.textContent = 'Copied!';
                        setTimeout(() => btnEl.textContent = 'Copy to Clipboard', 2000);
                    });
                }
            </script>
        </body>
        </html>
        """;
    }

    /// <summary>
    /// Builds a minimal error page for invalid token scenarios.
    /// </summary>
    private static string BuildErrorPage(string message)
    {
        return $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Enrollment Error</title>
            <style>
                body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
                       display: flex; align-items: center; justify-content: center; min-height: 100vh; }
                .card { background: #1e293b; border-radius: 12px; padding: 2rem; max-width: 400px;
                        text-align: center; }
                .icon { font-size: 3rem; margin-bottom: 1rem; }
                h1 { font-size: 1.25rem; color: #f87171; margin-bottom: 0.5rem; }
                p { color: #94a3b8; font-size: 0.875rem; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">&#9888;</div>
                <h1>Enrollment Unavailable</h1>
                <p>{{System.Net.WebUtility.HtmlEncode(message)}}</p>
            </div>
        </body>
        </html>
        """;
    }
}

/// <summary>
/// Request body for QR code-based certificate enrollment.
/// </summary>
public class QrEnrollmentRequest
{
    /// <summary>PEM-encoded PKCS#10 Certificate Signing Request.</summary>
    public string CsrPem { get; set; } = string.Empty;
}
