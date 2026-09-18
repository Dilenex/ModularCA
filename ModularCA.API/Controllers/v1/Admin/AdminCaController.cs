using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using Serilog;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Errors;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin
{
    /// <summary>
    /// Admin endpoints for managing Certificate Authorities including creation, listing, and hierarchy management.
    /// Class-level <c>[Authorize]</c> ensures no action falls through the
    /// permissive branch where a forgotten attribute meant an anonymous caller could reach
    /// a handler. Every action names its own policy; the class carries none, because policies
    /// stack rather than override, and a class-level CA-scoped policy would fail closed on any
    /// mutation whose target comes from the body (CA creation) before the action's own check ran.
    /// </summary>
    [ApiController]
    [Route("api/v1/admin/authorities")]
    [Authorize]
    [NodeRole(ProcessRole.Control)]
    public class AdminCaController(ICertificateStore certService, ICurrentUserService currentUser, ModularCADbContext db, IAuditService audit, CaCreationService caCreationService, IDistributedCache cache, ISecurityAlertService alertService, ICaGroupAuthorizationService groupAuth, IKeyCeremonyService ceremonySvc, IFeatureFlagService featureFlags) : ControllerBase
    {
        private readonly ICertificateStore _certService = certService;
        private readonly ICurrentUserService _currentUser = currentUser;
        private readonly ModularCADbContext _db = db;
        private readonly IAuditService _audit = audit;
        private readonly CaCreationService _caCreation = caCreationService;
        private readonly IDistributedCache _cache = cache;
        private readonly ISecurityAlertService _alertService = alertService;
        private readonly ICaGroupAuthorizationService _groupAuth = groupAuth;
        private readonly IKeyCeremonyService _ceremonySvc = ceremonySvc;
        private readonly IFeatureFlagService _featureFlags = featureFlags;

        [HttpGet]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetCertificateAuthorities()
        {
            var query = _db.CertificateAuthorities
                .Include(ca => ca.Certificate)
                .Where(ca => !ca.IsSshCa) // SSH CAs are managed separately via /admin/ssh
                .AsNoTracking()
                .AsQueryable();

            // Filter CAs to only those belonging to the user's accessible tenants
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds != null)
                query = query.Where(ca => tenantIds.Contains(ca.TenantId));

            var cas = await query.ToListAsync();

            var result = cas.Select(ca => new
            {
                ca.Id,
                ca.Name,
                ca.Label,
                ca.Type,
                IsRoot = ca.Type == "Root",
                ca.IsDefault,
                ca.IsEnabled,
                ca.ParentCaId,
                // The CA's certificate id, not just its serial. CRL schedules and several other
                // resources key on CaCertificateId, and without this the admin UI had no way to
                // resolve one from an authority — the Create CRL Schedule form was posting the
                // CA's own id into a CaCertificateId field and always 404ing.
                ca.CertificateId,
                CertificateSerial = ca.Certificate?.SerialNumber,
                CertificateSubjectDN = ca.Certificate?.SubjectDN,
                CertificateNotAfter = ca.Certificate?.NotAfter,
            });

            return Ok(result);
        }

        /// <summary>
        /// Returns all CA certificates including system CAs, filtered by the current user's tenant access.
        /// System admins see all CA certificates; other users see only those belonging to their accessible tenants.
        /// </summary>
        [HttpGet("include-system-ca")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetAllCaCertificates()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();

            var certs = await _certService.GetAllCertificatesAsync();
            var caCerts = certs.Where(c => c.IsCA).ToList();

            // Apply tenant filtering for non-system-admins
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds != null && HttpContext.Items["IsSystemAdmin"] is not true)
            {
                var accessibleCertIds = await _db.CertificateAuthorities
                    .Where(ca => tenantIds.Contains(ca.TenantId) && ca.CertificateId != null)
                    .Select(ca => ca.CertificateId!.Value)
                    .ToListAsync();
                var accessibleCertIdSet = new HashSet<Guid>(accessibleCertIds);
                caCerts = caCerts.Where(c => accessibleCertIdSet.Contains(c.CertificateId)).ToList();
            }

            return Ok(caCerts);
        }

        /// <summary>
        /// Returns system signing CA certificates. Requires CaAuditor policy.
        /// </summary>
        [HttpGet("system-ca")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetSystemCaCertificates()
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            var certs = await _certService.GetAllCertificatesAsync();
            var caCerts = certs
                .Where(c => c.IsCA && (c.SubjectDN?.Contains("System Signing CA") ?? false))
                .ToList();
            return Ok(caCerts);
        }

        /// <summary>
        /// Retrieves CA certificate metadata by serial number. Enforces that
        /// the caller has access to the owning CA's tenant before returning the record, and
        /// collapses cross-tenant mismatches to 404 to avoid existence oracles.
        /// </summary>
        [HttpGet("{serial}")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<ActionResult<CertificateInfoModel>> GetCertificateInfo(string serial)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();
            if (!await CallerCanSeeCaCertAsync(cert.CertificateId))
                return NotFound();
            return Ok(cert);
        }

        /// <summary>
        /// Downloads a CA certificate file by serial. Applies the same
        /// tenant gate as <see cref="GetCertificateInfo"/> and returns 404 on mismatch.
        /// </summary>
        [HttpGet("{serial}/file")]
        [Authorize(Policy = "CaAuditor")]
        public async Task<IActionResult> GetCertificateFile(string serial)
        {
            await _currentUser.EnsureLoadedAsync();
            if (!_currentUser.IsAuthenticated || _currentUser.User == null)
                return Unauthorized();
            var cert = await _certService.GetCertificateInfoAsync(serial);
            if (cert == null)
                return NotFound();
            if (!await CallerCanSeeCaCertAsync(cert.CertificateId))
                return NotFound();

            var acceptHeader = Request.Headers["Accept"].ToString();
            if (acceptHeader.Contains("application/x-pem-file", StringComparison.OrdinalIgnoreCase) ||
                acceptHeader.Contains("text/plain", StringComparison.OrdinalIgnoreCase))
            {
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                var pemBytes = System.Text.Encoding.UTF8.GetBytes(cert.Pem);
                return File(pemBytes, "application/x-pem-file", fileName);
            }
            else if (acceptHeader.Contains("application/x-x509-ca-cert", StringComparison.OrdinalIgnoreCase) ||
                     acceptHeader.Contains("application/pkix-cert", StringComparison.OrdinalIgnoreCase) ||
                     acceptHeader.Contains("application/octet-stream", StringComparison.OrdinalIgnoreCase))
            {
                var certDer = CertificateUtil.ParseFromPem(cert.Pem);
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                return File(certDer.GetEncoded(), "application/x-x509-ca-cert", fileName);
            }
            else
            {
                var certName = cert.SubjectDN.Split(',')[0].Trim();
                var fileName = certName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)
                    ? certName.Substring(3).Trim()
                    : certName;
                var pemBytes = System.Text.Encoding.UTF8.GetBytes(cert.Pem);
                return File(pemBytes, "application/x-pem-file", fileName);
            }
        }

        /// <summary>
        /// Returns the CA hierarchy tree with full certificate details, protocol configs, and service URLs.
        /// System admins see all CAs; other users see only CAs belonging to their accessible tenants.
        /// </summary>
        [HttpGet("hierarchy")]
        [Authorize(Policy = "CaAuditor")]
        [ProducesResponseType(200)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> GetHierarchy()
        {
            var caQuery = _db.CertificateAuthorities
                .Include(ca => ca.Certificate)
                .AsNoTracking()
                .Where(ca => !ca.IsSshCa) // SSH CAs are managed separately via /admin/ssh — keep them out of the X.509 hierarchy
                .AsQueryable();

            // Filter CAs to only those belonging to the user's accessible tenants
            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds != null)
                caQuery = caQuery.Where(ca => tenantIds.Contains(ca.TenantId));

            var cas = await caQuery.ToListAsync();
            var caIds = cas.Select(ca => ca.Id).ToHashSet();

            var protocolConfigs = await _db.CaProtocolConfigs
                .Include(pc => pc.SigningProfile)
                .Include(pc => pc.CertProfile)
                .Where(pc => caIds.Contains(pc.CaId))
                .AsNoTracking()
                .ToListAsync();

            var caCertIds = cas.Where(ca => ca.CertificateId != null).Select(ca => ca.CertificateId!.Value).ToHashSet();
            var serviceUrls = await _db.CaServiceUrls
                .Where(su => caCertIds.Contains(su.CaCertificateId))
                .AsNoTracking()
                .ToListAsync();

            // Guard against a malformed parent chain (a ParentCaId cycle) causing unbounded
            // recursion → StackOverflowException → 500 that would blank the entire CA tree (and with
            // it the CA detail page and the Distribution service-URL tab, which both read this feed).
            var visited = new HashSet<Guid>();

            object MapCa(Shared.Entities.CertificateAuthorityEntity ca)
            {
                visited.Add(ca.Id);

                // Protocols disabled system-wide are left out here as they are on the protocol
                // configuration page: the row stays in the table, but a protocol this deployment
                // does not serve is not listed as configured on the CA.
                var caProtocols = protocolConfigs
                    .Where(pc => pc.CaId == ca.Id
                        && _featureFlags.IsEnabled(ModularCA.Shared.Enrollment.ProtocolCompatibility.FeatureFlagName(pc.Protocol)))
                    .Select(pc => new
                    {
                        pc.Protocol,
                        Enabled = pc.IsEnabled,
                        SigningProfileId = pc.SigningProfileId,
                        SigningProfileName = pc.SigningProfile?.Name,
                        CertProfileId = pc.CertProfileId,
                        CertProfileName = pc.CertProfile?.Name,
                    })
                    .ToList();

                var urls = serviceUrls.FirstOrDefault(su => su.CaCertificateId == ca.CertificateId);

                return new
                {
                    ca.Id,
                    ca.Name,
                    ca.Label,
                    ca.TenantId,
                    ca.Type,
                    IsRoot = ca.Type == "Root",
                    ca.IsDefault,
                    ca.IsEnabled,
                    ca.ParentCaId,
                    ca.OcspResponderCertificateId,
                    ca.CmpSigningCertificateId,
                    ca.CertificateId,
                    Certificate = ca.Certificate != null ? new
                    {
                        ca.Certificate.SerialNumber,
                        ca.Certificate.SubjectDN,
                        ca.Certificate.Issuer,
                        ca.Certificate.NotBefore,
                        ca.Certificate.NotAfter,
                        ca.Certificate.Thumbprints,
                        ca.Certificate.IsCA,
                        ca.Certificate.Revoked,
                        ca.Certificate.RevocationReason,
                        ca.Certificate.KeyUsagesJson,
                        ca.Certificate.ExtendedKeyUsagesJson,
                        ca.Certificate.Pem,
                    } : null,
                    // The key algorithm the CA actually has, read from its certificate. The console
                    // needs it to say, before anything is saved, that SCEP cannot run here.
                    KeyAlgorithm = ModularCA.Shared.Enrollment.ProtocolCompatibility.KeyAlgorithmOf(ca.Certificate),
                    ProtocolConfigs = caProtocols,
                    ServiceUrls = urls != null ? new
                    {
                        urls.PublicBaseUrl,
                    } : null,
                    // Recursively nest children. Skip any already-visited CA so a cycle can't loop forever.
                    Children = cas.Where(c => c.ParentCaId == ca.Id && !visited.Contains(c.Id)).Select(c => MapCa(c)).ToList()
                };
            }

            // Top level = true roots (no parent) PLUS "orphans" whose parent is not in the visible set
            // (e.g. filtered out by the tenant fence or the SSH-CA exclusion). Surfacing orphans here
            // means a CA never silently disappears from the tree just because its parent isn't visible —
            // which previously made a freshly-created sub-CA (and the apparent loss of the whole list)
            // look like the data had vanished.
            var roots = cas.Where(ca => ca.ParentCaId == null || !caIds.Contains(ca.ParentCaId.Value));
            var result = roots.Select(ca => MapCa(ca)).ToList();

            return Ok(result);
        }

        /// <summary>
        /// Update CA properties. Runtime fields (Name, Label, IsDefault, IsEnabled) take effect immediately.
        /// Requires step-up MFA verification.
        /// </summary>
        [HttpPut("{id:guid}")]
        [Authorize(Policy = "SystemOperator")]
        [RequireStepUp(StepUpOps.UpdateCa, "id")]
        public async Task<IActionResult> UpdateCa(Guid id, [FromBody] UpdateCaRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();

            var ca = await _db.CertificateAuthorities.FindAsync(id);
            if (ca == null)
                return NotFound(new { error = $"CA with ID {id} not found" });

            var changes = new List<string>();

            if (request.Name != null && request.Name != ca.Name)
            {
                ca.Name = request.Name;
                changes.Add("Name");
            }
            if (request.Label != null && request.Label != ca.Label)
            {
                ca.Label = request.Label;
                changes.Add("Label");
            }
            if (request.IsDefault.HasValue && request.IsDefault.Value != ca.IsDefault)
            {
                if (request.IsDefault.Value)
                {
                    // Clear other defaults
                    var others = await _db.CertificateAuthorities
                        .Where(c => c.IsDefault && c.Id != id)
                        .ToListAsync();
                    foreach (var other in others) other.IsDefault = false;
                }
                ca.IsDefault = request.IsDefault.Value;
                changes.Add("IsDefault");
            }
            if (request.IsEnabled.HasValue && request.IsEnabled.Value != ca.IsEnabled)
            {
                ca.IsEnabled = request.IsEnabled.Value;
                changes.Add("IsEnabled");
            }

            await _db.SaveChangesAsync();

            if (changes.Count > 0)
            {
                await _currentUser.EnsureLoadedAsync();
                await _audit.LogAsync(AuditActionType.CaUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CertificateAuthority", id.ToString(), new { Changes = changes, ca.Name, ca.Label },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: ca.Id, tenantId: ca.TenantId);
            }

            return Ok(new
            {
                message = changes.Count > 0 ? $"CA updated: {string.Join(", ", changes)}" : "No changes",
                changes,
                reissueRequired = false,
            });
        }

        /// <summary>
        /// Create an intermediate CA signed by a parent CA. Requires step-up MFA verification.
        /// Open to a tenant administrator: <c>ca.manage</c> held tenant-wide for the target tenant,
        /// with a parent in that tenant or one the caller holds <c>ca.manage</c> on. The tenant
        /// and parent come from the body, so the check is made here rather than by a route policy
        /// (see <see cref="CaCreationAccess"/>).
        /// </summary>
        [HttpPost("create-intermediate")]
        [Authorize]
        [RequireStepUp(StepUpOps.CreateCa)]
        public async Task<IActionResult> CreateIntermediate([FromBody] CreateIntermediateCaRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();

            if (!await CaCreationAccess.MayCreateIntermediateAsync(_groupAuth, _db, _currentUser.User.Id, request.TenantId, request.ParentCaId))
            {
                Log.Warning("Authorization denied for user {UserId} ({Username}) creating an intermediate CA in tenant {TenantId} under parent {ParentCaId}",
                    _currentUser.User.Id, _currentUser.User.Username, request.TenantId, request.ParentCaId);
                return StatusCode(403, new { error = "You need ca.manage for the target tenant, and for the parent CA when it belongs to another tenant." });
            }

            var parentCa = await _db.CertificateAuthorities
                .Include(ca => ca.Certificate)
                .FirstOrDefaultAsync(ca => ca.Id == request.ParentCaId && ca.IsEnabled);

            if (parentCa == null)
                return BadRequest(new { error = "Parent CA not found or disabled" });

            if (parentCa.Certificate == null)
                return BadRequest(new { error = "Parent CA has no certificate" });

            // The System Signing CA signs keystore entries only — never sub-CAs or
            // end-entity certs. Refuse to let it parent a new CA.
            if (string.Equals(parentCa.Label, "system-signing-ca", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { error = "The system signing CA cannot parent sub-CAs. Select a non-system CA as the parent." });

            // Enforce central key-algorithm policy before touching the service layer
            if (!KeyAlgorithmPolicy.IsAllowed(request.KeyAlgorithm, request.KeySize))
                return BadRequest(new { error = $"Key algorithm '{request.KeyAlgorithm}' with size/curve '{request.KeySize}' is not permitted. Allowed: RSA 2048/3072/4096/7680/8192, ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA-44/65/87, SLH-DSA-*." });

            // Check ceremony-first enforcement for this tenant
            var tenant = await _db.Tenants.FindAsync(request.TenantId);
            if (tenant?.RequireKeyCeremony == true)
            {
                var parameters = new ModularCA.Shared.Models.KeyCeremonyParameters
                {
                    SubjectCN = request.SubjectCN,
                    SubjectO = request.SubjectO,
                    SubjectOU = request.SubjectOU,
                    SubjectL = request.SubjectL,
                    SubjectST = request.SubjectST,
                    SubjectC = request.SubjectC,
                    KeyAlgorithm = request.KeyAlgorithm,
                    KeySize = request.KeySize,
                    ValidityYears = request.ValidityYears,
                    TenantId = request.TenantId,
                    ParentCaId = request.ParentCaId,
                    Label = request.Label,
                    PublicBaseUrl = request.PublicBaseUrl,
                    CertProfileId = request.CertProfileId,
                    NameConstraintsPermitted = request.NameConstraintsPermitted,
                    NameConstraintsExcluded = request.NameConstraintsExcluded,
                };
                var ceremony = await _ceremonySvc.InitiateAsync(
                    "CreateIntermediateCA",
                    $"Create intermediate CA '{request.SubjectCN}' under {parentCa.Name}",
                    string.Empty,
                    _currentUser.User.Id,
                    _currentUser.User.Username ?? string.Empty,
                    System.Text.Json.JsonSerializer.Serialize(parameters));
                return Ok(new
                {
                    requiresCeremony = true,
                    ceremonyId = ceremony.Id,
                    ceremony.Status,
                    ceremony.RequiredApprovals,
                    message = $"Key ceremony required for tenant '{tenant.Name}'. A ceremony has been created and requires {ceremony.RequiredApprovals} approval(s)."
                });
            }

            try
            {
                var newCa = await _caCreation.CreateIntermediateAsync(
                    parentCa, parentCa.Certificate,
                    request.SubjectCN, request.SubjectO, request.SubjectOU,
                    request.SubjectL, request.SubjectST, request.SubjectC,
                    request.KeyAlgorithm, request.KeySize, request.ValidityYears,
                    request.Label, request.TenantId,
                    publicBaseUrl: request.PublicBaseUrl,
                    certProfileId: request.CertProfileId,
                    nameConstraintsPermittedJson: request.NameConstraintsPermitted is { Count: > 0 } perm
                        ? System.Text.Json.JsonSerializer.Serialize(perm)
                        : null,
                    nameConstraintsExcludedJson: request.NameConstraintsExcluded is { Count: > 0 } excl
                        ? System.Text.Json.JsonSerializer.Serialize(excl)
                        : null);

                await _currentUser.EnsureLoadedAsync();
                await _audit.LogAsync(AuditActionType.CaCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CertificateAuthority", newCa.Id.ToString(),
                    new { newCa.Name, newCa.Label, newCa.Type, request.KeyAlgorithm, request.KeySize },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: newCa.Id, tenantId: request.TenantId);

                return Ok(new
                {
                    newCa.Id,
                    newCa.Name,
                    newCa.Label,
                    newCa.Type,
                    newCa.CertificateId,
                    newCa.ParentCaId,
                    message = $"Intermediate CA '{request.SubjectCN}' created successfully"
                });
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to create intermediate CA");

                // Every CA creation attempt — including
                // failures — must produce an audit trail. Wrapped so the audit emission
                // cannot mask the original error response.
                try
                {
                    await _currentUser.EnsureLoadedAsync();
                    await _audit.LogAsync(AuditActionType.CaCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                        "CertificateAuthority", request.ParentCaId.ToString(),
                        new
                        {
                            Type = "Intermediate",
                            request.SubjectCN,
                            request.Label,
                            request.KeyAlgorithm,
                            request.KeySize,
                            request.ParentCaId,
                            request.TenantId,
                        },
                        HttpContext.Connection.RemoteIpAddress?.ToString(),
                        success: false,
                        errorMessage: ex.Message,
                        tenantId: request.TenantId);
                }
                catch (Exception auditEx)
                {
                    Log.Warning(auditEx, "Audit emission for failed intermediate CA creation failed");
                }

                return DescribeCreationFailure(ex, "intermediate");
            }
        }

        /// <summary>
        /// Chooses the response for a failed CA creation: the exception's own message when the
        /// operator can act on it, and the sanitized 500 otherwise.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Both creation endpoints previously answered every failure with "An unexpected error
        /// occurred … Please try again." That is not merely unhelpful, it is wrong: the failures
        /// an operator actually hits here are configuration refusals — an ExtendedKeyUsage on a
        /// CA certificate, a key usage RFC 5480 forbids for the chosen key type, a parent CA with
        /// no usable private key — and retrying reproduces them exactly. The guards raising them
        /// already carry a sentence naming the rule and the fix; the catch discarded it.
        /// </para>
        /// <para>
        /// The type filter is the security control, not the message text. Only the three
        /// exception families that mean "the request asked for something not allowed" are
        /// forwarded; everything else keeps the sanitized 500, because arbitrary exception text
        /// carries SQL, file paths and occasionally key material. This mirrors
        /// <c>ReissueInfrastructure</c>, which already made the same trade for the same reason.
        /// </para>
        /// <para>
        /// A <see cref="RequestValidationException"/> is rethrown rather than formatted here, so
        /// <c>RequestValidationMiddleware</c> stays the single renderer for that family and its
        /// per-type fields (<c>violations</c>, <c>allowed</c>, <c>parameter</c>, <c>code</c>)
        /// survive. That is now the common case rather than a future one: the CA rules in
        /// <c>CaCertificateRules</c> and most of <c>CaCreationService</c> raise that family, so
        /// an EKU-on-a-CA refusal arrives as a coded 400 and only the stragglers still take the
        /// <see cref="InvalidOperationException"/> branch below.
        /// </para>
        /// </remarks>
        /// <param name="ex">The exception the creation attempt failed with.</param>
        /// <param name="kind">"root" or "intermediate", for the fallback message.</param>
        private IActionResult DescribeCreationFailure(Exception ex, string kind)
        {
            if (ex is RequestValidationException)
            {
                // Capture-and-throw rather than `throw ex`, which would reset the stack trace.
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
            }

            if (ex is InvalidOperationException or ArgumentException or NotSupportedException)
            {
                return BadRequest(new { error = ex.Message });
            }

            var correlationId = HttpContext.Items.TryGetValue("CorrelationId", out var cid) && cid is string s
                ? s
                : HttpContext.TraceIdentifier;

            return StatusCode(500, new
            {
                error = $"An unexpected error occurred while creating the {kind} CA. "
                      + "Contact your administrator with the correlation id below.",
                correlationId,
            });
        }

        /// <summary>
        /// Shared tenant gate for CA certificate lookups. Returns true
        /// when the caller is a system admin (all tenants), or when the owning CA's tenant
        /// is in the caller's <c>AccessibleTenantIds</c>. Also returns true when the cert is
        /// not attached to any CA record (legacy / standalone trust anchor).
        /// </summary>
        private async Task<bool> CallerCanSeeCaCertAsync(Guid certificateId)
        {
            if (HttpContext.Items["IsSystemAdmin"] is true)
                return true;

            var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
            if (tenantIds == null)
                return false;

            // If the certificate is not bound to any CertificateAuthorities row, fall back
            // to denying — admin callers should never reach here through an unbound cert.
            var caTenant = await _db.CertificateAuthorities
                .AsNoTracking()
                .Where(c => c.CertificateId == certificateId)
                .Select(c => (Guid?)c.TenantId)
                .FirstOrDefaultAsync();
            return caTenant.HasValue && tenantIds.Contains(caTenant.Value);
        }

        /// <summary>
        /// Create a new self-signed root CA. Requires step-up MFA verification.
        /// </summary>
        [HttpPost("create-root")]
        [Authorize(Policy = "SystemAdmin")]
        [RequireStepUp(StepUpOps.CreateCa)]
        public async Task<IActionResult> CreateRoot([FromBody] CreateRootCaRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();

            if (string.IsNullOrWhiteSpace(request.SubjectCN))
                return BadRequest(new { error = "Common Name is required" });

            // Enforce central key-algorithm policy before touching the service layer
            if (!KeyAlgorithmPolicy.IsAllowed(request.KeyAlgorithm, request.KeySize))
                return BadRequest(new { error = $"Key algorithm '{request.KeyAlgorithm}' with size/curve '{request.KeySize}' is not permitted. Allowed: RSA 2048/3072/4096/7680/8192, ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA-44/65/87, SLH-DSA-*." });

            // Check ceremony-first enforcement for this tenant
            var rootTenant = await _db.Tenants.FindAsync(request.TenantId);
            if (rootTenant?.RequireKeyCeremony == true)
            {
                var parameters = new ModularCA.Shared.Models.KeyCeremonyParameters
                {
                    SubjectCN = request.SubjectCN,
                    SubjectO = request.SubjectO,
                    SubjectOU = request.SubjectOU,
                    SubjectL = request.SubjectL,
                    SubjectST = request.SubjectST,
                    SubjectC = request.SubjectC,
                    KeyAlgorithm = request.KeyAlgorithm,
                    KeySize = request.KeySize,
                    ValidityYears = request.ValidityYears,
                    TenantId = request.TenantId,
                    Label = request.Label,
                    PublicBaseUrl = request.PublicBaseUrl,
                    NameConstraintsPermitted = request.NameConstraintsPermitted,
                    NameConstraintsExcluded = request.NameConstraintsExcluded,
                };
                var ceremony = await _ceremonySvc.InitiateAsync(
                    "CreateRootCA",
                    $"Create root CA '{request.SubjectCN}'",
                    string.Empty,
                    _currentUser.User.Id,
                    _currentUser.User.Username ?? string.Empty,
                    System.Text.Json.JsonSerializer.Serialize(parameters));
                return Ok(new
                {
                    requiresCeremony = true,
                    ceremonyId = ceremony.Id,
                    ceremony.Status,
                    ceremony.RequiredApprovals,
                    message = $"Key ceremony required for tenant '{rootTenant.Name}'. A ceremony has been created and requires {ceremony.RequiredApprovals} approval(s)."
                });
            }

            try
            {
                var newCa = await _caCreation.CreateRootAsync(
                    request.SubjectCN, request.SubjectO, request.SubjectOU,
                    request.SubjectL, request.SubjectST, request.SubjectC,
                    request.KeyAlgorithm, request.KeySize, request.ValidityYears,
                    request.Label, request.TenantId,
                    publicBaseUrl: request.PublicBaseUrl,
                    nameConstraintsPermittedJson: request.NameConstraintsPermitted is { Count: > 0 } perm
                        ? System.Text.Json.JsonSerializer.Serialize(perm)
                        : null,
                    nameConstraintsExcludedJson: request.NameConstraintsExcluded is { Count: > 0 } excl
                        ? System.Text.Json.JsonSerializer.Serialize(excl)
                        : null);

                await _currentUser.EnsureLoadedAsync();
                await _audit.LogAsync(AuditActionType.CaCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                    "CertificateAuthority", newCa.Id.ToString(),
                    new { newCa.Name, newCa.Label, Type = "Root", request.KeyAlgorithm, request.KeySize },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: newCa.Id, tenantId: request.TenantId);

                _ = _alertService.RaiseAlertAsync("RootCaCreated", AlertSeverity.Warning, $"Root CA '{request.SubjectCN}' created by {_currentUser.User?.Username}", new { CaId = newCa.Id, newCa.Name, request.KeyAlgorithm, request.KeySize });
                return Ok(new
                {
                    newCa.Id,
                    newCa.Name,
                    newCa.Label,
                    newCa.Type,
                    newCa.CertificateId,
                    message = $"Root CA '{request.SubjectCN}' created successfully"
                });
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Failed to create root CA");

                // Mirror the success-path CaCreated audit
                // with success=false on the failure branch so SIEM has a single action
                // type to filter on for "CA creation attempt." Wrapped so audit failure
                // cannot mask the user-facing 500.
                try
                {
                    await _currentUser.EnsureLoadedAsync();
                    await _audit.LogAsync(AuditActionType.CaCreated, _currentUser.User?.Id, _currentUser.User?.Username,
                        "CertificateAuthority", request.SubjectCN,
                        new
                        {
                            Type = "Root",
                            request.SubjectCN,
                            request.Label,
                            request.KeyAlgorithm,
                            request.KeySize,
                            request.TenantId,
                        },
                        HttpContext.Connection.RemoteIpAddress?.ToString(),
                        success: false,
                        errorMessage: ex.Message,
                        tenantId: request.TenantId);
                }
                catch (Exception auditEx)
                {
                    Log.Warning(auditEx, "Audit emission for failed root CA creation failed");
                }

                return DescribeCreationFailure(ex, "root");
            }
        }

        /// <summary>
        /// Reissues a CA's delegated OCSP responder and/or TSA certificate.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Use this rather than the generic certificate-reissue flow. That flow revokes the old
        /// certificate and issues a replacement, but nothing updates
        /// <c>CertificateAuthorities.OcspResponderCertificateId</c> — those pointers were only
        /// ever written by bootstrap and by CA creation. The CA is left pointing at a revoked
        /// certificate, the OCSP resolver filters revoked certificates out, finds nothing, and
        /// refuses to fall back to CA-direct signing because a responder was configured. Every
        /// request to that CA then answers <c>unauthorized</c>, and restarting does not help
        /// because the stale pointer is in the database.
        /// </para>
        /// <para>
        /// This action performs the whole operation: issue, repoint, write the key to the
        /// keystore, register the identity in the runtime registry, and revoke the predecessor as
        /// Superseded. It also repairs a CA already left in the broken state, which is its most
        /// likely first use.
        /// </para>
        /// </remarks>
        /// <param name="caId">The CA to operate on.</param>
        /// <param name="request">Which certificates to reissue.</param>
        [HttpPost("{caId:guid}/reissue-infrastructure")]
        [Authorize(Policy = "SystemOperator")]
        [RequireStepUp(StepUpOps.ReissueInfrastructureCerts, "caId")]
        public async Task<IActionResult> ReissueInfrastructure(Guid caId, [FromBody] ReissueInfrastructureRequest request)
        {
            await _currentUser.EnsureLoadedAsync();
            if (_currentUser.User == null) return Unauthorized();

            var ca = await _db.CertificateAuthorities.FirstOrDefaultAsync(c => c.Id == caId && !c.IsDeleted);
            if (ca == null) return NotFound(new { error = "Certificate authority not found." });

            // CA-scoped authorization: reissuing a CA's responder is a change to that CA.
            if (!await _groupAuth.HasCaCapabilityAsync(_currentUser.User.Id, ca.Id, ModularCA.Shared.Authorization.Capabilities.CaManage))
                return StatusCode(403, new { error = "You are not authorized to manage this certificate authority." });

            if (!request.ReissueOcspResponder && !request.ReissueTsa && !request.ReissueCmpSigner)
                return BadRequest(new { error = "Select the OCSP responder, the TSA, the CMP signer, or any combination." });

            try
            {
                var result = await _caCreation.ReissueInfrastructureCertsAsync(
                    caId,
                    request.ReissueOcspResponder,
                    request.ReissueTsa,
                    request.RevokeSuperseded,
                    request.ReissueCmpSigner);

                await _audit.LogAsync(
                    AuditActionType.CertificateReissued,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "CertificateAuthority", caId.ToString(),
                    new
                    {
                        Action = "ReissueInfrastructureCerts",
                        result.CaLabel,
                        result.NewOcspResponderSerial,
                        result.NewTsaSerial,
                        result.NewCmpSignerSerial,
                        SupersededRevoked = result.SupersededSerialsRevoked,
                    },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: ca.Id, tenantId: ca.TenantId);

                return Ok(new
                {
                    message = "Infrastructure certificates reissued. The responder is live immediately — no restart required.",
                    caLabel = result.CaLabel,
                    newOcspResponderSerial = result.NewOcspResponderSerial,
                    newTsaSerial = result.NewTsaSerial,
                    newCmpSignerSerial = result.NewCmpSignerSerial,
                    supersededRevoked = result.SupersededSerialsRevoked,
                });
            }
            catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException
                                          or ArgumentException or NotSupportedException)
            {
                // These carry operator-actionable messages (CA revoked, no private key available,
                // HSM-backed signer). Surface them rather than collapsing to a correlation id.
                //
                // RequestValidationException is listed first and deliberately: most of this
                // path's refusals have been migrated to that family, and without it in the
                // filter they would sail past this block to the middleware — correctly answered,
                // but with the failure audit record silently skipped. A reissue attempt must
                // leave a trail whether it succeeded or not, so the audit happens here either
                // way and only the rendering differs.
                await _audit.LogAsync(
                    AuditActionType.CertificateReissued,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "CertificateAuthority", caId.ToString(),
                    new { Action = "ReissueInfrastructureCerts", Success = false, Error = ex.Message },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: ca.Id, tenantId: ca.TenantId);

                if (ex is RequestValidationException)
                {
                    // Let RequestValidationMiddleware render it, so the status (404 for a missing
                    // CA, 409 for a conflict) and the per-type fields survive.
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex).Throw();
                }

                return BadRequest(new { error = ex.Message });
            }
        }


    }

    /// <summary>
    /// Request body for updating an existing Certificate Authority's runtime properties.
    /// </summary>
    public class UpdateCaRequest
    {
        [MaxLength(255)]
        public string? Name { get; set; }

        [MaxLength(255)]
        public string? Label { get; set; }

        public bool? IsDefault { get; set; }
        public bool? IsEnabled { get; set; }
    }

    /// <summary>
    /// Request body for creating an intermediate Certificate Authority under an existing parent CA.
    /// </summary>
    public class CreateIntermediateCaRequest
    {
        [Required, MaxLength(256)]
        public string SubjectCN { get; set; } = string.Empty;

        [MaxLength(256)]
        public string SubjectO { get; set; } = string.Empty;

        [MaxLength(256)]
        public string? SubjectOU { get; set; }

        [MaxLength(256)]
        public string? SubjectL { get; set; }

        [MaxLength(256)]
        public string? SubjectST { get; set; }

        [MaxLength(256)]
        public string? SubjectC { get; set; }

        public Guid ParentCaId { get; set; }
        /// <summary>Tenant that owns this CA.</summary>
        public Guid TenantId { get; set; }

        [Required, MaxLength(50)]
        public string KeyAlgorithm { get; set; } = "ECDSA";

        public int KeySize { get; set; } = 384;
        public int ValidityYears { get; set; } = 10;

        [MaxLength(255)]
        public string? Label { get; set; }
        /// <summary>Optional CA certificate profile ID. Defaults to "Main CA Certificate Profile" when not specified.</summary>
        public Guid? CertProfileId { get; set; }
        /// <summary>
        /// Public base URL for this CA (e.g. <c>http://path2.ca.example.com</c>). CDP, OCSP, and
        /// AIA endpoints are auto-generated from this base URL at cert-build time. Leave null to
        /// issue certs without CDP/AIA extensions until a base URL is set later.
        /// </summary>
        [MaxLength(2048)]
        public string? PublicBaseUrl { get; set; }

        /// <summary>
        /// Optional list of permitted name subtrees (NameConstraints, RFC 5280 §4.2.1.10) baked
        /// into the CA cert and copied onto the per-CA signing profile. Format matches the
        /// signing-profile column: a JSON array of <c>"DNS:.example.com"</c>, <c>"IP:10.0.0.0/8"</c>,
        /// <c>"Email:@example.com"</c>, <c>"URI:https://example.com"</c>, or <c>"DN:CN=...,O=..."</c> entries.
        /// Leave null to omit the extension entirely.
        /// </summary>
        public List<string>? NameConstraintsPermitted { get; set; }

        /// <summary>
        /// Optional list of excluded name subtrees, same format as <see cref="NameConstraintsPermitted"/>.
        /// </summary>
        public List<string>? NameConstraintsExcluded { get; set; }
    }

    /// <summary>
    /// Request body for creating a new self-signed root Certificate Authority.
    /// </summary>
    public class CreateRootCaRequest
    {
        [Required, MaxLength(256)]
        public string SubjectCN { get; set; } = string.Empty;

        [MaxLength(256)]
        public string? SubjectO { get; set; }

        [MaxLength(256)]
        public string? SubjectOU { get; set; }

        [MaxLength(256)]
        public string? SubjectL { get; set; }

        [MaxLength(256)]
        public string? SubjectST { get; set; }

        [MaxLength(256)]
        public string? SubjectC { get; set; }

        /// <summary>Tenant that owns this CA.</summary>
        public Guid TenantId { get; set; }

        [Required, MaxLength(50)]
        public string KeyAlgorithm { get; set; } = "ECDSA";

        public int KeySize { get; set; } = 384;
        public int ValidityYears { get; set; } = 25;

        [MaxLength(255)]
        public string? Label { get; set; }
        /// <summary>Optional CA certificate profile ID. Defaults to "Main CA Certificate Profile" when not specified.</summary>
        public Guid? CertProfileId { get; set; }
        /// <summary>
        /// Public base URL for this CA (e.g. <c>http://path2.ca.example.com</c>). CDP, OCSP, and
        /// AIA endpoints are auto-generated from this base URL at cert-build time. Leave null to
        /// issue certs without CDP/AIA extensions until a base URL is set later.
        /// </summary>
        [MaxLength(2048)]
        public string? PublicBaseUrl { get; set; }

        /// <summary>
        /// Optional list of permitted name subtrees (NameConstraints, RFC 5280 §4.2.1.10) baked
        /// into the CA cert and copied onto the per-CA signing profile. Format matches the
        /// signing-profile column: a JSON array of <c>"DNS:.example.com"</c>, <c>"IP:10.0.0.0/8"</c>,
        /// <c>"Email:@example.com"</c>, <c>"URI:https://example.com"</c>, or <c>"DN:CN=...,O=..."</c> entries.
        /// Leave null to omit the extension entirely. Most root CAs leave this empty and apply
        /// constraints only on their immediate intermediates.
        /// </summary>
        public List<string>? NameConstraintsPermitted { get; set; }

        /// <summary>
        /// Optional list of excluded name subtrees, same format as <see cref="NameConstraintsPermitted"/>.
        /// </summary>
        public List<string>? NameConstraintsExcluded { get; set; }
    }

    /// <summary>
    /// Body for <c>POST /api/v1/admin/authorities/{caId}/reissue-infrastructure</c>.
    /// </summary>
    public class ReissueInfrastructureRequest
    {
        /// <summary>Reissue the delegated OCSP responder certificate.</summary>
        public bool ReissueOcspResponder { get; set; } = true;

        /// <summary>Reissue the TSA signer certificate.</summary>
        public bool ReissueTsa { get; set; }

        /// <summary>
        /// Issue or reissue the dedicated CMP message-signing certificate. Not issued at CA
        /// creation; see <c>CertificateAuthorityEntity.CmpSigningCertificateId</c> for why one is
        /// needed at all.
        /// </summary>
        public bool ReissueCmpSigner { get; set; }

        /// <summary>
        /// Revoke the certificate being replaced when it is still valid. Leave true unless you
        /// have a reason to keep two valid responders for one CA. A predecessor that is already
        /// revoked is untouched either way.
        /// </summary>
        public bool RevokeSuperseded { get; set; } = true;
    }

}
