using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for certificate compliance: generating/exporting compliance reports and
/// viewing, summarizing, and resolving the individual compliance findings produced by the
/// Compliance scan job. Requires the SystemAuditor authorization policy.
/// </summary>
[ApiController]
[Route("api/v1/admin/compliance")]
[Authorize(Policy = "SystemAuditor")]
[NodeRole(ProcessRole.Control)]
public class AdminComplianceController : ControllerBase
{
    private readonly IComplianceReportService _reportService;
    private readonly ICurrentUserService _currentUser;
    private readonly ModularCADbContext _db;
    private readonly IAuditService _audit;

    /// <summary>
    /// Initializes a new instance of the <see cref="AdminComplianceController"/> class.
    /// </summary>
    /// <param name="reportService">Service for generating compliance reports.</param>
    /// <param name="currentUser">Service for resolving the authenticated user.</param>
    /// <param name="db">Database context for querying and updating compliance findings.</param>
    /// <param name="audit">Audit trail for recording who resolved or dismissed a finding.</param>
    public AdminComplianceController(
        IComplianceReportService reportService,
        ICurrentUserService currentUser,
        ModularCADbContext db,
        IAuditService audit)
    {
        _reportService = reportService;
        _currentUser = currentUser;
        _db = db;
        _audit = audit;
    }

    /// <summary>
    /// Generates a compliance report as JSON covering certificate inventory, algorithm distribution,
    /// compliance findings summary, policy violations, expiry forecast, revocation and issuance history,
    /// and CA hierarchy. Accepts an optional CA filter and date range for history sections.
    /// </summary>
    /// <param name="request">Report parameters including date range and optional CA filter.</param>
    /// <returns>A JSON compliance report.</returns>
    [HttpPost("report")]
    public async Task<IActionResult> GenerateReport([FromBody] ComplianceReportRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        if (request.FromDate > request.ToDate)
            return BadRequest(new { error = "fromDate must be before or equal to toDate." });

        var report = await _reportService.GenerateReportAsync(request);
        return Ok(report);
    }

    /// <summary>
    /// Generates a compliance report and exports it as a CSV file download.
    /// Each row represents a single certificate with serial, subject, issuer, algorithm,
    /// key size, validity dates, status, health score, and findings count.
    /// </summary>
    /// <param name="request">Report parameters including date range and optional CA filter.</param>
    /// <returns>A CSV file download containing the certificate inventory.</returns>
    [HttpPost("export/csv")]
    public async Task<IActionResult> ExportCsv([FromBody] ComplianceReportRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (!_currentUser.IsAuthenticated || _currentUser.User == null)
            return Unauthorized();

        if (request.FromDate > request.ToDate)
            return BadRequest(new { error = "fromDate must be before or equal to toDate." });

        var report = await _reportService.GenerateReportAsync(request);
        var csvBytes = await _reportService.ExportCsvAsync(report);

        var fileName = $"compliance-report-{request.FromDate:yyyyMMdd}-{request.ToDate:yyyyMMdd}.csv";
        return File(csvBytes, "text/csv", fileName);
    }

    /// <summary>
    /// Returns a paginated list of active (unresolved) compliance findings,
    /// optionally filtered by severity and/or type.
    /// </summary>
    /// <param name="severity">Optional filter by severity (Critical, Warning, Info).</param>
    /// <param name="type">Optional filter by finding type (WeakKey, DeprecatedAlgorithm, etc.).</param>
    /// <param name="includeResolved">When true, includes resolved findings. Default false.</param>
    /// <param name="page">Page number (1-based). Default 1.</param>
    /// <param name="pageSize">Number of items per page. Default 50, max 200.</param>
    [HttpGet]
    public async Task<IActionResult> GetFindings(
        [FromQuery] string? severity,
        [FromQuery] string? type,
        [FromQuery] bool includeResolved = false,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? sort = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 1;
        if (pageSize > 200) pageSize = 200;

        var query = _db.CertComplianceFindings.AsQueryable();

        if (!includeResolved)
            query = query.Where(v => !v.IsResolved);

        if (!string.IsNullOrWhiteSpace(severity))
            query = query.Where(v => v.Severity == severity);

        if (!string.IsNullOrWhiteSpace(type))
            query = query.Where(v => v.Type == type);

        var totalCount = await query.CountAsync();

        // sort: detectedAt (default, newest first), severity, type.
        var parsedSort = ModularCA.Core.ListSort.Parse(sort, "detectedAt", "severity", "type");
        IOrderedQueryable<Shared.Entities.CertComplianceFindingEntity> ordered = parsedSort switch
        {
            ("severity", false) => query.OrderBy(v => v.Severity).ThenByDescending(v => v.DetectedAt),
            ("severity", true) => query.OrderByDescending(v => v.Severity).ThenByDescending(v => v.DetectedAt),
            ("type", false) => query.OrderBy(v => v.Type).ThenByDescending(v => v.DetectedAt),
            ("type", true) => query.OrderByDescending(v => v.Type).ThenByDescending(v => v.DetectedAt),
            ("detectedAt", false) => query.OrderBy(v => v.DetectedAt),
            _ => query.OrderByDescending(v => v.DetectedAt),
        };
        var items = await ordered
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(v => new
            {
                v.Id,
                v.CertificateId,
                // Correlated lookup acts as a left join: null if the certificate row
                // was purged. The page shows the serial (matching audit-log references)
                // and falls back to the GUID when absent.
                CertificateSerial = _db.Certificates
                    .Where(c => c.CertificateId == v.CertificateId)
                    .Select(c => c.SerialNumber)
                    .FirstOrDefault(),
                v.Severity,
                v.Type,
                v.Description,
                v.DetectedAt,
                // Emit as `resolved` to match the page's finding contract;
                // `isResolved` (camelCase of the entity field) was never read.
                Resolved = v.IsResolved,
                v.ResolvedAt
            })
            .ToListAsync();

        return Ok(new
        {
            items,
            totalCount,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling((double)totalCount / pageSize)
        });
    }

    /// <summary>
    /// Returns aggregated counts of active (unresolved) compliance findings
    /// grouped by severity and by finding type.
    /// </summary>
    [HttpGet("summary")]
    public async Task<IActionResult> GetSummary()
    {
        var activeFindings = _db.CertComplianceFindings.Where(v => !v.IsResolved);

        // Shape matches the admin Compliance page summary cards
        // ({ critical, warning, info, resolved }). Counts are of active (unresolved)
        // findings by severity; resolved is the lifetime count of resolved findings.
        var critical = await activeFindings.CountAsync(v => v.Severity == "Critical");
        var warning = await activeFindings.CountAsync(v => v.Severity == "Warning");
        var info = await activeFindings.CountAsync(v => v.Severity == "Info");
        var resolved = await _db.CertComplianceFindings.CountAsync(v => v.IsResolved);

        return Ok(new
        {
            critical,
            warning,
            info,
            resolved
        });
    }

    /// <summary>
    /// Marks an individual compliance finding as resolved. Sets the IsResolved
    /// flag to true and records the current UTC timestamp as the resolution time.
    /// </summary>
    /// <param name="id">The unique identifier of the compliance finding to resolve.</param>
    // The class policy is SystemAuditor — the deliberately READ-ONLY bundle. This is the only
    // mutation on the controller, and it inherited that policy, so an auditor could walk the
    // Critical findings and clear every one of them. Nothing recorded it either: the controller
    // did not take IAuditService at all. Clearing a compliance finding is an operator action.
    [Authorize(Policy = "SystemOperator")]
    [HttpPost("{id}/resolve")]
    public async Task<IActionResult> Resolve(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();

        var finding = await _db.CertComplianceFindings.FindAsync(id);
        if (finding == null)
            return NotFound(new { error = "Compliance finding not found" });

        if (finding.IsResolved)
            return Ok(new { message = "Finding is already resolved", finding.Id, finding.ResolvedAt });

        finding.IsResolved = true;
        finding.ResolvedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.ComplianceFindingResolved,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            "ComplianceFinding", finding.Id.ToString(),
            new { finding.Severity, finding.Type, finding.CertificateId, finding.Description },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Finding resolved", finding.Id, finding.ResolvedAt });
    }
}
