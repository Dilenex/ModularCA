using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for the OID catalog (standard and extended key usage OIDs).
/// </summary>
/// <remarks>
/// <para>
/// The catalog is what issuance resolves a profile's usages against, so it is the real limit on
/// what this CA can be configured to emit. It was previously read-only here and gated by a
/// hardcoded allow-list in <c>CreateCertProfileValidator</c>, which meant the table looked like a
/// catalog and behaved like a constant: adding a usage was impossible through the product, and the
/// only route was editing <c>config/OIDSeed.yaml</c> before first run or writing to the database
/// by hand.
/// </para>
/// <para>
/// Writes stay <c>SystemOperator</c> — the catalog is global, shared across every tenant, and a
/// row added here widens what every CA in the deployment may issue. Reads are opened to
/// <c>CaAuditor</c> because the certificate-profile editor needs the list to render its usage
/// pickers, and the contents are public identifiers, not secrets.
/// </para>
/// </remarks>
[ApiController]
[Route("api/v1/admin/oid-options")]
[Authorize(Policy = "SystemOperator")]
public class AdminOidController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit) : ControllerBase
{
    /// <summary>Standard key usage bits are fixed by RFC 5280 §4.2.1.3; only EKUs are extensible.</summary>
    private const string ExtendedKind = "Extended";

    /// <summary>
    /// Forbidden in a subscriber certificate (RFC 5280 §4.2.1.12, CA/B Forum BR §7.1.2.2), and
    /// rejected outright by <c>IssuanceValidationService</c>. Cataloguing it would only let an
    /// operator build a profile that fails at first issuance.
    /// </summary>
    private const string AnyExtendedKeyUsageOid = "2.5.29.37.0";

    /// <summary>Dotted decimal, each arc a non-negative integer with no leading zeros.</summary>
    private static readonly Regex OidPattern = new(
        @"^[0-2](\.(0|[1-9]\d*)){1,20}$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    /// <summary>
    /// Returns the full OID catalog. Readable by any caller who can view certificates, because
    /// the profile editor's key-usage and extended-key-usage pickers are driven from it — a picker
    /// built from a hardcoded list is how <c>smartcardLogon</c> ended up impossible to select
    /// despite being present in the catalog and permitted by the validator.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetAll()
    {
        var oids = await db.OIDOptions
            .AsNoTracking()
            .OrderBy(o => o.KeyUsage).ThenBy(o => o.FriendlyName)
            .Select(o => new { o.OID, o.FriendlyName, o.KeyUsage, o.IsDefaultEntry })
            .ToListAsync();
        return Ok(oids);
    }

    /// <summary>
    /// Adds an extended key usage to the catalog, making it selectable in profiles and resolvable
    /// at issuance.
    /// </summary>
    /// <remarks>
    /// Only extended key usages may be added. The standard key usages are the nine bits of the
    /// RFC 5280 KeyUsage BIT STRING and there is no tenth — a row claiming otherwise would be
    /// accepted by the profile validator and then silently dropped by the certificate builder,
    /// which maps friendly names onto those nine bits and nothing else.
    /// </remarks>
    [HttpPost]
    [RequireStepUp(StepUpOps.ManageOidCatalog)]
    public async Task<IActionResult> Create([FromBody] CreateOidOptionRequest request)
    {
        var oid = request.Oid?.Trim() ?? string.Empty;
        var friendlyName = request.FriendlyName?.Trim() ?? string.Empty;

        if (!OidPattern.IsMatch(oid))
            return BadRequest(new { error = "OID must be dotted decimal, e.g. 1.3.6.1.5.2.3.5." });

        if (string.Equals(oid, AnyExtendedKeyUsageOid, StringComparison.Ordinal))
        {
            return BadRequest(new
            {
                error = "anyExtendedKeyUsage (2.5.29.37.0) is forbidden in subscriber certificates " +
                        "(RFC 5280 4.2.1.12) and is rejected at issuance."
            });
        }

        // The friendly name is one of the two spellings a profile may store, so a duplicate would
        // make resolution depend on row order.
        if (await db.OIDOptions.AnyAsync(o => o.OID == oid))
            return Conflict(new { error = $"OID {oid} is already in the catalog." });

        if (await db.OIDOptions.AnyAsync(o => o.FriendlyName == friendlyName))
            return Conflict(new { error = $"Friendly name '{friendlyName}' is already in the catalog." });

        var entity = new OIDOptionEntity
        {
            OID = oid,
            FriendlyName = friendlyName,
            KeyUsage = ExtendedKind,
            IsDefaultEntry = false,
            AddedOn = DateTime.UtcNow,
        };

        db.OIDOptions.Add(entity);
        await db.SaveChangesAsync();

        await audit.LogAsync(
            AuditActionType.OidOptionCreated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "OIDOption", entity.OID,
            new { entity.OID, entity.FriendlyName, entity.KeyUsage },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetAll), new { entity.OID, entity.FriendlyName, entity.KeyUsage });
    }

    /// <summary>
    /// Removes an operator-added extended key usage from the catalog.
    /// </summary>
    /// <remarks>
    /// Refuses to remove a seeded default, and refuses to remove an entry a profile still
    /// references. The second guard matters more than it looks: issuance resolves usages against
    /// this table and DROPS what it cannot find, so deleting a referenced row does not break the
    /// profile loudly — it quietly issues certificates without that usage, which for a Smart Card
    /// Logon or KDC Authentication EKU means a logon that stops working for no visible reason.
    /// </remarks>
    [HttpDelete("{oid}")]
    [RequireStepUp(StepUpOps.ManageOidCatalog)]
    public async Task<IActionResult> Delete(string oid)
    {
        var entity = await db.OIDOptions.FirstOrDefaultAsync(o => o.OID == oid);
        if (entity == null)
            return NotFound(new { error = "OID not found in the catalog." });

        if (entity.IsDefaultEntry)
            return BadRequest(new { error = "Seeded default OIDs cannot be removed." });

        // Both spellings a profile may have stored.
        var referencedByCertProfile = await db.CertProfiles.AnyAsync(p =>
            p.ExtendedKeyUsages.Contains(entity.OID) || p.ExtendedKeyUsages.Contains(entity.FriendlyName));
        var referencedBySigningProfile = await db.SigningProfiles.AnyAsync(p =>
            p.AllowedEKUs != null &&
            (p.AllowedEKUs.Contains(entity.OID) || p.AllowedEKUs.Contains(entity.FriendlyName)));

        if (referencedByCertProfile || referencedBySigningProfile)
        {
            return Conflict(new
            {
                error = $"OID {oid} is still referenced by a certificate or signing profile. " +
                        "Remove it from those profiles first."
            });
        }

        db.OIDOptions.Remove(entity);
        await db.SaveChangesAsync();

        await audit.LogAsync(
            AuditActionType.OidOptionDeleted,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "OIDOption", entity.OID,
            new { entity.OID, entity.FriendlyName, entity.KeyUsage },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }
}

/// <summary>Request body for adding an extended key usage to the OID catalog.</summary>
public class CreateOidOptionRequest
{
    /// <summary>Dotted-decimal OID, e.g. <c>1.3.6.1.5.2.3.5</c>.</summary>
    [Required]
    [MaxLength(255)]
    public string Oid { get; set; } = string.Empty;

    /// <summary>
    /// Short camelCase identifier, e.g. <c>kdcAuthentication</c>. Stored alongside the OID as an
    /// alternative spelling a profile may reference, and used as the display label.
    /// </summary>
    [Required]
    [MaxLength(64)]
    public string FriendlyName { get; set; } = string.Empty;
}
