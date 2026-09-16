using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Moves generated template OIDs under the operator's arc once <c>Msae:TemplateOidArc</c> is
/// configured. Until then it only reports how many templates are waiting.
/// </summary>
/// <remarks>
/// <para>
/// Two generated forms exist: the pre-2026-09-15 <c>2.25.{id as one integer}</c>, which Windows
/// cannot parse for about half of all ids, and the current four-arc form under the default arc.
/// Both are recognised by recomputing them from the template's own id, so anything an operator
/// typed is left alone even if it happens to sit under 2.25.
/// </para>
/// <para>
/// Nothing is rewritten while no arc is configured, by design: a template's OID should change
/// once, straight to the arc it will keep, because every change makes Windows clients treat it as
/// a new template and re-enroll. Certificates already issued keep the old OID in their template
/// extension. Operator OIDs that Windows cannot parse are reported, never changed.
/// </para>
/// </remarks>
public static class MsaeTemplateOidRepair
{
    /// <summary>
    /// Rewrites generated OIDs under <paramref name="baseArc"/> and returns how many changed.
    /// With no arc configured it changes nothing and returns 0.
    /// </summary>
    public static async Task<int> RunAsync(ModularCADbContext db, string? baseArc, ILogger logger, CancellationToken cancellation = default)
    {
        var offered = await db.CertificateTemplates
            .Where(t => t.MsaeTemplateOid != null)
            .ToListAsync(cancellation);
        var active = !string.IsNullOrWhiteSpace(baseArc);
        var waiting = 0;
        var changed = 0;
        foreach (var template in offered)
        {
            var generated = template.MsaeTemplateOid == MsaeTemplateOids.LegacyFromTemplateId(template.Id)
                || template.MsaeTemplateOid == MsaeTemplateOids.FromTemplateId(template.Id, MsaeTemplateOids.DefaultArc);
            if (generated)
            {
                if (!active) { waiting++; continue; }
                var fresh = MsaeTemplateOids.FromTemplateId(template.Id, baseArc);
                if (fresh == template.MsaeTemplateOid) continue;
                logger.LogWarning("Template {Name} ({Id}): generated OID {Old} moved to {New}. Windows clients see a new template and re-enroll once.",
                    template.Name, template.Id, template.MsaeTemplateOid, fresh);
                template.MsaeTemplateOid = fresh;
                changed++;
            }
            else if (!MsaeTemplateOids.IsValid(template.MsaeTemplateOid))
            {
                logger.LogWarning("Template {Name} ({Id}) carries OID {Oid}, which Windows cannot parse (an arc above 2^63-1). It will not appear in any Windows client's template list.",
                    template.Name, template.Id, template.MsaeTemplateOid);
            }
        }
        if (waiting > 0)
            logger.LogInformation("{Count} template OID(s) are generated under the default arc; set Msae:TemplateOidArc to your Private Enterprise Number arc and they move there at the next start.", waiting);
        if (changed > 0) await db.SaveChangesAsync(cancellation);
        return changed;
    }
}
