using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.API.Startup;
using ModularCA.Database;
using ModularCA.Shared.Signing;

namespace ModularCA.API.HealthChecks;

/// <summary>
/// Reports which roles this process runs and, for each, whether what it needs is there:
/// validation needs the signer reachable (it signs OCSP through it and serves the last
/// published CRL regardless), enrollment needs the signer unlocked (nothing issues until it
/// is), the control plane needs the database. The entry is unhealthy when an active role's
/// need is unmet, so a load balancer stops sending that role's traffic here; roles the
/// process does not run are not reported, because nothing here is answering for them.
/// </summary>
public sealed class NodeRoleHealthCheck : IHealthCheck
{
    private readonly ActiveRoles _roles;
    private readonly ISigningService _signer;
    private readonly ModularCADbContext _db;

    /// <summary>Creates the check over the process's role set, its signer and its database.</summary>
    public NodeRoleHealthCheck(ActiveRoles roles, ISigningService signer, ModularCADbContext db)
    {
        _roles = roles;
        _signer = signer;
        _db = db;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var report = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["active"] = _roles.Names,
        };
        var allMet = true;

        SignerHealth? signer = null;
        if (_roles.Has(ProcessRole.Validation) || _roles.Has(ProcessRole.Enrollment))
        {
            try
            {
                signer = await _signer.HealthAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Role health: the signer did not answer");
            }
        }

        if (_roles.Has(ProcessRole.Validation))
        {
            var reachable = signer != null && signer.Backend != SignerHealth.UnreachableBackend;
            report["validation"] = new { needs = "signer reachable", satisfied = reachable };
            allMet &= reachable;
        }

        if (_roles.Has(ProcessRole.Enrollment))
        {
            var unlocked = signer?.Unlocked == true;
            report["enrollment"] = new { needs = "signer unlocked", satisfied = unlocked };
            allMet &= unlocked;
        }

        if (_roles.Has(ProcessRole.Control))
        {
            var database = false;
            try
            {
                database = await _db.Database.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Role health: the database did not answer");
            }
            report["control"] = new { needs = "database", satisfied = database };
            allMet &= database;
        }

        var data = new Dictionary<string, object>(StringComparer.Ordinal) { ["roles"] = report };
        return allMet
            ? HealthCheckResult.Healthy("Every active role has what it needs", data)
            : HealthCheckResult.Unhealthy("An active role lacks what it needs", data: data);
    }
}
