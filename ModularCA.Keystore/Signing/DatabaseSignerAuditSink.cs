using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// Writes signer decisions to the <c>SignerAudit</c> table in the shared database. Each decision
/// is one insert on a scope of the sink's own, so it is committed whether or not the caller's
/// unit of work is, and a caller's rollback cannot take a signer's record with it.
/// </summary>
public sealed class DatabaseSignerAuditSink : ISignerAuditSink
{
    private readonly IServiceScopeFactory _scopes;

    /// <summary>Creates a sink that opens its own database scope per decision.</summary>
    public DatabaseSignerAuditSink(IServiceScopeFactory scopes)
    {
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
    }

    /// <inheritdoc />
    public async Task RecordAsync(SignerDecision decision, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ModularCADbContext>();
        db.SignerAudit.Add(ToEntity(decision));
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Maps a decision to its row. Public so a test can assert the mapping without a database.</summary>
    public static SignerAuditEntity ToEntity(SignerDecision decision) => new()
    {
        At = decision.At,
        Operation = decision.Operation,
        Caller = Truncate(decision.Context.Caller, 128),
        Purpose = decision.Context.Purpose.ToString(),
        KeyCertificateId = decision.Key?.CertificateId,
        Keystore = decision.Key?.Keystore,
        CaId = decision.Context.CaId,
        TenantId = decision.Context.TenantId,
        Algorithm = decision.Algorithm?.Name,
        Outcome = decision.Allowed ? SignerAuditEntity.AllowedOutcome : SignerAuditEntity.RefusedOutcome,
        Reason = decision.Reason == null ? null : Truncate(decision.Reason, 1024),
        DataHash = decision.DataHash == null ? null : Convert.ToHexStringLower(decision.DataHash),
    };

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
