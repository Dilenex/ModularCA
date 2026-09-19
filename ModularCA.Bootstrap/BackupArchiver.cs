using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;

namespace ModularCA.Bootstrap;

/// <summary>
/// Thin adapter that exposes <see cref="BackupRestore.Backup"/> through the
/// <see cref="IBackupArchiver"/> interface so Core-layer scheduler jobs can trigger
/// backups without Core having to reference Bootstrap. The node's own signer exports the
/// keystore files.
/// </summary>
public class BackupArchiver : IBackupArchiver
{
    private readonly ISigningService _signer;

    /// <summary>Creates the adapter over the node's signer.</summary>
    public BackupArchiver(ISigningService signer)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    /// <inheritdoc />
    public Task<int> CreateArchiveAsync(string outputPath, CancellationToken cancellationToken = default)
    {
        // BackupRestore.Backup doesn't accept a token today; if cancellation is
        // requested we honour it before kicking off the (synchronous, zip-writing)
        // archive routine. Mid-archive cancellation would require plumbing through
        // BackupRestore — out of scope for this wiring.
        cancellationToken.ThrowIfCancellationRequested();
        return BackupRestore.Backup(outputPath, _ => _signer);
    }
}
