using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using Org.BouncyCastle.Security;

namespace ModularCA.Core.Services;

/// <summary>
/// What was found where an SSH CA key's row says its key file is.
/// </summary>
/// <param name="Code">Null when the file holds the row's key; otherwise one of <see cref="SshKeyImportReasons"/>.</param>
/// <param name="KeyFile">The full path the file was read from, or the one it was expected at; null when the row names none.</param>
/// <param name="Detail">The reason for an operator, with the path; empty when the file is usable.</param>
public sealed record SshKeyFileFinding(string? Code, string? KeyFile, string Detail)
{
    /// <summary>Whether the file is an unencrypted OpenSSH private key whose public half is the row's.</summary>
    public bool Usable => Code == null;
}

/// <summary>
/// The one-time move of SSH CA keys from plaintext files on the node into the signer
/// (<c>docs/architecture/ssh-keystore.md</c>, "The import"). This is the only place in the node
/// that reads an SSH key file, and the only place that deletes one.
/// </summary>
/// <remarks>
/// <para>
/// For every <c>SshCaKeys</c> row whose storage is <see cref="SshCaKeyStorage.LegacyFile"/>,
/// enabled or not: the file is read and must be an unencrypted <c>openssh-key-v1</c> key whose
/// public half is the row's; it is offered to the signer as PKCS#8 under
/// <see cref="SigningPurpose.SshKeyMigration"/>; the signer's list must then show a key for the
/// row with that public key; one transaction sets the row's storage to
/// <see cref="SshCaKeyStorage.Signer"/>, clears its path and writes the
/// <see cref="SshKeyImportEntity"/> that keeps the path; and only then is the file overwritten
/// with zeros, flushed, and deleted with its <c>.pub</c>, and the audit entry written.
/// </para>
/// <para>
/// Every step can be repeated. A stop after the signer took the key leaves the row as it was:
/// the next pass offers the key again, the signer answers that it holds it, and the pass goes
/// on. A stop after the transaction leaves a file the row no longer names: the import record
/// names it, and the next pass, whatever the signer's state, removes it and writes the audit
/// entry still owed. A key whose file is missing, unreadable, encrypted or another key stays
/// as it is with its reason, and the other keys are imported all the same.
/// </para>
/// <para>
/// No key material is logged, and the buffers held here (the file's bytes, the PKCS#8) are
/// zeroed. The key objects the decoder builds are left to the collector.
/// </para>
/// </remarks>
public sealed class SshKeyFileImport
{
    /// <summary>The caller identity the import asks the signer under.</summary>
    public const string SignerCaller = "ssh-key-import";

    /// <summary>
    /// The directory SSH CA key files were written to unless the retired key path setting named
    /// another, relative to the application directory.
    /// </summary>
    public const string DefaultKeyDirectory = "config/ssh-ca-keys";

    /// <summary>No OpenSSH private key file is anywhere near this size; a larger file is not read.</summary>
    private const int MaxKeyFileBytes = 256 * 1024;

    /// <summary>
    /// How many keys a signer that has taken none may answer "unsupported" for before the pass
    /// stops offering it keys. One such answer can be about the key; two in a row with no key
    /// taken is a signer that predates the SSH keystore.
    /// </summary>
    private const int UnsupportedBeforeStopping = 2;

    private readonly ModularCADbContext _db;
    private readonly ISigningService _signer;
    private readonly IAuditService _audit;
    private readonly SshKeyImportState _state;
    private readonly ILogger<SshKeyFileImport> _logger;
    private readonly string _baseDirectory;

    /// <summary>
    /// Called with <c>overwrite</c> before a key file is overwritten and with <c>delete</c>
    /// once it has been overwritten and flushed, before it is deleted, each with the file's
    /// path. For tests, which observe the file between the steps and stop the import there.
    /// </summary>
    internal Action<string, string>? FileStep { get; set; }

    /// <summary>
    /// Creates the import over the application database, the signer, the audit and the state
    /// the readiness page reads.
    /// </summary>
    /// <param name="db">The application database, in a scope of the import's own.</param>
    /// <param name="signer">The signer the keys are imported into.</param>
    /// <param name="audit">Where each import is recorded.</param>
    /// <param name="state">What the last pass left, for the readiness page and the retry.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="baseDirectory">
    /// The directory a relative key path is relative to: the application directory, which is
    /// what the service that wrote those paths used. Null for <see cref="AppContext.BaseDirectory"/>.
    /// </param>
    public SshKeyFileImport(ModularCADbContext db, ISigningService signer, IAuditService audit, SshKeyImportState state,
        ILogger<SshKeyFileImport> logger, string? baseDirectory = null)
    {
        _db = db;
        _signer = signer;
        _audit = audit;
        _state = state;
        _logger = logger;
        _baseDirectory = baseDirectory ?? AppContext.BaseDirectory;
    }

    /// <summary>
    /// Runs one pass: finishes what an earlier pass left (a key file still on disk, an audit
    /// entry still owed), then imports every key that is still a file, when the signer is
    /// unlocked. Nothing here throws for a key that cannot be imported; the report and
    /// <see cref="SshKeyImportState"/> carry the reason. Returns what the pass did.
    /// </summary>
    public async Task<SshKeyImportReport> RunAsync(CancellationToken cancellationToken = default)
    {
        var report = await RunPassAsync(cancellationToken);
        foreach (var awaiting in _state.Record(report))
        {
            _logger.LogWarning("SSH CA key '{Name}' ({KeyId}) is still a key file on this node and signs nothing: {Detail}",
                awaiting.Name, awaiting.KeyId, awaiting.Detail);
        }
        if (report.Imported.Count > 0)
        {
            _logger.LogWarning(
                "{Count} SSH CA key(s) were imported into the signer. They were stored in plaintext before this version: backup archives and "
                + "pre-restore snapshots made before the import still contain them, and overwriting a file does not guarantee it is erased. "
                + "Rotating those SSH CAs is the only remedy.", report.Imported.Count);
        }
        return report;
    }

    /// <summary>The pass itself, without the bookkeeping <see cref="RunAsync"/> adds.</summary>
    private async Task<SshKeyImportReport> RunPassAsync(CancellationToken cancellationToken)
    {
        await FinishImportedAsync(cancellationToken);

        var rows = await _db.SshCaKeys.AsNoTracking()
            .Where(k => k.KeyStorage == SshCaKeyStorage.LegacyFile)
            .OrderBy(k => k.Name).ThenBy(k => k.Id)
            .ToListAsync(cancellationToken);
        var imported = new List<Guid>();
        var awaiting = new List<SshKeyAwaitingImport>();
        var waitingOnSigner = false;
        var unsupported = 0;

        if (rows.Count > 0)
        {
            SignerHealth health;
            try
            {
                health = await _signer.HealthAsync(cancellationToken);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("SSH key import: the signer did not report its state ({Error}).", ex.GetType().Name);
                health = SignerHealth.Unreachable();
            }

            // Set once the signer has shown that no further key can be imported in this pass.
            (string Code, string Detail)? stopped = null;
            if (!health.Unlocked)
            {
                var code = health.Backend == SignerHealth.UnreachableBackend ? SshKeyImportReasons.SignerUnreachable : SshKeyImportReasons.SignerLocked;
                stopped = (code, SshKeyImportReasons.Sentence(code));
                waitingOnSigner = true;
            }

            foreach (var row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (stopped is { } stop)
                {
                    awaiting.Add(Awaiting(row, stop.Code, stop.Detail, ExpectedPath(row.PrivateKeyPath)));
                    continue;
                }

                Outcome outcome;
                try
                {
                    outcome = await ImportAsync(row, cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError("SSH key import: importing SSH CA key {KeyId} failed with {Error}: {Message}", row.Id, ex.GetType().Name, ex.Message);
                    _db.ChangeTracker.Clear();
                    outcome = Outcome.Failed(SshKeyImportReasons.Failed, $"The import failed ({ex.GetType().Name}: {ex.Message}).", ExpectedPath(row.PrivateKeyPath));
                }

                if (outcome.Imported)
                {
                    imported.Add(row.Id);
                    continue;
                }
                awaiting.Add(Awaiting(row, outcome.Code!, outcome.Detail, outcome.KeyFile));
                if (outcome.StopsThePass)
                {
                    stopped = (outcome.Code!, outcome.Detail);
                    waitingOnSigner = outcome.Code is SshKeyImportReasons.SignerLocked or SshKeyImportReasons.SignerUnreachable;
                }
                else if (outcome.Code == SshKeyImportReasons.SignerUpgradeRequired && imported.Count == 0 && ++unsupported >= UnsupportedBeforeStopping)
                {
                    // A signer that took no key and has answered "unsupported" twice is one that
                    // predates the SSH keystore: no further key is read or sent to it in this pass.
                    stopped = (SshKeyImportReasons.SignerUpgradeRequired,
                        $"{SshCaKeyUnavailableException.SignerPredatesSshKeystore}. Upgrade the signer, and the import runs again by itself.");
                }
            }
        }

        var filesPending = await _db.SshKeyImports.AsNoTracking().CountAsync(i => i.FileRemovedAt == null, cancellationToken);
        var auditsPending = await _db.SshKeyImports.AsNoTracking().CountAsync(i => i.AuditedAt == null, cancellationToken);
        return new SshKeyImportReport(imported, awaiting, filesPending, auditsPending, waitingOnSigner);
    }

    /// <summary>
    /// Imports one key: reads its file, offers it to the signer, confirms the signer lists it,
    /// switches the row and removes the file. Returns what became of it.
    /// </summary>
    private async Task<Outcome> ImportAsync(SshCaKeyEntity row, CancellationToken cancellationToken)
    {
        var (finding, key) = Read(row.Name, row.PublicKey, row.PrivateKeyPath, _baseDirectory);
        if (key == null)
            return Outcome.Failed(finding.Code!, finding.Detail, finding.KeyFile);

        var keyFile = finding.KeyFile!;
        var target = new KeyRef(row.Id, KeyRef.SshKeystore);
        var context = SigningContext.ForCa(SignerCaller, SigningPurpose.SshKeyMigration, row.CertificateAuthorityId, spaceId: null);

        var pkcs8 = key.ToPkcs8();
        KeyRef held;
        try
        {
            held = await _signer.ImportKeyAsync(new KeyMaterial(pkcs8, KeyMaterial.Pkcs8, row.Id, KeyRef.SshKeystore), context, cancellationToken);
        }
        catch (SigningRefusedException ex)
        {
            return await RefusedAsync(row, ex, keyFile, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }

        if (!string.Equals(held.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase) || held.CertificateId != row.Id)
        {
            _logger.LogError(
                "SSH key import: the signer answered the import of SSH CA key {KeyId} with the reference {Reference}, which is not in {Keystore}. No row was changed and no file was removed.",
                row.Id, held, KeyRef.SshKeystore);
            return Outcome.Stop(SshKeyImportReasons.SignerUpgradeRequired,
                $"{SshCaKeyUnavailableException.SignerPredatesSshKeystore}: it answered the import with a key in {held.Keystore}, which holds X.509 keys.", keyFile);
        }

        if (!await SignerListsAsync(target, key.PublicKey, context, cancellationToken))
            return Outcome.Failed(SshKeyImportReasons.NotConfirmed,
                $"The signer took the key and does not list a key with the fingerprint {key.PublicKey.Fingerprint} for this SSH CA. The row and the file {keyFile} were left as they are.", keyFile);

        var record = await SwitchRowAsync(row, key.PublicKey.Fingerprint, keyFile, cancellationToken);
        if (record == null)
            return Outcome.Done;

        _logger.LogInformation("SSH CA key '{Name}' ({KeyId}, {Fingerprint}) imported into the signer.", row.Name, row.Id, key.PublicKey.Fingerprint);
        await FinishAsync(record, row, fileVerified: true, cancellationToken);
        return Outcome.Done;
    }

    /// <summary>
    /// What a refusal of the import means for the key and for the rest of the pass. A locked or
    /// unreachable signer stops the pass, and so does nothing else: a signer that cannot take
    /// one key is asked for the next all the same.
    /// </summary>
    private async Task<Outcome> RefusedAsync(SshCaKeyEntity row, SigningRefusedException refusal, string keyFile, CancellationToken cancellationToken)
    {
        switch (refusal.Reason)
        {
            case SigningRefusalReason.SignerLocked:
                return Outcome.Stop(SshKeyImportReasons.SignerLocked, SshKeyImportReasons.Sentence(SshKeyImportReasons.SignerLocked), keyFile);
            case SigningRefusalReason.SignerUnavailable:
                return Outcome.Stop(SshKeyImportReasons.SignerUnreachable, SshKeyImportReasons.Sentence(SshKeyImportReasons.SignerUnreachable), keyFile);
            case SigningRefusalReason.OperationUnsupported:
                return Outcome.Failed(SshKeyImportReasons.SignerUpgradeRequired,
                    $"{SshCaKeyUnavailableException.SignerPredatesSshKeystore}, or cannot hold this key. Upgrade the signer, and the import runs "
                    + $"again by itself. The signer answered: {refusal.Message}", keyFile);
        }

        // Another control process may have imported the key between the read of the rows and now.
        var storage = await _db.SshCaKeys.AsNoTracking().Where(k => k.Id == row.Id).Select(k => k.KeyStorage).FirstOrDefaultAsync(cancellationToken);
        if (storage == SshCaKeyStorage.Signer)
            return Outcome.Done;
        return Outcome.Failed(SshKeyImportReasons.SignerRefused, $"The signer refused the key ({refusal.Reason}): {refusal.Message}", keyFile);
    }

    /// <summary>
    /// Whether the signer lists a key of kind <see cref="KeyKind.SshCa"/> under
    /// <paramref name="target"/> with the public key <paramref name="publicKey"/>. No test
    /// signature is made: that would issue a certificate nothing recorded.
    /// </summary>
    private async Task<bool> SignerListsAsync(KeyRef target, SshPublicKey publicKey, SigningContext context, CancellationToken cancellationToken)
    {
        var listed = await _signer.ListKeysAsync(context, cancellationToken);
        foreach (var info in listed)
        {
            if (info.Kind != KeyKind.SshCa || info.Key.CertificateId != target.CertificateId
                || !string.Equals(info.Key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                if (SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(info.PublicKeyDer)).Equals(publicKey))
                    return true;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or IOException)
            {
                // A listed key that cannot be read is not the row's key.
            }
        }
        return false;
    }

    /// <summary>
    /// The one transaction of an import: the row's storage becomes
    /// <see cref="SshCaKeyStorage.Signer"/>, its path is cleared, and the record that keeps the
    /// path is written. Returns the record, or null when the row was no longer a legacy file,
    /// which is another process having switched it; that process removes the file.
    /// </summary>
    private async Task<SshKeyImportEntity?> SwitchRowAsync(SshCaKeyEntity row, string fingerprint, string keyFile, CancellationToken cancellationToken)
    {
        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            var current = await _db.SshCaKeys.FirstOrDefaultAsync(k => k.Id == row.Id, cancellationToken);
            if (current == null || current.KeyStorage != SshCaKeyStorage.LegacyFile)
            {
                await transaction.RollbackAsync(cancellationToken);
                _db.ChangeTracker.Clear();
                return null;
            }

            current.KeyStorage = SshCaKeyStorage.Signer;
            current.PrivateKeyPath = null;

            var record = await _db.SshKeyImports.FirstOrDefaultAsync(i => i.SshCaKeyId == row.Id, cancellationToken);
            if (record == null)
            {
                record = new SshKeyImportEntity { SshCaKeyId = row.Id };
                _db.SshKeyImports.Add(record);
            }
            record.Name = row.Name;
            record.Fingerprint = fingerprint;
            record.FilePath = keyFile;
            record.ImportedAt = DateTime.UtcNow;
            record.FileRemovedAt = null;
            record.AuditedAt = null;

            await _db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return record;
        }
        catch
        {
            try { await transaction.RollbackAsync(CancellationToken.None); } catch { /* the failure being unwound is the one to report */ }
            _db.ChangeTracker.Clear();
            throw;
        }
    }

    /// <summary>
    /// Finishes every import an earlier pass, or another process, left unfinished: a key file
    /// still on disk, an audit entry still owed. It needs nothing from the signer, so it runs
    /// whatever the signer's state.
    /// </summary>
    private async Task FinishImportedAsync(CancellationToken cancellationToken)
    {
        var unfinished = await _db.SshKeyImports
            .Where(i => i.FileRemovedAt == null || i.AuditedAt == null)
            .OrderBy(i => i.ImportedAt)
            .ToListAsync(cancellationToken);
        foreach (var record in unfinished)
        {
            var row = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == record.SshCaKeyId, cancellationToken);
            await FinishAsync(record, row, fileVerified: false, cancellationToken);
        }
    }

    /// <summary>
    /// Removes the key file of an imported key and writes the audit entry of the import, each
    /// only when still owed, and marks the record. A file that cannot be removed, or an audit
    /// that cannot be written, is logged and left for the next pass.
    /// </summary>
    /// <param name="record">The import record; tracked by the context.</param>
    /// <param name="row">The key's row, for its public key and CA; null when it is gone.</param>
    /// <param name="fileVerified">Whether this pass has just read the file and found the row's key in it.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    private async Task FinishAsync(SshKeyImportEntity record, SshCaKeyEntity? row, bool fileVerified, CancellationToken cancellationToken)
    {
        if (record.FileRemovedAt == null)
        {
            try
            {
                RemoveKeyFiles(record, TryParsePublicKey(row?.PublicKey), fileVerified);
                record.FileRemovedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(
                    "SSH CA key '{Name}' ({KeyId}) is held by the signer, and its key file {File} could not be removed ({Error}: {Message}). "
                    + "Remove the file by hand; the next start tries again.",
                    record.Name, record.SshCaKeyId, record.FilePath, ex.GetType().Name, ex.Message);
            }
        }

        if (record.AuditedAt == null)
        {
            try
            {
                await _audit.LogAsync(AuditActionType.SshCaKeyImported, null, "system", "SshCaKey", record.SshCaKeyId.ToString(),
                    new
                    {
                        record.Name,
                        record.Fingerprint,
                        File = record.FilePath,
                        FileRemoved = record.FileRemovedAt != null,
                        record.ImportedAt,
                        Storage = SshCaKeyStorage.Signer,
                    },
                    certificateAuthorityId: row?.CertificateAuthorityId);
                record.AuditedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning("The audit entry for the import of SSH CA key {KeyId} could not be written ({Error}); the next pass writes it.",
                    record.SshCaKeyId, ex.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Removes the private key file of an imported key and its <c>.pub</c>, and the directory
    /// when that leaves it empty. The private key file is overwritten with zeros and flushed to
    /// disk before it is deleted. A file this pass did not just read is removed only when it
    /// still holds the key, or zeros from an overwrite that was not followed by its delete; a
    /// file holding anything else is left alone. The <c>.pub</c> is removed only when it holds
    /// the row's public key.
    /// </summary>
    private void RemoveKeyFiles(SshKeyImportEntity record, SshPublicKey? rowKey, bool fileVerified)
    {
        var path = record.FilePath;
        if (File.Exists(path))
        {
            if (fileVerified || HoldsKeyOrZeros(path, record.Fingerprint))
            {
                OverwriteAndDelete(path);
                _logger.LogInformation("The key file of SSH CA key '{Name}' ({KeyId}) was overwritten and deleted: {File}", record.Name, record.SshCaKeyId, path);
            }
            else
            {
                _logger.LogWarning(
                    "The file {File} no longer holds SSH CA key '{Name}' ({KeyId}), which the signer holds; it was left as it is.",
                    path, record.Name, record.SshCaKeyId);
            }
        }

        var publicPath = path + ".pub";
        if (File.Exists(publicPath))
        {
            if (rowKey != null && rowKey.Equals(TryReadPublicFile(publicPath)))
                File.Delete(publicPath);
            else
                _logger.LogWarning("The file {File} does not hold the public key of SSH CA key {KeyId}; it was left as it is.", publicPath, record.SshCaKeyId);
        }

        var directory = Path.GetDirectoryName(path);
        try
        {
            if (!string.IsNullOrEmpty(directory) && Directory.Exists(directory) && !Directory.EnumerateFileSystemEntries(directory).Any())
                Directory.Delete(directory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An empty directory left behind holds no key.
        }
    }

    /// <summary>
    /// Overwrites a file with zeros over its whole length, flushes that to disk, and deletes it.
    /// On solid-state drives, copy-on-write filesystems, snapshots and filesystem backups an
    /// overwrite does not guarantee the old bytes are gone; this is what a process can do.
    /// </summary>
    private void OverwriteAndDelete(string path) => EraseFile(path, FileStep);

    /// <summary>
    /// Whether the file at <paramref name="path"/> begins as an OpenSSH private key file does,
    /// or holds nothing but zeros (an overwrite that was not followed by its delete). A factory
    /// reset asks this before it erases a file at a path a key row named, so that a row cannot
    /// point it at some other file.
    /// </summary>
    public static bool LooksLikeKeyFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxKeyFileBytes)
                return false;
            var bytes = File.ReadAllBytes(path);
            try
            {
                return bytes.All(b => b == 0) || bytes.AsSpan().StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----"u8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Overwrites a file with zeros over its whole length, flushes that to disk, and deletes it:
    /// how a plaintext SSH CA key file is removed, by the import and by a factory reset.
    /// </summary>
    /// <param name="path">The file to erase.</param>
    /// <param name="step">Called with <c>overwrite</c> before the overwrite and <c>delete</c> before the delete, with the path; for tests.</param>
    public static void EraseFile(string path, Action<string, string>? step = null)
    {
        step?.Invoke("overwrite", path);
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.ReadOnly))
            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);

        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            var remaining = stream.Length;
            var zeros = new byte[(int)Math.Min(Math.Max(remaining, 1), 64 * 1024)];
            stream.Position = 0;
            while (remaining > 0)
            {
                var count = (int)Math.Min(remaining, zeros.Length);
                stream.Write(zeros, 0, count);
                remaining -= count;
            }
            stream.Flush(flushToDisk: true);
        }

        step?.Invoke("delete", path);
        File.Delete(path);
    }

    /// <summary>
    /// Whether the file at <paramref name="path"/> is the key with <paramref name="fingerprint"/>,
    /// or nothing but zeros.
    /// </summary>
    private static bool HoldsKeyOrZeros(string path, string fingerprint)
    {
        if (new FileInfo(path).Length > MaxKeyFileBytes)
            return false;
        var bytes = File.ReadAllBytes(path);
        try
        {
            if (bytes.All(b => b == 0))
                return true;
            return SshPrivateKeyFile.ReadFile(bytes).PublicKey.Fingerprint == fingerprint;
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>The public key in a <c>.pub</c> file, or null when it is not one public key.</summary>
    private static SshPublicKey? TryReadPublicFile(string path)
    {
        try
        {
            if (new FileInfo(path).Length > SshPublicKey.MaxAuthorizedKeyLength)
                return null;
            return TryParsePublicKey(File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The public key of an authorized_keys line, or null when the text is not one.</summary>
    private static SshPublicKey? TryParsePublicKey(string? authorizedKey)
    {
        if (string.IsNullOrWhiteSpace(authorizedKey))
            return null;
        try
        {
            return SshPublicKey.ParseAuthorizedKey(authorizedKey);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Looks at the key file of one SSH CA key row without importing anything, for the upgrade
    /// check: whether the file is there, is an unencrypted OpenSSH private key, and holds the
    /// row's key. The key read is discarded.
    /// </summary>
    /// <param name="name">The SSH CA key's name, for the reason.</param>
    /// <param name="publicKey">The row's public key, an authorized_keys line.</param>
    /// <param name="keyFile">The row's key file path.</param>
    /// <param name="baseDirectory">The directory a relative path is relative to: the installed application directory.</param>
    public static SshKeyFileFinding Inspect(string name, string? publicKey, string? keyFile, string baseDirectory)
        => Read(name, publicKey, keyFile, baseDirectory).Finding;

    /// <summary>
    /// The paths a row's key file is looked for at, in order: the path as the row gives it
    /// (relative to <paramref name="baseDirectory"/> when it is relative, which is how the
    /// service that wrote it resolved its key directory), then a file of the same name in
    /// <see cref="DefaultKeyDirectory"/> under <paramref name="baseDirectory"/>, which is where
    /// a restore onto another host puts the files of an archive whose rows name the old host's
    /// directory.
    /// </summary>
    internal static IReadOnlyList<string> Candidates(string keyFile, string baseDirectory)
    {
        var candidates = new List<string>();
        try
        {
            candidates.Add(Path.GetFullPath(Path.IsPathRooted(keyFile) ? keyFile : Path.Combine(baseDirectory, keyFile)));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            // A path this system cannot form is not looked at; the file name still is.
        }

        var name = keyFile[(keyFile.LastIndexOfAny(['/', '\\']) + 1)..];
        if (name.Length > 0 && name is not ("." or ".."))
        {
            var byName = Path.GetFullPath(Path.Combine(baseDirectory, DefaultKeyDirectory, name));
            if (!candidates.Contains(byName, StringComparer.Ordinal))
                candidates.Add(byName);
        }
        return candidates;
    }

    /// <summary>The first path a row's key file is looked for at, or null when the row names none.</summary>
    private string? ExpectedPath(string? keyFile)
        => string.IsNullOrWhiteSpace(keyFile) ? null : Candidates(keyFile, _baseDirectory).FirstOrDefault();

    /// <summary>
    /// Reads the key file of a row and checks it against the row's public key. Returns the key
    /// only when the file holds it; otherwise the finding says why not.
    /// </summary>
    private static (SshKeyFileFinding Finding, SshPrivateKey? Key) Read(string name, string? publicKey, string? keyFile, string baseDirectory)
    {
        static (SshKeyFileFinding, SshPrivateKey?) No(string code, string? path, string detail) => (new SshKeyFileFinding(code, path, detail), null);

        if (string.IsNullOrWhiteSpace(keyFile))
            return No(SshKeyImportReasons.FileMissing, null, $"The row of SSH CA key '{name}' names no key file.");

        var candidates = Candidates(keyFile, baseDirectory);
        var expected = candidates.FirstOrDefault();
        var rowKey = TryParsePublicKey(publicKey);
        if (rowKey == null)
            return No(SshKeyImportReasons.RowUnreadable, expected,
                $"The public key recorded for SSH CA key '{name}' cannot be read, so no key file can be matched to it.");

        var path = candidates.FirstOrDefault(File.Exists);
        if (path == null)
            return No(SshKeyImportReasons.FileMissing, expected,
                $"No key file was found for SSH CA key '{name}'. It was looked for at {string.Join(" and at ", candidates)}. "
                + "Put the file there on the host that runs the control role, or disable this SSH CA.");

        byte[] bytes;
        try
        {
            if (new FileInfo(path).Length > MaxKeyFileBytes)
                return No(SshKeyImportReasons.FileNotAKey, path, $"The file {path} is too large to be an OpenSSH private key.");
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or NotSupportedException)
        {
            return No(SshKeyImportReasons.FileUnreadable, path, $"The key file {path} could not be read ({ex.GetType().Name}: {ex.Message}).");
        }

        SshPrivateKey key;
        try
        {
            key = SshPrivateKeyFile.ReadFile(bytes);
        }
        catch (SshPrivateKeyEncryptedException)
        {
            return No(SshKeyImportReasons.FileEncrypted, path,
                $"The key file {path} is protected by a passphrase. Only an unencrypted key file is imported: remove the passphrase with the OpenSSH key tool, and the import takes the file at its next pass.");
        }
        catch (FormatException ex)
        {
            return No(SshKeyImportReasons.FileNotAKey, path, $"The file {path} is not an unencrypted OpenSSH private key this version reads ({ex.Message})");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }

        if (!key.PublicKey.Equals(rowKey))
            return No(SshKeyImportReasons.KeyMismatch, path,
                $"The key file {path} holds the key {key.PublicKey.Fingerprint}; SSH CA key '{name}' publishes {rowKey.Fingerprint}. The file is not this SSH CA's key.");

        if (!SshKeyTypes.Certifiable.Contains(key.PublicKey.KeyType)
            || (key.PublicKey.KeyType == SshKeyTypes.Rsa && key.PublicKey.KeySizeBits < SshCertificateRules.MinRsaBits))
            return No(SshKeyImportReasons.UnsupportedKey, path,
                $"The key in {path} is a {key.PublicKey.KeyType} key of {key.PublicKey.KeySizeBits} bits. The signer holds Ed25519, ECDSA P-256, P-384 and P-521 "
                + $"and RSA keys of at least {SshCertificateRules.MinRsaBits} bits as SSH CA keys.");

        return (new SshKeyFileFinding(null, path, string.Empty), key);
    }

    /// <summary>The entry of a key that stays a file.</summary>
    private static SshKeyAwaitingImport Awaiting(SshCaKeyEntity row, string code, string detail, string? keyFile)
        => new(row.Id, row.Name, code, SshKeyImportReasons.Sentence(code), detail, keyFile, DateTime.UtcNow);

    /// <summary>
    /// What became of one key in a pass: imported, or left with a reason, and whether that
    /// reason holds for every key after it.
    /// </summary>
    private sealed record Outcome(bool Imported, string? Code, string Detail, string? KeyFile, bool StopsThePass)
    {
        /// <summary>The key is the signer's, by this pass or by another process.</summary>
        public static readonly Outcome Done = new(true, null, string.Empty, null, false);

        /// <summary>The key stays a file; the next key is tried.</summary>
        public static Outcome Failed(string code, string detail, string? keyFile) => new(false, code, detail, keyFile, false);

        /// <summary>The key stays a file, and so does every key after it in this pass.</summary>
        public static Outcome Stop(string code, string detail, string? keyFile) => new(false, code, detail, keyFile, true);
    }
}
