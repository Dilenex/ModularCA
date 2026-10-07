using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using Org.BouncyCastle.Security;

namespace ModularCA.Core.Services;

/// <summary>Where the private key of one SSH CA key is, as the readiness page and the admin key list show it.</summary>
/// <param name="Id">The <c>SshCaKeys</c> row.</param>
/// <param name="Name">The SSH CA key's name.</param>
/// <param name="IsEnabled">Whether the row is enabled.</param>
/// <param name="KeyStorage">The row's storage, one of <see cref="SshCaKeyStorage"/>.</param>
/// <param name="State">One of <see cref="SshKeyCustody"/>'s states.</param>
/// <param name="ReasonCode">For a key that is not held: why, as a code. Null for a held key.</param>
/// <param name="Reason">The sentence for the code, which names no path and nothing the signer said. Null for a held key.</param>
/// <param name="Detail">The whole reason for an operator, with paths. Null for a held key.</param>
/// <param name="KeyFile">For a key awaiting import: the path its file is expected at, when known.</param>
/// <param name="ImportedAt">When the key was imported from a file on the node; null for a key that never was one.</param>
public sealed record SshKeyCustodyEntry(Guid Id, string Name, bool IsEnabled, string KeyStorage, string State,
    string? ReasonCode, string? Reason, string? Detail, string? KeyFile, DateTime? ImportedAt);

/// <summary>What the signer and the key rows say together about every SSH CA key.</summary>
/// <param name="SignerUnlocked">Whether the signer answered that it is unlocked.</param>
/// <param name="SignerListed">Whether the signer's list of keys could be read; when not, no key is reported as missing from it.</param>
/// <param name="Keys">Every SSH CA key, by name.</param>
public sealed record SshKeyCustodyReport(bool SignerUnlocked, bool SignerListed, IReadOnlyList<SshKeyCustodyEntry> Keys)
{
    /// <summary>How many SSH CA keys the signer holds for their rows.</summary>
    public int Held => Keys.Count(k => k.State == SshKeyCustody.Held);

    /// <summary>The keys that are still files on the node.</summary>
    public IEnumerable<SshKeyCustodyEntry> AwaitingImport => Keys.Where(k => k.State == SshKeyCustody.AwaitingImport);

    /// <summary>The keys whose rows say the signer holds them and which the signer does not list.</summary>
    public IEnumerable<SshKeyCustodyEntry> NotHeld => Keys.Where(k => k.State == SshKeyCustody.NotHeld);

    /// <summary>
    /// What the readiness page shows of this report: the counts, and for each key that is not
    /// held its id, its name (which the public SSH route lists too), a reason code and the
    /// sentence for the code. It carries no path, no host name and nothing the signer or the
    /// operating system said; those are on the admin key list.
    /// </summary>
    public SshKeyReadiness ToReadiness() => new(
        Keys.Count,
        Held,
        AwaitingImport.Select(k => new SshKeyReadinessEntry(k.Id, k.Name, k.ReasonCode ?? SshKeyImportReasons.NotAttempted, k.Reason ?? string.Empty)).ToList(),
        NotHeld.Select(k => new SshKeyReadinessEntry(k.Id, k.Name, k.ReasonCode ?? SshKeyCustody.SignerHoldsNoKey, k.Reason ?? string.Empty)).ToList(),
        Keys.Count(k => k.State == SshKeyCustody.Unknown));
}

/// <summary>The SSH part of the signer's entry on the readiness page.</summary>
/// <param name="Total">How many SSH CA keys there are.</param>
/// <param name="Held">How many of them the signer holds.</param>
/// <param name="AwaitingImport">The keys that are still files on the node, each with its reason.</param>
/// <param name="NotHeld">The keys recorded as the signer's which the signer does not list.</param>
/// <param name="Unknown">How many keys could not be checked because the signer is locked or did not answer.</param>
public sealed record SshKeyReadiness(int Total, int Held, IReadOnlyList<SshKeyReadinessEntry> AwaitingImport,
    IReadOnlyList<SshKeyReadinessEntry> NotHeld, int Unknown);

/// <summary>One SSH CA key the signer does not hold, as the readiness page names it.</summary>
/// <param name="Id">The <c>SshCaKeys</c> row.</param>
/// <param name="Name">The SSH CA key's name.</param>
/// <param name="ReasonCode">Why, as a code: one of <see cref="SshKeyImportReasons"/>, or <see cref="SshKeyCustody.SignerHoldsNoKey"/>.</param>
/// <param name="Reason">The sentence for the code.</param>
public sealed record SshKeyReadinessEntry(Guid Id, string Name, string ReasonCode, string Reason);

/// <summary>
/// Reads where every SSH CA key is: held by the signer, still a file on the node awaiting its
/// import, or recorded as the signer's while the signer lists no key for it. The last is a row
/// written by a creation that stopped before its key was committed, or a signer that lost its
/// SSH keystore; such an SSH CA signs nothing. It reads no key and no key file.
/// </summary>
public static class SshKeyCustody
{
    /// <summary>The signer lists the row's key.</summary>
    public const string Held = "held";

    /// <summary>The key is still a file on the node; the row's storage is <see cref="SshCaKeyStorage.LegacyFile"/>.</summary>
    public const string AwaitingImport = "awaitingImport";

    /// <summary>The row says the signer holds the key, and the signer, unlocked, lists none for it.</summary>
    public const string NotHeld = "notHeld";

    /// <summary>The signer is locked or did not answer, so whether it holds the key is not known.</summary>
    public const string Unknown = "unknown";

    /// <summary>The reason code of a <see cref="NotHeld"/> key.</summary>
    public const string SignerHoldsNoKey = "signerHoldsNoKey";

    /// <summary>The caller identity the list of keys is asked under.</summary>
    private const string SignerCaller = "ssh-key-readiness";

    /// <summary>
    /// Reads the SSH CA key rows and, when there are any, the signer's state and its list of
    /// keys. A signer that does not answer, or whose list cannot be read, makes the keys the
    /// rows give to it <see cref="Unknown"/>, never <see cref="NotHeld"/>.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="signer">The signer.</param>
    /// <param name="imports">What the last import pass in this process left, or null where no import runs.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<SshKeyCustodyReport> ReadAsync(ModularCADbContext db, ISigningService signer, SshKeyImportState? imports,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(signer);

        var rows = await db.SshCaKeys.AsNoTracking()
            .OrderBy(k => k.Name).ThenBy(k => k.Id)
            .Select(k => new { k.Id, k.Name, k.IsEnabled, k.KeyStorage, k.PublicKey, k.CertificateAuthorityId })
            .ToListAsync(cancellationToken);
        if (rows.Count == 0)
            return new SshKeyCustodyReport(SignerUnlocked: false, SignerListed: false, []);

        var importedAt = await db.SshKeyImports.AsNoTracking()
            .ToDictionaryAsync(i => i.SshCaKeyId, i => i.ImportedAt, cancellationToken);

        // Only the SSH CAs whose rows give their key to the signer are asked about, one list each.
        var signerCas = rows.Where(r => r.KeyStorage != SshCaKeyStorage.LegacyFile).Select(r => r.CertificateAuthorityId).Distinct().ToList();
        var unlocked = false;
        Dictionary<Guid, List<SshPublicKey>>? listed = null;
        try
        {
            unlocked = (await signer.HealthAsync(cancellationToken)).Unlocked;
            if (unlocked)
            {
                var found = new Dictionary<Guid, List<SshPublicKey>>();
                foreach (var caId in signerCas)
                {
                    var keys = await signer.ListKeysAsync(SigningContext.ForCa(SignerCaller, SigningPurpose.Certificate, caId, spaceId: null), cancellationToken);
                    foreach (var key in keys)
                    {
                        if (key.Kind != KeyKind.SshCa || !string.Equals(key.Key.Keystore, KeyRef.SshKeystore, StringComparison.OrdinalIgnoreCase))
                            continue;
                        try
                        {
                            var publicKey = SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(key.PublicKeyDer));
                            if (!found.TryGetValue(key.Key.CertificateId, out var held))
                                found[key.Key.CertificateId] = held = [];
                            held.Add(publicKey);
                        }
                        catch (Exception ex) when (ex is ArgumentException or FormatException or IOException)
                        {
                            // A listed key that cannot be read is no row's key.
                        }
                    }
                }
                listed = found;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Serilog.Log.Warning("SSH key readiness: the signer's keys could not be listed ({Error}).", ex.GetType().Name);
            listed = null;
        }

        var entries = new List<SshKeyCustodyEntry>(rows.Count);
        foreach (var row in rows)
        {
            DateTime? imported = importedAt.TryGetValue(row.Id, out var at) ? at : null;
            if (row.KeyStorage == SshCaKeyStorage.LegacyFile)
            {
                var awaiting = imports?.Of(row.Id);
                var code = awaiting?.Code ?? SshKeyImportReasons.NotAttempted;
                var sentence = SshKeyImportReasons.Sentence(code);
                entries.Add(new SshKeyCustodyEntry(row.Id, row.Name, row.IsEnabled, row.KeyStorage, AwaitingImport,
                    code, sentence, awaiting?.Detail ?? sentence, awaiting?.KeyFile, imported));
                continue;
            }

            if (listed == null)
            {
                var sentence = unlocked
                    ? "The signer's keys could not be listed, so whether it holds this key is not known."
                    : "The signer is locked or did not answer, so whether it holds this key is not known.";
                entries.Add(new SshKeyCustodyEntry(row.Id, row.Name, row.IsEnabled, row.KeyStorage, Unknown, null, sentence, sentence, null, imported));
                continue;
            }

            var rowKey = TryParse(row.PublicKey);
            if (rowKey != null && listed.TryGetValue(row.Id, out var keysOfRow) && keysOfRow.Any(k => k.Equals(rowKey)))
            {
                entries.Add(new SshKeyCustodyEntry(row.Id, row.Name, row.IsEnabled, row.KeyStorage, Held, null, null, null, null, imported));
                continue;
            }

            const string notHeld = "The signer holds no key for this SSH CA, so it signs nothing.";
            entries.Add(new SshKeyCustodyEntry(row.Id, row.Name, row.IsEnabled, row.KeyStorage, NotHeld, SignerHoldsNoKey, notHeld,
                notHeld + " Its creation stopped before the key was committed, or the signer no longer has the SSH keystore that held it. "
                + "Disable this SSH CA and create a new one, or restore the signer's SSH keystore from a backup.", null, imported));
        }
        return new SshKeyCustodyReport(unlocked, listed != null, entries);
    }

    /// <summary>The public key on a row, or null when it cannot be read.</summary>
    private static SshPublicKey? TryParse(string? authorizedKey)
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
}
