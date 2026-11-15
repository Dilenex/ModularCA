using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using ModularCA.Journal;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Database;

/// <summary>
/// The facts the node asserts in the signer's journal, queued from the changes a save is about
/// to make (<c>docs/architecture/signer-journal.md</c>). Reading them off the change tracker,
/// in the save itself, has two effects that calling the signer from each service would not:
/// the fact commits or rolls back with the change it describes, and a new code path that
/// revokes or disables something is covered without knowing about the journal.
/// </summary>
public partial class ModularCADbContext
{
    /// <summary>Facts waiting to be recorded in the signer's journal.</summary>
    public DbSet<SignerFactEntity> SignerFacts { get; set; }

    /// <summary>Raised after a save that queued a fact, so the node offers it to the signer at once instead of at its next look.</summary>
    public static event Action? SignerFactQueued;

    private static readonly ConcurrentDictionary<Guid, (byte[]? CaKey, Guid? CaId)> IssuerKeys = new();

    /// <summary>
    /// Queues a fact for the signer's journal; the caller's next save writes it with whatever
    /// else it changes. For a change the change tracker does not see: one made by a bulk
    /// statement, or one that is not a change of a row.
    /// </summary>
    /// <param name="type">The record type (<see cref="RecordType"/>).</param>
    /// <param name="payload">The fact's payload, encoded.</param>
    public void QueueSignerFact(ushort type, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        SignerFacts.Add(new SignerFactEntity { Type = type, Payload = payload, CreatedAt = DateTime.UtcNow });
    }

    /// <summary>
    /// Queues a fact at once, in a statement of its own, without saving anything else this
    /// context tracks. For a caller that changed a row with a bulk statement and has no save of
    /// its own to ride on. Inside the caller's transaction when it has one.
    /// </summary>
    /// <param name="type">The record type (<see cref="RecordType"/>).</param>
    /// <param name="payload">The fact's payload, encoded.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task QueueSignerFactNowAsync(ushort type, byte[] payload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (Database.IsRelational())
        {
            int recordType = type;
            var now = DateTime.UtcNow;
            await Database.ExecuteSqlInterpolatedAsync(
                $"""INSERT INTO "SignerFactQueue" ("Type", "Payload", "CreatedAt", "Attempts") VALUES ({recordType}, {payload}, {now}, 0)""", cancellationToken);
        }
        else
        {
            QueueSignerFact(type, payload);
            await base.SaveChangesAsync(true, cancellationToken);
        }
        SignalSignerFactQueued();
    }

    /// <summary>
    /// Queues, for the save about to run, the facts its tracked changes amount to: a certificate
    /// revoked, put on hold, released from hold or retired; a serial revoked with no
    /// certificate; a CA, an SSH CA key or a space disabled or deleted; an account deactivated,
    /// locked or deleted; a sign-in credential revoked; an ACME external account binding used;
    /// the stored incarnation replaced by another. Enabling again is not a fact. Returns
    /// whether any was queued.
    /// </summary>
    private bool QueueSignerFactsForTrackedChanges()
    {
        var facts = new List<(ushort Type, byte[] Payload)>();
        // Materialized first: queuing adds entries to the tracker being walked.
        foreach (var entry in ChangeTracker.Entries().Where(e => e.State is EntityState.Added or EntityState.Modified).ToList())
        {
            try
            {
                switch (entry.Entity)
                {
                    case CertificateEntity certificate:
                        CertificateFacts(entry, certificate, facts);
                        break;
                    case RevokedSerialTombstoneEntity tombstone when entry.State == EntityState.Added:
                        if (IssuerOf(tombstone.CaCertificateId) is { CaKey: { } tombstoneKey } &&
                            Serial(tombstone.SerialNumber) is { } tombstoneSerial)
                            facts.Add((RecordType.Revocation, new RevocationPayload(tombstoneSerial, tombstoneKey, tombstone.CertificateAuthorityId.ToString("D"),
                                ReasonCode(tombstone.RevocationReason), Micros(tombstone.RevocationDate), Known: false, RevocationForm.Revoked).Encode()));
                        break;
                    case CertificateAuthorityEntity ca when Turned(entry, nameof(CertificateAuthorityEntity.IsEnabled), to: false)
                                                            || Turned(entry, nameof(CertificateAuthorityEntity.IsDeleted), to: true):
                        facts.Add(Disabled(DisabledKind.Ca, ca.Id));
                        break;
                    case SshCaKeyEntity sshKey when Turned(entry, nameof(SshCaKeyEntity.IsEnabled), to: false):
                        facts.Add(Disabled(DisabledKind.SshCaKey, sshKey.Id));
                        break;
                    case SpaceEntity space when Turned(entry, nameof(SpaceEntity.IsEnabled), to: false)
                                                || Turned(entry, nameof(SpaceEntity.IsDeleted), to: true):
                        facts.Add(Disabled(DisabledKind.Space, space.Id));
                        break;
                    case UserEntity user when Turned(entry, nameof(UserEntity.IsActive), to: false)
                                              || Turned(entry, nameof(UserEntity.IsLocked), to: true)
                                              || Turned(entry, nameof(UserEntity.IsDeleted), to: true):
                        facts.Add(Disabled(DisabledKind.Account, user.Id));
                        break;
                    case MtlsCredentialEntity credential when Turned(entry, nameof(MtlsCredentialEntity.IsRevoked), to: true):
                        facts.Add(Disabled(DisabledKind.SignInCredential, credential.Id));
                        break;
                    case ApiKeyEntity apiKey when entry.State == EntityState.Modified
                                                  && entry.Property(nameof(ApiKeyEntity.RevokedAt)) is { OriginalValue: null, CurrentValue: not null }:
                        facts.Add(Disabled(DisabledKind.SignInCredential, apiKey.Id));
                        break;
                    case AcmeEabKeyEntity eab when Turned(entry, nameof(AcmeEabKeyEntity.IsUsed), to: true):
                        facts.Add((RecordType.SpentWithoutCertificate, new SpentWithoutCertificatePayload(TokenKind.AcmeExternalAccountBinding, eab.Id.ToString("D"), Micros(DateTime.UtcNow)).Encode()));
                        break;
                    case InstanceIncarnationEntity incarnation when entry.State == EntityState.Modified:
                        var hash = entry.Property(nameof(InstanceIncarnationEntity.ValueHash));
                        if (hash.OriginalValue is string before && hash.CurrentValue is string after
                            && !string.Equals(before, after, StringComparison.OrdinalIgnoreCase)
                            && Hash(before) is { } old && Hash(after) is { } current)
                            facts.Add((RecordType.ContinuityEvent, new ContinuityEventPayload(old, current, Micros(incarnation.RecordedAt)).Encode()));
                        break;
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A fact that cannot be built never stops the change it describes.
            }
        }

        foreach (var (type, payload) in facts)
            QueueSignerFact(type, payload);
        return facts.Count > 0 || ChangeTracker.Entries<SignerFactEntity>().Any(e => e.State == EntityState.Added);
    }

    private void CertificateFacts(EntityEntry entry, CertificateEntity certificate, List<(ushort, byte[])> facts)
    {
        var revoked = entry.Property(nameof(CertificateEntity.Revoked));
        var reason = entry.Property(nameof(CertificateEntity.RevocationReason));
        var retired = entry.Property(nameof(CertificateEntity.RetiredAt));
        var added = entry.State == EntityState.Added;
        var wasRevoked = !added && revoked.OriginalValue is true;
        var nowRevoked = certificate.Revoked;
        var becameRevoked = nowRevoked && (!wasRevoked || !string.Equals(reason.OriginalValue as string, certificate.RevocationReason, StringComparison.Ordinal));
        var released = wasRevoked && !nowRevoked;
        var becameRetired = certificate.RetiredAt != null && (added || retired.OriginalValue == null);
        if (!becameRevoked && !released && !becameRetired)
            return;

        // A certificate is named by its serial and its issuer's key. A root names itself.
        var issuer = certificate.IssuerCertificateId is Guid issuerId ? IssuerOf(issuerId)
            : certificate.IsCA ? (CaKey: KeyOf(certificate.RawCertificate), CaId: null) : IssuerByName(certificate.Issuer);
        if (issuer.CaKey is not { } caKey || Serial(certificate.SerialNumber) is not { } serial)
            return;
        var ca = issuer.CaId?.ToString("D");

        if (becameRevoked)
        {
            var code = ReasonCode(certificate.RevocationReason);
            facts.Add((RecordType.Revocation, new RevocationPayload(serial, caKey, ca, code, Micros(certificate.RevocationDate ?? DateTime.UtcNow), Known: true,
                code == (ulong)RevocationReason.CertificateHold ? RevocationForm.Hold : RevocationForm.Revoked).Encode()));
        }
        if (released)
            facts.Add((RecordType.Unrevocation, new UnrevocationPayload(serial, caKey, ca, Micros(DateTime.UtcNow)).Encode()));
        if (becameRetired)
            facts.Add((RecordType.Revocation, new RevocationPayload(serial, caKey, ca, 0, Micros(certificate.RetiredAt!.Value), Known: true, RevocationForm.Retired).Encode()));
    }

    private static bool Turned(EntityEntry entry, string property, bool to)
    {
        var p = entry.Property(property);
        if (p.CurrentValue is not bool now || now != to)
            return false;
        // A row added already disabled is not a change from enabled.
        return entry.State == EntityState.Modified && p.OriginalValue is bool was && was != to;
    }

    private static (ushort, byte[]) Disabled(ulong kind, Guid id)
        => (RecordType.Disabled, new DisabledPayload(kind, id.ToString("D"), Micros(DateTime.UtcNow)).Encode());

    private static long Micros(DateTime time)
        => JournalFormat.ToMicros(new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)));

    private static ulong ReasonCode(string? reason)
        => Enum.TryParse<RevocationReason>(reason, ignoreCase: true, out var parsed) ? (ulong)parsed : 0;

    private static byte[]? Serial(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            return null;
        try { return new BigInteger(hex.Trim(), 16).ToByteArrayUnsigned(); }
        catch (FormatException) { return null; }
    }

    private static byte[]? Hash(string hex)
    {
        try { return hex.Trim().Length == 64 ? Convert.FromHexString(hex.Trim()) : null; }
        catch (FormatException) { return null; }
    }

    private static byte[]? KeyOf(byte[]? rawCertificate)
    {
        if (rawCertificate is not { Length: > 0 })
            return null;
        try
        {
            return SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(new X509Certificate(rawCertificate).GetPublicKey()).GetDerEncoded());
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    /// <summary>The journal's name for the key of a CA certificate row, and the CA it is the current certificate of; remembered once read.</summary>
    private (byte[]? CaKey, Guid? CaId) IssuerOf(Guid caCertificateId)
    {
        if (IssuerKeys.TryGetValue(caCertificateId, out var known))
            return known;
        var tracked = ChangeTracker.Entries<CertificateEntity>().FirstOrDefault(e => e.Entity.CertificateId == caCertificateId)?.Entity;
        var raw = tracked?.RawCertificate ?? Certificates.AsNoTracking().Where(c => c.CertificateId == caCertificateId).Select(c => c.RawCertificate).FirstOrDefault();
        var key = KeyOf(raw);
        var ca = CertificateAuthorities.AsNoTracking().Where(a => a.CertificateId == caCertificateId).Select(a => (Guid?)a.Id).FirstOrDefault()
            // An earlier certificate of a CA whose certificate was renewed: the CA its history names.
            ?? CaCertificates.AsNoTracking().Where(h => h.CertificateId == caCertificateId).Select(h => (Guid?)h.CertificateAuthorityId).FirstOrDefault();
        var found = (key, ca);
        if (key != null && ca != null)
            IssuerKeys[caCertificateId] = found;
        return found;
    }

    /// <summary>
    /// For a row from before issuer links: the CA certificate whose subject is the certificate's
    /// issuer name, when exactly one has it, or when every one that has it is a certificate of
    /// the same CA over the same key (a CA whose certificate was renewed).
    /// </summary>
    private (byte[]? CaKey, Guid? CaId) IssuerByName(string? issuerName)
    {
        if (string.IsNullOrWhiteSpace(issuerName))
            return (null, null);
        var ids = Certificates.AsNoTracking().Where(c => c.IsCA && c.SubjectDN == issuerName).Select(c => c.CertificateId).Take(16).ToList();
        if (ids.Count == 1)
            return IssuerOf(ids[0]);
        if (ids.Count == 0)
            return (null, null);
        var issuers = ids.Select(IssuerOf).ToList();
        var first = issuers[0];
        return first.CaKey != null && first.CaId != null
               && issuers.All(i => i.CaId == first.CaId && i.CaKey != null && i.CaKey.AsSpan().SequenceEqual(first.CaKey))
            ? first
            : (null, null);
    }

    private static void SignalSignerFactQueued()
    {
        try { SignerFactQueued?.Invoke(); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { /* a listener's fault is not the save's */ }
    }
}
