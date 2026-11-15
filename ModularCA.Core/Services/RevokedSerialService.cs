using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace ModularCA.Core.Services;

/// <summary>What recording a tombstone left.</summary>
/// <param name="Tombstone">The row written.</param>
/// <param name="CrlNumber">The number of the CRL regenerated to carry it, or null when the regeneration did not run or failed.</param>
public sealed record TombstoneResult(RevokedSerialTombstoneEntity Tombstone, long? CrlNumber);

/// <summary>What adopting a supplied certificate left.</summary>
/// <param name="Certificate">The certificate row written.</param>
/// <param name="Revoked">Whether the row was written revoked.</param>
/// <param name="FromTombstone">Whether the revocation came from a tombstone recorded earlier for the serial, which the adoption removed.</param>
/// <param name="CrlNumber">The number of the CRL regenerated after a revoked adoption, or null.</param>
public sealed record AdoptionResult(CertificateEntity Certificate, bool Revoked, bool FromTombstone, long? CrlNumber);

/// <summary>
/// Revocation of what the database does not hold (<c>docs/architecture/rollback-continuity.md</c>,
/// section 5). A certificate issued in time a rollback took away is real and unknown here: this
/// service records its serial as revoked with no certificate row (a tombstone), or takes the
/// certificate itself, verifies it under the CA's key and adopts it as an ordinary row.
/// <para>
/// Both are scoped to one CA and to the key its current certificate carries, the scope its CRL
/// already covers (<see cref="IssuerChainResolver.SameKeyCaCertificateIdsAsync"/>). Authorization,
/// step-up and auditing belong to the caller, as with <see cref="CertificateRevocationService"/>.
/// </para>
/// </summary>
public sealed partial class RevokedSerialService(ModularCADbContext db, ICrlService crls, ILogger<RevokedSerialService> logger)
{
    /// <summary>The longest serial accepted, in hex digits: RFC 5280 §4.1.2.2 allows twenty octets.</summary>
    public const int MaxSerialHexLength = 40;

    /// <summary>The validity assumed for a CA none of whose profiles states a maximum, as issuance assumes it.</summary>
    private const string DefaultMaxValidity = "P1Y";

    [GeneratedRegex("^[0-9A-F]+$")]
    private static partial Regex HexPattern();

    /// <summary>
    /// Records <paramref name="serialNumber"/> as revoked under CA <paramref name="caId"/> with no
    /// certificate row, and regenerates the CA's CRL so the entry is published at once. The
    /// revocation date is now. The entry stays on the CRL until <see cref="ListedUntilAsync"/>.
    /// </summary>
    /// <param name="caId">The certificate authority (<c>CertificateAuthorities.Id</c>).</param>
    /// <param name="serialNumber">The serial in hex; separators and leading zeros are ignored.</param>
    /// <param name="reason">The RFC 5280 reason. A hold is refused: a tombstone cannot be released.</param>
    /// <param name="invalidityDate">When the key or certificate is believed to have become invalid, if known.</param>
    /// <param name="note">Why the serial is revoked without its certificate. Required.</param>
    /// <param name="actorUserId">The administrator recording it.</param>
    /// <param name="actorUsername">That administrator's user name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidRequestException">The serial, the reason or the note is not acceptable (400).</exception>
    /// <exception cref="ResourceNotFoundException">The CA does not exist or has no certificate (404).</exception>
    /// <exception cref="ResourceConflictException">
    /// A certificate with that serial exists under the CA (revoke the certificate instead), or
    /// the serial already has a tombstone (409).
    /// </exception>
    public async Task<TombstoneResult> RecordTombstoneAsync(Guid caId, string? serialNumber, RevocationReason reason,
        DateTime? invalidityDate, string? note, Guid? actorUserId, string? actorUsername, CancellationToken cancellationToken = default)
    {
        var (tombstone, caCertificateId) = await AddTombstoneAsync(caId, serialNumber, reason, invalidityDate, note, actorUserId, actorUsername, cancellationToken);
        return new TombstoneResult(tombstone, await TryRegenerateCrlAsync(caCertificateId));
    }

    /// <summary>What <see cref="RecordTombstonesAsync"/> did with one serial.</summary>
    /// <param name="SerialNumber">The serial as it was given.</param>
    /// <param name="Tombstone">The entry recorded; null when it was not.</param>
    /// <param name="Refusal">Why it was not recorded: the CA holds a certificate with that serial, it is already recorded, or it is not a serial.</param>
    public sealed record TombstoneOutcome(string SerialNumber, RevokedSerialTombstoneEntity? Tombstone, string? Refusal);

    /// <summary>
    /// Records several serials as revoked under CA <paramref name="caId"/> with no certificate
    /// row, each as <see cref="RecordTombstoneAsync"/> records one, and regenerates the CA's CRL
    /// once, after the last. A serial that cannot be recorded (the CA holds its certificate, it
    /// is already recorded, it is not a serial, or its reason is a hold) is reported with the
    /// reason and does not stop the others.
    /// </summary>
    /// <param name="caId">The certificate authority.</param>
    /// <param name="serials">The serials with their reasons.</param>
    /// <param name="note">Why they are revoked without their certificates. Required.</param>
    /// <param name="actorUserId">The administrator recording them.</param>
    /// <param name="actorUsername">That administrator's user name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>What was done with each serial, in the order given, and the number of the CRL generated afterwards.</returns>
    /// <exception cref="InvalidRequestException">The note is missing or too long (400).</exception>
    /// <exception cref="ResourceNotFoundException">The CA does not exist or has no certificate (404).</exception>
    public async Task<(IReadOnlyList<TombstoneOutcome> Outcomes, long? CrlNumber)> RecordTombstonesAsync(Guid caId,
        IReadOnlyList<(string SerialNumber, RevocationReason Reason)> serials, string? note, Guid? actorUserId, string? actorUsername,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serials);
        RequireNote(note, "Say why the serials are revoked without their certificates.");
        var ca = await LoadCaAsync(caId, cancellationToken);
        var outcomes = new List<TombstoneOutcome>(serials.Count);
        foreach (var (serialNumber, reason) in serials)
        {
            try
            {
                var (tombstone, _) = await AddTombstoneAsync(caId, serialNumber, reason, null, note, actorUserId, actorUsername, cancellationToken);
                outcomes.Add(new TombstoneOutcome(serialNumber, tombstone, null));
            }
            catch (Exception ex) when (ex is InvalidRequestException or ResourceConflictException)
            {
                outcomes.Add(new TombstoneOutcome(serialNumber, null, ex.Message));
            }
        }
        var crlNumber = outcomes.Any(o => o.Tombstone != null) ? await TryRegenerateCrlAsync(ca.CertificateId) : null;
        return (outcomes, crlNumber);
    }

    /// <summary>How many serials <see cref="RecordTombstonesInSetsAsync"/> checks and saves together.</summary>
    public const int SetSize = 500;

    /// <summary>
    /// Records any number of serials as revoked under CA <paramref name="caId"/> with no
    /// certificate row, <see cref="SetSize"/> at a time: each set is checked with two queries
    /// (the certificates the CA holds among them, the serials already recorded) and saved in
    /// one transaction, and the CA's CRL is regenerated once, after the last. What
    /// <see cref="RecordTombstonesAsync"/> does one serial at a time, for a list of any length.
    /// </summary>
    /// <param name="caId">The certificate authority.</param>
    /// <param name="serials">The serials with their reasons.</param>
    /// <param name="note">Why they are revoked without their certificates. Required.</param>
    /// <param name="actorUserId">The administrator recording them.</param>
    /// <param name="actorUsername">That administrator's user name.</param>
    /// <param name="saved">Called after each set is saved, with what it recorded, so the caller can audit it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>How many were recorded, each one that was not with the reason, and the number of the CRL generated afterwards.</returns>
    /// <exception cref="InvalidRequestException">The note is missing or too long (400).</exception>
    /// <exception cref="ResourceNotFoundException">The CA does not exist or has no certificate (404).</exception>
    public async Task<(int Recorded, IReadOnlyList<TombstoneOutcome> Refused, long? CrlNumber)> RecordTombstonesInSetsAsync(Guid caId,
        IReadOnlyList<(string SerialNumber, RevocationReason Reason)> serials, string? note, Guid? actorUserId, string? actorUsername,
        Func<IReadOnlyList<RevokedSerialTombstoneEntity>, Task>? saved = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serials);
        var why = RequireNote(note, "Say why the serials are revoked without their certificates.");
        var ca = await LoadCaAsync(caId, cancellationToken);
        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, ca.CertificateId, ca.Certificate, cancellationToken);
        var refused = new List<TombstoneOutcome>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var recorded = 0;
        DateTime? listedUntil = null;

        foreach (var set in serials.Chunk(SetSize))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wanted = new List<(string Serial, RevocationReason Reason)>(set.Length);
            foreach (var (given, reason) in set)
            {
                string serial;
                try
                {
                    serial = NormalizeSerial(given);
                }
                catch (InvalidRequestException ex)
                {
                    refused.Add(new TombstoneOutcome(given, null, ex.Message));
                    continue;
                }
                if (reason == RevocationReason.CertificateHold)
                    refused.Add(new TombstoneOutcome(given, null, "A serial without a certificate cannot be put on hold: the revocation is permanent."));
                else if (!seen.Add(serial))
                    refused.Add(new TombstoneOutcome(given, null, $"Serial {serial} is named twice."));
                else
                    wanted.Add((serial, reason));
            }
            if (wanted.Count == 0)
                continue;

            var plain = wanted.Select(w => w.Serial).ToList();
            var forms = plain.SelectMany(x => new[] { x, "0" + x, "00" + x }).ToList();
            var held = (await db.Certificates.AsNoTracking()
                    .Where(c => EF.Parameter(forms).Contains(c.SerialNumber))
                    .Where(c => (c.IssuerCertificateId != null && scope.Contains(c.IssuerCertificateId.Value))
                             || (c.IssuerCertificateId == null && c.Issuer == ca.IssuerDn))
                    .Select(c => c.SerialNumber)
                    .ToListAsync(cancellationToken))
                .Select(s => { var t = s.TrimStart('0'); return t.Length == 0 ? "0" : t; })
                .ToHashSet(StringComparer.Ordinal);
            var already = (await db.RevokedSerialTombstones.AsNoTracking()
                    .Where(t => scope.Contains(t.CaCertificateId) && EF.Parameter(plain).Contains(t.SerialNumber))
                    .Select(t => t.SerialNumber)
                    .ToListAsync(cancellationToken))
                .ToHashSet(StringComparer.Ordinal);

            var now = DateTime.UtcNow;
            listedUntil ??= await ListedUntilAsync(ca.Id, now, cancellationToken);
            var added = new List<RevokedSerialTombstoneEntity>(wanted.Count);
            foreach (var (serial, reason) in wanted)
            {
                if (held.Contains(serial))
                    refused.Add(new TombstoneOutcome(serial, null, $"Serial {serial} belongs to a certificate this CA holds. Revoke the certificate instead."));
                else if (already.Contains(serial))
                    refused.Add(new TombstoneOutcome(serial, null, $"Serial {serial} is already recorded as revoked for this CA."));
                else
                    added.Add(new RevokedSerialTombstoneEntity
                    {
                        CaCertificateId = ca.CertificateId,
                        CertificateAuthorityId = ca.Id,
                        IssuerDN = ca.IssuerDn,
                        SerialNumber = serial,
                        RevocationDate = now,
                        RevocationReason = reason.ToString(),
                        ListedUntil = listedUntil.Value,
                        Note = why,
                        CreatedByUserId = actorUserId,
                        CreatedByUsername = actorUsername ?? string.Empty,
                        CreatedAt = now,
                    });
            }
            if (added.Count == 0)
                continue;

            db.RevokedSerialTombstones.AddRange(added);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
            {
                // Someone recorded one of these serials at the same moment: nothing of this set was saved.
                foreach (var tombstone in added)
                    db.Entry(tombstone).State = EntityState.Detached;
                refused.AddRange(added.Select(t => new TombstoneOutcome(t.SerialNumber, null,
                    "Not recorded: another request recorded one of the same serials at the same moment. Run the action again.")));
                continue;
            }
            foreach (var tombstone in added)
            {
                db.Entry(tombstone).State = EntityState.Detached;
                MetricsService.CertsRevoked.WithLabels(ca.IssuerDn, tombstone.RevocationReason).Inc();
            }
            recorded += added.Count;
            if (saved != null)
                await saved(added);
        }

        var crlNumber = recorded > 0 ? await TryRegenerateCrlAsync(ca.CertificateId) : null;
        return (recorded, refused, crlNumber);
    }

    /// <summary>Checks and saves one tombstone, without regenerating the CRL. Returns it with the CA's certificate id.</summary>
    private async Task<(RevokedSerialTombstoneEntity Tombstone, Guid CaCertificateId)> AddTombstoneAsync(Guid caId, string? serialNumber, RevocationReason reason,
        DateTime? invalidityDate, string? note, Guid? actorUserId, string? actorUsername, CancellationToken cancellationToken)
    {
        var serial = NormalizeSerial(serialNumber);
        if (reason == RevocationReason.CertificateHold)
            throw new InvalidRequestException("A serial without a certificate cannot be put on hold: the revocation is permanent. Choose another reason.");
        var why = RequireNote(note, "Say why the serial is revoked without its certificate.");

        var ca = await LoadCaAsync(caId, cancellationToken);
        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, ca.CertificateId, ca.Certificate, cancellationToken);

        var existing = await FindCertificateAsync(serial, ca, scope, cancellationToken);
        if (existing != null)
            throw new ResourceConflictException(
                $"Serial {serial} belongs to a certificate this CA holds ({existing.SubjectDN}). Revoke the certificate instead.",
                remediation: $"Revoke certificate {existing.CertificateId}.");
        if (await db.RevokedSerialTombstones.AnyAsync(t => t.SerialNumber == serial && scope.Contains(t.CaCertificateId), cancellationToken))
            throw new ResourceConflictException($"Serial {serial} is already recorded as revoked for this CA.");

        var now = DateTime.UtcNow;
        var tombstone = new RevokedSerialTombstoneEntity
        {
            CaCertificateId = ca.CertificateId,
            CertificateAuthorityId = ca.Id,
            IssuerDN = ca.IssuerDn,
            SerialNumber = serial,
            RevocationDate = now,
            RevocationReason = reason.ToString(),
            InvalidityDate = invalidityDate?.ToUniversalTime(),
            ListedUntil = await ListedUntilAsync(ca.Id, now, cancellationToken),
            Note = why,
            CreatedByUserId = actorUserId,
            CreatedByUsername = actorUsername ?? string.Empty,
            CreatedAt = now,
        };
        db.RevokedSerialTombstones.Add(tombstone);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
        {
            // Two administrators recorded the same serial at once; the index let one through.
            db.Entry(tombstone).State = EntityState.Detached;
            throw new ResourceConflictException($"Serial {serial} is already recorded as revoked for this CA.");
        }

        MetricsService.CertsRevoked.WithLabels(ca.IssuerDn, reason.ToString()).Inc();
        return (tombstone, ca.CertificateId);
    }

    /// <summary>
    /// Of <paramref name="serials"/>, those for which CA <paramref name="caId"/> holds a
    /// certificate row its CRL answers for: such a serial is revoked by revoking the
    /// certificate, not by recording the serial alone. Serials are compared without leading
    /// zeros and without case.
    /// </summary>
    public async Task<IReadOnlySet<string>> HeldAsync(Guid caId, IReadOnlyCollection<string> serials, CancellationToken cancellationToken = default)
    {
        var held = new HashSet<string>(StringComparer.Ordinal);
        if (serials.Count == 0)
            return held;
        var ca = await LoadCaAsync(caId, cancellationToken);
        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, ca.CertificateId, ca.Certificate, cancellationToken);
        foreach (var chunk in serials.Select(Plain).Distinct(StringComparer.Ordinal).Chunk(500))
        {
            var forms = chunk.SelectMany(x => new[] { x, "0" + x, "00" + x }).ToList();
            var found = await db.Certificates.AsNoTracking()
                .Where(c => forms.Contains(c.SerialNumber))
                .Where(c => (c.IssuerCertificateId != null && scope.Contains(c.IssuerCertificateId.Value))
                         || (c.IssuerCertificateId == null && c.Issuer == ca.IssuerDn))
                .Select(c => c.SerialNumber)
                .ToListAsync(cancellationToken);
            foreach (var serial in found)
                held.Add(Plain(serial));
        }
        return held;

        static string Plain(string serial)
        {
            var trimmed = serial.Trim().TrimStart('0').ToUpperInvariant();
            return trimmed.Length == 0 ? "0" : trimmed;
        }
    }

    /// <summary>
    /// Adopts a certificate supplied from outside as an ordinary row of CA <paramref name="caId"/>:
    /// its issuer name must be the CA's and its signature must verify under the key of the CA's
    /// current certificate. The row is marked as adopted, with no profile and no known requester.
    /// A tombstone recorded earlier for its serial becomes the row's revocation and is removed;
    /// otherwise the row is written revoked only when <paramref name="revokeReason"/> is given.
    /// </summary>
    /// <param name="caId">The certificate authority.</param>
    /// <param name="certificate">The certificate, as PEM or as base64 of its DER.</param>
    /// <param name="note">Where the certificate came from and why it is adopted. Required.</param>
    /// <param name="revokeReason">Revoke it in the same step with this reason; null adopts it as good.</param>
    /// <param name="invalidityDate">The invalidity date of that revocation, if known.</param>
    /// <param name="actorUsername">The administrator adopting it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidRequestException">
    /// The certificate cannot be read, names another issuer, is not signed by this CA's key, or is
    /// a CA certificate (400).
    /// </exception>
    /// <exception cref="ResourceNotFoundException">The CA does not exist or has no certificate (404).</exception>
    /// <exception cref="ResourceConflictException">The CA already holds a certificate with that serial (409).</exception>
    public async Task<AdoptionResult> AdoptCertificateAsync(Guid caId, string? certificate, string? note,
        RevocationReason? revokeReason, DateTime? invalidityDate, string? actorUsername, CancellationToken cancellationToken = default)
    {
        var why = RequireNote(note, "Say where the certificate came from.");
        if (revokeReason == RevocationReason.CertificateHold)
            throw new InvalidRequestException("Adopt the certificate first, then place it on hold: a hold is not given at adoption.");
        var supplied = ParseSupplied(certificate);
        var ca = await LoadCaAsync(caId, cancellationToken);

        if (!supplied.IssuerDN.Equivalent(ca.Certificate.SubjectDN, inOrder: true))
            throw new InvalidRequestException(
                $"The certificate names another issuer ({supplied.IssuerDN}). This CA is {ca.Certificate.SubjectDN}.");
        try
        {
            supplied.Verify(ca.Certificate.GetPublicKey());
        }
        catch (Exception ex)
        {
            logger.LogInformation("Adoption refused for CA {CaId}: the supplied certificate does not verify under the CA's key ({Kind}).", caId, ex.GetType().Name);
            throw new InvalidRequestException(
                "The certificate is not signed by the key of this CA's current certificate, so it is not adopted.",
                remediation: "Check that the certificate was issued by this CA. A certificate signed by a key the CA no longer uses cannot be adopted; record its serial as revoked instead.");
        }
        if (IsCaCertificate(supplied))
            throw new InvalidRequestException(
                "The certificate is a CA certificate. A subordinate CA is not adopted this way; record its serial as revoked instead.");

        var serial = CertificateUtil.FormatSerialNumber(supplied.SerialNumber);
        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, ca.CertificateId, ca.Certificate, cancellationToken);
        var existing = await FindCertificateAsync(serial, ca, scope, cancellationToken);
        if (existing != null)
            throw new ResourceConflictException(
                $"This CA already holds a certificate with serial {serial} ({existing.SubjectDN}).",
                remediation: $"Open certificate {existing.CertificateId}.");

        var tombstone = await db.RevokedSerialTombstones
            .FirstOrDefaultAsync(t => t.SerialNumber == serial && scope.Contains(t.CaCertificateId), cancellationToken);

        var now = DateTime.UtcNow;
        var info = CertificateUtil.ParseCertificate(supplied);
        var der = supplied.GetEncoded();
        var row = new CertificateEntity
        {
            CertificateId = Guid.CreateVersion7(),
            SerialNumber = serial,
            SubjectDN = info.SubjectDN,
            Issuer = ca.IssuerDn,
            IssuerCertificateId = ca.CertificateId,
            Pem = CertificateUtil.ConvertDerToPem(der, "CERTIFICATE"),
            RawCertificate = der,
            NotBefore = supplied.NotBefore.ToUniversalTime(),
            NotAfter = supplied.NotAfter.ToUniversalTime(),
            Thumbprints = info.Thumbprints,
            IsCA = false,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(info.SubjectAlternativeNames),
            KeyUsagesJson = JsonSerializer.Serialize(info.KeyUsages),
            ExtendedKeyUsagesJson = JsonSerializer.Serialize(info.ExtendedKeyUsages),
            AdoptedAt = now,
            AdoptedBy = actorUsername ?? string.Empty,
            AdoptionNote = why,
            CreatedAt = now,
        };
        if (row.SubjectDN.Length > CertificateEntity.SubjectDnMaxLength)
            throw new InvalidRequestException($"The certificate's subject is longer than the {CertificateEntity.SubjectDnMaxLength} characters a certificate row holds.");

        if (tombstone != null)
        {
            row.Revoked = true;
            row.RevocationReason = tombstone.RevocationReason;
            row.RevocationDate = tombstone.RevocationDate;
            row.InvalidityDate = tombstone.InvalidityDate;
            db.RevokedSerialTombstones.Remove(tombstone);
        }
        else if (revokeReason is { } reason)
        {
            row.Revoked = true;
            row.RevocationReason = reason.ToString();
            row.RevocationDate = now;
            row.InvalidityDate = invalidityDate?.ToUniversalTime();
        }

        db.Certificates.Add(row);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
        {
            db.ChangeTracker.Clear();
            throw new ResourceConflictException($"This CA already holds a certificate with serial {serial}.");
        }

        long? crlNumber = null;
        if (row.Revoked && tombstone == null)
        {
            MetricsService.CertsRevoked.WithLabels(ca.IssuerDn, row.RevocationReason!).Inc();
            crlNumber = await TryRegenerateCrlAsync(ca.CertificateId);
        }
        return new AdoptionResult(row, row.Revoked, tombstone != null, crlNumber);
    }

    /// <summary>The tombstones recorded for CA <paramref name="caId"/>, newest first.</summary>
    public Task<List<RevokedSerialTombstoneEntity>> ListAsync(Guid caId, CancellationToken cancellationToken = default)
        => db.RevokedSerialTombstones.AsNoTracking()
            .Where(t => t.CertificateAuthorityId == caId)
            .OrderByDescending(t => t.RevocationDate)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// When a tombstone recorded at <paramref name="from"/> leaves the CRL of CA <paramref name="caId"/>:
    /// <paramref name="from"/> plus the longest maximum validity among the certificate profiles
    /// the CA can issue with (its own, its space's and the instance-wide ones; one year for a
    /// profile that states none, as issuance assumes), and never past the end of the CA's own
    /// certificate. A certificate with that serial cannot still be valid after it.
    /// </summary>
    public async Task<DateTime> ListedUntilAsync(Guid caId, DateTime from, CancellationToken cancellationToken = default)
    {
        var caEndOf = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => c.Certificate == null ? (DateTime?)null : c.Certificate.NotAfter)
            .FirstOrDefaultAsync(cancellationToken);
        var until = from.Add(await LongestValidityAsync(db, caId, cancellationToken));
        return caEndOf is { } caEnd && caEnd > from && caEnd < until ? caEnd : until;
    }

    /// <summary>
    /// The longest maximum validity among the certificate profiles CA <paramref name="caId"/> can
    /// issue with (its own, its space's and the instance-wide ones; one year for a profile that
    /// states none): how long after its revocation a serial with no certificate stays listed.
    /// </summary>
    public static async Task<TimeSpan> LongestValidityAsync(ModularCADbContext db, Guid caId, CancellationToken cancellationToken = default)
    {
        var spaceId = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => c.SpaceId)
            .FirstOrDefaultAsync(cancellationToken);
        var maxima = await db.CertProfiles.AsNoTracking()
            .Where(p => p.CertificateAuthorityId == caId
                || (p.CertificateAuthorityId == null && (p.SpaceId == null || p.SpaceId == spaceId)))
            .Select(p => p.ValidityPeriodMax)
            .ToListAsync(cancellationToken);

        var longest = Iso8601ParserUtil.ParseIso8601(DefaultMaxValidity);
        foreach (var maximum in maxima)
        {
            try
            {
                var span = Iso8601ParserUtil.ParseIso8601(string.IsNullOrWhiteSpace(maximum) ? DefaultMaxValidity : maximum);
                if (span > longest)
                    longest = span;
            }
            catch (FormatException)
            {
                // A profile whose maximum cannot be read issues nothing; it does not lengthen the stay.
            }
        }

        return longest;
    }

    /// <summary>The serial in stored form, or a 400 when it is not a positive hex number of at most twenty octets.</summary>
    internal static string NormalizeSerial(string? serialNumber)
    {
        var serial = CertificateUtil.NormalizeSerialForLookup(serialNumber);
        if (serial.Length == 0)
            throw new InvalidRequestException("A serial number is required.");
        if (!HexPattern().IsMatch(serial))
            throw new InvalidRequestException("The serial number must be hexadecimal, as the certificate shows it.");
        if (serial == "0")
            throw new InvalidRequestException("A serial number is a positive number; zero is not one.");
        if (serial.Length > MaxSerialHexLength)
            throw new InvalidRequestException("The serial number is longer than the twenty octets a certificate serial can have.");
        return serial;
    }

    private static string RequireNote(string? note, string whenMissing)
    {
        var trimmed = note?.Trim() ?? string.Empty;
        if (trimmed.Length == 0)
            throw new InvalidRequestException(whenMissing);
        if (trimmed.Length > RevokedSerialTombstoneEntity.NoteMaxLength)
            throw new InvalidRequestException($"The note is longer than {RevokedSerialTombstoneEntity.NoteMaxLength} characters.");
        return trimmed;
    }

    /// <summary>Reads the supplied certificate from PEM or from base64 of its DER; a 400 when it is neither.</summary>
    private static X509Certificate ParseSupplied(string? certificate)
    {
        if (string.IsNullOrWhiteSpace(certificate))
            throw new InvalidRequestException("Supply the certificate, as PEM or as base64 of its DER encoding.");
        try
        {
            var text = certificate.Trim();
            if (text.Contains("-----BEGIN", StringComparison.Ordinal))
                return CertificateUtil.ParseFromPem(text);
            return new X509CertificateParser().ReadCertificate(Convert.FromBase64String(text))
                ?? throw new FormatException("No certificate in the data.");
        }
        catch (Exception)
        {
            throw new InvalidRequestException("The certificate could not be read. Supply one X.509 certificate, as PEM or as base64 of its DER encoding.");
        }
    }

    private static bool IsCaCertificate(X509Certificate certificate)
    {
        var value = certificate.GetExtensionValue(X509Extensions.BasicConstraints);
        return value != null && BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(value)).IsCA();
    }

    private sealed record CaContext(Guid Id, Guid CertificateId, X509Certificate Certificate, string IssuerDn);

    /// <summary>The CA with its current certificate parsed; 404 when there is no such CA or it has no X.509 certificate.</summary>
    private async Task<CaContext> LoadCaAsync(Guid caId, CancellationToken cancellationToken)
    {
        var ca = await db.CertificateAuthorities.AsNoTracking()
            .Where(c => c.Id == caId)
            .Select(c => new { c.Id, c.CertificateId, Row = c.Certificate })
            .FirstOrDefaultAsync(cancellationToken)
            ?? throw new ResourceNotFoundException("Certificate authority", "Certificate authority not found.", caId.ToString());
        if (ca.CertificateId is not Guid certificateId || ca.Row == null)
            throw new ResourceNotFoundException("Certificate authority", "This certificate authority has no X.509 certificate.", caId.ToString());

        X509Certificate parsed;
        try
        {
            parsed = ca.Row.RawCertificate is { Length: > 0 } raw
                ? new X509CertificateParser().ReadCertificate(raw)
                : CertificateUtil.ParseFromPem(ca.Row.Pem);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"The certificate of CA {caId} could not be read.", ex);
        }
        return new CaContext(ca.Id, certificateId, parsed, parsed.SubjectDN.ToString());
    }

    /// <summary>The certificate row with <paramref name="serial"/> that this CA's CRL and OCSP answer for, if there is one.</summary>
    private Task<CertificateEntity?> FindCertificateAsync(string serial, CaContext ca, List<Guid> scope, CancellationToken cancellationToken)
        => db.Certificates.AsNoTracking()
            .Where(c => c.SerialNumber == serial)
            .Where(c => (c.IssuerCertificateId != null && scope.Contains(c.IssuerCertificateId.Value))
                     || (c.IssuerCertificateId == null && c.Issuer == ca.IssuerDn))
            .FirstOrDefaultAsync(cancellationToken);

    /// <summary>
    /// Regenerates the CA's full CRL, and its delta when one is configured, as a revocation does.
    /// Best effort: the row is already committed, and the scheduled run publishes it otherwise.
    /// </summary>
    private async Task<long?> TryRegenerateCrlAsync(Guid caCertificateId)
    {
        try
        {
            await crls.GenerateCrlAsync(caCertificateId);
            if (await db.CrlConfigurations.AnyAsync(c => c.CaCertificateId == caCertificateId && c.IsDelta))
            {
                try { await crls.GenerateDeltaCrlAsync(caCertificateId); }
                catch (Exception dex) { logger.LogWarning(dex, "Delta CRL regeneration failed for CA certificate {CaCertificateId}", caCertificateId); }
            }
            return await db.Crls.AsNoTracking()
                .Where(c => !c.IsDelta && c.Task != null && c.Task.CaCertificateId == caCertificateId)
                .OrderByDescending(c => c.CrlNumber)
                .Select(c => (long?)c.CrlNumber)
                .FirstOrDefaultAsync();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "CRL regeneration after a change to CA certificate {CaCertificateId} failed; the next scheduled run publishes it.", caCertificateId);
            return null;
        }
    }
}
