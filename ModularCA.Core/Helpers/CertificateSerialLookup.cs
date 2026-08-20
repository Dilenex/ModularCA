using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Helpers;

/// <summary>
/// Outcome of resolving a certificate serial number to a single row.
/// </summary>
public enum SerialResolution
{
    /// <summary>Exactly one certificate matched.</summary>
    Found,

    /// <summary>No certificate matched the serial.</summary>
    NotFound,

    /// <summary>
    /// More than one certificate matched. The serial alone does not identify a row, so the caller
    /// must either narrow by issuer or refuse the operation — it must NOT pick one.
    /// </summary>
    Ambiguous
}

/// <summary>
/// The result of a serial-number lookup: the outcome and, when unambiguous, the matched row.
/// </summary>
/// <param name="Outcome">Whether the serial matched zero, one, or several certificates.</param>
/// <param name="Certificate">The matched certificate; non-null only when <paramref name="Outcome"/> is <see cref="SerialResolution.Found"/>.</param>
public readonly record struct CertificateSerialResult(SerialResolution Outcome, CertificateEntity? Certificate);

/// <summary>
/// Safe resolution of a certificate from a serial number.
/// <para>
/// A serial number is not a primary key. X.509 requires serials to be unique only within an
/// issuer, and this schema models exactly that: the unique index on <c>Certificates</c> is
/// <c>(SerialNumber, Issuer)</c>. A bare <c>FirstOrDefault(c =&gt; c.SerialNumber == s)</c>
/// therefore asks the database for "any row carrying this serial" and accepts whichever it
/// returns first — a selection with no <c>ORDER BY</c> and so no defined ordering, which the
/// engine is free to answer differently between two calls in the same request.
/// </para>
/// <para>
/// The realistic way duplicates arise is not chance — serials are generated with
/// <c>RandomNumberGenerator</c>, so accidental collision is negligible — but import: a
/// cross-certified or externally-issued certificate carries a serial its own issuer chose,
/// and nothing stops that value colliding with one this instance already minted.
/// </para>
/// <para>
/// These helpers make the ambiguous case explicit instead of silent. Callers that hold an issuer
/// should filter by it before calling (the extension composes onto any <see cref="IQueryable{T}"/>,
/// so <c>db.Certificates.Where(c =&gt; c.IssuerCertificateId == id).ResolveBySerialAsync(s)</c>
/// works and is strictly better). Callers that genuinely only have a serial get a truthful
/// three-state answer and decide for themselves.
/// </para>
/// </summary>
public static class CertificateSerialLookup
{
    /// <summary>
    /// Resolves <paramref name="serialNumber"/> against <paramref name="source"/>, reporting
    /// whether it matched zero, exactly one, or several certificates.
    /// <para>
    /// Reads at most two rows: enough to prove ambiguity, without loading an unbounded result set
    /// if the data turns out to be worse than expected.
    /// </para>
    /// </summary>
    /// <param name="source">Certificate query to resolve against; pre-filter it by issuer where possible.</param>
    /// <param name="serialNumber">The serial number to look up. Null or whitespace yields <see cref="SerialResolution.NotFound"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<CertificateSerialResult> ResolveBySerialAsync(
        this IQueryable<CertificateEntity> source,
        string? serialNumber,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return new CertificateSerialResult(SerialResolution.NotFound, null);

        var matches = await source
            .Where(c => c.SerialNumber == serialNumber)
            .Take(2)
            .ToListAsync(ct);

        return matches.Count switch
        {
            0 => new CertificateSerialResult(SerialResolution.NotFound, null),
            1 => new CertificateSerialResult(SerialResolution.Found, matches[0]),
            _ => new CertificateSerialResult(SerialResolution.Ambiguous, null)
        };
    }

    /// <summary>
    /// Convenience form of <see cref="ResolveBySerialAsync"/> that collapses "no match" and
    /// "several matches" to <c>null</c>.
    /// <para>
    /// Use this ONLY where the caller treats null as a refusal — a 404, a "not found" branch, a
    /// skip. That makes ambiguity fail closed with no per-call-site handling. Do NOT use it where
    /// null is permissive (for example an authorization resolver whose null means "no CA scope
    /// applies, fall back to a broader check") — there, null on ambiguity would fail OPEN. Those
    /// callers must use <see cref="ResolveBySerialAsync"/> and handle
    /// <see cref="SerialResolution.Ambiguous"/> as a denial.
    /// </para>
    /// </summary>
    public static async Task<CertificateEntity?> ResolveBySerialOrNullAsync(
        this IQueryable<CertificateEntity> source,
        string? serialNumber,
        CancellationToken ct = default)
        => (await source.ResolveBySerialAsync(serialNumber, ct)).Certificate;

    /// <summary>
    /// Synchronous counterpart to <see cref="ResolveBySerialOrNullAsync"/>, for the few callers
    /// that are not on an async path. Prefer the async form wherever the call site allows it —
    /// this exists so a synchronous caller is not left with the unsafe
    /// <c>FirstOrDefault(c =&gt; c.SerialNumber == s)</c> as its only option.
    /// </summary>
    public static CertificateEntity? ResolveBySerialOrNull(
        this IQueryable<CertificateEntity> source,
        string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return null;

        var matches = source
            .Where(c => c.SerialNumber == serialNumber)
            .Take(2)
            .ToList();

        return matches.Count == 1 ? matches[0] : null;
    }
}
