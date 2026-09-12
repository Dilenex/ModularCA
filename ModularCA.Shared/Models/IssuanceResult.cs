using ModularCA.Shared.Errors;

namespace ModularCA.Shared.Models;

/// <summary>
/// Result of a certificate issuance or reissuance operation: the PEM-encoded certificate, plus
/// everything worth telling the operator about how it was produced.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Diagnostics"/> replaced a bare <c>List&lt;string&gt;</c> of warnings. The string
/// list worked, but it could only ever carry a sentence — no code to search for, no severity,
/// no field to attach it to on a form — and in practice only two validity clamps ever wrote to
/// it. Everything else that adjusted a certificate on its way out, including an extended key
/// usage being removed by the signing profile's ceiling, had nowhere to go and went to the log.
/// </para>
/// <para>
/// <see cref="Warnings"/> is kept as a derived view because several callers only ever log the
/// sentences, and rewriting them to destructure a record would have added noise without adding
/// anything. It is computed from <see cref="Diagnostics"/> rather than stored alongside it, so
/// the two cannot disagree.
/// </para>
/// </remarks>
/// <param name="Pem">The issued certificate, PEM-encoded.</param>
/// <param name="Diagnostics">Adjustments and advisories raised while issuing.</param>
public record IssuanceResult(string Pem, IReadOnlyList<Diagnostic> Diagnostics)
{
    /// <summary>Creates a result with no diagnostics.</summary>
    public IssuanceResult(string pem) : this(pem, Array.Empty<Diagnostic>()) { }

    /// <summary>
    /// The detail sentences of every diagnostic above info severity, for callers that only log.
    /// </summary>
    public IReadOnlyList<string> Warnings =>
        Diagnostics
            .Where(d => !string.Equals(d.Severity, DiagnosticSeverity.Info, StringComparison.Ordinal))
            .Select(d => d.Detail)
            .ToList();
}
