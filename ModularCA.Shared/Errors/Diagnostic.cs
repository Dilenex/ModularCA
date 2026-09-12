namespace ModularCA.Shared.Errors;

/// <summary>
/// Severity of a <see cref="Diagnostic"/>, as it appears on the wire.
/// </summary>
/// <remarks>
/// Deliberately string constants rather than an enum. These values cross the JSON boundary, and
/// this application configures a global <c>JsonStringEnumConverter</c> whose behaviour has
/// already had to be worked around once for the WebAuthn option DTOs. A severity that is a
/// string in the source is a string on the wire with no converter in the path, and no casing
/// surprise between one endpoint and the next.
/// </remarks>
public static class DiagnosticSeverity
{
    /// <summary>Something worth surfacing that did not change the outcome.</summary>
    public const string Info = "info";

    /// <summary>The operation succeeded, but not exactly as asked.</summary>
    public const string Warning = "warning";

    /// <summary>The operation did not happen.</summary>
    public const string Error = "error";
}

/// <summary>
/// One thing worth telling the operator about an operation that otherwise succeeded.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of the failure that started the whole error-reporting effort. A profile
/// asked for <c>clientAuth</c> and <c>smartcardLogon</c>; the signing profile's <c>AllowedEKUs</c>
/// ceiling permitted only <c>clientAuth</c>; the certificate issued with <c>smartcardLogon</c>
/// silently removed. Windows smart-card logon then failed with <c>CERT_E_WRONG_USAGE</c> and
/// nothing on screen connected the two. The drop was detected — it was written to a
/// <c>LogInformation</c> nobody reads — but it had no route to the caller, because the only
/// channel out of issuance was a list of strings populated by two validity clamps.
/// </para>
/// <para>
/// A refusal and a silent adjustment are the same problem wearing different clothes: the
/// operator asked for something and did not get it. The only real difference is whether a
/// certificate came out the other end. So a diagnostic carries the same fields a
/// <see cref="RequestValidationException"/> does — a stable <see cref="Code"/>, a
/// <see cref="Title"/>, an explanatory <see cref="Detail"/>, an optional
/// <see cref="Remediation"/> — plus a <see cref="Severity"/> and the
/// <see cref="Field"/> it belongs next to on a form.
/// </para>
/// </remarks>
/// <param name="Severity">One of the <see cref="DiagnosticSeverity"/> constants.</param>
/// <param name="Code">Stable identifier from <see cref="ErrorCodes"/>.</param>
/// <param name="Title">Short classification, e.g. "Extended key usage dropped".</param>
/// <param name="Detail">The explanatory sentence shown to the operator.</param>
/// <param name="Remediation">What to do about it, when the detail does not already say.</param>
/// <param name="Field">The request or profile field this concerns, for inline rendering.</param>
public sealed record Diagnostic(
    string Severity,
    string Code,
    string Title,
    string Detail,
    string? Remediation = null,
    string? Field = null)
{
    /// <summary>Creates a warning-severity diagnostic.</summary>
    public static Diagnostic Warning(
        string code, string title, string detail, string? remediation = null, string? field = null)
        => new(DiagnosticSeverity.Warning, code, title, detail, remediation, field);

    /// <summary>Creates an info-severity diagnostic.</summary>
    public static Diagnostic Info(
        string code, string title, string detail, string? remediation = null, string? field = null)
        => new(DiagnosticSeverity.Info, code, title, detail, remediation, field);
}
