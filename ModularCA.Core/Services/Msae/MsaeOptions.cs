namespace ModularCA.Core.Services.Msae;

/// <summary>Operator settings for the Windows enrollment protocols, bound from the <c>Msae</c> configuration section.</summary>
public sealed class MsaeOptions
{
    /// <summary>Configuration section name.</summary>
    public const string Section = "Msae";

    /// <summary>
    /// Base arc for generated template OIDs, normally the operator's Private Enterprise Number arc,
    /// e.g. <c>1.3.6.1.4.1.66874.2.1</c>. Blank means <see cref="MsaeTemplateOids.DefaultArc"/>.
    /// Changing it does not touch templates that already carry an OID.
    /// </summary>
    public string? TemplateOidArc { get; set; }

    /// <summary>
    /// Moves template identifiers this product generated under an older arc to the current one,
    /// once, at the next start. Off by default and deliberately so: a template identifier is how
    /// a Windows client recognises a certificate it already holds, so moving one makes every
    /// client treat that template as new and enroll again. New templates always use the current
    /// arc and need nothing set.
    /// </summary>
    public bool MoveGeneratedTemplateOids { get; set; }
}
