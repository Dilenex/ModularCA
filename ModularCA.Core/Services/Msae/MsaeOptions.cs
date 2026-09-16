namespace ModularCA.Core.Services.Msae;

/// <summary>Operator settings for the Windows enrollment protocols, bound from the <c>Msae</c> configuration section.</summary>
public sealed class MsaeOptions
{
    /// <summary>Configuration section name.</summary>
    public const string Section = "Msae";

    /// <summary>
    /// Base arc for generated template OIDs, normally the operator's Private Enterprise Number arc,
    /// e.g. <c>1.3.6.1.4.1.99999.4</c>. Blank means <see cref="MsaeTemplateOids.DefaultArc"/>.
    /// Changing it does not touch templates that already carry an OID.
    /// </summary>
    public string? TemplateOidArc { get; set; }
}
