namespace ModularCA.Shared.Utils;

/// <summary>One of the end-entity certificate profiles a new install is given.</summary>
/// <param name="Name">The profile's name.</param>
/// <param name="Description">What it is for.</param>
/// <param name="KeyUsages">Its key usages, as the OID catalog names them.</param>
/// <param name="ExtendedKeyUsages">Its extended key usages, as the OID catalog names them.</param>
/// <param name="ExtendedKeyUsageOids">The same usages as OIDs, the form a profile stores.</param>
/// <param name="ValidityPeriodMax">The longest certificate, as an ISO 8601 duration.</param>
public sealed record StandardCertProfile(
    string Name, string Description, string[] KeyUsages, string[] ExtendedKeyUsages, string[] ExtendedKeyUsageOids, string ValidityPeriodMax);

/// <summary>
/// The purpose-specific end-entity certificate profiles and the seeded request profile each is
/// the default of. Bootstrap seeds them on a new install; migration
/// <c>StandardCertProfiles</c> adds them to an install that predates them, and holds its own copy
/// of these values, which must not change once released.
/// </summary>
public static class StandardCertProfiles
{
    /// <summary>TLS servers.</summary>
    public const string TlsServer = "TLS Server";

    /// <summary>Devices that authenticate as TLS clients.</summary>
    public const string DeviceClient = "Device Client";

    /// <summary>People: sign-in and signed or encrypted mail.</summary>
    public const string UserAuthenticationAndEmail = "User Authentication and Email";

    /// <summary>Code signing.</summary>
    public const string CodeSigning = "Code Signing";

    /// <summary>The shortest certificate each profile allows.</summary>
    public const string ValidityPeriodMin = "P1D";

    /// <summary>Every standard profile.</summary>
    public static readonly IReadOnlyList<StandardCertProfile> All =
    [
        new(TlsServer, "TLS server certificates. Server authentication only.",
            ["digitalSignature", "keyEncipherment"], ["Server Authentication"], ["1.3.6.1.5.5.7.3.1"], "P397D"),
        new(DeviceClient, "Device certificates that authenticate as a TLS client.",
            ["digitalSignature", "keyEncipherment"], ["Client Authentication"], ["1.3.6.1.5.5.7.3.2"], "P2Y"),
        new(UserAuthenticationAndEmail, "User certificates for sign-in and for signed or encrypted mail.",
            ["digitalSignature", "keyEncipherment"], ["Client Authentication", "Email Protection"], ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"], "P1Y"),
        new(CodeSigning, "Code signing certificates. Digital signature only.",
            ["digitalSignature"], ["Code Signing"], ["1.3.6.1.5.5.7.3.3"], "P1Y"),
    ];

    /// <summary>The certificate profile each seeded request profile defaults to, by name.</summary>
    public static readonly IReadOnlyDictionary<string, string> DefaultForRequestProfile = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Web Server (ACME)"] = TlsServer,
        ["Enterprise Server (EST)"] = TlsServer,
        ["Web TLS (Internal)"] = SystemCertProfiles.WebTls,
        ["MDM Device (SCEP)"] = DeviceClient,
        ["Enterprise User (CMP)"] = UserAuthenticationAndEmail,
        ["Code Signing"] = CodeSigning,
    };
}
