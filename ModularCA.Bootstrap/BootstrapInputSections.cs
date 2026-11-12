using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// Refuses a bootstrap input that lacks a section the procedure reads. The models give every
/// section a default, but a deserializer still writes null for one that is present and empty: a
/// setup request body with <c>"admin": null</c>, or a <c>bootstrap.yaml</c> with a bare
/// <c>HttpsApi:</c> key. Such an input used to fail halfway through with a null reference; it is
/// now refused before anything is changed, naming the section. Sections the procedure treats as
/// optional (the setup request's <c>security</c>, bootstrap.yaml's <c>Administration</c> and
/// <c>Acme</c>) are not required here.
/// </summary>
public static class BootstrapInputSections
{
    /// <summary>
    /// Throws <see cref="InvalidRequestException"/> naming every section of the setup request
    /// that is null, by its JSON name.
    /// </summary>
    /// <param name="request">The wizard's setup request.</param>
    public static void EnsureSetupSectionsPresent(SetupRequest request)
    {
        var missing = new List<string>();
        if (request.Organization is null) missing.Add("organization");
        if (request.RootCa is null) missing.Add("rootCa");
        if (request.Admin is null) missing.Add("admin");
        if (request.Features is null) missing.Add("features");
        if (request.WebTlsCertificate is null) missing.Add("webTlsCertificate");
        if (request.Database is null) missing.Add("database");
        if (request.Network is null) missing.Add("network");
        Refuse("The setup request", missing);
    }

    /// <summary>
    /// Throws <see cref="InvalidRequestException"/> naming every section of bootstrap.yaml that
    /// is null, by its YAML key.
    /// </summary>
    /// <param name="config">The loaded bootstrap.yaml.</param>
    public static void EnsureBootstrapSectionsPresent(YamlBootstrapLoader.BootstrapConfig config)
    {
        var missing = new List<string>();
        if (config.CA is null) missing.Add("CA");
        if (config.HttpsApi is null) missing.Add("HttpsApi");
        if (config.Features is null) missing.Add("Features");
        Refuse("bootstrap.yaml", missing);
    }

    /// <summary>
    /// Throws <see cref="InvalidRequestException"/> when bootstrap.yaml's
    /// <c>Administration.ClaimTokenSha256</c> is given but is not a SHA-256 in hex (64 hex digits),
    /// or <c>Administration.ClaimTokenLifetimeHours</c> is given but is not between 1 and 8760.
    /// A wrong hash would leave the first administrator with no password and a claim nobody can
    /// redeem, so it is refused before anything is changed. A missing or empty hash is not a claim
    /// and passes: the bootstrap then generates a password.
    /// </summary>
    /// <param name="administration">bootstrap.yaml's Administration section, or null when it is absent.</param>
    public static void EnsureClaimTokenUsable(YamlBootstrapLoader.AdministrationConfig? administration)
    {
        if (string.IsNullOrWhiteSpace(administration?.ClaimTokenSha256)) return;
        if (!ModularCA.Auth.Services.AccountClaims.TryParseHashHex(administration.ClaimTokenSha256, out _))
            throw new InvalidRequestException(
                "bootstrap.yaml's Administration.ClaimTokenSha256 is not a SHA-256: it must be 64 hex digits.",
                ErrorCodes.RequestInvalid,
                "Put the hash of the claim token there, never the token itself. ModularCA.API --new-claim-token prints a token and the line to use; nothing was changed.");
        var maxHours = (int)ModularCA.Auth.Services.AccountClaims.MaxLifetime.TotalHours;
        if (administration.ClaimTokenLifetimeHours is int hours && (hours < 1 || hours > maxHours))
            throw new InvalidRequestException(
                $"bootstrap.yaml's Administration.ClaimTokenLifetimeHours is {hours}: it must be between 1 and {maxHours}.",
                ErrorCodes.RequestInvalid,
                "Leave it out for seven days; nothing was changed.");
    }

    private static void Refuse(string source, List<string> missing)
    {
        if (missing.Count == 0) return;
        var noun = missing.Count == 1 ? "section" : "sections";
        throw new InvalidRequestException(
            $"{source} has an empty {noun}: {string.Join(", ", missing)}.",
            ErrorCodes.RequestInvalid,
            "Fill in or remove each empty section; nothing was changed.");
    }
}
