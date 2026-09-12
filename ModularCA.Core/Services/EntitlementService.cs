using Microsoft.Extensions.Logging;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Licensing;

namespace ModularCA.Core.Services;

/// <summary>
/// Resolves entitlements from a signed licence loaded once at startup.
/// </summary>
/// <remarks>
/// <para>
/// Registered as a singleton and resolved once, because a licence cannot change while the
/// process runs — installing a new one is a file drop and a restart. That also keeps the
/// hot path free of file IO and of any temptation to re-verify a signature per request.
/// </para>
/// <para>
/// An unreadable or unsigned licence degrades to the free edition and logs why. It is never a
/// startup failure: refusing to boot a certificate authority over a licence file would take
/// issuance, CRL and OCSP down for a paperwork problem.
/// </para>
/// </remarks>
public sealed class EntitlementService : IEntitlementService
{
    private readonly HashSet<string> _entitlements;

    /// <inheritdoc/>
    public LicenseLoadResult License { get; }

    /// <summary>
    /// Creates the service from a licence document, verifying it once.
    /// </summary>
    /// <param name="licenseDocument">Licence file contents, or null/empty for the free edition.</param>
    /// <param name="logger">Logger; the licence state is recorded once at startup.</param>
    /// <param name="signerPublicKey">Test-only override for the pinned signing key.</param>
    public EntitlementService(
        string? licenseDocument,
        ILogger<EntitlementService>? logger = null,
        byte[]? signerPublicKey = null)
    {
        License = LicenseVerifier.Verify(licenseDocument, signerPublicKey);

        _entitlements = License.IsValid
            ? new HashSet<string>(License.Claims!.Entitlements, StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);

        if (License.Status == LicenseStatus.Valid)
            logger?.LogInformation("Licence loaded: {Diagnostic}", License.Diagnostic);
        else if (License.Status == LicenseStatus.Absent)
            logger?.LogInformation("{Diagnostic}", License.Diagnostic);
        else
            // Warning, not Error: the server is fine and serving. Something a human must fix,
            // not something that is currently breaking certificate issuance.
            logger?.LogWarning("Running the free edition. {Diagnostic}", License.Diagnostic);
    }

    /// <inheritdoc/>
    public bool IsEntitled(string featureKey) => _entitlements.Contains(featureKey);

    /// <inheritdoc/>
    public bool IsAvailable(string featureKey) => Explain(featureKey) is null;

    /// <inheritdoc/>
    public EntitlementDenial? Explain(string featureKey)
    {
        if (!IsEntitled(featureKey))
        {
            return new EntitlementDenial(
                EntitlementDenialReason.NotEntitled,
                featureKey,
                $"This installation is not licensed for '{featureKey}'.",
                "Purchase the feature, then install the updated licence and restart the service.");
        }

        var maintenance = License.Claims!.MaintenanceThrough;
        if (!FeatureCatalog.CoveredByMaintenance(featureKey, maintenance))
        {
            var introduced = FeatureCatalog.IntroducedOn(featureKey);
            var shipped = introduced is { } d ? d.ToString("yyyy-MM-dd") : "a later release";

            return new EntitlementDenial(
                EntitlementDenialReason.MaintenanceLapsed,
                featureKey,
                $"'{featureKey}' shipped on {shipped}, after this licence's maintenance ended on "
                + $"{maintenance:yyyy-MM-dd}. The entitlement itself does not expire.",
                "Renew maintenance to use features released after that date. Everything you were "
                + "already using stays available, and security updates are unaffected.");
        }

        return null;
    }

    /// <inheritdoc/>
    public int? GetLimit(string limitName)
        => License.IsValid && License.Claims!.Limits.TryGetValue(limitName, out var value)
            ? value
            : null;
}
