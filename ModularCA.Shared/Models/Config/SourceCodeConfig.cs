namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Where this deployment's source code can be obtained, for the AGPL section 13 offer.
/// </summary>
/// <remarks>
/// <para>
/// The AGPL requires that anyone who modifies ModularCA and lets others interact with it over a
/// network prominently offer those users the Corresponding Source <em>of their modified version</em>.
/// A hardcoded link to the upstream repository would not satisfy that — it would be worse than
/// nothing, because the page would assert source availability that does not match the running
/// binary, which is a false statement made to that operator's own users on their behalf.
/// </para>
/// <para>
/// So the URL is configuration. The default points upstream, which is correct for the
/// overwhelmingly common case of running an unmodified build. An operator who modifies the
/// software points it at their own published source, and that is the whole compliance step.
/// </para>
/// <para>
/// Nothing here gates or verifies anything. It cannot: only the operator knows whether they
/// modified the code. The value of making it a visible, configurable field is that complying is
/// a one-line change and <em>not</em> complying leaves a statement in the UI that is plainly
/// wrong — which is a far better incentive than any check this program could run on itself.
/// </para>
/// </remarks>
public class SourceCodeConfig
{
    /// <summary>
    /// The canonical upstream repository. Used when <see cref="Url"/> is unset.
    /// </summary>
    /// <remarks>
    /// A constant rather than a magic string in the property initialiser, so the test that
    /// asserts the default is non-empty has something to name. A blank source URL would render a
    /// footer that silently offers nothing, and that is not a failure anyone would notice by
    /// looking at the page.
    /// </remarks>
    public const string UpstreamUrl = "https://github.com/Dilenex/ModularCA";

    /// <summary>
    /// URL where the Corresponding Source for the running build can be obtained.
    /// </summary>
    /// <remarks>
    /// Set this to your own repository if you have modified ModularCA. Leave it alone if you are
    /// running an unmodified release.
    /// </remarks>
    public string Url { get; set; } = UpstreamUrl;

    /// <summary>
    /// SPDX identifier shown alongside the link. Only change this if you hold a commercial
    /// licence for the core, in which case the AGPL notice does not describe your terms.
    /// </summary>
    public string License { get; set; } = "AGPL-3.0-only";

    /// <summary>Returns <see cref="Url"/>, falling back to upstream when it is blank.</summary>
    /// <remarks>
    /// Never returns empty. An operator who clears the field in a config file gets the upstream
    /// link rather than a dead notice — wrong for a modified build, but a visible statement that
    /// can be corrected, which an empty string is not.
    /// </remarks>
    public string EffectiveUrl =>
        string.IsNullOrWhiteSpace(Url) ? UpstreamUrl : Url.Trim();
}
