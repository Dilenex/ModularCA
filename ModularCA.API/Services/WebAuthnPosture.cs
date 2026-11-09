using Fido2NetLib;
using Fido2NetLib.Objects;

namespace ModularCA.API.Services;

/// <summary>
/// The WebAuthn user-verification posture the security policy asks for, in one place for every
/// endpoint that issues or verifies assertion options.
/// </summary>
/// <remarks>
/// Fido2 enforces user verification only when the ORIGINAL options asked for
/// <see cref="UserVerificationRequirement.Required"/>. The password-login endpoint used to issue
/// its own options with <see cref="UserVerificationRequirement.Preferred"/> under the key the
/// verify step reads, so a security key signed in without its PIN while the policy required
/// verification (bug hunt 2026-11, F5).
/// </remarks>
public static class WebAuthnPosture
{
    /// <summary>The requirement to put in assertion options under the policy.</summary>
    /// <param name="requireUserVerification">The policy's <c>RequireWebAuthnUserVerification</c>.</param>
    /// <returns><c>Required</c> when the policy requires verification, otherwise <c>Preferred</c>.</returns>
    public static UserVerificationRequirement For(bool requireUserVerification)
        => requireUserVerification ? UserVerificationRequirement.Required : UserVerificationRequirement.Preferred;

    /// <summary>
    /// Whether options cached for an assertion are strict enough to verify under the policy now:
    /// false when the policy requires verification and the options did not ask for it, wherever
    /// they were issued and whenever (options cached before the policy was tightened included).
    /// </summary>
    /// <param name="options">The options the assertion answers.</param>
    /// <param name="requireUserVerification">The policy's <c>RequireWebAuthnUserVerification</c>.</param>
    /// <returns>True when the assertion may be verified against these options.</returns>
    public static bool OptionsMeetPolicy(AssertionOptions options, bool requireUserVerification)
        => !requireUserVerification || options.UserVerification == UserVerificationRequirement.Required;
}
