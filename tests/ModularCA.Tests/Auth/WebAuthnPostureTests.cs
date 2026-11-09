using Fido2NetLib;
using Fido2NetLib.Objects;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Bug hunt 2026-11, F5: the password-login endpoint issued WebAuthn assertion options with user
/// verification Preferred whatever the policy said, and Fido2 enforces verification only when the
/// original options asked for Required, so a security key signed in without its PIN. Login now
/// issues options under the policy, and verification refuses options that do not meet it.
/// </summary>
public sealed class WebAuthnPostureTests
{
    private const string PostureType = "ModularCA.API.Services.WebAuthnPosture";

    private static UserVerificationRequirement For(bool require)
        => (UserVerificationRequirement)ApiAssembly.TypeNamed(PostureType).GetMethod("For")!.Invoke(null, [require])!;

    private static bool Meets(AssertionOptions options, bool require)
        => (bool)ApiAssembly.TypeNamed(PostureType).GetMethod("OptionsMeetPolicy")!.Invoke(null, [options, require])!;

    /// <summary>Options as the login endpoint issues them and as the verify step reads them back from the cache.</summary>
    private static AssertionOptions IssuedAndCached(UserVerificationRequirement uv)
    {
        var fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = "ca.example.test",
            ServerName = "ModularCA",
            Origins = new HashSet<string> { "https://ca.example.test" },
        });
        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = uv,
        });
        return AssertionOptions.FromJson(options.ToJson());
    }

    [Fact]
    public void The_policy_decides_the_requirement_in_issued_options()
    {
        Assert.Equal(UserVerificationRequirement.Required, For(true));
        Assert.Equal(UserVerificationRequirement.Preferred, For(false));
    }

    [Fact]
    public void Cached_options_keep_their_requirement()
        => Assert.Equal(UserVerificationRequirement.Required, IssuedAndCached(For(true)).UserVerification);

    [Fact]
    public void Options_without_required_verification_are_refused_when_the_policy_requires_it()
    {
        Assert.False(Meets(IssuedAndCached(UserVerificationRequirement.Preferred), require: true));
        Assert.True(Meets(IssuedAndCached(UserVerificationRequirement.Required), require: true));
        Assert.True(Meets(IssuedAndCached(UserVerificationRequirement.Preferred), require: false));
    }
}
