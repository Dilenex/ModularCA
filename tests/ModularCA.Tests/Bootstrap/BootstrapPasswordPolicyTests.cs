using ModularCA.Auth.Services;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Covers the password rules the bootstrap paths depend on.
/// <para>
/// The rules had two implementations — <c>PasswordPolicyService.ValidatePolicyRules</c> for the
/// runtime and <c>BootstrapProfileSeeder.MeetsPolicy</c> for bootstrap — and the duplication is
/// how the gap arose. The generated-password path looped on its copy; the wizard-supplied path
/// called neither, so the most privileged account in the install was the one account whose
/// password was never checked. There is now one implementation and these tests hold it to the
/// defaults the wizard is validated against.
/// </para>
/// </summary>
public class BootstrapPasswordPolicyTests
{
    private static PasswordPolicyEntity Defaults() => new();

    [Fact]
    public void Default_policy_is_the_one_the_setup_wizard_enforces()
    {
        // SetupController validates the administrator password against `new PasswordPolicyEntity()`
        // because SeedPasswordPolicy has not run yet. If these defaults change, the wizard's
        // pre-check changes with them — which is the intent, but it should be a deliberate edit
        // rather than a surprise.
        var policy = Defaults();

        Assert.Equal(12, policy.MinLength);
        Assert.True(policy.RequireUppercase);
        Assert.True(policy.RequireLowercase);
        Assert.True(policy.RequireDigit);
        Assert.True(policy.RequireSymbol);
    }

    [Theory]
    [InlineData("short1!A", "at least 12")]            // too short
    [InlineData("alllowercase1!", "uppercase")]
    [InlineData("ALLUPPERCASE1!", "lowercase")]
    [InlineData("NoDigitsHere!!", "digit")]
    [InlineData("NoSymbolsHere1", "symbol")]
    public void Weak_passwords_are_rejected_with_a_reason(string password, string expectedFragment)
    {
        var errors = PasswordPolicyService.Validate(password, Defaults());

        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains(expectedFragment, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_compliant_password_is_accepted()
    {
        Assert.Empty(PasswordPolicyService.Validate("Str0ng-Bootstrap-Pw!", Defaults()));
    }

    [Fact]
    public void Every_violation_is_reported_not_just_the_first()
    {
        // The wizard joins these into one message, so an operator fixing a password should not
        // have to submit five times to discover five problems.
        var errors = PasswordPolicyService.Validate("aaaa", Defaults());

        Assert.True(errors.Count >= 4, $"expected length + uppercase + digit + symbol, got: {string.Join(" | ", errors)}");
    }

    [Fact]
    public void MeetsPolicy_agrees_with_Validate()
    {
        // MeetsPolicy is now a thin delegation. Pinning the agreement means a future attempt to
        // "optimise" it back into its own copy fails here rather than in production.
        var policy = Defaults();
        foreach (var candidate in new[] { "Str0ng-Bootstrap-Pw!", "weak", "NoDigits!!!!", "" })
        {
            var viaService = PasswordPolicyService.Validate(candidate, policy).Count == 0;
            var viaSeeder = InvokeMeetsPolicy(candidate, policy);
            Assert.Equal(viaService, viaSeeder);
        }
    }

    /// <summary>
    /// <c>MeetsPolicy</c> is internal to ModularCA.Bootstrap, so reach it reflectively rather
    /// than widening its visibility purely for a test.
    /// </summary>
    private static bool InvokeMeetsPolicy(string password, PasswordPolicyEntity policy)
    {
        var seeder = typeof(ModularCA.Bootstrap.BootstrapProfileSeeder);
        var method = seeder.GetMethod("MeetsPolicy",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        return (bool)method!.Invoke(null, [password, policy])!;
    }
}
