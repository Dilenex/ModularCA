using System.Reflection;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// A step-up verification allows the authenticator's clock to differ from the host's by 15
/// seconds in either direction. It accepted the current 30-second step alone, which refused a
/// correct code whenever the two clocks sat on opposite sides of a step boundary.
/// </summary>
public class StepUpTotpToleranceTests
{
    private static readonly Type Totp = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Auth.TotpController");
    private static readonly Type StepUp = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Auth.MfaStepUpController");
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    /// <summary>The start of a 30-second step.</summary>
    private static readonly DateTimeOffset StepStart = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000 / 30 * 30);
    private static readonly long Step = StepStart.ToUnixTimeSeconds() / 30;

    private static readonly TimeSpan Tolerance = (TimeSpan)StepUp
        .GetField("StepUpTotpTolerance", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;

    private static string CodeFor(long step)
    {
        var key = (byte[])Totp.GetMethod("Base32Decode", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [Secret])!;
        return (string)Totp.GetMethod("GenerateTotp", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [key, step])!;
    }

    private static (bool valid, long timeStep) Verify(string code, int secondsIntoStep, long lastUsed = 0)
        => ((bool, long))Totp.GetMethod("VerifyTotpCodeWithin", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [Secret, code, lastUsed, Tolerance, StepStart.AddSeconds(secondsIntoStep)])!;

    [Fact]
    public void The_tolerance_is_fifteen_seconds()
        => Assert.Equal(TimeSpan.FromSeconds(15), Tolerance);

    [Theory]
    [InlineData(0)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(29)]
    public void The_current_code_is_accepted_throughout_its_step(int secondsIntoStep)
        => Assert.Equal((true, Step), Verify(CodeFor(Step), secondsIntoStep));

    /// <summary>The previous code is good for 15 seconds after its step ended, and no longer.</summary>
    [Theory]
    [InlineData(0, true)]
    [InlineData(14, true)]
    [InlineData(15, false)]
    [InlineData(29, false)]
    public void The_previous_code_is_accepted_early_in_a_step(int secondsIntoStep, bool accepted)
    {
        var (valid, step) = Verify(CodeFor(Step - 1), secondsIntoStep);
        Assert.Equal(accepted, valid);
        if (accepted) Assert.Equal(Step - 1, step);
    }

    /// <summary>The next code is good from 15 seconds before its step starts, and no sooner.</summary>
    [Theory]
    [InlineData(0, false)]
    [InlineData(14, false)]
    [InlineData(15, true)]
    [InlineData(29, true)]
    public void The_next_code_is_accepted_late_in_a_step(int secondsIntoStep, bool accepted)
    {
        var (valid, step) = Verify(CodeFor(Step + 1), secondsIntoStep);
        Assert.Equal(accepted, valid);
        if (accepted) Assert.Equal(Step + 1, step);
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(2)]
    public void A_code_two_steps_away_is_never_accepted(int offset)
    {
        Assert.False(Verify(CodeFor(Step + offset), 0).valid);
        Assert.False(Verify(CodeFor(Step + offset), 29).valid);
    }

    /// <summary>The tolerance does not reopen a step that was already used, or one before it.</summary>
    [Fact]
    public void A_step_at_or_before_the_last_used_one_is_refused()
    {
        Assert.False(Verify(CodeFor(Step), 5, lastUsed: Step).valid);
        Assert.False(Verify(CodeFor(Step - 1), 5, lastUsed: Step - 1).valid);
        Assert.False(Verify(CodeFor(Step - 1), 5, lastUsed: Step).valid);
        Assert.True(Verify(CodeFor(Step), 5, lastUsed: Step - 1).valid);
    }
}
