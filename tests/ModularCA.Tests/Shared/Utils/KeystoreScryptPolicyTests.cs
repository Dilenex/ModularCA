using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// What a keystore scrypt setting may be saved as, and what a keystore write does with a stored N
/// that scrypt cannot use.
/// </summary>
public sealed class KeystoreScryptPolicyTests
{
    [Theory]
    [InlineData(1 << 14, 8, 1)]
    [InlineData(1 << 16, 8, 1)]
    [InlineData(1 << 17, 8, 1)]
    [InlineData(1 << 20, 8, 1)]
    [InlineData(1 << 16, 1, 16)]
    public void A_power_of_two_n_with_r_and_p_in_range_may_be_saved(int n, int r, int p)
        => Assert.Null(KeystoreScryptPolicy.CheckNewSetting(n, r, p));

    [Theory]
    [InlineData(30000)]
    [InlineData(65535)]
    [InlineData(65537)]
    [InlineData(1000000)]
    [InlineData(0)]
    [InlineData(-65536)]
    public void An_n_that_is_not_a_power_of_two_may_not_be_saved(int n)
        => Assert.Contains("power of two", KeystoreScryptPolicy.CheckNewSetting(n, 8, 1));

    [Theory]
    [InlineData(1 << 13, 8, 1)]
    [InlineData(1 << 21, 8, 1)]
    [InlineData(1 << 16, 0, 1)]
    [InlineData(1 << 16, 33, 1)]
    [InlineData(1 << 16, 8, 0)]
    [InlineData(1 << 16, 8, 17)]
    public void Values_outside_the_ranges_may_not_be_saved(int n, int r, int p)
        => Assert.NotNull(KeystoreScryptPolicy.CheckNewSetting(n, r, p));

    [Theory]
    [InlineData(30000)]
    [InlineData(1)]
    [InlineData(0)]
    public void A_stored_n_scrypt_cannot_use_is_refused_naming_the_setting(int n)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => KeystoreScryptPolicy.RequireUsableStoredN(n));
        Assert.Contains("KeystoreScryptN", ex.Message);
        Assert.Contains(n.ToString(), ex.Message);
    }

    [Fact]
    public void A_stored_power_of_two_n_is_usable()
        => KeystoreScryptPolicy.RequireUsableStoredN(1 << 16);
}

/// <summary>
/// A new keystore scrypt setting may need at most 1 GiB per derivation (128 · N · r bytes).
/// The ranges alone allowed N = 2^20 with r = 32, which is 4 GiB.
/// </summary>
public sealed class KeystoreScryptMemoryCeilingTests
{
    [Theory]
    [InlineData(1 << 16, 8)]   // the default: 64 MiB
    [InlineData(1 << 17, 8)]   // OWASP's minimum: 128 MiB
    [InlineData(1 << 20, 8)]   // exactly 1 GiB
    [InlineData(1 << 19, 16)]  // exactly 1 GiB
    [InlineData(1 << 18, 32)]  // exactly 1 GiB
    [InlineData(1 << 15, 32)]  // 128 MiB
    public void A_setting_within_one_gibibyte_may_be_saved(int n, int r)
        => Assert.Null(KeystoreScryptPolicy.CheckNewSetting(n, r, 1));

    [Theory]
    [InlineData(1 << 20, 16)]  // 2 GiB
    [InlineData(1 << 20, 32)]  // 4 GiB, which the old ranges allowed
    [InlineData(1 << 19, 32)]  // 2 GiB
    [InlineData(1 << 19, 17)]  // 1088 MiB, just over
    public void A_setting_over_one_gibibyte_may_not_be_saved(int n, int r)
    {
        var error = KeystoreScryptPolicy.CheckNewSetting(n, r, 1);

        Assert.NotNull(error);
        Assert.Contains("MiB", error);
    }

    [Fact]
    public void The_ceiling_is_one_gibibyte()
    {
        Assert.Equal(1L << 30, KeystoreScryptPolicy.MaxMemoryBytes);
        Assert.Equal(4L << 30, KeystoreScryptPolicy.MemoryBytes(1 << 20, 32));
        Assert.True(KeystoreScryptPolicy.ExceedsMemoryCeiling(1 << 20, 16));
        Assert.False(KeystoreScryptPolicy.ExceedsMemoryCeiling(1 << 20, 8));
    }
}
