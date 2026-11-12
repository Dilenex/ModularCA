using System.Collections;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The access-token key is read from <c>JWT.Secret</c> at each check. With no usable secret it
/// offers no key at all, so every token is refused, rather than a key made from an empty or short
/// value that a forged token could be signed with.
/// </summary>
public class JwtSigningKeyTests
{
    private static readonly Type KeyType = ApiAssembly.TypeNamed("ModularCA.API.Startup.JwtSigningKey");

    private static int KeyCount(string? secret)
    {
        var config = new SystemConfig { JWT = { Secret = secret! } };
        var keys = Activator.CreateInstance(KeyType, config)!;
        var list = (IEnumerable)KeyType.GetMethod("Keys")!.Invoke(keys, null)!;
        return list.Cast<object>().Count();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("0123456789abcdef0123456789abcde")] // 31 bytes
    public void No_key_is_offered_for_a_missing_or_short_secret(string? secret)
        => Assert.Equal(0, KeyCount(secret));

    [Fact]
    public void A_secret_of_32_bytes_or_more_gives_one_key()
    {
        Assert.Equal(1, KeyCount("0123456789abcdef0123456789abcdef"));
        Assert.Equal(1, KeyCount(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64))));
    }
}
