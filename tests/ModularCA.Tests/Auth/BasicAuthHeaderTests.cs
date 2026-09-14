using System.Text;
using ModularCA.Auth.Utils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Pins the RFC 7617 parsing rules used by EST's HTTP Basic authentication.
/// </summary>
/// <remarks>
/// EST (RFC 7030 section 3.2.3) makes Basic its baseline client authentication, so this parser sits
/// in front of every password-authenticated enrollment. Its failure mode is quiet: a mis-split
/// credential is rejected as a bad password, which sends the operator to the account rather than to
/// the header.
/// </remarks>
public class BasicAuthHeaderTests
{
    private static string Header(string raw) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));

    [Fact]
    public void Parses_a_well_formed_credential()
    {
        Assert.True(BasicAuthHeader.TryParse(Header("alice:s3cret"), out var u, out var p));
        Assert.Equal("alice", u);
        Assert.Equal("s3cret", p);
    }

    [Fact]
    public void Splits_on_the_first_colon_so_a_password_may_contain_colons()
    {
        // RFC 7617 forbids a colon in the user-id and permits one in the password. Splitting on
        // every colon truncates the password, and the request then fails as "invalid password"
        // against an account whose password is entirely correct.
        Assert.True(BasicAuthHeader.TryParse(Header("alice:a:b:c"), out var u, out var p));
        Assert.Equal("alice", u);
        Assert.Equal("a:b:c", p);
    }

    [Fact]
    public void Accepts_a_scheme_token_in_any_case()
    {
        // RFC 7235 makes the scheme token case-insensitive, and clients in the field send "basic".
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:pw"));
        Assert.True(BasicAuthHeader.TryParse("basic " + encoded, out var u, out _));
        Assert.Equal("alice", u);
        Assert.True(BasicAuthHeader.TryParse("BASIC " + encoded, out _, out _));
    }

    [Fact]
    public void Accepts_an_empty_password()
    {
        // Not useful as a credential, but it is well-formed, and the verifier — not the parser —
        // is where an empty password gets rejected, with an audit record.
        Assert.True(BasicAuthHeader.TryParse(Header("alice:"), out var u, out var p));
        Assert.Equal("alice", u);
        Assert.Equal(string.Empty, p);
    }

    [Fact]
    public void Decodes_non_ascii_credentials_as_utf8()
    {
        Assert.True(BasicAuthHeader.TryParse(Header("bjørn:pä$$"), out var u, out var p));
        Assert.Equal("bjørn", u);
        Assert.Equal("pä$$", p);
    }

    [Fact]
    public void Tolerates_surrounding_whitespace_in_the_token()
    {
        Assert.True(BasicAuthHeader.TryParse(Header("alice:pw") + "  ", out var u, out _));
        Assert.Equal("alice", u);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer abc.def.ghi")]      // another scheme entirely
    [InlineData("Basic")]                   // scheme with no token
    [InlineData("Basic !!!not-base64!!!")]  // undecodable token
    public void Rejects_anything_that_is_not_a_basic_credential(string? headerValue)
    {
        Assert.False(BasicAuthHeader.TryParse(headerValue, out var u, out var p));
        Assert.Equal(string.Empty, u);
        Assert.Equal(string.Empty, p);
    }

    [Theory]
    [InlineData("alicenopassword")]  // no colon at all
    [InlineData(":passwordonly")]    // empty user-id cannot identify an account
    public void Rejects_a_decoded_body_that_carries_no_user_id(string decoded)
    {
        Assert.False(BasicAuthHeader.TryParse(Header(decoded), out var u, out _));
        Assert.Equal(string.Empty, u);
    }
}
