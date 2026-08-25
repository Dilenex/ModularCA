using ModularCA.Core.Services.Cmp;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Tests for <see cref="CmpService.DnEquals"/>, the DN comparison used by the CMP revocation
/// path. Too lenient and DNs that should differ compare equal; too strict and legitimate
/// revocations are rejected. The previous implementation used <c>String.Contains</c>, which let
/// "CN=Foo" match "CN=FooBar" — the case in test #4 below.
/// <para>
/// This class used to claim it prevented "a CA revoking certs issued by a different CA". It
/// does not: it exercises a pure string helper and never reaches the revocation handler. The
/// guard that actually enforces ownership is <see cref="CmpService.IsRevocableByCa"/>, covered
/// by <see cref="CmpRevocationOwnershipTests"/> — and until that was written, the guard was
/// conditional on a non-empty stored issuer and nothing tested it at all.
/// </para>
/// </summary>
public class CmpServiceDnEqualsTests
{
    [Fact]
    public void Identical_Strings_Are_Equal()
    {
        Assert.True(CmpService.DnEquals("CN=Foo,O=Acme", "CN=Foo,O=Acme"));
    }

    [Fact]
    public void Case_Insensitive_Equal_Matches()
    {
        Assert.True(CmpService.DnEquals("CN=Foo,O=Acme", "cn=foo,o=acme"));
    }

    [Fact]
    public void Different_RDN_Order_Still_Matches_Via_Structural_Compare()
    {
        // Some clients emit DN strings in different RDN orders than the canonical CA storage.
        // BouncyCastle's X509Name.Equivalent(inOrder: false) accepts that.
        Assert.True(CmpService.DnEquals("CN=Foo,O=Acme", "O=Acme,CN=Foo"));
    }

    [Fact]
    public void Substring_Does_NOT_Match_Anymore()
    {
        // The bug we fixed. A CA with subject "CN=Foo,O=Acme" must NOT be allowed to revoke
        // certs whose issuer is "CN=FooBar,O=Acme" — the prior Contains-based fallback let
        // this through.
        Assert.False(CmpService.DnEquals("CN=Foo,O=Acme", "CN=FooBar,O=Acme"));
    }

    [Fact]
    public void Different_Organization_Does_Not_Match()
    {
        Assert.False(CmpService.DnEquals("CN=Foo,O=Acme", "CN=Foo,O=AcmeCorp"));
    }

    [Fact]
    public void Malformed_Input_Returns_False_Fail_Closed()
    {
        // Garbage on either side parses to nothing usable — fail closed (don't revoke).
        Assert.False(CmpService.DnEquals("not a DN", "CN=Foo"));
        Assert.False(CmpService.DnEquals("CN=Foo", "completely invalid"));
    }
}
