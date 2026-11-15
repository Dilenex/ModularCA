using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// A serial as people read it (whole octets, as OpenSSL prints it) and back: the form the
/// consoles show, and what a search makes of a serial typed or pasted in any spelling.
/// </summary>
public class SerialDisplayTests
{
    [Theory]
    [InlineData("2C06C00CB8D82FBE8931387809E6DA6", "02C06C00CB8D82FBE8931387809E6DA6")]
    [InlineData("E8790FF9CBADC6BD5C0D3B1F7A82613E", "E8790FF9CBADC6BD5C0D3B1F7A82613E")]
    [InlineData("A", "0A")]
    [InlineData("0", "00")]
    [InlineData("", "")]
    [InlineData(null, "")]
    [InlineData("not-a-serial", "not-a-serial")]
    public void A_serial_is_shown_in_whole_octets(string? stored, string shown)
        => Assert.Equal(shown, CertificateUtil.DisplaySerial(stored));

    [Fact]
    public void What_is_shown_is_taken_back_to_the_stored_form()
    {
        foreach (var stored in new[] { "2C06C00", "E879", "A", "10" })
            Assert.Equal(stored, CertificateUtil.NormalizeSerialForLookup(CertificateUtil.DisplaySerial(stored)));
    }

    [Theory]
    [InlineData("02C06C00", "2C06C00")]
    [InlineData("02:c0:6c:00", "2C06C00")]
    [InlineData("  02 C0 6C 00 ", "2C06C00")]
    [InlineData("c06", "C06")]
    public void A_search_for_hex_matches_serials_in_their_stored_form(string typed, string term)
        => Assert.Equal(term, CertificateUtil.SerialSearchTerm(typed));

    [Theory]
    [InlineData("host.example.test")]
    [InlineData("CN=web")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(":-")]
    [InlineData(null)]
    public void A_search_that_is_not_hex_is_left_as_typed(string? typed)
        => Assert.Null(CertificateUtil.SerialSearchTerm(typed));
}
