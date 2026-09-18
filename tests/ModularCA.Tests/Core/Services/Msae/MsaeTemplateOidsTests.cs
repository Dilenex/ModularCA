using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Msae;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the OIDs templates are offered to Windows under. Windows parses an arc into a signed
/// 64-bit integer and refuses anything larger (measured on Windows 11), so generated OIDs spread
/// the template id over four 31-bit arcs, and no OID with a larger arc is accepted from anyone.
/// </summary>
public class MsaeTemplateOidsTests
{
    [Fact]
    public void A_generated_oid_is_four_31_bit_arcs_of_the_template_id_under_the_base_arc()
    {
        // All ones: each 32-bit word loses its top bit, leaving 2^31 - 1 four times.
        var allOnes = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
        Assert.Equal(MsaeTemplateOids.DefaultArc + ".2147483647.2147483647.2147483647.2147483647", MsaeTemplateOids.FromTemplateId(allOnes));

        // Big-endian: the last byte of the id is the low byte of the last arc.
        Assert.Equal(MsaeTemplateOids.DefaultArc + ".0.0.0.1", MsaeTemplateOids.FromTemplateId(new Guid("00000000-0000-0000-0000-000000000001")));

        // The top bit of a word is dropped, not carried anywhere: an id with only that bit set
        // yields zeros, so the scheme never emits an arc of 2^31 or more.
        Assert.Equal(MsaeTemplateOids.DefaultArc + ".0.0.0.0", MsaeTemplateOids.FromTemplateId(new Guid("80000000-0000-0000-0000-000000000000")));
        Assert.Equal(MsaeTemplateOids.DefaultArc + ".1.2.3.4", MsaeTemplateOids.FromTemplateId(new Guid("00000001-0000-0002-0000-000300000004")));

        // An operator's Private Enterprise Number arc replaces the default; blank means default.
        var id = new Guid("00000001-0000-0002-0000-000300000004");
        Assert.Equal("1.3.6.1.4.1.99999.4.1.2.3.4", MsaeTemplateOids.FromTemplateId(id, " 1.3.6.1.4.1.99999.4 "));
        Assert.Equal(MsaeTemplateOids.DefaultArc + ".1.2.3.4", MsaeTemplateOids.FromTemplateId(id, "   "));
        Assert.Throws<ArgumentException>(() => MsaeTemplateOids.FromTemplateId(id, "3.1"));
        Assert.Throws<ArgumentException>(() => MsaeTemplateOids.FromTemplateId(id, "1.3.6.1.4.1.99999.4" + string.Concat(Enumerable.Repeat(".1234567890", 8))));
    }

    [Fact]
    public void Every_generated_oid_is_valid_and_fits_the_column()
    {
        for (var i = 0; i < 500; i++)
        {
            var oid = MsaeTemplateOids.FromTemplateId(Guid.NewGuid(), "1.3.6.1.4.1.99999.4");
            Assert.True(MsaeTemplateOids.IsValid(oid), oid);
            Assert.True(oid.Length <= MsaeTemplateOids.MaxLength, oid);
        }
        var a = Guid.NewGuid();
        Assert.Equal(MsaeTemplateOids.FromTemplateId(a), MsaeTemplateOids.FromTemplateId(a));
        Assert.NotEqual(MsaeTemplateOids.FromTemplateId(a), MsaeTemplateOids.FromTemplateId(Guid.NewGuid()));
    }

    [Fact]
    public void The_legacy_form_is_the_whole_id_as_one_integer_and_is_no_longer_valid_when_windows_cannot_read_it()
    {
        var allOnes = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
        Assert.Equal("2.25.340282366920938463463374607431768211455", MsaeTemplateOids.LegacyFromTemplateId(allOnes));
        Assert.Equal("2.25.1", MsaeTemplateOids.LegacyFromTemplateId(new Guid("00000000-0000-0000-0000-000000000001")));
        Assert.False(MsaeTemplateOids.IsValid(MsaeTemplateOids.LegacyFromTemplateId(allOnes)));
    }

    [Theory]
    [InlineData("1.3.6.1.4.1.311.21.8.1234567.7654321.1")]
    [InlineData("2.25.1")]
    [InlineData("0.9.2342")]
    [InlineData("2.25.9223372036854775807")]   // 2^63 - 1, the largest arc Windows parses
    public void Dotted_decimal_oids_windows_can_read_are_accepted(string oid)
    {
        Assert.True(MsaeTemplateOids.IsValid(oid));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("1")]
    [InlineData("3.1.2")]
    [InlineData("1.02.3")]
    [InlineData("1.3.")]
    [InlineData(".1.3")]
    [InlineData("1.3.6.a")]
    [InlineData("2.25.9223372036854775808")]   // 2^63: Windows refuses it
    [InlineData("2.25.124369198168217782787924187026858879669")]
    [InlineData("1.3.6.1.4.1.311.21.8.1234567.7654321.1234567.7654321.1234567.7654321.1234567.7654321.1234567.7654321.1234567.7654321.1234567.7654321.1234567.7654321.12345")]   // past the column
    public void Anything_else_is_refused(string oid)
    {
        Assert.False(MsaeTemplateOids.IsValid(oid));
    }

    [Fact]
    public void A_base_arc_must_leave_room_for_the_four_generated_arcs()
    {
        Assert.True(MsaeTemplateOids.IsValidBaseArc("1.3.6.1.4.1.99999.4"));
        // The budget is the column less the four generated arcs: 128 - 44 = 84 characters.
        Assert.True(MsaeTemplateOids.IsValidBaseArc(MsaeTemplateOids.DefaultArc));
        Assert.True(MsaeTemplateOids.IsValidBaseArc("1.3.6.1.4.1.12345678.1.1"));   // an eight-digit enterprise number, with room to spare
        var exactly84 = "1.3.6.1.4.1.9999" + string.Concat(Enumerable.Repeat(".1234567890", 6)) + ".1";
        Assert.Equal(84, exactly84.Length);
        Assert.True(MsaeTemplateOids.IsValidBaseArc(exactly84));
        Assert.False(MsaeTemplateOids.IsValidBaseArc(exactly84 + "1"));             // one char over
        Assert.False(MsaeTemplateOids.IsValidBaseArc("2.25.9223372036854775808"));
        Assert.False(MsaeTemplateOids.IsValidBaseArc(null));
    }

    [Fact]
    public async Task Startup_repair_moves_generated_oids_only_when_told_and_nothing_else_ever()
    {
        using var db = InMemoryDbContextFactory.Create();
        const string Historical = "2.25";
        const string Mine = "1.3.6.1.4.1.66874.2.9";

        var legacy = new CertificateTemplateEntity { Name = "legacy-generated" };
        legacy.MsaeTemplateOid = MsaeTemplateOids.LegacyFromTemplateId(legacy.Id);
        var historical = new CertificateTemplateEntity { Name = "generated-under-2.25" };
        historical.MsaeTemplateOid = MsaeTemplateOids.FromTemplateId(historical.Id, Historical);
        var current = new CertificateTemplateEntity { Name = "generated-under-the-product-arc" };
        current.MsaeTemplateOid = MsaeTemplateOids.FromTemplateId(current.Id);
        var operators = new CertificateTemplateEntity { Name = "from-adcs", MsaeTemplateOid = "1.3.6.1.4.1.311.21.8.5.1" };
        var someoneElses = new CertificateTemplateEntity { Name = "typed-under-2.25", MsaeTemplateOid = MsaeTemplateOids.LegacyFromTemplateId(Guid.NewGuid()) };
        var notOffered = new CertificateTemplateEntity { Name = "not-offered", MsaeTemplateOid = null };
        db.CertificateTemplates.AddRange(legacy, historical, current, operators, someoneElses, notOffered);
        await db.SaveChangesAsync();

        // A new template needs no configuration: it is already under this product's own arc.
        Assert.StartsWith(MsaeTemplateOids.DefaultArc + ".", current.MsaeTemplateOid);

        // Nothing moves while the move is not asked for, whatever arc is configured.
        Assert.Equal(0, await MsaeTemplateOidRepair.RunAsync(db, null, move: false, logger: NullLogger.Instance));
        Assert.Equal(0, await MsaeTemplateOidRepair.RunAsync(db, Mine, move: false, logger: NullLogger.Instance));
        Assert.Equal(MsaeTemplateOids.LegacyFromTemplateId(legacy.Id), legacy.MsaeTemplateOid);
        Assert.Equal(MsaeTemplateOids.FromTemplateId(historical.Id, Historical), historical.MsaeTemplateOid);

        // Told to move, with no arc configured: both older forms come to the product's arc, and
        // the one already there is left alone. Operator identifiers are never touched.
        Assert.Equal(2, await MsaeTemplateOidRepair.RunAsync(db, null, move: true, logger: NullLogger.Instance));
        Assert.Equal(MsaeTemplateOids.FromTemplateId(legacy.Id), legacy.MsaeTemplateOid);
        Assert.Equal(MsaeTemplateOids.FromTemplateId(historical.Id), historical.MsaeTemplateOid);
        Assert.Equal(MsaeTemplateOids.FromTemplateId(current.Id), current.MsaeTemplateOid);
        Assert.Equal("1.3.6.1.4.1.311.21.8.5.1", operators.MsaeTemplateOid);
        Assert.StartsWith("2.25.", someoneElses.MsaeTemplateOid);
        Assert.DoesNotContain('.', someoneElses.MsaeTemplateOid!.Substring(5));   // still one big arc: untouched
        Assert.Null(notOffered.MsaeTemplateOid);

        // Idempotent.
        Assert.Equal(0, await MsaeTemplateOidRepair.RunAsync(db, null, move: true, logger: NullLogger.Instance));

        // An operator with their own enterprise number moves everything generated to it.
        Assert.Equal(3, await MsaeTemplateOidRepair.RunAsync(db, Mine, move: true, logger: NullLogger.Instance));
        Assert.Equal(MsaeTemplateOids.FromTemplateId(legacy.Id, Mine), legacy.MsaeTemplateOid);
        Assert.Equal(MsaeTemplateOids.FromTemplateId(historical.Id, Mine), historical.MsaeTemplateOid);
        Assert.Equal(MsaeTemplateOids.FromTemplateId(current.Id, Mine), current.MsaeTemplateOid);
        Assert.Equal("1.3.6.1.4.1.311.21.8.5.1", operators.MsaeTemplateOid);
    }
}
