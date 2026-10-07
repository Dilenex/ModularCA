using System.Text.Json;
using ModularCA.Core.Services;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The audit scrubber blanks any value whose property name looks sensitive, except a true or
/// false, so a policy change still records which switch moved.
/// </summary>
public class AuditJsonScrubberTests
{
    [Fact]
    public void A_switch_keeps_its_value_under_a_sensitive_name()
    {
        var scrubbed = AuditJsonScrubber.SerializeAndScrub(new
        {
            Before = new { RequireKeyCeremony = true },
            After = new { RequireKeyCeremony = false },
        });

        using var doc = JsonDocument.Parse(scrubbed!);
        Assert.True(doc.RootElement.GetProperty("Before").GetProperty("RequireKeyCeremony").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("After").GetProperty("RequireKeyCeremony").GetBoolean());
    }

    [Theory]
    [InlineData("{\"privateKey\":\"abc\"}")]
    [InlineData("{\"pin\":1234}")]
    [InlineData("{\"apiToken\":{\"value\":\"abc\"}}")]
    [InlineData("{\"secrets\":[\"abc\"]}")]
    public void Anything_else_under_a_sensitive_name_is_blanked(string json)
    {
        var scrubbed = AuditJsonScrubber.ScrubJsonString(json);

        using var doc = JsonDocument.Parse(scrubbed);
        var value = Assert.Single(doc.RootElement.EnumerateObject()).Value;
        Assert.Equal("***", value.GetString());
    }
}
