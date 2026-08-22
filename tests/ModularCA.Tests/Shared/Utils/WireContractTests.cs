using System.Text.Json;
using ModularCA.Shared.Models.CertProfiles;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared.Utils;

/// <summary>
/// Pins the JSON wire names for the properties whose casing has actually caused shipped bugs, and
/// the stored-blob casing contract.
/// <para>
/// The failures were never a lossy naming transform — for almost every property in this codebase
/// <c>JsonNamingPolicy.CamelCase</c> is exactly "lowercase the first character". They were a human
/// convention mismatch: a frontend author writes <c>allowedEkus</c>, treating "EKUs" as a word,
/// while the C# property is <c>AllowedEKUs</c> and the wire key is therefore <c>allowedEKUs</c>.
/// Because API responses are typed <c>any</c>, the wrong key is a silent <c>undefined</c> rather
/// than a compile error, and a <c>?? default</c> then masks it — the UI shows a plausible value and
/// the next save writes that default over real data.
/// </para>
/// <para>
/// These tests are the cheap guard: if someone renames a property, the wire name changes here
/// loudly instead of silently in a browser weeks later.
/// </para>
/// </summary>
public class WireContractTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static string KeyOf<T>(T value) where T : notnull
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(value, Web));
        return string.Join(",", doc.RootElement.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public void SigningProfile_EKU_field_is_allowedEKUs_not_allowedEkus()
    {
        var keys = KeyOf(new SigningProfileDto());
        Assert.Contains("allowedEKUs", keys);
        Assert.DoesNotContain("allowedEkus", keys);
    }

    /// <summary>
    /// These four were silently dropped: the admin UI rendered controls for them and sent the
    /// values, but they were absent from the request DTO so the controls were inert.
    /// AllowWildcard is security-relevant — it gates wildcard SAN issuance.
    /// </summary>
    [Theory]
    [InlineData("allowWildcard")]
    [InlineData("ctEnabled")]
    [InlineData("ctLogIds")]
    public void CertProfile_request_carries_the_previously_dropped_fields(string wireName)
        => Assert.Contains(wireName, KeyOf(new CreateCertProfileRequest()));

    [Theory]
    [InlineData("extendedKeyUsageCritical")]
    [InlineData("policyQualifiersJson")]
    public void SigningProfile_request_carries_the_previously_dropped_fields(string wireName)
        => Assert.Contains(wireName, KeyOf(new CreateSigningProfileRequest()));

    /// <summary>
    /// Stored blobs (ApprovalsJson, ParametersJson) are handed to the browser inside a camelCase
    /// envelope, so they must be written camelCase too. A bare JsonSerializer.Serialize applies no
    /// policy, which is how ceremony approver names came to render as "-".
    /// </summary>
    [Fact]
    public void Stored_blobs_are_written_camelCase()
    {
        var json = JsonSerializer.Serialize(new { Username = "alice", Action = "Approved" },
                                            SafeJsonOptions.Stored);
        Assert.Contains("\"username\"", json);
        Assert.DoesNotContain("\"Username\"", json);
    }

    /// <summary>
    /// The critical half of that change: rows written BEFORE it hold PascalCase keys, and the
    /// default deserializer is case-sensitive. Switching the write side without case-insensitive
    /// reads would have made every pre-existing blob unreadable.
    /// </summary>
    [Theory]
    [InlineData("[{\"Username\":\"alice\",\"Action\":\"Approved\"}]")]  // legacy PascalCase row
    [InlineData("[{\"username\":\"alice\",\"action\":\"Approved\"}]")]  // row written after the change
    public void Stored_blobs_read_back_under_either_casing(string stored)
    {
        var records = JsonSerializer.Deserialize<List<StoredApproval>>(stored, SafeJsonOptions.Stored);

        Assert.NotNull(records);
        Assert.Single(records!);
        Assert.Equal("alice", records![0].Username);
        Assert.Equal("Approved", records[0].Action);
    }

    /// <summary>Mirrors the shape KeyCeremonyService persists into ApprovalsJson.</summary>
    private sealed class StoredApproval
    {
        public string Username { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
    }

    /// <summary>
    /// The MaxDepth guard on the stored options must survive; it is the DoS cap that
    /// SafeJsonOptions exists for.
    /// </summary>
    [Fact]
    public void Stored_options_keep_the_depth_cap()
        => Assert.Equal(16, SafeJsonOptions.Stored.MaxDepth);
}
