using System.Text.Json;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.SigningProfiles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Establishes ground truth for the signing-profile EKU round trip: the JSON wire name, the
/// persistence path, and what happens when the stored value is already corrupt.
/// </summary>
public class SigningProfileEkuRoundTripTests
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// Pins the wire name. System.Text.Json's camelCase policy lowercases only the leading
    /// character run of <c>AllowedEKUs</c>, so the JSON key is <c>allowedEKUs</c> — NOT
    /// <c>allowedEkus</c>. The admin UI read the latter and silently got undefined.
    /// </summary>
    [Fact]
    public void Dto_serializes_the_EKU_field_as_allowedEKUs()
    {
        var json = JsonSerializer.Serialize(
            new SigningProfileDto { AllowedEKUs = $"[\"{ServerAuthOid}\"]" },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"allowedEKUs\"", json);
        Assert.DoesNotContain("\"allowedEkus\"", json);
    }

    /// <summary>
    /// The request DTO must bind that same key back. Web defaults are case-insensitive, so this
    /// also proves a client sending either casing is accepted.
    /// </summary>
    [Theory]
    [InlineData("allowedEKUs")]
    [InlineData("allowedEkus")]
    public void Update_request_binds_the_EKU_field(string wireName)
    {
        var body = $"{{\"name\":\"p\",\"{wireName}\":\"[\\\"{ServerAuthOid}\\\"]\"}}";

        var parsed = JsonSerializer.Deserialize<UpdateSigningProfileRequest>(
            body, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Equal($"[\"{ServerAuthOid}\"]", parsed!.AllowedEKUs);
    }

    [Fact]
    public async Task UpdateAsync_persists_AllowedEKUs()
    {
        using var db = InMemoryDbContextFactory.Create();
        var entity = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "sp", AllowedEKUs = "[]" };
        db.SigningProfiles.Add(entity);
        await db.SaveChangesAsync();

        var svc = new SigningProfileService(db);
        await svc.UpdateAsync(entity.Id, new UpdateSigningProfileRequest
        {
            Name = "sp",
            AllowedEKUs = $"[\"{ServerAuthOid}\"]",
        });

        var reloaded = await svc.GetByIdAsync(entity.Id);
        Assert.Equal($"[\"{ServerAuthOid}\"]", reloaded!.AllowedEKUs);
    }

    /// <summary>
    /// The write path now normalises, so a save repairs a value corrupted by the old parse bug
    /// rather than persisting it unchanged and compounding it on the next round trip.
    /// </summary>
    [Theory]
    // double-encoded: an array whose single element is itself an encoded array
    [InlineData("[\"[\\\"1.3.6.1.5.5.7.3.1\\\"]\"]")]
    // CSV fragments of a JSON array — exactly what the old .split(',') produced and then stored
    [InlineData("[\"[\\\"1.3.6.1.5.5.7.3.1\\\"\",\"\\\"1.3.6.1.5.5.7.3.1\\\"]\"]")]
    // plain comma-separated
    [InlineData("1.3.6.1.5.5.7.3.1")]
    public async Task UpdateAsync_repairs_a_corrupted_value(string stored)
    {
        using var db = InMemoryDbContextFactory.Create();
        var entity = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "sp", AllowedEKUs = "[]" };
        db.SigningProfiles.Add(entity);
        await db.SaveChangesAsync();

        var svc = new SigningProfileService(db);
        await svc.UpdateAsync(entity.Id, new UpdateSigningProfileRequest { Name = "sp", AllowedEKUs = stored });

        var reloaded = await svc.GetByIdAsync(entity.Id);
        Assert.Equal($"[\"{ServerAuthOid}\"]", reloaded!.AllowedEKUs);
    }

    /// <summary>
    /// The UI has always sent this checkbox; it was absent from the request DTO and the entity
    /// mapping, so it silently did nothing.
    /// </summary>
    [Fact]
    public async Task UpdateAsync_persists_ExtendedKeyUsageCritical()
    {
        using var db = InMemoryDbContextFactory.Create();
        var entity = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "sp", AllowedEKUs = "[]" };
        db.SigningProfiles.Add(entity);
        await db.SaveChangesAsync();

        var svc = new SigningProfileService(db);
        await svc.UpdateAsync(entity.Id, new UpdateSigningProfileRequest
        {
            Name = "sp",
            AllowedEKUs = $"[\"{ServerAuthOid}\"]",
            ExtendedKeyUsageCritical = true,
        });

        Assert.True((await svc.GetByIdAsync(entity.Id))!.ExtendedKeyUsageCritical);
    }
}
