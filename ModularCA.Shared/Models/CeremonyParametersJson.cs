using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace ModularCA.Shared.Models;

/// <summary>
/// The one reader of stored ceremony parameters
/// (<see cref="Entities.KeyCeremonyEntity.ParametersJson"/>). Case-insensitive, because stored
/// rows hold both casings: PascalCase from a bare serializer (controlled-user, CA and SSH
/// ceremonies) and camelCase from <see cref="Utils.SafeJsonOptions.Stored"/> (RevokeCa and the
/// policy changes).
/// <para>
/// Fails closed on a pre-0.4.0 scope key (<c>TenantId</c>, <c>MintedTierTenantId</c>, in any
/// case). The RenameTenantToSpace migration renames them; one left behind would otherwise read as
/// a null space, which means the whole instance.
/// </para>
/// <para>
/// Any other unknown member is skipped, even on a type that refuses one as a request body
/// (<see cref="KeyCeremonyParameters"/>): a stored row outlives the shape that wrote it.
/// </para>
/// </summary>
public static class CeremonyParametersJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver
        {
            Modifiers = { info => { if (info.Kind == JsonTypeInfoKind.Object) info.UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip; } },
        },
    };

    /// <summary>The top-level keys that named the space before 0.4.0, compared without regard to case.</summary>
    public static readonly IReadOnlyList<string> LegacyKeys = ["TenantId", "MintedTierTenantId"];

    /// <summary>
    /// Reads <paramref name="json"/> as <typeparamref name="T"/>. Throws <see cref="JsonException"/>
    /// when it does not parse or carries a legacy scope key (see <see cref="LegacyKeys"/>).
    /// </summary>
    public static T? Read<T>(string json)
    {
        RefuseLegacyKeys(json);
        return JsonSerializer.Deserialize<T>(json, Options);
    }

    /// <summary>
    /// The space <paramref name="json"/> names in its top-level <c>SpaceId</c> (any case), or null
    /// for the instance or when it names none. Reads every stored shape, whatever else it holds.
    /// Throws <see cref="JsonException"/> as <see cref="Read{T}"/> does.
    /// </summary>
    public static Guid? ReadSpaceId(string json)
    {
        var scope = Read<SpaceScope>(json);
        return scope?.SpaceId is Guid id && id != Guid.Empty ? id : null;
    }

    private static void RefuseLegacyKeys(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            return;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (LegacyKeys.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
                throw new JsonException(
                    $"Stored ceremony parameters carry the pre-0.4.0 key '{property.Name}', which the RenameTenantToSpace "
                    + "migration renames. Refusing to read them: a lost space would widen the ceremony to the whole instance.");
        }
    }

    private sealed class SpaceScope
    {
        public Guid? SpaceId { get; set; }
    }
}
