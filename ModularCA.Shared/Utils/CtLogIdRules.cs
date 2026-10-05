using System.Text.Json;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Parses a cert profile's <c>CtLogIds</c>: a JSON array of internal CT log ids
/// (<c>CtLogEntity.Id</c>), not RFC 6962 LogIDs. Blank means every enabled log.
/// </summary>
/// <remarks>
/// Issuance deserialises the field as a list of GUIDs inside the CT submission's catch-all, so a
/// malformed value turned off CT submission for every certificate under the profile, logged only as
/// a warning. The admin API refuses such a value at save (and ids naming no log), so this parser
/// and the issuance read agree on what is valid.
/// </remarks>
public static class CtLogIdRules
{
    /// <summary>
    /// True, with the ids, for a blank field (no ids) or a JSON array of GUIDs; false, with the
    /// reason, otherwise.
    /// </summary>
    public static bool TryParse(string? json, out List<Guid> ids, out string? error)
    {
        ids = new List<Guid>();
        error = null;
        if (string.IsNullOrWhiteSpace(json)) return true;
        List<Guid>? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<List<Guid>>(json, SafeJsonOptions.Default);
        }
        catch (JsonException)
        {
            error = "CtLogIds must be a JSON array of CT log ids (GUIDs from GET /api/v1/admin/ct-logs/options), such as [\"3f2504e0-4f89-11d3-9a0c-0305e82c3301\"].";
            return false;
        }
        if (parsed != null) ids = parsed;
        return true;
    }
}
