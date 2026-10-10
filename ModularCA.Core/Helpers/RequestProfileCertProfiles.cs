using System.Text.Json;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The certificate profiles a request profile designates.
/// </summary>
public static class RequestProfileCertProfiles
{
    /// <summary>
    /// The designated certificate profile ids: the default, then the allowed list (a JSON array
    /// of ids), without repeats. An unreadable list counts as empty.
    /// </summary>
    /// <param name="defaultCertProfileId">The request profile's default certificate profile.</param>
    /// <param name="allowedCertProfileIds">The request profile's allowed list as stored.</param>
    public static List<Guid> DesignatedIds(Guid? defaultCertProfileId, string? allowedCertProfileIds)
    {
        var ids = new List<Guid>();
        if (defaultCertProfileId is Guid first)
            ids.Add(first);
        if (!string.IsNullOrWhiteSpace(allowedCertProfileIds))
        {
            try
            {
                foreach (var id in JsonSerializer.Deserialize<List<Guid>>(allowedCertProfileIds) ?? [])
                    if (!ids.Contains(id)) ids.Add(id);
            }
            catch (JsonException) { }
        }
        return ids;
    }
}
