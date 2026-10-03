using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModularCA.API.Json;

/// <summary>
/// The converters the API adds to the MVC JSON options, in one place so the tests bind request
/// bodies exactly as the host does.
/// </summary>
public static class ApiJsonOptions
{
    /// <summary>
    /// Adds the API's converters to <paramref name="options"/>: enums as their string names, so
    /// request-body enums bind from names (e.g. "Superseded") rather than integer codes, and every
    /// DateTime as ISO-8601 UTC with a trailing 'Z' (see <see cref="UtcDateTimeJsonConverter"/>).
    /// </summary>
    public static void Apply(JsonSerializerOptions options)
    {
        options.Converters.Add(new JsonStringEnumConverter());
        options.Converters.Add(new UtcDateTimeJsonConverter());
    }
}
