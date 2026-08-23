using System.Text.Json.Serialization;

namespace ModularCA.Shared.Models.Acme;

public class AcmeErrorResponse
{
    public string Type { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public int Status { get; set; }
    // Omitted when null rather than emitted as JSON null. RFC 8555 marks these optional,
    // and clients treat optional as "may be absent" — certbot crashed outright on a
    // present-but-null directory `meta`. Same shape, same guard.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<AcmeErrorResponse>? Subproblems { get; set; }
    // Omitted when null rather than emitted as JSON null. RFC 8555 marks these optional,
    // and clients treat optional as "may be absent" — certbot crashed outright on a
    // present-but-null directory `meta`. Same shape, same guard.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeIdentifier? Identifier { get; set; }
}
