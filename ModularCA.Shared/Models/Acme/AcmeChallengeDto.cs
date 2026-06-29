using System.Text.Json.Serialization;

namespace ModularCA.Shared.Models.Acme;

public class AcmeChallengeDto
{
    public Guid Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime? ValidatedAt { get; set; }

    /// <summary>
    /// RFC 8555 §8: when a challenge fails, the challenge object SHOULD carry an
    /// <c>error</c> field holding the RFC 7807 problem document describing why
    /// validation failed. Without it, clients (e.g. acme.sh) report an empty
    /// "Verification error:" because they have no detail to display. Omitted from
    /// the wire when null so pending/valid challenges don't emit a null member.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeErrorResponse? Error { get; set; }
}
