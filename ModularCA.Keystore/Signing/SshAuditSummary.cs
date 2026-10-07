using System.Globalization;
using System.Text;
using System.Text.Json;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// Writes what a <c>SignSsh</c> decision was asked to certify, for <see cref="SignerAuditEntity.Summary"/>:
/// the certificate's type, serial, key id, the number of principals and the validity window.
/// It is written from the request, before any check, so a refused call is summarised as an
/// allowed one is. Principals are counted and never named.
/// </summary>
/// <remarks>
/// The summary is one JSON object on one line, written by a JSON writer so that no text in it
/// can end a string or add a member. The type and the key id are the caller's text and are the
/// only parts whose length the caller controls: each is cut to a fixed number of characters, on
/// a character boundary, and <c>key_id_truncated</c> says when the key id was. Everything
/// outside printable ASCII is escaped, so the longest summary this writes is known:
/// <see cref="MaxLength"/>, which is within <see cref="SignerAuditEntity.SummaryMaxLength"/>.
/// The serial is written as a decimal string because it is 64 bits unsigned, which not every
/// JSON reader holds as a number.
/// </remarks>
internal static class SshAuditSummary
{
    /// <summary>The most characters of the key id the summary carries.</summary>
    public const int MaxKeyIdChars = 96;

    /// <summary>The most characters of the certificate type the summary carries; <c>user</c> and <c>host</c> are four.</summary>
    public const int MaxTypeChars = 16;

    /// <summary>
    /// The longest summary <see cref="Of"/> writes: every character of the type and the key id
    /// escaped to six, the longest serial, principal count and times, and the member names.
    /// </summary>
    public const int MaxLength = 6 * (MaxKeyIdChars + MaxTypeChars) + 20 + 10 + 20 + 20 + 128;

    /// <summary>The summary of <paramref name="request"/>.</summary>
    public static string Of(SshCertificateRequest request)
    {
        var keyId = request.KeyId ?? string.Empty;
        var shownKeyId = Cut(keyId, MaxKeyIdChars);

        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("type", Cut(request.CertType ?? string.Empty, MaxTypeChars));
            json.WriteString("serial", request.Serial.ToString(CultureInfo.InvariantCulture));
            json.WriteString("key_id", shownKeyId);
            if (shownKeyId.Length != keyId.Length)
                json.WriteBoolean("key_id_truncated", true);
            json.WriteNumber("principals", request.Principals?.Count ?? 0);
            json.WriteNumber("valid_after", request.ValidAfter);
            json.WriteNumber("valid_before", request.ValidBefore);
            json.WriteEndObject();
        }
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    /// <summary>
    /// At most <paramref name="maxChars"/> UTF-16 characters of <paramref name="text"/>, never
    /// half of a surrogate pair. An unpaired surrogate becomes U+FFFD, since it has no JSON form
    /// and no UTF-8 one either.
    /// </summary>
    internal static string Cut(string text, int maxChars)
    {
        var cut = new StringBuilder(Math.Min(text.Length, maxChars));
        foreach (var rune in text.EnumerateRunes())
        {
            if (cut.Length + rune.Utf16SequenceLength > maxChars)
                break;
            cut.Append(rune.ToString());
        }
        return cut.ToString();
    }
}
