using System.Text.Json;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Central <see cref="JsonSerializerOptions"/> instance used for deserializing
    /// JSON blobs stored on CSR and profile entities. Sets a conservative
    /// <c>MaxDepth</c> cap to block denial-of-service amplification via deeply
    /// nested payloads.
    /// </summary>
    public static class SafeJsonOptions
    {
        /// <summary>
        /// Shared read-only options with <c>MaxDepth = 16</c> and a small default
        /// buffer. Safe to pass to <see cref="JsonSerializer.Deserialize{T}(string, JsonSerializerOptions?)"/>
        /// from any caller.
        /// </summary>
        public static readonly JsonSerializerOptions Default = new()
        {
            MaxDepth = 16,
            DefaultBufferSize = 4096
        };

        /// <summary>
        /// Options for JSON blobs that are STORED in a column and later handed to the browser
        /// verbatim inside an API response (<c>ApprovalsJson</c>, <c>ParametersJson</c>).
        /// <para>
        /// These blobs used to be written with a bare <c>JsonSerializer.Serialize</c>, which applies
        /// no naming policy — so a PascalCase object ended up nested inside a camelCase envelope.
        /// The frontend, reasonably expecting camelCase throughout, read <c>entry.userName</c> from
        /// a record whose key was <c>Username</c> and rendered every ceremony approver as "-".
        /// Writing them camelCase makes the inner and outer casing agree.
        /// </para>
        /// <para>
        /// <see cref="JsonSerializerOptions.PropertyNameCaseInsensitive"/> is essential, not
        /// incidental: rows written before this change hold PascalCase keys, and the default
        /// deserializer is case-SENSITIVE. Without it, switching the write side would have made
        /// every pre-existing blob unreadable — a far worse bug than the one being fixed.
        /// </para>
        /// </summary>
        public static readonly JsonSerializerOptions Stored = new()
        {
            MaxDepth = 16,
            DefaultBufferSize = 4096,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }
}
