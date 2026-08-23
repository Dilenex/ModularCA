using System.Text.Json.Serialization;
using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Models.Acme;

/// <summary>
/// ACME directory response containing all endpoint URLs per RFC 8555 section 7.1.1.
/// </summary>
public class AcmeDirectoryResponse
{
    public string NewNonce { get; set; } = string.Empty;
    public string NewAccount { get; set; } = string.Empty;
    public string NewOrder { get; set; } = string.Empty;
    public string RevokeCert { get; set; } = string.Empty;
    public string KeyChange { get; set; } = string.Empty;

    /// <summary>
    /// Optional metadata about the ACME server, including whether external account binding is
    /// required.
    /// </summary>
    /// <remarks>
    /// OMITTED when null rather than serialized as <c>"meta": null</c>. RFC 8555 §7.1.1 makes the
    /// field optional, and clients read "optional" as "may be absent" — not "may be null".
    /// certbot does <c>jobj.pop('meta', {})</c>, which returns the default only when the KEY is
    /// missing; a present-but-null value yields None and the next line crashes with
    /// <c>TypeError: argument of type 'NoneType' is not iterable</c>, before it can even register
    /// an account. Every certbot run against this server failed that way.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AcmeDirectoryMeta? Meta { get; set; }
}

/// <summary>
/// Metadata object for the ACME directory response per RFC 8555 section 7.1.1.
/// </summary>
public class AcmeDirectoryMeta
{
    /// <summary>
    /// Absolute URL of the terms of service a client must accept before registering an account.
    /// </summary>
    /// <remarks>
    /// Load-bearing, not decorative: RFC 8555 §7.3.3 ties the requirement to the advertisement.
    /// A server may only reject a <c>new-account</c> whose <c>termsOfServiceAgreed</c> is absent
    /// if it publishes this URL, because conforming clients set that flag only when they have
    /// terms in hand. Publishing nothing while demanding agreement is unsatisfiable.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TermsOfService { get; set; }

    /// <summary>
    /// Indicates that the server requires external account binding for new account registrations.
    /// </summary>
    /// <remarks>
    /// Also omitted when null, for the same reason as <see cref="AcmeDirectoryResponse.Meta"/>:
    /// once a meta object IS emitted, a null member inside it is the same hazard one level down.
    /// </remarks>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ExternalAccountRequired { get; set; }

    /// <summary>
    /// Builds the meta object for the given ACME config, or returns <c>null</c> when there is
    /// nothing to advertise so the caller omits the field entirely.
    /// </summary>
    /// <remarks>
    /// Lives beside the DTO rather than in the controller so the advertisement is derived from
    /// the same <see cref="AcmeConfig.PublishedTermsOfServiceUrl"/> the <c>new-account</c>
    /// agreement check reads, and so both can be pinned by a unit test.
    /// </remarks>
    public static AcmeDirectoryMeta? For(AcmeConfig acme)
    {
        var meta = new AcmeDirectoryMeta
        {
            TermsOfService = acme.PublishedTermsOfServiceUrl,
            ExternalAccountRequired = acme.ExternalAccountRequired ? true : null,
        };

        return meta.TermsOfService == null && meta.ExternalAccountRequired == null ? null : meta;
    }
}
