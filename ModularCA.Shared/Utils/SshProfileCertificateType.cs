using ModularCA.Shared.Signing;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The certificate type of an SSH request profile or SSH certificate profile: <c>user</c>,
/// <c>host</c>, or none, which is stored as null and means the profile serves either. A profile
/// whose type is set is refused for a certificate of the other type; one with no type works as
/// every profile did before the column existed.
/// </summary>
public static class SshProfileCertificateType
{
    /// <summary>A profile for user certificates.</summary>
    public const string User = SshCertificateRequest.UserType;

    /// <summary>A profile for host certificates.</summary>
    public const string Host = SshCertificateRequest.HostType;

    /// <summary>What a request sends to say a profile serves either type. It is stored as null.</summary>
    public const string Either = "either";

    /// <summary>
    /// Null when <paramref name="sent"/> can be the <c>certificateType</c> of a profile request
    /// (<c>user</c>, <c>host</c>, <c>either</c>, or nothing), otherwise the message for a 400.
    /// </summary>
    /// <param name="sent">The field as sent in the request body.</param>
    public static string? Error(string? sent)
        => sent is null or User or Host or Either
            ? null
            : "certificateType must be \"user\", \"host\" or \"either\".";

    /// <summary>The value to store for a valid <paramref name="sent"/> value: <c>user</c>, <c>host</c>, or null for either.</summary>
    /// <param name="sent">A value <see cref="Error"/> accepts.</param>
    public static string? Stored(string? sent) => sent is User or Host ? sent : null;

    /// <summary>Whether a profile of type <paramref name="profileType"/> may be used for a certificate of <paramref name="certificateType"/>.</summary>
    /// <param name="profileType">The profile's stored type; null serves either.</param>
    /// <param name="certificateType"><see cref="User"/> or <see cref="Host"/>.</param>
    public static bool Allows(string? profileType, string certificateType)
        => string.IsNullOrEmpty(profileType) || string.Equals(profileType, certificateType, StringComparison.Ordinal);

    /// <summary>
    /// Null when the profile may be used for a certificate of <paramref name="certificateType"/>,
    /// otherwise the sentence a sign route answers with 400.
    /// </summary>
    /// <param name="profileKind">What the profile is, as the sentence names it: <c>request profile</c> or <c>certificate profile</c>.</param>
    /// <param name="profileName">The profile's name.</param>
    /// <param name="profileType">The profile's stored type; null serves either.</param>
    /// <param name="certificateType"><see cref="User"/> or <see cref="Host"/>.</param>
    public static string? Refusal(string profileKind, string profileName, string? profileType, string certificateType)
        => Allows(profileType, certificateType)
            ? null
            : $"SSH {profileKind} '{profileName}' is for {profileType} certificates and cannot be used for a {certificateType} certificate.";
}
