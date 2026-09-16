namespace ModularCA.Auth.Interfaces;

/// <summary>
/// The access badge a token is minted for: its id and name become the <c>badge</c> and
/// <c>badgen</c> claims, which the authorization resolver and the audit trail read back.
/// </summary>
public sealed record AccessBadgeClaim(Guid Id, string Name);
