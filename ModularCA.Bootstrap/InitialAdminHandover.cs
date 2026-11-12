namespace ModularCA.Bootstrap;

/// <summary>
/// How a headless bootstrap handed over the first administrator, so its closing banner can say
/// what to do next without repeating any secret: claim the account with the token whose hash
/// bootstrap.yaml gave, or read the generated password from its owner-only file.
/// </summary>
/// <param name="Username">The first administrator's username.</param>
/// <param name="ClaimExpiresAt">When the claim expires (UTC); null when a password file was written instead.</param>
/// <param name="PasswordFile">The path of the file holding the generated password; null for a claim.</param>
public sealed record InitialAdminHandover(string Username, DateTime? ClaimExpiresAt, string? PasswordFile)
{
    /// <summary>The first administrator's id, for the audit record of its claim; empty when the caller did not give one.</summary>
    public Guid UserId { get; init; }

    /// <summary>A handover by claim token, expiring at <paramref name="expiresAt"/>.</summary>
    /// <param name="username">The first administrator's username.</param>
    /// <param name="expiresAt">When the claim expires (UTC).</param>
    public static InitialAdminHandover ByClaim(string username, DateTime expiresAt) => new(username, expiresAt, null);

    /// <summary>A handover by a generated password left in <paramref name="path"/>.</summary>
    /// <param name="username">The first administrator's username.</param>
    /// <param name="path">The password file's path.</param>
    public static InitialAdminHandover ByPasswordFile(string username, string path) => new(username, null, path);

    /// <summary>
    /// The closing banner's lines: what the operator does next to get in. Never contains a password
    /// or token.
    /// </summary>
    public IReadOnlyList<string> BannerLines() => ClaimExpiresAt is DateTime expires
        ? [
            $"IMPORTANT: '{Username}' HAS NO PASSWORD AND IS WAITING TO BE CLAIMED.",
            "Open the console's sign-in page, choose \"Have a claim token?\" (/claim), and set the",
            "password with the claim token whose hash bootstrap.yaml gives.",
            $"The claim expires {expires:yyyy-MM-dd HH:mm} UTC. After that, issue a new one on this host:",
            $"  ModularCA.API --issue-claim-token {Username}",
        ]
        : [
            $"IMPORTANT: THE INITIAL PASSWORD OF '{Username}' IS IN {PasswordFile}",
            "It is readable by this account only and is not printed anywhere. Read it, sign in,",
            "and change the password when asked; the file is deleted when you do. If it is",
            "still there afterwards, delete it.",
        ];
}
