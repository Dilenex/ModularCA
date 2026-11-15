using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// The rules a local account's password must meet when it is set or changed. One row. A password
/// already stored is never re-checked at sign-in, so a stricter policy does not lock anyone out.
/// <para>
/// The defaults are the NIST SP 800-63B preset
/// (<see cref="ModularCA.Shared.Utils.PasswordPolicyPresets.ApplyNist80063B"/>), and they are what a
/// new install is seeded with: length alone, no composition rules, no periodic expiry, and the
/// bundled blocklist on. An install made before 0.4.5 keeps the row it has (12 characters, all four
/// character classes, 90 days); the <c>TighterDefaults</c> migration writes that row when an
/// installed instance somehow has none, so these defaults never reach an existing install.
/// </para>
/// </summary>
[Table("PasswordPolicy")]
public class PasswordPolicyEntity
{
    /// <summary>The row's key.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Shortest password accepted, in characters. Default 15 (SP 800-63B for a password used alone).</summary>
    public int MinLength { get; set; } = 15;

    /// <summary>Longest password accepted, in characters; 0 means no maximum. Default 128.</summary>
    public int MaxLength { get; set; } = 128;

    /// <summary>Whether a password needs at least one upper-case letter. Default false.</summary>
    public bool RequireUppercase { get; set; } = false;

    /// <summary>Whether a password needs at least one lower-case letter. Default false.</summary>
    public bool RequireLowercase { get; set; } = false;

    /// <summary>Whether a password needs at least one digit. Default false.</summary>
    public bool RequireDigit { get; set; } = false;

    /// <summary>Whether a password needs at least one character that is neither a letter nor a digit. Default false.</summary>
    public bool RequireSymbol { get; set; } = false;

    /// <summary>Least number of upper-case letters; 0 sets no count.</summary>
    public int MinUppercase { get; set; } = 0;

    /// <summary>Least number of lower-case letters; 0 sets no count.</summary>
    public int MinLowercase { get; set; } = 0;

    /// <summary>Least number of digits; 0 sets no count.</summary>
    public int MinDigits { get; set; } = 0;

    /// <summary>Least number of characters that are neither letters nor digits; 0 sets no count.</summary>
    public int MinSpecial { get; set; } = 0;

    /// <summary>
    /// Days after a password change before the password expires. 0 means passwords never expire,
    /// which is the default: while it is 0 no account is treated as expired, whatever expiry date
    /// an earlier policy stamped on it (<see cref="ModularCA.Shared.Utils.PasswordExpiry"/>).
    /// </summary>
    public int MaxAgeDays { get; set; } = 0;

    /// <summary>How many prior passwords a new one may not repeat; 0 keeps no history.</summary>
    public int HistoryCount { get; set; } = 0;

    /// <summary>
    /// Whether a new password is checked against the blocklist shipped with the product
    /// (<c>password-blocklist/bundled-blocklist.txt</c> beside the binaries). Default true. The
    /// administrator's own list (<see cref="DictionaryPath"/>) is checked as well when set: it
    /// adds to the bundled list and does not replace it.
    /// </summary>
    public bool UseBundledBlocklist { get; set; } = true;

    /// <summary>
    /// The administrator's own blocklist: the full path of a file in
    /// <c>config/password-dictionaries</c>, or null for none. Checked whenever it is set, whether
    /// or not <see cref="UseBundledBlocklist"/> is on.
    /// </summary>
    [MaxLength(500)]
    public string? DictionaryPath { get; set; }

    /// <summary>Whether <see cref="DictionaryPath"/> lists hex SHA-256 hashes of passwords rather than the passwords themselves.</summary>
    public bool DictionaryIsHashed { get; set; } = false;

    /// <summary>When the row was last written.</summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
