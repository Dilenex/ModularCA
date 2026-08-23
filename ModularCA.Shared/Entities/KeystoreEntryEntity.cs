using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Keystore metadata row stored in the app database. Tracks the password blob, scrypt
/// parameters, and the SHA-256 SPKI fingerprint of the CA certificate
/// expected to have signed the keystore file so <see cref="ModularCA.Keystore.Services.KeystoreService"/>
/// can reject tamper-resigning by any other CA in the database.
/// </summary>
[Table("Keystores")]
public class KeystoreEntryEntity
{
    public int Id { get; set; }
    public string Name { get; set; } = default!;

    // A `PassHash` column used to sit here: an unsalted, single-round SHA-256 of the keystore
    // master passphrase. Nothing ever read it. It was a standing offline-cracking target on the
    // one secret that unwraps every CA private key, bought nothing, and is removed by the
    // DropKeystorePassHash migration.

    [Required]
    public byte[] Passblob { get; set; } = Array.Empty<byte>();
    public int ScryptN { get; set; }
    public int ScryptR { get; set; }
    public int ScryptP { get; set; }
    public string Salt { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool Enabled { get; set; }

    /// <summary>
    /// SHA-256 fingerprint of the SubjectPublicKeyInfo DER of the keystore-signing
    /// CA. Populated by the bootstrap flow once the System Signing CA is issued. When present,
    /// <see cref="ModularCA.Keystore.Services.KeystoreService"/> requires every file-level
    /// signature to validate against exactly this cert, not any CA in the database.
    /// Stored as lowercase hex (64 chars) for easy diffing. Null on legacy rows.
    /// </summary>
    [MaxLength(64)]
    public string? SigningCaSpkiSha256 { get; set; }

    /// <summary>
    /// HMAC-SHA256 over <see cref="SigningCaSpkiSha256"/>, keyed by a value derived from the
    /// keystore's secondary passphrase (which lives outside the database). Closes the attack
    /// where DB-write access alone could swap the pin for an attacker-controlled CA's
    /// fingerprint: forging a matching MAC requires the secondary passphrase too, which the
    /// DB does not have.
    /// Null on legacy rows; verification treats null as "unprotected, warn loudly" so existing
    /// installs keep working. On the next keystore rewrite the MAC is populated automatically.
    /// </summary>
    public byte[]? SigningCaSpkiSha256Mac { get; set; }
}
