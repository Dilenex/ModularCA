using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("SshCaKeys")]
public class SshCaKeyEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(20)]
    public string KeyType { get; set; } = "ed25519";

    /// <summary>
    /// Key size in bits. For RSA: 2048/3072/4096. For ECDSA: 256/384/521 (NIST curve size).
    /// Null for fixed-size algorithms like ed25519.
    /// </summary>
    public int? KeySize { get; set; }

    public string PublicKey { get; set; } = string.Empty;

    /// <summary>
    /// The path of the plaintext key file on the node, for a key whose <see cref="KeyStorage"/>
    /// is <see cref="SshCaKeyStorage.LegacyFile"/>. Null for a key the signer holds.
    /// </summary>
    [MaxLength(500)]
    public string? PrivateKeyPath { get; set; }

    /// <summary>
    /// Where the private key is: one of the <see cref="SshCaKeyStorage"/> values. A new row is
    /// <see cref="SshCaKeyStorage.Signer"/>; a row written with a key file is
    /// <see cref="SshCaKeyStorage.LegacyFile"/> until the key is imported into the signer.
    /// </summary>
    [Required]
    [MaxLength(20)]
    public string KeyStorage { get; set; } = SshCaKeyStorage.Signer;

    /// <summary>
    /// The CA entity this SSH CA key is linked to. Used for group-role authorization.
    /// The CA entity is auto-created during SSH key generation.
    /// </summary>
    [Required]
    public Guid CertificateAuthorityId { get; set; }

    [ForeignKey("CertificateAuthorityId")]
    public virtual CertificateAuthorityEntity CertificateAuthority { get; set; } = default!;

    public bool IsUserCa { get; set; } = true;
    public bool IsHostCa { get; set; } = false;
    public int MaxValidityHours { get; set; } = 24;
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>The values of <see cref="SshCaKeyEntity.KeyStorage"/>.</summary>
public static class SshCaKeyStorage
{
    /// <summary>A plaintext key file on the node, at <see cref="SshCaKeyEntity.PrivateKeyPath"/>, not yet imported into the signer.</summary>
    public const string LegacyFile = "LegacyFile";

    /// <summary>The signer holds the key in <c>ssh-ca.keystore</c>.</summary>
    public const string Signer = "Signer";

    /// <summary>The key is on a PKCS#11 token the signer opens.</summary>
    public const string Pkcs11 = "Pkcs11";
}
