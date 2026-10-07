using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// The record that an SSH CA key was a plaintext file on the node and has been imported into
/// the signer: one row per key, written in the same transaction that sets its
/// <see cref="SshCaKeyEntity.KeyStorage"/> to <see cref="SshCaKeyStorage.Signer"/> and clears
/// its <see cref="SshCaKeyEntity.PrivateKeyPath"/>.
/// </summary>
/// <remarks>
/// It serves two purposes. It is what the notice about plaintext storage before the upgrade is
/// read from, and it survives audit retention and a wiped audit database. And it keeps the path
/// the key row no longer has, so a start that follows a stop between that transaction and the
/// removal of the file still finds the file and removes it: <see cref="FileRemovedAt"/> is null
/// until then. It has no foreign key, so it outlives the key row.
/// </remarks>
[Table("SshKeyImports")]
public class SshKeyImportEntity
{
    /// <summary>The <c>SshCaKeys</c> row the key belongs to.</summary>
    [Key]
    public Guid SshCaKeyId { get; set; }

    /// <summary>The name of the SSH CA key when it was imported.</summary>
    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>The SHA-256 fingerprint of the public key, as OpenSSH prints it.</summary>
    [Required]
    [MaxLength(100)]
    public string Fingerprint { get; set; } = string.Empty;

    /// <summary>The full path of the private key file that was read, on the host that imported it.</summary>
    [Required]
    [MaxLength(1024)]
    public string FilePath { get; set; } = string.Empty;

    /// <summary>When the row was switched to the signer.</summary>
    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the private key file and its <c>.pub</c> were overwritten and deleted, or found
    /// already gone. Null while the file may still be on disk.
    /// </summary>
    public DateTime? FileRemovedAt { get; set; }

    /// <summary>When the audit entry of the import was written. Null until it has been.</summary>
    public DateTime? AuditedAt { get; set; }
}
