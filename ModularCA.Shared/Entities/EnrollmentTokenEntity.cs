using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

[Table("EnrollmentTokens")]
public class EnrollmentTokenEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// SHA-256 hash of the enrollment token, uppercase hex — never the token itself.
    /// <para>
    /// The property keeps the name <c>Token</c> to match <c>RefreshTokenEntity.Token</c>, which
    /// stores a hash under the same name; the column is the lookup key, so
    /// <c>EnrollmentTokenService.HashEnrollmentToken</c> must be applied to any candidate value
    /// before it is compared against this. The plaintext exists exactly once, in the response to
    /// the call that created it, and is not recoverable from here afterwards.
    /// </para>
    /// <para>
    /// A fast digest rather than a password hash: lookup is by exact value against a unique
    /// index, and the input is 32 bytes of <c>RandomNumberGenerator</c> output rather than
    /// anything a person chose, so there is no dictionary to slow an attacker down with.
    /// </para>
    /// </summary>
    [Required]
    [MaxLength(128)]
    public string Token { get; set; } = string.Empty;

    public Guid CreatedByUserId { get; set; }

    [ForeignKey("CreatedByUserId")]
    public virtual UserEntity? CreatedByUser { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }

    public int MaxUses { get; set; } = 1;
    public int UsesRemaining { get; set; } = 1;

    [MaxLength(255)]
    public string? SubjectRestriction { get; set; }

    [MaxLength(500)]
    public string? SANRestriction { get; set; }

    [MaxLength(20)]
    public string? Protocol { get; set; }

    public bool IsRevoked { get; set; } = false;

    /// <summary>
    /// Pre-selected request profile for QR/link enrollment. Controls subject/SAN validation rules.
    /// </summary>
    public Guid? RequestProfileId { get; set; }

    /// <summary>
    /// Pre-selected certificate profile for QR/link enrollment. Determines cert type and extensions.
    /// </summary>
    public Guid? CertProfileId { get; set; }

    /// <summary>
    /// Pre-selected signing profile for QR/link enrollment. Determines which CA key signs the cert.
    /// </summary>
    public Guid? SigningProfileId { get; set; }

    /// <summary>
    /// The CA this token targets. Populated from the signing profile's
    /// issuer at generation time so the admin list endpoint can filter by tenant without
    /// relying on the stale "creator's group membership" heuristic. Null for system-wide
    /// tokens minted by a SystemOperator.
    /// </summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>
    /// The tenant this token is scoped to. Redundant with
    /// <see cref="CertificateAuthorityId"/> but cheaper to filter on at list time.
    /// </summary>
    public Guid? TenantId { get; set; }

    // ─── CMP-specific fields ─────────────────────────

    /// <summary>
    /// When true, this enrollment token also doubles as a CMP
    /// PBMAC shared-secret credential. The client's <c>senderKID</c> must equal
    /// <see cref="CmpReferenceValue"/> and their shared secret must hash to
    /// <see cref="CmpSecretHashBase64"/>.
    /// </summary>
    public bool UsedForCmp { get; set; } = false;

    /// <summary>
    /// The CMP <c>senderKID</c> / referenceValue the client will
    /// present. Stored in the clear because it is not a secret — only the identifier
    /// used to look up the matching secret hash.
    /// </summary>
    [MaxLength(255)]
    public string? CmpReferenceValue { get; set; }

    /// <summary>
    /// PBKDF2-SHA256 hash of the CMP shared secret, base64-encoded.
    /// Format: <c>pbkdf2-sha256$iter$saltBase64$hashBase64</c>. Never returned from
    /// admin GET endpoints — only the presence of <see cref="UsedForCmp"/> is surfaced.
    /// </summary>
    [MaxLength(512)]
    public string? CmpSecretHashBase64 { get; set; }

    /// <summary>
    /// The CMP PBMAC shared secret, wrapped by the signer, for CMP rows only; null for every
    /// bearer enrollment token. Base64 of the blob <c>WrappedSecretEnvelope</c> describes.
    /// <para>
    /// PBMAC is a symmetric MAC: to verify a client's protection the CA has to recompute it,
    /// which means recovering the secret itself. A hash cannot do that, so this one credential
    /// genuinely cannot be stored the way <see cref="Token"/> is. What it can be is kept under a
    /// key the node does not hold: the signer wraps it under a key derived from the keystore, so
    /// a stolen database and a stolen node together still do not yield it. Recovering it costs a
    /// call to the signer, which CMP was already making to sign its response.
    /// </para>
    /// <para>
    /// <see cref="CmpSecretHashBase64"/> is unrelated and stays: it serves the
    /// caller-presents-the-secret path, which can verify against a hash.
    /// </para>
    /// </summary>
    [MaxLength(1024)]
    public string? CmpSecretWrapped { get; set; }

    /// <summary>
    /// The last four characters of the CMP shared secret, in the clear, so the console can still
    /// tell two credentials apart in a list. It used to be taken from the secret column, which is
    /// now ciphertext and would cost an unwrap per row to read. Four characters of a
    /// forty-three-character random secret is what that screen already showed.
    /// </summary>
    [MaxLength(8)]
    public string? CmpSecretLastFour { get; set; }
}
