using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One decision the signer took about a private key: what was asked, by whom, under which
/// context, and whether policy allowed it. The signer writes a row for every decision, allowed
/// or refused, before it answers, so this table is the record of what was signed even when the
/// node's own audit is lost. It carries no foreign keys on purpose: a row must outlive the CA,
/// the certificate and the space it names.
/// </summary>
[Table("SignerAudit")]
public class SignerAuditEntity
{
    /// <summary>Row id.</summary>
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>When the decision was taken, UTC.</summary>
    public DateTime At { get; set; }

    /// <summary>The contract operation: <c>Sign</c>, <c>Decrypt</c>, <c>Export</c>, <c>Generate</c> and so on.</summary>
    [MaxLength(32)]
    public string Operation { get; set; } = string.Empty;

    /// <summary>The caller's identity as the context named it.</summary>
    [MaxLength(128)]
    public string Caller { get; set; } = string.Empty;

    /// <summary>The purpose the context named, as the enum member's name.</summary>
    [MaxLength(32)]
    public string Purpose { get; set; } = string.Empty;

    /// <summary>The certificate id of the key the operation named, when it named one.</summary>
    public Guid? KeyCertificateId { get; set; }

    /// <summary>The keystore name of the key reference, when the operation named one.</summary>
    [MaxLength(64)]
    public string? Keystore { get; set; }

    /// <summary>The CA the context said the operation was for.</summary>
    public Guid? CaId { get; set; }

    /// <summary>The space the context said the operation was for.</summary>
    public Guid? SpaceId { get; set; }

    /// <summary>
    /// The scope the context stated, which <see cref="SpaceId"/> alone cannot tell apart when it
    /// is null: <see cref="InstanceScope"/>, <see cref="SpaceScope"/> (<see cref="TenantScope"/>
    /// on rows written before 0.4.0; read both with <see cref="IsSpaceScope"/>) or
    /// <see cref="NoScope"/>. Null on rows written before the column existed.
    /// </summary>
    [MaxLength(16)]
    public string? EffectiveScope { get; set; }

    /// <summary>
    /// The <c>KeyCeremonies</c> row the context named, when it named one, whether or not the
    /// signer could verify it: a refusal of an unverifiable ceremony records the id it was told.
    /// </summary>
    public Guid? CeremonyId { get; set; }

    /// <summary>
    /// Who was on the other end of the wire when the signer runs as a role: the SPKI pin of the
    /// client certificate the connection presented, as the signer computed it, so the row names
    /// the peer the signer admitted and not what the peer said about itself. Null when the
    /// signer runs in process, where there is no peer.
    /// </summary>
    [MaxLength(256)]
    public string? PeerIdentity { get; set; }

    /// <summary>The signature algorithm, for a signature.</summary>
    [MaxLength(64)]
    public string? Algorithm { get; set; }

    /// <summary><see cref="AllowedOutcome"/> or <see cref="RefusedOutcome"/>.</summary>
    [MaxLength(16)]
    public string Outcome { get; set; } = string.Empty;

    /// <summary>Why the operation was refused; null when it was allowed.</summary>
    [MaxLength(1024)]
    public string? Reason { get; set; }

    /// <summary>SHA-256 over the bytes that were signed, lower-case hex; null for an operation that signs nothing.</summary>
    [MaxLength(64)]
    public string? DataHash { get; set; }

    /// <summary>
    /// What kind of secret a <c>WrapSecret</c> or <c>UnwrapSecret</c> decision was about, as the
    /// <c>SecretKind</c> member's name, including for a refusal: the row says which separation
    /// the policy was applying. Null for every operation that is about a key rather than a
    /// secret.
    /// </summary>
    [MaxLength(32)]
    public string? SecretKind { get; set; }

    /// <summary>
    /// The id of the key that wrapped, or was asked to unwrap, a secret: SHA-256 over the DER
    /// SubjectPublicKeyInfo of the keystore key the wrapping key was derived from, lower-case
    /// hex, as the blob's own header names it. This is what makes a rotation legible after the
    /// fact: the rows say which key was still in use, and for what. Null for every operation
    /// that is about a key rather than a secret.
    /// </summary>
    [MaxLength(64)]
    public string? WrappingKeyId { get; set; }

    /// <summary>
    /// What a <c>SignSsh</c> decision was asked to certify, allowed or refused: one JSON object
    /// with the certificate's <c>type</c>, <c>serial</c> (a decimal string, since it is 64 bits
    /// unsigned), <c>key_id</c>, the number of <c>principals</c>, and <c>valid_after</c> and
    /// <c>valid_before</c> in Unix seconds. Principals are counted and never named, so this
    /// table does not become a directory of user names. The key id and the type are the caller's
    /// text: they are cut to a fixed length (<c>key_id_truncated</c> says when) and escaped to
    /// ASCII, so neither can alter the object or outgrow the column. Null for every other
    /// operation and on rows written before the column existed.
    /// </summary>
    [MaxLength(SummaryMaxLength)]
    public string? Summary { get; set; }

    /// <summary>The length of <see cref="Summary"/>.</summary>
    public const int SummaryMaxLength = 1024;

    /// <summary>The policy allowed the operation.</summary>
    public const string AllowedOutcome = "allowed";

    /// <summary>The policy refused the operation.</summary>
    public const string RefusedOutcome = "refused";

    /// <summary>The context stated the instance as its scope.</summary>
    public const string InstanceScope = "instance";

    /// <summary>The context stated a space as its scope. Written from 0.4.0.</summary>
    public const string SpaceScope = "space";

    /// <summary>The context stated a space as its scope: the token rows written before 0.4.0 hold. Never written now.</summary>
    public const string TenantScope = "tenant";

    /// <summary>Whether <paramref name="effectiveScope"/> states a space: <see cref="SpaceScope"/> or the legacy <see cref="TenantScope"/>.</summary>
    public static bool IsSpaceScope(string? effectiveScope)
        => effectiveScope is SpaceScope or TenantScope;

    /// <summary>The context stated no scope.</summary>
    public const string NoScope = "none";
}
