using System.Security.Cryptography;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The one thing an SSH CA key signs: an OpenSSH certificate the signer builds itself from the
/// fields of an <see cref="SshCertificateRequest"/>. No bytes are taken to be signed, so a key in
/// <see cref="KeyRef.SshKeystore"/> cannot be made to sign an <c>SSHSIG</c> blob, an
/// authentication challenge or anything else that is not a certificate within its own limits.
/// </summary>
/// <remarks>
/// <para>
/// A call is judged in this order, and the first failure is the refusal: the lock state, the
/// purpose, the keystore the reference names and the scope the context states
/// (<see cref="JudgeSshCertificateContext"/>); that a key is bound to the row; the row and its
/// CA, read from the database for this call (<see cref="JudgeSshUse"/>); the key's backend; the
/// shape of the request (<see cref="ReadSshCertificateFields"/>); and then the certificate's
/// own rules, which are <see cref="SshCertificateRules"/> as <see cref="SshCertificateIssuer"/>
/// applies them, under the limits of the row (<see cref="SshLimitsOf"/>) and the signer's clock.
/// </para>
/// <para>
/// The issuer makes the nonce, writes the bound key's public half as the signature key, derives
/// the signature algorithm from it, and hands back a certificate only when the signature
/// verifies under that public key. Every call writes one audit row, allowed or refused, with a
/// summary of what was asked (<see cref="SshAuditSummary"/>); an allowed row carries the SHA-256
/// of the certificate, so it can be matched to the certificate the node stored.
/// </para>
/// </remarks>
public sealed partial class InProcessSigningService
{
    /// <summary>The audit operation of <see cref="SignSshCertificateAsync"/>.</summary>
    private const string SignSshOperation = "SignSsh";

    /// <summary>
    /// How far a certificate's <c>valid_after</c> may sit from this signer's clock: ten minutes
    /// before it, five minutes after. <b>This is an open owner decision</b>, question 1 of
    /// <c>docs/architecture/ssh-keystore.md</c>: whether the node backdates <c>valid_after</c>
    /// for clock skew, and by how much, is not settled, and this value changes with the answer.
    /// It is wider in the past than the five minutes the design first gave so that a node that
    /// backdates by five minutes and runs up to five minutes behind the signer is still served;
    /// it is not wider in the future, since nothing asks for a certificate that is not valid yet.
    /// </summary>
    private static readonly SshClockSkew SshValidAfterAllowance = new(Past: TimeSpan.FromMinutes(10), Future: TimeSpan.FromMinutes(5));

    /// <inheritdoc />
    /// <remarks>
    /// The order of the checks, and where each lives, is in the remarks of
    /// <c>InProcessSigningService.SshCertificates.cs</c>. The audit row is written before the
    /// certificate is returned, so a signer that fails closed on its audit hands out no
    /// certificate it could not record. <see cref="_sshKeyWrites"/> is not taken: signing writes
    /// nothing, and a row never changes key, so a commit or an import running beside it cannot
    /// change the key this call resolved.
    /// </remarks>
    public async Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var key = request.Key ?? throw new ArgumentException("The request names no key.", nameof(request));

        var summary = SshAuditSummary.Of(request);
        var refusal = JudgeSshCertificateContext(key, context);

        SshKeyBinding? binding = null;
        if (refusal == null && (binding = _keystore.GetSshKey(key.CertificateId)) == null)
            refusal = new SigningRefusedException(SigningRefusalReason.UnknownKey,
                $"The signer holds no SSH CA key for SSH CA key row {key.CertificateId}.");

        SshRow? row = null;
        if (refusal == null)
        {
            row = await ReadSshRowAsync(key.CertificateId, cancellationToken);
            refusal = JudgeSshUse(row, binding!.PublicKey, context, key);
        }
        if (refusal == null && binding!.Handle is not SoftwarePrivateKeyHandle)
            refusal = new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"The SSH CA key {key} is held by a backend that signs no SSH certificates yet; only a software key in {KeyRef.SshKeystore} does.");

        SshCertificateFields? fields = null;
        if (refusal == null)
            (fields, refusal) = ReadSshCertificateFields(request);

        SshCertificate? certificate = null;
        if (refusal == null)
        {
            try
            {
                certificate = await SshCertificateIssuer.IssueAsync(
                    fields!,
                    new SshHandleSigner(binding!.PublicKey, (SoftwarePrivateKeyHandle)binding.Handle),
                    SshLimitsOf(row!),
                    DateTimeOffset.UtcNow,
                    SshValidAfterAllowance,
                    cancellationToken);
            }
            catch (SshCertificateRefusedException ex)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.UntypedData,
                    $"The SSH CA key {key} does not sign this certificate: {Echoed(ex.Message)}");
            }
            catch (SshSigningFailedException ex)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.IntegrityFailure,
                    $"No certificate was issued with the SSH CA key {key}: {Echoed(ex.Message)}");
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                refusal = new SigningRefusedException(SigningRefusalReason.UntypedData,
                    $"The fields offered cannot be encoded as an SSH certificate: {Echoed(ex.Message)}");
            }
        }

        if (refusal != null)
        {
            await RecordAsync(SignSshOperation, context, key, null, allowed: false, refusal.Message, null, cancellationToken, summary: summary);
            throw refusal;
        }

        var blob = certificate!.Blob;
        await RecordAsync(SignSshOperation, context, key,
            SignatureAlgorithm.FromName(SshSignatureAlgorithms.SignerAlgorithmName(certificate.SignatureAlgorithm)),
            allowed: true, reason: null, SHA256.HashData(blob), cancellationToken, summary: summary);
        return blob;
    }

    /// <summary>
    /// What is judged before any key or row is looked at: the signer is unlocked; the purpose is
    /// <see cref="SigningPurpose.SshCertificate"/> and no other, so no purpose that signs X.509
    /// structures or manages keys reaches this call; the reference names
    /// <see cref="KeyRef.SshKeystore"/>, since a key is an SSH CA key because it is in that
    /// keystore and no other key signs an SSH certificate; and the context states the instance
    /// as its scope (<see cref="JudgeSshScope"/>).
    /// </summary>
    private SigningRefusedException? JudgeSshCertificateContext(KeyRef key, SigningContext context)
    {
        if (!_unlocked)
            return new SigningRefusedException(SigningRefusalReason.SignerLocked, "The signer has not unlocked its keystore.");
        if (context.Purpose != SigningPurpose.SshCertificate)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"An SSH certificate is signed only under an {SigningPurpose.SshCertificate} context, not {context.Purpose}.");
        if (!IsSshRef(key))
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"The key {key} is not an SSH CA key; an SSH certificate is signed only with a key in {KeyRef.SshKeystore}.");
        return JudgeSshScope(context);
    }

    /// <summary>
    /// Whether the row a key is bound to still licenses it to sign, judged on the row as it is
    /// now. <see cref="JudgeSshRow"/> is the same question at the moment a key is bound; this is
    /// the one asked at every use, with one rule to a line so that each stands on its own.
    /// </summary>
    /// <remarks>
    /// The row must exist and still carry <paramref name="boundKey"/>, compared as OpenSSH
    /// encodes it: a row re-pointed at another public key after the key was bound gets no
    /// signature from the key the signer holds for it. Its storage must be
    /// <see cref="SshCaKeyStorage.Signer"/>: a <see cref="SshCaKeyStorage.LegacyFile"/> row is
    /// one whose migration has not finished, and the file is still its key of record. Its CA
    /// must exist, be an SSH CA and have no space; the row and the CA must be enabled and the CA
    /// not deleted; and the context must name that CA.
    /// </remarks>
    private static SigningRefusedException? JudgeSshUse(SshRow? row, SshPublicKey boundKey, SigningContext context, KeyRef key)
    {
        if (row == null)
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"No SSH CA key row {key.CertificateId} exists; the key the signer holds for it signs nothing.");
        if (row.PublicKey == null)
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"SSH CA key row {row.Id} does not carry a public key the signer can read; the key the signer holds for it signs nothing.");
        if (!row.PublicKey.Equals(boundKey))
            return new SigningRefusedException(SigningRefusalReason.CertificateMismatch,
                $"SSH CA key row {row.Id} no longer carries the public key of the key the signer holds for it ({boundKey.Fingerprint}); that key signs nothing for the row.");
        if (!string.Equals(row.KeyStorage, SshCaKeyStorage.Signer, StringComparison.Ordinal))
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                row.KeyStorage == SshCaKeyStorage.LegacyFile
                    ? $"SSH CA key row {row.Id} is awaiting import into the signer: its storage is still '{row.KeyStorage}', so the signer does not sign for it."
                    : $"SSH CA key row {row.Id} has storage '{row.KeyStorage}'; the signer signs only for a row whose storage is '{SshCaKeyStorage.Signer}'.");
        if (!row.CaExists || !row.CaIsSshCa)
            return new SigningRefusedException(SigningRefusalReason.PurposeNotPermitted,
                $"CA {row.CaId} is not an SSH CA; no SSH certificate is signed for it.");
        if (row.CaSpaceId != null)
            return new SigningRefusedException(SigningRefusalReason.TenantMismatch,
                $"CA {row.CaId} belongs to space {row.CaSpaceId}; SSH CAs are instance CAs.");
        if (!row.IsEnabled)
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"SSH CA key row {row.Id} is disabled; its key signs nothing.");
        if (!row.CaIsEnabled)
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"SSH CA {row.CaId} is disabled; its key signs nothing.");
        if (row.CaIsDeleted)
            return new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
                $"SSH CA {row.CaId} is deleted; its key signs nothing.");
        if (context.CaId == null)
            return new SigningRefusedException(SigningRefusalReason.ContextRequired,
                $"Signing with the SSH CA key {key} requires the context to name the SSH CA it belongs to.");
        if (context.CaId != row.CaId)
            return new SigningRefusedException(SigningRefusalReason.CaMismatch,
                $"The SSH CA key {key} belongs to CA {row.CaId}, not CA {context.CaId}.");
        return null;
    }

    /// <summary>
    /// The limits an <c>SshCaKeys</c> row places on what its key signs, as the certificate
    /// rules take them: the types from <c>IsUserCa</c> and <c>IsHostCa</c>, and the longest
    /// validity from <c>MaxValidityHours</c>. A number of hours that is not positive permits no
    /// validity at all, and one too large for a <see cref="TimeSpan"/> is the longest there is.
    /// </summary>
    private static SshCaLimits SshLimitsOf(SshRow row)
    {
        var maxValidity = row.MaxValidityHours <= 0 ? TimeSpan.Zero
            : row.MaxValidityHours >= TimeSpan.MaxValue.TotalHours ? TimeSpan.MaxValue
            : TimeSpan.FromHours(row.MaxValidityHours);
        return new SshCaLimits(AllowUser: row.IsUserCa, AllowHost: row.IsHostCa, MaxValidity: maxValidity);
    }

    /// <summary>
    /// Turns the plain request into the fields a certificate is built from, or refuses a request
    /// that is not one: a type that is not exactly <see cref="SshCertificateRequest.UserType"/>
    /// or <see cref="SshCertificateRequest.HostType"/>, a subject key that is not an OpenSSH
    /// public key blob, or a time before the Unix epoch. A member left null is read as empty.
    /// Nothing here is a rule about what a certificate may say; those are the issuer's.
    /// </summary>
    private static (SshCertificateFields? Fields, SigningRefusedException? Refusal) ReadSshCertificateFields(SshCertificateRequest request)
    {
        SshCertificateType type;
        switch (request.CertType)
        {
            case SshCertificateRequest.UserType:
                type = SshCertificateType.User;
                break;
            case SshCertificateRequest.HostType:
                type = SshCertificateType.Host;
                break;
            default:
                return (null, new SigningRefusedException(SigningRefusalReason.UntypedData,
                    $"An SSH certificate is of type '{SshCertificateRequest.UserType}' or '{SshCertificateRequest.HostType}'; the request names neither."));
        }

        SshPublicKey subject;
        try
        {
            subject = SshPublicKey.FromBlob(request.SubjectPublicKey ?? []);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return (null, new SigningRefusedException(SigningRefusalReason.UntypedData,
                $"The subject public key is not an OpenSSH public key blob: {Echoed(ex.Message)}"));
        }

        if (request.ValidAfter < 0 || request.ValidBefore < 0)
            return (null, new SigningRefusedException(SigningRefusalReason.UntypedData,
                "The validity of an SSH certificate is in Unix seconds; a time before the epoch is not one."));

        return (new SshCertificateFields
        {
            SubjectKey = subject,
            Type = type,
            Serial = request.Serial,
            KeyId = request.KeyId ?? string.Empty,
            Principals = (request.Principals ?? []).Select(p => p ?? string.Empty).ToList(),
            ValidAfter = (ulong)request.ValidAfter,
            ValidBefore = (ulong)request.ValidBefore,
            CriticalOptions = SshOptionsOf(request.CriticalOptions),
            Extensions = SshOptionsOf(request.Extensions),
        }, null);
    }

    /// <summary>
    /// The text of a rule or a parser as a refusal repeats it, cut to <see cref="MaxEchoedChars"/>.
    /// Such a message can quote a name the caller sent (an option, a key type), and a refusal
    /// crosses the wire as a status detail and is written to the audit, so its length is not the
    /// caller's to choose.
    /// </summary>
    private static string Echoed(string message) => SshAuditSummary.Cut(message, MaxEchoedChars);

    /// <summary>The most characters of a rule's or a parser's message a refusal repeats.</summary>
    private const int MaxEchoedChars = 400;

    /// <summary>The request's options as the certificate rules take them; a missing list, name or value is empty.</summary>
    private static List<SshOption> SshOptionsOf(IReadOnlyList<SshCertificateOption>? options)
        => (options ?? []).Select(o => new SshOption(o?.Name ?? string.Empty, o?.Value ?? string.Empty)).ToList();
}
