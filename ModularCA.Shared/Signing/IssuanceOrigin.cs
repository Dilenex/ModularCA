namespace ModularCA.Shared.Signing;

/// <summary>
/// What the node knows about an issuance and the signer does not, in the signing contract's own
/// plain types: the four keys of a certificate's record in the signer's journal
/// (<c>docs/architecture/signer-journal.md</c>) and the protocol and requester of its signing
/// context. The signer writes it into the record and decides nothing from it. Every member is
/// optional; one the node does not know is absent. Identifiers only: never a token, a secret or
/// a hash of one.
/// </summary>
/// <param name="Spent">The one-time tokens this issuance used.</param>
/// <param name="Answers">What was being answered.</param>
/// <param name="Replaces">The certificate this one renews or reissues, when the node knows.</param>
/// <param name="Belongs">What the certificate belongs to.</param>
/// <param name="Protocol">The protocol the request came in by: <c>ACME</c>, <c>EST</c>, <c>SCEP</c>, <c>CMP</c>, <c>MSAE</c> and so on.</param>
/// <param name="Requester">The requesting account's identifier, when there is one.</param>
public sealed record IssuanceOrigin(
    IReadOnlyList<IssuanceSpent>? Spent = null,
    IssuanceAnswers? Answers = null,
    IssuanceReplaces? Replaces = null,
    IssuanceBelongs? Belongs = null,
    string? Protocol = null,
    string? Requester = null);

/// <summary>A one-time token an issuance used.</summary>
/// <param name="Kind">The token's kind: 1 enrollment token, 2 CMP shared secret, 3 ACME external account binding, 4 first administrator's claim.</param>
/// <param name="Id">The token's identifier: its row id, never its value.</param>
/// <param name="Use">Which use of the token this was, counted from 1.</param>
public sealed record IssuanceSpent(ulong Kind, string Id, ulong Use);

/// <summary>What an issuance answered.</summary>
/// <param name="Kind">0 none, 1 pending request, 2 ACME order, 3 enrollment transaction.</param>
/// <param name="Id">Its identifier, when it has one.</param>
public sealed record IssuanceAnswers(ulong Kind, string? Id);

/// <summary>The certificate an issuance renews or reissues.</summary>
/// <param name="Serial">Its serial: unsigned, big-endian, no leading zero byte.</param>
/// <param name="CaKey">SHA-256 of its issuing CA's public key (SubjectPublicKeyInfo).</param>
public sealed record IssuanceReplaces(byte[] Serial, byte[] CaKey);

/// <summary>What a certificate belongs to, by identifier; each member only when it applies.</summary>
/// <param name="Profile">The certificate profile.</param>
/// <param name="Space">The space.</param>
/// <param name="OwnerKind">The owner's kind: 1 user, 2 badge, 3 infrastructure registration.</param>
/// <param name="Owner">The owner.</param>
/// <param name="Template">The template.</param>
public sealed record IssuanceBelongs(string? Profile = null, string? Space = null, ulong? OwnerKind = null, string? Owner = null, string? Template = null)
{
    /// <summary>Whether no member is set.</summary>
    public bool IsEmpty => Profile == null && Space == null && OwnerKind == null && Owner == null && Template == null;
}
