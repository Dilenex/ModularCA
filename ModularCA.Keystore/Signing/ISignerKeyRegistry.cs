using ModularCA.Ssh;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// The registry the signer resolves keys from: <see cref="IKeystoreCertificates"/> plus the
/// private key handles the node unlocked or the signer committed since. This is the only
/// interface through which a handle is reached, and it is internal to the keystore project's
/// consumers: the signer, its persistence and the startup unlock.
/// </summary>
/// <remarks>
/// It holds two sets of keys that never mix. The keys of <c>ca-certs.keystore</c> and of a
/// PKCS#11 token are paired with certificates and are what <see cref="IKeystoreCertificates.GetSigners"/>
/// and <see cref="GetPrivateKeyFor"/> see. The keys of <c>ssh-ca.keystore</c> have no certificate:
/// each is bound to the <c>SshCaKeys</c> row that carries its public key, and is reached only by
/// that row's id through <see cref="GetSshKey"/>. An SSH key is never a signer, and a signer's
/// key is never returned for an SSH row, whatever the database says about either.
/// </remarks>
public interface ISignerKeyRegistry : ModularCA.Shared.Interfaces.IKeystoreCertificates
{
    /// <summary>
    /// The private key handle for <paramref name="cert"/>, matched by public key, or null when
    /// the registry holds no key for it. SSH CA keys are not searched.
    /// </summary>
    IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert);

    /// <summary>
    /// Registers a certificate with its private key handle at runtime, so a key the signer has
    /// just committed resolves without a restart. A certificate already held (same public key,
    /// or same serial and subject) is not added twice; it joins the trusted authorities either way.
    /// </summary>
    void RegisterSigner(X509Certificate certificate, IPrivateKeyHandle handle);

    /// <summary>
    /// The SSH CA key bound to the <c>SshCaKeys</c> row <paramref name="sshCaKeyId"/>, or null
    /// when none is. The binding was made when the key was loaded from, committed to or imported
    /// into <c>ssh-ca.keystore</c>; the caller still checks the row carries the same public key.
    /// </summary>
    SshKeyBinding? GetSshKey(Guid sshCaKeyId);

    /// <summary>Every SSH CA key the registry holds, with the row each is bound to.</summary>
    IReadOnlyList<SshKeyBinding> GetSshKeys();

    /// <summary>
    /// Binds an SSH CA key to its <c>SshCaKeys</c> row at runtime, for a key the signer has just
    /// committed or imported. A row already bound keeps its binding when the public key is the
    /// same, and the call throws <see cref="InvalidOperationException"/> when it differs: a row
    /// never changes key.
    /// </summary>
    void RegisterSshKey(SshKeyBinding binding);
}

/// <summary>
/// An SSH CA key the signer holds: the <c>SshCaKeys</c> row it is bound to, its public half, and
/// the handle that signs with it. Only a key that came out of, or went into,
/// <c>ssh-ca.keystore</c> has one.
/// </summary>
/// <param name="KeyId">The <c>SshCaKeys</c> row id.</param>
/// <param name="PublicKey">The key's public half, which the row carried when the binding was made.</param>
/// <param name="Handle">The private key.</param>
public sealed record SshKeyBinding(Guid KeyId, SshPublicKey PublicKey, IPrivateKeyHandle Handle);
