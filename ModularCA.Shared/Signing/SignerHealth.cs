namespace ModularCA.Shared.Signing;

/// <summary>
/// The signer's own account of its state. The node asks for this before it serves enrollment
/// and shows it as a readiness step; a signer that is not unlocked holds no usable key.
/// </summary>
/// <param name="Unlocked">Whether the keystore has been decrypted and its keys are available to sign with.</param>
/// <param name="KeyCount">How many private keys the signer currently holds.</param>
/// <param name="Backend">Where keys live: <see cref="SoftwareBackend"/> or <see cref="Pkcs11Backend"/>.</param>
public sealed record SignerHealth(bool Unlocked, int KeyCount, string Backend)
{
    /// <summary>Keys are held in the signer's own memory, decrypted from the keystore files.</summary>
    public const string SoftwareBackend = "software";

    /// <summary>A PKCS#11 token holds the keys and performs every signature on-device.</summary>
    public const string Pkcs11Backend = "pkcs11";

    /// <summary>
    /// The signer is remote and did not answer: the report is the node's own, not the
    /// signer's, and says only that nothing can be signed until the channel is back.
    /// </summary>
    public const string UnreachableBackend = "unreachable";

    /// <summary>The report the node gives for a remote signer it cannot reach.</summary>
    public static SignerHealth Unreachable() => new(false, 0, UnreachableBackend);
}
