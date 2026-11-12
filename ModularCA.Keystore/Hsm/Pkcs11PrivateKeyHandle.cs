using Net.Pkcs11Interop.HighLevelAPI;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// HSM-backed private key handle that delegates signing operations to a PKCS#11 device.
/// The private key never leaves the HSM — all cryptographic operations are performed on-device.
/// </summary>
public sealed class Pkcs11PrivateKeyHandle : IPrivateKeyHandle
{
    private readonly IPkcs11Token _token;
    private readonly IObjectHandle _keyHandle;
    private readonly string _keyLabel;
    private readonly int? _ecdsaComponentLength;

    /// <summary>
    /// Initializes a new instance of <see cref="Pkcs11PrivateKeyHandle"/> bound to a specific HSM key.
    /// </summary>
    /// <param name="token">The PKCS#11 token (in production the <see cref="Pkcs11SessionManager"/> that owns the session).</param>
    /// <param name="keyHandle">The PKCS#11 object handle referencing the private key on the HSM.</param>
    /// <param name="keyLabel">A human-readable label identifying the key (CKA_LABEL).</param>
    /// <param name="ecdsaComponentLength">
    /// For an EC key, the byte length of each half of the raw <c>r || s</c> the token returns
    /// (<see cref="EcdsaSignatureEncoding.ComponentLength"/> of the certificate's key); null for
    /// other keys.
    /// </param>
    public Pkcs11PrivateKeyHandle(IPkcs11Token token, IObjectHandle keyHandle, string keyLabel, int? ecdsaComponentLength = null)
    {
        _token = token ?? throw new ArgumentNullException(nameof(token));
        _keyHandle = keyHandle ?? throw new ArgumentNullException(nameof(keyHandle));
        _keyLabel = keyLabel;
        _ecdsaComponentLength = ecdsaComponentLength;
    }

    /// <summary>
    /// Always returns <c>false</c> because HSM-backed keys cannot be exported.
    /// </summary>
    public bool CanExport => false;

    /// <summary>
    /// Throws <see cref="NotSupportedException"/> because HSM-backed private keys cannot be exported.
    /// </summary>
    /// <returns>Never returns; always throws.</returns>
    public byte[]? ExportPrivateKeyDer() =>
        throw new NotSupportedException($"HSM-backed key '{_keyLabel}' cannot be exported. Private key material stays on the HSM device.");

    /// <summary>
    /// Signs the provided data using the HSM. The signing operation is performed entirely on-device.
    /// An ECDSA signature comes back from the token as raw <c>r || s</c> and is returned as the
    /// DER <c>SEQUENCE { INTEGER r, INTEGER s }</c> that certificates, CRLs, OCSP responses and
    /// CMS carry, the same shape a software key returns; RSA and EdDSA signatures are returned
    /// as the token produced them. The mechanism carries the RSA-PSS or Ed448 parameters the
    /// algorithm's AlgorithmIdentifier implies (<see cref="Pkcs11AlgorithmMapper.GetSignMechanism"/>).
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="algorithm">The signing algorithm identifier (e.g. "SHA256withRSA", "SHA256withECDSA").</param>
    /// <returns>The signature value, ready for an X.509 signature field.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">An ECDSA signature from the token is not the length the key's curve gives.</exception>
    public byte[] Sign(byte[] data, string algorithm)
    {
        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism(algorithm);
        var signature = _token.Sign(_keyHandle, data, mechanism);
        if (!Pkcs11AlgorithmMapper.IsEcdsa(mechanism.Mechanism))
            return signature;

        // Without the curve (a handle made without the certificate's key) the halves are
        // taken as equal; with it, a signature of any other length is refused.
        var componentLength = _ecdsaComponentLength ?? Math.Max(1, signature.Length / 2);
        return EcdsaSignatureEncoding.RawToDer(signature, componentLength);
    }

    /// <summary>
    /// Returns a human-readable description of this key handle.
    /// </summary>
    public override string ToString() => $"Pkcs11Key[{_keyLabel}]";
}
