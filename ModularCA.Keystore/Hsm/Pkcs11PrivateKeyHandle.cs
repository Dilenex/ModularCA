using Net.Pkcs11Interop.HighLevelAPI;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// HSM-backed private key handle that delegates signing operations to a PKCS#11 device.
/// The private key never leaves the HSM — all cryptographic operations are performed on-device.
/// </summary>
public sealed class Pkcs11PrivateKeyHandle : IPrivateKeyHandle
{
    private readonly Pkcs11SessionManager _sessionManager;
    private readonly IObjectHandle _keyHandle;
    private readonly string _keyLabel;

    /// <summary>
    /// Initializes a new instance of <see cref="Pkcs11PrivateKeyHandle"/> bound to a specific HSM key.
    /// </summary>
    /// <param name="sessionManager">The PKCS#11 session manager that owns the HSM session.</param>
    /// <param name="keyHandle">The PKCS#11 object handle referencing the private key on the HSM.</param>
    /// <param name="keyLabel">A human-readable label identifying the key (CKA_LABEL).</param>
    public Pkcs11PrivateKeyHandle(Pkcs11SessionManager sessionManager, IObjectHandle keyHandle, string keyLabel)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _keyHandle = keyHandle ?? throw new ArgumentNullException(nameof(keyHandle));
        _keyLabel = keyLabel;
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
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="algorithm">The signing algorithm identifier (e.g. "SHA256withRSA", "SHA256withECDSA").</param>
    /// <returns>The signature bytes produced by the HSM.</returns>
    public byte[] Sign(byte[] data, string algorithm)
    {
        var mechanism = Pkcs11AlgorithmMapper.GetSignMechanism(algorithm);
        return _sessionManager.Sign(_keyHandle, data, mechanism);
    }

    /// <summary>
    /// Returns a human-readable description of this key handle.
    /// </summary>
    public override string ToString() => $"Pkcs11Key[{_keyLabel}]";
}
