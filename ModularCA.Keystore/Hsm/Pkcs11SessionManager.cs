using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using System.Security.Cryptography;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// Manages PKCS#11 HSM sessions: loads the PKCS#11 module, authenticates to a slot,
/// and provides signing and key lookup operations. Thread-safe via locking.
/// <para>
/// The PIN is stored as a <c>char[]</c> rather than an immutable
/// <see cref="string"/> so it can be zeroed on <see cref="Dispose"/>. The GC may still
/// relocate the buffer but the window where the value is recoverable from a heap scan
/// is bounded by the session manager's lifetime rather than the process lifetime.
/// </para>
/// <para>
/// <see cref="FindPrivateKey"/> and <see cref="FindPrivateKeyById"/> refuse
/// key handles whose <c>CKA_TOKEN</c>, <c>CKA_PRIVATE</c>, <c>CKA_SENSITIVE</c>, and
/// <c>CKA_EXTRACTABLE</c> attributes disagree with the HSM-containment contract that
/// <see cref="Pkcs11PrivateKeyHandle.CanExport"/> advertises. A session-scoped or
/// extractable key is not adopted and a warning is logged so the operator can fix the
/// provisioning.
/// </para>
/// <para>
/// <see cref="Sign"/> only auto-recovers from a small allow-list of recoverable
/// PKCS#11 return codes (session-invalid / session-closed / device-error). Auth-related
/// codes (PIN_INCORRECT, USER_NOT_LOGGED_IN, DEVICE_REMOVED) are NOT retried so an unrelated
/// transient error cannot repeatedly hit the HSM with the cached PIN and trigger a lockout.
/// </para>
/// <para>
/// Curve parameters read from <c>CKA_EC_PARAMS</c> are validated against the
/// approved set (P-256, P-384, P-521). Any other curve is rejected before it can be embedded
/// in a SubjectPublicKeyInfo.
/// </para>
/// </summary>
public sealed class Pkcs11SessionManager : IDisposable
{
    private readonly IPkcs11Library _library;
    private readonly ISlot _slot;
    private ISession? _session;

    // Store the PIN in a char[] we control so Dispose can zero it. The C#
    // GC can still move the buffer, but the window where a heap scan recovers the PIN
    // is bounded by this class's lifetime rather than the process lifetime.
    private char[]? _pin;

    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>DER-encoded OID for NIST P-256 (secp256r1).</summary>
    private static readonly byte[] EcParamsP256 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>DER-encoded OID for NIST P-384 (secp384r1).</summary>
    private static readonly byte[] EcParamsP384 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    /// <summary>DER-encoded OID for NIST P-521 (secp521r1).</summary>
    private static readonly byte[] EcParamsP521 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

    /// <summary>
    /// Initialises the session manager by loading the PKCS#11 module, locating
    /// the requested slot, and opening an authenticated read/write session. The PIN
    /// argument is COPIED into an internal <c>char[]</c> and the caller should zero its
    /// own buffer on return. This constructor is the preferred entry point.
    /// </summary>
    /// <param name="modulePath">File-system path to the PKCS#11 shared library (e.g. softhsm2.dll).</param>
    /// <param name="slotId">Numeric slot identifier to use.</param>
    /// <param name="pin">User PIN for the token in the target slot.</param>
    /// <exception cref="InvalidOperationException">Thrown when the specified slot cannot be found.</exception>
    public Pkcs11SessionManager(string modulePath, ulong slotId, ReadOnlySpan<char> pin)
    {
        if (pin.IsEmpty)
            throw new ArgumentException("PIN must not be empty.", nameof(pin));

        var factories = new Pkcs11InteropFactories();
        _library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, modulePath, AppType.MultiThreaded);
        _slot = _library.GetSlotList(SlotsType.WithTokenPresent)
            .FirstOrDefault(s => s.GetSlotInfo().SlotId == slotId)
            ?? throw new InvalidOperationException($"PKCS#11 slot {slotId} not found");

        _pin = new char[pin.Length];
        pin.CopyTo(_pin);
        EnsureSession();
    }

    /// <summary>
    /// Convenience constructor for callers that still supply the PIN as a
    /// <see cref="string"/>. Prefer the <see cref="ReadOnlySpan{Char}"/> overload where
    /// possible because an immutable <c>string</c> cannot be zeroed in managed memory.
    /// </summary>
    public Pkcs11SessionManager(string modulePath, ulong slotId, string pin)
        : this(modulePath, slotId, (pin ?? throw new ArgumentNullException(nameof(pin))).AsSpan())
    {
    }

    /// <summary>
    /// Opens a new read/write session and logs in with the user PIN if no
    /// active session exists.
    /// </summary>
    private void EnsureSession()
    {
        if (_session is not null)
            return;
        if (_pin is null)
            throw new ObjectDisposedException(nameof(Pkcs11SessionManager), "PIN has been cleared.");

        _session = _slot.OpenSession(SessionType.ReadWrite);
        // The Pkcs11Interop session wants a string here — we materialize it
        // from our char[], then let it go out of scope so only our char[] copy persists.
        _session.Login(CKU.CKU_USER, new string(_pin));
    }

    /// <summary>
    /// Recovers from a stale or broken session by closing the current one
    /// and opening a fresh authenticated session.
    /// </summary>
    private void RecoverSession()
    {
        try { _session?.CloseSession(); } catch { /* best-effort cleanup */ }
        _session = null;
        EnsureSession();
    }

    /// <summary>
    /// Reads the token/private/sensitive/extractable attributes from a
    /// candidate key handle and returns <c>true</c> only when the key is a genuine,
    /// non-extractable, token-resident, sensitive private key. Any deviation is logged
    /// so the operator can fix the provisioning script, and the handle is rejected.
    /// </summary>
    private bool IsHandleHsmContained(IObjectHandle handle, string lookupDescription)
    {
        try
        {
            var attrs = _session!.GetAttributeValue(handle, new List<CKA>
            {
                CKA.CKA_TOKEN,
                CKA.CKA_PRIVATE,
                CKA.CKA_SENSITIVE,
                CKA.CKA_EXTRACTABLE,
            });
            var token = attrs[0].GetValueAsBool();
            var @private = attrs[1].GetValueAsBool();
            var sensitive = attrs[2].GetValueAsBool();
            var extractable = attrs[3].GetValueAsBool();
            if (!token || !@private || !sensitive || extractable)
            {
                Console.Error.WriteLine(
                    $"[WARNING] Pkcs11SessionManager: refusing key '{lookupDescription}' — " +
                    $"attributes CKA_TOKEN={token} CKA_PRIVATE={@private} CKA_SENSITIVE={sensitive} " +
                    $"CKA_EXTRACTABLE={extractable} do not satisfy HSM-containment policy.");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[WARNING] Pkcs11SessionManager: could not read containment attributes for '{lookupDescription}': {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Searches the token for a private key object whose <c>CKA_LABEL</c>
    /// matches the supplied label string.
    /// </summary>
    /// <param name="label">The label to match against <c>CKA_LABEL</c>.</param>
    /// <returns>
    /// The handle of the first matching private key, or <c>null</c> if none is found
    /// or no matching handle satisfies the HSM-containment policy.
    /// </returns>
    public IObjectHandle? FindPrivateKey(string label)
    {
        lock (_lock)
        {
            EnsureSession();
            var attributes = new List<IObjectAttribute>
            {
                _session!.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            };
            var results = _session.FindAllObjects(attributes);
            foreach (var h in results)
            {
                if (IsHandleHsmContained(h, $"label='{label}'"))
                    return h;
            }
            return null;
        }
    }

    /// <summary>
    /// Searches the token for a private key object whose <c>CKA_ID</c>
    /// matches the supplied byte array.
    /// </summary>
    /// <param name="id">The key identifier bytes to match against <c>CKA_ID</c>.</param>
    /// <returns>
    /// The handle of the first matching private key, or <c>null</c> if none is found
    /// or no matching handle satisfies the HSM-containment policy.
    /// </returns>
    public IObjectHandle? FindPrivateKeyById(byte[] id)
    {
        lock (_lock)
        {
            EnsureSession();
            var attributes = new List<IObjectAttribute>
            {
                _session!.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, id),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            };
            var results = _session.FindAllObjects(attributes);
            foreach (var h in results)
            {
                if (IsHandleHsmContained(h, $"id={Convert.ToHexString(id)}"))
                    return h;
            }
            return null;
        }
    }

    /// <summary>
    /// Allow-list of PKCS#11 return codes that <see cref="Sign"/> treats as
    /// recoverable. Any other error is rethrown after logging so we never silently retry
    /// auth-related failures that could trip an HSM lockout policy.
    /// </summary>
    private static readonly HashSet<CKR> RecoverablePkcs11Codes = new()
    {
        CKR.CKR_SESSION_HANDLE_INVALID,
        CKR.CKR_SESSION_CLOSED,
        CKR.CKR_DEVICE_ERROR,
    };

    /// <summary>
    /// Signs the provided data using the specified private key and PKCS#11 mechanism.
    /// Automatically recovers the session on a small allow-list of transient errors
    /// auth-related failures are NOT retried.
    /// </summary>
    /// <param name="key">Handle to the private key stored on the token.</param>
    /// <param name="data">The data bytes to sign.</param>
    /// <param name="mechanism">The <see cref="CKM"/> signing mechanism to use.</param>
    /// <returns>The raw signature bytes produced by the HSM.</returns>
    /// <exception cref="Pkcs11Exception">
    /// Re-thrown after one recovery attempt if the signing operation still fails,
    /// or immediately if the first error is not in the recoverable-codes allow-list.
    /// </exception>
    public byte[] Sign(IObjectHandle key, byte[] data, CKM mechanism)
    {
        lock (_lock)
        {
            EnsureSession();
            try
            {
                return _session!.Sign(
                    _session.Factories.MechanismFactory.Create(mechanism),
                    key,
                    data);
            }
            catch (Pkcs11Exception ex)
            {
                // Log the ORIGINAL exception so forensics are possible, and
                // only retry on known-recoverable codes. PIN/auth failures fall through.
                Console.Error.WriteLine(
                    $"[WARNING] Pkcs11SessionManager.Sign first attempt failed: {ex.Method}={ex.RV} ({ex.Message}).");

                if (!RecoverablePkcs11Codes.Contains(ex.RV))
                    throw;

                RecoverSession();
                return _session!.Sign(
                    _session.Factories.MechanismFactory.Create(mechanism),
                    key,
                    data);
            }
        }
    }

    /// <summary>
    /// Generates an RSA or EC key pair on the HSM token.
    /// <para>
    /// For RSA the <paramref name="keySize"/> sets the modulus length in bits.
    /// For EC the <paramref name="keySize"/> selects the curve (256, 384, or 521).
    /// </para>
    /// </summary>
    /// <param name="algorithm">Key algorithm family: "RSA" or "EC".</param>
    /// <param name="keySize">
    /// RSA modulus length in bits, or the EC curve size (256, 384, 521).
    /// </param>
    /// <param name="label">Label assigned to both the public and private key objects.</param>
    /// <returns>A tuple of (publicKey, privateKey) object handles on the token.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="algorithm"/> is not "RSA" or "EC",
    /// or when an unsupported EC curve size is specified.
    /// </exception>
    public (IObjectHandle pubKey, IObjectHandle privKey) GenerateKeyPair(
        string algorithm, int keySize, string label)
    {
        lock (_lock)
        {
            EnsureSession();
            var mechanism = _session!.Factories.MechanismFactory.Create(
                Pkcs11AlgorithmMapper.GetKeyGenMechanism(algorithm));

            List<IObjectAttribute> pubTemplate;
            List<IObjectAttribute> privTemplate;

            if (algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
            {
                pubTemplate =
                [
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, (ulong)keySize),
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }),
                ];
            }
            else if (algorithm.Equals("EC", StringComparison.OrdinalIgnoreCase))
            {
                var ecParams = keySize switch
                {
                    256 => EcParamsP256,
                    384 => EcParamsP384,
                    521 => EcParamsP521,
                    _ => throw new NotSupportedException(
                        $"Unsupported EC curve size {keySize}. Supported: 256, 384, 521."),
                };

                pubTemplate =
                [
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                    _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, ecParams),
                ];
            }
            else
            {
                throw new NotSupportedException(
                    $"Unsupported key algorithm '{algorithm}'. Supported: RSA, EC.");
            }

            privTemplate =
            [
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                _session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
            ];

            _session.GenerateKeyPair(mechanism, pubTemplate, privTemplate,
                out var pubKey, out var privKey);

            return (pubKey, privKey);
        }
    }

    /// <summary>
    /// Reads the DER-encoded public key material from the token.
    /// For EC keys this returns <c>CKA_VALUE</c>; for RSA keys the modulus and
    /// public exponent are read and assembled into a DER-encoded
    /// <c>SubjectPublicKeyInfo</c> structure.
    /// </summary>
    /// <param name="pubKey">Handle of the public key object on the token.</param>
    /// <returns>DER-encoded public key bytes.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the key type is not RSA or EC, or when required attributes
    /// cannot be read from the token.
    /// </exception>
    public byte[] GetPublicKeyDer(IObjectHandle pubKey)
    {
        lock (_lock)
        {
            EnsureSession();

            // Determine the key type first.
            var keyTypeAttrs = _session!.GetAttributeValue(pubKey,
                new List<CKA> { CKA.CKA_KEY_TYPE });

            var keyType = keyTypeAttrs[0].GetValueAsUlong();

            if (keyType == (ulong)CKK.CKK_EC)
            {
                // Read EC point and curve parameters.
                var attrs = _session.GetAttributeValue(pubKey,
                    new List<CKA> { CKA.CKA_EC_POINT, CKA.CKA_EC_PARAMS });

                var ecPoint = attrs[0].GetValueAsByteArray();
                var ecParams = attrs[1].GetValueAsByteArray();

                if (ecPoint is null || ecParams is null)
                    throw new InvalidOperationException("Unable to read EC public key attributes from token.");

                // Validate CKA_EC_PARAMS against the approved curve set so a
                // mis-provisioned slot returning secp192r1 / brainpool / custom OIDs doesn't
                // feed a bogus SPKI into the rest of the stack.
                if (!EcParamsApproved(ecParams))
                    throw new InvalidOperationException(
                        "Token CKA_EC_PARAMS does not match an approved curve (P-256, P-384, P-521). " +
                        "Refusing to build a SubjectPublicKeyInfo with a disallowed curve.");

                return BuildEcSubjectPublicKeyInfo(ecParams, ecPoint);
            }

            if (keyType == (ulong)CKK.CKK_RSA)
            {
                var attrs = _session.GetAttributeValue(pubKey,
                    new List<CKA> { CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT });

                var modulus = attrs[0].GetValueAsByteArray();
                var exponent = attrs[1].GetValueAsByteArray();

                if (modulus is null || exponent is null)
                    throw new InvalidOperationException("Unable to read RSA public key attributes from token.");

                return BuildRsaSubjectPublicKeyInfo(modulus, exponent);
            }

            throw new InvalidOperationException(
                $"Unsupported key type {keyType}. Only RSA and EC public keys are supported.");
        }
    }

    /// <summary>
    /// Compare the token-returned CKA_EC_PARAMS bytes against the approved
    /// NIST P-256/P-384/P-521 DER OIDs. Returns <c>true</c> only for exact byte-level
    /// matches — there is no attempt to normalise named vs. explicit encodings.
    /// </summary>
    private static bool EcParamsApproved(byte[] ecParams)
    {
        return ecParams.AsSpan().SequenceEqual(EcParamsP256)
            || ecParams.AsSpan().SequenceEqual(EcParamsP384)
            || ecParams.AsSpan().SequenceEqual(EcParamsP521);
    }

    /// <summary>
    /// Releases the PKCS#11 session and unloads the library. Zeros the PIN
    /// buffer before the reference is dropped.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            try { _session?.Logout(); } catch { /* best-effort */ }
            try { _session?.CloseSession(); } catch { /* best-effort */ }
            _session = null;

            // Zero the PIN FIRST, and guard the library teardown.
            //
            // The whole point of holding the PIN in a char[] rather than a string is that it can be
            // wiped. Previously an unguarded _library.Dispose() sat between the session teardown and
            // the wipe, so a throw from the PKCS#11 module — exactly the situation where an operator
            // is least likely to notice — left the PIN recoverable in managed memory for the rest of
            // the process lifetime, defeating the design this class documents at length.
            if (_pin != null)
            {
                CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(_pin.AsSpan()));
                _pin = null;
            }
            try { _library.Dispose(); } catch { /* best-effort: the PIN is already gone */ }
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  DER encoding helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>RSA OID: 1.2.840.113549.1.1.1</summary>
    private static readonly byte[] RsaOid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    /// <summary>EC OID: 1.2.840.10045.2.1</summary>
    private static readonly byte[] EcPublicKeyOid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    private static byte[] BuildRsaSubjectPublicKeyInfo(byte[] modulus, byte[] exponent)
    {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        var modulusInt = WrapAsInteger(modulus);
        var exponentInt = WrapAsInteger(exponent);
        var rsaPublicKey = WrapAsSequence([.. modulusInt, .. exponentInt]);

        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
        var algorithmId = WrapAsSequence([.. RsaOid, 0x05, 0x00]);

        // BIT STRING wrapping the RSAPublicKey
        var bitString = WrapAsBitString(rsaPublicKey);

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
        return WrapAsSequence([.. algorithmId, .. bitString]);
    }

    private static byte[] BuildEcSubjectPublicKeyInfo(byte[] ecParams, byte[] ecPoint)
    {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ECParameters(OID) }
        var algorithmId = WrapAsSequence([.. EcPublicKeyOid, .. ecParams]);

        // ecPoint may be DER OCTET STRING wrapped; unwrap if so.
        var pointBytes = ecPoint;
        if (pointBytes.Length > 2 && pointBytes[0] == 0x04 &&
            pointBytes[1] == pointBytes.Length - 2)
        {
            // It is an OCTET STRING tag (0x04) wrapping the raw point.
            pointBytes = pointBytes[2..];
        }

        var bitString = WrapAsBitString(pointBytes);
        return WrapAsSequence([.. algorithmId, .. bitString]);
    }

    private static byte[] WrapAsInteger(byte[] value)
    {
        // Ensure positive representation (leading zero if high bit set).
        if (value.Length > 0 && (value[0] & 0x80) != 0)
            value = [0x00, .. value];

        return [0x02, .. EncodeLength(value.Length), .. value];
    }

    private static byte[] WrapAsSequence(byte[] content)
    {
        return [0x30, .. EncodeLength(content.Length), .. content];
    }

    private static byte[] WrapAsBitString(byte[] content)
    {
        // BIT STRING: tag 0x03, length, 0x00 (unused bits), content
        var length = content.Length + 1;
        return [0x03, .. EncodeLength(length), 0x00, .. content];
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80)
            return [(byte)length];
        if (length <= 0xFF)
            return [0x81, (byte)length];
        if (length <= 0xFFFF)
            return [0x82, (byte)(length >> 8), (byte)length];
        return [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length];
    }
}
