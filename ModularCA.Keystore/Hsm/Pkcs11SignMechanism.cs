using Net.Pkcs11Interop.Common;

namespace ModularCA.Keystore.Hsm;

/// <summary>
/// A PKCS#11 signing mechanism with the parameters it needs: <see cref="Pss"/> for the RSA-PSS
/// mechanisms, <see cref="Eddsa"/> for Ed448, neither for the rest. Built by
/// <see cref="Pkcs11AlgorithmMapper.GetSignMechanism"/> from the algorithm name, so the
/// parameters match the AlgorithmIdentifier the signed structure advertises for that name.
/// </summary>
/// <param name="Mechanism">The <c>CKM_</c> mechanism.</param>
/// <param name="Pss">The <c>CK_RSA_PKCS_PSS_PARAMS</c> for an RSA-PSS mechanism; null otherwise.</param>
/// <param name="Eddsa">The <c>CK_EDDSA_PARAMS</c> for <c>CKM_EDDSA</c> over Ed448; null otherwise.</param>
public sealed record Pkcs11SignMechanism(CKM Mechanism, Pkcs11PssParameters? Pss = null, Pkcs11EddsaParameters? Eddsa = null);

/// <summary>
/// <c>CK_RSA_PKCS_PSS_PARAMS</c>: the hash, the mask generation function and the salt length.
/// For a certificate or CRL these must be what its <c>RSASSA-PSS-params</c> say.
/// </summary>
/// <param name="HashAlgorithm">The hash mechanism (<c>hashAlg</c>), for example <c>CKM_SHA256</c>.</param>
/// <param name="Mgf">The mask generation function (<c>mgf</c>), for example <c>CKG_MGF1_SHA256</c>.</param>
/// <param name="SaltLength">The salt length in bytes (<c>sLen</c>).</param>
public sealed record Pkcs11PssParameters(CKM HashAlgorithm, CKG Mgf, ulong SaltLength);

/// <summary>
/// <c>CK_EDDSA_PARAMS</c> (PKCS#11 3.0): <c>phFlag</c> and an optional context. The signer only
/// ever asks for pure EdDSA with no context, which is what the Ed448 AlgorithmIdentifier of
/// RFC 8410 means.
/// </summary>
/// <param name="PreHash">The <c>phFlag</c>: false for pure EdDSA.</param>
public sealed record Pkcs11EddsaParameters(bool PreHash)
{
    /// <summary>
    /// The structure as the native module reads it, for this process: <c>CK_BBOOL phFlag</c>,
    /// <c>CK_ULONG ulContextDataLen</c> (zero) and <c>CK_BYTE_PTR pContextData</c> (null), laid out
    /// with the platform's <c>CK_ULONG</c> size and packing as Pkcs11Interop detects them.
    /// </summary>
    public byte[] ToNative() => ToNative(Platform.NativeULongSize, Platform.StructPackingSize, IntPtr.Size);

    /// <summary>
    /// The structure laid out for a platform: packed to one byte as Windows modules are, or
    /// with natural alignment as on Unix. With no context the length is zero and the pointer
    /// null, so only <c>phFlag</c> is non-zero.
    /// </summary>
    /// <param name="ulongSize">The size of <c>CK_ULONG</c>: 4 on Windows and 32-bit Unix, 8 on 64-bit Unix.</param>
    /// <param name="structPacking">1 when structures are packed (Windows), 0 for natural alignment.</param>
    /// <param name="pointerSize">The size of a pointer.</param>
    public byte[] ToNative(int ulongSize, int structPacking, int pointerSize)
    {
        int size;
        if (structPacking == 1)
        {
            size = 1 + ulongSize + pointerSize;
        }
        else
        {
            var offset = Align(1, ulongSize) + ulongSize;
            offset = Align(offset, pointerSize) + pointerSize;
            size = Align(offset, Math.Max(ulongSize, pointerSize));
        }
        var native = new byte[size];
        native[0] = PreHash ? (byte)1 : (byte)0;
        return native;
    }

    /// <summary><paramref name="offset"/> rounded up to a multiple of <paramref name="alignment"/>.</summary>
    private static int Align(int offset, int alignment) => (offset + alignment - 1) / alignment * alignment;
}
