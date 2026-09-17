using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ModularCA.Keystore.Adapters
{
    /// <summary>
    /// Software-backed implementation of <see cref="IPrivateKeyHandle"/> that holds the private
    /// key in managed memory. The signer signs through <see cref="Sign(byte[], string)"/>;
    /// <see cref="ExportPrivateKeyDer"/> exists for the operations that need the key itself
    /// (opening a SCEP envelope, unwrapping a stored end-entity key, re-signing the keystore
    /// file), all of which live inside the keystore project. The optional
    /// <c>canExport</c> flag lets a handle refuse export at construction time, in which case
    /// <see cref="ExportPrivateKeyDer"/> throws <see cref="NotSupportedException"/> to match
    /// the PKCS#11 behaviour.
    /// </summary>
    public class SoftwarePrivateKeyHandle : IPrivateKeyHandle
    {
        private readonly AsymmetricKeyParameter _privateKey;

        /// <summary>
        /// Creates a new software-backed private key handle. <paramref name="canExport"/>
        /// defaults to <c>true</c> to preserve existing call sites; passing <c>false</c>
        /// declares that this key must never be materialised as raw DER, in which case
        /// <see cref="ExportPrivateKeyDer"/> will throw.
        /// </summary>
        public SoftwarePrivateKeyHandle(AsymmetricKeyParameter privateKey, bool canExport = true)
        {
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            CanExport = canExport;
        }

        /// <inheritdoc />
        public bool CanExport { get; }

        /// <summary>
        /// The key itself, for the signer in this assembly: CMS decryption and public-key
        /// derivation need the parameters, not a DER copy that then has to be zeroed. Never
        /// leaves the keystore project.
        /// </summary>
        internal AsymmetricKeyParameter PrivateKey => _privateKey;

        /// <summary>
        /// Exports the private key in DER-encoded PKCS#8 format when <see cref="CanExport"/>
        /// is <c>true</c>. Throws <see cref="NotSupportedException"/> when the handle was
        /// constructed with <c>canExport: false</c>. Callers MUST zero the returned buffer
        /// with
        /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span{byte})"/>
        /// once the raw key material is no longer needed. Prefer
        /// <see cref="Sign(byte[], string)"/> for any signing operation — it keeps the key
        /// in this handle and off the caller's managed heap.
        /// </summary>
        public byte[]? ExportPrivateKeyDer()
        {
            if (!CanExport)
                throw new NotSupportedException(
                    "Software-backed private key handle was created with canExport=false. " +
                    "Use Sign(byte[], string) to perform cryptographic operations without materialising the raw key.");

            var pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
            return pkInfo.GetDerEncoded();
        }

        /// <summary>
        /// Signs the given data using the specified algorithm and returns the signature bytes.
        /// </summary>
        public byte[] Sign(byte[] data, string algorithm)
        {
            var signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(true, _privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }
    }
}
