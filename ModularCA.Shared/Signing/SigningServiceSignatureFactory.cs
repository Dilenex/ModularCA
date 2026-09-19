using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Utilities;

namespace ModularCA.Shared.Signing;

/// <summary>
/// BouncyCastle <see cref="ISignatureFactory"/> over <see cref="ISigningService"/>, so the
/// certificate, CRL and OCSP generators keep working unchanged while the key they sign with is
/// held by the signer. Collects the to-be-signed bytes the generator streams in and hands them
/// to <see cref="ISigningService.SignAsync"/> once, with the context the caller supplied.
/// Classical (RSA, ECDSA, EdDSA) and post-quantum (ML-DSA, SLH-DSA) algorithm names resolve
/// through <see cref="DefaultSignatureAlgorithmFinder"/>.
/// </summary>
public sealed class SigningServiceSignatureFactory : ISignatureFactory
{
    private readonly ISigningService _signer;
    private readonly KeyRef _key;
    private readonly SignatureAlgorithm _algorithm;
    private readonly SigningContext _context;
    private readonly AlgorithmIdentifier _algorithmIdentifier;

    /// <summary>
    /// Creates a factory that signs with <paramref name="key"/> through <paramref name="signer"/>
    /// under <paramref name="context"/>.
    /// </summary>
    public SigningServiceSignatureFactory(ISigningService signer, KeyRef key, SignatureAlgorithm algorithm, SigningContext context)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _algorithm = algorithm;
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _algorithmIdentifier = DefaultSignatureAlgorithmFinder.Instance.Find(algorithm.Name);
    }

    /// <summary>The <see cref="AlgorithmIdentifier"/> the generator writes into the signed structure.</summary>
    public object AlgorithmDetails => _algorithmIdentifier;

    /// <summary>Creates a calculator that buffers the to-be-signed bytes and signs them on <c>GetResult</c>.</summary>
    public IStreamCalculator<IBlockResult> CreateCalculator() => new Calculator(this);

    private sealed class Calculator : IStreamCalculator<IBlockResult>
    {
        private readonly MemoryStream _buffer = new();
        private readonly SigningServiceSignatureFactory _owner;

        public Calculator(SigningServiceSignatureFactory owner) => _owner = owner;

        public Stream Stream => _buffer;

        /// <summary>
        /// The generators are synchronous, so the asynchronous signing call is waited on here.
        /// There is no synchronization context in the host, so this blocks a pool thread and
        /// nothing else.
        /// </summary>
        public IBlockResult GetResult()
        {
            var tbs = _buffer.ToArray();
            var signature = _owner._signer
                .SignAsync(_owner._key, _owner._algorithm, tbs, _owner._context)
                .GetAwaiter().GetResult();
            return new SignatureResult(signature);
        }
    }

    private sealed class SignatureResult : IBlockResult
    {
        private readonly byte[] _signature;

        public SignatureResult(byte[] signature) => _signature = signature ?? throw new ArgumentNullException(nameof(signature));

        public byte[] Collect() => _signature;

        public int Collect(byte[] output, int outOff)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (outOff < 0) throw new ArgumentOutOfRangeException(nameof(outOff), "Offset cannot be negative");
            if (outOff > output.Length - _signature.Length) throw new ArgumentOutOfRangeException(nameof(outOff), "Output buffer is too small");
            Array.Copy(_signature, 0, output, outOff, _signature.Length);
            return _signature.Length;
        }

        public int Collect(Span<byte> output)
        {
            if (output.Length < _signature.Length)
                throw new ArgumentException($"Output buffer must be at least {_signature.Length} bytes", nameof(output));
            _signature.AsSpan().CopyTo(output);
            return _signature.Length;
        }

        public int GetMaxResultLength() => _signature.Length;
    }
}
