using ModularCA.Shared.Models;
using Org.BouncyCastle.X509;

namespace ModularCA.Keystore.Signing;

/// <summary>
/// In-memory registry of the CA certificates the node loaded from its keystores, with the
/// private key handles the signer resolves. Supports registration at runtime: a key the signer
/// commits (an intermediate CA, an infrastructure certificate) and a trust anchor an operator
/// imports. Callers outside the keystore project see it as <see cref="IKeystoreCertificates"/>
/// only, which has no key on it.
/// </summary>
public sealed class MultiCARegistry : ISignerKeyRegistry
{
    private readonly object _lock = new();
    private readonly List<(X509Certificate Certificate, IPrivateKeyHandle Handle)> _signers;
    private readonly List<X509Certificate> _trusted;

    /// <summary>Creates a registry over the signers and trusted certificates the unlock produced.</summary>
    public MultiCARegistry(IEnumerable<(X509Certificate Certificate, IPrivateKeyHandle Handle)> signers, IEnumerable<X509Certificate> trusted)
    {
        _signers = signers.ToList();
        _trusted = trusted.ToList();
    }

    /// <summary>A registry holding nothing, for setup mode and for a node whose keystore did not load.</summary>
    public static MultiCARegistry Empty() => new(Array.Empty<(X509Certificate, IPrivateKeyHandle)>(), Array.Empty<X509Certificate>());

    /// <inheritdoc />
    public List<X509Certificate> GetTrustedAuthorities() { lock (_lock) return _trusted.ToList(); }

    /// <inheritdoc />
    public List<CertificateAuthorityIdentity> GetSigners()
    {
        lock (_lock) return _signers.Select(s => new CertificateAuthorityIdentity(s.Certificate)).ToList();
    }

    /// <inheritdoc />
    /// <remarks>
    /// Matches by SPKI (SHA-256 over the DER-encoded public key) when it can be computed, so two
    /// signers with the same subject but different keys cannot be swapped at lookup time; falls
    /// back to serial and subject when it cannot.
    /// </remarks>
    public IPrivateKeyHandle? GetPrivateKeyFor(X509Certificate cert)
    {
        lock (_lock)
        {
            var targetSpki = TryComputeSpkiHash(cert);
            if (targetSpki != null)
            {
                foreach (var s in _signers)
                {
                    var spki = TryComputeSpkiHash(s.Certificate);
                    if (spki != null && spki.AsSpan().SequenceEqual(targetSpki.AsSpan()))
                        return s.Handle;
                }
            }

            foreach (var s in _signers)
            {
                if (s.Certificate.SerialNumber.Equals(cert.SerialNumber) && s.Certificate.SubjectDN.Equivalent(cert.SubjectDN))
                    return s.Handle;
            }
            return null;
        }
    }

    /// <inheritdoc />
    public void RegisterSigner(X509Certificate certificate, IPrivateKeyHandle handle)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(handle);
        lock (_lock)
        {
            if (GetPrivateKeyForUnlocked(certificate) == null)
                _signers.Add((certificate, handle));
            if (!_trusted.Any(t => t.SerialNumber.Equals(certificate.SerialNumber)))
                _trusted.Add(certificate);
        }
    }

    /// <inheritdoc />
    public void RegisterTrustedCert(X509Certificate cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        lock (_lock)
        {
            if (!_trusted.Any(t => t.SerialNumber.Equals(cert.SerialNumber)))
                _trusted.Add(cert);
        }
    }

    /// <summary>The lookup without taking the lock, for a caller that already holds it.</summary>
    private IPrivateKeyHandle? GetPrivateKeyForUnlocked(X509Certificate cert)
    {
        var targetSpki = TryComputeSpkiHash(cert);
        foreach (var s in _signers)
        {
            if (targetSpki != null)
            {
                var spki = TryComputeSpkiHash(s.Certificate);
                if (spki != null && spki.AsSpan().SequenceEqual(targetSpki.AsSpan()))
                    return s.Handle;
            }
            if (s.Certificate.SerialNumber.Equals(cert.SerialNumber) && s.Certificate.SubjectDN.Equivalent(cert.SubjectDN))
                return s.Handle;
        }
        return null;
    }

    /// <summary>SHA-256 over the DER-encoded SubjectPublicKeyInfo, or null when the key cannot be encoded.</summary>
    private static byte[]? TryComputeSpkiHash(X509Certificate cert)
    {
        try
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(cert.GetPublicKey()).GetDerEncoded();
            return System.Security.Cryptography.SHA256.HashData(spki);
        }
        catch
        {
            return null;
        }
    }
}
