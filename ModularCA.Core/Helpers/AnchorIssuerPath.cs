using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Helpers;

/// <summary>
/// The certificates above a CA certificate that this instance holds, loaded for
/// <see cref="X509ChainValidationUtil.ValidateAgainstAnchor(X509Certificate2, X509Certificate2, IReadOnlyCollection{X509Certificate2}?, bool, out string?)"/>
/// so that a required revocation check under an intermediate CA has a complete chain to run on.
/// The one place the callers that prove issuance (mTLS sign-in and step-up, EST re-enrollment) get
/// those certificates, so they cannot come to differ in which parents they pass.
/// <para>
/// The walk is <see cref="IssuerChainResolver.ResolveIssuerPathAsync"/>, the same one the rest of
/// the product uses. It ends early at a parent this instance does not hold (an intermediate under
/// an external or offline root that was never imported); the validator treats a path that does not
/// reach a self-signed root as no path at all, and nothing here needs to tell the cases apart. The
/// certificates are not trusted for being in the database: the chain engine verifies each
/// signature.
/// </para>
/// </summary>
public sealed class AnchorIssuerPath : IDisposable
{
    private readonly List<X509Certificate2> _certificates;

    private AnchorIssuerPath(List<X509Certificate2> certificates) => _certificates = certificates;

    /// <summary>The certificates above the anchor, nearest first; empty when none are needed or held.</summary>
    public IReadOnlyList<X509Certificate2> Certificates => _certificates;

    /// <summary>
    /// Loads the certificates above <paramref name="anchor"/>, up to and including its self-signed
    /// root where the instance holds them. Returns an empty path, without touching the database,
    /// when <paramref name="requireRevocationCheck"/> is false or the anchor is itself a root:
    /// the validator uses the parents for the revocation check alone. A parent whose stored
    /// certificate cannot be parsed also yields an empty path, which leaves the validator on the
    /// behaviour it has without parents.
    /// </summary>
    /// <param name="db">The context to read through.</param>
    /// <param name="anchor">The stored row of the CA certificate that issuance is proven against.</param>
    /// <param name="requireRevocationCheck">Whether the validation this is for requires a revocation check.</param>
    public static async Task<AnchorIssuerPath> LoadAsync(
        ModularCADbContext db, CertificateEntity anchor, bool requireRevocationCheck)
    {
        var loaded = new List<X509Certificate2>();
        if (!requireRevocationCheck || anchor.IssuerCertificateId == anchor.CertificateId)
            return new AnchorIssuerPath(loaded);

        var parents = await IssuerChainResolver.ResolveIssuerPathAsync(db, anchor);
        try
        {
            foreach (var parent in parents)
                loaded.Add(Load(parent));
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException)
        {
            foreach (var certificate in loaded)
                certificate.Dispose();
            loaded.Clear();
        }
        return new AnchorIssuerPath(loaded);
    }

    /// <summary>Parses a stored certificate row, from its DER when present and otherwise its PEM.</summary>
    /// <param name="entity">The stored certificate.</param>
    /// <exception cref="InvalidOperationException">The row holds neither DER nor PEM.</exception>
    private static X509Certificate2 Load(CertificateEntity entity)
    {
        if (entity.RawCertificate is { Length: > 0 } der)
            return X509CertificateLoader.LoadCertificate(der);
        if (!string.IsNullOrWhiteSpace(entity.Pem))
            return X509Certificate2.CreateFromPem(entity.Pem);
        throw new InvalidOperationException(
            $"CA certificate row {entity.CertificateId} contains neither DER nor PEM certificate data.");
    }

    /// <summary>Disposes the loaded certificates.</summary>
    public void Dispose()
    {
        foreach (var certificate in _certificates)
            certificate.Dispose();
        _certificates.Clear();
    }
}
