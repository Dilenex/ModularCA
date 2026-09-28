using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>Picks the server certificate for a TLS connection on the HTTPS listener.</summary>
public static class TlsServerCertificateSelector
{
    /// <summary>
    /// The instance's web TLS certificate, whatever name the client asked for: the public
    /// domain, the mTLS and EST subdomains, any other name, or none. Read on every handshake,
    /// so a renewed certificate is presented from the next connection on.
    /// </summary>
    public static X509Certificate2? Select(string? serverName, ApiCertificateProvider instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        return instance.GetCertificate();
    }
}
