using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Models.Config;
using ModularCA.Signer.Identity;

namespace ModularCA.API.Ingress;

/// <summary>How an upstream's TLS certificate is judged.</summary>
public enum UpstreamTrustMode
{
    /// <summary>The route pins the node's SPKI; that key and no other.</summary>
    Pinned,

    /// <summary>The certificate must chain to the configured upstream CA; the name is not checked, the pin is for that.</summary>
    SharedCa,

    /// <summary>Anything is accepted: the dangerous flag, and every https destination is loopback.</summary>
    AcceptAnyLoopback,

    /// <summary>The system trust store and the name, as any HTTPS client.</summary>
    System,
}

/// <summary>
/// The trust decision for upstream TLS, per cluster: a pinned key, the shared upstream CA,
/// anything on loopback under the dangerous flag, else the system store. The order is fixed
/// (a pin beats the CA, the CA beats the flag) so a stricter setting on one route is never
/// loosened by a looser global one. The dangerous flag never applies to a non-loopback
/// destination: configuration validation refuses such a route, and a database route that is
/// not loopback gets the system store instead, whatever the flag says.
/// </summary>
public sealed class UpstreamTrustPolicy
{
    private readonly X509Certificate2Collection? _sharedCa;
    private readonly bool _dangerousAcceptAnyOnLoopback;

    /// <summary>Creates the policy; <paramref name="sharedCa"/> is null when no upstream CA is configured.</summary>
    public UpstreamTrustPolicy(X509Certificate2Collection? sharedCa, bool dangerousAcceptAnyOnLoopback)
    {
        _sharedCa = sharedCa is { Count: > 0 } ? sharedCa : null;
        _dangerousAcceptAnyOnLoopback = dangerousAcceptAnyOnLoopback;
    }

    /// <summary>Whether a shared upstream CA is configured.</summary>
    public bool HasSharedCa => _sharedCa != null;

    /// <summary>
    /// Builds the policy from the ingress section, reading the upstream CA PEM file when one
    /// is named, relative paths against <paramref name="baseDirectory"/>. Throws
    /// <see cref="FileNotFoundException"/> or a <see cref="System.Security.Cryptography.CryptographicException"/>
    /// for a file that is missing or holds no certificate.
    /// </summary>
    public static UpstreamTrustPolicy Load(IngressConfig config, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(config);
        X509Certificate2Collection? ca = null;
        if (!string.IsNullOrWhiteSpace(config.UpstreamCaCertificatePath))
        {
            var path = SignerConfig.ResolvePath(config.UpstreamCaCertificatePath, baseDirectory);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Ingress.UpstreamCaCertificatePath '{config.UpstreamCaCertificatePath}' does not exist.", path);
            ca = new X509Certificate2Collection();
            ca.ImportFromPemFile(path);
            if (ca.Count == 0)
                throw new System.Security.Cryptography.CryptographicException($"Ingress.UpstreamCaCertificatePath '{config.UpstreamCaCertificatePath}' holds no certificate.");
        }
        return new UpstreamTrustPolicy(ca, config.DangerousAcceptAnyUpstreamCertificate);
    }

    /// <summary>The mode for a cluster, from the pin and the loopback fact its metadata carries.</summary>
    public UpstreamTrustMode ModeFor(string? pinnedSpki, bool httpsLoopback)
    {
        if (IngressRouteConfig.NormalizePin(pinnedSpki) != null) return UpstreamTrustMode.Pinned;
        if (_sharedCa != null) return UpstreamTrustMode.SharedCa;
        if (_dangerousAcceptAnyOnLoopback && httpsLoopback) return UpstreamTrustMode.AcceptAnyLoopback;
        return UpstreamTrustMode.System;
    }

    /// <summary>The mode for a cluster from its metadata, as <see cref="IngressProxyConfigProvider"/> writes it.</summary>
    public UpstreamTrustMode ModeFor(IReadOnlyDictionary<string, string>? metadata)
    {
        string? pin = null;
        var loopback = false;
        if (metadata != null)
        {
            metadata.TryGetValue(IngressProxyConfigProvider.PinMetadata, out pin);
            loopback = metadata.TryGetValue(IngressProxyConfigProvider.LoopbackMetadata, out var l) && string.Equals(l, "true", StringComparison.OrdinalIgnoreCase);
        }
        return ModeFor(pin, loopback);
    }

    /// <summary>
    /// The validation callback for a cluster, or null for <see cref="UpstreamTrustMode.System"/>,
    /// which leaves the handler's default validation in place.
    /// </summary>
    public RemoteCertificateValidationCallback? CallbackFor(IReadOnlyDictionary<string, string>? metadata)
    {
        string? pin = null;
        metadata?.TryGetValue(IngressProxyConfigProvider.PinMetadata, out pin);
        var mode = ModeFor(metadata);
        return mode == UpstreamTrustMode.System
            ? null
            : (_, certificate, _, errors) => Accept(mode, certificate as X509Certificate2, errors, pin);
    }

    /// <summary>
    /// Judges one certificate under <paramref name="mode"/>: the pinned key, a chain to the
    /// shared CA (name mismatch tolerated, since a node is reached by address), anything under
    /// the loopback exception, and under <see cref="UpstreamTrustMode.System"/> only a
    /// certificate the handler found no fault with.
    /// </summary>
    public bool Accept(UpstreamTrustMode mode, X509Certificate2? certificate, SslPolicyErrors errors, string? pinnedSpki)
    {
        switch (mode)
        {
            case UpstreamTrustMode.Pinned:
                return SpkiPin.Matches(certificate, pinnedSpki);
            case UpstreamTrustMode.SharedCa:
                if (certificate == null || _sharedCa == null) return false;
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.AddRange(_sharedCa);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    return chain.Build(certificate);
                }
            case UpstreamTrustMode.AcceptAnyLoopback:
                return true;
            default:
                return errors == SslPolicyErrors.None;
        }
    }
}
