using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--role signer --check-ready</c>: whether the local signer is listening and answering, for a
/// container manager's health command (Quadlet's <c>HealthCmd=</c>, a Kubernetes exec probe). It
/// exits 0 when a TLS server at <c>Signer.Listen</c> completes a handshake with the signer's own
/// server certificate, the one <c>Signer.ServerCertificate</c> names, and 1 otherwise.
/// </summary>
/// <remarks>
/// <para>
/// The signer answers only the node, admitted by the pin of its client certificate, and the
/// signer's container does not hold that certificate. So the check makes no gRPC call. It offers
/// TLS 1.3 alone, where the server sends its certificate and proves it holds the key
/// (CertificateVerify, Finished) before it asks for the client's, and it presents none: the
/// signer then refuses the connection, which is expected and not a failure. A server that answers
/// with the signer's own certificate has finished starting: the signer listens only after its
/// configuration, keystore and schema checks are done. A locked keystore still counts as ready,
/// since the signer is up and the node's health reports the lock.
/// </para>
/// <para>
/// It reads the signer's settings file and server certificate and nothing else: no database, no
/// keystore, no log file, so a health command run every few seconds leaves nothing behind.
/// </para>
/// </remarks>
public static class SignerReadinessCheck
{
    /// <summary>The flag.</summary>
    public const string Flag = "--check-ready";

    /// <summary>How long the connection and the handshake may take together.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Whether the command line names <see cref="Flag"/>.</summary>
    public static bool IsNamedIn(IReadOnlyList<string> args)
        => args.Any(a => string.Equals(a, Flag, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Reads the signer's settings from <paramref name="paths"/> (<c>signer.yaml</c> in its own
    /// directory, <c>config/config.yaml</c> otherwise) and runs <see cref="CheckAsync"/>. Returns
    /// the exit code: 0 ready, 1 not ready or not configured.
    /// </summary>
    /// <param name="paths">Where the signer's files are.</param>
    /// <param name="output">Where the verdict goes when ready.</param>
    /// <param name="error">Where the reason goes when not.</param>
    public static async Task<int> RunAsync(SignerPaths paths, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!File.Exists(paths.ConfigPath))
        {
            error.WriteLine($"not ready: {paths.ConfigPath} does not exist, so the signer is not configured.");
            return 1;
        }
        SystemConfig config;
        try
        {
            config = YamlConfigLoader.Load(paths.ConfigPath, _ => { });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            error.WriteLine($"not ready: {paths.ConfigPath} could not be read: {ex.Message}");
            return 1;
        }
        return await CheckAsync(config.Signer, paths, DefaultTimeout, output, error);
    }

    /// <summary>
    /// Connects to <c>Signer.Listen</c> (loopback when it binds every interface) and returns 0
    /// when the server completes a TLS 1.3 handshake with the certificate whose public key is that
    /// of <c>Signer.ServerCertificate</c>, 1 when nothing listens, nothing answers within
    /// <paramref name="timeout"/>, or another certificate answers.
    /// </summary>
    /// <param name="signer">The signer's settings: <c>Listen</c>, <c>ServerCertificate</c> and its password.</param>
    /// <param name="paths">How the certificate path resolves.</param>
    /// <param name="timeout">The limit on the connection and the handshake together.</param>
    /// <param name="output">Where the verdict goes when ready.</param>
    /// <param name="error">Where the reason goes when not.</param>
    public static async Task<int> CheckAsync(SignerConfig signer, SignerPaths paths, TimeSpan timeout, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        string expectedPin;
        IPAddress address;
        int port;
        var serverPath = paths.ResolveFile(signer.ServerCertificate);
        try
        {
            (address, port) = SignerServerOptions.ParseListen(signer.Listen);
            using var server = Pkcs12Files.Load(serverPath, signer.ServerCertificatePassword);
            expectedPin = SpkiPin.Compute(server);
        }
        catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            error.WriteLine($"not ready: {ex.Message}");
            return 1;
        }
        if (address.Equals(IPAddress.Any))
            address = IPAddress.Loopback;
        else if (address.Equals(IPAddress.IPv6Any))
            address = IPAddress.IPv6Loopback;

        using var deadline = new CancellationTokenSource(timeout);
        using var tcp = new TcpClient(address.AddressFamily);
        try
        {
            await tcp.ConnectAsync(address, port, deadline.Token);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            error.WriteLine($"not ready: nothing accepts connections on {Endpoint(address, port)} ({Reason(ex)}).");
            return 1;
        }

        string? presented = null;
        var matched = false;
        using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = address.ToString(),
                EnabledSslProtocols = SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http2],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // The pin is the whole decision, as on the node: the identity CA is in no store.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate == null)
                        return false;
                    var presentedCertificate = certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                    presented = SpkiPin.Compute(presentedCertificate);
                    matched = SpkiPin.Matches(presentedCertificate, expectedPin);
                    return matched;
                },
            }, deadline.Token);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException or SocketException)
        {
            // The signer refuses a client with no certificate. That ends the connection after the
            // server has proved itself, or, on a stack that reports it inside the handshake,
            // fails the handshake; either way what matters is the certificate it showed.
            if (!matched)
            {
                error.WriteLine(presented == null
                    ? $"not ready: {Endpoint(address, port)} accepts connections but completed no TLS 1.3 handshake ({Reason(ex)})."
                    : $"not ready: {Endpoint(address, port)} answers with a certificate whose SPKI pin is {presented}, not the signer's {expectedPin} ({serverPath}).");
                return 1;
            }
        }

        if (!matched)
        {
            error.WriteLine($"not ready: {Endpoint(address, port)} answers with a certificate whose SPKI pin is {presented ?? "(none)"}, not the signer's {expectedPin} ({serverPath}).");
            return 1;
        }
        output.WriteLine($"ready: the signer answers on {Endpoint(address, port)} with its server certificate ({expectedPin}).");
        return 0;
    }

    /// <summary>The address and port as one would type them.</summary>
    private static string Endpoint(IPAddress address, int port)
        => address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";

    /// <summary>A short reason for a failed connection or handshake.</summary>
    private static string Reason(Exception ex)
        => ex is OperationCanceledException ? "timed out" : ex.Message;
}
