using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ModularCA.API.ProxyProtocol;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--check-ready</c> outside the signer role (<c>--role node --check-ready</c>, or any role set
/// but the signer alone): whether the local node answers its own health endpoint, for a container
/// manager's health command (Quadlet's <c>HealthCmd=</c>, a Kubernetes or Podman exec probe). The
/// image has no <c>curl</c>, so an <c>httpGet</c> probe, which Podman runs as <c>curl</c> inside
/// the container, cannot work.
/// </summary>
/// <remarks>
/// <para>
/// Two questions, one flag apart:
/// </para>
/// <list type="bullet">
/// <item><c>--check-ready</c> asks <c>/health/live</c> and exits 0 on 200 only: every health check
/// passes (the database, the signer reachable and unlocked for the roles that need it, the
/// secrets the signer wraps read). <c>/health/live</c> is the anonymous summary of the checks
/// <c>/health/ready</c> reports in full; that one needs a SystemAuditor token, which a probe has
/// no business holding. A node that waits for its signer answers 503, so it is not ready.</item>
/// <item><c>--check-ready --live</c> asks <c>/health</c>, which runs no check, and exits 0 on 200:
/// the process accepts connections and its request pipeline answers. A node waiting for its
/// signer, or for a database that is down, is alive; restarting it would fix neither, and the
/// checks behind <c>/health/live</c> can take longer than a probe's timeout while the database
/// does not answer.</item>
/// </list>
/// <para>
/// The listener comes from this host's <c>config.yaml</c> (with the environment overrides the
/// node applies): the loopback-only health listener, <c>Health.LoopbackPort</c>, when it is set
/// (plain HTTP on <c>127.0.0.1</c>, never the PROXY protocol: <see cref="HealthListener"/>);
/// otherwise <c>Https.Port</c>, or
/// <c>Http.Port</c> where this process opens the plain-HTTP listener (the validation or ingress
/// role), on <c>Https.ListenAddress</c>. The probe only ever connects over loopback: a wildcard
/// bind is reached at <c>127.0.0.1</c> (or <c>::1</c> for <c>::</c>), and an address list with
/// neither a wildcard nor a loopback address is refused rather than probed across a network.
/// </para>
/// <para>
/// TLS: the certificate is not validated, on loopback only. The node answers there with
/// whatever web TLS certificate it holds (self-signed, the temporary one, issued for a public
/// name that is not <c>127.0.0.1</c>), and the probe checks the process, not the certificate,
/// whose expiry the health checks report. Nothing but a process on this host (in the pod, this
/// pod) can answer on loopback, and the probe sends no credential and reads only a status code.
/// </para>
/// <para>
/// The PROXY protocol (<c>Https.ProxyProtocol</c>, <c>Http.ProxyProtocol</c>): such a listener
/// closes a connection from any address outside <c>Http.ProxyProtocolTrustedCidrs</c> and
/// requires a header from those inside it. The probe prefers a listener without the protocol.
/// It uses one with the protocol only when loopback is already a trusted proxy, and then sends
/// a v2 <c>LOCAL</c> header, which names no client and keeps loopback as the peer, so the probe
/// claims no address it does not have. It never asks for a trust the operator did not give:
/// with every usable listener taking the protocol and loopback untrusted, it exits 1 and says
/// so, naming <c>Health.LoopbackPort</c>, which is the fix.
/// </para>
/// <para>
/// It reads <c>config.yaml</c> and nothing else: no database, no keystore, no log file, so a
/// health command run every few seconds leaves nothing behind.
/// </para>
/// </remarks>
public static class NodeReadinessCheck
{
    /// <summary>The flag that asks whether the node is alive rather than ready.</summary>
    public const string LiveFlag = "--live";

    /// <summary>The flag naming the configuration directory, <c>config/</c> beside the binary by default.</summary>
    public const string ConfigDirFlag = "--config-dir";

    /// <summary>The path the readiness check asks: every health check, anonymously, by status code.</summary>
    public const string ReadyPath = "/health/live";

    /// <summary>The path the liveness check asks: no health check, just the request pipeline.</summary>
    public const string LivePath = "/health";

    /// <summary>How long the connection, the handshake and the response may take together.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The bytes of <see cref="ProxyV2LocalHeader"/>.</summary>
    private static readonly byte[] LocalHeader =
    [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // signature
        0x20, // version 2, command LOCAL
        0x00, // family UNSPEC, protocol UNSPEC
        0x00, 0x00, // no address block
    ];

    /// <summary>
    /// A PROXY protocol v2 header with the <c>LOCAL</c> command, family UNSPEC and no address
    /// block: "this connection is the proxy's own", which keeps the real peer.
    /// </summary>
    public static ReadOnlyMemory<byte> ProxyV2LocalHeader => LocalHeader;

    /// <summary>Whether the command line names <see cref="LiveFlag"/>.</summary>
    /// <param name="args">The command line.</param>
    public static bool IsLiveNamedIn(IReadOnlyList<string> args)
        => args.Any(a => string.Equals(a, LiveFlag, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Where and how the probe connects: the scheme, the loopback address and port of one of the
    /// node's listeners, and whether that listener takes the PROXY protocol, so the probe sends a
    /// v2 <c>LOCAL</c> header first.
    /// </summary>
    /// <param name="Scheme"><c>https</c> or <c>http</c>.</param>
    /// <param name="Address">The loopback address to connect to.</param>
    /// <param name="Port">The listener's port.</param>
    /// <param name="SendsProxyHeader">Whether the listener takes the PROXY protocol (and trusts loopback).</param>
    /// <param name="Listener">The listener's name for messages, e.g. <c>HTTPS</c>.</param>
    public sealed record ProbeTarget(string Scheme, IPAddress Address, int Port, bool SendsProxyHeader, string Listener)
    {
        /// <summary>The URL of <paramref name="path"/> on this listener.</summary>
        /// <param name="path">The absolute path, e.g. <c>/health/live</c>.</param>
        public Uri UrlOf(string path)
            => new($"{Scheme}://{(Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]" : Address.ToString())}:{Port}{path}");
    }

    /// <summary>
    /// Reads this host's <c>config.yaml</c> (from <c>--config-dir</c>, or <c>config/</c> under
    /// <paramref name="baseDirectory"/>), works out the roles the command line or <c>Roles</c>
    /// names and the listener to ask, and runs <see cref="CheckAsync"/>. Returns the exit code:
    /// 0 ready (or alive, with <see cref="LiveFlag"/>), 1 otherwise, the reason on one line.
    /// </summary>
    /// <param name="args">The command line.</param>
    /// <param name="baseDirectory">The directory the binary runs from.</param>
    /// <param name="output">Where the verdict goes when ready.</param>
    /// <param name="error">Where the reason goes when not.</param>
    /// <param name="timeout">The limit on the request; <see cref="DefaultTimeout"/> when null.</param>
    public static async Task<int> RunAsync(IReadOnlyList<string> args, string baseDirectory, TextWriter output, TextWriter error, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        var live = IsLiveNamedIn(args);
        var not = live ? "not alive" : "not ready";

        string configDir;
        var at = args.ToList().FindIndex(a => string.Equals(a, ConfigDirFlag, StringComparison.OrdinalIgnoreCase));
        if (at >= 0)
        {
            if (at + 1 >= args.Count || string.IsNullOrWhiteSpace(args[at + 1]) || args[at + 1].StartsWith("--", StringComparison.Ordinal))
            {
                error.WriteLine($"{not}: {ConfigDirFlag} needs a directory. Usage: --role node --check-ready [{LiveFlag}] [{ConfigDirFlag} <dir>]");
                return 1;
            }
            configDir = Path.GetFullPath(args[at + 1]);
        }
        else
        {
            configDir = Path.Combine(baseDirectory, "config");
        }

        var configPath = Path.Combine(configDir, "config.yaml");
        if (!File.Exists(configPath))
        {
            error.WriteLine($"{not}: {configPath} does not exist, so the node is not configured.");
            return 1;
        }
        SystemConfig config;
        try
        {
            config = YamlConfigLoader.Load(configPath, _ => { });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            error.WriteLine($"{not}: {configPath} could not be read: {ex.Message}");
            return 1;
        }
        // As the node applies them, so MODULARCA__HEALTH__LOOPBACKPORT (how the pod sets the
        // health port) is seen here too; silently, since the check prints one line.
        new EnvVarConfigOverlay().Apply(config, TextWriter.Null);

        ProcessRole roles;
        try
        {
            roles = ProcessRoles.Parse(args, config.Roles);
        }
        catch (ArgumentException ex)
        {
            error.WriteLine($"{not}: {ex.Message}");
            return 1;
        }
        if (roles == ProcessRole.Signer)
        {
            error.WriteLine($"{not}: Roles in {configPath} names the signer alone, which serves no health endpoint; check it with --role signer --check-ready.");
            return 1;
        }

        var target = ResolveTarget(config, roles, out var reason);
        if (target == null)
        {
            error.WriteLine($"{not}: {reason}");
            return 1;
        }
        return await CheckAsync(target, live, timeout ?? DefaultTimeout, output, error);
    }

    /// <summary>
    /// The loopback address that reaches a listener bound to <paramref name="listenAddress"/>, one
    /// entry of <c>Https.ListenAddress</c>: <c>127.0.0.1</c> for <c>0.0.0.0</c>, <c>*</c> and
    /// <c>[::]</c> (which Kestrel binds on every interface, dual-stack), <c>::1</c> for <c>::</c>,
    /// a loopback address itself, and null for any other address or one that does not parse.
    /// </summary>
    /// <param name="listenAddress">One entry of the list, as written.</param>
    public static IPAddress? LoopbackFor(string listenAddress)
    {
        var entry = listenAddress.Trim();
        // The forms startup binds with ListenAnyIP.
        if (entry is "0.0.0.0" or "[::]" or "*")
            return IPAddress.Loopback;
        if (entry.StartsWith('[') && entry.EndsWith(']'))
            entry = entry[1..^1];
        if (!IPAddress.TryParse(entry, out var address))
            return null;
        if (address.Equals(IPAddress.Any))
            return IPAddress.Loopback;
        if (address.Equals(IPAddress.IPv6Any))
            return IPAddress.IPv6Loopback;
        return IPAddress.IsLoopback(address) ? address : null;
    }

    /// <summary>
    /// Chooses the listener the probe asks, from the host's settings and the process's roles.
    /// The loopback-only health listener (<c>Health.LoopbackPort</c>) when it is set, and then no
    /// other; without it, in this order: HTTPS without the PROXY protocol; HTTPS with it, when loopback is in
    /// <c>Http.ProxyProtocolTrustedCidrs</c>; then the same two for the plain-HTTP listener,
    /// which this process opens only with the validation or ingress role and a non-zero
    /// <c>Http.Port</c>. Returns null, with the reason, when none can be reached from loopback.
    /// </summary>
    /// <param name="config">This host's settings.</param>
    /// <param name="roles">The roles the probed process runs.</param>
    /// <param name="reason">Why no listener can be asked, when the result is null.</param>
    public static ProbeTarget? ResolveTarget(SystemConfig config, ProcessRole roles, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(config);
        reason = null;

        // The loopback-only health listener, when this host has one: 127.0.0.1, plain HTTP, never
        // the PROXY protocol, whatever the main listeners take.
        var healthPort = config.Health.LoopbackPort;
        if (healthPort is < 0 or > 65535)
        {
            reason = $"Health.LoopbackPort {healthPort} is not a port, so the node does not start with it; "
                   + $"fix it in config.yaml or {EnvVarConfigOverlay.HealthLoopbackPortVariable}.";
            return null;
        }
        if (healthPort > 0)
            return new ProbeTarget("http", IPAddress.Loopback, healthPort, false, "health");

        var listen =string.IsNullOrWhiteSpace(config.Https.ListenAddress) ? "0.0.0.0" : config.Https.ListenAddress;
        var address = listen.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(LoopbackFor)
            .FirstOrDefault(a => a != null);
        if (address == null)
        {
            reason = $"Https.ListenAddress ({listen}) has neither a wildcard nor a loopback address, and the probe connects over loopback only. "
                   + "Add 127.0.0.1 to the list.";
            return null;
        }

        IReadOnlyList<IPNetwork> trusted;
        try
        {
            trusted = ConfigInputRules.TrustedProxyNetworks(config.Http.ProxyProtocolTrustedCidrs, "Http.ProxyProtocolTrustedCidrs");
        }
        catch (FormatException ex)
        {
            reason = ex.Message;
            return null;
        }
        // The address the connection comes from: the family's loopback, whatever loopback address it goes to.
        var source = address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var loopbackTrusted = trusted.Count > 0 && ProxyProtocolConnectionMiddleware.IsTrusted(source, trusted);

        var httpsPort = config.Https.Port;
        var httpOpen = config.Http.Port > 0
            && (roles.HasFlag(ProcessRole.Validation) || roles.HasFlag(ProcessRole.Ingress));

        if (httpsPort > 0 && !config.Https.ProxyProtocol)
            return new ProbeTarget("https", address, httpsPort, false, "HTTPS");
        if (httpsPort > 0 && loopbackTrusted)
            return new ProbeTarget("https", address, httpsPort, true, "HTTPS");
        if (httpOpen && !config.Http.ProxyProtocol)
            return new ProbeTarget("http", address, config.Http.Port, false, "HTTP");
        if (httpOpen && loopbackTrusted)
            return new ProbeTarget("http", address, config.Http.Port, true, "HTTP");

        var listeners = httpOpen
            ? "Both listeners take the PROXY protocol (Https.ProxyProtocol, Http.ProxyProtocol)"
            : "The HTTPS listener takes the PROXY protocol (Https.ProxyProtocol) and this process opens no plain-HTTP listener without it";
        reason = $"{listeners}, and {source} is not in Http.ProxyProtocolTrustedCidrs, so the node closes the probe's connection. "
               + "Set Health.LoopbackPort (or MODULARCA__HEALTH__LOOPBACKPORT) to open the loopback-only health listener, which never takes "
               + "the PROXY protocol, and the probe asks that.";
        return null;
    }

    /// <summary>
    /// Asks <see cref="ReadyPath"/> (or <see cref="LivePath"/> when <paramref name="live"/>) on
    /// <paramref name="target"/> and returns 0 when it answers 200, 1 when it answers anything
    /// else, nothing accepts the connection, or nothing answers within <paramref name="timeout"/>.
    /// </summary>
    /// <param name="target">The listener, from <see cref="ResolveTarget"/>.</param>
    /// <param name="live">Ask whether the process answers rather than whether every check passes.</param>
    /// <param name="timeout">The limit on the connection, the handshake and the response together.</param>
    /// <param name="output">Where the verdict goes when ready.</param>
    /// <param name="error">Where the reason goes when not.</param>
    public static async Task<int> CheckAsync(ProbeTarget target, bool live, TimeSpan timeout, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if (!IPAddress.IsLoopback(target.Address))
            throw new ArgumentException($"The probe connects over loopback only, not to {target.Address}.", nameof(target));

        var (yes, not) = live ? ("alive", "not alive") : ("ready", "not ready");
        var url = target.UrlOf(live ? LivePath : ReadyPath);
        var proxy = target.SendsProxyHeader ? ", with a PROXY v2 LOCAL header" : string.Empty;

        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            ConnectTimeout = timeout,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(target, cancellationToken),
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                // Loopback only (checked above): the probe checks the process, not its certificate.
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None || IPAddress.IsLoopback(target.Address),
            },
        };
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        using var deadline = new CancellationTokenSource(timeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, url) { Version = HttpVersion.Version11 };
        request.Headers.Accept.ParseAdd("application/json");

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or SocketException or AuthenticationException)
        {
            error.WriteLine(Innermost<SocketException>(ex) is { SocketErrorCode: SocketError.ConnectionRefused }
                ? $"{not}: nothing accepts connections on the {target.Listener} listener at {Endpoint(target)} (connection refused)."
                : $"{not}: {url} did not answer{proxy} ({Reason(ex, deadline)}).");
            return 1;
        }

        using (response)
        {
            var status = await StatusFieldAsync(response, deadline.Token);
            var detail = status == null ? string.Empty : $" ({status})";
            if (response.StatusCode == HttpStatusCode.OK)
            {
                output.WriteLine($"{yes}: {url} answered 200{detail}{proxy}.");
                return 0;
            }
            error.WriteLine($"{not}: {url} answered {(int)response.StatusCode}{detail}{proxy}.");
            return 1;
        }
    }

    /// <summary>
    /// Opens the TCP connection to <paramref name="target"/> and, for a listener that takes the
    /// PROXY protocol, writes the v2 <c>LOCAL</c> header before anything else (the TLS
    /// ClientHello or the HTTP request), as a proxy's own health check would.
    /// </summary>
    private static async ValueTask<Stream> ConnectAsync(ProbeTarget target, CancellationToken cancellationToken)
    {
        var socket = new Socket(target.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target.Address, target.Port), cancellationToken);
            var stream = new NetworkStream(socket, ownsSocket: true);
            if (target.SendsProxyHeader)
                await stream.WriteAsync(ProxyV2LocalHeader, cancellationToken);
            return stream;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>The <c>status</c> field of the health endpoint's JSON body, or null when there is none.</summary>
    private static async Task<string?> StatusFieldAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            using var json = JsonDocument.Parse(body);
            return json.RootElement.ValueKind == JsonValueKind.Object
                   && json.RootElement.TryGetProperty("status", out var status)
                   && status.ValueKind == JsonValueKind.String
                ? status.GetString()
                : null;
        }
        catch (Exception ex) when (ex is JsonException or HttpRequestException or IOException or OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>The innermost exception of type <typeparamref name="T"/> in the chain, or null.</summary>
    private static T? Innermost<T>(Exception ex) where T : Exception
    {
        T? found = null;
        for (Exception? e = ex; e != null; e = e.InnerException)
        {
            if (e is T t)
                found = t;
        }
        return found;
    }

    /// <summary>A short reason for a failed request: "timed out", or the innermost message.</summary>
    private static string Reason(Exception ex, CancellationTokenSource deadline)
    {
        if (deadline.IsCancellationRequested || ex is OperationCanceledException)
            return "timed out";
        var inner = ex;
        while (inner.InnerException != null)
            inner = inner.InnerException;
        return inner.Message.TrimEnd('.');
    }

    /// <summary>The address and port as one would type them.</summary>
    private static string Endpoint(ProbeTarget target)
        => target.Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{target.Address}]:{target.Port}" : $"{target.Address}:{target.Port}";
}
