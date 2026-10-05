using System.Security.Cryptography.X509Certificates;
using ModularCA.Shared.Models.Config;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Startup;

/// <summary>
/// The identity bootstrap of the signer channel, run on the signer role:
/// <c>--role signer --init-identity</c> creates the identity CA and the signer's server
/// certificate into the signer's config directory; <c>--role signer --issue-node-identity
/// &lt;dir&gt;</c> issues a node's client certificate into <c>dir</c> beside a
/// <c>signer-pin.txt</c> carrying the server's SPKI pin, for the operator to place in the
/// node's config. Every file is PKCS#12 under the password the configuration names for it,
/// written owner-only.
/// </summary>
public static class SignerIdentityCommands
{
    /// <summary>The flag that creates the identity CA and the server certificate.</summary>
    public const string InitFlag = "--init-identity";

    /// <summary>The flag that issues a node identity; takes the output directory.</summary>
    public const string IssueNodeFlag = "--issue-node-identity";

    /// <summary>Optional with <see cref="InitFlag"/>: the name or address the node dials, for the server certificate's SAN, when it is not the host of <c>Signer.Listen</c>.</summary>
    public const string HostFlag = "--host";

    /// <summary>Optional with <see cref="IssueNodeFlag"/>: the password of the node's PKCS#12, when it is not <c>Signer.ClientCertificatePassword</c>.</summary>
    public const string ClientPasswordFlag = "--client-password";

    /// <summary>Optional with <see cref="InitFlag"/>: replace an existing identity CA, which invalidates every node identity it issued.</summary>
    public const string ForceFlag = "--force";

    /// <summary>
    /// Optional with <see cref="IssueNodeFlag"/>: write the result into the named config.yaml
    /// instead of printing it for an operator to transcribe. Takes the path to the file.
    /// <para>
    /// Both halves of the channel — the node's client certificate, endpoint and server pin, and
    /// the signer's client pin — land in the one <c>Signer:</c> section, because a container pod
    /// shares one config volume between the node and the signer and each process reads the keys
    /// meant for it. The output directory becomes the file's directory, so the certificate is
    /// where <c>ClientCertificate</c> says it is.
    /// </para>
    /// <para>
    /// Idempotent, which is what makes it usable as an init container: when the file already
    /// names a remote signer, the client certificate exists, and both pins are set, it does
    /// nothing and exits zero. <see cref="ForceFlag"/> reissues regardless.
    /// </para>
    /// </summary>
    public const string ApplyFlag = "--apply";

    /// <summary>The file the node's client certificate is written to under the output directory.</summary>
    public const string ClientFileName = "signer-client.pfx";

    /// <summary>The file the server's SPKI pin is written to under the output directory.</summary>
    public const string PinFileName = "signer-pin.txt";

    /// <summary>Whether the command line names one of the identity commands.</summary>
    public static bool IsIdentityCommand(IReadOnlyList<string> args)
        => args.Any(a => a.Equals(InitFlag, StringComparison.OrdinalIgnoreCase) || a.Equals(IssueNodeFlag, StringComparison.OrdinalIgnoreCase));

    /// <summary>Runs the identity command the arguments name and returns the exit code.</summary>
    public static int Run(IReadOnlyList<string> args, SignerConfig signer, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(signer);
        try
        {
            if (args.Any(a => a.Equals(InitFlag, StringComparison.OrdinalIgnoreCase)))
                return InitIdentity(args, signer, baseDirectory);
            return IssueNodeIdentity(args, signer, baseDirectory);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine($"[FATAL] {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Creates the identity CA (ECDSA P-256, self-signed, ten years) and the server certificate
    /// with the listen host as its SAN, into the paths <c>Signer.IdentityCa</c> and
    /// <c>Signer.ServerCertificate</c> name. Refuses to replace an existing CA without
    /// <see cref="ForceFlag"/>, since every node identity it issued would stop matching.
    /// </summary>
    private static int InitIdentity(IReadOnlyList<string> args, SignerConfig signer, string baseDirectory)
    {
        var caPath = SignerConfig.ResolvePath(signer.IdentityCa, baseDirectory);
        var serverPath = SignerConfig.ResolvePath(signer.ServerCertificate, baseDirectory);
        var force = args.Any(a => a.Equals(ForceFlag, StringComparison.OrdinalIgnoreCase));
        if (File.Exists(caPath) && !force)
        {
            Console.Error.WriteLine($"[FATAL] The identity CA already exists at {caPath}.");
            Console.Error.WriteLine($"        Pass {ForceFlag} to replace it; every node identity it issued then has to be reissued and re-pinned.");
            return 1;
        }

        var host = ValueOf(args, HostFlag);
        if (host == null)
        {
            var (address, _) = SignerServerOptions.ParseListen(signer.Listen);
            host = address.ToString();
            if (System.Net.IPAddress.IsLoopback(address))
                host = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "::1" : "127.0.0.1";
            else if (address.Equals(System.Net.IPAddress.Any) || address.Equals(System.Net.IPAddress.IPv6Any))
            {
                Console.Error.WriteLine($"[FATAL] Signer.Listen binds every interface; pass {HostFlag} <name-or-address> so the server certificate names what the node dials.");
                return 1;
            }
        }

        var now = DateTimeOffset.UtcNow;
        using var ca = SignerIdentity.CreateIdentityCa(now);
        using var server = SignerIdentity.IssueServerCertificate(ca, host, now);
        Pkcs12Files.Write(caPath, ca, null, signer.IdentityCaPassword);
        Pkcs12Files.Write(serverPath, server, new[] { ca }, signer.ServerCertificatePassword);

        Console.WriteLine("Signer identity created.");
        Console.WriteLine($"  Identity CA:        {caPath}  ({SignerIdentity.IdentityCaSubject}, valid until {ca.NotAfter:yyyy-MM-dd})");
        Console.WriteLine($"  Server certificate: {serverPath}  (SAN {host}, valid until {server.NotAfter:yyyy-MM-dd})");
        Console.WriteLine($"  Server SPKI pin:    {SpkiPin.Compute(server)}");
        Console.WriteLine();
        Console.WriteLine($"Next: issue the node its identity with  --role signer {IssueNodeFlag} <output-dir>");
        return 0;
    }

    /// <summary>
    /// Issues a node client certificate (one year) under the identity CA into the output
    /// directory as <see cref="ClientFileName"/>, writes the server's pin beside it as
    /// <see cref="PinFileName"/>, and prints the client's pin for <c>Signer.PinnedClientSpki</c>
    /// on the signer and the keys the node's config needs.
    /// </summary>
    private static int IssueNodeIdentity(IReadOnlyList<string> args, SignerConfig signer, string baseDirectory)
    {
        var applyTo = ValueOf(args, ApplyFlag);
        var outputDir = ValueOf(args, IssueNodeFlag);
        if (applyTo is not null)
        {
            // With --apply the certificate goes beside the config it is named in.
            outputDir = Path.GetDirectoryName(Path.GetFullPath(applyTo)) ?? ".";
            if (!File.Exists(applyTo))
            {
                Console.Error.WriteLine($"[FATAL] {ApplyFlag}: no config.yaml at {applyTo}.");
                return 1;
            }

            var force = args.Any(a => a.Equals(ForceFlag, StringComparison.OrdinalIgnoreCase));
            if (!force && AlreadyApplied(applyTo, outputDir))
            {
                Console.WriteLine($"Node identity already applied in {applyTo}; nothing to do.");
                return 0;
            }
        }
        if (string.IsNullOrWhiteSpace(outputDir))
        {
            Console.Error.WriteLine($"Usage: --role signer {IssueNodeFlag} <output-dir> [{ClientPasswordFlag} <password>]");
            Console.Error.WriteLine($"   or: --role signer {IssueNodeFlag} {ApplyFlag} <config.yaml>");
            return 1;
        }
        var caPath = SignerConfig.ResolvePath(signer.IdentityCa, baseDirectory);
        var serverPath = SignerConfig.ResolvePath(signer.ServerCertificate, baseDirectory);
        if (!File.Exists(caPath) || !File.Exists(serverPath))
        {
            Console.Error.WriteLine($"[FATAL] No signer identity at {caPath}; run  --role signer {InitFlag}  first.");
            return 1;
        }

        using var ca = Pkcs12Files.Load(caPath, signer.IdentityCaPassword);
        using var server = Pkcs12Files.Load(serverPath, signer.ServerCertificatePassword);
        var clientPassword = ValueOf(args, ClientPasswordFlag) ?? signer.ClientCertificatePassword;

        Directory.CreateDirectory(outputDir);
        using var client = SignerIdentity.IssueClientCertificate(ca, DateTimeOffset.UtcNow);
        var clientPath = Path.Combine(outputDir, ClientFileName);
        var pinPath = Path.Combine(outputDir, PinFileName);
        Pkcs12Files.Write(clientPath, client, new[] { ca }, clientPassword);
        var serverPin = SpkiPin.Compute(server);
        File.WriteAllText(pinPath, serverPin + Environment.NewLine);
        var clientPin = SpkiPin.Compute(client);

        var (listenAddress, listenPort) = SignerServerOptions.ParseListen(signer.Listen);
        var dialHost = DialHostOf(server)
            ?? (System.Net.IPAddress.IsLoopback(listenAddress) ? "127.0.0.1" : listenAddress.ToString());

        Console.WriteLine("Node identity issued.");
        Console.WriteLine($"  Client certificate: {clientPath}  ({SignerIdentity.NodeSubject}, valid until {client.NotAfter:yyyy-MM-dd})");
        Console.WriteLine($"  Server pin:         {pinPath}");
        Console.WriteLine();

        if (applyTo is not null)
        {
            return ApplyToConfig(applyTo, signer, dialHost, listenPort, clientPin, serverPin, clientPassword);
        }

        Console.WriteLine("On the signer, set in config.yaml and restart the signer unit:");
        Console.WriteLine("  Signer:");
        Console.WriteLine($"    PinnedClientSpki: \"{clientPin}\"");
        Console.WriteLine();
        Console.WriteLine($"On the node, place {ClientFileName} in its config directory and set:");
        Console.WriteLine("  Signer:");
        Console.WriteLine("    Mode: \"Remote\"");
        Console.WriteLine($"    Endpoint: \"https://{dialHost}:{listenPort}\"");
        Console.WriteLine($"    ClientCertificate: \"config/{ClientFileName}\"");
        Console.WriteLine($"    ClientCertificatePassword: \"{(string.IsNullOrEmpty(clientPassword) ? string.Empty : "<the password given>")}\"");
        Console.WriteLine($"    PinnedServerSpki: \"{serverPin}\"");
        Console.WriteLine();
        Console.WriteLine("The node's keystore.yaml and keystores/ are not needed on the node once the signer holds them.");
        return 0;
    }

    /// <summary>
    /// Writes both halves of the channel into the one <c>Signer:</c> section of a config.yaml,
    /// leaving every other section untouched, and proves the result by loading it back. The file
    /// is rewritten in place (<see cref="ConfigYamlWriter.WriteKeepingAccess"/>), so on a split
    /// install it keeps the signer's group read; the copy kept beside it is owner-only.
    /// </summary>
    private static int ApplyToConfig(
        string configPath, SignerConfig current, string dialHost, int listenPort,
        string clientPin, string serverPin, string clientPassword)
    {
        var section = new SignerConfig
        {
            // The node's half.
            Mode = SignerConfig.RemoteMode,
            Endpoint = $"https://{dialHost}:{listenPort}",
            ClientCertificate = "config/" + ClientFileName,
            ClientCertificatePassword = clientPassword,
            PinnedServerSpki = serverPin,
            // The signer's half, carried over so nothing the signer needs is lost.
            Listen = current.Listen,
            ServerCertificate = current.ServerCertificate,
            ServerCertificatePassword = current.ServerCertificatePassword,
            PinnedClientSpki = clientPin,
            IdentityCa = current.IdentityCa,
            IdentityCaPassword = current.IdentityCaPassword,
        };

        var backup = configPath + $".pre-signer-{DateTime.UtcNow:yyyyMMdd-HHmmss}.bak";
        var original = File.ReadAllText(configPath);
        if (File.Exists(backup))
            throw new IOException($"{backup} already exists.");
        ConfigYamlWriter.WriteKeepingAccess(backup, original);

        ConfigYamlWriter.WriteKeepingAccess(configPath, YamlSectionSplicer.Replace(original, "Signer", section));

        var reloaded = YamlConfigLoader.Load(configPath).Signer;
        if (!reloaded.IsRemote
            || !string.Equals(reloaded.PinnedClientSpki, clientPin, StringComparison.Ordinal)
            || !string.Equals(reloaded.PinnedServerSpki, serverPin, StringComparison.Ordinal))
        {
            ConfigYamlWriter.WriteKeepingAccess(configPath, original);
            Console.Error.WriteLine($"[FATAL] {configPath} did not load back with the Signer section as written; restored from {backup}.");
            return 1;
        }

        Console.WriteLine($"Applied to {configPath} (previous copy at {backup}).");
        Console.WriteLine("  The node reads Mode, Endpoint, ClientCertificate and PinnedServerSpki from it;");
        Console.WriteLine("  the signer reads Listen, ServerCertificate and PinnedClientSpki. Restart both.");
        return 0;
    }

    /// <summary>
    /// Whether a config already names a remote signer with both pins set and the client
    /// certificate present — the state <see cref="ApplyFlag"/> produces.
    /// </summary>
    private static bool AlreadyApplied(string configPath, string configDir)
    {
        try
        {
            var signer = YamlConfigLoader.Load(configPath).Signer;
            return signer.IsRemote
                && SpkiPin.Normalize(signer.PinnedClientSpki) is not null
                && SpkiPin.Normalize(signer.PinnedServerSpki) is not null
                && File.Exists(Path.Combine(configDir, ClientFileName));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// The name the node dials, from the server certificate's subject alternative name: the
    /// DNS name or the IP address <c>--init-identity</c> put there. Null when it has none.
    /// </summary>
    private static string? DialHostOf(X509Certificate2 server)
    {
        var san = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san == null) return null;
        var dns = san.EnumerateDnsNames().FirstOrDefault();
        if (dns != null) return dns;
        var ip = san.EnumerateIPAddresses().FirstOrDefault();
        if (ip == null) return null;
        return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]" : ip.ToString();
    }

    /// <summary>The value following <paramref name="flag"/>, or null when the flag is absent or bare.</summary>
    private static string? ValueOf(IReadOnlyList<string> args, string flag)
    {
        for (var i = 0; i < args.Count - 1; i++)
        {
            if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase) && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                return args[i + 1];
        }
        return null;
    }
}
