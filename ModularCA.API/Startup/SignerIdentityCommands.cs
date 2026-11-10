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
/// written owner-only. <c>--init-identity</c> is safe to repeat: an identity already in place
/// and consistent is left alone and the command exits zero.
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

    /// <summary>
    /// Optional with <see cref="InitFlag"/>: replace an existing identity CA (or a partial one),
    /// which invalidates every node identity it issued. Without it an existing identity is never
    /// replaced: a consistent one is left as it is, an inconsistent one is refused.
    /// </summary>
    public const string ForceFlag = "--force";

    /// <summary>
    /// Optional with <see cref="IssueNodeFlag"/>: write the result into the named config.yaml
    /// instead of printing it for an operator to transcribe. Takes the path to the node's file.
    /// <para>
    /// The node's half of the channel (its client certificate, the endpoint and the server pin)
    /// goes into the named file's <c>Signer:</c> section, and the client certificate beside it,
    /// so it is where <c>ClientCertificate</c> says. The signer's half (the client pin) goes
    /// where the signer reads it: with <c>--signer-dir</c>, into the <c>Signer:</c> section of
    /// that directory's <c>signer.yaml</c>, which is how the pod runs it, with the node's config
    /// volume and the signer's both mounted; without it, into the same section of the same file,
    /// for a layout where both processes read one <c>config.yaml</c>.
    /// </para>
    /// <para>
    /// Idempotent, which is what makes it usable as an init container: when the node's file
    /// already names a remote signer, the client certificate exists, and both pins are set (with
    /// <c>--signer-dir</c>: and match the server certificate and the client certificate), it does
    /// nothing and exits zero. <see cref="ForceFlag"/> reissues regardless.
    /// </para>
    /// <para>
    /// With <c>--signer-dir</c>, once the pins are in place (applied now or found applied), it
    /// also takes out of the node's config directory what the signer's directory holds a
    /// verified copy of: <c>keystore.yaml</c>, the identity files and the signer's settings in
    /// <c>config.yaml</c> (<see cref="NodeSideSignerCleanup"/>). That never changes the exit code.
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

    /// <summary>Runs the identity command the arguments name in the shared layout under <paramref name="baseDirectory"/> and returns the exit code.</summary>
    public static int Run(IReadOnlyList<string> args, SignerConfig signer, string baseDirectory)
        => Run(args, signer, SignerPaths.Shared(baseDirectory));

    /// <summary>
    /// Runs the identity command the arguments name and returns the exit code. The identity
    /// files resolve through <paramref name="paths"/>: under the application directory in the
    /// shared layout, into the signer's own directory with <c>--signer-dir</c>.
    /// </summary>
    public static int Run(IReadOnlyList<string> args, SignerConfig signer, SignerPaths paths)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(paths);
        try
        {
            if (args.Any(a => a.Equals(InitFlag, StringComparison.OrdinalIgnoreCase)))
                return InitIdentity(args, signer, paths);
            return IssueNodeIdentity(args, signer, paths);
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
    /// <c>Signer.ServerCertificate</c> name. With <c>--signer-dir</c> both files go into the
    /// signer's directory.
    /// <para>
    /// Safe to repeat, which is what lets the pod run it as an init container on every start:
    /// when both files exist and agree (<see cref="CheckExisting"/>) it changes nothing and exits
    /// zero. It never replaces an existing CA without <see cref="ForceFlag"/>, since every node
    /// identity it issued would stop matching, and it exits non-zero, changing nothing, when what
    /// it finds is partial or inconsistent: one file without the other, a file it cannot open, a
    /// server certificate the CA did not issue, or one that has expired or names another host.
    /// </para>
    /// </summary>
    private static int InitIdentity(IReadOnlyList<string> args, SignerConfig signer, SignerPaths paths)
    {
        var caPath = paths.ResolveFile(signer.IdentityCa);
        var serverPath = paths.ResolveFile(signer.ServerCertificate);
        var force = args.Any(a => a.Equals(ForceFlag, StringComparison.OrdinalIgnoreCase));

        var host = ValueOf(args, HostFlag);
        string? hostProblem = null;
        if (host == null)
        {
            var (address, _) = SignerServerOptions.ParseListen(signer.Listen);
            host = address.ToString();
            if (System.Net.IPAddress.IsLoopback(address))
                host = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "::1" : "127.0.0.1";
            else if (address.Equals(System.Net.IPAddress.Any) || address.Equals(System.Net.IPAddress.IPv6Any))
            {
                hostProblem = $"Signer.Listen binds every interface; pass {HostFlag} <name-or-address> so the server certificate names what the node dials.";
                host = null;
            }
        }

        if (!force && (File.Exists(caPath) || File.Exists(serverPath)))
        {
            // With a Listen on every interface and no --host there is no expected name to compare
            // the existing certificate with, and the name it carries stands.
            var problem = CheckExisting(caPath, serverPath, signer, host, out var summary);
            if (problem != null)
            {
                Console.Error.WriteLine($"[FATAL] {problem}");
                Console.Error.WriteLine($"        Nothing was changed. Put the files right, or pass {ForceFlag} to create both again;");
                Console.Error.WriteLine("        every node identity the old CA issued then has to be reissued and re-pinned.");
                return 1;
            }
            Console.WriteLine("Signer identity already present; nothing was changed.");
            Console.WriteLine(summary);
            return 0;
        }

        if (host == null)
        {
            Console.Error.WriteLine($"[FATAL] {hostProblem}");
            return 1;
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
        Console.WriteLine($"Next: issue the node its identity with  {RoleArgs(paths)} {IssueNodeFlag} <output-dir>");
        return 0;
    }

    /// <summary>
    /// Checks an identity that is already on disk and returns what is wrong with it, or null when
    /// it is whole: both files present and opening under their configured passwords, each with
    /// its private key, the CA being the identity CA and the server certificate issued and signed
    /// by it, neither expired, and the server certificate naming <paramref name="expectedHost"/>
    /// when that is known. <paramref name="summary"/> describes a whole identity for the log.
    /// </summary>
    /// <param name="caPath">Where <c>Signer.IdentityCa</c> resolves.</param>
    /// <param name="serverPath">Where <c>Signer.ServerCertificate</c> resolves.</param>
    /// <param name="signer">The signer settings, for the two passwords.</param>
    /// <param name="expectedHost">The name or address the server certificate must carry; null to accept the one it has.</param>
    /// <param name="summary">The paths, validity and server pin, when the identity is whole; empty otherwise.</param>
    internal static string? CheckExisting(string caPath, string serverPath, SignerConfig signer, string? expectedHost, out string summary)
    {
        summary = string.Empty;
        if (!File.Exists(caPath))
            return $"The server certificate exists at {serverPath} but the identity CA that issued it is missing from {caPath}.";
        if (!File.Exists(serverPath))
            return $"The identity CA exists at {caPath} but the server certificate is missing from {serverPath}.";

        X509Certificate2 ca;
        try
        {
            ca = Pkcs12Files.Load(caPath, signer.IdentityCaPassword);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            return $"The identity CA at {caPath} cannot be opened with Signer.IdentityCaPassword: {ex.Message}";
        }
        using (ca)
        {
            X509Certificate2 server;
            try
            {
                server = Pkcs12Files.Load(serverPath, signer.ServerCertificatePassword);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                return $"The server certificate at {serverPath} cannot be opened with Signer.ServerCertificatePassword: {ex.Message}";
            }
            using (server)
            {
                var now = DateTime.UtcNow;
                if (!ca.HasPrivateKey)
                    return $"{caPath} holds no private key, so it cannot issue node identities.";
                if (!string.Equals(ca.Subject, SignerIdentity.IdentityCaSubject, StringComparison.Ordinal))
                    return $"{caPath} holds \"{ca.Subject}\", not the signer identity CA.";
                if (ca.NotAfter.ToUniversalTime() <= now)
                    return $"The identity CA at {caPath} expired on {ca.NotAfter:yyyy-MM-dd}.";
                if (!server.HasPrivateKey)
                    return $"{serverPath} holds no private key, so the signer cannot listen with it.";
                if (!IssuedBy(server, ca))
                    return $"The server certificate at {serverPath} was not issued by the identity CA at {caPath}.";
                if (server.NotAfter.ToUniversalTime() <= now)
                    return $"The server certificate at {serverPath} expired on {server.NotAfter:yyyy-MM-dd}.";
                if (expectedHost != null && !NamesHost(server, expectedHost))
                    return $"The server certificate at {serverPath} names {DialHostOf(server) ?? "no host"}, not {expectedHost}, "
                        + $"which is what {HostFlag} or Signer.Listen says the node dials.";

                summary = $"  Identity CA:        {caPath}  ({ca.Subject}, valid until {ca.NotAfter:yyyy-MM-dd})"
                    + Environment.NewLine
                    + $"  Server certificate: {serverPath}  (SAN {DialHostOf(server)}, valid until {server.NotAfter:yyyy-MM-dd})"
                    + Environment.NewLine
                    + $"  Server SPKI pin:    {SpkiPin.Compute(server)}";
                return null;
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="issuer"/> issued and signed <paramref name="certificate"/>: a chain
    /// built with the issuer as its only trust anchor, so a certificate that only copies the
    /// issuer's name does not pass. Revocation is not checked; the identity CA publishes none.
    /// Also used by <see cref="NodeSideSignerCleanup"/> for the node's client certificate.
    /// </summary>
    internal static bool IssuedBy(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        using var anchor = X509CertificateLoader.LoadCertificate(issuer.RawData);
        using var leaf = X509CertificateLoader.LoadCertificate(certificate.RawData);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(anchor);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = DateTime.Now;
        if (!chain.Build(leaf))
            return false;
        return chain.ChainElements.Count == 2
            && chain.ChainElements[1].Certificate.RawData.AsSpan().SequenceEqual(issuer.RawData);
    }

    /// <summary>Whether the server certificate's subject alternative name carries <paramref name="host"/>, as a DNS name or an IP address.</summary>
    private static bool NamesHost(X509Certificate2 server, string host)
    {
        var san = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san == null)
            return false;
        var bare = host.Trim('[', ']');
        if (System.Net.IPAddress.TryParse(bare, out var address))
            return san.EnumerateIPAddresses().Any(a => a.Equals(address));
        return san.EnumerateDnsNames().Any(d => string.Equals(d, host, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The role arguments to repeat in a printed command: <c>--role signer</c>, with <c>--signer-dir</c> when one is in use.</summary>
    private static string RoleArgs(SignerPaths paths)
        => paths.IsDedicated ? $"--role signer {SignerPaths.Flag} {paths.SignerDirectory}" : "--role signer";

    /// <summary>
    /// Issues a node client certificate (one year) under the identity CA into the output
    /// directory as <see cref="ClientFileName"/>, writes the server's pin beside it as
    /// <see cref="PinFileName"/>, and prints the client's pin for <c>Signer.PinnedClientSpki</c>
    /// on the signer and the keys the node's config needs. <see cref="ApplyFlag"/> writes them
    /// instead: the node's half into the named config.yaml, the signer's into its own
    /// <c>signer.yaml</c> with <c>--signer-dir</c> (<see cref="ApplyApart"/>), or into the same
    /// file without it (<see cref="ApplyToConfig"/>). With <c>--signer-dir</c>, once both halves
    /// are in place, <see cref="NodeSideSignerCleanup"/> removes the signer's files and settings
    /// from the node's config directory where the signer's directory holds a verified copy.
    /// </summary>
    private static int IssueNodeIdentity(IReadOnlyList<string> args, SignerConfig signer, SignerPaths paths)
    {
        var applyTo = ValueOf(args, ApplyFlag);
        var outputDir = ValueOf(args, IssueNodeFlag);
        SignerConfig? nodeSigner = null;
        if (applyTo is not null)
        {
            // With --apply the certificate goes beside the config it is named in.
            outputDir = Path.GetDirectoryName(Path.GetFullPath(applyTo)) ?? ".";
            if (!File.Exists(applyTo))
            {
                Console.Error.WriteLine($"[FATAL] {ApplyFlag}: no config.yaml at {applyTo}.");
                return 1;
            }
            if (paths.IsDedicated)
            {
                if (!File.Exists(paths.ConfigPath))
                {
                    Console.Error.WriteLine($"[FATAL] {ApplyFlag} writes the signer's pin into {paths.ConfigPath}, which does not exist.");
                    Console.Error.WriteLine($"        Fill the directory first: {RoleArgs(paths)} {SignerDirectoryMigration.Flag}.");
                    return 1;
                }
                try
                {
                    nodeSigner = YamlConfigLoader.Load(applyTo).Signer;
                }
                catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException)
                {
                    Console.Error.WriteLine($"[FATAL] {ApplyFlag}: {applyTo} could not be read: {ex.Message}");
                    return 1;
                }
            }

            var force = args.Any(a => a.Equals(ForceFlag, StringComparison.OrdinalIgnoreCase));
            if (!force && (nodeSigner is not null ? AlreadyAppliedApart(nodeSigner, outputDir, signer, paths) : AlreadyApplied(applyTo, outputDir)))
            {
                Console.WriteLine(nodeSigner is not null
                    ? $"Node identity already applied in {applyTo} and {paths.ConfigPath}, and the pins match the certificates; nothing to do."
                    : $"Node identity already applied in {applyTo}; nothing to do.");
                // A pod upgraded from 0.4.3 lands here at its first start, with the signer's
                // files and settings still in the node's config directory.
                if (nodeSigner is not null)
                    NodeSideSignerCleanup.Run(applyTo, paths, Console.Out, Console.Error);
                return 0;
            }
        }
        if (string.IsNullOrWhiteSpace(outputDir))
        {
            Console.Error.WriteLine($"Usage: --role signer {IssueNodeFlag} <output-dir> [{ClientPasswordFlag} <password>]");
            Console.Error.WriteLine($"   or: --role signer {IssueNodeFlag} {ApplyFlag} <config.yaml>");
            return 1;
        }
        var caPath = paths.ResolveFile(signer.IdentityCa);
        var serverPath = paths.ResolveFile(signer.ServerCertificate);
        if (!File.Exists(caPath) || !File.Exists(serverPath))
        {
            Console.Error.WriteLine($"[FATAL] No signer identity at {caPath}; run  {RoleArgs(paths)} {InitFlag}  first.");
            return 1;
        }

        using var ca = Pkcs12Files.Load(caPath, signer.IdentityCaPassword);
        using var server = Pkcs12Files.Load(serverPath, signer.ServerCertificatePassword);
        // With the signer apart, the node's password for its certificate is in the node's file.
        var clientPassword = ValueOf(args, ClientPasswordFlag) ?? nodeSigner?.ClientCertificatePassword ?? signer.ClientCertificatePassword;

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
            if (!paths.IsDedicated)
                return ApplyToConfig(applyTo, signer, dialHost, listenPort, clientPin, serverPin, clientPassword);
            var applied = ApplyApart(applyTo, paths.ConfigPath, signer, dialHost, listenPort, clientPin, serverPin, clientPassword);
            if (applied == 0)
                NodeSideSignerCleanup.Run(applyTo, paths, Console.Out, Console.Error);
            return applied;
        }

        Console.WriteLine($"On the signer, set in {(paths.IsDedicated ? paths.ConfigPath : "config.yaml")} and restart the signer unit:");
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
    /// Writes the two halves of the channel into the two files that hold them when the signer has
    /// its own directory: the node's half (<c>Mode</c>, <c>Endpoint</c>, <c>ClientCertificate</c>
    /// and its password, <c>PinnedServerSpki</c>) as the whole <c>Signer:</c> section of the
    /// node's config.yaml, and the signer's half, with the new <c>PinnedClientSpki</c>, as the
    /// whole <c>Signer:</c> section of <c>signer.yaml</c>. Every other section of either file is
    /// left alone. Each file is copied beside itself first, both are loaded back, and both are
    /// restored when either does not read as written, so the two never disagree. The copy of the
    /// node's file leaves out the signer's settings and secrets
    /// (<see cref="NodeSideSignerCleanup.BackupContents"/>), which <c>signer.yaml</c> holds.
    /// </summary>
    private static int ApplyApart(
        string nodeConfigPath, string signerConfigPath, SignerConfig current, string dialHost, int listenPort,
        string clientPin, string serverPin, string clientPassword)
    {
        // Dictionaries keep the keys in this order and exactly as spelled.
        var nodeSection = new Dictionary<string, object>
        {
            ["Mode"] = SignerConfig.RemoteMode,
            ["Endpoint"] = $"https://{dialHost}:{listenPort}",
            ["ClientCertificate"] = "config/" + ClientFileName,
            ["ClientCertificatePassword"] = clientPassword,
            ["PinnedServerSpki"] = serverPin,
        };
        var signerSection = new Dictionary<string, object>
        {
            ["Listen"] = current.Listen,
            ["ServerCertificate"] = current.ServerCertificate,
            ["ServerCertificatePassword"] = current.ServerCertificatePassword,
            ["PinnedClientSpki"] = clientPin,
            ["IdentityCa"] = current.IdentityCa,
            ["IdentityCaPassword"] = current.IdentityCaPassword,
        };

        var stamp = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        var nodeBackup = nodeConfigPath + $".pre-signer-{stamp}.bak";
        var signerBackup = signerConfigPath + $".pre-signer-{stamp}.bak";
        for (var n = 2; File.Exists(nodeBackup) || File.Exists(signerBackup); n++)
        {
            nodeBackup = nodeConfigPath + $".pre-signer-{stamp}-{n}.bak";
            signerBackup = signerConfigPath + $".pre-signer-{stamp}-{n}.bak";
        }
        var nodeOriginal = File.ReadAllText(nodeConfigPath);
        var signerOriginal = File.ReadAllText(signerConfigPath);
        // The node's copy leaves out the signer's settings, secrets included: they are in
        // signer.yaml, and a copy in the node's directory would keep them where the node can read
        // them. A failure below restores from nodeOriginal, not from this copy.
        ConfigYamlWriter.WriteKeepingAccess(nodeBackup, NodeSideSignerCleanup.BackupContents(nodeOriginal, signerConfigPath));
        ConfigYamlWriter.WriteKeepingAccess(signerBackup, signerOriginal);

        string? failure = null;
        try
        {
            ConfigYamlWriter.WriteKeepingAccess(nodeConfigPath, YamlSectionSplicer.Replace(nodeOriginal, "Signer", nodeSection));
            ConfigYamlWriter.WriteKeepingAccess(signerConfigPath, YamlSectionSplicer.Replace(signerOriginal, "Signer", signerSection));
            var node = YamlConfigLoader.Load(nodeConfigPath).Signer;
            var signer = YamlConfigLoader.Load(signerConfigPath).Signer;
            if (!node.IsRemote
                || !string.Equals(node.PinnedServerSpki, serverPin, StringComparison.Ordinal)
                || !string.Equals(signer.PinnedClientSpki, clientPin, StringComparison.Ordinal)
                || !string.Equals(signer.Listen, current.Listen, StringComparison.Ordinal)
                || !string.Equals(signer.ServerCertificate, current.ServerCertificate, StringComparison.Ordinal))
                failure = "did not load back with the Signer sections as written";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            failure = ex.Message;
        }
        if (failure != null)
        {
            ConfigYamlWriter.WriteKeepingAccess(nodeConfigPath, nodeOriginal);
            ConfigYamlWriter.WriteKeepingAccess(signerConfigPath, signerOriginal);
            Console.Error.WriteLine($"[FATAL] {nodeConfigPath} and {signerConfigPath}: {failure}; both restored as they were.");
            return 1;
        }

        Console.WriteLine($"Applied to {nodeConfigPath} (previous copy at {nodeBackup}):");
        Console.WriteLine("  the node's half: Mode, Endpoint, ClientCertificate and PinnedServerSpki.");
        Console.WriteLine($"Applied to {signerConfigPath} (previous copy at {signerBackup}):");
        Console.WriteLine("  the signer's half, with the new PinnedClientSpki. Restart both.");
        return 0;
    }

    /// <summary>
    /// Whether the node's file and the signer's already hold a channel that works: the node's
    /// names a remote signer and pins the public key of the signer's server certificate, its
    /// client certificate is beside it and opens under its password, and the signer's pins that
    /// certificate's public key. Anything else, a pin left over from an identity CA that was
    /// replaced included, is not applied, and the node is issued a certificate again.
    /// </summary>
    private static bool AlreadyAppliedApart(SignerConfig node, string nodeDir, SignerConfig signer, SignerPaths paths)
    {
        try
        {
            var clientPath = Path.Combine(nodeDir, ClientFileName);
            if (!node.IsRemote || !File.Exists(clientPath))
                return false;
            using var server = Pkcs12Files.Load(paths.ResolveFile(signer.ServerCertificate), signer.ServerCertificatePassword);
            using var client = Pkcs12Files.Load(clientPath, node.ClientCertificatePassword);
            return SpkiPin.Matches(server, node.PinnedServerSpki) && SpkiPin.Matches(client, signer.PinnedClientSpki);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
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
