namespace ModularCA.API.Startup;

/// <summary>
/// Controls which source addresses the setup wizard accepts. Private networks are allowed by
/// default; <c>--setup-loopback-only</c> narrows it to the machine itself.
/// </summary>
/// <remarks>
/// <para>
/// This defaulted the other way and it was the wrong default in a way that showed. Three layers
/// gate the wizard and only this one insisted on loopback: Kestrel binds <c>0.0.0.0</c>,
/// <c>IpWhitelistMiddleware</c> admits RFC 1918 plus loopback before the whitelist table is
/// warm, and the startup banner told the operator in as many words that "Setup listener is
/// reachable from RFC1918 networks" — after which <c>SetupController</c> answered 403 to
/// exactly those callers unless an undocumented-looking <c>--setup-local</c> flag had been
/// passed. The product advertised the thing it then refused, and the workaround was an SSH
/// tunnel to reach a web wizard on a machine the operator was already administering.
/// </para>
/// <para>
/// Widening this is a smaller change to the security posture than it appears, because the IP
/// check was never the control that mattered. Setup mode always mints a 32-byte random token,
/// prints it only to the server console, and requires it on every setup request with a
/// constant-time compare and a 30-minute TTL; failures are logged with the caller's address. So
/// the question this class answers is "may you reach the wizard", and the token still decides
/// "may you use it". Reaching it from the LAN without the token gets you a 403 either way.
/// </para>
/// <para>
/// Operators who want the old posture — physical or SSH access required, no LAN reachability at
/// all — pass <c>--setup-loopback-only</c>. That is the right default for a CA on a hostile
/// network, and the wrong one for the overwhelmingly common case of standing up a server on an
/// internal subnet from a laptop on the same subnet.
/// </para>
/// </remarks>
internal static class SetupNetworkMode
{
    private static bool _allowPrivateNetworks = true;

    /// <summary>
    /// Narrows the wizard to loopback only. Called from startup when
    /// <c>--setup-loopback-only</c> is present.
    /// </summary>
    public static void RestrictToLoopback() => _allowPrivateNetworks = false;

    /// <summary>
    /// Enables access from private network addresses. Retained because <c>--setup-local</c>
    /// used to be required for this and may still appear in scripts and runbooks; it is now the
    /// default and the flag is a no-op.
    /// </summary>
    public static void AllowPrivateNetworks() => _allowPrivateNetworks = true;

    /// <summary>
    /// True when the wizard accepts callers from private networks as well as loopback.
    /// </summary>
    public static bool IsPrivateNetworkAllowed => _allowPrivateNetworks;
}
