using System.Net.Mail;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Save-time checks for settings written through PUT /admin/config/* or the settings store
/// (<see cref="StoredSettingError"/>). Each method returns null when the value is acceptable,
/// otherwise a message for a 400 response or a refused write.
/// </summary>
public static class ConfigInputRules
{
    /// <summary>Largest expiry warning mark accepted, in days (ten years).</summary>
    public const int MaxWarningDays = 3650;

    /// <summary>
    /// Validates the expiry-notification day marks: each from 1 to <see cref="MaxWarningDays"/>.
    /// Zero or a negative mark would match certificates that have already expired or never fire.
    /// Null means "not supplied".
    /// </summary>
    /// <param name="days">The marks from the request body.</param>
    public static string? WarningDaysError(IEnumerable<int>? days)
    {
        if (days == null) return null;
        var bad = days.Where(d => d < 1 || d > MaxWarningDays).ToList();
        return bad.Count == 0
            ? null
            : $"WarningDays must each be from 1 to {MaxWarningDays}; got {string.Join(", ", bad)}.";
    }

    /// <summary>
    /// Validates a comma-separated recipient list as the mail senders split it (comma, entries
    /// trimmed, blanks dropped): every entry must parse as a mail address. Null or empty means no
    /// recipients and is accepted.
    /// </summary>
    /// <param name="csv">The recipients string from the request body.</param>
    /// <param name="field">The field name used in the message.</param>
    public static string? EmailListError(string? csv, string field)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        var bad = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(e => !MailAddress.TryCreate(e, out _))
            .ToList();
        return bad.Count == 0 ? null : $"{field} contains invalid email addresses: {string.Join(", ", bad)}.";
    }

    /// <summary>
    /// Validates one CORS origin. Rejects the wildcard, anything that is not an absolute URL, and
    /// plain http except for localhost, 127.0.0.1 and ::1 — the rules startup enforces, where a
    /// violation stops the server from starting. With <paramref name="requireBareOrigin"/>, also
    /// rejects a path, query, fragment or trailing slash: origins are compared as strings and the
    /// browser's Origin header never carries one, so such an entry would never match.
    /// </summary>
    /// <param name="origin">One trimmed origin.</param>
    /// <param name="requireBareOrigin">True at save time; false at startup, so an existing config still loads.</param>
    public static string? CorsOriginError(string origin, bool requireBareOrigin)
    {
        if (origin == "*")
            return "Wildcard origin '*' is not allowed. Specify exact origins in Http.CorsOrigins.";
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            return $"Invalid origin '{origin}' in Http.CorsOrigins — must be an absolute URL.";
        var isLocal = string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                      || uri.Host == "127.0.0.1" || uri.Host == "::1" || uri.Host == "[::1]";
        if (!isLocal && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return $"Non-local origin '{origin}' must use https:// in Http.CorsOrigins.";
        if (requireBareOrigin)
        {
            if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                return $"Origin '{origin}' must use https://.";
            var schemeEnd = origin.IndexOf("://", StringComparison.Ordinal) + 3;
            if (origin.IndexOfAny(new[] { '/', '?', '#' }, schemeEnd) >= 0)
                return $"Origin '{origin}' must be scheme, host and optional port only, with no path or trailing '/'.";
            if (!string.IsNullOrEmpty(uri.UserInfo))
                return $"Origin '{origin}' must not carry a user name or password.";
        }
        return null;
    }

    private static readonly System.Text.RegularExpressions.Regex SunsetDate =
        new(@"^\d{4}-\d{2}-\d{2}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// Validates one algorithm sunset rule, <c>ALG:YYYY-MM-DD</c>, as the console writes it and
    /// CertPolicyService reads it (split at the last colon). ALG is what the rule is compared with,
    /// case-insensitively: the key algorithm and size joined by a hyphen (<c>RSA-2048</c>,
    /// <c>ECDSA-P-256</c>), the key algorithm alone (<c>RSA</c>, <c>Ed25519</c>,
    /// <c>ML-DSA-65</c>), or the signature algorithm (<c>SHA1withRSA</c>); it may not be blank or
    /// hold spaces or a colon. The date must be a real calendar date written YYYY-MM-DD.
    /// CertPolicyService skips a rule it cannot read with only a log line, so the check is made here.
    /// </summary>
    /// <param name="rule">One rule from <c>CertPolicy.AlgorithmSunsetRules</c>.</param>
    public static string? AlgorithmSunsetRuleError(string? rule)
    {
        if (string.IsNullOrWhiteSpace(rule)) return "An algorithm sunset rule is empty.";
        var colon = rule.LastIndexOf(':');
        if (colon <= 0 || colon >= rule.Length - 1)
            return $"Sunset rule '{rule}' must be ALGORITHM:YYYY-MM-DD, e.g. RSA-2048:2030-01-01.";
        var alg = rule[..colon].Trim();
        var date = rule[(colon + 1)..].Trim();
        if (alg.Length == 0 || alg.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c == ':'))
            return $"Sunset rule '{rule}': the algorithm must be one word such as RSA-2048, ECDSA-P-256 or SHA1withRSA, with no spaces or colons.";
        if (!SunsetDate.IsMatch(date)
            || !DateTime.TryParseExact(date, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out _))
            return $"Sunset rule '{rule}': '{date}' is not a date written YYYY-MM-DD.";
        return null;
    }

    /// <summary>
    /// Validates every algorithm sunset rule (<see cref="AlgorithmSunsetRuleError"/>). Returns the
    /// first problem, or null when all pass or the list is null (not supplied).
    /// </summary>
    /// <param name="rules">The rules from the request body.</param>
    public static string? AlgorithmSunsetRulesError(IEnumerable<string?>? rules)
    {
        if (rules == null) return null;
        foreach (var rule in rules)
        {
            if (AlgorithmSunsetRuleError(rule) is { } error)
                return error;
        }
        return null;
    }

    /// <summary>
    /// Validates a comma-separated CORS origin list, split as startup splits it. Returns the first
    /// problem, or null when every origin passes <see cref="CorsOriginError"/>.
    /// </summary>
    /// <param name="csv">The Http.CorsOrigins value.</param>
    /// <param name="requireBareOrigin">See <see cref="CorsOriginError"/>.</param>
    public static string? CorsOriginsError(string? csv, bool requireBareOrigin)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        foreach (var origin in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (CorsOriginError(origin, requireBareOrigin) is { } error)
                return error;
        }
        return null;
    }

    /// <summary>
    /// Parses one trusted-proxy entry (<c>Http.TrustedProxyCidrs</c> or <c>Http.ProxyProtocolTrustedCidrs</c>): an IPv4 or IPv6 address, a slash and a
    /// prefix length within the address family's range, with no bits set after the prefix.
    /// Returns null and the network when it parses, otherwise a message naming the entry.
    /// </summary>
    /// <param name="cidr">One trimmed entry.</param>
    /// <param name="network">The network, when the entry parses.</param>
    /// <param name="setting">The setting the entry came from, named in the message.</param>
    public static string? TrustedProxyCidrError(string cidr, out System.Net.IPNetwork network, string setting = "Http.TrustedProxyCidrs")
    {
        network = default;
        var slash = cidr.IndexOf('/');
        if (slash <= 0 || slash == cidr.Length - 1)
            return $"Trusted proxy '{cidr}' in {setting} is not in CIDR form: write address/prefix, e.g. 10.0.1.5/32.";
        if (!System.Net.IPAddress.TryParse(cidr[..slash], out var address) || address.ToString().Contains('%'))
            return $"Trusted proxy '{cidr}' in {setting} does not start with an IP address.";
        var max = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (!int.TryParse(cidr[(slash + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix)
            || prefix > max)
            return $"Trusted proxy '{cidr}' in {setting} has a prefix length that is not from 0 to {max}.";

        var bytes = address.GetAddressBytes();
        var masked = (byte[])bytes.Clone();
        for (var i = 0; i < masked.Length; i++)
        {
            var keep = Math.Clamp(prefix - i * 8, 0, 8);
            masked[i] &= (byte)(0xFF << (8 - keep));
        }
        if (!bytes.AsSpan().SequenceEqual(masked))
            return $"Trusted proxy '{cidr}' in {setting} has bits set after the /{prefix} prefix: write {new System.Net.IPAddress(masked)}/{prefix}, or /{max} for one address.";

        network = new System.Net.IPNetwork(address, prefix);
        return null;
    }

    /// <summary>
    /// Validates a comma-separated trusted-proxy list (by default <c>Http.TrustedProxyCidrs</c>),
    /// split as startup splits it (comma, entries trimmed, blanks dropped). Returns the first
    /// entry that does not parse (<see cref="TrustedProxyCidrError"/>), or null when all do or
    /// the list is blank.
    /// </summary>
    /// <param name="csv">The list's value.</param>
    /// <param name="setting">The setting the list came from, named in the message.</param>
    public static string? TrustedProxyCidrsError(string? csv, string setting = "Http.TrustedProxyCidrs")
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        foreach (var cidr in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TrustedProxyCidrError(cidr, out _, setting) is { } error)
                return error;
        }
        return null;
    }

    /// <summary>
    /// The networks a trusted-proxy list (by default <c>Http.TrustedProxyCidrs</c>) names. Throws
    /// when an entry does not parse; check <see cref="TrustedProxyCidrsError"/> first.
    /// </summary>
    /// <param name="csv">The list's value.</param>
    /// <param name="setting">The setting the list came from, named in the message.</param>
    /// <exception cref="FormatException">An entry is not a usable CIDR.</exception>
    public static IReadOnlyList<System.Net.IPNetwork> TrustedProxyNetworks(string? csv, string setting = "Http.TrustedProxyCidrs")
    {
        if (string.IsNullOrWhiteSpace(csv)) return [];
        var networks = new List<System.Net.IPNetwork>();
        foreach (var cidr in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TrustedProxyCidrError(cidr, out var network, setting) is { } error)
                throw new FormatException(error);
            networks.Add(network);
        }
        return networks;
    }

    /// <summary>
    /// The reverse-proxy settings together: <c>Security.BehindReverseProxy</c> on with no trusted
    /// proxy named is refused, because forwarded headers are then honoured from loopback only,
    /// every request appears to come from the proxy, and an RFC1918 proxy address passes every
    /// internal-only IP whitelist rule. Also refuses an entry that does not parse. Returns null
    /// when the pair is usable.
    /// </summary>
    /// <param name="behindReverseProxy">Security.BehindReverseProxy.</param>
    /// <param name="trustedProxyCidrs">Http.TrustedProxyCidrs.</param>
    public static string? ReverseProxyError(bool behindReverseProxy, string? trustedProxyCidrs)
    {
        if (TrustedProxyCidrsError(trustedProxyCidrs) is { } error)
            return error;
        if (behindReverseProxy && string.IsNullOrWhiteSpace(trustedProxyCidrs))
            return "Security.BehindReverseProxy is on but Http.TrustedProxyCidrs names no proxy. Every request would appear "
                 + "to come from the proxy, and an internal proxy address passes the internal-only IP whitelist rules. "
                 + "Name the proxy, e.g. 10.0.1.5/32, or 127.0.0.1/32,::1/128 for a proxy on this host, or turn BehindReverseProxy off.";
        return null;
    }

    /// <summary>
    /// The PROXY protocol settings together. Refuses an entry of
    /// <c>Http.ProxyProtocolTrustedCidrs</c> that does not parse, whether or not a listener takes
    /// the protocol; a listener taking it (<c>Https.ProxyProtocol</c> or <c>Http.ProxyProtocol</c>)
    /// with that list empty, since every connection would then be closed; and an entry that
    /// trusts every address (a <c>/0</c> prefix), since any client could then send a header and
    /// choose its own address, which is the one thing the protocol must never allow. Returns null
    /// when the settings are usable.
    /// </summary>
    /// <param name="httpsProxyProtocol">Https.ProxyProtocol.</param>
    /// <param name="httpProxyProtocol">Http.ProxyProtocol.</param>
    /// <param name="trustedCidrs">Http.ProxyProtocolTrustedCidrs.</param>
    public static string? ProxyProtocolError(bool httpsProxyProtocol, bool httpProxyProtocol, string? trustedCidrs)
    {
        const string setting = "Http.ProxyProtocolTrustedCidrs";
        if (TrustedProxyCidrsError(trustedCidrs, setting) is { } error)
            return error;

        foreach (var network in TrustedProxyNetworks(trustedCidrs, setting))
        {
            if (network.PrefixLength == 0)
                return $"Trusted proxy '{network}' in {setting} trusts every address, so any client could send a PROXY header "
                     + "and choose its own address. Name the proxy itself, e.g. 10.100.105.22/32.";
        }

        if ((httpsProxyProtocol || httpProxyProtocol) && string.IsNullOrWhiteSpace(trustedCidrs))
        {
            var listeners = (httpsProxyProtocol, httpProxyProtocol) switch
            {
                (true, true) => "Https.ProxyProtocol and Http.ProxyProtocol are",
                (true, false) => "Https.ProxyProtocol is",
                _ => "Http.ProxyProtocol is",
            };
            return $"{listeners} on but {setting} names no proxy, so every connection to that listener would be closed. "
                 + "Name the proxy that sends the PROXY header as it appears to this host, e.g. 10.100.105.22/32, "
                 + "or turn the listener's ProxyProtocol off. Do not use Http.TrustedProxyCidrs for a passthrough proxy.";
        }
        return null;
    }

    /// <summary>
    /// Validates a dotted object identifier as X.660 writes it: at least two arcs of decimal
    /// digits separated by dots, no leading zeros, the first arc 0, 1 or 2, and the second at most
    /// 39 under 0 or 1. Returns null when it is one, otherwise a message naming
    /// <paramref name="field"/>.
    /// </summary>
    /// <param name="oid">The value from the request body or the settings store.</param>
    /// <param name="field">The setting name used in the message, e.g. <c>Tsa.PolicyOid</c>.</param>
    public static string? ObjectIdentifierError(string? oid, string field)
    {
        var example = "e.g. 1.3.6.1.4.1.66874.1.5.1";
        if (string.IsNullOrWhiteSpace(oid))
            return $"{field} must be an object identifier written with dots, {example}.";
        var arcs = oid.Split('.');
        if (arcs.Length < 2
            || arcs.Any(a => a.Length == 0 || !a.All(char.IsAsciiDigit) || (a.Length > 1 && a[0] == '0')))
            return $"{field} '{oid}' is not an object identifier: write decimal arcs separated by dots, with no spaces or leading zeros, {example}.";
        if (arcs[0] is not ("0" or "1" or "2"))
            return $"{field} '{oid}' is not an object identifier: the first arc must be 0, 1 or 2.";
        if (arcs[0] != "2" && (arcs[1].Length > 2 || int.Parse(arcs[1], System.Globalization.CultureInfo.InvariantCulture) > 39))
            return $"{field} '{oid}' is not an object identifier: under {arcs[0]} the second arc must be from 0 to 39.";
        return null;
    }

    /// <summary>
    /// The rule a stored setting's value must pass beyond its type, for settings that no console
    /// endpoint checks before they reach the settings store: null when the value passes or the
    /// setting has no such rule. The store applies it to every write, from the console or
    /// <c>--settings set</c>. The value must already be of the setting's type.
    /// </summary>
    /// <param name="key">The store key, with underscores.</param>
    /// <param name="value">The value being stored.</param>
    public static string? StoredSettingError(string key, System.Text.Json.Nodes.JsonNode? value) => key switch
    {
        "Tsa_PolicyOid" => ObjectIdentifierError(value is System.Text.Json.Nodes.JsonValue text && text.TryGetValue<string>(out var oid) ? oid : null, "Tsa.PolicyOid"),
        _ => null,
    };

    /// <summary>
    /// The origins a CORS origin list allows, split as startup splits it. None when the list is
    /// blank, or when any entry breaks the startup rules (<see cref="CorsOriginsError"/> without
    /// the bare-origin check): a list that would have stopped a start allows nothing.
    /// </summary>
    /// <param name="csv">The Http.CorsOrigins value.</param>
    public static string[] CorsOriginsAllowed(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv) || CorsOriginsError(csv, requireBareOrigin: false) != null)
            return [];
        return csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
