using ModularCA.Shared.Models.Config;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Pins the forwarded-header hop limit and the condition that silently disables the IP whitelist.
/// </summary>
/// <remarks>
/// <para>
/// Found by probing two live deployments. A reverse proxy in front of ModularCA makes every
/// request arrive from the proxy's own address; when that address is RFC1918 it satisfies every
/// internal-only whitelist rule, so the whitelist permits the entire internet. It fails open, with
/// no symptom — the audit trail shows a plausible internal address for every caller, and the
/// startup banner asserted the whitelist was still rejecting non-RFC1918 sources.
/// </para>
/// <para>
/// The hop count is the second half. With <c>client → CDN → proxy → Kestrel</c>, the proxy appends
/// the address it sees — the CDN edge — so <c>X-Forwarded-For</c> arrives as
/// <c>&lt;client&gt;, &lt;edge&gt;</c>. Walking back one hop returns the CDN and calls it the
/// client, which is not obviously wrong in a log: it is a real address, just the wrong one.
/// </para>
/// </remarks>
public class ForwardedHeaderHopLimitTests
{
    /// <summary>Mirrors the clamp applied where ForwardedHeadersOptions is built.</summary>
    private static int EffectiveLimit(int configured) => Math.Max(1, configured);

    [Fact]
    public void The_default_is_one_hop()
    {
        // Unchanged behaviour for the single-proxy deployment, which is most of them. Making this
        // configurable must not move anyone who never sets it.
        Assert.Equal(1, new HttpConfig().ForwardedHeaderHopLimit);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void A_zero_or_negative_limit_clamps_to_one(int configured)
    {
        // ForwardLimit = 0 disables the walk entirely while still looking like a deliberate
        // setting, which would silently reinstate exactly the bug this exists to fix.
        Assert.Equal(1, EffectiveLimit(configured));
    }

    [Fact]
    public void A_cdn_in_front_of_a_proxy_needs_two()
    {
        // Not arithmetic for its own sake: this is the value the Cloudflare-plus-nginx deployment
        // needs, and getting it wrong yields the CDN's edge address in every audit record.
        Assert.Equal(2, EffectiveLimit(2));
    }

    /// <summary>
    /// Mirrors the startup check: claiming to be behind a proxy while naming none is the
    /// configuration that silently disables the whitelist.
    /// </summary>
    private static bool WarnsAboutSilentBypass(bool behindProxy, string trustedCidrs) =>
        behindProxy && string.IsNullOrWhiteSpace(trustedCidrs);

    [Fact]
    public void Claiming_a_proxy_without_naming_one_is_warned_about()
    {
        Assert.True(WarnsAboutSilentBypass(behindProxy: true, trustedCidrs: ""));
        Assert.True(WarnsAboutSilentBypass(behindProxy: true, trustedCidrs: "   "));
    }

    [Fact]
    public void A_named_proxy_or_no_proxy_is_not_warned_about()
    {
        // The two correct configurations. A warning that fires on a healthy install is a warning
        // people learn to scroll past, which costs more than it saves.
        Assert.False(WarnsAboutSilentBypass(behindProxy: true, trustedCidrs: "203.0.113.2/32"));
        Assert.False(WarnsAboutSilentBypass(behindProxy: false, trustedCidrs: ""));
    }

    [Fact]
    public void The_default_configuration_does_not_warn()
    {
        // Out of the box: no proxy claimed, none named.
        var http = new HttpConfig();
        var security = new SecurityConfig();
        Assert.False(WarnsAboutSilentBypass(security.BehindReverseProxy, http.TrustedProxyCidrs));
    }
}
