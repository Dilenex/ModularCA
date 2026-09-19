using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using ModularCA.Signer.Identity;
using Xunit;

namespace ModularCA.Tests.Ingress;

/// <summary>
/// The upstream trust decision: a pin beats the shared CA, the CA beats the dangerous flag,
/// the flag applies to loopback only and never to a destination elsewhere, and the pinned
/// mode accepts the pinned key and nothing else.
/// </summary>
public sealed class UpstreamTrustPolicyTests
{
    private static object Policy(X509Certificate2Collection? ca, bool dangerous)
        => Activator.CreateInstance(IngressApi.TrustPolicy, ca, dangerous)!;

    private static string Mode(object policy, string? pin, bool loopback)
        => IngressApi.Call(policy, "ModeFor", pin, loopback)!.ToString()!;

    private static bool Accept(object policy, string mode, X509Certificate2? certificate, SslPolicyErrors errors, string? pin)
        => (bool)IngressApi.Call(policy, "Accept", Enum.Parse(IngressApi.TrustMode, mode), certificate, errors, pin)!;

    private static readonly X509Certificate2 Node = RemoteSignerIdentityForIngress.Server;
    private static readonly X509Certificate2 Other = RemoteSignerIdentityForIngress.Other;

    [Fact]
    public void The_dangerous_flag_applies_to_loopback_only()
    {
        var policy = Policy(null, dangerous: true);
        Assert.Equal("AcceptAnyLoopback", Mode(policy, null, loopback: true));
        Assert.Equal("System", Mode(policy, null, loopback: false));
    }

    [Fact]
    public void Without_the_flag_loopback_gets_the_system_store()
        => Assert.Equal("System", Mode(Policy(null, dangerous: false), null, loopback: true));

    [Fact]
    public void A_pin_beats_the_shared_ca_which_beats_the_flag()
    {
        var ca = new X509Certificate2Collection(RemoteSignerIdentityForIngress.IdentityCa);
        var pin = SpkiPin.Compute(Node);
        Assert.Equal("Pinned", Mode(Policy(ca, dangerous: true), pin, loopback: true));
        Assert.Equal("SharedCa", Mode(Policy(ca, dangerous: true), null, loopback: true));
        Assert.Equal("AcceptAnyLoopback", Mode(Policy(null, dangerous: true), null, loopback: true));
    }

    [Fact]
    public void Pinned_accepts_the_pinned_key_and_nothing_else()
    {
        var policy = Policy(null, dangerous: false);
        var pin = SpkiPin.Compute(Node);
        Assert.True(Accept(policy, "Pinned", Node, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch, pin));
        Assert.False(Accept(policy, "Pinned", Other, SslPolicyErrors.None, pin));
        Assert.False(Accept(policy, "Pinned", null, SslPolicyErrors.None, pin));
        Assert.False(Accept(policy, "Pinned", Node, SslPolicyErrors.None, "not-a-pin"));
    }

    [Fact]
    public void Shared_ca_accepts_a_certificate_the_ca_issued_whatever_its_name_and_refuses_another()
    {
        var ca = new X509Certificate2Collection(RemoteSignerIdentityForIngress.IdentityCa);
        var policy = Policy(ca, dangerous: false);
        Assert.True(Accept(policy, "SharedCa", Node, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch, null));
        Assert.False(Accept(policy, "SharedCa", RemoteSignerIdentityForIngress.Stranger, SslPolicyErrors.None, null));
    }

    [Fact]
    public void System_accepts_only_what_the_handler_found_no_fault_with()
    {
        var policy = Policy(null, dangerous: false);
        Assert.True(Accept(policy, "System", Node, SslPolicyErrors.None, null));
        Assert.False(Accept(policy, "System", Node, SslPolicyErrors.RemoteCertificateChainErrors, null));
    }

    [Fact]
    public void The_callback_is_absent_for_the_system_mode_and_present_otherwise()
    {
        var policy = Policy(null, dangerous: true);
        var pinKey = IngressApi.ProviderConstant("PinMetadata");
        var loopbackKey = IngressApi.ProviderConstant("LoopbackMetadata");

        Assert.Null(IngressApi.Call(policy, "CallbackFor", new Dictionary<string, string> { [loopbackKey] = "false" }));
        var loopback = (RemoteCertificateValidationCallback?)IngressApi.Call(policy, "CallbackFor", new Dictionary<string, string> { [loopbackKey] = "true" });
        Assert.NotNull(loopback);
        Assert.True(loopback!(this, Other, null, SslPolicyErrors.RemoteCertificateChainErrors));

        var pinned = (RemoteCertificateValidationCallback?)IngressApi.Call(policy, "CallbackFor", new Dictionary<string, string> { [loopbackKey] = "true", [pinKey] = SpkiPin.Compute(Node) });
        Assert.NotNull(pinned);
        Assert.True(pinned!(this, Node, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(pinned(this, Other, null, SslPolicyErrors.None));
    }
}

/// <summary>Certificates for the trust tests: a CA, a server it issued, a second one it issued, and one from elsewhere.</summary>
internal static class RemoteSignerIdentityForIngress
{
    public static readonly X509Certificate2 IdentityCa;
    public static readonly X509Certificate2 Server;
    public static readonly X509Certificate2 Other;
    public static readonly X509Certificate2 Stranger;

    static RemoteSignerIdentityForIngress()
    {
        var now = DateTimeOffset.UtcNow;
        IdentityCa = SignerIdentity.CreateIdentityCa(now);
        Server = SignerIdentity.IssueServerCertificate(IdentityCa, "127.0.0.1", now);
        Other = SignerIdentity.IssueServerCertificate(IdentityCa, "127.0.0.1", now);
        var strangerCa = SignerIdentity.CreateIdentityCa(now);
        Stranger = SignerIdentity.IssueServerCertificate(strangerCa, "127.0.0.1", now);
    }
}
