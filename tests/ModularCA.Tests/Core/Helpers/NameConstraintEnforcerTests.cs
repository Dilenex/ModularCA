using ModularCA.Core.Helpers;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Helpers;

/// <summary>
/// <see cref="NameConstraintEnforcer"/> over real CA certificates: BouncyCastle's matching for each
/// type, pinned where this server documents a rule (the DNS leading dot above all), the path rule
/// (every CA's constraints bind), and the fail-closed cases.
/// </summary>
public sealed class NameConstraintEnforcerTests
{
    private static X509Certificate Ca(string subject, string? permitted = null, string? excluded = null)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.One);
        gen.SetIssuerDN(new X509Name(subject));
        gen.SetSubjectDN(new X509Name(subject));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        gen.SetPublicKey(keys.Public);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        var p = NameConstraintRules.ParseJson(permitted);
        var x = NameConstraintRules.ParseJson(excluded);
        if (p != null || x != null)
            gen.AddExtension(X509Extensions.NameConstraints, true, new NameConstraints(p, x));
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()));
    }

    private static void Check(X509Certificate ca, string subject, params string[] sans)
        => NameConstraintEnforcer.Enforce(NameConstraintEnforcer.Collect([ca]), Name(subject), sans);

    private static X509Name Name(string subject)
        => subject.Length == 0 ? new X509Name(new List<DerObjectIdentifier>(), new List<string>()) : new X509Name(subject);

    private static bool Allowed(X509Certificate ca, string subject, params string[] sans)
    {
        try { Check(ca, subject, sans); return true; }
        catch (CertificatePolicyViolationException ex) when (ex.Code == ErrorCodes.NameConstraintViolation) { return false; }
    }

    /// <summary>
    /// The DNS rule the console and <see cref="NameConstraintRules"/> describe, and the matcher
    /// issuance used before BouncyCastle took over: <c>.domain</c> is subdomains only, a plain
    /// domain the name itself and its subdomains, on label boundaries, ignoring case.
    /// BouncyCastle 2.7.0 agrees on every row, so DNS goes through it like the other types.
    /// </summary>
    [Theory]
    [InlineData(".example.com", "example.com", false)]
    [InlineData(".example.com", "a.example.com", true)]
    [InlineData(".example.com", "a.b.example.com", true)]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "a.example.com", true)]
    [InlineData("example.com", "badexample.com", false)]
    [InlineData("example.com", "EXAMPLE.COM", true)]
    [InlineData("Example.COM", "a.example.com", true)]
    [InlineData("example.com", "*.example.com", true)]
    [InlineData(".example.com", "*.example.com", true)]
    public void Dns_subtrees_match_as_the_console_describes(string constraint, string name, bool within)
    {
        Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"DNS:{constraint}\"]"), "CN=leaf", $"DNS:{name}"));
        Assert.Equal(!within, Allowed(Ca("CN=X", excluded: $"[\"DNS:{constraint}\"]"), "CN=leaf", $"DNS:{name}"));
    }

    [Theory]
    [InlineData("10.0.0.0/8", "IP:10.1.2.3", true)]
    [InlineData("10.0.0.0/8", "IP:11.1.2.3", false)]
    [InlineData("10.0.0.0/8", "IP:::1", false)]
    [InlineData("2001:db8::/32", "IP:2001:db8::1", true)]
    [InlineData("2001:db8::/32", "IP:2001:db9::1", false)]
    [InlineData("2001:db8::/32", "IP:10.0.0.1", false)]
    [InlineData("10.0.0.0/8", "IP:#0a000001", true)]
    public void Ip_subtrees_are_ranges_of_one_family(string constraint, string san, bool within)
    {
        Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"IP:{constraint}\"]"), "CN=leaf", san));
        Assert.Equal(!within, Allowed(Ca("CN=X", excluded: $"[\"IP:{constraint}\"]"), "CN=leaf", san));
    }

    [Theory]
    [InlineData("admin@example.com", "admin@example.com", true)]
    [InlineData("admin@example.com", "other@example.com", false)]
    [InlineData("example.com", "x@example.com", true)]
    [InlineData("example.com", "x@a.example.com", false)]
    [InlineData(".example.com", "x@a.example.com", true)]
    [InlineData(".example.com", "x@example.com", false)]
    public void Email_subtrees_are_a_mailbox_a_host_or_a_domain(string constraint, string mailbox, bool within)
    {
        Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"EMAIL:{constraint}\"]"), "CN=leaf", $"EMAIL:{mailbox}"));
        Assert.Equal(!within, Allowed(Ca("CN=X", excluded: $"[\"EMAIL:{constraint}\"]"), "CN=leaf", $"EMAIL:{mailbox}"));
        // RFC 5280 §4.2.1.10: emailAddress attributes of the subject are rfc822 names too.
        Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"EMAIL:{constraint}\"]"), $"CN=leaf,E={mailbox}"));
    }

    [Theory]
    [InlineData("example.com", "https://example.com/x", true)]
    [InlineData("example.com", "https://a.example.com/x", false)]
    [InlineData(".example.com", "https://a.example.com:8443/x", true)]
    [InlineData(".example.com", "https://example.com/", false)]
    [InlineData("example.com", "urn:example:thing", false)]
    public void Uri_subtrees_constrain_the_host(string constraint, string uri, bool within)
        => Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"URI:{constraint}\"]"), "CN=leaf", $"URI:{uri}"));

    /// <summary>A DN subtree matches a subject whose RDNs begin with the subtree's, in encoded order.</summary>
    [Theory]
    [InlineData("C=US,O=Acme", "C=US,O=Acme,CN=x", true)]
    [InlineData("C=US,O=Acme", "C=US,O=Acme", true)]
    [InlineData("C=US,O=Acme", "CN=x,O=Acme,C=US", false)]
    [InlineData("C=US,O=Acme", "C=US,O=Other,CN=x", false)]
    [InlineData("O=Acme", "CN=x,O=Acme", false)]
    public void Dn_subtrees_match_leading_rdns(string constraint, string subject, bool within)
    {
        Assert.Equal(within, Allowed(Ca("CN=P", permitted: $"[\"DN:{constraint}\"]"), subject));
        Assert.Equal(!within, Allowed(Ca("CN=X", excluded: $"[\"DN:{constraint}\"]"), subject));
    }

    [Fact]
    public void An_empty_subject_is_not_held_to_a_dn_subtree()
        => Assert.True(Allowed(Ca("CN=P", permitted: "[\"DN:C=US,O=Acme\"]"), "", "DNS:host.example"));

    [Fact]
    public void A_constraint_on_one_type_leaves_the_others_free()
    {
        var ca = Ca("CN=P", permitted: "[\"DNS:.example.com\"]");
        Assert.True(Allowed(ca, "CN=anything", "IP:192.0.2.1", "EMAIL:a@b.test", "URI:https://c.test/", "UPN:u@corp.test"));
    }

    /// <summary>
    /// Every CA of the path binds: a name inside the issuer's wide subtree but outside the root's
    /// narrow one is refused, and the message names the root and its subtree.
    /// </summary>
    [Fact]
    public void Every_ca_in_the_path_binds_and_the_refusal_names_the_one_that_refused()
    {
        var root = Ca("CN=Narrow Root", permitted: "[\"DNS:.acme.test\"]");
        var issuer = Ca("CN=Wide Issuer", permitted: "[\"DNS:.test\"]", excluded: "[\"IP:10.9.0.0/16\"]");
        var constraints = NameConstraintEnforcer.Collect([issuer, root]);

        NameConstraintEnforcer.Enforce(constraints, new X509Name("CN=leaf"), ["DNS:a.acme.test"]);
        var ex = Assert.Throws<CertificatePolicyViolationException>(
            () => NameConstraintEnforcer.Enforce(constraints, new X509Name("CN=leaf"), ["DNS:a.other.test"]));
        Assert.Equal(ErrorCodes.NameConstraintViolation, ex.Code);
        Assert.Contains("SAN DNS:a.other.test", ex.Message);
        Assert.Contains("CN=Narrow Root", ex.Message);
        Assert.Contains("[DNS:.acme.test]", ex.Message);

        var excluded = Assert.Throws<CertificatePolicyViolationException>(
            () => NameConstraintEnforcer.Enforce(constraints, new X509Name("CN=leaf"), ["DNS:a.acme.test", "IP:10.9.3.4"]));
        Assert.Contains("IP:10.9.3.4", excluded.Message);
        Assert.Contains("excluded subtree IP:10.9.0.0/16 of CA 'CN=Wide Issuer'", excluded.Message);
    }

    [Fact]
    public void An_unparseable_extension_refuses_rather_than_issuing_unconstrained()
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.One);
        gen.SetIssuerDN(new X509Name("CN=Broken"));
        gen.SetSubjectDN(new X509Name("CN=Broken"));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        gen.SetPublicKey(keys.Public);
        gen.AddExtension(X509Extensions.NameConstraints, true, new DerUtf8String("not a NameConstraints"));
        var broken = gen.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()));

        var ex = Assert.Throws<InvalidOperationException>(() => NameConstraintEnforcer.Collect([broken]));
        Assert.Contains("cannot be parsed", ex.Message);
    }

    [Fact]
    public void A_path_without_constraints_checks_nothing()
        => NameConstraintEnforcer.Enforce(NameConstraintEnforcer.Collect([Ca("CN=Free")]), new X509Name("CN=x"), ["NOT-A-SAN"]);
}
