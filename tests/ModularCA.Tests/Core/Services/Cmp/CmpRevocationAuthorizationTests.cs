using ModularCA.Core.Services.Cmp;
using Xunit;

namespace ModularCA.Tests.Core.Services.Cmp;

/// <summary>
/// Covers who may revoke over CMP, as distinct from
/// <see cref="CmpRevocationOwnershipTests"/>, which covers which CA the target belongs to.
/// <para>
/// Those are different questions, and only the second one was being asked. Every check in the
/// revocation handler established that the addressed CA had issued the target; none established
/// that the caller had any relationship to it. So any peer that could authenticate a CMP message
/// to a CA — one device shared secret, or one certificate that CA had issued — could revoke every
/// certificate that CA had ever issued, a serial at a time. The operator's own mTLS credential and
/// the Web TLS certificate serving the admin UI are ordinary rows carrying that issuer DN, so the
/// reach included locking the operator out of the system while the audit trail recorded a series
/// of well-formed revocations.
/// </para>
/// </summary>
public class CmpRevocationAuthorizationTests
{
    private const string DeviceDn = "CN=printer1,O=Acme,C=US";
    private const string AdminDn = "CN=admin-mtls,O=Acme,C=US";

    // ── signature-protected callers ──────────────────────────────────────────

    [Fact]
    public void A_signer_may_revoke_the_very_certificate_it_signed_with()
    {
        var (allowed, _) = CmpService.SignerMayRevoke(
            signerSerialHex: "0A1B2C", signerSubjectDn: DeviceDn,
            targetSerial: "0A1B2C", targetSubjectDn: DeviceDn);
        Assert.True(allowed);
    }

    [Fact]
    public void A_signer_may_revoke_an_older_certificate_of_its_own_identity()
    {
        // The case that has to keep working: rekey, then retire the predecessor. Different
        // serial, same subject.
        var (allowed, _) = CmpService.SignerMayRevoke(
            signerSerialHex: "FF01", signerSubjectDn: DeviceDn,
            targetSerial: "0A1B2C", targetSubjectDn: DeviceDn);
        Assert.True(allowed);
    }

    [Fact]
    public void A_signer_may_not_revoke_a_different_subjects_certificate()
    {
        // The escalation: one enrolled device revoking the administrator's mTLS credential.
        var (allowed, reason) = CmpService.SignerMayRevoke(
            signerSerialHex: "FF01", signerSubjectDn: DeviceDn,
            targetSerial: "0A1B2C", targetSubjectDn: AdminDn);
        Assert.False(allowed);
        Assert.Contains("neither the target nor shares its subject", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Rdn_order_and_spacing_do_not_defeat_the_subject_match()
    {
        // Goes through DnEquals rather than a string compare, so a client that emits its DN in a
        // different RDN order still renews and retires its own certificates.
        var (allowed, _) = CmpService.SignerMayRevoke(
            signerSerialHex: "FF01", signerSubjectDn: "C=US, O=Acme, CN=printer1",
            targetSerial: "0A1B2C", targetSubjectDn: DeviceDn);
        Assert.True(allowed);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    public void A_signer_with_no_recorded_identity_may_revoke_nothing(string? serial, string? subject)
    {
        // Fail closed. Two blank identities must not match each other into an allow.
        var (allowed, _) = CmpService.SignerMayRevoke(serial, subject, "0A1B2C", DeviceDn);
        Assert.False(allowed);
    }

    [Fact]
    public void A_blank_target_subject_is_not_a_wildcard()
    {
        var (allowed, _) = CmpService.SignerMayRevoke("FF01", DeviceDn, "0A1B2C", targetSubjectDn: "");
        Assert.False(allowed);
    }

    // ── PBMAC shared-secret callers ──────────────────────────────────────────

    [Fact]
    public void An_unrestricted_shared_secret_may_revoke_nothing()
    {
        // The heart of it. A bare PBMAC credential says "someone who holds this secret", which is
        // not an identity, so it gets no revocation authority at all rather than the CA's whole
        // issuance history. An operator who wants one grants it a scope.
        var (allowed, reason) = CmpService.CredentialMayRevoke(
            subjectRestriction: null, sanRestriction: null,
            targetSubjectDn: DeviceDn, targetSans: []);
        Assert.False(allowed);
        Assert.Contains("no subject or SAN restriction", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_scoped_shared_secret_may_revoke_inside_its_scope()
    {
        var (allowed, _) = CmpService.CredentialMayRevoke(
            subjectRestriction: "O=Acme", sanRestriction: null,
            targetSubjectDn: DeviceDn, targetSans: []);
        Assert.True(allowed);
    }

    [Fact]
    public void A_scoped_shared_secret_may_not_revoke_outside_its_scope()
    {
        var (allowed, reason) = CmpService.CredentialMayRevoke(
            subjectRestriction: "O=Acme", sanRestriction: null,
            targetSubjectDn: "CN=vpn,O=Other Corp,C=US", targetSans: []);
        Assert.False(allowed);
        Assert.Contains("outside credential scope", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_san_restriction_bounds_the_targets_alternative_names_too()
    {
        // A credential scoped to devices.example.com must not reach a certificate that also
        // carries the CA's own front-end name.
        var (allowed, _) = CmpService.CredentialMayRevoke(
            subjectRestriction: null, sanRestriction: "devices.example.com",
            targetSubjectDn: DeviceDn,
            targetSans: ["DNS:printer1.devices.example.com", "DNS:ca.example.com"]);
        Assert.False(allowed);
    }

    [Fact]
    public void A_target_entirely_inside_the_san_restriction_is_revocable()
    {
        var (allowed, _) = CmpService.CredentialMayRevoke(
            subjectRestriction: null, sanRestriction: "devices.example.com",
            targetSubjectDn: DeviceDn,
            targetSans: ["DNS:printer1.devices.example.com"]);
        Assert.True(allowed);
    }
}
