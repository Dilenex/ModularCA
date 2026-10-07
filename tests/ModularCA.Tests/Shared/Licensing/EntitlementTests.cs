using System.Text;
using System.Text.Json;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Licensing;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Shared.Licensing;

/// <summary>
/// Mints real signed licences so the verifier is exercised rather than stubbed.
/// </summary>
/// <remarks>
/// The signing half never ships — the product only verifies — so this is the only place the two
/// halves meet, and a round-trip here is what proves the wire format the licence issuer will
/// have to produce is the one the verifier accepts.
/// </remarks>
internal static class LicenseMint
{
    internal static (byte[] PublicKey, Ed25519PrivateKeyParameters Private) NewSigner()
    {
        var priv = new Ed25519PrivateKeyParameters(new SecureRandom());
        return (priv.GeneratePublicKey().GetEncoded(), priv);
    }

    internal static string Sign(LicenseClaims claims, Ed25519PrivateKeyParameters key)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(claims);
        var input = LicenseVerifier.SigningInput(json);

        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(input, 0, input.Length);

        return LicenseVerifier.Encode(json, signer.GenerateSignature());
    }

    internal static LicenseClaims Claims(
        DateOnly maintenanceThrough,
        IReadOnlyList<string>? entitlements = null,
        IReadOnlyDictionary<string, int>? limits = null)
        => new()
        {
            Licensee = "Example MSP Ltd",
            LicenseId = "LIC-0001",
            IssuedOn = new DateOnly(2026, 1, 1),
            MaintenanceThrough = maintenanceThrough,
            Entitlements = entitlements ?? new[] { FeatureKeys.MultiTenancy },
            Limits = limits ?? new Dictionary<string, int>(StringComparer.Ordinal),
        };
}

/// <summary>
/// Covers the licence document: its wire format, its signature, and every way it can fail.
/// </summary>
public class LicenseVerifierTests
{
    [Fact]
    public void A_signed_licence_round_trips()
    {
        var (pub, priv) = LicenseMint.NewSigner();
        var doc = LicenseMint.Sign(LicenseMint.Claims(new DateOnly(2027, 6, 30)), priv);

        var result = LicenseVerifier.Verify(doc, pub);

        Assert.Equal(LicenseStatus.Valid, result.Status);
        Assert.True(result.IsValid);
        Assert.Equal("Example MSP Ltd", result.Claims!.Licensee);
        Assert.Equal(new DateOnly(2027, 6, 30), result.Claims.MaintenanceThrough);
        Assert.Contains(FeatureKeys.MultiTenancy, result.Claims.Entitlements);
    }

    [Fact]
    public void Editing_the_claims_breaks_the_signature()
    {
        // The whole point. Someone extending their own maintenance date by hand must not verify.
        var (pub, priv) = LicenseMint.NewSigner();
        var doc = LicenseMint.Sign(LicenseMint.Claims(new DateOnly(2026, 1, 1)), priv);

        var tamperedClaims = LicenseMint.Claims(new DateOnly(2099, 1, 1));
        var tamperedPayload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(tamperedClaims))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var forged = tamperedPayload + "." + doc.Split('.')[1];

        var result = LicenseVerifier.Verify(forged, pub);

        Assert.Equal(LicenseStatus.SignatureInvalid, result.Status);
        Assert.Null(result.Claims);
    }

    [Fact]
    public void A_licence_signed_by_the_wrong_key_is_refused()
    {
        var (_, mine) = LicenseMint.NewSigner();
        var (otherPub, _) = LicenseMint.NewSigner();
        var doc = LicenseMint.Sign(LicenseMint.Claims(new DateOnly(2027, 1, 1)), mine);

        Assert.Equal(LicenseStatus.SignatureInvalid, LicenseVerifier.Verify(doc, otherPub).Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void An_absent_licence_is_the_free_edition_not_an_error(string? doc)
    {
        var result = LicenseVerifier.Verify(doc);

        Assert.Equal(LicenseStatus.Absent, result.Status);
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("no-dot-here")]
    [InlineData("too.many.dots")]
    [InlineData(".")]
    [InlineData("a.")]
    [InlineData(".b")]
    [InlineData("not*base64url.AAAA")]
    public void A_malformed_document_never_throws(string doc)
    {
        var (pub, _) = LicenseMint.NewSigner();

        var result = LicenseVerifier.Verify(doc, pub);

        // Which failure it is matters less than that it is one of them and nothing escaped: this
        // runs during startup, and an exception here would stop a CA booting over a text file.
        Assert.NotEqual(LicenseStatus.Valid, result.Status);
        Assert.False(string.IsNullOrWhiteSpace(result.Diagnostic));
    }

    [Fact]
    public void A_key_of_the_wrong_length_refuses_rather_than_throwing()
    {
        var (_, priv) = LicenseMint.NewSigner();
        var doc = LicenseMint.Sign(LicenseMint.Claims(new DateOnly(2027, 1, 1)), priv);

        var result = LicenseVerifier.Verify(doc, new byte[5]);

        Assert.Equal(LicenseStatus.SignatureInvalid, result.Status);
    }

    [Fact]
    public void The_shipped_signing_key_is_still_the_placeholder()
    {
        // Fails the day a real key is pinned, which is the point: that change must be deliberate
        // and must come with updating this test, not slip in unnoticed either way.
        Assert.False(LicenseVerifier.LicenseKeyIsConfigured,
            "A real licence signing key is now pinned. Update this assertion — and confirm the "
            + "private half is stored somewhere the build cannot reach.");
    }

    /// <summary>
    /// A signature over the claims that a cofactorless verifier accepts for a small-order
    /// public key whenever the challenge is a multiple of the key's order: R is the identity
    /// point and S is zero, so the check reduces to [k]A being the identity.
    /// </summary>
    private static string SmallOrderForgery(string licenseId)
    {
        var claims = LicenseMint.Claims(new DateOnly(2099, 1, 1));
        var json = JsonSerializer.SerializeToUtf8Bytes(new LicenseClaims
        {
            Licensee = claims.Licensee,
            LicenseId = licenseId,
            IssuedOn = claims.IssuedOn,
            MaintenanceThrough = claims.MaintenanceThrough,
            Entitlements = claims.Entitlements,
            Limits = claims.Limits,
        });
        var signature = new byte[64];
        signature[0] = 0x01;
        return LicenseVerifier.Encode(json, signature);
    }

    [Fact]
    public void While_the_vendor_key_is_the_placeholder_every_licence_is_refused_as_unconfigured()
    {
        var (_, priv) = LicenseMint.NewSigner();
        var documents = new[] { LicenseMint.Sign(LicenseMint.Claims(new DateOnly(2027, 1, 1)), priv) }
            .Concat(Enumerable.Range(0, 16).Select(i => SmallOrderForgery($"LIC-FORGED-{i}")));

        foreach (var doc in documents)
        {
            var result = LicenseVerifier.Verify(doc);
            Assert.Equal(LicenseStatus.SignatureInvalid, result.Status);
            Assert.Null(result.Claims);
            Assert.Contains("no licence signing key configured", result.Diagnostic);
        }
    }

    [Fact]
    public void An_all_zero_override_key_is_refused_as_unconfigured()
    {
        var result = LicenseVerifier.Verify(SmallOrderForgery("LIC-FORGED"), new byte[32]);

        Assert.Equal(LicenseStatus.SignatureInvalid, result.Status);
        Assert.Contains("no licence signing key configured", result.Diagnostic);
    }

    [Fact]
    public void The_free_edition_is_unchanged_while_the_key_is_the_placeholder()
    {
        var result = LicenseVerifier.Verify(null);

        Assert.Equal(LicenseStatus.Absent, result.Status);
        Assert.Equal(LicenseStatus.Absent, new EntitlementService(null).License.Status);
    }

    /// <summary>The eight small-order points of edwards25519 in their canonical and common non-canonical encodings.</summary>
    public static IEnumerable<object[]> SmallOrderKeys() => new[]
    {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    }.Select(hex => new object[] { hex });

    [Theory]
    [MemberData(nameof(SmallOrderKeys))]
    public void BouncyCastle_rejects_a_forgery_under_a_small_order_public_key(string keyHex)
    {
        // Pins the library behaviour the placeholder check no longer depends on: if a future
        // BouncyCastle accepted these, an unconfigured build would still refuse every licence.
        var key = Convert.FromHexString(keyHex);
        var signature = new byte[64];
        signature[0] = 0x01;

        for (var i = 0; i < 32; i++)
        {
            var message = Encoding.ASCII.GetBytes($"licence-{i}");
            bool verified;
            try
            {
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(key, 0));
                verifier.BlockUpdate(message, 0, message.Length);
                verified = verifier.VerifySignature(signature);
            }
            catch (Exception)
            {
                verified = false;
            }
            Assert.False(verified, $"BouncyCastle accepted a forged signature under small-order key {keyHex}.");
        }
    }
}

/// <summary>
/// Covers the catalogue that decides which features a maintenance date covers.
/// </summary>
public class FeatureCatalogTests
{
    [Fact]
    public void Every_declared_feature_has_an_introduction_date()
    {
        // A key with no date can never be covered by any maintenance window, so it would be
        // permanently unavailable to a customer who paid for it.
        foreach (var key in FeatureCatalog.AllKeys)
            Assert.True(FeatureCatalog.IntroducedOn(key).HasValue, $"{key} has no introduction date.");
    }

    [Fact]
    public void Feature_keys_are_unique()
    {
        Assert.Equal(FeatureCatalog.AllKeys.Count, FeatureCatalog.AllKeys.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Maintenance_covers_a_feature_introduced_on_the_same_day()
    {
        // Boundary: a customer whose maintenance ended the day a feature shipped gets it. The
        // inclusive reading is the one that favours the customer, which is the right default for
        // a boundary nobody will remember the reasoning for later.
        var introduced = FeatureCatalog.IntroducedOn(FeatureKeys.MultiTenancy)!.Value;

        Assert.True(FeatureCatalog.CoveredByMaintenance(FeatureKeys.MultiTenancy, introduced));
        Assert.False(FeatureCatalog.CoveredByMaintenance(FeatureKeys.MultiTenancy, introduced.AddDays(-1)));
    }

    [Fact]
    public void An_unknown_feature_key_is_not_covered()
    {
        // A licence from a newer release may name features this build has never heard of.
        Assert.Null(FeatureCatalog.IntroducedOn("some.future.feature"));
        Assert.False(FeatureCatalog.CoveredByMaintenance("some.future.feature", new DateOnly(2099, 1, 1)));
    }

    [Fact]
    public void The_catalogue_is_exactly_the_set_of_keys_that_have_been_offered()
    {
        // Pinned as a whole rather than asserted per key, because the dangerous edit here is a
        // DELETION and nothing else would catch one. Adding a key is harmless — an older build
        // ignores names it does not know. Removing one silently revokes a feature from every
        // customer holding a licence that names it, and it fails nowhere: the licence still
        // verifies, the entitlement is still listed in its claims, and IsEntitled simply starts
        // answering false. Four keys were removed while this list was still safe to change
        // (LDAP publishing, CT submission, policy sync, lifecycle notifications — all of them
        // already implemented in the open tree, so unenforceable against a fork of this commit,
        // and all of them table stakes the free tier is better for including). Once a licence
        // has been issued naming a key, that window is closed and this test is the reminder.
        var expected = new[]
        {
            "tenancy.multi",
            "backup.orchestration",
            "compliance.reporting",
            "identity.federation",
            "hsm.fleet",
            "ha.clustering",
        };

        Assert.Equal(
            expected.OrderBy(k => k, StringComparer.Ordinal),
            FeatureCatalog.AllKeys.OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public void No_feature_gates_the_volume_of_certificates_or_authorities()
    {
        // A standing rule, not an observation about today's list. This is a security product: a
        // ceiling on how many certificates or CAs may exist pays the operator to reuse
        // certificates, skip rotations and let expiries slide — it charges for exactly the
        // behaviour the product exists to encourage. Gate on organisational boundaries instead.
        foreach (var key in FeatureCatalog.AllKeys)
        {
            Assert.DoesNotContain("count", key, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("quota", key, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("volume", key, StringComparison.OrdinalIgnoreCase);
        }
    }
}

/// <summary>
/// Covers entitlement resolution and the space-creation gate.
/// </summary>
public class EntitlementServiceTests
{
    private static IEntitlementService Free() => new EntitlementService(null);

    private static IEntitlementService Licensed(
        DateOnly maintenanceThrough,
        IReadOnlyList<string>? entitlements = null,
        IReadOnlyDictionary<string, int>? limits = null)
    {
        var (pub, priv) = LicenseMint.NewSigner();
        var doc = LicenseMint.Sign(LicenseMint.Claims(maintenanceThrough, entitlements, limits), priv);
        return new EntitlementService(doc, null, pub);
    }

    [Fact]
    public void The_free_edition_is_entitled_to_nothing_and_says_so_clearly()
    {
        var free = Free();

        Assert.False(free.IsEntitled(FeatureKeys.MultiTenancy));
        Assert.False(free.IsAvailable(FeatureKeys.MultiTenancy));
        Assert.Equal(LicenseStatus.Absent, free.License.Status);

        var denial = free.Explain(FeatureKeys.MultiTenancy);
        Assert.NotNull(denial);
        Assert.Equal(EntitlementDenialReason.NotEntitled, denial!.Reason);
    }

    [Fact]
    public void An_unverifiable_licence_degrades_to_the_free_edition_rather_than_throwing()
    {
        var service = new EntitlementService("garbage-without-a-dot");

        Assert.False(service.IsAvailable(FeatureKeys.MultiTenancy));
        Assert.NotEqual(LicenseStatus.Valid, service.License.Status);
    }

    [Fact]
    public void A_current_licence_makes_its_features_available()
    {
        var svc = Licensed(new DateOnly(2099, 1, 1));

        Assert.True(svc.IsEntitled(FeatureKeys.MultiTenancy));
        Assert.True(svc.IsAvailable(FeatureKeys.MultiTenancy));
        Assert.Null(svc.Explain(FeatureKeys.MultiTenancy));
    }

    [Fact]
    public void A_feature_the_licence_never_granted_reports_not_entitled()
    {
        var svc = Licensed(new DateOnly(2099, 1, 1), new[] { FeatureKeys.MultiTenancy });

        var denial = svc.Explain(FeatureKeys.HsmFleet);

        Assert.Equal(EntitlementDenialReason.NotEntitled, denial!.Reason);
    }

    [Fact]
    public void Lapsed_maintenance_keeps_the_entitlement_but_withholds_newer_features()
    {
        // The heart of the perpetual model: entitled forever, available only up to the
        // maintenance date. A feature introduced after it is withheld; the entitlement is not.
        var beforeAnythingShipped = FeatureCatalog.IntroducedOn(FeatureKeys.MultiTenancy)!.Value.AddDays(-1);
        var svc = Licensed(beforeAnythingShipped);

        Assert.True(svc.IsEntitled(FeatureKeys.MultiTenancy), "entitlements are perpetual");
        Assert.False(svc.IsAvailable(FeatureKeys.MultiTenancy));

        var denial = svc.Explain(FeatureKeys.MultiTenancy);
        Assert.Equal(EntitlementDenialReason.MaintenanceLapsed, denial!.Reason);
        Assert.Contains("does not expire", denial.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("security updates", denial.Remediation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Availability_does_not_consult_the_clock()
    {
        // Both sides of the comparison come from the licence and the catalogue, so a licence
        // whose maintenance ended years ago still covers what it covered. This codebase has
        // already lost a day to a host whose CMOS clock had drifted; entitlement must not be
        // the next thing NTP can break.
        var longExpired = FeatureCatalog.IntroducedOn(FeatureKeys.MultiTenancy)!.Value;
        var svc = Licensed(longExpired);

        Assert.True(svc.IsAvailable(FeatureKeys.MultiTenancy));
    }

    [Fact]
    public void Limits_are_read_from_the_licence_and_absent_when_unset()
    {
        var unlimited = Licensed(new DateOnly(2099, 1, 1));
        Assert.Null(unlimited.GetLimit(LicenseLimits.MaxTenants));

        var capped = Licensed(new DateOnly(2099, 1, 1), null,
            new Dictionary<string, int>(StringComparer.Ordinal) { [LicenseLimits.MaxTenants] = 10 });
        Assert.Equal(10, capped.GetLimit(LicenseLimits.MaxTenants));
    }

    // ---- SpaceCreationGate ------------------------------------------------------------------

    [Fact]
    public void The_free_edition_is_recommended_a_licence_from_the_fifth_space()
    {
        Assert.Equal(SpaceCreationGate.LicenceRecommendation,
            SpaceCreationGate.Recommendation(Free(), SpaceCreationGate.SpacesWithoutLicence));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    public void Up_to_four_spaces_nothing_is_said(int existing)
    {
        Assert.Null(SpaceCreationGate.Recommendation(Free(), existing));
    }

    [Fact]
    public void A_refusal_names_the_feature_before_its_key()
    {
        // The name tells the reader whether this concerns them; the key is what they quote in a
        // ticket. An identifier alone makes them decode it first to find out if it is relevant.
        var refusal = FeatureGate.Require(Free(), FeatureKeys.MultiTenancy, "Creating additional spaces", "Existing spaces are unaffected.");

        Assert.NotNull(refusal);
        var nameAt = refusal!.Message.IndexOf("multi-tenancy", StringComparison.Ordinal);
        var keyAt = refusal.Message.IndexOf(FeatureKeys.MultiTenancy, StringComparison.Ordinal);

        Assert.True(nameAt >= 0, $"refusal does not name the feature: {refusal.Message}");
        Assert.True(keyAt >= 0, $"refusal does not carry the key: {refusal.Message}");
        Assert.True(nameAt < keyAt, $"the key precedes the name: {refusal.Message}");
    }

    [Fact]
    public void A_lapsed_licence_is_still_recommended_one()
    {
        var lapsed = Licensed(FeatureCatalog.IntroducedOn(FeatureKeys.MultiTenancy)!.Value.AddDays(-1));

        Assert.NotNull(SpaceCreationGate.Recommendation(lapsed, SpaceCreationGate.SpacesWithoutLicence));
    }

    [Fact]
    public void An_entitled_installation_is_never_recommended_a_licence()
    {
        Assert.Null(SpaceCreationGate.Recommendation(Licensed(new DateOnly(2099, 1, 1)), 500));
    }

    [Fact]
    public void A_licence_ceiling_no_longer_refuses_creation()
    {
        var capped = Licensed(new DateOnly(2099, 1, 1), null,
            new Dictionary<string, int>(StringComparer.Ordinal) { [LicenseLimits.MaxTenants] = 2 });

        Assert.Null(SpaceCreationGate.Recommendation(capped, 7));
    }
}
