using System.Security;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Keystore;

/// <summary>
/// Covers <see cref="KeystoreService.LoadVerifiedPinnedSpki"/>, the authenticated way to read a
/// keystore's pinned signer SPKI.
/// <para>
/// The pin says which CA is allowed to have signed a keystore file. Verifying a file signature
/// against a pin that nobody authenticated only proves the file agrees with the database — which
/// is worth nothing when the database is what an attacker can write to. That is why the pin
/// carries its own MAC, keyed by the secondary passphrase, which lives outside the database.
/// </para>
/// <para>
/// Two call sites read the pin without that check and both mattered: the Unlocker (the
/// break-glass tool, where the operator is already in an incident) and
/// <c>BackupRestore.VerifyRestoredKeystoresOrThrow</c> (where the database being consulted was
/// itself just restored from an archive). The runtime loader had always done it; these are the
/// siblings that missed the pattern.
/// </para>
/// </summary>
public class PinnedSpkiMacTests
{
    private const string Keystore = "ca-certs.keystore";
    private const string Secondary = "secondary-passphrase-for-test";

    /// <summary>Arbitrary but well-formed SPKI SHA-256 hex.</summary>
    private const string Spki = "9f2c4a1b8e7d6350f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708";

    private static KeystoreEntryEntity Row(string? spki, byte[]? mac) => new()
    {
        Name = Keystore,
        Salt = string.Empty,
        CreatedAt = DateTime.UtcNow,
        Enabled = true,
        SigningCaSpkiSha256 = spki,
        SigningCaSpkiSha256Mac = mac,
    };

    [Fact]
    public void Returns_the_pin_when_the_mac_matches()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Keystores.Add(Row(Spki, KeystoreService.ComputeSpkiPinMac(Spki, Secondary)));
        db.SaveChanges();

        var pinned = KeystoreService.LoadVerifiedPinnedSpki(db, Keystore, Secondary);

        Assert.Equal(Spki, pinned);
    }

    [Fact]
    public void Throws_when_the_pin_was_swapped_under_a_stale_mac()
    {
        // The attack this exists to stop: write access to the app DB, no access to the secondary
        // passphrase. The attacker repoints the pin at their own CA but cannot recompute the MAC.
        const string attackerSpki = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        using var db = InMemoryDbContextFactory.Create();
        db.Keystores.Add(Row(attackerSpki, KeystoreService.ComputeSpkiPinMac(Spki, Secondary)));
        db.SaveChanges();

        var ex = Assert.Throws<SecurityException>(
            () => KeystoreService.LoadVerifiedPinnedSpki(db, Keystore, Secondary));
        Assert.Contains("MAC mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Throws_when_the_secondary_passphrase_is_wrong()
    {
        // Same failure, benign cause: the secondary passphrase was rotated after the pin's MAC
        // was written. Worth failing on — keystores written under the old passphrase cannot be
        // decrypted with the new one either, so this surfaces the real problem early.
        using var db = InMemoryDbContextFactory.Create();
        db.Keystores.Add(Row(Spki, KeystoreService.ComputeSpkiPinMac(Spki, Secondary)));
        db.SaveChanges();

        Assert.Throws<SecurityException>(
            () => KeystoreService.LoadVerifiedPinnedSpki(db, Keystore, "a-different-secondary"));
    }

    [Fact]
    public void Accepts_a_legacy_row_that_has_no_mac()
    {
        // Installs predating the MAC column must keep loading; the MAC is populated on the next
        // keystore rewrite. VerifySpkiPinMac warns once and proceeds.
        using var db = InMemoryDbContextFactory.Create();
        db.Keystores.Add(Row(Spki, mac: null));
        db.SaveChanges();

        Assert.Equal(Spki, KeystoreService.LoadVerifiedPinnedSpki(db, Keystore, Secondary));
    }

    [Fact]
    public void Returns_null_when_no_pin_is_stored()
    {
        // No pin at all is the older legacy shape. Callers pass the null through to
        // FindValidSigner, which falls back to "any IsCA cert" with a loud warning — unchanged
        // behaviour, and not this method's decision to make.
        using var db = InMemoryDbContextFactory.Create();
        db.Keystores.Add(Row(spki: null, mac: null));
        db.SaveChanges();

        Assert.Null(KeystoreService.LoadVerifiedPinnedSpki(db, Keystore, Secondary));
    }

    [Fact]
    public void Returns_null_when_the_keystore_has_no_row()
    {
        using var db = InMemoryDbContextFactory.Create();

        Assert.Null(KeystoreService.LoadVerifiedPinnedSpki(db, "never-seen.keystore", Secondary));
    }

    [Fact]
    public void Mac_is_bound_to_both_the_pin_and_the_passphrase()
    {
        // Guards the derivation itself: a MAC that ignored either input would let one of the two
        // tampering routes above through, and neither test above would catch it on its own.
        var baseline = KeystoreService.ComputeSpkiPinMac(Spki, Secondary);

        Assert.NotEqual(baseline, KeystoreService.ComputeSpkiPinMac(Spki, "other-secondary"));
        Assert.NotEqual(
            baseline,
            KeystoreService.ComputeSpkiPinMac("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", Secondary));
        Assert.Equal(baseline, KeystoreService.ComputeSpkiPinMac(Spki, Secondary));
    }
}
