using System.Text.Json;
using ModularCA.Ssh;

namespace ModularCA.Core.Services;

/// <summary>An SSH CA key row that names a key file, as the upgrade check reads it.</summary>
/// <param name="Id">The <c>SshCaKeys</c> row.</param>
/// <param name="Name">The SSH CA key's name.</param>
/// <param name="PublicKey">The row's public key, an authorized_keys line.</param>
/// <param name="KeyFile">The path the row gives for its key file.</param>
/// <param name="Enabled">Whether the row and its CA are enabled and the CA is not deleted.</param>
public sealed record SshUpgradeKeyRow(Guid Id, string Name, string? PublicKey, string? KeyFile, bool Enabled);

/// <summary>An SSH signing profile, as the upgrade check reads it.</summary>
/// <param name="Id">The profile.</param>
/// <param name="Name">Its name.</param>
/// <param name="AllowUserCerts">Whether it signs user certificates.</param>
/// <param name="DefaultExtensions">Its default extensions, a JSON array of strings.</param>
public sealed record SshUpgradeSigningProfile(Guid Id, string Name, bool AllowUserCerts, string? DefaultExtensions);

/// <summary>An SSH certificate profile, as the upgrade check reads it.</summary>
/// <param name="Id">The profile.</param>
/// <param name="Name">Its name.</param>
/// <param name="RequiredExtensions">The extensions it adds to every certificate, a JSON array of strings.</param>
public sealed record SshUpgradeCertProfile(Guid Id, string Name, string? RequiredExtensions);

/// <summary>A live SSH user certificate, as the upgrade check reads it.</summary>
/// <param name="KeyId">The certificate's key id.</param>
/// <param name="Principals">Its principals, a JSON array of strings.</param>
public sealed record SshUpgradeUserCertificate(string? KeyId, string? Principals);

/// <summary>What the upgrade check concludes about the SSH CA key files.</summary>
/// <param name="Refused">Whether the upgrade is refused until the operator has acted.</param>
/// <param name="Summary">One clause for the verdict line.</param>
/// <param name="Detail">The finding, possibly of several lines.</param>
public sealed record SshUpgradeKeysFinding(bool Refused, string Summary, string Detail);

/// <summary>
/// What <c>--upgrade-check</c> says about SSH (<c>docs/architecture/ssh-keystore.md</c>, "Upgrade
/// check"): whether every SSH CA key file the first start will import into the signer is there
/// and holds its SSH CA's key, which user signing profiles relied on extensions that were
/// added by default before certificates became exact, and what SSH login names change for
/// requests (<c>docs/architecture/ssh-login-names.md</c>). The key files themselves are looked
/// at by the import, which is the one place that reads them.
/// </summary>
public static class SshUpgradeCheck
{
    /// <summary>The name of the key finding in the report.</summary>
    public const string KeysFindingName = "SSH CA keys";

    /// <summary>The five permits every user certificate carried before, whatever its profile named.</summary>
    public static readonly IReadOnlyList<string> FormerDefaultPermits =
    [
        "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc",
    ];

    /// <summary>
    /// The finding for the SSH CA key files. No row with a key file is clean. Every file present
    /// and holding its row's key is clean, with the count the first start imports. A file that
    /// is missing, unreadable, encrypted or another key refuses the upgrade when its SSH CA is
    /// enabled, naming the SSH CA, its row and the path; for a disabled SSH CA it is only
    /// mentioned, since disabling is the remedy the refusal offers.
    /// </summary>
    /// <param name="rows">The SSH CA key rows that name a key file.</param>
    /// <param name="installDirectory">The installed application directory, which a relative key path is relative to.</param>
    public static SshUpgradeKeysFinding Keys(IReadOnlyList<SshUpgradeKeyRow> rows, string installDirectory)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (rows.Count == 0)
            return new SshUpgradeKeysFinding(false, KeysFindingName, "no SSH CA key is a file on a node; nothing to import.");

        var usable = 0;
        var blocking = new List<string>();
        var left = new List<string>();
        foreach (var row in rows.OrderBy(r => r.Name, StringComparer.Ordinal).ThenBy(r => r.Id))
        {
            var finding = SshKeyFileImport.Inspect(row.Name, row.PublicKey, row.KeyFile, installDirectory);
            if (finding.Usable)
            {
                usable++;
                continue;
            }
            var line = $"'{row.Name}' ({row.Id}), expected at {finding.KeyFile ?? "(no path on the row)"}: {SshKeyImportReasons.Sentence(finding.Code!)}";
            (row.Enabled ? blocking : left).Add(line);
        }

        if (blocking.Count > 0)
        {
            var lines = new List<string>
            {
                $"{blocking.Count} SSH CA key file(s) are missing or do not hold their SSH CA's key. Such a key cannot be imported into the signer, "
                + "and its SSH CA would sign nothing after the upgrade:",
            };
            lines.AddRange(blocking.Select(b => "  " + b));
            lines.Add("Put the files in place on this host, or disable those SSH CAs, then run the check again. The key files are on the host "
                + "that runs the control role: on a split install, run this check on that host.");
            return new SshUpgradeKeysFinding(true, $"{KeysFindingName}: {blocking.Count} key file(s) missing or not matching", string.Join(Environment.NewLine, lines));
        }

        var detail = $"{usable} SSH CA key(s) will be imported into the signer at first start and their files deleted; "
            + "archives made before this upgrade still contain them in plaintext";
        if (left.Count > 0)
        {
            detail += Environment.NewLine + $"{left.Count} disabled SSH CA key(s) have no usable key file and stay as they are:"
                + Environment.NewLine + string.Join(Environment.NewLine, left.Select(l => "  " + l));
        }
        return new SshUpgradeKeysFinding(false, KeysFindingName, detail);
    }

    /// <summary>
    /// The note about SSH signing profiles that relied on default extensions, or null when no
    /// profile did. Before this release every user certificate carried the five
    /// <see cref="FormerDefaultPermits"/> whatever its profile named; now it carries exactly
    /// what the signing profile's default extensions and the cert profile's required
    /// extensions come to (<see cref="SshCertificateOptions"/>). A user signing profile is
    /// listed when, with some cert profile, or with none when there is none, a certificate from
    /// it lacks one of the five. It informs only and never refuses.
    /// </summary>
    /// <param name="signingProfiles">Every SSH signing profile.</param>
    /// <param name="certProfiles">Every SSH certificate profile; any of them can be combined with a signing profile.</param>
    /// <param name="beforeUpgrade">
    /// Whether the database is still from before exact extensions, so that the change is ahead
    /// ("will be narrower than before"). False once it has been upgraded: the same profiles are
    /// still listed, as the ones whose certificates carry fewer permits than they once did.
    /// </param>
    public static string? ProfilesNote(IReadOnlyList<SshUpgradeSigningProfile> signingProfiles, IReadOnlyList<SshUpgradeCertProfile> certProfiles,
        bool beforeUpgrade = true)
    {
        ArgumentNullException.ThrowIfNull(signingProfiles);
        ArgumentNullException.ThrowIfNull(certProfiles);
        var required = certProfiles.Select(c => Strings(c.RequiredExtensions)).ToList();

        var narrower = new List<string>();
        foreach (var profile in signingProfiles.Where(p => p.AllowUserCerts).OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.Id))
        {
            var defaults = Strings(profile.DefaultExtensions);
            var named = Permits(defaults);
            // What a certificate from this profile carries whichever cert profile it is combined with.
            var always = required.Count == 0
                ? named
                : required.Select(r => Permits(defaults.Concat(r))).Aggregate((a, b) => a.Intersect(b, StringComparer.Ordinal).ToList());
            var missing = FormerDefaultPermits.Except(always, StringComparer.Ordinal).ToList();
            if (missing.Count == 0)
                continue;
            narrower.Add($"  '{profile.Name}' ({profile.Id}): names {(named.Count == 0 ? "no permit" : string.Join(", ", named))}; "
                + $"certificates from it {(beforeUpgrade ? "will no longer carry" : "do not carry")} {string.Join(", ", missing)}");
        }
        if (narrower.Count == 0)
            return null;

        var lines = new List<string>
        {
            beforeUpgrade
                ? $"{narrower.Count} SSH signing profile(s) for user certificates relied on the extensions the OpenSSH key tool added to every user "
                  + "certificate by default. From this release a certificate carries exactly the extensions its profiles name, so certificates from "
                  + "these profiles will be narrower than before:"
                : $"{narrower.Count} SSH signing profile(s) for user certificates name fewer permits than every user certificate carried by default "
                  + "before certificates became exact. A certificate carries exactly the extensions its profiles name, so certificates from these "
                  + "profiles are narrower than they were then:",
        };
        lines.AddRange(narrower);
        lines.Add("To keep a permit, add it to the signing profile's default extensions. A cert profile's required extensions are added too; "
            + "a request that names its own extensions carries those and the required ones, and nothing by default.");
        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// The note about SSH login names, or null when the install has no SSH CA key. From this
    /// release the CA writes the key id, a self-service request may only name the requester's
    /// own username and the login names granted to them, and the admin form signs for a user or
    /// a service identity. It counts the live user certificates that carry a name other than
    /// their key id, which are the ones a requester could not get again as they are; they stay
    /// valid until they expire. It informs only and never refuses.
    /// </summary>
    /// <param name="sshCaKeys">How many SSH CA keys the install has.</param>
    /// <param name="liveUserCertificates">The unexpired, unrevoked user certificates.</param>
    /// <param name="beforeUpgrade">Whether the database is still from before login names, so that the change is ahead.</param>
    public static string? LoginNamesNote(int sshCaKeys, IReadOnlyList<SshUpgradeUserCertificate> liveUserCertificates, bool beforeUpgrade = true)
    {
        ArgumentNullException.ThrowIfNull(liveUserCertificates);
        if (sshCaKeys <= 0)
            return null;
        var otherNames = liveUserCertificates.Count(c => Strings(c.Principals).Any(p => !string.Equals(p, c.KeyId, StringComparison.Ordinal)));
        var lines = new List<string>
        {
            beforeUpgrade
                ? "After this upgrade the CA writes the key id of every SSH certificate, and a self-service request may only name the requester's "
                  + "own username and the login names granted to them on the SSH CA. The admin form signs for a user, who must hold the names, or "
                  + "for a service identity. A request that sends a key id, or names another account, will be refused."
                : "The CA writes the key id of every SSH certificate, and a self-service request may only name the requester's own username and "
                  + "the login names granted to them on the SSH CA. The admin form signs for a user, who must hold the names, or for a service "
                  + "identity. A request that sends a key id, or names another account, is refused.",
            $"{otherNames} of {liveUserCertificates.Count} live user certificate(s) carry a name other than their key id. "
            + (beforeUpgrade ? "The upgrade revokes none of them: they stay valid until they expire." : "The upgrade revoked none of them: they stay valid until they expire."),
            "Every SSH CA key lets everyone log in as their own username until that is turned off on the key. Grant the other login names "
            + "on each SSH CA before those certificates are due to be asked for again.",
        };
        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>The former default permits among what <paramref name="options"/> come to as certificate extensions.</summary>
    private static List<string> Permits(IEnumerable<string> options)
    {
        var carried = SshCertificateOptions.From(options).Extensions.Select(e => e.Name).ToHashSet(StringComparer.Ordinal);
        return FormerDefaultPermits.Where(carried.Contains).ToList();
    }

    /// <summary>A JSON array of strings as a list; anything else is no option at all.</summary>
    private static List<string> Strings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json)?.Where(s => s != null).ToList() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
