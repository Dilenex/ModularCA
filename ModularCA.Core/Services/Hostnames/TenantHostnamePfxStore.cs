using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ModularCA.Core.Services.Hostnames;

/// <summary>
/// Where tenant hostname certificates and their private keys live on disk: PKCS#12 files under
/// <c>config/tenant-tls/</c>, one per hostname, protected exactly as <c>config/api-tls.pfx</c> is:
/// the same <c>Https.CertificatePassword</c>, the same owner-only file permissions, the same
/// write-to-temp, load-test, then rename commit.
/// </summary>
public static class TenantHostnamePfxStore
{
    /// <summary>Key alias inside each PKCS#12 file.</summary>
    public const string KeyAlias = "tenant-tls";

    /// <summary>The directory holding the files, beside <c>api-tls.pfx</c>.</summary>
    public static string Directory => Path.Combine(AppContext.BaseDirectory, "config", "tenant-tls");

    /// <summary>The file for one hostname row.</summary>
    public static string PathFor(Guid hostnameId) => Path.Combine(Directory, $"{hostnameId:N}.pfx");

    /// <summary>
    /// Writes <paramref name="store"/> for the hostname and returns the certificate as loaded back
    /// from the committed file. The file is written to a sibling <c>.new</c> first, load-tested,
    /// then moved into place, so a crash mid-write never leaves a half-written PFX where the
    /// listener expects a good one.
    /// </summary>
    public static X509Certificate2 Write(Guid hostnameId, Pkcs12Store store, string password)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var path = PathFor(hostnameId);
        var temp = path + ".new";
        try
        {
            using (var fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                store.Save(fs, password.ToCharArray(), new SecureRandom());
            FileSecurityUtil.SetOwnerOnly(temp);
            var loaded = X509CertificateLoader.LoadPkcs12FromFile(temp, password, X509KeyStorageFlags.MachineKeySet);
            File.Move(temp, path, overwrite: true);
            return loaded;
        }
        finally
        {
            if (File.Exists(temp))
            {
                try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
    }

    /// <summary>The certificate for one hostname, or null when there is no file or it will not load.</summary>
    public static X509Certificate2? TryLoad(Guid hostnameId, string password, Action<string>? onError = null)
    {
        var path = PathFor(hostnameId);
        if (!File.Exists(path)) return null;
        try
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.MachineKeySet);
        }
        catch (Exception ex)
        {
            onError?.Invoke($"{path}: {ex.Message}");
            return null;
        }
    }

    /// <summary>Removes the hostname's file, if any.</summary>
    public static void Delete(Guid hostnameId)
    {
        var path = PathFor(hostnameId);
        if (File.Exists(path)) File.Delete(path);
    }

    /// <summary>
    /// Every hostname that has a certificate on record, with its certificate from disk. Rows
    /// whose file is missing or unreadable are reported and skipped; the listener then answers
    /// that name with the console's certificate until the next issuance.
    /// </summary>
    public static IReadOnlyDictionary<string, X509Certificate2> LoadAll(ModularCADbContext db, string password, Action<string>? onError = null)
    {
        var map = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        var rows = db.TenantHostnames.AsNoTracking()
            .Where(h => h.CertificateId != null)
            .Select(h => new { h.Id, h.Hostname })
            .ToList();
        foreach (var row in rows)
        {
            var cert = TryLoad(row.Id, password, onError);
            if (cert == null)
            {
                onError?.Invoke($"No usable certificate file for tenant hostname {row.Hostname}; it is served with the default certificate.");
                continue;
            }
            map[row.Hostname] = cert;
        }
        return map;
    }
}
