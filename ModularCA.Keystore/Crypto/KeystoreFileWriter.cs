using System.Text;

namespace ModularCA.Keystore.Crypto;

/// <summary>
/// Writes encrypted keystore entries and a single system CA signature to the MCAKSTR v2 binary file format.
/// </summary>
public static class KeystoreFileWriter
{
    /// <summary>
    /// On-disk magic header identifying the keystore format version.
    /// <list type="bullet">
    /// <item>V2 — raw <c>main + secondary</c> scrypt input concatenation (legacy).</item>
    /// <item>V3 — length-prefixed UTF-8 scrypt input.</item>
    /// <item>V4 — per-entry key via HKDF-SHA256(file_master_key, "entry:" || u32be(index)),
    /// and entry signature covers <c>(index, nonce, ciphertext, tag)</c> instead of
    /// <c>(nonce, ciphertext, tag)</c>. File-level signature unchanged.</item>
    /// </list>
    /// The parser accepts all three so existing V2/V3 keystores keep loading; every new
    /// write produced by this writer uses the current version.
    /// </summary>
    public const int CurrentFormatVersion = 4;

    private static readonly byte[] MagicHeader = Encoding.ASCII.GetBytes("MCAKSTR\x04");

    /// <summary>
    /// Scrypt key-derivation parameters (CPU/memory cost N, block size R, parallelism P).
    /// </summary>
    public record ScryptParams(int N, int R, int P);

    /// <summary>
    /// An encrypted keystore entry with its nonce, ciphertext, authentication tag, and a single signature.
    /// </summary>
    public record EncryptedEntry(byte[] Nonce, byte[] Ciphertext, byte[] Tag, byte[]? Signature);

    /// <summary>
    /// Writes a complete keystore file with all encrypted entries and a single file-level signature from the system CA.
    /// Writes to <c>{path}.tmp</c> first, a new file only its owner can read from the moment it is
    /// created (<see cref="ModularCA.Shared.Utils.FileSecurityUtil.CreateOwnerOnly(string, Action{FileStream}, bool)"/>),
    /// flushes+fsync, then atomically renames via
    /// <see cref="File.Replace(string, string, string?)"/>. The previous file is kept as <c>{path}.bak</c>
    /// so a crash mid-rename leaves both the pre-image and the new file on disk. A crash mid-write to
    /// the <c>.tmp</c> leaves the original file untouched.
    /// </summary>
    public static void WriteEntireKeystore(
        string path,
        byte[] salt,
        ScryptParams scrypt,
        List<EncryptedEntry> entries,
        byte[]? fileSig = null)
    {
        var tmpPath = path + ".tmp";
        var bakPath = path + ".bak";

        // Remove any leftover .tmp from a previous crashed write so we never inherit stale bytes.
        if (File.Exists(tmpPath))
            File.Delete(tmpPath);

        // Owner-only from creation: the rename below gives the keystore the temp file's mode, so a
        // temp file made at default permissions was the keystore's mode until the caller's chmod.
        ModularCA.Shared.Utils.FileSecurityUtil.CreateOwnerOnly(tmpPath, stream =>
        {
            using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

            writer.Write(MagicHeader);
            writer.Write((ushort)salt.Length);
            writer.Write(salt);
            writer.Write(scrypt.N);
            writer.Write(scrypt.R);
            writer.Write(scrypt.P);

            writer.Write(entries.Count);

            foreach (var entry in entries)
            {
                writer.Write(entry.Nonce.Length);
                writer.Write(entry.Nonce);

                writer.Write(entry.Ciphertext.Length);
                writer.Write(entry.Ciphertext);

                writer.Write(entry.Tag.Length);
                writer.Write(entry.Tag);

                KeystoreSignatureBlock.Write(writer, entry.Signature);
            }

            // Single file-wide signature from the system CA
            KeystoreSignatureBlock.Write(writer, fileSig);

            writer.Flush();
            stream.Flush(flushToDisk: true);
        });

        if (File.Exists(path))
        {
            // File.Replace requires the destination to exist; it also handles the .bak copy
            // as a single atomic NTFS/ext4 rename where the filesystem supports it.
            File.Replace(tmpPath, path, bakPath, ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(tmpPath, path);
        }
    }
}
