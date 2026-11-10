namespace ModularCA.Shared.Utils;

/// <summary>
/// The rules for the scrypt cost an administrator sets for keystore files
/// (<c>SecurityPolicy.KeystoreScryptN</c>, <c>KeystoreScryptR</c> and <c>KeystoreScryptP</c>).
/// scrypt needs N to be a power of two greater than 1, and one derivation takes about
/// 128 · N · r bytes of memory.
/// </summary>
/// <remarks>
/// <para>
/// A new setting is held to <see cref="MaxMemoryBytes"/>, 1 GiB per derivation. That is
/// libsodium's "sensitive" scrypt level (<c>crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE</c>)
/// and eight times OWASP's recommended minimum of N = 2^17, r = 8, p = 1 (128 MiB). The default,
/// N = 2^16, r = 8, p = 1, takes 64 MiB, and N = 2^20 with r = 8 is exactly the ceiling. Backup
/// passwords have the same ceiling (<c>BackupKeyManager.MaxScryptMemoryBytes</c>). The ranges
/// alone allowed N = 2^20 with r = 32: 4 GiB for each derivation, enough to exhaust a small host.
/// </para>
/// <para>
/// The ceiling applies to setting a value, not to using one. A keystore file written under an
/// earlier, larger setting still opens, because the file parser keeps its own wider bounds, and
/// a stored setting above the ceiling is still honoured on write so that an install keeps the
/// cost it chose, with a warning; changing it means saving a value within the ceiling.
/// </para>
/// <para>
/// A stored N that is not a power of two can never have produced a keystore file, so no file
/// carries one. It is refused when it is set, and refused on write, with a message that says
/// how to fix it, rather than failing deep inside scrypt.
/// </para>
/// </remarks>
public static class KeystoreScryptPolicy
{
    /// <summary>The smallest N that may be set: 2^14.</summary>
    public const int MinN = 1 << 14;

    /// <summary>The largest N that may be set: 2^20.</summary>
    public const int MaxN = 1 << 20;

    /// <summary>The largest block size r that may be set.</summary>
    public const int MaxR = 32;

    /// <summary>The largest parallelism p that may be set.</summary>
    public const int MaxP = 16;

    /// <summary>The most memory one derivation may need under a new setting (128 · N · r bytes): 1 GiB.</summary>
    public const long MaxMemoryBytes = 1L << 30;

    /// <summary>Whether <paramref name="n"/> is a power of two greater than 1, which scrypt requires of N.</summary>
    public static bool IsPowerOfTwo(int n) => n > 1 && (n & (n - 1)) == 0;

    /// <summary>The memory one scrypt derivation needs with cost <paramref name="n"/> and block size <paramref name="r"/>, in bytes.</summary>
    public static long MemoryBytes(int n, int r) => 128L * n * r;

    /// <summary>Whether a derivation with cost <paramref name="n"/> and block size <paramref name="r"/> needs more than <see cref="MaxMemoryBytes"/>.</summary>
    public static bool ExceedsMemoryCeiling(int n, int r) => MemoryBytes(n, r) > MaxMemoryBytes;

    /// <summary>
    /// Checks a keystore scrypt setting an administrator wants to save: N a power of two from
    /// <see cref="MinN"/> to <see cref="MaxN"/>, r from 1 to <see cref="MaxR"/>, p from 1 to
    /// <see cref="MaxP"/>, and no more than <see cref="MaxMemoryBytes"/> for one derivation.
    /// </summary>
    /// <param name="n">The cost parameter N.</param>
    /// <param name="r">The block size r.</param>
    /// <param name="p">The parallelism p.</param>
    /// <returns>Null when the setting may be saved; otherwise why not, in a sentence for the administrator.</returns>
    public static string? CheckNewSetting(int n, int r, int p)
    {
        if (!IsPowerOfTwo(n) || n < MinN || n > MaxN)
            return $"KeystoreScryptN must be a power of two from {MinN} (2^14) to {MaxN} (2^20); {n} is not. The default is 65536 (2^16).";
        if (r < 1 || r > MaxR)
            return $"KeystoreScryptR must be from 1 to {MaxR}; {r} is not. The default is 8.";
        if (p < 1 || p > MaxP)
            return $"KeystoreScryptP must be from 1 to {MaxP}; {p} is not. The default is 1.";
        if (ExceedsMemoryCeiling(n, r))
            return $"KeystoreScryptN = {n} with KeystoreScryptR = {r} needs {MemoryBytes(n, r) >> 20} MiB for each keystore key derivation "
                + $"(128 x N x r bytes), more than the {MaxMemoryBytes >> 20} MiB allowed. Lower N or r: at r = 8, N may be at most {MaxN}.";
        return null;
    }

    /// <summary>
    /// Refuses a stored keystore scrypt N that is not a power of two, before a keystore write
    /// reaches scrypt with it. Such a value could be saved before this check existed; every
    /// write with it fails, so the write fails here instead, saying which setting is wrong and
    /// what to set it to. Nothing is written.
    /// </summary>
    /// <param name="n">The stored <c>SecurityPolicy.KeystoreScryptN</c>.</param>
    /// <exception cref="InvalidOperationException">When <paramref name="n"/> is not a power of two greater than 1.</exception>
    public static void RequireUsableStoredN(int n)
    {
        if (!IsPowerOfTwo(n))
            throw new InvalidOperationException(
                $"The security policy's KeystoreScryptN is {n}, which is not a power of two, and scrypt cannot derive a keystore key with it, "
                + $"so no keystore file was written. Set KeystoreScryptN to a power of two from {MinN} to {MaxN} (the default is 65536) "
                + "with PUT /api/v1/admin/security-policy. Existing keystore files are unaffected and still open.");
    }
}
