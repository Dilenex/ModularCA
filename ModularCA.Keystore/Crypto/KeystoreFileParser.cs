using ModularCA.Keystore.KeystoreFormat;
using System.Text;

namespace ModularCA.Keystore.Crypto
{
    /// <summary>
    /// Parses the binary MCAKSTR v2 keystore file format (single-signature) into a structured KeystoreFile object.
    /// Every length field read from the file is bound-checked against a
    /// conservative constant before allocation so a crafted or truncated file can't drive the
    /// parser into an <see cref="OutOfMemoryException"/>. Scrypt cost parameters are also
    /// clamped to a sensible range so a malicious <c>N</c> cannot cause the key derivation
    /// function to allocate gigabytes of memory.
    /// </summary>
    public static class KeystoreFileParser
    {
        // The parser accepts both v2 (legacy, raw main+secondary concat) and v3
        // (length-prefixed scrypt input). The parsed version is surfaced on KeystoreFile so
        // downstream ScryptKeyDeriver picks the right encoding.
        private const string MagicHeaderV2 = "MCAKSTR\x02";
        private const string MagicHeaderV3 = "MCAKSTR\x03";
        private const string MagicHeaderV4 = "MCAKSTR\x04";

        // Per-field maximum sizes. The keystore format is meant for a handful
        // of small private-key entries — a single CA private key is a few hundred bytes for EC,
        // at most a few kilobytes for RSA-8192, and ML-DSA-87 tops out around 5 KiB. 1 MiB per
        // field is ~100x the largest real payload and still keeps a crafted file from driving
        // the parser into a GC pause or OOM. Entry count is bounded so a 2-billion-entry header
        // can't trigger a huge List<>-capacity allocation before we've read anything.
        private const int MaxFieldBytes = 1 << 20;     // 1 MiB
        private const int MaxSaltBytes = 1024;
        private const int MaxEntries = 4096;

        // Scrypt N must be a power of two in a sensible range. Anything outside
        // [2^14, 2^20] is either too weak to defend the keystore or large enough to DoS
        // bootstrap. r and p are clamped to small constants — the writer always pins r=8, p=1
        // so any value outside [1,32] on a parsed file is suspect.
        // These read bounds are deliberately wider than what an administrator may now set
        // (KeystoreScryptPolicy: at most 1 GiB, 128·N·r, per derivation). A file written under
        // an earlier setting of up to N=2^20, r=32 must keep opening, so the ceiling is enforced
        // where a cost is set, not here.
        private const int MinScryptN = 1 << 14;
        private const int MaxScryptN = 1 << 20;
        private const int MaxScryptR = 32;
        private const int MaxScryptP = 32;

        /// <summary>
        /// Reads and parses a keystore file from disk, extracting salt, scrypt params, encrypted entries, and the file signature.
        /// </summary>
        public static KeystoreFile Parse(string path)
        {
            var bytes = File.ReadAllBytes(path);
            var span = new ReadOnlySpan<byte>(bytes);

            // 1. Validate magic header — accept v2 (legacy) and v3.
            RequireBytes(span, 0, 8, "magic header");
            var magic = Encoding.ASCII.GetString(span.Slice(0, 8));
            int formatVersion;
            if (magic == MagicHeaderV4)
                formatVersion = 4;
            else if (magic == MagicHeaderV3)
                formatVersion = 3;
            else if (magic == MagicHeaderV2)
                formatVersion = 2;
            else
                throw new InvalidDataException("Invalid keystore magic header.");

            int cursor = 8;

            // 2. Read salt length (ushort)
            RequireBytes(span, cursor, 2, "salt length");
            ushort saltLength = BitConverter.ToUInt16(span.Slice(cursor, 2));
            cursor += 2;

            if (saltLength == 0 || saltLength > MaxSaltBytes)
                throw new InvalidDataException($"Invalid keystore salt length {saltLength} (expected 1..{MaxSaltBytes}).");

            // 3. Read salt
            RequireBytes(span, cursor, saltLength, "salt");
            byte[] salt = span.Slice(cursor, saltLength).ToArray();
            cursor += saltLength;

            // 4. Read Scrypt params (N, r, p) — bound-checked to refuse crafted files that
            //    would drive SCrypt.Generate into multi-GB allocations.
            RequireBytes(span, cursor, 12, "scrypt parameters");
            int n = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            int r = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            int p = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;

            if (n < MinScryptN || n > MaxScryptN || (n & (n - 1)) != 0)
                throw new InvalidDataException($"Invalid keystore scrypt N={n} (must be a power of two in [{MinScryptN}, {MaxScryptN}]).");
            if (r < 1 || r > MaxScryptR)
                throw new InvalidDataException($"Invalid keystore scrypt r={r} (expected 1..{MaxScryptR}).");
            if (p < 1 || p > MaxScryptP)
                throw new InvalidDataException($"Invalid keystore scrypt p={p} (expected 1..{MaxScryptP}).");

            // 5. Read entry count
            RequireBytes(span, cursor, 4, "entry count");
            int entryCount = BitConverter.ToInt32(span.Slice(cursor, 4)); cursor += 4;
            if (entryCount < 0 || entryCount > MaxEntries)
                throw new InvalidDataException($"Invalid keystore entry count {entryCount} (expected 0..{MaxEntries}).");
            Console.WriteLine("Entry count: " + entryCount);

            var entries = new List<KeystoreFile.KeystoreEntry>(entryCount);
            for (int i = 0; i < entryCount; i++)
            {
                int nonceLen = ReadBoundedInt(span, ref cursor, "nonce");
                RequireBytes(span, cursor, nonceLen, "nonce body");
                byte[] nonce = span.Slice(cursor, nonceLen).ToArray();
                cursor += nonceLen;

                int cipherLen = ReadBoundedInt(span, ref cursor, "ciphertext");
                RequireBytes(span, cursor, cipherLen, "ciphertext body");
                byte[] ciphertext = span.Slice(cursor, cipherLen).ToArray();
                cursor += cipherLen;

                int tagLen = ReadBoundedInt(span, ref cursor, "tag");
                // Enforce tag length to match the AES-256-GCM standard at the
                // parser level. AesGcmDecryptor also enforces this, but catching it here
                // gives a clearer error and refuses the file before any key derivation.
                if (tagLen != 16)
                    throw new InvalidDataException($"Invalid keystore AES-GCM tag length {tagLen} (expected 16).");
                RequireBytes(span, cursor, tagLen, "tag body");
                byte[] tag = span.Slice(cursor, tagLen).ToArray();
                cursor += tagLen;

                RequireBytes(span, cursor, 2, "entry signature length");
                // ushort naturally bounds to 65535 which is well below MaxFieldBytes — the
                // cursor-based slice below handles "past end of file" via RequireBytes.
                ushort sigLen = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
                RequireBytes(span, cursor, sigLen, "entry signature body");
                byte[]? sig = sigLen > 0 ? span.Slice(cursor, sigLen).ToArray() : null;
                cursor += sigLen;

                entries.Add(new KeystoreFile.KeystoreEntry(nonce, ciphertext, tag, sig));
            }

            // 6. Read single file-wide signature. ushort naturally caps at 65535.
            RequireBytes(span, cursor, 2, "file signature length");
            ushort fileSigLen = BitConverter.ToUInt16(span.Slice(cursor, 2)); cursor += 2;
            RequireBytes(span, cursor, fileSigLen, "file signature body");
            byte[]? fileSig = fileSigLen > 0 ? span.Slice(cursor, fileSigLen).ToArray() : null;
            cursor += fileSigLen;

            return new KeystoreFile
            {
                FormatVersion = formatVersion,
                ScryptSalt = Convert.ToBase64String(salt),
                ScryptN = n,
                ScryptR = r,
                ScryptP = p,
                Entries = entries,
                FileSignature = fileSig
            };
        }

        /// <summary>
        /// Reads a bound-checked 32-bit length prefix. A negative or
        /// absurdly large length read from the file throws a descriptive
        /// <see cref="InvalidDataException"/> instead of sliding into an <c>OutOfMemoryException</c>.
        /// </summary>
        private static int ReadBoundedInt(ReadOnlySpan<byte> span, ref int cursor, string fieldName)
        {
            RequireBytes(span, cursor, 4, $"{fieldName} length");
            int value = BitConverter.ToInt32(span.Slice(cursor, 4));
            cursor += 4;
            if (value < 0 || value > MaxFieldBytes)
                throw new InvalidDataException($"Invalid keystore {fieldName} length {value} (expected 0..{MaxFieldBytes}).");
            return value;
        }

        /// <summary>
        /// Throws <see cref="InvalidDataException"/> when the parser would read past the end
        /// of the file, producing a clearer error than the default
        /// <see cref="ArgumentOutOfRangeException"/> from <see cref="ReadOnlySpan{T}.Slice(int, int)"/>.
        /// </summary>
        private static void RequireBytes(ReadOnlySpan<byte> span, int offset, int length, string what)
        {
            if (offset < 0 || length < 0 || (long)offset + length > span.Length)
                throw new InvalidDataException($"Keystore truncated: insufficient bytes for {what} at offset {offset}.");
        }
    }
}
