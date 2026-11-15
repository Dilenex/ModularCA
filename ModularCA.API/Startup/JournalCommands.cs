using System.Text;
using System.Text.Json;
using ModularCA.Journal;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Startup;

/// <summary>
/// The two commands that read the signer's issuance journal from its files and exit:
/// <c>--role signer --journal-head [--journal-directory &lt;path&gt;] [--sealed | --sealed-from &lt;sequence&gt;]</c> and
/// <c>--role signer --journal-verify [--journal-directory &lt;path&gt;]</c>. Both open the segment
/// files for reading only. They create and lock nothing, write no log file, and need no signer,
/// keystore, database or credentials, so they run beside a signer that is appending, on a
/// read-only mount, and on a bare copy of the directory.
/// </summary>
public static class JournalCommands
{
    /// <summary>Prints the journal's head as one line of JSON.</summary>
    public const string HeadFlag = "--journal-head";

    /// <summary>Verifies the whole journal and reports the first fault.</summary>
    public const string VerifyFlag = "--journal-verify";

    /// <summary>
    /// Names the directory to read, instead of the journal home the signer's settings name:
    /// either a home, which is read through its <c>current/</c>, or a directory that holds
    /// segment files itself (<see cref="JournalLayout.ReadDirectory"/>).
    /// </summary>
    public const string DirectoryFlag = "--journal-directory";

    /// <summary>With <see cref="HeadFlag"/>: also read and list every sealed segment.</summary>
    public const string SealedFlag = "--sealed";

    /// <summary>
    /// With <see cref="HeadFlag"/>: also read and list the sealed segments whose first sequence
    /// is at or after the one given, and open no older one. For a caller that already holds
    /// the segments before it.
    /// </summary>
    public const string SealedFromFlag = "--sealed-from";

    /// <summary>With <see cref="VerifyFlag"/>: SHA-256 of the system key the journal is expected to begin under, hex.</summary>
    public const string SystemKeyFlag = "--system-key";

    /// <summary>The exit status for a command line that cannot be read.</summary>
    public const int ExitUsage = 1;

    /// <summary>Whether <paramref name="args"/> name one of the two commands.</summary>
    public static bool IsNamedIn(IReadOnlyList<string> args)
        => args.Any(a => string.Equals(a, HeadFlag, StringComparison.OrdinalIgnoreCase) || string.Equals(a, VerifyFlag, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Runs the command the arguments name and returns the exit status: 0 with the line on
    /// <paramref name="output"/>; 3 when the directory holds no journal; 4 when the chain in what
    /// was read does not hold, with the reason on <paramref name="error"/>; 1 for a command line
    /// that cannot be read.
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="paths">Where the signer's files are, for the directory its settings name.</param>
    /// <param name="output">Standard output: the one line of JSON.</param>
    /// <param name="error">Standard error: the reason for any status but 0.</param>
    public static int Run(IReadOnlyList<string> args, SignerPaths paths, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(paths);
        var head = args.Any(a => string.Equals(a, HeadFlag, StringComparison.OrdinalIgnoreCase));
        var verify = args.Any(a => string.Equals(a, VerifyFlag, StringComparison.OrdinalIgnoreCase));
        if (head && verify)
        {
            error.WriteLine($"{HeadFlag} and {VerifyFlag} are two commands; give one.");
            return ExitUsage;
        }

        ProcessRole role;
        try
        {
            role = ProcessRoles.Parse(args);
        }
        catch (ArgumentException ex)
        {
            error.WriteLine(ex.Message);
            return ExitUsage;
        }
        if (role != ProcessRole.Signer)
        {
            error.WriteLine($"{(head ? HeadFlag : VerifyFlag)} reads the signer's journal: run it as --role signer {(head ? HeadFlag : VerifyFlag)} [{DirectoryFlag} <path>].");
            return ExitUsage;
        }

        string directory;
        byte[]? expectedSystemKey = null;
        ulong? sealedFrom = null;
        try
        {
            // A home is read through its current/; a directory that holds segments itself (a
            // set-aside journal, a bare copy) is read as it is.
            directory = JournalLayout.ReadDirectory(Value(args, DirectoryFlag) is { } named ? Path.GetFullPath(named) : ConfiguredDirectory(paths));
            if (Value(args, SealedFromFlag) is { } first)
            {
                if (!ulong.TryParse(first.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var sequence))
                    throw new ArgumentException($"{SealedFromFlag} takes a sequence: a whole number, the first sequence of the oldest sealed segment to list.");
                sealedFrom = sequence;
            }
            if (Value(args, SystemKeyFlag) is { } hex)
            {
                expectedSystemKey = Convert.FromHexString(hex.Trim());
                if (expectedSystemKey.Length != JournalFormat.HashLength)
                    throw new FormatException();
            }
        }
        catch (ArgumentException ex)
        {
            error.WriteLine(ex.Message);
            return ExitUsage;
        }
        catch (FormatException)
        {
            error.WriteLine($"{SystemKeyFlag} takes the SHA-256 of the system key's public key: 64 hex digits.");
            return ExitUsage;
        }

        if (head)
        {
            var result = JournalHead.Read(directory, includeSealed: args.Any(a => string.Equals(a, SealedFlag, StringComparison.OrdinalIgnoreCase)), sealedFrom);
            if (result.ExitCode == JournalHead.ExitOk)
                output.WriteLine(result.Json);
            else
                error.WriteLine(result.Error);
            return result.ExitCode;
        }
        return Verify(directory, expectedSystemKey, output, error);
    }

    private static int Verify(string directory, byte[]? expectedSystemKey, TextWriter output, TextWriter error)
    {
        var result = JournalVerifier.Verify(directory, new JournalVerifyOptions { ExpectedSystemKey = expectedSystemKey });
        if (result.Fault == null && !result.HasJournal)
        {
            error.WriteLine($"the directory '{directory}' holds no journal");
            return JournalHead.ExitNoJournal;
        }

        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteBoolean("ok", result.Fault == null);
            if (result.Fault is { } fault)
            {
                json.WriteStartObject("fault");
                json.WriteString("segment", fault.Segment);
                json.WriteNumber("seq", fault.Seq);
                json.WriteString("reason", fault.Reason);
                json.WriteEndObject();
            }
            json.WriteNumber("segments", result.Segments.Count);
            json.WriteNumber("records", result.Records);
            json.WriteNumber("checkpoints", result.Checkpoints);
            if (result.Head is { } head)
            {
                json.WriteString("instanceId", head.InstanceId);
                json.WriteNumber("seq", head.Seq);
                json.WriteString("hash", JournalHead.Hex(head.Hash));
                if (head.Key != null)
                    json.WriteString("systemKey", JournalHead.Hex(head.Key.SystemKey));
            }
            json.WriteStartArray("unvouched");
            foreach (var change in result.Unvouched)
            {
                json.WriteStartObject();
                json.WriteString("segment", change.Segment);
                json.WriteNumber("seq", change.Seq);
                json.WriteString("newSystemKey", JournalHead.Hex(change.NewSystemKey));
                json.WriteString("explainedBy", change.Explains.Kind == ExplanationKind.Restore ? "restore" : "changedIncarnation");
                if (change.Explains.Archive != null) json.WriteString("archive", change.Explains.Archive);
                if (change.Explains.ArchiveInstanceId != null) json.WriteString("archiveInstanceId", change.Explains.ArchiveInstanceId);
                if (change.Explains.ArchiveCreatedAt is long created) json.WriteString("archiveCreatedAtUtc", JournalFormat.FromMicros(created).UtcDateTime);
                if (change.Explains.OldIncarnation != null) json.WriteString("oldIncarnation", JournalHead.Hex(change.Explains.OldIncarnation));
                if (change.Explains.NewIncarnation != null) json.WriteString("newIncarnation", JournalHead.Hex(change.Explains.NewIncarnation));
                json.WriteEndObject();
            }
            json.WriteEndArray();
            json.WriteStartArray("notes");
            foreach (var note in result.Notes)
                json.WriteStringValue(note);
            json.WriteEndArray();
            json.WriteEndObject();
        }
        output.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
        if (result.Fault == null)
            return JournalHead.ExitOk;
        error.WriteLine(result.Fault.ToString());
        return JournalHead.ExitBrokenChain;
    }

    /// <summary>
    /// The directory the signer's settings name: the environment variable, then
    /// <c>Signer.Journal.Directory</c> in the signer's settings file when that file can be read,
    /// then the default beside the keystores. A settings file that is missing or does not parse
    /// is not an error here: the command needs none.
    /// </summary>
    internal static string ConfiguredDirectory(SignerPaths paths)
    {
        var signer = new SignerConfig();
        try
        {
            if (File.Exists(paths.ConfigPath))
                signer = YamlConfigLoader.Load(paths.ConfigPath).Signer ?? signer;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            signer = new SignerConfig();
        }
        var fromEnvironment = Environment.GetEnvironmentVariable(EnvVarConfigOverlay.SignerJournalDirectoryVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
            signer.Journal = new SignerJournalConfig { Directory = fromEnvironment.Trim() };
        return paths.JournalDirectory(signer);
    }

    private static string? Value(IReadOnlyList<string> args, string flag)
    {
        for (var i = 0; i < args.Count; i++)
        {
            if (!string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase))
                continue;
            if (i + 1 >= args.Count || string.IsNullOrWhiteSpace(args[i + 1]) || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"{flag} needs a value.");
            return args[i + 1];
        }
        return null;
    }
}
