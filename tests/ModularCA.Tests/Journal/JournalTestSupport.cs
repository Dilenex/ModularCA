using Xunit;
using ModularCA.Journal;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>An ECDSA P-256 key the journal tests sign with.</summary>
internal sealed class TestJournalKey : IJournalSigningKey
{
    private readonly AsymmetricKeyParameter _private;

    public TestJournalKey()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        var pair = generator.GenerateKeyPair();
        _private = pair.Private;
        PublicKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetDerEncoded();
    }

    public byte[] PublicKey { get; }

    public string Algorithm => "SHA256WITHECDSA";

    public int Signatures { get; private set; }

    public byte[] Sign(byte[] message)
    {
        Signatures++;
        var signer = SignerUtilities.GetSigner(Algorithm);
        signer.Init(true, _private);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }
}

/// <summary>
/// File operations that record what the writer did and fail on demand: every append, flush and
/// rename by path, a gate that holds a flush until the test opens it, and switches that make
/// the next create, append or flush throw.
/// </summary>
internal sealed class RecordingJournalFiles : IJournalFiles
{
    private readonly object _gate = new();
    private readonly Dictionary<string, MemoryStream> _appended = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Events { get; } = new();
    public ManualResetEventSlim FlushGate { get; } = new(initialState: true);
    public ManualResetEventSlim FlushEntered { get; } = new(initialState: false);
    public Func<string, Exception?>? FailCreate { get; set; }
    public Func<string, int, Exception?>? FailAppend { get; set; }
    public Func<string, Exception?>? FailFlush { get; set; }
    public int Flushes { get; private set; }

    /// <summary>The longest each file has ever been, by its current path; a shorter length later is a truncation.</summary>
    public Dictionary<string, long> HighWater { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void EnsureDirectory(string directory) => JournalFiles.Default.EnsureDirectory(directory);

    public IJournalAppendFile Create(string path, bool overStub)
    {
        if (FailCreate?.Invoke(path) is { } failure)
            throw failure;
        lock (_gate)
        {
            Events.Add($"create {Path.GetFileName(path)}{(overStub ? " over-stub" : string.Empty)}");
            _appended[path] = new MemoryStream();
            if (!overStub)
                HighWater[path] = 0;
        }
        return new Recorded(this, path, JournalFiles.Default.Create(path, overStub));
    }

    public void Rename(string from, string to, bool overStub)
    {
        lock (_gate)
        {
            Events.Add($"rename {Path.GetFileName(from)} -> {Path.GetFileName(to)}");
            if (_appended.Remove(from, out var bytes))
                _appended[to] = bytes;
            if (HighWater.Remove(from, out var mark))
                HighWater[to] = mark;
        }
        JournalFiles.Default.Rename(from, to, overStub);
    }

    /// <summary>The bytes the writer appended to the file now at <paramref name="path"/>, in order.</summary>
    public byte[] Appended(string path)
    {
        lock (_gate)
            return _appended[path].ToArray();
    }

    /// <summary>Checks that no file the writer made is shorter than it has ever been.</summary>
    public void AssertNothingShrank()
    {
        lock (_gate)
        {
            foreach (var (path, mark) in HighWater.ToList())
            {
                var length = new FileInfo(path).Length;
                Assert.True(length >= mark, $"{Path.GetFileName(path)} was {mark} bytes and is now {length}");
                HighWater[path] = length;
            }
        }
    }

    private sealed class Recorded(RecordingJournalFiles owner, string path, IJournalAppendFile inner) : IJournalAppendFile
    {
        public void Append(ReadOnlySpan<byte> bytes)
        {
            if (owner.FailAppend?.Invoke(path, bytes.Length) is { } failure)
            {
                // A device that fills part way: half of the batch lands, then the write fails.
                inner.Append(bytes[..(bytes.Length / 2)]);
                throw failure;
            }
            lock (owner._gate)
            {
                owner.Events.Add($"append {Path.GetFileName(path)} {bytes.Length}");
                owner._appended[path].Write(bytes);
            }
            inner.Append(bytes);
        }

        public void Flush()
        {
            owner.FlushEntered.Set();
            owner.FlushGate.Wait();
            if (owner.FailFlush?.Invoke(path) is { } failure)
                throw failure;
            inner.Flush();
            lock (owner._gate)
            {
                owner.Flushes++;
                owner.Events.Add($"flush {Path.GetFileName(path)}");
            }
        }

        public void Dispose() => inner.Dispose();
    }
}

/// <summary>A journal directory of its own for one test, removed afterwards.</summary>
internal sealed class JournalSandbox : IDisposable
{
    public JournalSandbox()
    {
        Root = Path.Combine(Path.GetTempPath(), "mca-journal-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Root);
        Home = Path.Combine(Root, "journal");
    }

    public string Root { get; }

    /// <summary>The journal's home: what the signer is given. It holds <c>current/</c> and the set-aside journals.</summary>
    public string Home { get; set; }

    /// <summary>The directory of live segments, <c>current/</c> in the home: what the writer is given and a reader reads.</summary>
    public string Directory => JournalLayout.Current(Home);
    public TestJournalKey CheckpointKey { get; set; } = new();
    public TestJournalKey SystemKey { get; set; } = new();
    public string InstanceId { get; set; } = new string('a', 64);
    public byte[] Incarnation { get; set; } = new byte[32];
    public List<string> Log { get; } = new();

    public JournalWriterOptions Options(IJournalFiles? files = null, Action<OptionsOverride>? change = null)
    {
        var o = new OptionsOverride();
        change?.Invoke(o);
        return new JournalWriterOptions
        {
            Directory = Directory,
            InstanceId = InstanceId,
            CheckpointKey = CheckpointKey,
            SystemKey = SystemKey,
            Incarnation = Incarnation,
            Version = "0.0.0-test",
            Files = files ?? JournalFiles.Default,
            Log = Log.Add,
            FindHeldKey = o.FindHeldKey,
            SegmentSealBytes = o.SegmentSealBytes,
            SegmentSealAge = o.SegmentSealAge,
            CheckpointInterval = o.CheckpointInterval,
            CheckpointRecords = o.CheckpointRecords,
            UnexplainedKeyChangeWait = o.UnexplainedKeyChangeWait,
        };
    }

    public JournalWriter Open(IJournalFiles? files = null, Action<OptionsOverride>? change = null) => JournalWriter.Open(Options(files, change));

    /// <summary>Every whole record of the directory, oldest first, with the segment it is in.</summary>
    public List<(string Segment, JournalRecord Record)> Records()
    {
        var all = new List<(string, JournalRecord)>();
        foreach (var file in JournalReader.ListSegments(Directory))
            JournalReader.Read(file, (record, _) => { all.Add((file.Name, record)); return true; });
        return all;
    }

    public JournalVerification Verify() => JournalVerifier.Verify(Directory);

    public string[] Names() => System.IO.Directory.Exists(Directory)
        ? System.IO.Directory.GetFiles(Directory).Select(f => Path.GetFileName(f)!).OrderBy(n => n, StringComparer.Ordinal).ToArray()
        : Array.Empty<string>();

    public void Dispose()
    {
        try
        {
            foreach (var file in System.IO.Directory.GetFiles(Root, "*", SearchOption.AllDirectories))
                File.SetAttributes(file, FileAttributes.Normal);
            System.IO.Directory.Delete(Root, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    internal sealed class OptionsOverride
    {
        public Func<byte[], IJournalSigningKey?>? FindHeldKey { get; set; }
        public long SegmentSealBytes { get; set; } = JournalFormat.SegmentSealBytes;
        public TimeSpan SegmentSealAge { get; set; } = JournalFormat.SegmentSealAge;
        public TimeSpan CheckpointInterval { get; set; } = JournalFormat.CheckpointInterval;
        public int CheckpointRecords { get; set; } = JournalFormat.CheckpointRecords;
        public TimeSpan UnexplainedKeyChangeWait { get; set; } = TimeSpan.FromMinutes(10);
    }
}
