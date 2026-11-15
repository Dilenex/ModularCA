using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModularCA.Bootstrap;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// <c>--backup-manifest</c> and the reading of an archive behind it and behind a restore
/// (<see cref="BackupArchiveFile"/>), over archives these tests write in the format a backup
/// writes: a ZIP holding <c>manifest.json</c>, encrypted under a random key or under a password.
/// No database is involved; the restore drill runs the same command on an archive the real
/// program took.
/// </summary>
public sealed class BackupManifestCommandTests : IDisposable
{
    private const string Pin = "3f6c1d0a9b8e7f6a5d4c3b2a1908f7e6d5c4b3a2918070605040302010fedcba";
    private const string Password = "a long backup password 42!";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-manifest-" + Guid.NewGuid().ToString("N")[..12]);
    private readonly string _base;
    private readonly string _mount;
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(BackupKeyManager.KeySize);

    /// <summary>An application directory with a backup key, and a directory standing in for a mount that holds archives.</summary>
    public BackupManifestCommandTests()
    {
        _base = Path.Combine(_root, "app");
        _mount = Path.Combine(_root, "mount");
        Directory.CreateDirectory(Path.Combine(_base, "config"));
        Directory.CreateDirectory(_mount);
        File.WriteAllBytes(Path.Combine(_base, "config", "backup.key"), _key);
    }

    /// <summary>Removes the directories.</summary>
    public void Dispose()
    {
        try
        {
            foreach (var file in Directory.GetFiles(_root, "*", SearchOption.AllDirectories))
                File.SetAttributes(file, FileAttributes.Normal);
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>The manifest a 0.4.5 backup writes.</summary>
    private static string CurrentManifest(string? latestMigration = null) => JsonSerializer.Serialize(new
    {
        Version = "1.0",
        Timestamp = new DateTime(2026, 11, 12, 2, 0, 0, DateTimeKind.Utc),
        AppDatabase = "modularca",
        AuditDatabase = "modularca-audit",
        MachineName = "ca-pod-7",
        InstanceId = Pin,
        ProductVersion = "0.4.5",
        LatestMigration = latestMigration ?? BackupManifestCommand.KnownMigrations(audit: false).Max(StringComparer.Ordinal),
        LatestAuditMigration = BackupManifestCommand.KnownMigrations(audit: true).Max(StringComparer.Ordinal),
        SchemaVersion = "tables:90:0123456789abcdef:migrations:70:fedcba9876543210",
        CaCount = 2,
        CertCount = 41,
        UserCount = 7,
        KeystoreIntegrity = true,
        DbIntegrity = true,
        WrappedSecrets = new[] { "dp-keys" },
        BackupSizeBytes = 1234L,
    });

    /// <summary>The manifest a backup wrote before 0.4.5: no instance, no product version, no migration.</summary>
    private static string OldManifest() => JsonSerializer.Serialize(new
    {
        Version = "1.0",
        Timestamp = new DateTime(2026, 9, 1, 2, 0, 0, DateTimeKind.Utc),
        AppDatabase = "modularca",
        AuditDatabase = "modularca-audit",
        MachineName = "ca1",
        SchemaVersion = "tables:88:0123456789abcdef:migrations:66:fedcba9876543210",
        CaCount = 1,
        CertCount = 3,
        UserCount = 2,
        KeystoreIntegrity = true,
        DbIntegrity = true,
        BackupSizeBytes = 99L,
    });

    private static byte[] Zip(string? manifest, bool withAudit = true)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, string text)
            {
                using var writer = new StreamWriter(zip.CreateEntry(name).Open());
                writer.Write(text);
            }
            if (manifest != null) Add("manifest.json", manifest);
            Add("db-app.dump", "not a real dump");
            if (withAudit) Add("db-audit.dump", "not a real dump");
        }
        return buffer.ToArray();
    }

    /// <summary>Encrypts a ZIP as a backup does: <c>[MCAB][version][mode][salt][N][r][p][nonce][tag][ciphertext]</c>.</summary>
    private static byte[] Encrypt(byte[] zip, byte[] key, BackupEncryptionMode mode = BackupEncryptionMode.RandomKey, byte[]? salt = null, long n = 0, int r = 0, int p = 0)
    {
        var nonce = RandomNumberGenerator.GetBytes(BackupKeyManager.NonceSize);
        var tag = new byte[BackupKeyManager.TagSize];
        var ciphertext = new byte[zip.Length];
        using (var aes = new AesGcm(key, BackupKeyManager.TagSize))
            aes.Encrypt(nonce, zip, ciphertext, tag);

        using var file = new MemoryStream();
        file.Write(BackupKeyManager.MagicBytes);
        file.WriteByte(BackupKeyManager.FormatVersion);
        file.WriteByte((byte)mode);
        file.Write(salt ?? new byte[BackupKeyManager.SaltSize]);
        Span<byte> numbers = stackalloc byte[16];
        BinaryPrimitives.WriteInt64LittleEndian(numbers, n);
        BinaryPrimitives.WriteInt32LittleEndian(numbers[8..], r);
        BinaryPrimitives.WriteInt32LittleEndian(numbers[12..], p);
        file.Write(numbers);
        file.Write(nonce);
        file.Write(tag);
        file.Write(ciphertext);
        return file.ToArray();
    }

    private string Archive(string name, byte[] bytes)
    {
        var path = Path.Combine(_mount, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private (int Exit, string Out, string Error) Run(params string[] args)
    {
        var (output, error) = (new StringWriter(), new StringWriter());
        var exit = BackupManifestCommand.Run(args, _base, output, error);
        return (exit, output.ToString(), error.ToString());
    }

    private static JsonElement OneLine(string output)
    {
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).ToList();
        return JsonDocument.Parse(Assert.Single(lines)).RootElement;
    }

    [Fact]
    public void An_archive_says_which_instance_wrote_it_with_which_version_and_when_on_one_line()
    {
        var archive = Archive("modularca-backup-20261112-020000.enc", Encrypt(Zip(CurrentManifest()), _key));

        var (exit, output, error) = Run("--backup-manifest", archive);

        Assert.Equal(0, exit);
        Assert.Empty(error);
        var json = OneLine(output);
        Assert.Equal(Pin, json.GetProperty("instanceId").GetString());
        Assert.Equal("0.4.5", json.GetProperty("productVersion").GetString());
        Assert.Equal("tables:90:0123456789abcdef:migrations:70:fedcba9876543210", json.GetProperty("schemaVersion").GetString());
        Assert.Equal(new DateTime(2026, 11, 12, 2, 0, 0, DateTimeKind.Utc), json.GetProperty("createdAtUtc").GetDateTime().ToUniversalTime());
        Assert.Equal("modularca-backup-20261112-020000.enc", json.GetProperty("archive").GetString());
        Assert.Equal("RandomKey", json.GetProperty("encryption").GetString());
        Assert.True(json.GetProperty("hasAuditDatabase").GetBoolean());
        Assert.False(json.GetProperty("newerThanThisBuild").GetBoolean());
        Assert.Equal(new FileInfo(archive).Length, json.GetProperty("sizeBytes").GetInt64());
        Assert.Equal(BackupManifestCommand.ProductVersion(), json.GetProperty("readByVersion").GetString());
    }

    [Fact]
    public void The_line_carries_no_count_of_users_and_nothing_secret()
    {
        var archive = Archive("a.enc", Encrypt(Zip(CurrentManifest()), _key));

        var (_, output, _) = Run("--backup-manifest", archive);

        Assert.DoesNotContain("user", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("wrapped", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToHexString(_key), output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(_key), output, StringComparison.Ordinal);
    }

    [Fact]
    public void An_archive_from_before_the_instance_was_recorded_shows_null_for_what_it_does_not_say()
    {
        var archive = Archive("old.enc", Encrypt(Zip(OldManifest(), withAudit: false), _key));

        var (exit, output, _) = Run("--backup-manifest", archive);

        Assert.Equal(0, exit);
        var json = OneLine(output);
        // The fields are there, and null: a reader sees that the archive does not say, not that the field is unknown.
        foreach (var name in new[] { "instanceId", "productVersion", "latestMigration", "newerThanThisBuild" })
            Assert.Equal(JsonValueKind.Null, json.GetProperty(name).ValueKind);
        Assert.Equal("tables:88:0123456789abcdef:migrations:66:fedcba9876543210", json.GetProperty("schemaVersion").GetString());
        Assert.Equal("ca1", json.GetProperty("machineName").GetString());
        Assert.False(json.GetProperty("hasAuditDatabase").GetBoolean());
    }

    [Fact]
    public void An_archive_taken_by_a_newer_build_says_so()
    {
        var archive = Archive("newer.enc", Encrypt(Zip(CurrentManifest("99991231235959_FromTheFuture")), _key));

        var (exit, output, _) = Run("--backup-manifest", archive);

        Assert.Equal(0, exit);
        Assert.True(OneLine(output).GetProperty("newerThanThisBuild").GetBoolean());
    }

    [Fact]
    public void The_key_file_can_be_named_and_the_archive_can_lie_anywhere_under_any_name()
    {
        var elsewhere = Path.Combine(_root, "secrets", "backup-key");
        Directory.CreateDirectory(Path.GetDirectoryName(elsewhere)!);
        var otherKey = RandomNumberGenerator.GetBytes(BackupKeyManager.KeySize);
        File.WriteAllBytes(elsewhere, otherKey);
        var archive = Archive("archive", Encrypt(Zip(CurrentManifest()), otherKey));

        Assert.Equal(RestoreExit.Refused, Run("--backup-manifest", archive).Exit);
        var (exit, output, _) = Run("--backup-manifest", archive, "--key-file", elsewhere);

        Assert.Equal(0, exit);
        Assert.Equal(Pin, OneLine(output).GetProperty("instanceId").GetString());
    }

    [Fact]
    public void A_wrong_key_is_refused_with_the_reason_on_standard_error_and_nothing_on_standard_output()
    {
        var archive = Archive("a.enc", Encrypt(Zip(CurrentManifest()), RandomNumberGenerator.GetBytes(BackupKeyManager.KeySize)));

        var (exit, output, error) = Run("--backup-manifest", archive);

        Assert.Equal(RestoreExit.Refused, exit);
        Assert.Empty(output);
        Assert.Contains("does not open with this key", error);
    }

    [Theory]
    [InlineData("text")]
    [InlineData("short")]
    [InlineData("zip-without-manifest")]
    [InlineData("encrypted-not-a-zip")]
    [InlineData("missing")]
    public void A_file_that_is_not_one_of_ours_is_refused_with_the_reason(string what)
    {
        var path = what switch
        {
            "text" => Archive("notes.txt", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("This is not a backup archive. ", 20)))),
            "short" => Archive("short.enc", [1, 2, 3]),
            "zip-without-manifest" => Archive("other-product.zip", Zip(manifest: null)),
            "encrypted-not-a-zip" => Archive("blob.enc", Encrypt(Encoding.UTF8.GetBytes("hello, this is not a zip"), _key)),
            _ => Path.Combine(_mount, "absent.enc"),
        };

        var (exit, output, error) = Run("--backup-manifest", path);

        Assert.Equal(RestoreExit.Refused, exit);
        Assert.Empty(output);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void An_archive_under_a_password_opens_with_the_password_from_a_file_and_not_with_a_wrong_one()
    {
        var salt = RandomNumberGenerator.GetBytes(BackupKeyManager.SaltSize);
        var (n, r, p) = (BackupKeyManager.MinScryptN, BackupKeyManager.DefaultScryptR, BackupKeyManager.DefaultScryptP);
        var kek = BackupKeyManager.DeriveKey(Password, salt, n, r, p);
        var archive = Archive("pw.enc", Encrypt(Zip(CurrentManifest()), kek, BackupEncryptionMode.StoredPassword, salt, n, r, p));
        var right = Path.Combine(_root, "right-password");
        var wrong = Path.Combine(_root, "wrong-password");
        File.WriteAllText(right, Password + "\n");
        File.WriteAllText(wrong, "not the password at all 1!\n");

        var withPassword = Run("--backup-manifest", archive, "--password-file", right);
        var withWrong = Run("--backup-manifest", archive, "--password-file", wrong);
        var withNothing = Run("--backup-manifest", archive);

        Assert.Equal(0, withPassword.Exit);
        Assert.Equal("StoredPassword", OneLine(withPassword.Out).GetProperty("encryption").GetString());
        Assert.Equal(RestoreExit.Refused, withWrong.Exit);
        Assert.Empty(withWrong.Out);
        Assert.Contains("does not open with this password", withWrong.Error);
        Assert.Equal(RestoreExit.Refused, withNothing.Exit);
        Assert.Contains("--password-file", withNothing.Error);
    }

    [Fact]
    public void Reading_an_archive_writes_nothing_beside_it_or_anywhere_under_the_application_directory()
    {
        var archive = Archive("ro.enc", Encrypt(Zip(CurrentManifest()), _key));
        File.SetAttributes(archive, FileAttributes.ReadOnly);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_mount, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            var before = Snapshot();

            Assert.Equal(0, Run("--backup-manifest", archive).Exit);

            Assert.Equal(before, Snapshot());
        }
        finally
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(_mount, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        List<string> Snapshot() => Directory.GetFileSystemEntries(_root, "*", SearchOption.AllDirectories)
            .Select(e => $"{Path.GetRelativePath(_root, e)}|{(File.Exists(e) ? new FileInfo(e).Length : -1)}|{File.GetLastWriteTimeUtc(e):O}")
            .Order(StringComparer.Ordinal).ToList();
    }

    [Theory]
    [InlineData("no-archive")]
    [InlineData("archive-is-a-flag")]
    [InlineData("key-file-without-a-value")]
    [InlineData("password-file-without-a-value")]
    public void Missing_arguments_are_refused(string what)
    {
        var archive = Archive("u.enc", Encrypt(Zip(CurrentManifest()), _key));
        string[] args = what switch
        {
            "no-archive" => ["--backup-manifest"],
            "archive-is-a-flag" => ["--backup-manifest", "--key-file", "x"],
            "key-file-without-a-value" => ["--backup-manifest", archive, "--key-file"],
            _ => ["--backup-manifest", archive, "--password-file"],
        };

        var (exit, output, error) = Run(args);

        Assert.Equal(RestoreExit.Refused, exit);
        Assert.Empty(output);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void The_key_files_this_host_names_in_config_yaml_are_the_defaults()
    {
        Assert.Equal(Path.Combine(_base, "config/backup.key"), BackupArchiveFile.DefaultKeyPaths(_base).RandomKeyPath);
        Assert.Equal(Path.Combine(_base, "config/backup-password.key"), BackupArchiveFile.DefaultKeyPaths(_base).PasswordKeyPath);

        File.WriteAllText(Path.Combine(_base, "config", "config.yaml"), "Backup:\n  EncryptionKeyPath: config/keys/b.key\n  PasswordFilePath: config/keys/p.key\n");

        Assert.Equal(Path.Combine(_base, "config/keys/b.key"), BackupArchiveFile.DefaultKeyPaths(_base).RandomKeyPath);
        Assert.Equal(Path.Combine(_base, "config/keys/p.key"), BackupArchiveFile.DefaultKeyPaths(_base).PasswordKeyPath);
    }

    // ---- the restore's statuses, where no database is needed ---------------------------------------

    [Fact]
    public void The_restore_statuses_are_the_schema_steps_numbers_with_the_same_meanings()
    {
        // The API is the host executable and is read by reflection, as elsewhere in these tests.
        var schemaStartup = ApiAssembly.TypeNamed("ModularCA.API.Startup.SchemaStartup");
        int Of(string name) => (int)schemaStartup.GetField(name)!.GetRawConstantValue()!;

        Assert.Equal(0, RestoreExit.Done);
        Assert.Equal(RestoreExit.Refused, Of("ExitCode"));
        Assert.Equal(RestoreExit.FailedAfterChanges, Of("AppliedThenFailedExitCode"));
        Assert.Equal(RestoreExit.Unreachable, Of("TempFailExitCode"));
        Assert.Equal((3, 4, 75), (RestoreExit.Refused, RestoreExit.FailedAfterChanges, RestoreExit.Unreachable));
    }

    [Fact]
    public void Each_verdict_is_one_line_that_starts_with_its_fixed_phrase()
    {
        var verdicts = new[]
        {
            (RestoreResult.Done(auditKept: true), 0, "RESTORE: DONE"),
            (RestoreResult.Done(auditKept: false), 0, "RESTORE: DONE"),
            (RestoreResult.Refused("the key\r\ndoes not fit."), 3, "RESTORE: REFUSED"),
            (RestoreResult.Unreachable("connection refused"), 75, "RESTORE: UNREACHABLE"),
            (RestoreResult.FailedAfterChanges(new string('x', 2000)), 4, "RESTORE: FAILED AFTER CHANGES"),
        };

        foreach (var (result, exit, marker) in verdicts)
        {
            Assert.Equal(exit, result.ExitCode);
            Assert.StartsWith(marker, result.Verdict);
            Assert.DoesNotContain('\n', result.Verdict);
            Assert.DoesNotContain('\r', result.Verdict);
            Assert.True(result.Verdict.Length < 600);
        }
        Assert.Contains("audit database was kept", verdicts[0].Item1.Verdict);
        Assert.Contains("replaced", verdicts[1].Item1.Verdict);
        Assert.EndsWith("Nothing was changed.", verdicts[2].Item1.Verdict);
        Assert.EndsWith("Nothing was changed.", verdicts[3].Item1.Verdict);
        Assert.DoesNotContain("Nothing was changed", verdicts[4].Item1.Verdict);
        // No marker is the start of another: a runner that matches on a prefix reads one meaning.
        var markers = new[] { RestoreExit.DoneMarker, RestoreExit.RefusedMarker, RestoreExit.FailedAfterChangesMarker, RestoreExit.UnreachableMarker };
        Assert.All(markers, a => Assert.All(markers.Where(b => b != a), b => Assert.False(b.StartsWith(a, StringComparison.Ordinal))));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("text")]
    [InlineData("wrong-key")]
    public async Task A_restore_of_an_archive_that_cannot_be_opened_is_refused_before_anything_is_touched(string what)
    {
        var wrongKey = Path.Combine(_root, "wrong.key");
        File.WriteAllBytes(wrongKey, RandomNumberGenerator.GetBytes(BackupKeyManager.KeySize));
        var path = what switch
        {
            "missing" => Path.Combine(_mount, "absent.enc"),
            "text" => Archive("notes.txt", Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("This is not a backup archive. ", 20)))),
            _ => Archive("a.enc", Encrypt(Zip(CurrentManifest()), _key)),
        };

        var result = await BackupRestore.RestoreWithVerdictAsync(path,
            _ => throw new InvalidOperationException("the signer must not be asked for anything"),
            new RestoreOptions { Interactive = false, Keys = new BackupKeySource(KeyFilePath: wrongKey) });

        Assert.Equal(RestoreExit.Refused, result.ExitCode);
        Assert.StartsWith(RestoreExit.RefusedMarker, result.Verdict);
        Assert.EndsWith("Nothing was changed.", result.Verdict);
    }

    [Fact]
    public void The_migrations_a_dump_carries_are_read_from_its_copy_block()
    {
        var script = string.Join("\r\n",
            "--",
            "-- PostgreSQL database dump",
            "--",
            "SET statement_timeout = 0;",
            "",
            "COPY public.\"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") FROM stdin;",
            "20250101000000_Initial\t9.0.0",
            "20260901120000_InstanceIncarnation\t10.0.0",
            "\\.",
            "",
            "COPY public.\"Other\" (\"Id\") FROM stdin;",
            "7",
            "\\.",
            "");

        Assert.Equal(["20250101000000_Initial", "20260901120000_InstanceIncarnation"],
            BackupRestore.ParseCopiedMigrations(script));
        Assert.Empty(BackupRestore.ParseCopiedMigrations("-- a dump with no such table\n"));
    }
}
