using ModularCA.Bootstrap;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Pins the pgpass format <see cref="BackupRestore.WritePgPassFile"/> emits.
/// <para>
/// Replaces <c>WriteMysqlDefaultsFileTests</c>, which pinned the my.cnf option-file format and
/// its <c>#</c>-truncation trap. The failure mode this file guards against is the same shape
/// and just as silent: a pgpass line is five colon-separated fields, so a password containing a
/// colon splits the line and libpq authenticates with a fragment, producing an
/// authentication failure that looks nothing like its cause.
/// <see cref="ModularCA.Auth.Utils.PasswordUtil.Generate"/>'s symbol set can produce both the
/// colon and the backslash, so this is a real intermittent failure rather than a theoretical
/// one. pgpass has no quoting: each is escaped with a backslash.
/// </para>
/// </summary>
public class WritePgPassFileTests
{
    [Fact]
    public void Writes_PasswordWithColon_EscapedSoTheLineDoesNotSplit()
    {
        var path = BackupRestore.WritePgPassFile("localhost", 5432, "modularca-app", "modularca_app", "Abc:123!def");
        try
        {
            var content = File.ReadAllText(path);
            Assert.Contains(@"Abc\:123!def", content);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Writes_PasswordWithBackslash_EscapedFirstSoItIsNotDoubledTwice()
    {
        // Order matters: the backslash must be escaped before the colon, or the backslash
        // emitted while escaping the colon would itself be doubled.
        var path = BackupRestore.WritePgPassFile("localhost", 5432, "db", "u", @"a\b:c");
        try
        {
            var content = File.ReadAllText(path);
            Assert.Contains("a\\\\b\\:c", content);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Writes_AllFiveFieldsInOrder()
    {
        var path = BackupRestore.WritePgPassFile("127.0.0.1", 5433, "modularca-audit", "user1", "plain123");
        try
        {
            var content = File.ReadAllText(path).TrimEnd('\n');
            Assert.Equal("127.0.0.1:5433:modularca-audit:user1:plain123", content);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Writes_HostContainingColon_Escaped()
    {
        // An IPv6 literal is the realistic case: every separator in it is the field separator.
        var path = BackupRestore.WritePgPassFile("::1", 5432, "db", "u", "p");
        try
        {
            var content = File.ReadAllText(path);
            Assert.StartsWith(@"\:\:1:5432:", content);
        }
        finally { File.Delete(path); }
    }
}
