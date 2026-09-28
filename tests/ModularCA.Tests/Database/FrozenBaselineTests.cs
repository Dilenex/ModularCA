using System.Security.Cryptography;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The two frozen baselines stay byte-for-byte what production and staging applied on
/// 2026-09-19. Editing or regenerating one passes every other test, because nothing else compares
/// a migration's text with what a live database recorded as applied. The hash ignores a leading
/// UTF-8 byte order mark and every carriage return, so a checkout's line endings do not matter.
/// </summary>
public class FrozenBaselineTests
{
    public static TheoryData<string, string> Baselines() => new()
    {
        { "ModularCA.Database/Migrations/20260919181506_InitialCreate.cs", "b1ad4f155fd738e7e733d37080c0aceeb623b300717815c4a44d714afc8de24b" },
        { "ModularCA.Database/Migrations/20260919181506_InitialCreate.Designer.cs", "5d933fa9e10177d29cd28853a8483cf48dceaac395167de1d2522c78e1ab4a3b" },
        { "ModularCA.Database/Migrations/Audit/20260919181510_InitialAuditSchema.cs", "60c09e23660bd4a7c0438e8ccd800ff6caf7fb685b9cc956e0614bb63f209f89" },
        { "ModularCA.Database/Migrations/Audit/20260919181510_InitialAuditSchema.Designer.cs", "65f03a5cd541e9cdadf1fd9ac49c9787a7e492955f2a969badd6985539defd5c" },
    };

    [Theory]
    [MemberData(nameof(Baselines))]
    public void A_frozen_baseline_is_unchanged(string relativePath, string pinnedSha256)
    {
        var path = Path.Combine(RepoRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(path), $"{relativePath} is missing. It is a frozen baseline applied by production and staging; restore it.");

        var actual = NormalisedSha256(File.ReadAllBytes(path));

        Assert.True(actual == pinnedSha256,
            $"{relativePath} has changed (normalised SHA-256 {actual}, pinned {pinnedSha256}). It is a frozen baseline that "
            + "production and staging applied on 2026-09-19, and a changed baseline is never applied to them again. Restore "
            + "the file and add a migration instead (dotnet ef migrations add).");
    }

    [Fact]
    public void Normalisation_ignores_the_byte_order_mark_and_carriage_returns_only()
    {
        byte[] lf = "a\nb\n"u8.ToArray();
        byte[] crlfWithBom = [0xEF, 0xBB, 0xBF, .. "a\r\nb\r\n"u8.ToArray()];
        Assert.Equal(NormalisedSha256(lf), NormalisedSha256(crlfWithBom));
        Assert.NotEqual(NormalisedSha256(lf), NormalisedSha256("a\nb \n"u8.ToArray()));
    }

    /// <summary>SHA-256 of <paramref name="content"/> without a leading UTF-8 BOM and without any 0x0D byte, in lower-case hex.</summary>
    private static string NormalisedSha256(byte[] content)
    {
        var start = content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF ? 3 : 0;
        var normalised = content.Skip(start).Where(b => b != 0x0D).ToArray();
        return Convert.ToHexStringLower(SHA256.HashData(normalised));
    }

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
