using Microsoft.Extensions.Configuration;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The signer host reads its default JSON configuration files once and watches none of them.
/// Each watch is an inotify instance, a Linux user has 128 by default, and the contract suite
/// keeps a hosted signer per test world alive for the whole class: with watching on, CI ran out
/// part-way through and every later signer failed to start.
/// </summary>
public sealed class SignerHostConfigurationTests
{
    [Fact]
    public async Task No_configuration_file_is_watched_for_changes()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);

        var root = Assert.IsAssignableFrom<IConfigurationRoot>(host.Configuration);
        var files = root.Providers.OfType<FileConfigurationProvider>().ToList();

        Assert.NotEmpty(files); // the defaults are still read: appsettings.json and its environment variant
        Assert.All(files, f => Assert.False(f.Source.ReloadOnChange, $"{f.Source.Path} is watched"));
    }
}
