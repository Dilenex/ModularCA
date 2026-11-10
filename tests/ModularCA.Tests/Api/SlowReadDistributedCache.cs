using Microsoft.Extensions.Caching.Distributed;

namespace ModularCA.Tests.Api;

/// <summary>
/// A distributed cache whose asynchronous reads wait before returning. Concurrent callers then
/// all read an entry before any of them removes it, which is the interleaving that lets a
/// read-then-remove "single-use" check pass more than once.
/// </summary>
/// <param name="inner">The cache that holds the entries.</param>
/// <param name="readDelayMs">How long each asynchronous read waits after reading.</param>
internal sealed class SlowReadDistributedCache(IDistributedCache inner, int readDelayMs = 50) : IDistributedCache
{
    /// <inheritdoc />
    public byte[]? Get(string key) => inner.Get(key);

    /// <inheritdoc />
    public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
    {
        var value = await inner.GetAsync(key, token);
        await Task.Delay(readDelayMs, token);
        return value;
    }

    /// <inheritdoc />
    public void Refresh(string key) => inner.Refresh(key);

    /// <inheritdoc />
    public Task RefreshAsync(string key, CancellationToken token = default) => inner.RefreshAsync(key, token);

    /// <inheritdoc />
    public void Remove(string key) => inner.Remove(key);

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken token = default) => inner.RemoveAsync(key, token);

    /// <inheritdoc />
    public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => inner.Set(key, value, options);

    /// <inheritdoc />
    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        => inner.SetAsync(key, value, options, token);
}
