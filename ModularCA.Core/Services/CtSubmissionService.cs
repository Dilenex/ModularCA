using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModularCA.Core.Services;

/// <summary>
/// Submits issued certificates to configured Certificate Transparency logs per RFC 6962.
/// </summary>
public interface ICtSubmissionService
{
    /// <summary>
    /// Submits a certificate chain to CT logs and returns the collected SCTs as Base64-encoded byte arrays.
    /// </summary>
    /// <param name="certDer">DER-encoded end-entity certificate.</param>
    /// <param name="issuerDer">DER-encoded issuer (CA) certificate.</param>
    /// <param name="ctLogIds">Optional list of specific CT log IDs to submit to. Null = all enabled logs.</param>
    /// <returns>
    /// The raw JSON answers, one per log whose SCT verified against the log's configured public
    /// key, or an empty list on failure. An SCT that does not verify is not returned.
    /// </returns>
    Task<List<byte[]>> SubmitToCTLogsAsync(byte[] certDer, byte[] issuerDer, List<Guid>? ctLogIds);
}

/// <summary>
/// Posts certificate chains to CT log add-chain endpoints (RFC 6962 section 4.1)
/// and returns the Signed Certificate Timestamps (SCTs).
/// </summary>
public class CtSubmissionService : ICtSubmissionService
{
    private readonly ModularCADbContext _db;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<CtSubmissionService> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="CtSubmissionService"/>.
    /// </summary>
    /// <param name="db">Database context for CT log configuration queries.</param>
    /// <param name="httpClientFactory">Factory for creating HTTP clients for CT log submissions.</param>
    /// <param name="logger">Logger instance.</param>
    public CtSubmissionService(ModularCADbContext db, IHttpClientFactory httpClientFactory, ILogger<CtSubmissionService> logger)
    {
        _db = db;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Submits a certificate chain to all matching CT logs and collects SCTs.
    /// Failures are logged as warnings but do not throw — CT submission must never block issuance.
    /// Each SCT is verified against its log's configured public key
    /// (<see cref="CtSctVerifier.VerifyX509Entry"/>) before it is kept; one that does not verify,
    /// or comes from a log with no key configured, is discarded with a warning.
    /// </summary>
    public async Task<List<byte[]>> SubmitToCTLogsAsync(byte[] certDer, byte[] issuerDer, List<Guid>? ctLogIds)
    {
        var scts = new List<byte[]>();

        try
        {
            var logsQuery = _db.CtLogs.Where(l => l.IsEnabled);
            if (ctLogIds != null && ctLogIds.Count > 0)
                logsQuery = logsQuery.Where(l => ctLogIds.Contains(l.Id));

            var logs = await logsQuery.AsNoTracking().ToListAsync();
            if (logs.Count == 0)
            {
                _logger.LogDebug("No enabled CT logs found for submission");
                return scts;
            }

            // Build the RFC 6962 add-chain request body
            var chainRequest = new AddChainRequest
            {
                Chain = new[]
                {
                    Convert.ToBase64String(certDer),
                    Convert.ToBase64String(issuerDer)
                }
            };

            var client = _httpClientFactory.CreateClient("CtLog");
            client.Timeout = TimeSpan.FromSeconds(10);

            // Submit to each CT log in parallel
            var tasks = logs.Select(async log =>
            {
                try
                {
                    var url = log.Url.TrimEnd('/') + "/ct/v1/add-chain";
                    _logger.LogDebug("Submitting certificate to CT log '{LogName}' at {Url}", log.Name, url);

                    var response = await client.PostAsJsonAsync(url, chainRequest);
                    if (!response.IsSuccessStatusCode)
                    {
                        var body = await response.Content.ReadAsStringAsync();
                        _logger.LogWarning("CT log '{LogName}' returned {StatusCode}: {Body}", log.Name, response.StatusCode, body);
                        return null;
                    }

                    var sctBytes = await response.Content.ReadAsByteArrayAsync();
                    var problem = string.IsNullOrWhiteSpace(log.PublicKeyBase64)
                        ? "the log has no public key configured, so its SCT cannot be verified"
                        : CtSctVerifier.VerifyX509Entry(sctBytes, certDer, log.PublicKeyBase64);
                    if (problem != null)
                    {
                        _logger.LogWarning("Discarding the SCT from CT log '{LogName}': {Problem}", log.Name, problem);
                        return null;
                    }
                    _logger.LogInformation("Received and verified the SCT from CT log '{LogName}'", log.Name);
                    return sctBytes;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to submit certificate to CT log '{LogName}' at {Url}", log.Name, log.Url);
                    return null;
                }
            });

            var results = await Task.WhenAll(tasks);
            foreach (var result in results)
            {
                if (result != null)
                    scts.Add(result);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CT log submission failed unexpectedly");
        }

        return scts;
    }

    /// <summary>
    /// RFC 6962 section 4.1 add-chain JSON request body.
    /// </summary>
    private class AddChainRequest
    {
        /// <summary>
        /// Array of Base64-encoded DER certificates forming the chain (leaf first, then issuer).
        /// </summary>
        [JsonPropertyName("chain")]
        public string[] Chain { get; set; } = Array.Empty<string>();
    }
}
