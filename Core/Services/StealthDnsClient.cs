using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Stealth DNS client using Cloudflare Workers as proxy
    /// Bypasses Mikrotik firewall by appearing as normal HTTPS API calls
    /// </summary>
    public class StealthDnsClient
    {
        private readonly ILogger _logger;
        private static readonly HttpClient _httpClient;
        
        // Cloudflare Workers endpoint (deployed!)
        private static readonly List<string> WorkerEndpoints = new List<string>
        {
            "https://dns-bypass-worker.eraymail.workers.dev", // ACTIVE!
            // Fallback endpoints (can add more workers later)
            "https://dns-tunnel-2.eraymail.workers.dev",
            "https://api-gateway.eraymail.workers.dev"
        };

        static StealthDnsClient()
        {
            var handler = new HttpClientHandler
            {
                UseProxy = false, // Direct connection
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 3,
                AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(10)
            };

            // Mimic normal browser
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");
            _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
            // REMOVED Accept-Encoding to prevent compression issues
            _httpClient.DefaultRequestHeaders.Add("Origin", "https://example.com");
            _httpClient.DefaultRequestHeaders.Add("Referer", "https://example.com/");
        }

        public StealthDnsClient(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Resolve domain name using stealth tunnel
        /// </summary>
        public async Task<List<string>> ResolveDomainAsync(string domain, string recordType = "A")
        {
            _logger.Debug($"[Stealth] Resolving {domain} via encrypted tunnel...");

            foreach (var endpoint in WorkerEndpoints)
            {
                try
                {
                    var ips = await QueryWorkerAsync(endpoint, domain, recordType);
                    if (ips.Count > 0)
                    {
                        _logger.Success($"[Stealth] Resolved {domain} → {string.Join(", ", ips)}");
                        return ips;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug($"[Stealth] Endpoint {endpoint} failed: {ex.Message}");
                    continue; // Try next endpoint
                }
            }

            _logger.Error($"[Stealth] All endpoints failed for {domain}");
            return new List<string>();
        }

        /// <summary>
        /// Query Cloudflare Worker endpoint
        /// </summary>
        private async Task<List<string>> QueryWorkerAsync(string endpoint, string domain, string recordType)
        {
            try
            {
                _logger.Debug($"[Stealth] Querying {endpoint} for {domain}...");

                var requestBody = new
                {
                    domain = domain,
                    type = recordType,
                    // Add noise to make requests look unique
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    client_id = Guid.NewGuid().ToString("N").Substring(0, 8)
                };

                var jsonContent = JsonSerializer.Serialize(requestBody);
                _logger.Debug($"[Stealth] Request body: {jsonContent}");
                
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(endpoint, content);
                _logger.Debug($"[Stealth] Response status: {response.StatusCode}");
                
                response.EnsureSuccessStatusCode();

                var responseBody = await response.Content.ReadAsStringAsync();
                _logger.Debug($"[Stealth] Response body: {responseBody}");
                
                var result = JsonSerializer.Deserialize<DnsResponse>(responseBody);

                return result?.ips ?? new List<string>();
            }
            catch (Exception ex)
            {
                _logger.Error($"[Stealth] Query failed for {endpoint}: {ex.GetType().Name} - {ex.Message}");
                if (ex.InnerException != null)
                {
                    _logger.Error($"[Stealth] Inner exception: {ex.InnerException.Message}");
                }
                throw;
            }
        }

        /// <summary>
        /// Test connectivity to stealth tunnel
        /// </summary>
        public async Task<bool> TestConnectivityAsync()
        {
            _logger.Info("[Stealth] Testing tunnel connectivity...");

            foreach (var endpoint in WorkerEndpoints)
            {
                try
                {
                    var ips = await QueryWorkerAsync(endpoint, "cloudflare.com", "A");
                    if (ips.Count > 0)
                    {
                        _logger.Success($"[Stealth] Tunnel operational: {endpoint}");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug($"[Stealth] Test failed for {endpoint}: {ex.Message}");
                }
            }

            _logger.Error("[Stealth] All tunnel endpoints unreachable!");
            return false;
        }

        /// <summary>
        /// Verify domain resolution with fallback
        /// </summary>
        public async Task<bool> VerifyDomainAsync(string domain)
        {
            try
            {
                var ips = await ResolveDomainAsync(domain);
                return ips.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Batch resolve multiple domains
        /// </summary>
        public async Task<Dictionary<string, List<string>>> ResolveBatchAsync(params string[] domains)
        {
            var results = new Dictionary<string, List<string>>();
            
            var tasks = domains.Select(async domain =>
            {
                var ips = await ResolveDomainAsync(domain);
                return new { Domain = domain, IPs = ips };
            });

            var responses = await Task.WhenAll(tasks);

            foreach (var response in responses)
            {
                results[response.Domain] = response.IPs;
            }

            return results;
        }

        #region Response Models

        private class DnsResponse
        {
            public bool success { get; set; }
            public string domain { get; set; }
            public List<string> ips { get; set; }
            public int ttl { get; set; }
            public long timestamp { get; set; }
        }

        #endregion
    }
}
