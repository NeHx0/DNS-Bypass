using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// DNS-over-HTTPS (DoH) client for bypassing port 53 blocks
    /// Uses HTTPS (port 443) to send DNS queries - appears as normal web traffic
    /// </summary>
    public class DohClient
    {
        private readonly ILogger _logger;
        private static readonly HttpClient _httpClient;

        static DohClient()
        {
            // Configure HttpClient for DoH
            var handler = new HttpClientHandler
            {
                // Use system proxy if available
                UseProxy = true,
                UseCookies = false,
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 3
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(10)
            };

            // Mimic a real browser to avoid detection
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/dns-message");
            _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
            _httpClient.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
        }

        public DohClient(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Test DoH connectivity by resolving a domain
        /// </summary>
        public async Task<bool> TestDohConnectivity(string dohUrl, string testDomain = "cloudflare.com")
        {
            try
            {
                _logger.Debug($"Testing DoH connectivity: {dohUrl}");

                // Simple DNS query for A record
                var response = await QueryDohAsync(dohUrl, testDomain);
                
                if (response != null && response.Length > 12)
                {
                    _logger.Success($"DoH test successful: {dohUrl}");
                    return true;
                }

                _logger.Warn($"DoH test failed: Invalid response from {dohUrl}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.Error($"DoH test failed: {dohUrl}", ex);
                return false;
            }
        }

        /// <summary>
        /// Perform a DNS query over HTTPS (RFC 8484)
        /// </summary>
        private async Task<byte[]> QueryDohAsync(string dohUrl, string domain)
        {
            try
            {
                // Build DNS query packet (simplified A record query)
                var dnsQuery = BuildDnsQuery(domain);
                var base64Query = Convert.ToBase64String(dnsQuery)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');

                // Use GET method with base64-encoded query (RFC 8484)
                var requestUrl = $"{dohUrl}?dns={base64Query}";

                var response = await _httpClient.GetAsync(requestUrl);
                response.EnsureSuccessStatusCode();

                var responseData = await response.Content.ReadAsByteArrayAsync();
                return responseData;
            }
            catch (Exception ex)
            {
                _logger.Debug($"DoH query failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Build a simple DNS query packet for A record (IPv4 address)
        /// </summary>
        private byte[] BuildDnsQuery(string domain)
        {
            var query = new System.Collections.Generic.List<byte>();

            // DNS Header (12 bytes)
            query.Add(0x00); query.Add(0x01); // Transaction ID: 0x0001
            query.Add(0x01); query.Add(0x00); // Flags: Standard query
            query.Add(0x00); query.Add(0x01); // Questions: 1
            query.Add(0x00); query.Add(0x00); // Answer RRs: 0
            query.Add(0x00); query.Add(0x00); // Authority RRs: 0
            query.Add(0x00); query.Add(0x00); // Additional RRs: 0

            // Question section
            foreach (var label in domain.Split('.'))
            {
                query.Add((byte)label.Length);
                query.AddRange(Encoding.ASCII.GetBytes(label));
            }
            query.Add(0x00); // End of domain name

            // Query type: A (IPv4 address)
            query.Add(0x00); query.Add(0x01);

            // Query class: IN (Internet)
            query.Add(0x00); query.Add(0x01);

            return query.ToArray();
        }

        /// <summary>
        /// Test multiple DoH providers and return the fastest one
        /// </summary>
        public async Task<string> FindFastestDohProvider(string[] dohUrls)
        {
            _logger.Info("Testing DoH providers for best connectivity...");

            var tasks = dohUrls.Select(async url =>
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var success = await TestDohConnectivity(url);
                sw.Stop();

                return new { Url = url, Success = success, Latency = sw.ElapsedMilliseconds };
            });

            var results = await Task.WhenAll(tasks);

            var fastest = results
                .Where(r => r.Success)
                .OrderBy(r => r.Latency)
                .FirstOrDefault();

            if (fastest != null)
            {
                _logger.Success($"Fastest DoH: {fastest.Url} ({fastest.Latency}ms)");
                return fastest.Url;
            }

            _logger.Error("No working DoH provider found!");
            return null;
        }
    }
}
