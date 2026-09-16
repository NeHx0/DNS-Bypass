using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Helpers;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Manages DNS-over-HTTPS configuration in Windows
    /// Bypasses port 53 blocks by using HTTPS (port 443)
    /// </summary>
    public class DohManager
    {
        private readonly ILogger _logger;
        private readonly IRegistryManager _registry;
        private readonly ProcessHelper _processHelper;
        private readonly DohClient _dohClient;

        // Windows DoH registry path
        private const string DohRegistryPath = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string DohPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

        // DoH templates (RFC 8484 compliant)
        private static readonly Dictionary<string, string> DohTemplates = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cloudflare"] = "https://cloudflare-dns.com/dns-query",
            ["CloudflareSec"] = "https://security.cloudflare-dns.com/dns-query", // Malware blocking
            ["CloudflareFamily"] = "https://family.cloudflare-dns.com/dns-query", // Adult content blocking
            ["Google"] = "https://dns.google/dns-query",
            ["Quad9"] = "https://dns.quad9.net/dns-query",
            ["Quad9Secured"] = "https://dns11.quad9.net/dns-query", // ECS support
            ["OpenDNS"] = "https://doh.opendns.com/dns-query",
            ["AdGuard"] = "https://dns.adguard.com/dns-query",
            ["AdGuardFamily"] = "https://dns-family.adguard.com/dns-query",
            ["Mullvad"] = "https://dns.mullvad.net/dns-query",
            ["NextDNS"] = "https://dns.nextdns.io",
            ["DNSSBDE"] = "https://doh.dns.sb/dns-query", // Germany
            ["CZNIC"] = "https://odvr.nic.cz/doh" // Czech Republic
        };

        public DohManager(ILogger logger, IRegistryManager registry)
        {
            _logger = logger;
            _registry = registry;
            _processHelper = new ProcessHelper(logger);
            _dohClient = new DohClient(logger);
        }

        /// <summary>
        /// Enable DoH for a specific DNS server using Windows native support
        /// </summary>
        public async Task<bool> EnableDohAsync(string dnsServer, string dohTemplate)
        {
            try
            {
                _logger.Info($"Enabling DoH for {dnsServer} -> {dohTemplate}");

                // Test DoH connectivity first
                var dohWorks = await _dohClient.TestDohConnectivity(dohTemplate);
                if (!dohWorks)
                {
                    _logger.Warn($"DoH test failed for {dohTemplate}, trying anyway...");
                }

                // Method 1: Use netsh to configure DoH (Windows 10 1903+)
                var netshResult = await EnableDohViaNetshAsync(dnsServer, dohTemplate);
                if (netshResult)
                {
                    _logger.Success($"DoH enabled via netsh for {dnsServer}");
                    return true;
                }

                // Method 2: Registry-based configuration
                var registryResult = EnableDohViaRegistry(dnsServer, dohTemplate);
                if (registryResult)
                {
                    _logger.Success($"DoH enabled via registry for {dnsServer}");
                    
                    // Restart DNS Client service to apply changes
                    await RestartDnsClientServiceAsync();
                    return true;
                }

                _logger.Error($"Failed to enable DoH for {dnsServer}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.Error($"DoH enablement failed for {dnsServer}", ex);
                return false;
            }
        }

        /// <summary>
        /// Enable DoH using netsh command (Windows 10 1903+)
        /// </summary>
        private async Task<bool> EnableDohViaNetshAsync(string dnsServer, string dohTemplate)
        {
            try
            {
                // Add DNS server with DoH template
                // dohTemplate: 1=Off, 2=Allow, 3=Require
                var command = $"dns add encryption server={dnsServer} dohtemplate={dohTemplate} autoupgrade=yes";
                
                return await Task.Run(() => _processHelper.ExecuteNetsh(command));
            }
            catch (Exception ex)
            {
                _logger.Debug($"netsh DoH failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enable DoH via registry (fallback method)
        /// </summary>
        private bool EnableDohViaRegistry(string dnsServer, string dohTemplate)
        {
            try
            {
                // Enable DoH globally
                _registry.WriteDword(DohPolicyPath, "DoHPolicy", 2); // 2 = Allow, 3 = Require

                // Set DoH template for specific server
                var serverKey = $"{DohRegistryPath}\\DohWellKnownServers\\{dnsServer}";
                _registry.CreateKey(serverKey);
                _registry.WriteString(serverKey, "Template", dohTemplate);

                return true;
            }
            catch (Exception ex)
            {
                _logger.Debug($"Registry DoH config failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Configure DoH for a DNS provider by name
        /// </summary>
        public async Task<bool> EnableDohForProviderAsync(string providerName, string[] dnsServers)
        {
            if (!DohTemplates.ContainsKey(providerName))
            {
                _logger.Warn($"No DoH template found for provider: {providerName}");
                return false;
            }

            var dohTemplate = DohTemplates[providerName];
            var success = false;

            foreach (var dnsServer in dnsServers)
            {
                var result = await EnableDohAsync(dnsServer, dohTemplate);
                if (result) success = true;
            }

            return success;
        }

        /// <summary>
        /// Test and find the best working DoH provider
        /// </summary>
        public async Task<string> FindBestDohProviderAsync()
        {
            _logger.Info("Testing DoH providers...");

            var providerUrl = await _dohClient.FindFastestDohProvider(DohTemplates.Values.ToArray());
            
            if (providerUrl != null)
            {
                var provider = DohTemplates.FirstOrDefault(x => x.Value == providerUrl).Key;
                _logger.Success($"Best DoH provider: {provider}");
                return provider;
            }

            return null;
        }

        /// <summary>
        /// Disable DoH and revert to standard DNS
        /// </summary>
        public async Task<bool> DisableDohAsync()
        {
            try
            {
                _logger.Info("Disabling DoH...");

                // Remove DoH policy
                _registry.DeleteValue(DohPolicyPath, "DoHPolicy");

                // Restart DNS Client service
                await RestartDnsClientServiceAsync();

                _logger.Success("DoH disabled");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error("Failed to disable DoH", ex);
                return false;
            }
        }

        /// <summary>
        /// Restart DNS Client service to apply changes
        /// </summary>
        private async Task RestartDnsClientServiceAsync()
        {
            try
            {
                _logger.Info("Restarting DNS Client service...");

                // Stop service
                await _processHelper.ExecuteAsync("net", "stop dnscache /y");
                await Task.Delay(1000);

                // Start service
                var result = await _processHelper.ExecuteAsync("net", "start dnscache");
                
                if (result.Success)
                {
                    _logger.Success("DNS Client service restarted");
                }
                else
                {
                    _logger.Warn("Service restart may have failed - changes will apply on next reboot");
                }
            }
            catch (Exception ex)
            {
                _logger.Warn($"Service restart warning: {ex.Message}");
            }
        }

        /// <summary>
        /// Get DoH status for current DNS servers
        /// </summary>
        public async Task<string> GetDohStatusAsync()
        {
            try
            {
                var result = await _processHelper.ExecuteAsync("netsh", "dns show encryption");
                return result.Success ? result.Output : "DoH status unknown";
            }
            catch (Exception ex)
            {
                _logger.Debug($"Could not get DoH status: {ex.Message}");
                return "DoH status unknown (netsh not available)";
            }
        }
    }
}
