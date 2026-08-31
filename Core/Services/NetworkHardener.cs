using System;
using System.Linq;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Models;
using DnsAdvancedBypass.Core.Helpers;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Network hardening service to prevent DNS leaks and secure Windows network stack.
    /// Implements comprehensive leak prevention measures.
    /// </summary>
    public class NetworkHardener : INetworkHardener
    {
        private readonly ILogger _logger;
        private readonly IRegistryManager _registry;
        private readonly ProcessHelper _processHelper;

        // Registry key paths
        private const string NetBtParamsBase = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
        private const string DnsCacheParams = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string DnsClientPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        private const string NcsiParams = @"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet";
        private const string NcsiPolicy = @"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator";
        private const string Tcpip6Params = @"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters";

        public NetworkHardener(ILogger logger, IRegistryManager registry)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _processHelper = new ProcessHelper(logger);
        }

        public async Task<HardeningResult> ApplyFullHardeningAsync()
        {
            var result = new HardeningResult
            {
                Success = false,
                Message = "Starting full network hardening..."
            };

            _logger.Info("═══════════════════════════════════════════════════════════");
            _logger.Info("  NETWORK HARDENING - Phase 1: DNS Leak Prevention");
            _logger.Info("═══════════════════════════════════════════════════════════");

            try
            {
                // Step 1: NetBIOS
                _logger.Info("Step 1/5: Disabling NetBIOS over TCP/IP...");
                bool netbios = await DisableNetBiosAsync();
                result.AddStep("NetBIOS Disable", netbios, netbios ? "NetBIOS over TCP/IP disabled on all adapters" : "Failed to disable NetBIOS");

                // Step 2: IPv6 Transitions
                _logger.Info("Step 2/5: Disabling IPv6 transition technologies...");
                bool ipv6 = await DisableIPv6TransitionsAsync();
                result.AddStep("IPv6 Transitions Disable", ipv6, ipv6 ? "Teredo, ISATAP, 6to4, and IP-HTTPS disabled" : "Failed to disable IPv6 transitions");

                // Step 3: DNS Cache
                _logger.Info("Step 3/5: Optimizing DNS cache settings...");
                bool cache = await OptimizeDnsCacheAsync();
                result.AddStep("DNS Cache Optimization", cache, cache ? "Negative TTL and cache limits configured" : "Failed to optimize DNS cache");

                // Step 4: NCSI
                _logger.Info("Step 4/5: Disabling NCSI probes...");
                bool ncsi = await DisableNCSIAsync();
                result.AddStep("NCSI Disable", ncsi, ncsi ? "Network Connectivity Status Indicator probes disabled" : "Failed to disable NCSI");

                // Step 5: DNS Client Hardening
                _logger.Info("Step 5/5: Hardening DNS client settings...");
                bool dnsClient = await HardenDnsClientAsync();
                result.AddStep("DNS Client Hardening", dnsClient, dnsClient ? "DoH required, smart resolution off, LLMNR off" : "Failed to harden DNS client");

                // Calculate overall success
                int successCount = result.Steps.Count(s => s.Success);
                result.Success = successCount >= 4; // At least 4 out of 5 must succeed
                result.Message = $"Hardening completed: {successCount}/5 steps successful";

                _logger.Info("═══════════════════════════════════════════════════════════");
                if (result.Success)
                    _logger.Success($"✓ Hardening applied successfully ({successCount}/5)");
                else
                    _logger.Warn($"⚠ Hardening partially applied ({successCount}/5)");
                _logger.Info("═══════════════════════════════════════════════════════════");

                return result;
            }
            catch (Exception ex)
            {
                _logger.Error("Full hardening failed", ex);
                result.Success = false;
                result.Message = $"Exception during hardening: {ex.Message}";
                return result;
            }
        }

        public async Task<bool> DisableNetBiosAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (!_registry.KeyExists(NetBtParamsBase))
                    {
                        _logger.Warn("NetBT registry key not found - NetBIOS may not be installed");
                        return true; // Consider it success if NetBIOS isn't even present
                    }

                    var subKeys = _registry.EnumerateSubKeys(NetBtParamsBase);
                    if (subKeys.Length == 0)
                    {
                        _logger.Warn("No network adapters found in NetBT registry");
                        return false;
                    }

                    int successCount = 0;
                    foreach (string subKeyName in subKeys)
                    {
                        string interfaceKey = $"{NetBtParamsBase}\\{subKeyName}";
                        // NetbiosOptions: 2 = Disable NetBIOS over TCP/IP
                        if (_registry.WriteDword(interfaceKey, "NetbiosOptions", 2))
                            successCount++;
                    }

                    bool success = successCount > 0;
                    if (success)
                        _logger.Success($"NetBIOS disabled on {successCount} adapter(s)");
                    else
                        _logger.Error("Failed to disable NetBIOS on any adapter");

                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("NetBIOS disable failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> DisableIPv6TransitionsAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    int successCount = 0;

                    // 1. Teredo
                    var teredoResult = _processHelper.Execute("netsh", "interface teredo set state disabled", 10000);
                    if (teredoResult.Success)
                    {
                        _logger.Debug("Teredo disabled");
                        successCount++;
                    }

                    // 2. ISATAP
                    var isatapResult = _processHelper.Execute("netsh", "interface isatap set state disabled", 10000);
                    if (isatapResult.Success)
                    {
                        _logger.Debug("ISATAP disabled");
                        successCount++;
                    }

                    // 3. 6to4
                    var sixToFourResult = _processHelper.Execute("netsh", "interface 6to4 set state disabled", 10000);
                    if (sixToFourResult.Success)
                    {
                        _logger.Debug("6to4 disabled");
                        successCount++;
                    }

                    // 4. IP-HTTPS (DirectAccess)
                    var ipHttpsResult = _processHelper.Execute("netsh", "interface httpstunnel set state disabled", 10000);
                    if (ipHttpsResult.Success)
                    {
                        _logger.Debug("IP-HTTPS disabled");
                        successCount++;
                    }

                    // 5. Registry: Disable IPv6 components globally
                    // DisabledComponents = 0xFF disables all IPv6 components except loopback
                    if (_registry.WriteDword(Tcpip6Params, "DisabledComponents", 0xFF))
                    {
                        _logger.Debug("IPv6 components disabled via registry");
                        successCount++;
                    }

                    bool success = successCount >= 4; // At least 4 out of 5 should succeed
                    if (success)
                        _logger.Success($"IPv6 transitions disabled ({successCount}/5 methods)");
                    else
                        _logger.Warn($"IPv6 transitions partially disabled ({successCount}/5 methods)");

                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("IPv6 transition disable failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> OptimizeDnsCacheAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    int successCount = 0;

                    // 1. Negative cache time (30 seconds)
                    if (_registry.WriteDword(DnsCacheParams, "NegativeCacheTime", 30))
                    {
                        _logger.Debug("DNS negative cache TTL set to 30 seconds");
                        successCount++;
                    }

                    // 2. Max cache TTL (1 day = 86400 seconds)
                    if (_registry.WriteDword(DnsCacheParams, "MaxCacheTtl", 86400))
                    {
                        _logger.Debug("DNS max cache TTL set to 86400 seconds");
                        successCount++;
                    }

                    // 3. Max cache entry TTL limit
                    if (_registry.WriteDword(DnsCacheParams, "MaxCacheEntryTtlLimit", 86400))
                    {
                        _logger.Debug("DNS cache entry limit set");
                        successCount++;
                    }

                    // 4. Negative SOA cache time
                    if (_registry.WriteDword(DnsCacheParams, "NegativeSOACacheTime", 30))
                    {
                        _logger.Debug("DNS negative SOA cache time set");
                        successCount++;
                    }

                    bool success = successCount >= 3;
                    if (success)
                        _logger.Success($"DNS cache optimized ({successCount}/4 settings)");
                    else
                        _logger.Warn($"DNS cache partially optimized ({successCount}/4 settings)");

                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("DNS cache optimization failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> DisableNCSIAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    int successCount = 0;

                    // Method 1: Disable active probing
                    if (_registry.WriteDword(NcsiParams, "EnableActiveProbing", 0))
                    {
                        _logger.Debug("NCSI active probing disabled");
                        successCount++;
                    }

                    // Method 2: Policy-based disable
                    if (_registry.WriteDword(NcsiPolicy, "NoActiveProbe", 1))
                    {
                        _logger.Debug("NCSI probes disabled via policy");
                        successCount++;
                    }

                    // Method 3: Disable passive polling
                    if (_registry.WriteDword(NcsiParams, "EnablePassivePolling", 0))
                    {
                        _logger.Debug("NCSI passive polling disabled");
                        successCount++;
                    }

                    bool success = successCount >= 2;
                    if (success)
                        _logger.Success($"NCSI disabled ({successCount}/3 methods)");
                    else
                        _logger.Warn($"NCSI partially disabled ({successCount}/3 methods)");

                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("NCSI disable failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> HardenDnsClientAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    int successCount = 0;

                    // 1. Require DoH globally (3 = required, no plaintext fallback)
                    if (_registry.WriteDword(DnsCacheParams, "EnableAutoDoh", 3))
                    {
                        _logger.Debug("DoH enforcement enabled (required mode)");
                        successCount++;
                    }

                    // 2. Disable smart multi-homed name resolution (prevents parallel queries to all adapters)
                    if (_registry.WriteDword(DnsClientPolicy, "DisableSmartNameResolution", 1))
                    {
                        _logger.Debug("Smart multi-homed resolution disabled");
                        successCount++;
                    }

                    // 3. Disable parallel A and AAAA queries (prevents IPv6 leak vector)
                    if (_registry.WriteDword(DnsCacheParams, "DisableParallelAandAAAA", 1))
                    {
                        _logger.Debug("Parallel A/AAAA queries disabled");
                        successCount++;
                    }

                    // 4. Disable LLMNR (Link-Local Multicast Name Resolution)
                    if (_registry.WriteDword(DnsClientPolicy, "EnableMulticast", 0))
                    {
                        _logger.Debug("LLMNR/multicast name resolution disabled");
                        successCount++;
                    }

                    // 5. Disable Smart Protocol Reordering (can leak DNS to slower interfaces)
                    if (_registry.WriteDword(DnsClientPolicy, "DisableSmartProtocolReordering", 1))
                    {
                        _logger.Debug("Smart protocol reordering disabled");
                        successCount++;
                    }

                    bool success = successCount >= 4;
                    if (success)
                        _logger.Success($"DNS client hardened ({successCount}/5 settings)");
                    else
                        _logger.Warn($"DNS client partially hardened ({successCount}/5 settings)");

                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("DNS client hardening failed", ex);
                    return false;
                }
            });
        }

        public async Task<HardeningResult> RevertHardeningAsync()
        {
            var result = new HardeningResult
            {
                Success = false,
                Message = "Reverting hardening changes..."
            };

            _logger.Info("Reverting network hardening...");

            try
            {
                // This would require storing original values before hardening
                // For now, we'll implement a basic revert that removes our changes

                _logger.Warn("Full revert not yet implemented - manual registry cleanup may be required");
                result.Success = false;
                result.Message = "Revert functionality coming in next sprint";
                return result;
            }
            catch (Exception ex)
            {
                _logger.Error("Hardening revert failed", ex);
                result.Success = false;
                result.Message = $"Revert failed: {ex.Message}";
                return result;
            }
        }

        public async Task<HardeningStatus> GetHardeningStatusAsync()
        {
            return await Task.Run(() =>
            {
                var status = new HardeningStatus
                {
                    NetBiosDisabled = CheckNetBiosDisabled(),
                    IPv6TransitionsDisabled = CheckIPv6TransitionsDisabled(),
                    DnsCacheOptimized = CheckDnsCacheOptimized(),
                    NCSIDisabled = CheckNCSIDisabled(),
                    DnsClientHardened = CheckDnsClientHardened()
                };

                return status;
            });
        }

        private bool CheckNetBiosDisabled()
        {
            if (!_registry.KeyExists(NetBtParamsBase))
                return true; // If NetBT doesn't exist, it's effectively disabled

            var subKeys = _registry.EnumerateSubKeys(NetBtParamsBase);
            if (subKeys.Length == 0)
                return false;

            // Check first adapter as sample
            string firstKey = $"{NetBtParamsBase}\\{subKeys[0]}";
            int value = _registry.ReadDword(firstKey, "NetbiosOptions", -1);
            return value == 2;
        }

        private bool CheckIPv6TransitionsDisabled()
        {
            int disabledComponents = _registry.ReadDword(Tcpip6Params, "DisabledComponents", 0);
            return disabledComponents == 0xFF;
        }

        private bool CheckDnsCacheOptimized()
        {
            int negativeTtl = _registry.ReadDword(DnsCacheParams, "NegativeCacheTime", -1);
            return negativeTtl == 30;
        }

        private bool CheckNCSIDisabled()
        {
            int activeProbing = _registry.ReadDword(NcsiParams, "EnableActiveProbing", 1);
            return activeProbing == 0;
        }

        private bool CheckDnsClientHardened()
        {
            int autoDoh = _registry.ReadDword(DnsCacheParams, "EnableAutoDoh", -1);
            int smartRes = _registry.ReadDword(DnsClientPolicy, "DisableSmartNameResolution", 0);
            int llmnr = _registry.ReadDword(DnsClientPolicy, "EnableMulticast", 1);

            return autoDoh == 3 && smartRes == 1 && llmnr == 0;
        }
    }
}
