// DNS Bypass v2.5
// DNS-based filtering bypass & network assessment tool (authorized testing)
//
// CLI usage (scriptable):
//   "DNS Bypass.exe" --activate
//   "DNS Bypass.exe" --activate --all                    (apply to every active adapter)
//   "DNS Bypass.exe" --activate --adapter "Wi-Fi"        (target a specific adapter)
//   "DNS Bypass.exe" --activate --adapter 2              (or by list index)
//   "DNS Bypass.exe" --activate --revert-on-fail         (auto-rollback if verification fails)
//   "DNS Bypass.exe" --revert
//   "DNS Bypass.exe" --status
//   "DNS Bypass.exe" --provider Cloudflare
//   "DNS Bypass.exe" --provider Google --activate
//
// Requires Windows + Administrator. Shows admin-required prompt if not elevated.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

// New modular architecture imports
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Models;
using DnsAdvancedBypass.Core.Services;
using DnsAdvancedBypass.Core.Helpers;

#pragma warning disable SYSLIB0014 // WebClient/ServicePointManager kept for .NET Framework compatibility

namespace DnsAdvancedBypass
{
    class Program
    {
        // Dependency injection - modular services
        private static ILogger _logger;
        private static IRegistryManager _registry;
        private static INetworkHardener _hardener;
        private static IBackupService _backupService;
        private static IRestoreService _restoreService;
        private static IConfigurationService _configService;

        private static readonly string AppDataDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BlockerKiller");

        private static readonly string BackupFile = Path.Combine(AppDataDir, "dns_backup.json");
        private static readonly string PrevBackupFile = Path.Combine(AppDataDir, "dns_backup.prev.json");
        private static readonly string LegacyBackupFile = Path.Combine(AppDataDir, "dns_backup.txt");
        private static readonly string SettingsFile = Path.Combine(AppDataDir, "settings.ini");

        // Windows DoH (DNS over HTTPS) is configured per interface under the Dnscache service key.
        private static readonly string DohRegBase =
            @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";
        private static readonly string DnsCacheParams =
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private static readonly string DnsClientPolicy =
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

        // Hardware lock: this copy only runs on the owner's PC or when the
        // owner's phone is visible (USB tethering / hotspot / ARP neighbor).
        private static readonly byte[][] AllowedMacs =
        {
            new byte[] { 0xE4, 0x0D, 0x36, 0x48, 0xA8, 0x19 }, // PC
            new byte[] { 0x5C, 0x40, 0x71, 0xAF, 0x09, 0x78 }  // phone
        };

        private static readonly Dictionary<string, ProviderInfo> Providers =
            new Dictionary<string, ProviderInfo>(StringComparer.OrdinalIgnoreCase)
            {
                ["Cloudflare"] = new ProviderInfo
                {
                    V4 = new[] { "1.1.1.1", "1.0.0.1" },
                    V6 = new[] { "2606:4700:4700::1111", "2606:4700:4700::1001" },
                    Doh4 = "https://cloudflare-dns.com/dns-query",
                    Doh6 = "https://cloudflare-dns.com/dns-query"
                },
                ["Google"] = new ProviderInfo
                {
                    V4 = new[] { "8.8.8.8", "8.8.4.4" },
                    V6 = new[] { "2001:4860:4860::8888", "2001:4860:4860::8844" },
                    Doh4 = "https://dns.google/dns-query",
                    Doh6 = "https://dns.google/dns-query"
                },
                ["Quad9"] = new ProviderInfo
                {
                    V4 = new[] { "9.9.9.9", "149.112.112.112" },
                    V6 = new[] { "2620:fe::fe", "2620:fe::9" },
                    Doh4 = "https://dns.quad9.net/dns-query",
                    Doh6 = "https://dns.quad9.net/dns-query"
                },
                ["OpenDNS"] = new ProviderInfo
                {
                    V4 = new[] { "208.67.222.222", "208.67.220.220" },
                    V6 = new[] { "2620:119:35::35", "2620:119:53::53" },
                    Doh4 = "https://doh.opendns.com/dns-query",
                    Doh6 = "https://doh.opendns.com/dns-query"
                },
                ["AdGuard"] = new ProviderInfo
                {
                    V4 = new[] { "94.140.14.14", "94.140.15.15" },
                    V6 = new[] { "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff" },
                    Doh4 = "https://dns.adguard.com/dns-query",
                    Doh6 = "https://dns.adguard.com/dns-query"
                },
                ["UncensoredDNS"] = new ProviderInfo
                {
                    V4 = new[] { "91.239.100.100", "89.233.43.71" },
                    V6 = new[] { "2001:67c:28a4::", "2001:67c:28a4::8" },
                    Doh4 = "",
                    Doh6 = ""
                },
                ["CZ.NIC"] = new ProviderInfo
                {
                    V4 = new[] { "193.17.47.1", "185.43.135.1" },
                    V6 = new[] { "2001:148f:ffff::1", "2001:148f:ffff::2" },
                    Doh4 = "https://odvr.nic.cz/doh",
                    Doh6 = "https://odvr.nic.cz/doh"
                },
                ["DNS.SB"] = new ProviderInfo
                {
                    V4 = new[] { "185.222.222.222", "45.11.45.11" },
                    V6 = new[] { "2a09::", "2a11::" },
                    Doh4 = "https://doh.dns.sb/dns-query",
                    Doh6 = "https://doh.dns.sb/dns-query"
                },
                ["Mullvad"] = new ProviderInfo
                {
                    V4 = new[] { "194.242.2.2", "194.242.2.3" },
                    V6 = new[] { "2a07:e340::2", "2a07:e340::3" },
                    Doh4 = "https://dns.mullvad.net/dns-query",
                    Doh6 = "https://dns.mullvad.net/dns-query"
                },
                ["NextDNS"] = new ProviderInfo
                {
                    V4 = new[] { "45.90.28.0", "45.90.30.0" },
                    V6 = new[] { "2a07:a8c0::", "2a07:a8c1::" },
                    Doh4 = "https://dns.nextdns.io",
                    Doh6 = "https://dns.nextdns.io"
                }
            };

        private static string selectedProvider = "Cloudflare";
        private static string custom1 = "";
        private static string custom2 = "";
        private static string customDoh = "";

        // CLI state
        private static bool cliMode;
        private static bool cliAllAdapters;
        private static bool cliRevertOnFail;
        private static string cliAdapterName = "";

        private static readonly Random Rng = new Random();

        static void Main(string[] args)
        {
            Console.Title = "DNS Bypass v2.5";
            Console.OutputEncoding = Encoding.UTF8;

            // Apply console transparency
            SetConsoleTransparency(230); // 230/255 = ~90% opacity

            // Initialize modular services
            _logger = new ConsoleLogger(debugMode: false);
            _registry = new SafeRegistryHelper(_logger);
            _hardener = new NetworkHardener(_logger, _registry);
            _backupService = new BackupService(_logger, _registry);
            _restoreService = new RestoreService(_logger, _registry, _backupService);
            _configService = new ConfigurationService(_logger);

            if (!IsAuthorizedDevice())
            {
                ShowUnauthorized();
                return;
            }

            LoadSettings();

            if (args.Length > 0)
            {
                RunCliMode(args);
                return;
            }

            if (!IsAdministrator())
            {
                ShowAdminRequired();
                return;
            }

            while (true)
            {
                PrintHeader();

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  [1] Activate Bypass");
                Console.WriteLine("  [2] Revert to Default");
                Console.WriteLine("  [3] Status / Leak Check");
                Console.WriteLine("  [4] Change DNS Provider");
                Console.WriteLine("  [5] Test a Website");
                Console.WriteLine("  [6] Apply to ALL active adapters");
                Console.WriteLine("  [7] Network Hardening (Anti-Leak)");
                Console.WriteLine("  [8] Backup System");
                Console.WriteLine("  [9] Restore from Backup");
                Console.WriteLine("  [10] Exit");
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  Active provider : {selectedProvider}" +
                                  (string.IsNullOrEmpty(GetProviderDoh()) ? "  (no DoH)" : "  (DoH ready)"));
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("  Select option: ");
                Console.ForegroundColor = ConsoleColor.White;

                string input = Console.ReadLine();
                Console.Clear();

                switch (input)
                {
                    case "1":
                        ActivateBypass();
                        break;
                    case "2":
                        RevertToDefault();
                        break;
                    case "3":
                        StatusCheck();
                        break;
                    case "4":
                        ChangeProvider();
                        break;
                    case "5":
                        TestWebsite();
                        break;
                    case "6":
                        ActivateOnAllAdapters();
                        break;
                    case "7":
                        ApplyNetworkHardening();
                        break;
                    case "8":
                        BackupSystem();
                        break;
                    case "9":
                        RestoreFromBackup();
                        break;
                    case "10":
                        Log("INFO", "Shutting down...");
                        Thread.Sleep(400);
                        PlayExitSound();
                        return;
                    default:
                        Log("ERROR", "Invalid option");
                        Thread.Sleep(800);
                        break;
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  Press any key to return to menu...");
                Console.ReadKey(true);
            }
        }

        // ---------------------------------------------------------------- CLI

        static void RunCliMode(string[] args)
        {
            cliMode = true;
            var actions = new List<string>();

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                switch (a)
                {
                    case "--provider":
                        if (i + 1 < args.Length) SetProviderFromCli(args[++i]);
                        break;
                    case "--adapter":
                        if (i + 1 < args.Length) cliAdapterName = args[++i];
                        break;
                    case "--all":
                        cliAllAdapters = true;
                        break;
                    case "--revert-on-fail":
                        cliRevertOnFail = true;
                        break;
                    case "--activate":
                    case "--revert":
                    case "--status":
                        actions.Add(a);
                        break;
                    default:
                        Log("ERROR", "Unknown argument: " + args[i]);
                        break;
                }
            }

            if (actions.Count == 0)
            {
                Log("ERROR", "No mode given. Use --activate | --revert | --status | --provider <name>");
                return;
            }

            foreach (string m in actions)
            {
                if ((m == "--activate" || m == "--revert") && !IsAdministrator())
                {
                    Log("ERROR", "Yönetici olarak çalıştırılmalıdır! Sağ tık → 'Yönetici olarak çalıştır' ile başlatın.");
                    Environment.ExitCode = 1;
                    return;
                }

                switch (m)
                {
                    case "--activate":
                        if (cliAllAdapters) ActivateOnAllAdapters();
                        else ActivateBypass();
                        break;
                    case "--revert":
                        RevertToDefault();
                        break;
                    case "--status":
                        StatusCheck();
                        break;
                }
            }
        }

        static void SetProviderFromCli(string name)
        {
            if (Providers.ContainsKey(name))
            {
                selectedProvider = name;
                SaveSettings();
                Log("SUCCESS", "Provider -> " + name);
            }
            else
            {
                Log("ERROR", "Unknown provider: " + name + ". Available: " + string.Join(", ", Providers.Keys));
            }
        }

        // -------------------------------------------------------- main actions

        static void ActivateBypass()
        {
            var adapter = SelectAdapter("Bypass target");
            if (adapter == null) { Log("ERROR", "No active network adapter found"); return; }

            if (adapter.GetIPProperties().GatewayAddresses.Count == 0)
                Log("WARN", "Selected adapter has no gateway - it may not be the active internet connection");

            var v4 = GetProviderServers(false);
            var v6 = GetProviderServers(true);
            if (v4.Length == 0)
            {
                Log("ERROR", "No IPv4 DNS servers configured for provider '" + selectedProvider + "'");
                return;
            }

            string doh = GetProviderDoh();
            Log("INFO", "Adapter: " + adapter.Name + " [" + adapter.NetworkInterfaceType + "]");
            Log("INFO", "Provider: " + selectedProvider + " -> " + string.Join(", ", v4) +
                (string.IsNullOrEmpty(doh) ? "" : "  (DoH: " + doh + ")"));

            // Pre-flight: confirm at least one candidate resolver answers on port 53.
            Console.WriteLine();
            Log("INFO", "Probing provider resolvers (UDP/TCP 53)...");
            int reachable = TestProviderServers(v4);
            if (reachable == 0 && string.IsNullOrEmpty(doh))
                Log("WARN", "All resolvers unreachable on port 53 and provider has no DoH - bypass will likely fail");
            else if (reachable == 0 && !string.IsNullOrEmpty(doh))
                Log("WARN", "Plain DNS blocked, but DoH template is available - applying with DoH");

            var entry = PrepareBackupForAdapter(adapter);
            if (entry == null) return;

            Thread.Sleep(300);

            bool applied = ApplyDnsServers(adapter, v4, v6, !string.IsNullOrEmpty(doh));

            FlushDns();
            RunProcess("ipconfig", "/registerdns", out _);

            if (!applied)
            {
                Log("ERROR", "DNS could not be applied. Restoring previous settings...");
                RestoreEntry(entry, adapter);
                FlushDns();
                return;
            }

            if (!VerifyDnsApplied(adapter, v4, !string.IsNullOrEmpty(doh)))
            {
                bool revert = cliRevertOnFail;
                if (!revert && !cliMode)
                {
                    Console.Write("  Settings look wrong. Revert to previous DNS? [Y/n]: ");
                    string ans = Console.ReadLine();
                    revert = string.IsNullOrEmpty(ans) ||
                             ans.Trim().ToLowerInvariant().StartsWith("y");
                }
                if (revert)
                {
                    Log("WARN", "Reverting to previous settings...");
                    RestoreEntry(entry, adapter);
                    FlushDns();
                }
                else
                {
                    Log("WARN", "Keeping current settings despite verification warnings.");
                }
                return;
            }

            Log("SUCCESS", "DNS updated. Verifying connectivity...");
            Thread.Sleep(600);
            VerifyNetwork();

            Log("SUCCESS", "Bypass activated successfully");
            PlaySuccessSound();
            OpenGitHub();
        }

        // Applies the provider DNS to every active adapter so no second interface
        // can keep leaking the filtered resolver.
        static void ActivateOnAllAdapters()
        {
            var list = GetCandidateAdapters()
                .Where(a => a.GetIPProperties().UnicastAddresses
                             .Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork))
                .ToList();
            if (list.Count == 0) { Log("ERROR", "No active network adapters found"); return; }

            var v4 = GetProviderServers(false);
            var v6 = GetProviderServers(true);
            if (v4.Length == 0)
            {
                Log("ERROR", "No IPv4 DNS servers configured for provider '" + selectedProvider + "'");
                return;
            }

            string doh = GetProviderDoh();
            Log("INFO", "Applying to " + list.Count + " active adapter(s): " +
                string.Join(", ", list.Select(a => a.Name)));

            Console.WriteLine();
            Log("INFO", "Probing provider resolvers (UDP/TCP 53)...");
            int reachable = TestProviderServers(v4);
            if (reachable == 0 && string.IsNullOrEmpty(doh))
                Log("WARN", "All resolvers unreachable on plain DNS and no DoH available");

            int okCount = 0;
            foreach (var adapter in list)
            {
                Console.WriteLine();
                Log("INFO", "--- Adapter: " + adapter.Name + " [" + adapter.NetworkInterfaceType + "] ---");
                var entry = PrepareBackupForAdapter(adapter);
                if (entry == null) continue;

                if (!ApplyDnsServers(adapter, v4, v6, !string.IsNullOrEmpty(doh)))
                {
                    Log("ERROR", "Apply failed on '" + adapter.Name + "'. Restoring...");
                    RestoreEntry(entry, adapter);
                    continue;
                }

                FlushDns();
                Thread.Sleep(300);

                if (VerifyDnsApplied(adapter, v4, !string.IsNullOrEmpty(doh)))
                    okCount++;
                else
                    Log("WARN", "Verification failed on '" + adapter.Name + "' - review with --status");
            }

            RunProcess("ipconfig", "/registerdns", out _);
            FlushDns();
            Log(okCount == list.Count ? "SUCCESS" : "WARN",
                okCount + "/" + list.Count + " adapters updated");
            VerifyNetwork();
            if (okCount == list.Count)
            {
                PlaySuccessSound();
                OpenGitHub();
            }
        }

        static void RevertToDefault()
        {
            var bak = ReadBackup();
            if (bak == null || bak.Adapters.Count == 0)
            {
                Log("ERROR", "No backup found. Nothing to revert.");
                return;
            }

            int restored = 0;
            foreach (var entry in bak.Adapters)
            {
                NetworkInterface adapter = null;
                if (!string.IsNullOrEmpty(entry.Guid))
                    adapter = NetworkInterface.GetAllNetworkInterfaces()
                        .FirstOrDefault(a => a.Id.Equals(entry.Guid, StringComparison.OrdinalIgnoreCase) &&
                                             a.OperationalStatus == OperationalStatus.Up);
                if (adapter == null) adapter = GetAdapterByName(entry.Name);
                if (adapter == null)
                {
                    Log("WARN", "Adapter '" + entry.Name + "' not found - skipping");
                    continue;
                }
                if (RestoreEntry(entry, adapter)) restored++;
            }

            if (restored > 0)
            {
                RestoreGlobalDnsState();
                try { File.Delete(BackupFile); } catch { }
                try { File.Delete(PrevBackupFile); } catch { }
                RestartDnsClient();
                FlushDns();
                RunProcess("ipconfig", "/registerdns", out _);
                Log("SUCCESS", restored + " adapter(s) restored");
                PlaySuccessSound();
                Thread.Sleep(500);
                VerifyNetwork();
            }
            else
            {
                Log("ERROR", "No adapter could be restored. Backup kept at " + BackupFile);
            }
        }

        // Applies provider DNS (v4 + v6) with retries, registry persistence,
        // required DoH, and leak hardening, then verifies.
        static bool ApplyDnsServers(NetworkInterface adapter, string[] v4, string[] v6, bool enableDoh)
        {
            Log("INFO", "Clearing existing DNS entries...");
            RunNetshRetry("interface ip delete dns \"" + adapter.Name + "\" all", 2);
            RunNetshRetry("interface ipv6 delete dns \"" + adapter.Name + "\" all", 2);

            Log("INFO", "Setting primary DNS (" + v4[0] + ")...");
            bool ok1 = RunNetshRetry("interface ip set dns \"" + adapter.Name + "\" static " + v4[0] + " validate=no", 3)
                       || RunNetshRetry("interface ip set dns \"" + adapter.Name + "\" static " + v4[0], 2);
            bool ok2 = true;
            if (v4.Length > 1)
            {
                Log("INFO", "Setting secondary DNS (" + v4[1] + ")...");
                ok2 = RunNetshRetry("interface ip add dns \"" + adapter.Name + "\" " + v4[1] + " index=2 validate=no", 3)
                      || RunNetshRetry("interface ip add dns \"" + adapter.Name + "\" " + v4[1] + " index=2", 2);
            }

            // Always overwrite IPv6 DNS so DHCP IPv6 resolvers cannot leak.
            if (v6.Length > 0)
            {
                Log("INFO", "Setting IPv6 DNS (" + string.Join(", ", v6) + ")...");
                RunNetshRetry("interface ipv6 set dns \"" + adapter.Name + "\" static " + v6[0] + " validate=no", 2);
                if (v6.Length > 1)
                    RunNetshRetry("interface ipv6 add dns \"" + adapter.Name + "\" " + v6[1] + " index=2 validate=no", 2);
            }

            WriteInterfaceNameServers(adapter, v4, v6);

            if (!ok1 || !ok2)
            {
                Log("WARN", "netsh reported a failure - applying via registry fallback");
                var current = ReadAdapterDns(adapter, false);
                if (current.Count > 0 && current[0].Equals(v4[0], StringComparison.Ordinal))
                {
                    ok1 = true;
                    ok2 = true;
                    Log("INFO", "Registry/adapter DNS already matches provider");
                }
            }

            if (enableDoh)
            {
                string tpl = GetProviderDoh();
                if (!string.IsNullOrEmpty(tpl))
                {
                    ApplyDohTemplate(adapter, tpl);
                    ApplyDohEncryption(v4, v6, tpl);
                    HardenDnsClient();
                }
                else
                    Log("INFO", "Provider has no DoH template - plain DNS only");
            }
            else
            {
                HardenDnsClient();
            }

            RestartDnsClient();
            return ok1 && ok2;
        }

        static bool RunNetshRetry(string arguments, int retries)
        {
            for (int attempt = 0; attempt <= retries; attempt++)
            {
                if (attempt > 0)
                {
                    Log("WARN", "Netsh retry " + attempt + "/" + retries + "...");
                    Thread.Sleep(600);
                }
                if (RunNetsh(arguments)) return true;
            }
            return false;
        }

        // Two-stage verification: (1) the adapter really shows our server,
        // (2) that server actually answers a live DNS query (unless DoH is in place,
        // in which case a silent UDP resolver is expected on filtered networks).
        static bool VerifyDnsApplied(NetworkInterface adapter, string[] expectedV4, bool dohApplied)
        {
            try
            {
                Thread.Sleep(600);
                var fresh = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(a => a.Id == adapter.Id);
                if (fresh == null) return false;

                var current = fresh.GetIPProperties().DnsAddresses
                    .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                    .Select(x => x.ToString()).ToList();

                bool configOk = current.Count > 0 && current[0].Equals(expectedV4[0], StringComparison.Ordinal);
                if (configOk)
                    Log("INFO", "DNS config verified on '" + adapter.Name + "' (" + string.Join(", ", current) + ")");
                else
                {
                    Log("WARN", "DNS mismatch: expected " + expectedV4[0] + ", found " +
                        (current.Count > 0 ? string.Join(", ", current) : "(none)"));
                    return false;
                }

                if (IPAddress.TryParse(expectedV4[0], out var resolver))
                {
                    bool answers = QueryDnsServer(resolver, "example.com", 3000);
                    if (answers)
                        Log("SUCCESS", "Resolver " + resolver + " answered a live DNS query");
                    else if (dohApplied)
                        Log("INFO", "Resolver silent on plain DNS, but DoH is enabled (expected on filtered networks)");
                    else
                    {
                        Log("WARN", "Resolver " + resolver + " did not answer plain DNS");
                        return false;
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Shared restore logic: used by RevertToDefault and automatic rollback.
        static bool RestoreEntry(DnsBackupEntry entry, NetworkInterface adapter)
        {
            var target = adapter;

            // Prefer the stable interface GUID; fall back to the adapter name.
            if (!string.IsNullOrEmpty(entry.Guid))
            {
                var byGuid = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(a => a.Id.Equals(entry.Guid, StringComparison.OrdinalIgnoreCase) &&
                                         a.OperationalStatus == OperationalStatus.Up);
                if (byGuid != null) target = byGuid;
                else if (!entry.Guid.Equals(adapter.Id, StringComparison.OrdinalIgnoreCase))
                    Log("WARN", "Backup GUID not active; applying to '" + target.Name + "'");
            }
            else if (!entry.Name.Equals(target.Name, StringComparison.OrdinalIgnoreCase))
            {
                var named = GetAdapterByName(entry.Name);
                if (named != null) target = named;
                Log("WARN", "Backup was for adapter '" + entry.Name + "', applying to '" + target.Name + "'");
            }

            Log("INFO", "Restoring original DNS on " + target.Name + " ...");

            if (entry.Mode4 == "static" && entry.Dns4.Count > 0)
            {
                RunNetshRetry("interface ip delete dns \"" + target.Name + "\" all", 2);
                RunNetshRetry("interface ip set dns \"" + target.Name + "\" static " + entry.Dns4[0], 2);
                for (int i = 1; i < entry.Dns4.Count && i < 4; i++)
                    RunNetshRetry("interface ip add dns \"" + target.Name + "\" " + entry.Dns4[i] + " index=" + (i + 1), 2);
            }
            else
            {
                RunNetshRetry("interface ip set dns \"" + target.Name + "\" dhcp", 2);
                RunNetshRetry("interface ip delete dns \"" + target.Name + "\" all", 2);
            }

            if (entry.Mode6 == "static" && entry.Dns6.Count > 0)
            {
                RunNetshRetry("interface ipv6 delete dns \"" + target.Name + "\" all", 2);
                RunNetshRetry("interface ipv6 set dns \"" + target.Name + "\" static " + entry.Dns6[0], 2);
                for (int i = 1; i < entry.Dns6.Count && i < 4; i++)
                    RunNetshRetry("interface ipv6 add dns \"" + target.Name + "\" " + entry.Dns6[i] + " index=" + (i + 1), 2);
            }
            else
            {
                RunNetshRetry("interface ipv6 set dns \"" + target.Name + "\" dhcp", 2);
            }

            RestoreDohState(target, entry);
            RestoreInterfaceNameServers(target, entry);
            return true;
        }

        static void StatusCheck()
        {
            Console.WriteLine();
            Log("INFO", "Current DNS configuration (all active adapters):");
            bool any = false;

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                .Where(a => a.OperationalStatus == OperationalStatus.Up &&
                            a.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                var dns = nic.GetIPProperties().DnsAddresses
                    .Where(d => d.AddressFamily == AddressFamily.InterNetwork).ToList();
                var dns6 = nic.GetIPProperties().DnsAddresses
                    .Where(d => d.AddressFamily == AddressFamily.InterNetworkV6).ToList();

                if (dns.Count == 0 && dns6.Count == 0) continue;
                any = true;

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  * " + nic.Name + " [" + nic.NetworkInterfaceType + "]");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                foreach (var d in dns)
                {
                    Console.WriteLine("      IPv4: " + d + AnnotateDns(d.ToString()));
                    CheckLeak(nic.Name, d.ToString());
                }
                foreach (var d in dns6)
                {
                    Console.WriteLine("      IPv6: " + d + AnnotateDns(d.ToString()));
                    CheckLeak(nic.Name, d.ToString());
                }
                string doh = GetCurrentDohTemplate(nic);
                if (!string.IsNullOrEmpty(doh))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("      DoH : " + doh);
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                }
            }

            if (!any) Log("INFO", "No adapters with DNS servers found.");

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Backup file : " + (File.Exists(BackupFile) ? "EXISTS (revert available)" : "none"));
            Console.WriteLine("  Provider    : " + selectedProvider +
                (string.IsNullOrEmpty(GetProviderDoh()) ? "  (no DoH)" : "  (DoH ready)"));
            Console.WriteLine("  Device lock : OK");
            Console.WriteLine();

            Log("INFO", "Outbound connectivity test:");
            SetColor(TcpConnect("1.1.1.1", 443, 4000) ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine("  TCP 1.1.1.1:443   : " + (TcpConnect("1.1.1.1", 443, 4000) ? "OK" : "FAIL"));
            SetColor(TcpConnect("8.8.8.8", 53, 4000) ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine("  TCP 8.8.8.8:53    : " + (TcpConnect("8.8.8.8", 53, 4000) ? "OK" : "FAIL"));

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Public IP         : " + GetPublicIp());
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void ChangeProvider()
        {
            Console.WriteLine();
            var names = Providers.Keys.ToList();
            for (int i = 0; i < names.Count; i++)
            {
                var info = Providers[names[i]];
                string doh = string.IsNullOrEmpty(info.Doh4) ? "" : "  [DoH]";
                Console.WriteLine("  [" + (i + 1) + "] " + names[i] + doh);
            }
            Console.WriteLine("  [" + (names.Count + 1) + "] Custom (enter own servers)");
            Console.WriteLine("  [" + (names.Count + 2) + "] Cancel");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  Select: ");
            Console.ForegroundColor = ConsoleColor.White;

            string s = Console.ReadLine();
            if (!int.TryParse(s, out int idx) || idx < 1 || idx > names.Count + 2)
            {
                Log("ERROR", "Invalid selection");
                return;
            }

            if (idx <= names.Count)
            {
                selectedProvider = names[idx - 1];
                SaveSettings();
                Log("SUCCESS", "Provider set to " + selectedProvider + ". Applied on next activation.");
                return;
            }

            if (idx == names.Count + 1)
            {
                Console.Write("  Primary DNS:   ");
                string p = Console.ReadLine()?.Trim() ?? "";
                Console.Write("  Secondary DNS: ");
                string q = Console.ReadLine()?.Trim() ?? "";
                Console.Write("  DoH URL (optional, Enter to skip): ");
                string d = Console.ReadLine()?.Trim() ?? "";

                if (!string.IsNullOrEmpty(p) && !IPAddress.TryParse(p, out _))
                {
                    Log("ERROR", "Invalid IP: " + p);
                    return;
                }
                if (!string.IsNullOrEmpty(q) && !IPAddress.TryParse(q, out _))
                {
                    Log("ERROR", "Invalid IP: " + q);
                    return;
                }
                if (!string.IsNullOrEmpty(d) &&
                    (!Uri.TryCreate(d, UriKind.Absolute, out var du) ||
                     !du.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)))
                {
                    Log("ERROR", "Invalid DoH URL (must start with https://): " + d);
                    return;
                }

                custom1 = p;
                custom2 = q;
                customDoh = d;
                selectedProvider = "Custom";
                SaveSettings();
                Log("SUCCESS", "Custom DNS saved. Applied on next activation.");
            }
        }

        static void TestWebsite()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  Enter URL or domain: ");
            Console.ForegroundColor = ConsoleColor.White;
            string input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input)) return;
            RunWebsiteTest(input);
        }

        static void ApplyNetworkHardening()
        {
            Console.WriteLine();
            Log("INFO", "Network Hardening will apply anti-leak measures to your system");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  This will:");
            Console.WriteLine("    • Disable NetBIOS over TCP/IP");
            Console.WriteLine("    • Disable IPv6 transition technologies (Teredo, ISATAP, 6to4)");
            Console.WriteLine("    • Optimize DNS cache settings");
            Console.WriteLine("    • Disable NCSI (Network Connectivity) probes");
            Console.WriteLine("    • Harden DNS client (DoH required, LLMNR off)");
            Console.WriteLine();
            Console.WriteLine("  These changes are system-wide and persistent.");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.Write("  Continue? [Y/n]: ");
            
            string confirm = Console.ReadLine();
            if (!string.IsNullOrEmpty(confirm) && !confirm.Trim().ToLowerInvariant().StartsWith("y"))
            {
                Log("INFO", "Hardening cancelled");
                return;
            }

            Console.WriteLine();
            Log("INFO", "Applying network hardening...");
            
            try
            {
                // Run hardening asynchronously
                var result = _hardener.ApplyFullHardeningAsync().GetAwaiter().GetResult();
                
                Console.WriteLine();
                if (result.Success)
                {
                    Log("SUCCESS", "Network hardening completed successfully");
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  ✓ System hardened against DNS leaks");
                    Console.ForegroundColor = ConsoleColor.White;
                    
                    // Show status
                    Console.WriteLine();
                    Log("INFO", "Checking hardening status...");
                    var status = _hardener.GetHardeningStatusAsync().GetAwaiter().GetResult();
                    ShowHardeningStatus(status);
                    
                    PlaySuccessSound();
                }
                else
                {
                    Log("WARN", result.Message);
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("  Some hardening steps failed. See log above for details.");
                    Console.ForegroundColor = ConsoleColor.White;
                }
                
                // Show detailed steps
                if (result.Steps.Count > 0)
                {
                    Console.WriteLine();
                    Log("INFO", "Hardening steps:");
                    foreach (var step in result.Steps)
                    {
                        Console.Write("    ");
                        Console.ForegroundColor = step.Success ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.Write(step.Success ? "✓" : "✗");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($" {step.Name}: {step.Details}");
                    }
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", $"Hardening failed: {ex.Message}");
            }
        }

        static void ShowHardeningStatus(HardeningStatus status)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Hardening Status:");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            
            ShowStatusLine("NetBIOS", status.NetBiosDisabled);
            ShowStatusLine("IPv6 Transitions", status.IPv6TransitionsDisabled);
            ShowStatusLine("DNS Cache", status.DnsCacheOptimized);
            ShowStatusLine("NCSI Probes", status.NCSIDisabled);
            ShowStatusLine("DNS Client", status.DnsClientHardened);
            
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  Overall: ");
            
            int percentage = status.GetHardeningPercentage();
            if (percentage == 100)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Fully Hardened (" + percentage + "%)");
            }
            else if (percentage >= 80)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Mostly Hardened (" + percentage + "%)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Partially Hardened (" + percentage + "%)");
            }
            
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void ShowStatusLine(string feature, bool enabled)
        {
            Console.Write("    " + feature.PadRight(20) + ": ");
            Console.ForegroundColor = enabled ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine(enabled ? "DISABLED" : "ACTIVE");
            Console.ForegroundColor = ConsoleColor.DarkGray;
        }

        static void BackupSystem()
        {
            Console.WriteLine();
            Log("INFO", "System Backup - Create snapshot of current state");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  Description (optional): ");
            Console.ForegroundColor = ConsoleColor.White;
            
            string description = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(description))
                description = "Manual backup";

            Console.WriteLine();
            Log("INFO", "Creating system snapshot...");

            try
            {
                var snapshot = _backupService.CreateSystemSnapshotAsync(description).GetAwaiter().GetResult();
                
                if (snapshot != null)
                {
                    bool saved = _backupService.SaveSnapshotAsync(snapshot).GetAwaiter().GetResult();
                    
                    if (saved)
                    {
                        Log("SUCCESS", "System backup created successfully");
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"  Snapshot ID: {snapshot.Id}");
                        Console.WriteLine($"  Timestamp: {snapshot.Timestamp:g}");
                        Console.WriteLine($"  Description: {snapshot.Description}");
                        Console.ForegroundColor = ConsoleColor.White;
                        PlaySuccessSound();
                    }
                    else
                    {
                        Log("ERROR", "Failed to save snapshot");
                    }
                }
                else
                {
                    Log("ERROR", "Failed to create snapshot");
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", $"Backup failed: {ex.Message}");
            }
        }

        static void RestoreFromBackup()
        {
            Console.WriteLine();
            Log("INFO", "Restore from Backup");
            Console.WriteLine();

            try
            {
                // List available snapshots
                var snapshots = _backupService.ListSnapshotsAsync().GetAwaiter().GetResult();
                
                if (snapshots.Count == 0)
                {
                    Log("WARN", "No backups found");
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  Available backups:");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                
                for (int i = 0; i < snapshots.Count && i < 10; i++)
                {
                    var snap = snapshots[i];
                    Console.WriteLine($"  [{i + 1}] {snap.Timestamp:g} - {snap.Description} ({snap.FileSizeBytes / 1024} KB)");
                }
                
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("  Select backup (1-{0}) or 0 for latest: ", Math.Min(snapshots.Count, 10));
                Console.ForegroundColor = ConsoleColor.White;
                
                string input = Console.ReadLine();
                if (!int.TryParse(input, out int choice))
                {
                    Log("ERROR", "Invalid selection");
                    return;
                }

                SystemSnapshot selectedSnapshot;
                if (choice == 0)
                {
                    selectedSnapshot = _backupService.GetLatestSnapshotAsync().GetAwaiter().GetResult();
                    Log("INFO", "Using latest snapshot");
                }
                else if (choice >= 1 && choice <= Math.Min(snapshots.Count, 10))
                {
                    var snapshotInfo = snapshots[choice - 1];
                    selectedSnapshot = _backupService.LoadSnapshotAsync(snapshotInfo.FilePath).GetAwaiter().GetResult();
                }
                else
                {
                    Log("ERROR", "Invalid selection");
                    return;
                }

                if (selectedSnapshot == null)
                {
                    Log("ERROR", "Failed to load snapshot");
                    return;
                }

                // Confirm restore
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  WARNING: This will restore registry and DNS settings to a previous state.");
                Console.Write("  Continue? [Y/n]: ");
                Console.ForegroundColor = ConsoleColor.White;
                
                string confirm = Console.ReadLine();
                if (!string.IsNullOrEmpty(confirm) && !confirm.Trim().ToLowerInvariant().StartsWith("y"))
                {
                    Log("INFO", "Restore cancelled");
                    return;
                }

                // Perform restore
                Console.WriteLine();
                Log("INFO", "Restoring system state...");
                
                var result = _restoreService.RestoreFromSnapshotAsync(selectedSnapshot, dryRun: false).GetAwaiter().GetResult();
                
                Console.WriteLine();
                if (result.Success)
                {
                    Log("SUCCESS", result.Message);
                    PlaySuccessSound();
                }
                else
                {
                    Log("ERROR", result.Message);
                }

                // Show restore steps
                if (result.Steps.Count > 0)
                {
                    Console.WriteLine();
                    Log("INFO", "Restore steps:");
                    foreach (var step in result.Steps)
                    {
                        Console.Write("    ");
                        Console.ForegroundColor = step.Success ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.Write(step.Success ? "✓" : "✗");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($" {step.Category}: {step.Details}");
                    }
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", $"Restore failed: {ex.Message}");
            }
        }

        static void RunWebsiteTest(string input)
        {
            if (!input.Contains("://")) input = "https://" + input;
            if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            {
                Log("ERROR", "Invalid URL");
                return;
            }

            string host = uri.Host;
            Console.WriteLine();
            Log("INFO", "Testing " + host);

            bool resolved = Resolve(host, 5000);
            Console.Write("  DNS resolution        : ");
            SetColor(resolved ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine(resolved ? "OK" : "BLOCKED / FAILED");

            bool tcp443 = TcpConnect(host, 443, 4000);
            Console.Write("  TCP :443              : ");
            SetColor(tcp443 ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine(tcp443 ? "OPEN" : "CLOSED / FILTERED");

            if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                bool tcp80 = TcpConnect(host, 80, 4000);
                Console.Write("  TCP :80               : ");
                SetColor(tcp80 ? ConsoleColor.Green : ConsoleColor.Red);
                Console.WriteLine(tcp80 ? "OPEN" : "CLOSED / FILTERED");
            }

            if (resolved && tcp443)
            {
                try
                {
                    try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch { }
                    using (var wc = new WebClient())
                    {
                        wc.Proxy = null;
                        wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                        wc.Encoding = Encoding.UTF8;
                        string body = wc.DownloadString(uri.AbsoluteUri);
                        Console.Write("  HTTP fetch            : ");
                        SetColor(ConsoleColor.Green);
                        Console.WriteLine("OK (" + body.Length + " bytes)");
                    }
                }
                catch (WebException wex)
                {
                    var resp = wex.Response as HttpWebResponse;
                    Console.Write("  HTTP fetch            : ");
                    SetColor(ConsoleColor.Red);
                    if (resp != null)
                        Console.WriteLine("BLOCKED (HTTP " + (int)resp.StatusCode + ")");
                    else
                        Console.WriteLine("FAILED (" + wex.Message + ")");
                }
                catch (Exception ex)
                {
                    Console.Write("  HTTP fetch            : ");
                    SetColor(ConsoleColor.Red);
                    Console.WriteLine("FAILED (" + ex.Message + ")");
                }
            }

            SetColor(ConsoleColor.White);
        }

        static void VerifyNetwork()
        {
            Log("INFO", "Post-change verification:");
            foreach (var host in new[] { "example.com", "wikipedia.org", "github.com" })
            {
                Console.Write("  DNS  " + host.PadRight(18) + ": ");
                bool ok = Resolve(host, 5000);
                SetColor(ok ? ConsoleColor.Green : ConsoleColor.Red);
                Console.WriteLine(ok ? "OK" : "FAIL");
            }

            Console.Write("  TCP  1.1.1.1:443      : ");
            bool t1 = TcpConnect("1.1.1.1", 443, 4000);
            SetColor(t1 ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine(t1 ? "OK" : "FAIL");

            Console.Write("  TCP  example.com:443  : ");
            bool t2 = TcpConnect("example.com", 443, 4000);
            SetColor(t2 ? ConsoleColor.Green : ConsoleColor.Red);
            Console.WriteLine(t2 ? "OK" : "FAIL");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Public IP            : " + GetPublicIp());
            SetColor(ConsoleColor.White);
        }

        // ------------------------------------------------------------ helpers

        static void CheckLeak(string adapter, string dnsAddr)
        {
            if (IsLocalDns(dnsAddr)) return;
            if (IsProviderDns(dnsAddr)) return;
            Log("WARN", "Possible DNS leak on '" + adapter + "' -> " + dnsAddr);
        }

        static bool IsProviderDns(string addr)
        {
            if (selectedProvider == "Custom")
                return addr == custom1 || addr == custom2;
            if (Providers.TryGetValue(selectedProvider, out var info))
                return info.V4.Concat(info.V6).Contains(addr, StringComparer.OrdinalIgnoreCase);
            return false;
        }

        static bool IsLocalDns(string addr)
        {
            if (!IPAddress.TryParse(addr, out var ip)) return true;
            if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
            var b = ip.GetAddressBytes();
            return b[0] == 10 ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 169 && b[1] == 254);
        }

        static string AnnotateDns(string addr)
        {
            if (IsProviderDns(addr)) return "  (selected provider)";
            if (IsLocalDns(addr)) return "  (local/private)";
            return "  (external)";
        }

        // ------------------------------------------------------------ backup

        static DnsBackup ReadBackup()
        {
            if (File.Exists(BackupFile))
            {
                try
                {
                    var b = JsonSerializer.Deserialize<DnsBackup>(File.ReadAllText(BackupFile, Encoding.UTF8));
                    if (b != null && b.Adapters != null) return b;
                }
                catch { }
            }

            // v1 key=value format (dns_backup.txt) - migrate in place.
            if (File.Exists(LegacyBackupFile))
            {
                string adapter = "", mode = "dhcp", dns4 = "", dns6 = "";
                foreach (var line in File.ReadAllLines(LegacyBackupFile))
                {
                    var kv = line.Split(new[] { '=' }, 2);
                    if (kv.Length != 2) continue;
                    if (kv[0] == "adapter") adapter = kv[1];
                    else if (kv[0] == "mode") mode = kv[1];
                    else if (kv[0] == "dns4") dns4 = kv[1];
                    else if (kv[0] == "dns6") dns6 = kv[1];
                }
                if (!string.IsNullOrEmpty(adapter))
                {
                    var nic = GetAdapterByName(adapter);
                    var v4list = dns4.Split(',').Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                    var v6list = dns6.Split(',').Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                    var b = new DnsBackup
                    {
                        Provider = selectedProvider,
                        CreatedAt = DateTime.Now.ToString("s"),
                        Adapters = new List<DnsBackupEntry>
                        {
                            new DnsBackupEntry
                            {
                                Name = adapter,
                                Guid = nic != null ? nic.Id : "",
                                Mode4 = mode,
                                Mode6 = v6list.Count > 0 ? "static" : "dhcp",
                                Dns4 = v4list,
                                Dns6 = v6list
                            }
                        }
                    };
                    SaveBackup(b);
                    try { File.Delete(LegacyBackupFile); } catch { }
                    Log("INFO", "Migrated legacy backup to new format");
                    return b;
                }
            }
            return null;
        }

        static void SaveBackup(DnsBackup b)
        {
            try
            {
                Directory.CreateDirectory(AppDataDir);
                if (File.Exists(BackupFile))
                {
                    try { File.Copy(BackupFile, PrevBackupFile, true); } catch { }
                }
                b.Version = 3;
                File.WriteAllText(BackupFile,
                    JsonSerializer.Serialize(b, new JsonSerializerOptions { WriteIndented = true }),
                    Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Backup save failed: " + ex.Message);
            }
        }

        static DnsBackupEntry PrepareBackupForAdapter(NetworkInterface adapter)
        {
            var bak = ReadBackup() ?? new DnsBackup
            {
                Provider = selectedProvider,
                CreatedAt = DateTime.Now.ToString("s")
            };

            CaptureGlobalDnsState(bak);

            var existing = bak.Adapters.FirstOrDefault(e =>
                (!string.IsNullOrEmpty(e.Guid) && e.Guid.Equals(adapter.Id, StringComparison.OrdinalIgnoreCase)) ||
                (string.IsNullOrEmpty(e.Guid) && e.Name.Equals(adapter.Name, StringComparison.OrdinalIgnoreCase)));
            if (existing != null)
            {
                SaveBackup(bak);
                Log("INFO", "Existing backup kept for '" + adapter.Name + "' (original DNS preserved)");
                return existing;
            }

            try
            {
                Directory.CreateDirectory(AppDataDir);
                var props = adapter.GetIPProperties();
                var v4 = props.DnsAddresses
                    .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                    .Select(x => x.ToString()).ToList();
                var v6 = props.DnsAddresses
                    .Where(x => x.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(x => x.ToString()).ToList();

                var entry = new DnsBackupEntry
                {
                    Name = adapter.Name,
                    Guid = adapter.Id,
                    Mode4 = v4.Count > 0 ? "static" : "dhcp",
                    Mode6 = v6.Count > 0 ? "static" : "dhcp",
                    Dns4 = v4,
                    Dns6 = v6,
                    NameServer4 = ReadNameServerValue(adapter.Id, false),
                    NameServer6 = ReadNameServerValue(adapter.Id, true)
                };

                // Snapshot DoH registry state so revert restores it exactly.
                try
                {
                    using (var k = Registry.LocalMachine.OpenSubKey(DohRegBase + @"\" + adapter.Id))
                    {
                        if (k != null)
                        {
                            var tpl = k.GetValue("DohTemplate") as string;
                            var auto = k.GetValue("EnableAutoDoh");
                            entry.DohTemplate = tpl ?? "";
                            entry.EnableAutoDoh = auto is int i ? i : (auto != null ? 1 : -1);
                        }
                    }
                }
                catch { }

                bak.Provider = selectedProvider;
                bak.Adapters.Add(entry);
                SaveBackup(bak);
                Log("INFO", "Original DNS backed up for '" + adapter.Name + "' (" +
                    (v4.Count > 0 ? string.Join(", ", v4) : "automatic") + ")");
                return entry;
            }
            catch (Exception ex)
            {
                Log("ERROR", "Backup failed: " + ex.Message);
                return null;
            }
        }

        // ------------------------------------------------------- DNS over HTTPS

        static string GetProviderDoh()
        {
            if (selectedProvider == "Custom") return customDoh ?? "";
            if (!Providers.TryGetValue(selectedProvider, out var info)) return "";
            return info.Doh4 ?? "";
        }

        static string GetCurrentDohTemplate(NetworkInterface adapter)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(DohRegBase + @"\" + adapter.Id))
                    return k?.GetValue("DohTemplate") as string ?? "";
            }
            catch
            {
                return "";
            }
        }

        static void ApplyDohTemplate(NetworkInterface adapter, string template)
        {
            try
            {
                var keyPath = DohRegBase + @"\" + adapter.Id;
                using (var k = Registry.LocalMachine.CreateSubKey(keyPath))
                {
                    k.SetValue("DohTemplate", template, RegistryValueKind.String);
                    // 3 = required DoH (no plaintext fallback) — stops on-path DNS hijack
                    k.SetValue("EnableAutoDoh", 3, RegistryValueKind.DWord);
                }
                Log("SUCCESS", "DoH enabled for '" + adapter.Name + "' -> " + template);
            }
            catch (Exception ex)
            {
                Log("WARN", "DoH could not be configured: " + ex.Message + " (plain DNS only)");
            }
        }

        static void RestoreDohState(NetworkInterface adapter, DnsBackupEntry entry)
        {
            try
            {
                var keyPath = DohRegBase + @"\" + adapter.Id;
                if (string.IsNullOrEmpty(entry.DohTemplate) && entry.EnableAutoDoh < 0)
                {
                    // Nothing existed before - remove whatever the bypass added.
                    using (var k = Registry.LocalMachine.OpenSubKey(keyPath, true))
                    {
                        if (k != null)
                        {
                            k.DeleteValue("DohTemplate", false);
                            k.DeleteValue("EnableAutoDoh", false);
                            Log("INFO", "DoH registry entries removed");
                        }
                    }
                    return;
                }
                using (var k = Registry.LocalMachine.CreateSubKey(keyPath))
                {
                    if (string.IsNullOrEmpty(entry.DohTemplate))
                        k.DeleteValue("DohTemplate", false);
                    else
                        k.SetValue("DohTemplate", entry.DohTemplate, RegistryValueKind.String);
                    if (entry.EnableAutoDoh < 0)
                        k.DeleteValue("EnableAutoDoh", false);
                    else
                        k.SetValue("EnableAutoDoh", entry.EnableAutoDoh, RegistryValueKind.DWord);
                }
                Log("INFO", "DoH registry state restored");
            }
            catch (Exception ex)
            {
                Log("WARN", "DoH restore failed: " + ex.Message);
            }
        }

        static List<string> ReadAdapterDns(NetworkInterface adapter, bool ipv6)
        {
            try
            {
                var fresh = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(a => a.Id.Equals(adapter.Id, StringComparison.OrdinalIgnoreCase))
                    ?? adapter;
                var family = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                return fresh.GetIPProperties().DnsAddresses
                    .Where(x => x.AddressFamily == family)
                    .Select(x => x.ToString())
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        static string TcpipInterfaceKey(string guid, bool ipv6)
        {
            return (ipv6
                ? @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\"
                : @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\") + guid;
        }

        static string ReadNameServerValue(string guid, bool ipv6)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(TcpipInterfaceKey(guid, ipv6)))
                    return k?.GetValue("NameServer") as string;
            }
            catch
            {
                return null;
            }
        }

        static void WriteNameServerValue(string guid, bool ipv6, string value)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(TcpipInterfaceKey(guid, ipv6), true))
                {
                    if (k == null) return;
                    k.SetValue("NameServer", value ?? "", RegistryValueKind.String);
                }
            }
            catch { }
        }

        static void WriteInterfaceNameServers(NetworkInterface adapter, string[] v4, string[] v6)
        {
            try
            {
                WriteNameServerValue(adapter.Id, false, v4 != null && v4.Length > 0 ? string.Join(",", v4) : "");
                WriteNameServerValue(adapter.Id, true, v6 != null && v6.Length > 0 ? string.Join(",", v6) : "");
                Log("INFO", "Persisted DNS in TCP/IP interface registry");
            }
            catch (Exception ex)
            {
                Log("WARN", "Registry DNS persist failed: " + ex.Message);
            }
        }

        static void RestoreInterfaceNameServers(NetworkInterface adapter, DnsBackupEntry entry)
        {
            try
            {
                if (entry.NameServer4 != null)
                    WriteNameServerValue(adapter.Id, false, entry.NameServer4);
                else if (entry.Mode4 != "static")
                    WriteNameServerValue(adapter.Id, false, "");

                if (entry.NameServer6 != null)
                    WriteNameServerValue(adapter.Id, true, entry.NameServer6);
                else if (entry.Mode6 != "static")
                    WriteNameServerValue(adapter.Id, true, "");
            }
            catch { }
        }

        static int ReadDword(string keyPath, string name, int missing)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    var v = k?.GetValue(name);
                    if (v is int i) return i;
                    if (v != null && int.TryParse(v.ToString(), out int p)) return p;
                }
            }
            catch { }
            return missing;
        }

        static void WriteDword(string keyPath, string name, int value)
        {
            using (var k = Registry.LocalMachine.CreateSubKey(keyPath))
                k.SetValue(name, value, RegistryValueKind.DWord);
        }

        static void DeleteValue(string keyPath, string name)
        {
            using (var k = Registry.LocalMachine.OpenSubKey(keyPath, true))
                k?.DeleteValue(name, false);
        }

        static void CaptureGlobalDnsState(DnsBackup bak)
        {
            if (bak.GlobalCaptured) return;
            bak.GlobalEnableAutoDoh = ReadDword(DnsCacheParams, "EnableAutoDoh", -1);
            bak.DisableSmartNameResolution = ReadDword(DnsClientPolicy, "DisableSmartNameResolution", -1);
            bak.EnableMulticast = ReadDword(DnsClientPolicy, "EnableMulticast", -1);
            bak.GlobalCaptured = true;
            if (bak.DohEncryptionAdded == null)
                bak.DohEncryptionAdded = new List<string>();
            SaveBackup(bak);
        }

        static void HardenDnsClient()
        {
            try
            {
                // Required DoH globally (3) so plaintext DNS cannot be hijacked.
                WriteDword(DnsCacheParams, "EnableAutoDoh", 3);
                // Stop Windows from querying every NIC's DNS in parallel (classic leak).
                WriteDword(DnsClientPolicy, "DisableSmartNameResolution", 1);
                WriteDword(DnsCacheParams, "DisableParallelAandAAAA", 1);
                // LLMNR/multicast name resolution can bypass unicast DNS.
                WriteDword(DnsClientPolicy, "EnableMulticast", 0);
                Log("INFO", "DNS client hardened (DoH required, smart multi-homed off, LLMNR off)");
            }
            catch (Exception ex)
            {
                Log("WARN", "DNS client harden failed: " + ex.Message);
            }
        }

        static void RestoreGlobalDnsState()
        {
            var bak = ReadBackup();
            if (bak == null || !bak.GlobalCaptured) return;

            try
            {
                if (bak.GlobalEnableAutoDoh < 0) DeleteValue(DnsCacheParams, "EnableAutoDoh");
                else WriteDword(DnsCacheParams, "EnableAutoDoh", bak.GlobalEnableAutoDoh);

                if (bak.DisableSmartNameResolution < 0) DeleteValue(DnsClientPolicy, "DisableSmartNameResolution");
                else WriteDword(DnsClientPolicy, "DisableSmartNameResolution", bak.DisableSmartNameResolution);

                if (bak.EnableMulticast < 0) DeleteValue(DnsClientPolicy, "EnableMulticast");
                else WriteDword(DnsClientPolicy, "EnableMulticast", bak.EnableMulticast);

                DeleteValue(DnsCacheParams, "DisableParallelAandAAAA");

                if (bak.DohEncryptionAdded != null)
                {
                    foreach (var ip in bak.DohEncryptionAdded.Distinct())
                        RunNetsh("dns delete encryption server=" + ip);
                }

                Log("INFO", "Global DNS client state restored");
            }
            catch (Exception ex)
            {
                Log("WARN", "Global DNS restore failed: " + ex.Message);
            }
        }

        static void ApplyDohEncryption(string[] v4, string[] v6, string template)
        {
            var bak = ReadBackup();
            if (bak != null && bak.DohEncryptionAdded == null)
                bak.DohEncryptionAdded = new List<string>();

            var servers = (v4 ?? Array.Empty<string>()).Concat(v6 ?? Array.Empty<string>());
            foreach (var ip in servers)
            {
                if (string.IsNullOrWhiteSpace(ip)) continue;
                string args = "dns add encryption server=" + ip +
                              " dohtemplate=" + template +
                              " autoupgrade=yes udpfallback=no";
                if (RunNetsh(args))
                {
                    Log("SUCCESS", "DoH encryption mapped for " + ip);
                    if (bak != null && !bak.DohEncryptionAdded.Contains(ip, StringComparer.OrdinalIgnoreCase))
                        bak.DohEncryptionAdded.Add(ip);
                }
            }
            if (bak != null) SaveBackup(bak);
        }

        static void RestartDnsClient()
        {
            Log("INFO", "Restarting DNS Client service...");
            int stop = RunProcess("net", "stop Dnscache", out _, 12000);
            int start = RunProcess("net", "start Dnscache", out _, 12000);
            if (stop == 0 && start == 0)
                Log("INFO", "DNS Client service restarted");
            else
                Log("WARN", "DNS Client service could not be restarted (protected on some SKUs) - cache flush still applied");
        }

        // -------------------------------------------------- DNS wire level tests

        // Pre-flight check: send a real DNS query to each candidate server.
        static int TestProviderServers(string[] v4)
        {
            int ok = 0;
            foreach (var s in v4)
            {
                if (!IPAddress.TryParse(s, out var ip)) continue;
                bool r = QueryDnsServer(ip, "example.com", 2500);
                Console.Write("  Probe " + s.PadRight(15) + ": ");
                SetColor(r ? ConsoleColor.Green : ConsoleColor.Red);
                Console.WriteLine(r ? "responds" : "no response");
                if (r) ok++;
            }
            SetColor(ConsoleColor.White);
            return ok;
        }

        // Queries a specific DNS server directly (UDP 53, then TCP 53) and
        // returns true if a response with a matching transaction ID arrives.
        static bool QueryDnsServer(IPAddress server, string host, int timeoutMs)
        {
            byte[] query = BuildDnsQuery(host);
            ushort id = (ushort)((query[0] << 8) | query[1]);

            try
            {
                using (var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0)))
                {
                    udp.Client.ReceiveTimeout = timeoutMs;
                    udp.Connect(server, 53);
                    udp.Send(query, query.Length);
                    var ep = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp = udp.Receive(ref ep);
                    if (resp.Length >= 12 && (ushort)((resp[0] << 8) | resp[1]) == id) return true;
                }
            }
            catch { }

            try
            {
                using (var tcp = new TcpClient())
                {
                    var ct = tcp.ConnectAsync(server, 53);
                    if (!ct.Wait(timeoutMs) || !tcp.Connected) return false;
                    var ns = tcp.GetStream();
                    ns.ReadTimeout = timeoutMs;
                    ns.WriteTimeout = timeoutMs;
                    var framed = new byte[query.Length + 2];
                    framed[0] = (byte)(query.Length >> 8);
                    framed[1] = (byte)(query.Length & 0xFF);
                    Buffer.BlockCopy(query, 0, framed, 2, query.Length);
                    ns.Write(framed, 0, framed.Length);
                    var lenBuf = new byte[2];
                    if (ns.Read(lenBuf, 0, 2) != 2) return false;
                    int len = (lenBuf[0] << 8) | lenBuf[1];
                    var rbuf = new byte[len];
                    int got = 0;
                    while (got < len)
                    {
                        int n = ns.Read(rbuf, got, len - got);
                        if (n <= 0) return false;
                        got += n;
                    }
                    return got >= 12 && (ushort)((rbuf[0] << 8) | rbuf[1]) == id;
                }
            }
            catch { }
            return false;
        }

        static byte[] BuildDnsQuery(string host)
        {
            var ms = new MemoryStream();
            var w = new BinaryWriter(ms);
            ushort id = (ushort)(Rng.Next(0x10000));
            w.Write(id);
            w.Write((ushort)0x0100); // RD flag
            w.Write((ushort)1);      // QDCOUNT
            w.Write((ushort)0);      // ANCOUNT
            w.Write((ushort)0);      // NSCOUNT
            w.Write((ushort)0);      // ARCOUNT
            foreach (var label in host.TrimEnd('.').Split('.'))
            {
                var b = Encoding.ASCII.GetBytes(label);
                w.Write((byte)b.Length);
                w.Write(b);
            }
            w.Write((byte)0);        // root label
            w.Write((ushort)1);      // QTYPE = A
            w.Write((ushort)1);      // QCLASS = IN
            return ms.ToArray();
        }

        // -------------------------------------------------------- adapters

        static List<NetworkInterface> GetCandidateAdapters()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(a => a.OperationalStatus == OperationalStatus.Up &&
                            (a.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                             a.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                             a.NetworkInterfaceType == NetworkInterfaceType.FastEthernetFx ||
                             a.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet) &&
                            !ContainsAny(a.Description, "virtual", "vpn", "loopback", "hyper-v", "tap",
                                         "tunnel", "bluetooth", "pseudo", "wan miniport", "wi-fi direct",
                                         "kernel debug", "safe net"))
                .OrderByDescending(a => IsRealNic(a))
                .ThenByDescending(a => a.GetIPProperties().GatewayAddresses.Count > 0)
                .ThenByDescending(a => a.GetIPProperties().UnicastAddresses
                                       .Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork))
                .ToList();
        }

        // A real NIC has a proper physical driver description; NDIS/WFP filter
        // drivers, packet shims, QoS schedulers etc. are virtual and cannot host DNS.
        static bool IsRealNic(NetworkInterface a)
        {
            return !ContainsAny(a.Description,
                "lightweight", "light weight", "filter", "wfp", "native mac",
                "packet scheduler", "packet driver", "qos", "ndis", "npcap",
                "pcap", "virtual", "vpn", "loopback", "hyper-v", "tap",
                "tunnel", "bluetooth", "pseudo", "wan miniport", "wi-fi direct",
                "kernel debug", "safe net");
        }

        static NetworkInterface GetAdapterByName(string name)
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase) &&
                                     a.OperationalStatus == OperationalStatus.Up);
        }

        // Interactive or CLI-aware adapter selection (never blocks in CLI mode).
        static NetworkInterface SelectAdapter(string prompt)
        {
            var list = GetCandidateAdapters();
            if (list.Count == 0) return null;

            if (!string.IsNullOrEmpty(cliAdapterName))
            {
                var named = GetAdapterByName(cliAdapterName);
                if (named != null) return named;
                if (int.TryParse(cliAdapterName, out int idx) && idx >= 1 && idx <= list.Count)
                    return list[idx - 1];
                Log("ERROR", "Adapter not found: " + cliAdapterName);
                return null;
            }

            if (cliMode)
            {
                var rec = list.FirstOrDefault(a => IsRealNic(a) &&
                                                   a.GetIPProperties().GatewayAddresses.Count > 0) ?? list[0];
                Log("INFO", "Auto-selected adapter: " + rec.Name);
                return rec;
            }

            if (list.Count == 1) return list[0];
            return SelectAdapterInteractive(list, prompt);
        }

        static NetworkInterface SelectAdapterInteractive(List<NetworkInterface> list, string prompt)
        {
            int recommended = -1;
            for (int i = 0; i < list.Count; i++)
            {
                var a = list[i];
                bool real = IsRealNic(a) && a.GetIPProperties().GatewayAddresses.Count > 0;
                if (real && recommended == -1) recommended = i;
            }

            Console.WriteLine();
            for (int i = 0; i < list.Count; i++)
            {
                var a = list[i];
                string mark = i == recommended ? "  (önerilen - bu ağ)" : "";
                Console.WriteLine("  [" + (i + 1) + "] " + a.Name + "  (" + a.NetworkInterfaceType + ")" + mark);
            }

            if (recommended >= 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  Önerilen ağ: [" + (recommended + 1) + "] " + list[recommended].Name);
                Console.ForegroundColor = ConsoleColor.White;
            }
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  Select " + prompt + " adapter: ");
            Console.ForegroundColor = ConsoleColor.White;

            string s = Console.ReadLine();
            if (int.TryParse(s, out int idx) && idx >= 1 && idx <= list.Count)
                return list[idx - 1];

            Log("INFO", "Using default: " + list[0].Name);
            return list[0];
        }

        // ------------------------------------------------------------ process

        static bool RunNetsh(string arguments)
        {
            string output;
            int code = RunProcess("netsh", arguments, out output);
            bool failed = code != 0 ||
                          ContainsAny(output, "error", "hata", "denied", "başarısız", "reddedildi", "yetki");

            if (failed && !string.IsNullOrWhiteSpace(output))
            {
                string first = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                     .FirstOrDefault() ?? output;
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("      -> " + first.Trim());
                SetColor(ConsoleColor.White);
            }
            return !failed;
        }

        static void PlaySuccessSound()
        {
            try
            {
                Console.Beep(880, 130);   // dı
                Thread.Sleep(70);
                Console.Beep(1175, 380);  // dııt
            }
            catch { }
        }

        static void PlayExitSound()
        {
            try
            {
                Console.Beep(620, 150);   // dıt
            }
            catch { }
        }

        static void OpenGitHub()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://github.com/NeHx0",
                    UseShellExecute = true
                });
                Log("INFO", "Opening GitHub profile in browser...");
            }
            catch (Exception ex)
            {
                Log("WARN", "Could not open browser: " + ex.Message);
            }
        }

        static void FlushDns()
        {
            Log("INFO", "Flushing DNS cache...");
            RunProcess("ipconfig", "/flushdns", out _);
            RunProcess("nbtstat", "-R", out _);
        }

        static int RunProcess(string fileName, string arguments, out string output)
        {
            return RunProcess(fileName, arguments, out output, 5000);
        }

        static int RunProcess(string fileName, string arguments, out string output, int timeoutMs)
        {
            output = "";
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var p = Process.Start(psi))
                {
                    var soTask = p.StandardOutput.ReadToEndAsync();
                    var seTask = p.StandardError.ReadToEndAsync();

                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); p.WaitForExit(); } catch { }
                    }
                    Task.WaitAll(soTask, seTask);

                    output = (soTask.Result + seTask.Result).Trim();
                    return p.ExitCode;
                }
            }
            catch (Exception ex)
            {
                output = ex.Message;
                return -1;
            }
        }

        static bool Resolve(string host, int timeoutMs)
        {
            try
            {
                var task = Dns.GetHostAddressesAsync(host);
                return task.Wait(timeoutMs) && !task.IsFaulted && task.Result.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        static bool TcpConnect(string host, int port, int timeoutMs)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var task = client.ConnectAsync(host, port);
                    return task.Wait(timeoutMs) && client.Connected;
                }
            }
            catch
            {
                return false;
            }
        }

        static string GetPublicIp()
        {
            try
            {
                try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch { }
                using (var wc = new WebClient())
                {
                    wc.Proxy = null;
                    wc.Headers.Add("User-Agent", "curl/8.0");
                    string trace = wc.DownloadString("https://www.cloudflare.com/cdn-cgi/trace");
                    foreach (var line in trace.Split('\n'))
                        if (line.StartsWith("ip=")) return line.Substring(3).Trim();
                }
            }
            catch { }
            return "unreachable";
        }

        static string[] GetProviderServers(bool ipv6)
        {
            if (selectedProvider == "Custom")
            {
                return new[] { custom1, custom2 }
                    .Where(x => !string.IsNullOrWhiteSpace(x) &&
                                IPAddress.TryParse(x, out var a) &&
                                a.AddressFamily == (ipv6 ? AddressFamily.InterNetworkV6
                                                         : AddressFamily.InterNetwork))
                    .ToArray();
            }

            if (!Providers.TryGetValue(selectedProvider, out var info))
                info = Providers["Cloudflare"];

            var src = ipv6 ? info.V6 : info.V4;
            return src.Where(x => IPAddress.TryParse(x, out var a) &&
                                  a.AddressFamily == (ipv6 ? AddressFamily.InterNetworkV6
                                                           : AddressFamily.InterNetwork))
                      .ToArray();
        }

        static void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(AppDataDir);
                File.WriteAllLines(SettingsFile, new[]
                {
                    "provider=" + selectedProvider,
                    "custom1=" + custom1,
                    "custom2=" + custom2,
                    "customDoh=" + customDoh
                });
            }
            catch { }
        }

        static void LoadSettings()
        {
            try
            {
                if (!File.Exists(SettingsFile)) return;
                foreach (var line in File.ReadAllLines(SettingsFile))
                {
                    var kv = line.Split(new[] { '=' }, 2);
                    if (kv.Length != 2) continue;
                    if (kv[0] == "provider")
                    {
                        if (Providers.ContainsKey(kv[1])) selectedProvider = kv[1];
                        else if (kv[1] == "Custom") selectedProvider = "Custom";
                    }
                    else if (kv[0] == "custom1") custom1 = kv[1];
                    else if (kv[0] == "custom2") custom2 = kv[1];
                    else if (kv[0] == "customDoh") customDoh = kv[1];
                }
            }
            catch { }
        }

        static bool IsAdministrator()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        static bool IsAuthorizedDevice()
        {
            try
            {
                foreach (var mac in CollectLocalMacs())
                {
                    if (MacIsAllowed(mac)) return true;
                }
            }
            catch { }
            return false;
        }

        static bool MacIsAllowed(byte[] mac)
        {
            if (mac == null || mac.Length < 6) return false;
            foreach (var allowed in AllowedMacs)
            {
                if (allowed.Length == 6 &&
                    mac[0] == allowed[0] && mac[1] == allowed[1] && mac[2] == allowed[2] &&
                    mac[3] == allowed[3] && mac[4] == allowed[4] && mac[5] == allowed[5])
                    return true;
            }
            return false;
        }

        static byte[] ParseMacBytes(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;

            for (int i = 0; i < raw.Length; i++)
            {
                int pos = i;
                var bytes = new byte[6];
                bool ok = true;
                for (int b = 0; b < 6; b++)
                {
                    if (pos + 1 >= raw.Length || !IsHexChar(raw[pos]) || !IsHexChar(raw[pos + 1]))
                    {
                        ok = false;
                        break;
                    }
                    bytes[b] = Convert.ToByte(raw.Substring(pos, 2), 16);
                    pos += 2;
                    if (b < 5)
                    {
                        if (pos >= raw.Length)
                        {
                            ok = false;
                            break;
                        }
                        char sep = raw[pos];
                        if (sep != ':' && sep != '-' && sep != '.')
                        {
                            ok = false;
                            break;
                        }
                        pos++;
                    }
                }
                if (ok) return bytes;
            }
            return null;
        }

        static bool IsHexChar(char c)
        {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }

        static void AddMac(List<byte[]> list, byte[] mac)
        {
            if (mac == null || mac.Length < 6) return;
            if (mac.All(b => b == 0)) return;
            foreach (var existing in list)
            {
                if (existing.Length >= 6 &&
                    existing[0] == mac[0] && existing[1] == mac[1] && existing[2] == mac[2] &&
                    existing[3] == mac[3] && existing[4] == mac[4] && existing[5] == mac[5])
                    return;
            }
            list.Add(mac);
        }

        static List<byte[]> CollectLocalMacs()
        {
            var list = new List<byte[]>();

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    var pa = nic.GetPhysicalAddress();
                    if (pa != null) AddMac(list, pa.GetAddressBytes());
                }
                catch { }
            }

            try
            {
                RunProcess("getmac", "/fo csv /nh", out string gm, 4000);
                foreach (var line in gm.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    AddMac(list, ParseMacBytes(line));
            }
            catch { }

            try
            {
                RunProcess("arp", "-a", out string arp, 4000);
                foreach (var line in arp.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    AddMac(list, ParseMacBytes(line));
            }
            catch { }

            try
            {
                RunProcess("netsh", "wlan show interfaces", out string wlan, 4000);
                foreach (var line in wlan.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.IndexOf("BSSID", StringComparison.OrdinalIgnoreCase) >= 0)
                        AddMac(list, ParseMacBytes(line));
                }
            }
            catch { }

            return list;
        }

        static void ShowUnauthorized()
        {
            try
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("  Cihaz doğrulaması başarısız. Bu kopya bu donanımda çalıştırılamaz.");
                Console.ForegroundColor = ConsoleColor.White;
            }
            catch { }

            MessageBoxW(IntPtr.Zero,
                "Bu kopya bu cihazda çalıştırılamaz.\n\nDonanım doğrulaması başarısız.",
                "Yetkisiz Cihaz",
                0x00000010 | 0x00040000);
        }

        static void ShowAdminRequired()
        {
            // Native Windows message box (no console output), error icon, topmost.
            MessageBoxW(IntPtr.Zero,
                "Bu program ağ ayarlarını değiştirebilmek için yönetici yetkisi gerektirir.\n\n" +
                "Lütfen \"DNS Bypass.exe\" dosyasına sağ tıklayıp\n" +
                "\"Yönetici olarak çalıştır\" seçeneğiyle başlatın.",
                "Yönetici Gerekli",
                0x00000010 | 0x00040000); // MB_ICONERROR | MB_TOPMOST
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern int SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);

        [DllImport("user32.dll")]
        static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_LAYERED = 0x80000;
        private const int LWA_ALPHA = 0x2;

        static bool ContainsAny(string s, params string[] needles)
        {
            return needles.Any(n => s.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        static void SetConsoleTransparency(byte alpha)
        {
            try
            {
                IntPtr hwnd = GetConsoleWindow();
                if (hwnd != IntPtr.Zero)
                {
                    int extendedStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
                    SetWindowLong(hwnd, GWL_EXSTYLE, extendedStyle | WS_EX_LAYERED);
                    SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA);
                }
            }
            catch
            {
                // Silently fail if transparency not supported
            }
        }

        static void SetColor(ConsoleColor c)
        {
            Console.ForegroundColor = c;
        }

        static void PrintHeader()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine(@"
          ██████╗ ███╗   ██╗███████╗    ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
          ██╔══██╗████╗  ██║██╔════╝    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
          ██║  ██║██╔██╗ ██║███████╗    ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
          ██║  ██║██║╚██╗██║╚════██║    ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
          ██████╔╝██║ ╚████║███████║    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
          ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                                            v2.5
");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("DNS Bypass & Assessment Tool\n");
        }

        static void Log(string type, string message)
        {
            string time = DateTime.Now.ToString("HH:mm:ss");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  [" + time + "] ");

            switch (type)
            {
                case "ERROR":
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case "SUCCESS":
                    Console.ForegroundColor = ConsoleColor.Green;
                    break;
                case "WARN":
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case "INFO":
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.White;
                    break;
            }

            Console.WriteLine("[" + type + "] " + message);
            Console.ForegroundColor = ConsoleColor.White;
        }
    }
}
