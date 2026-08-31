using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Service for creating and managing system snapshots.
    /// Captures complete system state for backup/restore operations.
    /// </summary>
    public class BackupService : IBackupService
    {
        private readonly ILogger _logger;
        private readonly IRegistryManager _registry;
        private readonly string _backupDirectory;

        // Registry key paths
        private const string NetBtParamsBase = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
        private const string Tcpip6Params = @"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters";
        private const string DnsCacheParams = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string DnsClientPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        private const string NcsiParams = @"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet";
        private const string NcsiPolicy = @"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator";

        public BackupService(ILogger logger, IRegistryManager registry, string backupDirectory = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            
            // Default backup directory: AppData\DNS-Bypass\Backups
            _backupDirectory = backupDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DNS-Bypass", "Backups");

            // Ensure backup directory exists
            try
            {
                Directory.CreateDirectory(_backupDirectory);
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to create backup directory: {_backupDirectory}", ex);
            }
        }

        public async Task<SystemSnapshot> CreateSystemSnapshotAsync(string description = null)
        {
            return await Task.Run(() =>
            {
                try
                {
                    _logger.Info("Creating system snapshot...");

                    var snapshot = new SystemSnapshot
                    {
                        Description = description ?? "System snapshot",
                        Reason = string.IsNullOrEmpty(description) ? "manual" : "auto",
                        Timestamp = DateTime.Now
                    };

                    // Capture registry state
                    snapshot.Registry = CaptureRegistryState();
                    _logger.Debug($"Registry snapshot: {snapshot.Registry.NetBiosSettings.Count} NetBIOS entries");

                    // Capture DNS backup (using existing DnsBackup model)
                    snapshot.DnsBackup = CaptureDnsBackup();
                    _logger.Debug($"DNS snapshot: {snapshot.DnsBackup.Adapters.Count} adapters");

                    // Capture service states
                    snapshot.ServiceStates = CaptureServiceStates();
                    _logger.Debug($"Service snapshot: {snapshot.ServiceStates.Count} services");

                    _logger.Success($"Snapshot created: {snapshot.Id}");
                    return snapshot;
                }
                catch (Exception ex)
                {
                    _logger.Error("Failed to create system snapshot", ex);
                    return null;
                }
            });
        }

        public async Task<bool> SaveSnapshotAsync(SystemSnapshot snapshot, string filePath = null)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (snapshot == null)
                    {
                        _logger.Error("Cannot save null snapshot");
                        return false;
                    }

                    // Generate file path if not provided
                    if (string.IsNullOrEmpty(filePath))
                    {
                        string timestamp = snapshot.Timestamp.ToString("yyyyMMdd_HHmmss");
                        string filename = $"snapshot_{timestamp}_{snapshot.Id.Substring(0, 8)}.json";
                        filePath = Path.Combine(_backupDirectory, filename);
                    }

                    // Ensure directory exists
                    var dir = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(dir))
                        Directory.CreateDirectory(dir);

                    // Serialize to JSON with indentation
                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    };

                    string json = JsonSerializer.Serialize(snapshot, options);
                    File.WriteAllText(filePath, json);

                    _logger.Success($"Snapshot saved: {Path.GetFileName(filePath)} ({json.Length} bytes)");
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to save snapshot: {filePath}", ex);
                    return false;
                }
            });
        }

        public async Task<SystemSnapshot> LoadSnapshotAsync(string filePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (!File.Exists(filePath))
                    {
                        _logger.Error($"Snapshot file not found: {filePath}");
                        return null;
                    }

                    string json = File.ReadAllText(filePath);
                    var options = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    };

                    var snapshot = JsonSerializer.Deserialize<SystemSnapshot>(json, options);
                    _logger.Success($"Snapshot loaded: {Path.GetFileName(filePath)}");
                    return snapshot;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to load snapshot: {filePath}", ex);
                    return null;
                }
            });
        }

        public async Task<List<SnapshotInfo>> ListSnapshotsAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (!Directory.Exists(_backupDirectory))
                    {
                        _logger.Debug("Backup directory does not exist");
                        return new List<SnapshotInfo>();
                    }

                    var snapshots = new List<SnapshotInfo>();
                    var files = Directory.GetFiles(_backupDirectory, "snapshot_*.json");

                    foreach (var file in files)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            
                            // Try to read snapshot metadata
                            string json = File.ReadAllText(file);
                            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
                            var snapshot = JsonSerializer.Deserialize<SystemSnapshot>(json, options);

                            snapshots.Add(new SnapshotInfo
                            {
                                Id = snapshot?.Id ?? "unknown",
                                Timestamp = snapshot?.Timestamp ?? fileInfo.CreationTime,
                                Description = snapshot?.Description ?? "Unknown",
                                FilePath = file,
                                FileSizeBytes = fileInfo.Length,
                                Reason = snapshot?.Reason ?? "unknown"
                            });
                        }
                        catch
                        {
                            // Skip corrupted snapshots
                            _logger.Warn($"Skipping corrupted snapshot: {Path.GetFileName(file)}");
                        }
                    }

                    return snapshots.OrderByDescending(s => s.Timestamp).ToList();
                }
                catch (Exception ex)
                {
                    _logger.Error("Failed to list snapshots", ex);
                    return new List<SnapshotInfo>();
                }
            });
        }

        public async Task<SystemSnapshot> GetLatestSnapshotAsync()
        {
            var snapshots = await ListSnapshotsAsync();
            if (snapshots.Count == 0)
                return null;

            var latest = snapshots.First();
            return await LoadSnapshotAsync(latest.FilePath);
        }

        public async Task<bool> DeleteSnapshotAsync(string filePath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                        _logger.Success($"Snapshot deleted: {Path.GetFileName(filePath)}");
                        return true;
                    }
                    else
                    {
                        _logger.Warn($"Snapshot file not found: {filePath}");
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to delete snapshot: {filePath}", ex);
                    return false;
                }
            });
        }

        public async Task<ValidationResult> ValidateSnapshotAsync(SystemSnapshot snapshot)
        {
            return await Task.Run(() =>
            {
                var result = ValidationResult.Valid();

                if (snapshot == null)
                {
                    result.AddError("Snapshot is null");
                    return result;
                }

                // Version check
                if (snapshot.Version < 1 || snapshot.Version > 2)
                {
                    result.AddWarning($"Snapshot version {snapshot.Version} may not be fully compatible");
                }

                // Computer name check
                if (!snapshot.ComputerName.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                {
                    result.AddWarning($"Snapshot was created on different computer: {snapshot.ComputerName}");
                }

                // Windows version check
                if (snapshot.WindowsVersion != Environment.OSVersion.ToString())
                {
                    result.AddWarning("Snapshot was created on different Windows version");
                }

                // Data validation
                if (snapshot.Registry == null)
                {
                    result.AddError("Registry snapshot is missing");
                }

                if (snapshot.DnsBackup == null)
                {
                    result.AddError("DNS backup is missing");
                }

                _logger.Debug($"Snapshot validation: {result.Errors.Count} errors, {result.Warnings.Count} warnings");
                return result;
            });
        }

        // ---------------------------------------------------------------- Private Methods

        private RegistrySnapshot CaptureRegistryState()
        {
            var snapshot = new RegistrySnapshot();

            // 1. NetBIOS settings
            if (_registry.KeyExists(NetBtParamsBase))
            {
                var subKeys = _registry.EnumerateSubKeys(NetBtParamsBase);
                foreach (var subKey in subKeys)
                {
                    string keyPath = $"{NetBtParamsBase}\\{subKey}";
                    int value = _registry.ReadDword(keyPath, "NetbiosOptions", -1);
                    if (value != -1)
                        snapshot.NetBiosSettings[$"{keyPath}\\NetbiosOptions"] = value;
                }
            }

            // 2. IPv6 settings
            snapshot.IPv6Settings[$"{Tcpip6Params}\\DisabledComponents"] =
                _registry.ReadDword(Tcpip6Params, "DisabledComponents", 0);

            // 3. DNS cache settings
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\NegativeCacheTime"] =
                _registry.ReadDword(DnsCacheParams, "NegativeCacheTime", 900);
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\MaxCacheTtl"] =
                _registry.ReadDword(DnsCacheParams, "MaxCacheTtl", 86400);
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\MaxCacheEntryTtlLimit"] =
                _registry.ReadDword(DnsCacheParams, "MaxCacheEntryTtlLimit", 86400);
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\NegativeSOACacheTime"] =
                _registry.ReadDword(DnsCacheParams, "NegativeSOACacheTime", 300);
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\EnableAutoDoh"] =
                _registry.ReadDword(DnsCacheParams, "EnableAutoDoh", 0);
            snapshot.DnsCacheSettings[$"{DnsCacheParams}\\DisableParallelAandAAAA"] =
                _registry.ReadDword(DnsCacheParams, "DisableParallelAandAAAA", 0);

            // 4. DNS client settings
            snapshot.DnsClientSettings[$"{DnsClientPolicy}\\DisableSmartNameResolution"] =
                _registry.ReadDword(DnsClientPolicy, "DisableSmartNameResolution", 0);
            snapshot.DnsClientSettings[$"{DnsClientPolicy}\\EnableMulticast"] =
                _registry.ReadDword(DnsClientPolicy, "EnableMulticast", 1);
            snapshot.DnsClientSettings[$"{DnsClientPolicy}\\DisableSmartProtocolReordering"] =
                _registry.ReadDword(DnsClientPolicy, "DisableSmartProtocolReordering", 0);

            // 5. NCSI settings
            snapshot.NcsiSettings[$"{NcsiParams}\\EnableActiveProbing"] =
                _registry.ReadDword(NcsiParams, "EnableActiveProbing", 1);
            snapshot.NcsiSettings[$"{NcsiParams}\\EnablePassivePolling"] =
                _registry.ReadDword(NcsiParams, "EnablePassivePolling", 1);
            snapshot.NcsiSettings[$"{NcsiPolicy}\\NoActiveProbe"] =
                _registry.ReadDword(NcsiPolicy, "NoActiveProbe", 0);

            return snapshot;
        }

        private DnsBackup CaptureDnsBackup()
        {
            // TODO: Integrate with existing DNS backup logic from Program.cs
            // For now, return empty backup
            return new DnsBackup
            {
                Provider = "Current",
                CreatedAt = DateTime.Now.ToString("s"),
                GlobalCaptured = false
            };
        }

        private Dictionary<string, string> CaptureServiceStates()
        {
            var states = new Dictionary<string, string>();
            
            // Capture Dnscache service state
            try
            {
                // TODO: Use ProcessHelper or ServiceController to get service state
                states["Dnscache"] = "Unknown";
            }
            catch
            {
                states["Dnscache"] = "Error";
            }

            return states;
        }
    }
}
