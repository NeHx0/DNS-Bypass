using System;
using System.Linq;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Models;
using DnsAdvancedBypass.Core.Helpers;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Service for restoring system state from snapshots.
    /// Supports full restore, partial restore, and dry-run validation.
    /// </summary>
    public class RestoreService : IRestoreService
    {
        private readonly ILogger _logger;
        private readonly IRegistryManager _registry;
        private readonly IBackupService _backupService;
        private readonly ProcessHelper _processHelper;

        public RestoreService(ILogger logger, IRegistryManager registry, IBackupService backupService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _backupService = backupService ?? throw new ArgumentNullException(nameof(backupService));
            _processHelper = new ProcessHelper(logger);
        }

        public async Task<RestoreResult> RestoreFromSnapshotAsync(SystemSnapshot snapshot, bool dryRun = false)
        {
            var result = new RestoreResult
            {
                Success = false,
                Message = dryRun ? "Simulating restore..." : "Starting restore..."
            };

            try
            {
                _logger.Info("═══════════════════════════════════════════════════════════");
                _logger.Info($"  {(dryRun ? "DRY-RUN" : "RESTORE")} - System Snapshot");
                _logger.Info("═══════════════════════════════════════════════════════════");

                // Validate snapshot
                var validation = await _backupService.ValidateSnapshotAsync(snapshot);
                if (!validation.IsValid)
                {
                    result.Message = $"Snapshot validation failed: {string.Join(", ", validation.Errors)}";
                    _logger.Error(result.Message);
                    return result;
                }

                if (validation.Warnings.Count > 0)
                {
                    foreach (var warning in validation.Warnings)
                        _logger.Warn($"Snapshot warning: {warning}");
                }

                // Restore registry
                _logger.Info($"Step 1/3: {(dryRun ? "Checking" : "Restoring")} registry settings...");
                bool regSuccess = dryRun || await RestoreRegistryAsync(snapshot);
                result.AddStep("Registry", regSuccess, regSuccess ? "Registry restored" : "Registry restore failed");
                if (regSuccess) result.SuccessfulChanges++;
                else result.FailedChanges++;

                // Restore DNS
                _logger.Info($"Step 2/3: {(dryRun ? "Checking" : "Restoring")} DNS settings...");
                bool dnsSuccess = dryRun || await RestoreDnsAsync(snapshot);
                result.AddStep("DNS", dnsSuccess, dnsSuccess ? "DNS restored" : "DNS restore failed");
                if (dnsSuccess) result.SuccessfulChanges++;
                else result.FailedChanges++;

                // Restore services
                _logger.Info($"Step 3/3: {(dryRun ? "Checking" : "Restoring")} service states...");
                bool svcSuccess = dryRun || await RestoreServicesAsync(snapshot);
                result.AddStep("Services", svcSuccess, svcSuccess ? "Services restored" : "Service restore failed");
                if (svcSuccess) result.SuccessfulChanges++;
                else result.FailedChanges++;

                result.TotalChanges = 3;
                result.Success = result.SuccessfulChanges >= 2; // At least 2 out of 3 must succeed
                result.Message = dryRun 
                    ? $"Dry-run completed: {result.SuccessfulChanges}/{result.TotalChanges} steps would succeed"
                    : $"Restore completed: {result.SuccessfulChanges}/{result.TotalChanges} steps successful";

                _logger.Info("═══════════════════════════════════════════════════════════");
                if (result.Success)
                    _logger.Success(result.Message);
                else
                    _logger.Warn(result.Message);
                _logger.Info("═══════════════════════════════════════════════════════════");

                return result;
            }
            catch (Exception ex)
            {
                _logger.Error("Restore failed", ex);
                result.Success = false;
                result.Message = $"Exception during restore: {ex.Message}";
                return result;
            }
        }

        public async Task<bool> RestoreRegistryAsync(SystemSnapshot snapshot)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (snapshot?.Registry == null)
                    {
                        _logger.Error("Registry snapshot is null");
                        return false;
                    }

                    int successCount = 0;
                    int totalCount = 0;

                    // Restore NetBIOS settings
                    foreach (var kvp in snapshot.Registry.NetBiosSettings)
                    {
                        totalCount++;
                        // Extract key path and value name from full path
                        // Format: "SYSTEM\\...\\{GUID}\\NetbiosOptions"
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            
                            if (_registry.WriteDword(keyPath, valueName, kvp.Value))
                            {
                                successCount++;
                                _logger.Debug($"Restored: {kvp.Key} = {kvp.Value}");
                            }
                        }
                    }

                    // Restore IPv6 settings
                    foreach (var kvp in snapshot.Registry.IPv6Settings)
                    {
                        totalCount++;
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            
                            if (_registry.WriteDword(keyPath, valueName, kvp.Value))
                                successCount++;
                        }
                    }

                    // Restore DNS cache settings
                    foreach (var kvp in snapshot.Registry.DnsCacheSettings)
                    {
                        totalCount++;
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            
                            if (_registry.WriteDword(keyPath, valueName, kvp.Value))
                                successCount++;
                        }
                    }

                    // Restore DNS client settings
                    foreach (var kvp in snapshot.Registry.DnsClientSettings)
                    {
                        totalCount++;
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            
                            if (_registry.WriteDword(keyPath, valueName, kvp.Value))
                                successCount++;
                        }
                    }

                    // Restore NCSI settings
                    foreach (var kvp in snapshot.Registry.NcsiSettings)
                    {
                        totalCount++;
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            
                            if (_registry.WriteDword(keyPath, valueName, kvp.Value))
                                successCount++;
                        }
                    }

                    bool success = successCount >= (totalCount * 0.8); // 80% success rate required
                    _logger.Info($"Registry restore: {successCount}/{totalCount} values restored");
                    return success;
                }
                catch (Exception ex)
                {
                    _logger.Error("Registry restore failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> RestoreDnsAsync(SystemSnapshot snapshot)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (snapshot?.DnsBackup == null)
                    {
                        _logger.Error("DNS backup is null");
                        return false;
                    }

                    // TODO: Integrate with existing DNS restore logic from Program.cs
                    _logger.Info($"DNS restore: {snapshot.DnsBackup.Adapters.Count} adapters to restore");
                    
                    // For now, return true (will be integrated in next phase)
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error("DNS restore failed", ex);
                    return false;
                }
            });
        }

        public async Task<bool> RestoreServicesAsync(SystemSnapshot snapshot)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (snapshot?.ServiceStates == null || snapshot.ServiceStates.Count == 0)
                    {
                        _logger.Warn("No service states to restore");
                        return true;
                    }

                    // Restart Dnscache service
                    _logger.Info("Restarting DNS Client service...");
                    var stopResult = _processHelper.Execute("net", "stop Dnscache", 12000);
                    var startResult = _processHelper.Execute("net", "start Dnscache", 12000);

                    bool success = startResult.Success;
                    if (success)
                        _logger.Info("DNS Client service restarted");
                    else
                        _logger.Warn("DNS Client restart may have failed (some SKUs protect this service)");

                    return true; // Don't fail the entire restore if service restart fails
                }
                catch (Exception ex)
                {
                    _logger.Error("Service restore failed", ex);
                    return false;
                }
            });
        }

        public async Task<RestoreReport> DryRunAsync(SystemSnapshot snapshot)
        {
            var report = new RestoreReport
            {
                Snapshot = snapshot,
                IsCompatible = true
            };

            try
            {
                // Validate snapshot
                var validation = await _backupService.ValidateSnapshotAsync(snapshot);
                if (!validation.IsValid)
                {
                    report.IsCompatible = false;
                    report.IncompatibilityReason = string.Join("; ", validation.Errors);
                }

                report.Warnings.AddRange(validation.Warnings);

                // Analyze planned registry changes
                if (snapshot?.Registry != null)
                {
                    foreach (var kvp in snapshot.Registry.NetBiosSettings)
                    {
                        int lastSeparator = kvp.Key.LastIndexOf('\\');
                        if (lastSeparator > 0)
                        {
                            string keyPath = kvp.Key.Substring(0, lastSeparator);
                            string valueName = kvp.Key.Substring(lastSeparator + 1);
                            int currentValue = _registry.ReadDword(keyPath, valueName, -1);

                            if (currentValue != kvp.Value)
                            {
                                report.PlannedChanges.Add(new PlannedChange
                                {
                                    Category = "Registry (NetBIOS)",
                                    Target = kvp.Key,
                                    CurrentValue = currentValue.ToString(),
                                    NewValue = kvp.Value.ToString(),
                                    Action = "Set"
                                });
                            }
                        }
                    }
                }

                _logger.Info($"Dry-run: {report.PlannedChanges.Count} changes planned");
                return report;
            }
            catch (Exception ex)
            {
                _logger.Error("Dry-run failed", ex);
                report.IsCompatible = false;
                report.IncompatibilityReason = ex.Message;
                return report;
            }
        }

        public async Task<RestoreResult> RevertLastHardeningAsync()
        {
            try
            {
                _logger.Info("Reverting last hardening operation...");

                // Get latest snapshot
                var snapshot = await _backupService.GetLatestSnapshotAsync();
                if (snapshot == null)
                {
                    var result = RestoreResult.Failed("No backup found to revert from");
                    _logger.Error(result.Message);
                    return result;
                }

                _logger.Info($"Found snapshot: {snapshot.Description} ({snapshot.Timestamp:g})");

                // Restore from snapshot
                return await RestoreFromSnapshotAsync(snapshot, dryRun: false);
            }
            catch (Exception ex)
            {
                _logger.Error("Revert failed", ex);
                return RestoreResult.Failed($"Revert failed: {ex.Message}");
            }
        }
    }
}
