using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Service for restoring system state from snapshots.
    /// Handles registry, DNS, and service restoration with validation.
    /// </summary>
    public interface IRestoreService
    {
        /// <summary>
        /// Restores system state from a snapshot.
        /// </summary>
        /// <param name="snapshot">Snapshot to restore from</param>
        /// <param name="dryRun">If true, simulates restore without applying changes</param>
        /// <returns>Restore result with success status and details</returns>
        Task<RestoreResult> RestoreFromSnapshotAsync(SystemSnapshot snapshot, bool dryRun = false);

        /// <summary>
        /// Restores only registry settings from snapshot.
        /// </summary>
        /// <param name="snapshot">Snapshot containing registry data</param>
        /// <returns>True if successful</returns>
        Task<bool> RestoreRegistryAsync(SystemSnapshot snapshot);

        /// <summary>
        /// Restores only DNS settings from snapshot.
        /// </summary>
        /// <param name="snapshot">Snapshot containing DNS backup</param>
        /// <returns>True if successful</returns>
        Task<bool> RestoreDnsAsync(SystemSnapshot snapshot);

        /// <summary>
        /// Restores only service states from snapshot.
        /// </summary>
        /// <param name="snapshot">Snapshot containing service states</param>
        /// <returns>True if successful</returns>
        Task<bool> RestoreServicesAsync(SystemSnapshot snapshot);

        /// <summary>
        /// Performs a dry-run restore to check what would be changed.
        /// </summary>
        /// <param name="snapshot">Snapshot to simulate</param>
        /// <returns>Report of changes that would be made</returns>
        Task<RestoreReport> DryRunAsync(SystemSnapshot snapshot);

        /// <summary>
        /// Reverts the most recent hardening operation.
        /// </summary>
        /// <returns>Restore result</returns>
        Task<RestoreResult> RevertLastHardeningAsync();
    }
}
