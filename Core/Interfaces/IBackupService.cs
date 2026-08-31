using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Service for creating and managing system snapshots.
    /// Captures registry, DNS, and service states for backup/restore operations.
    /// </summary>
    public interface IBackupService
    {
        /// <summary>
        /// Creates a complete system snapshot (registry + DNS + services).
        /// </summary>
        /// <param name="description">Optional description for this snapshot</param>
        /// <returns>Complete system snapshot</returns>
        Task<SystemSnapshot> CreateSystemSnapshotAsync(string description = null);

        /// <summary>
        /// Saves a snapshot to disk as JSON.
        /// </summary>
        /// <param name="snapshot">Snapshot to save</param>
        /// <param name="filePath">Optional custom file path (default: auto-generated in AppData)</param>
        /// <returns>True if saved successfully</returns>
        Task<bool> SaveSnapshotAsync(SystemSnapshot snapshot, string filePath = null);

        /// <summary>
        /// Loads a snapshot from disk.
        /// </summary>
        /// <param name="filePath">Path to snapshot JSON file</param>
        /// <returns>Loaded snapshot or null on failure</returns>
        Task<SystemSnapshot> LoadSnapshotAsync(string filePath);

        /// <summary>
        /// Lists all available snapshots in the backup directory.
        /// </summary>
        /// <returns>List of snapshot metadata (timestamp, description, file path)</returns>
        Task<List<SnapshotInfo>> ListSnapshotsAsync();

        /// <summary>
        /// Gets the most recent snapshot.
        /// </summary>
        /// <returns>Latest snapshot or null if none exist</returns>
        Task<SystemSnapshot> GetLatestSnapshotAsync();

        /// <summary>
        /// Deletes a snapshot file.
        /// </summary>
        /// <param name="filePath">Path to snapshot file to delete</param>
        /// <returns>True if deleted successfully</returns>
        Task<bool> DeleteSnapshotAsync(string filePath);

        /// <summary>
        /// Validates that a snapshot is compatible with the current system.
        /// </summary>
        /// <param name="snapshot">Snapshot to validate</param>
        /// <returns>Validation result with warnings/errors</returns>
        Task<ValidationResult> ValidateSnapshotAsync(SystemSnapshot snapshot);
    }
}
