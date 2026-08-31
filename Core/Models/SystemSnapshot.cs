using System;
using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Complete system state snapshot for backup/restore.
    /// Contains registry, DNS, and service states.
    /// </summary>
    public class SystemSnapshot
    {
        /// <summary>
        /// Snapshot format version for compatibility checking.
        /// </summary>
        public int Version { get; set; } = 2;

        /// <summary>
        /// Timestamp when snapshot was created.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.Now;

        /// <summary>
        /// User-provided description of this snapshot.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Unique identifier for this snapshot.
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Registry state snapshot.
        /// </summary>
        public RegistrySnapshot Registry { get; set; } = new RegistrySnapshot();

        /// <summary>
        /// DNS backup (adapter-specific DNS settings).
        /// </summary>
        public DnsBackup DnsBackup { get; set; } = new DnsBackup();

        /// <summary>
        /// Windows service states (e.g., Dnscache running status).
        /// </summary>
        public Dictionary<string, string> ServiceStates { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Computer name (for validation during restore).
        /// </summary>
        public string ComputerName { get; set; } = Environment.MachineName;

        /// <summary>
        /// Windows version (for compatibility warnings).
        /// </summary>
        public string WindowsVersion { get; set; } = Environment.OSVersion.ToString();

        /// <summary>
        /// Snapshot creation reason (e.g., "pre-hardening", "manual-backup").
        /// </summary>
        public string Reason { get; set; }
    }

    /// <summary>
    /// Metadata about a snapshot (for listing).
    /// </summary>
    public class SnapshotInfo
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string Description { get; set; }
        public string FilePath { get; set; }
        public long FileSizeBytes { get; set; }
        public string Reason { get; set; }
    }
}
