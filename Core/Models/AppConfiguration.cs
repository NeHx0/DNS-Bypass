using System;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Application configuration (JSON-based, replaces settings.ini).
    /// </summary>
    public class AppConfiguration
    {
        /// <summary>
        /// Configuration version for migration support.
        /// </summary>
        public int Version { get; set; } = 1;

        /// <summary>
        /// Active DNS provider name.
        /// </summary>
        public string ActiveProvider { get; set; } = "Cloudflare";

        /// <summary>
        /// Custom DNS configuration (when ActiveProvider = "Custom").
        /// </summary>
        public CustomDnsConfig CustomDns { get; set; } = new CustomDnsConfig();

        /// <summary>
        /// Application behavior settings.
        /// </summary>
        public BehaviorSettings Behavior { get; set; } = new BehaviorSettings();

        /// <summary>
        /// Backup/restore settings.
        /// </summary>
        public BackupSettings Backup { get; set; } = new BackupSettings();

        /// <summary>
        /// CLI mode preferences.
        /// </summary>
        public CliSettings Cli { get; set; } = new CliSettings();

        /// <summary>
        /// Last updated timestamp.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.Now;
    }

    /// <summary>
    /// Custom DNS server configuration.
    /// </summary>
    public class CustomDnsConfig
    {
        public string Primary { get; set; } = "";
        public string Secondary { get; set; } = "";
        public string DohUrl { get; set; } = "";
    }

    /// <summary>
    /// Application behavior settings.
    /// </summary>
    public class BehaviorSettings
    {
        /// <summary>
        /// Auto-apply hardening when activating bypass.
        /// </summary>
        public bool AutoHardenOnActivate { get; set; } = false;

        /// <summary>
        /// Auto-backup before hardening.
        /// </summary>
        public bool AutoBackupBeforeHardening { get; set; } = true;

        /// <summary>
        /// Auto-revert on verification failure.
        /// </summary>
        public bool AutoRevertOnFailure { get; set; } = false;

        /// <summary>
        /// Enable debug logging.
        /// </summary>
        public bool DebugMode { get; set; } = false;

        /// <summary>
        /// Auto-open GitHub profile after success.
        /// </summary>
        public bool OpenGitHubAfterSuccess { get; set; } = true;
    }

    /// <summary>
    /// Backup/restore settings.
    /// </summary>
    public class BackupSettings
    {
        /// <summary>
        /// Max number of snapshots to keep (auto-cleanup).
        /// </summary>
        public int MaxSnapshots { get; set; } = 10;

        /// <summary>
        /// Auto-delete snapshots older than this (days).
        /// </summary>
        public int AutoDeleteAfterDays { get; set; } = 30;

        /// <summary>
        /// Backup directory (relative to AppData or absolute path).
        /// </summary>
        public string BackupDirectory { get; set; } = "Backups";
    }

    /// <summary>
    /// CLI mode settings.
    /// </summary>
    public class CliSettings
    {
        /// <summary>
        /// Default adapter selection mode in CLI.
        /// </summary>
        public string DefaultAdapterSelection { get; set; } = "auto"; // "auto", "prompt", "all"

        /// <summary>
        /// Verbose output in CLI mode.
        /// </summary>
        public bool Verbose { get; set; } = false;

        /// <summary>
        /// JSON output format for CLI (for scripting).
        /// </summary>
        public bool JsonOutput { get; set; } = false;
    }
}
