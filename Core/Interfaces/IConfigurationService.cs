using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Service for managing application configuration (JSON-based).
    /// Replaces legacy settings.ini with structured JSON configuration.
    /// </summary>
    public interface IConfigurationService
    {
        /// <summary>
        /// Loads configuration from disk (config.json).
        /// </summary>
        /// <returns>Application configuration or default if file doesn't exist</returns>
        Task<AppConfiguration> LoadConfigurationAsync();

        /// <summary>
        /// Saves configuration to disk (config.json).
        /// </summary>
        /// <param name="config">Configuration to save</param>
        /// <returns>True if saved successfully</returns>
        Task<bool> SaveConfigurationAsync(AppConfiguration config);

        /// <summary>
        /// Migrates legacy settings.ini to new config.json format.
        /// </summary>
        /// <returns>Migrated configuration or null if migration failed</returns>
        Task<AppConfiguration> MigrateFromLegacyAsync();

        /// <summary>
        /// Gets the active DNS provider.
        /// </summary>
        /// <returns>Provider name</returns>
        string GetActiveProvider();

        /// <summary>
        /// Sets the active DNS provider.
        /// </summary>
        /// <param name="providerName">Provider name (e.g., "Cloudflare")</param>
        /// <returns>True if set successfully</returns>
        Task<bool> SetActiveProviderAsync(string providerName);

        /// <summary>
        /// Gets custom DNS servers (if provider is "Custom").
        /// </summary>
        /// <returns>Custom DNS configuration</returns>
        CustomDnsConfig GetCustomDns();

        /// <summary>
        /// Sets custom DNS servers.
        /// </summary>
        /// <param name="primary">Primary DNS</param>
        /// <param name="secondary">Secondary DNS (optional)</param>
        /// <param name="dohUrl">DoH URL (optional)</param>
        /// <returns>True if set successfully</returns>
        Task<bool> SetCustomDnsAsync(string primary, string secondary = null, string dohUrl = null);

        /// <summary>
        /// Resets configuration to defaults.
        /// </summary>
        /// <returns>Default configuration</returns>
        Task<AppConfiguration> ResetToDefaultsAsync();

        /// <summary>
        /// Exports configuration to a file (for backup/sharing).
        /// </summary>
        /// <param name="exportPath">Path to export file</param>
        /// <returns>True if exported successfully</returns>
        Task<bool> ExportConfigurationAsync(string exportPath);

        /// <summary>
        /// Imports configuration from a file.
        /// </summary>
        /// <param name="importPath">Path to import file</param>
        /// <returns>Imported configuration or null on failure</returns>
        Task<AppConfiguration> ImportConfigurationAsync(string importPath);
    }
}
