using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Service for managing application configuration (JSON-based).
    /// Replaces legacy settings.ini with structured JSON.
    /// </summary>
    public class ConfigurationService : IConfigurationService
    {
        private readonly ILogger _logger;
        private readonly string _configPath;
        private readonly string _legacyPath;
        private AppConfiguration _cachedConfig;

        public ConfigurationService(ILogger logger, string configDirectory = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            
            string appDataDir = configDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DNS-Bypass");

            Directory.CreateDirectory(appDataDir);
            
            _configPath = Path.Combine(appDataDir, "config.json");
            _legacyPath = Path.Combine(appDataDir, "settings.ini");
        }

        public async Task<AppConfiguration> LoadConfigurationAsync()
        {
            if (_cachedConfig != null)
                return _cachedConfig;

            return await Task.Run(() =>
            {
                try
                {
                    // Try loading JSON config
                    if (File.Exists(_configPath))
                    {
                        string json = File.ReadAllText(_configPath);
                        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
                        _cachedConfig = JsonSerializer.Deserialize<AppConfiguration>(json, options);
                        _logger.Debug("Configuration loaded from config.json");
                        return _cachedConfig;
                    }

                    // Try migrating from legacy settings.ini
                    if (File.Exists(_legacyPath))
                    {
                        _logger.Info("Migrating from legacy settings.ini...");
                        _cachedConfig = MigrateFromLegacy().Result;
                        SaveConfigurationAsync(_cachedConfig).Wait();
                        return _cachedConfig;
                    }

                    // Return defaults
                    _logger.Debug("Using default configuration");
                    _cachedConfig = new AppConfiguration();
                    return _cachedConfig;
                }
                catch (Exception ex)
                {
                    _logger.Error("Failed to load configuration, using defaults", ex);
                    _cachedConfig = new AppConfiguration();
                    return _cachedConfig;
                }
            });
        }

        public async Task<bool> SaveConfigurationAsync(AppConfiguration config)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (config == null)
                    {
                        _logger.Error("Cannot save null configuration");
                        return false;
                    }

                    config.LastUpdated = DateTime.Now;

                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    };

                    string json = JsonSerializer.Serialize(config, options);
                    File.WriteAllText(_configPath, json);

                    _cachedConfig = config;
                    _logger.Debug("Configuration saved");
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error("Failed to save configuration", ex);
                    return false;
                }
            });
        }

        public async Task<AppConfiguration> MigrateFromLegacyAsync()
        {
            return await MigrateFromLegacy();
        }

        private async Task<AppConfiguration> MigrateFromLegacy()
        {
            return await Task.Run(() =>
            {
                var config = new AppConfiguration();

                try
                {
                    if (!File.Exists(_legacyPath))
                        return config;

                    var lines = File.ReadAllLines(_legacyPath);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(new[] { '=' }, 2);
                        if (parts.Length != 2) continue;

                        string key = parts[0].Trim();
                        string value = parts[1].Trim();

                        switch (key.ToLowerInvariant())
                        {
                            case "provider":
                                config.ActiveProvider = value;
                                break;
                            case "custom1":
                                config.CustomDns.Primary = value;
                                break;
                            case "custom2":
                                config.CustomDns.Secondary = value;
                                break;
                            case "customdoh":
                                config.CustomDns.DohUrl = value;
                                break;
                        }
                    }

                    _logger.Success("Migrated from settings.ini");
                    
                    // Backup legacy file
                    try
                    {
                        File.Move(_legacyPath, _legacyPath + ".old");
                    }
                    catch { }

                    return config;
                }
                catch (Exception ex)
                {
                    _logger.Error("Migration from legacy settings failed", ex);
                    return config;
                }
            });
        }

        public string GetActiveProvider()
        {
            var config = LoadConfigurationAsync().Result;
            return config.ActiveProvider;
        }

        public async Task<bool> SetActiveProviderAsync(string providerName)
        {
            var config = await LoadConfigurationAsync();
            config.ActiveProvider = providerName;
            return await SaveConfigurationAsync(config);
        }

        public CustomDnsConfig GetCustomDns()
        {
            var config = LoadConfigurationAsync().Result;
            return config.CustomDns;
        }

        public async Task<bool> SetCustomDnsAsync(string primary, string secondary = null, string dohUrl = null)
        {
            var config = await LoadConfigurationAsync();
            config.CustomDns.Primary = primary ?? "";
            config.CustomDns.Secondary = secondary ?? "";
            config.CustomDns.DohUrl = dohUrl ?? "";
            config.ActiveProvider = "Custom";
            return await SaveConfigurationAsync(config);
        }

        public async Task<AppConfiguration> ResetToDefaultsAsync()
        {
            var config = new AppConfiguration();
            await SaveConfigurationAsync(config);
            _cachedConfig = config;
            _logger.Info("Configuration reset to defaults");
            return config;
        }

        public async Task<bool> ExportConfigurationAsync(string exportPath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var config = LoadConfigurationAsync().Result;
                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    };

                    string json = JsonSerializer.Serialize(config, options);
                    File.WriteAllText(exportPath, json);
                    
                    _logger.Success($"Configuration exported: {exportPath}");
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to export configuration: {exportPath}", ex);
                    return false;
                }
            });
        }

        public async Task<AppConfiguration> ImportConfigurationAsync(string importPath)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (!File.Exists(importPath))
                    {
                        _logger.Error($"Import file not found: {importPath}");
                        return null;
                    }

                    string json = File.ReadAllText(importPath);
                    var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
                    var config = JsonSerializer.Deserialize<AppConfiguration>(json, options);

                    SaveConfigurationAsync(config).Wait();
                    _cachedConfig = config;
                    
                    _logger.Success($"Configuration imported: {importPath}");
                    return config;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to import configuration: {importPath}", ex);
                    return null;
                }
            });
        }
    }
}
