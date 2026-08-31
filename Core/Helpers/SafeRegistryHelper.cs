using System;
using System.Linq;
using Microsoft.Win32;
using DnsAdvancedBypass.Core.Interfaces;

namespace DnsAdvancedBypass.Core.Helpers
{
    /// <summary>
    /// Thread-safe Windows Registry operations with comprehensive error handling.
    /// Implements IRegistryManager for dependency injection and testability.
    /// </summary>
    public class SafeRegistryHelper : IRegistryManager
    {
        private readonly ILogger _logger;
        private static readonly object _registryLock = new object();

        public SafeRegistryHelper(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public int ReadDword(string keyPath, string valueName, int defaultValue)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                    {
                        if (key == null)
                        {
                            _logger.Debug($"Registry key not found: {keyPath}");
                            return defaultValue;
                        }

                        var value = key.GetValue(valueName);
                        if (value == null)
                        {
                            _logger.Debug($"Registry value not found: {keyPath}\\{valueName}");
                            return defaultValue;
                        }

                        if (value is int intValue)
                            return intValue;

                        if (int.TryParse(value.ToString(), out int parsed))
                            return parsed;

                        _logger.Warn($"Registry value type mismatch: {keyPath}\\{valueName} (expected DWORD)");
                        return defaultValue;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry access denied: {keyPath}\\{valueName}", ex);
                    return defaultValue;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry read failed: {keyPath}\\{valueName}", ex);
                    return defaultValue;
                }
            }
        }

        public bool WriteDword(string keyPath, string valueName, int value)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.CreateSubKey(keyPath, true))
                    {
                        if (key == null)
                        {
                            _logger.Error($"Failed to create/open registry key: {keyPath}");
                            return false;
                        }

                        key.SetValue(valueName, value, RegistryValueKind.DWord);
                        _logger.Debug($"Registry DWORD written: {keyPath}\\{valueName} = {value}");
                        return true;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry write access denied: {keyPath}\\{valueName}", ex);
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry write failed: {keyPath}\\{valueName}", ex);
                    return false;
                }
            }
        }

        public string ReadString(string keyPath, string valueName, string defaultValue = null)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                    {
                        if (key == null)
                            return defaultValue;

                        var value = key.GetValue(valueName);
                        return value?.ToString() ?? defaultValue;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry access denied: {keyPath}\\{valueName}", ex);
                    return defaultValue;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry read failed: {keyPath}\\{valueName}", ex);
                    return defaultValue;
                }
            }
        }

        public bool WriteString(string keyPath, string valueName, string value)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.CreateSubKey(keyPath, true))
                    {
                        if (key == null)
                        {
                            _logger.Error($"Failed to create/open registry key: {keyPath}");
                            return false;
                        }

                        key.SetValue(valueName, value ?? "", RegistryValueKind.String);
                        _logger.Debug($"Registry string written: {keyPath}\\{valueName}");
                        return true;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry write access denied: {keyPath}\\{valueName}", ex);
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry write failed: {keyPath}\\{valueName}", ex);
                    return false;
                }
            }
        }

        public bool DeleteValue(string keyPath, string valueName, bool throwOnMissing = false)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, true))
                    {
                        if (key == null)
                        {
                            if (throwOnMissing)
                                throw new InvalidOperationException($"Registry key not found: {keyPath}");
                            return true; // Key doesn't exist, value implicitly deleted
                        }

                        key.DeleteValue(valueName, !throwOnMissing);
                        _logger.Debug($"Registry value deleted: {keyPath}\\{valueName}");
                        return true;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry delete access denied: {keyPath}\\{valueName}", ex);
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry delete failed: {keyPath}\\{valueName}", ex);
                    return false;
                }
            }
        }

        public bool KeyExists(string keyPath)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                    {
                        return key != null;
                    }
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool ValueExists(string keyPath, string valueName)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                    {
                        if (key == null)
                            return false;

                        return key.GetValue(valueName) != null;
                    }
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool CreateKey(string keyPath)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.CreateSubKey(keyPath, true))
                    {
                        if (key == null)
                        {
                            _logger.Error($"Failed to create registry key: {keyPath}");
                            return false;
                        }
                        _logger.Debug($"Registry key created: {keyPath}");
                        return true;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry create access denied: {keyPath}", ex);
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry create failed: {keyPath}", ex);
                    return false;
                }
            }
        }

        public string[] EnumerateSubKeys(string keyPath)
        {
            lock (_registryLock)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath, false))
                    {
                        if (key == null)
                        {
                            _logger.Debug($"Registry key not found for enumeration: {keyPath}");
                            return Array.Empty<string>();
                        }

                        var subKeys = key.GetSubKeyNames();
                        _logger.Debug($"Enumerated {subKeys.Length} subkeys under: {keyPath}");
                        return subKeys;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.Error($"Registry enumerate access denied: {keyPath}", ex);
                    return Array.Empty<string>();
                }
                catch (Exception ex)
                {
                    _logger.Error($"Registry enumerate failed: {keyPath}", ex);
                    return Array.Empty<string>();
                }
            }
        }
    }
}
