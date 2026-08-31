using System;
using Microsoft.Win32;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Thread-safe Windows Registry operations with error handling.
    /// </summary>
    public interface IRegistryManager
    {
        /// <summary>
        /// Reads a DWORD value from the registry.
        /// </summary>
        /// <param name="keyPath">Registry key path (e.g., SYSTEM\CurrentControlSet\Services\...)</param>
        /// <param name="valueName">Name of the value to read</param>
        /// <param name="defaultValue">Value to return if key/value doesn't exist</param>
        /// <returns>The DWORD value or defaultValue if not found</returns>
        int ReadDword(string keyPath, string valueName, int defaultValue);

        /// <summary>
        /// Writes a DWORD value to the registry.
        /// </summary>
        /// <param name="keyPath">Registry key path</param>
        /// <param name="valueName">Name of the value to write</param>
        /// <param name="value">Value to write</param>
        /// <returns>True if successful, false otherwise</returns>
        bool WriteDword(string keyPath, string valueName, int value);

        /// <summary>
        /// Reads a string value from the registry.
        /// </summary>
        string ReadString(string keyPath, string valueName, string defaultValue = null);

        /// <summary>
        /// Writes a string value to the registry.
        /// </summary>
        bool WriteString(string keyPath, string valueName, string value);

        /// <summary>
        /// Deletes a value from the registry.
        /// </summary>
        /// <param name="keyPath">Registry key path</param>
        /// <param name="valueName">Name of the value to delete</param>
        /// <param name="throwOnMissing">If true, throws exception if value doesn't exist</param>
        /// <returns>True if deleted or didn't exist, false on error</returns>
        bool DeleteValue(string keyPath, string valueName, bool throwOnMissing = false);

        /// <summary>
        /// Checks if a registry key exists.
        /// </summary>
        bool KeyExists(string keyPath);

        /// <summary>
        /// Checks if a registry value exists.
        /// </summary>
        bool ValueExists(string keyPath, string valueName);

        /// <summary>
        /// Creates a registry key if it doesn't exist.
        /// </summary>
        bool CreateKey(string keyPath);

        /// <summary>
        /// Enumerates all subkey names under a registry key.
        /// </summary>
        string[] EnumerateSubKeys(string keyPath);
    }
}
