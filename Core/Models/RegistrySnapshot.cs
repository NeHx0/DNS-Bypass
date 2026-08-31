using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Snapshot of registry values for hardening-related keys.
    /// Organized by category for easy restore.
    /// </summary>
    public class RegistrySnapshot
    {
        /// <summary>
        /// NetBIOS over TCP/IP settings (per network adapter).
        /// Key format: "Tcpip\\{GUID}\\NetbiosOptions" → value (int)
        /// </summary>
        public Dictionary<string, int> NetBiosSettings { get; set; } = new Dictionary<string, int>();

        /// <summary>
        /// IPv6 transition technology settings.
        /// Key format: "TCPIP6\\Parameters\\DisabledComponents" → value (int)
        /// </summary>
        public Dictionary<string, int> IPv6Settings { get; set; } = new Dictionary<string, int>();

        /// <summary>
        /// DNS cache settings.
        /// Key format: "Dnscache\\Parameters\\NegativeCacheTime" → value (int)
        /// </summary>
        public Dictionary<string, int> DnsCacheSettings { get; set; } = new Dictionary<string, int>();

        /// <summary>
        /// DNS client policy settings.
        /// Key format: "DNSClient\\EnableMulticast" → value (int)
        /// </summary>
        public Dictionary<string, int> DnsClientSettings { get; set; } = new Dictionary<string, int>();

        /// <summary>
        /// NCSI (Network Connectivity Status Indicator) settings.
        /// Key format: "NlaSvc\\Parameters\\Internet\\EnableActiveProbing" → value (int)
        /// </summary>
        public Dictionary<string, int> NcsiSettings { get; set; } = new Dictionary<string, int>();

        /// <summary>
        /// Generic registry values (for extensibility).
        /// Full key path → RegistryValue
        /// </summary>
        public Dictionary<string, RegistryValue> AdditionalValues { get; set; } = new Dictionary<string, RegistryValue>();
    }

    /// <summary>
    /// Represents a single registry value with metadata.
    /// </summary>
    public class RegistryValue
    {
        /// <summary>
        /// Value name within the key.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Registry value type (DWORD, String, etc.).
        /// </summary>
        public RegistryValueType Type { get; set; }

        /// <summary>
        /// Value data (stored as string, cast on restore).
        /// </summary>
        public string Data { get; set; }

        /// <summary>
        /// Was this value present before? (null = didn't exist)
        /// </summary>
        public bool? ExistedBefore { get; set; }
    }

    /// <summary>
    /// Registry value types.
    /// </summary>
    public enum RegistryValueType
    {
        DWord,
        String,
        MultiString,
        Binary,
        QWord
    }
}
