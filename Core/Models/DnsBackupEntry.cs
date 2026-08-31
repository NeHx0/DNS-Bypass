using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// One backup entry per adapter, keyed by the stable interface GUID.
    /// </summary>
    public class DnsBackupEntry
    {
        public string Name { get; set; } = "";
        public string Guid { get; set; } = "";
        public string Mode4 { get; set; } = "dhcp";
        public string Mode6 { get; set; } = "dhcp";
        public List<string> Dns4 { get; set; } = new List<string>();
        public List<string> Dns6 { get; set; } = new List<string>();
        public string DohTemplate { get; set; } = "";  // original registry value before we touched it
        public int EnableAutoDoh { get; set; } = -1;   // -1 = value did not exist originally
        public string NameServer4 { get; set; }        // original Tcpip NameServer (null = not captured)
        public string NameServer6 { get; set; }
    }
}
