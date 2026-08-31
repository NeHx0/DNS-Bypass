using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Complete DNS backup state (adapters + global settings).
    /// </summary>
    public class DnsBackup
    {
        public int Version { get; set; } = 3;
        public string Provider { get; set; } = "";
        public string CreatedAt { get; set; } = "";
        public List<DnsBackupEntry> Adapters { get; set; } = new List<DnsBackupEntry>();

        // Machine-wide DNS client state captured once, restored on full revert.
        public bool GlobalCaptured { get; set; }
        public int GlobalEnableAutoDoh { get; set; } = -1;
        public int DisableSmartNameResolution { get; set; } = -1;
        public int EnableMulticast { get; set; } = -1;
        public List<string> DohEncryptionAdded { get; set; } = new List<string>();
    }
}
