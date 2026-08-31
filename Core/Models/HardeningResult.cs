using System;
using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Result of a hardening operation.
    /// </summary>
    public class HardeningResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public List<HardeningStep> Steps { get; set; } = new List<HardeningStep>();
        public DateTime Timestamp { get; set; } = DateTime.Now;

        public static HardeningResult Succeeded(string message)
        {
            return new HardeningResult { Success = true, Message = message };
        }

        public static HardeningResult Failed(string message)
        {
            return new HardeningResult { Success = false, Message = message };
        }

        public void AddStep(string name, bool success, string details = "")
        {
            Steps.Add(new HardeningStep
            {
                Name = name,
                Success = success,
                Details = details,
                Timestamp = DateTime.Now
            });
        }
    }

    /// <summary>
    /// Individual step in the hardening process.
    /// </summary>
    public class HardeningStep
    {
        public string Name { get; set; }
        public bool Success { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Current hardening status of the system.
    /// </summary>
    public class HardeningStatus
    {
        public bool NetBiosDisabled { get; set; }
        public bool IPv6TransitionsDisabled { get; set; }
        public bool DnsCacheOptimized { get; set; }
        public bool NCSIDisabled { get; set; }
        public bool DnsClientHardened { get; set; }

        public bool IsFullyHardened =>
            NetBiosDisabled &&
            IPv6TransitionsDisabled &&
            DnsCacheOptimized &&
            NCSIDisabled &&
            DnsClientHardened;

        public int GetHardeningPercentage()
        {
            int total = 5;
            int applied = 0;
            if (NetBiosDisabled) applied++;
            if (IPv6TransitionsDisabled) applied++;
            if (DnsCacheOptimized) applied++;
            if (NCSIDisabled) applied++;
            if (DnsClientHardened) applied++;
            return (applied * 100) / total;
        }
    }
}
