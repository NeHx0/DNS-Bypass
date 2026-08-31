using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Models;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Network hardening service to prevent DNS leaks and secure network stack.
    /// </summary>
    public interface INetworkHardener
    {
        /// <summary>
        /// Applies all hardening measures to the system.
        /// </summary>
        /// <returns>Result with success status and detailed messages</returns>
        Task<HardeningResult> ApplyFullHardeningAsync();

        /// <summary>
        /// Disables NetBIOS over TCP/IP on all network adapters.
        /// </summary>
        Task<bool> DisableNetBiosAsync();

        /// <summary>
        /// Disables IPv6 transition technologies (Teredo, ISATAP, 6to4).
        /// </summary>
        Task<bool> DisableIPv6TransitionsAsync();

        /// <summary>
        /// Optimizes DNS cache settings (negative TTL, max cache time).
        /// </summary>
        Task<bool> OptimizeDnsCacheAsync();

        /// <summary>
        /// Disables Windows NCSI (Network Connectivity Status Indicator) probes.
        /// </summary>
        Task<bool> DisableNCSIAsync();

        /// <summary>
        /// Hardens DNS client settings (DoH required, smart resolution off, LLMNR off).
        /// </summary>
        Task<bool> HardenDnsClientAsync();

        /// <summary>
        /// Reverts all hardening changes to original system state.
        /// </summary>
        Task<HardeningResult> RevertHardeningAsync();

        /// <summary>
        /// Gets current hardening status (which features are enabled).
        /// </summary>
        Task<HardeningStatus> GetHardeningStatusAsync();
    }
}
