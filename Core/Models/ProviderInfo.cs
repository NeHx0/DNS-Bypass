namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// DNS provider information (servers, DoH endpoints).
    /// </summary>
    public class ProviderInfo
    {
        public string[] V4 { get; set; }
        public string[] V6 { get; set; }
        public string Doh4 { get; set; }   // DNS-over-HTTPS template (empty = not available)
        public string Doh6 { get; set; }
    }
}
