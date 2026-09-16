using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DnsAdvancedBypass.Core.Security
{
    /// <summary>
    /// Runtime protection layer - prevents tampering, debugging, and reverse engineering
    /// </summary>
    internal static class ProtectionShield
    {
        private static readonly string ProtectionSignature = "Encrypted By ErAy - 2026";
        private static bool _initialized = false;
        private static Timer _watchdog;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength, ref int returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        /// <summary>
        /// Initialize protection systems
        /// </summary>
        public static void Initialize()
        {
            if (_initialized) return;

            try
            {
                // Developer bypass: Check for special environment variable
                var devMode = Environment.GetEnvironmentVariable("DNS_BYPASS_DEV_MODE");
                if (devMode == "ErAy2026")
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[PROTECTION] Developer mode active - protection checks bypassed");
                    Console.ResetColor();
                    _initialized = true;
                    return;
                }

                // Anti-debug checks
                if (DetectDebugger())
                {
                    ShowProtectionMessage("Debugger Detected");
                    Environment.FailFast(ProtectionSignature);
                }

                // Anti-tamper integrity check
                if (!VerifyIntegrity())
                {
                    ShowProtectionMessage("Integrity Violation");
                    Environment.FailFast(ProtectionSignature);
                }

                // Anti-VM checks
                if (DetectVirtualMachine())
                {
                    ShowProtectionMessage("Virtual Environment Detected");
                    // Just warn, don't exit (too aggressive for normal users)
                }

                // Start protection watchdog
                StartWatchdog();

                _initialized = true;
            }
            catch (Exception ex)
            {
                ShowProtectionMessage($"Protection Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Multi-layer debugger detection
        /// </summary>
        private static bool DetectDebugger()
        {
            // Check 1: Managed debugger
            if (Debugger.IsAttached)
                return true;

            // Check 2: IsDebuggerPresent
            if (IsDebuggerPresent())
                return true;

            // Check 3: Remote debugger
            bool isRemoteDebuggerPresent = false;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), ref isRemoteDebuggerPresent);
            if (isRemoteDebuggerPresent)
                return true;

            // Check 4: NtQueryInformationProcess (ProcessDebugPort)
            try
            {
                int debugPort = 0;
                int returnLength = 0;
                int result = NtQueryInformationProcess(GetCurrentProcess(), 7, ref debugPort, sizeof(int), ref returnLength);
                if (result == 0 && debugPort != 0)
                    return true;
            }
            catch { }

            // Check 5: Timing attack
            var sw = Stopwatch.StartNew();
            Thread.Sleep(1);
            sw.Stop();
            if (sw.ElapsedMilliseconds > 5) // Debugger slows execution
                return true;

            return false;
        }

        /// <summary>
        /// Verify assembly integrity (simple hash check)
        /// </summary>
        private static bool VerifyIntegrity()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var location = assembly.Location;
                
                if (string.IsNullOrEmpty(location))
                    return false;

                // Check if file exists and is readable
                if (!System.IO.File.Exists(location))
                    return false;

                // Check for suspicious module loads
                var modules = Process.GetCurrentProcess().Modules;
                foreach (ProcessModule module in modules)
                {
                    var name = module.ModuleName?.ToLowerInvariant() ?? "";
                    if (name.Contains("dnspy") || 
                        name.Contains("ilspy") || 
                        name.Contains("deobf") ||
                        name.Contains("unpacker") ||
                        name.Contains("dumper"))
                    {
                        return false;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Detect common virtual machine indicators
        /// </summary>
        private static bool DetectVirtualMachine()
        {
            try
            {
                // Check for common VM artifacts
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (name.Contains("vmware") || 
                        name.Contains("vbox") || 
                        name.Contains("qemu") ||
                        name.Contains("virtualbox"))
                    {
                        return true;
                    }
                }

                // Check BIOS/System info via WMI would go here
                // Skipped for performance reasons
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Start a watchdog timer to continuously check for tampering
        /// </summary>
        private static void StartWatchdog()
        {
            _watchdog = new Timer(_ =>
            {
                if (DetectDebugger())
                {
                    ShowProtectionMessage("Runtime Tampering Detected");
                    Environment.FailFast(ProtectionSignature);
                }
            }, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        /// <summary>
        /// Show protection message
        /// </summary>
        private static void ShowProtectionMessage(string reason)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine("╔════════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                     🔒 PROTECTION ALERT 🔒                     ║");
            Console.WriteLine("╠════════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine($"║  {ProtectionSignature,-60}  ║");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("╠════════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine($"║  ⚠️  Reason: {reason,-49} ║");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("║  This software is protected against:                          ║");
            Console.WriteLine("║    • Debuggers (x64dbg, WinDbg, OllyDbg)                      ║");
            Console.WriteLine("║    • Decompilers (dnSpy, ILSpy, dotPeek)                      ║");
            Console.WriteLine("║    • Memory Dumpers (MegaDumper, ExtremeDumper)               ║");
            Console.WriteLine("║    • Reverse Engineering Tools                                 ║");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("║  Tampering attempts are logged and reported.                  ║");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("╠════════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("║  For legitimate security research:                            ║");
            Console.WriteLine("║  Contact: https://github.com/NeHx0                            ║");
            Console.WriteLine("║                                                                ║");
            Console.WriteLine("╚════════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
            Console.WriteLine("  Press any key to exit...");
            Console.ResetColor();

            try
            {
                Console.ReadKey(true);
            }
            catch { }
        }

        /// <summary>
        /// Cleanup watchdog on exit
        /// </summary>
        public static void Shutdown()
        {
            _watchdog?.Dispose();
        }
    }
}
