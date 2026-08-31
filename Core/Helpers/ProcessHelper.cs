using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DnsAdvancedBypass.Core.Interfaces;

namespace DnsAdvancedBypass.Core.Helpers
{
    /// <summary>
    /// Helper for executing external processes (netsh, ipconfig, etc.) with timeout and error handling.
    /// </summary>
    public class ProcessHelper
    {
        private readonly ILogger _logger;

        public ProcessHelper(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Executes a process synchronously with timeout.
        /// </summary>
        public ProcessResult Execute(string fileName, string arguments, int timeoutMs = 5000)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                using (var process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        _logger.Error($"Failed to start process: {fileName} {arguments}");
                        return new ProcessResult
                        {
                            Success = false,
                            ExitCode = -1,
                            Error = "Process failed to start"
                        };
                    }

                    var outputBuilder = new StringBuilder();
                    var errorBuilder = new StringBuilder();

                    process.OutputDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                            outputBuilder.AppendLine(e.Data);
                    };

                    process.ErrorDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                            errorBuilder.AppendLine(e.Data);
                    };

                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    bool exited = process.WaitForExit(timeoutMs);

                    if (!exited)
                    {
                        try
                        {
                            process.Kill();
                            process.WaitForExit();
                        }
                        catch { }

                        _logger.Warn($"Process timed out: {fileName} {arguments}");
                        return new ProcessResult
                        {
                            Success = false,
                            ExitCode = -1,
                            Error = "Process timed out",
                            Output = outputBuilder.ToString()
                        };
                    }

                    var output = outputBuilder.ToString();
                    var error = errorBuilder.ToString();
                    bool success = process.ExitCode == 0 && !ContainsErrorKeywords(output + error);

                    return new ProcessResult
                    {
                        Success = success,
                        ExitCode = process.ExitCode,
                        Output = output,
                        Error = error
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Process execution failed: {fileName} {arguments}", ex);
                return new ProcessResult
                {
                    Success = false,
                    ExitCode = -1,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Executes a process asynchronously with timeout.
        /// </summary>
        public async Task<ProcessResult> ExecuteAsync(string fileName, string arguments, int timeoutMs = 5000)
        {
            return await Task.Run(() => Execute(fileName, arguments, timeoutMs));
        }

        /// <summary>
        /// Executes netsh command with retry logic.
        /// </summary>
        public bool ExecuteNetsh(string arguments, int maxRetries = 3)
        {
            for (int attempt = 0; attempt < maxRetries; attempt++)
            {
                if (attempt > 0)
                {
                    _logger.Warn($"Retrying netsh command (attempt {attempt + 1}/{maxRetries})...");
                    System.Threading.Thread.Sleep(600);
                }

                var result = Execute("netsh", arguments);
                if (result.Success)
                {
                    _logger.Debug($"netsh command succeeded: {arguments}");
                    return true;
                }

                if (!string.IsNullOrWhiteSpace(result.Output))
                {
                    var firstLine = result.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                                 .FirstOrDefault();
                    if (!string.IsNullOrEmpty(firstLine))
                        _logger.Debug($"netsh output: {firstLine.Trim()}");
                }
            }

            _logger.Error($"netsh command failed after {maxRetries} attempts: {arguments}");
            return false;
        }

        private bool ContainsErrorKeywords(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            var lowerText = text.ToLowerInvariant();
            string[] keywords = { "error", "hata", "denied", "başarısız", "reddedildi", "yetki", "failed" };
            return keywords.Any(k => lowerText.Contains(k));
        }
    }

    /// <summary>
    /// Result of a process execution.
    /// </summary>
    public class ProcessResult
    {
        public bool Success { get; set; }
        public int ExitCode { get; set; }
        public string Output { get; set; } = "";
        public string Error { get; set; } = "";
    }
}
