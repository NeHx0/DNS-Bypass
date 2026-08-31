using System;
using DnsAdvancedBypass.Core.Interfaces;

namespace DnsAdvancedBypass.Core.Services
{
    /// <summary>
    /// Console-based logger with colored output.
    /// </summary>
    public class ConsoleLogger : ILogger
    {
        private readonly bool _debugMode;
        private readonly object _lock = new object();

        public ConsoleLogger(bool debugMode = false)
        {
            _debugMode = debugMode;
        }

        public void Info(string message)
        {
            Log("INFO", message, ConsoleColor.Cyan);
        }

        public void Success(string message)
        {
            Log("SUCCESS", message, ConsoleColor.Green);
        }

        public void Warn(string message)
        {
            Log("WARN", message, ConsoleColor.Yellow);
        }

        public void Error(string message)
        {
            Log("ERROR", message, ConsoleColor.Red);
        }

        public void Error(string message, Exception ex)
        {
            Log("ERROR", $"{message}: {ex.Message}", ConsoleColor.Red);
            if (_debugMode && ex.StackTrace != null)
            {
                lock (_lock)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine($"  Stack: {ex.StackTrace}");
                    Console.ResetColor();
                }
            }
        }

        public void Debug(string message)
        {
            if (_debugMode)
                Log("DEBUG", message, ConsoleColor.DarkGray);
        }

        private void Log(string level, string message, ConsoleColor color)
        {
            lock (_lock)
            {
                string time = DateTime.Now.ToString("HH:mm:ss");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"  [{time}] ");
                Console.ForegroundColor = color;
                Console.WriteLine($"[{level}] {message}");
                Console.ResetColor();
            }
        }
    }
}
