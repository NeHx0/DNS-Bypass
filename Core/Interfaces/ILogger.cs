using System;

namespace DnsAdvancedBypass.Core.Interfaces
{
    /// <summary>
    /// Logging abstraction for consistent log output across the application.
    /// </summary>
    public interface ILogger
    {
        /// <summary>
        /// Logs an informational message.
        /// </summary>
        void Info(string message);

        /// <summary>
        /// Logs a success message.
        /// </summary>
        void Success(string message);

        /// <summary>
        /// Logs a warning message.
        /// </summary>
        void Warn(string message);

        /// <summary>
        /// Logs an error message.
        /// </summary>
        void Error(string message);

        /// <summary>
        /// Logs an error message with exception details.
        /// </summary>
        void Error(string message, Exception ex);

        /// <summary>
        /// Logs a debug message (only if debug mode is enabled).
        /// </summary>
        void Debug(string message);
    }
}
