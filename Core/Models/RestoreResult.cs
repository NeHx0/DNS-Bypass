using System;
using System.Collections.Generic;

namespace DnsAdvancedBypass.Core.Models
{
    /// <summary>
    /// Result of a restore operation.
    /// </summary>
    public class RestoreResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public List<RestoreStep> Steps { get; set; } = new List<RestoreStep>();
        public int TotalChanges { get; set; }
        public int SuccessfulChanges { get; set; }
        public int FailedChanges { get; set; }

        public static RestoreResult Succeeded(string message)
        {
            return new RestoreResult { Success = true, Message = message };
        }

        public static RestoreResult Failed(string message)
        {
            return new RestoreResult { Success = false, Message = message };
        }

        public void AddStep(string category, bool success, string details = "")
        {
            Steps.Add(new RestoreStep
            {
                Category = category,
                Success = success,
                Details = details,
                Timestamp = DateTime.Now
            });
        }
    }

    /// <summary>
    /// Individual step in the restore process.
    /// </summary>
    public class RestoreStep
    {
        public string Category { get; set; }
        public bool Success { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Report from a dry-run restore (what would be changed).
    /// </summary>
    public class RestoreReport
    {
        public SystemSnapshot Snapshot { get; set; }
        public List<PlannedChange> PlannedChanges { get; set; } = new List<PlannedChange>();
        public List<string> Warnings { get; set; } = new List<string>();
        public bool IsCompatible { get; set; } = true;
        public string IncompatibilityReason { get; set; }

        public int TotalChangesCount => PlannedChanges.Count;
    }

    /// <summary>
    /// A planned change for dry-run preview.
    /// </summary>
    public class PlannedChange
    {
        public string Category { get; set; }      // "Registry", "DNS", "Service"
        public string Target { get; set; }        // Key/Adapter/Service name
        public string CurrentValue { get; set; }  // Current state
        public string NewValue { get; set; }      // State after restore
        public string Action { get; set; }        // "Set", "Delete", "Create"
    }

    /// <summary>
    /// Validation result for snapshot compatibility.
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid { get; set; } = true;
        public List<string> Errors { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();

        public static ValidationResult Valid()
        {
            return new ValidationResult { IsValid = true };
        }

        public static ValidationResult Invalid(string error)
        {
            return new ValidationResult
            {
                IsValid = false,
                Errors = new List<string> { error }
            };
        }

        public void AddError(string error)
        {
            Errors.Add(error);
            IsValid = false;
        }

        public void AddWarning(string warning)
        {
            Warnings.Add(warning);
        }
    }
}
