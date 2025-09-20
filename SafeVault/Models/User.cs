using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    public class User
    {
        public int UserID { get; set; }
        
        [Required]
        [StringLength(100, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        public string PasswordHash { get; set; } = string.Empty;
        
        [Required]
        public string Role { get; set; } = "User"; // User, Admin, SuperAdmin
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime LastLoginAt { get; set; }
        
        public bool IsActive { get; set; } = true;
        
        public string? RefreshToken { get; set; }
        
        public DateTime? RefreshTokenExpiryTime { get; set; }

        // Navigation properties for audit trail
        public List<UserSession> Sessions { get; set; } = new();
        public List<AuditLog> AuditLogs { get; set; } = new();
    }

    public class UserSession
    {
        public int SessionID { get; set; }
        public int UserID { get; set; }
        public string SessionToken { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; }
        public string IPAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        
        // Navigation property
        public User User { get; set; } = null!;
    }

    public class AuditLog
    {
        public int AuditID { get; set; }
        public int? UserID { get; set; }
        public string Action { get; set; } = string.Empty;
        public string Resource { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string IPAddress { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public bool Success { get; set; }
        
        // Navigation property
        public User? User { get; set; }
    }
}