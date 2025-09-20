using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services
{
    public interface IAuditService
    {
        Task LogAsync(int? userId, string action, string resource, string ipAddress, string details, bool success);
        Task<List<AuditLog>> GetAuditLogsAsync(int? userId = null, DateTime? fromDate = null, DateTime? toDate = null, int take = 100);
        Task<List<AuditLog>> GetSecurityEventsAsync(int take = 50);
    }

    public class AuditService : IAuditService
    {
        private readonly SafeVaultDbContext _context;
        private readonly ILogger<AuditService> _logger;

        public AuditService(SafeVaultDbContext context, ILogger<AuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(int? userId, string action, string resource, string ipAddress, string details, bool success)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    UserID = userId,
                    Action = action,
                    Resource = resource,
                    Timestamp = DateTime.UtcNow,
                    IPAddress = ipAddress,
                    Details = details,
                    Success = success
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Audit log created: {Action} on {Resource} for User {UserId} - Success: {Success}", 
                    action, resource, userId, success);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create audit log for action: {Action}", action);
            }
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(int? userId = null, DateTime? fromDate = null, DateTime? toDate = null, int take = 100)
        {
            try
            {
                var query = _context.AuditLogs.AsQueryable();

                if (userId.HasValue)
                    query = query.Where(a => a.UserID == userId.Value);

                if (fromDate.HasValue)
                    query = query.Where(a => a.Timestamp >= fromDate.Value);

                if (toDate.HasValue)
                    query = query.Where(a => a.Timestamp <= toDate.Value);

                return await query
                    .OrderByDescending(a => a.Timestamp)
                    .Take(take)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving audit logs");
                return new List<AuditLog>();
            }
        }

        public async Task<List<AuditLog>> GetSecurityEventsAsync(int take = 50)
        {
            try
            {
                var securityActions = new[]
                {
                    "LOGIN_FAILED", "LOGIN_SUCCESS", "LOGOUT_SUCCESS", "PASSWORD_CHANGE_FAILED", 
                    "PASSWORD_CHANGE_SUCCESS", "REGISTRATION_FAILED", "REGISTRATION_SUCCESS",
                    "REFRESH_TOKEN_FAILED", "TOKEN_REFRESH_SUCCESS", "ROLE_UPDATE", "USER_DEACTIVATED"
                };

                return await _context.AuditLogs
                    .Where(a => securityActions.Contains(a.Action))
                    .OrderByDescending(a => a.Timestamp)
                    .Take(take)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving security events");
                return new List<AuditLog>();
            }
        }
    }
}