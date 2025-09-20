using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [RequireAdminRole]
    public class AdminController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IAuditService _auditService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(IAuthService authService, IAuditService auditService, ILogger<AdminController> logger)
        {
            _authService = authService;
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// Get all users (Admin and SuperAdmin only)
        /// </summary>
        [HttpGet("users")]
        public async Task<ActionResult<List<UserInfo>>> GetAllUsers()
        {
            try
            {
                var users = await _authService.GetAllUsersAsync();
                
                await _auditService.LogAsync(User.GetUserId(), "VIEW_ALL_USERS", "Admin", 
                    GetClientIpAddress(), $"Admin {User.GetUsername()} viewed all users", true);

                return Ok(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all users");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Update user role (Admin can promote to Admin, SuperAdmin can promote to any role)
        /// </summary>
        [HttpPut("users/{userId}/role")]
        public async Task<IActionResult> UpdateUserRole(int userId, [FromBody] UpdateRoleRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid input data" });
                }

                var currentUserRole = User.GetRole();
                var adminUsername = User.GetUsername();

                // Validate role change permissions
                if (currentUserRole == "Admin" && request.Role == "SuperAdmin")
                {
                    await _auditService.LogAsync(User.GetUserId(), "ROLE_UPDATE_DENIED", "Admin", 
                        GetClientIpAddress(), $"Admin {adminUsername} tried to promote user {userId} to SuperAdmin", false);
                    
                    return Forbid("Admins cannot promote users to SuperAdmin role");
                }

                // Prevent role changes to the current user
                if (userId == User.GetUserId())
                {
                    await _auditService.LogAsync(User.GetUserId(), "ROLE_UPDATE_DENIED", "Admin", 
                        GetClientIpAddress(), $"{adminUsername} tried to change own role", false);
                    
                    return BadRequest(new { message = "Cannot change your own role" });
                }

                var success = await _authService.UpdateUserRoleAsync(userId, request.Role, adminUsername);

                if (success)
                {
                    _logger.LogInformation("User role updated: UserId={UserId}, NewRole={Role}, UpdatedBy={AdminUsername}", 
                        userId, request.Role, adminUsername);
                    return Ok(new { message = "User role updated successfully" });
                }
                else
                {
                    return NotFound(new { message = "User not found" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user role for UserId: {UserId}", userId);
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Deactivate user account (prevent login)
        /// </summary>
        [HttpPut("users/{userId}/deactivate")]
        public async Task<IActionResult> DeactivateUser(int userId)
        {
            try
            {
                var adminUsername = User.GetUsername();

                // Prevent deactivating self
                if (userId == User.GetUserId())
                {
                    await _auditService.LogAsync(User.GetUserId(), "USER_DEACTIVATION_DENIED", "Admin", 
                        GetClientIpAddress(), $"{adminUsername} tried to deactivate own account", false);
                    
                    return BadRequest(new { message = "Cannot deactivate your own account" });
                }

                var success = await _authService.DeactivateUserAsync(userId, adminUsername);

                if (success)
                {
                    _logger.LogInformation("User deactivated: UserId={UserId}, DeactivatedBy={AdminUsername}", 
                        userId, adminUsername);
                    return Ok(new { message = "User deactivated successfully" });
                }
                else
                {
                    return NotFound(new { message = "User not found" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deactivating user: UserId={UserId}", userId);
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get audit logs (filtered by parameters)
        /// </summary>
        [HttpGet("audit-logs")]
        public async Task<ActionResult<List<AuditLog>>> GetAuditLogs(
            [FromQuery] int? userId = null,
            [FromQuery] DateTime? fromDate = null,
            [FromQuery] DateTime? toDate = null,
            [FromQuery] int take = 100)
        {
            try
            {
                // Limit take parameter to prevent performance issues
                take = Math.Min(take, 1000);

                var logs = await _auditService.GetAuditLogsAsync(userId, fromDate, toDate, take);

                await _auditService.LogAsync(User.GetUserId(), "VIEW_AUDIT_LOGS", "Admin", 
                    GetClientIpAddress(), $"Admin {User.GetUsername()} viewed audit logs", true);

                return Ok(logs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting audit logs");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get security events (login attempts, password changes, etc.)
        /// </summary>
        [HttpGet("security-events")]
        public async Task<ActionResult<List<AuditLog>>> GetSecurityEvents([FromQuery] int take = 50)
        {
            try
            {
                take = Math.Min(take, 200);
                var events = await _auditService.GetSecurityEventsAsync(take);

                await _auditService.LogAsync(User.GetUserId(), "VIEW_SECURITY_EVENTS", "Admin", 
                    GetClientIpAddress(), $"Admin {User.GetUsername()} viewed security events", true);

                return Ok(events);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting security events");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get system statistics (SuperAdmin only)
        /// </summary>
        [HttpGet("statistics")]
        [RequireSuperAdminRole]
        public async Task<ActionResult> GetSystemStatistics()
        {
            try
            {
                var users = await _authService.GetAllUsersAsync();
                var recentEvents = await _auditService.GetSecurityEventsAsync(10);

                var stats = new
                {
                    TotalUsers = users.Count,
                    ActiveUsers = users.Count, // All returned users are active
                    UsersByRole = users.GroupBy(u => u.Role).ToDictionary(g => g.Key, g => g.Count()),
                    RecentActivity = recentEvents.Take(5).Select(e => new 
                    {
                        e.Action,
                        e.Timestamp,
                        Username = users.FirstOrDefault(u => u.UserID == e.UserID)?.Username ?? "Unknown",
                        e.Success
                    }),
                    LastHourLogins = recentEvents.Count(e => e.Action == "LOGIN_SUCCESS" && e.Timestamp > DateTime.UtcNow.AddHours(-1)),
                    LastHourFailedLogins = recentEvents.Count(e => e.Action == "LOGIN_FAILED" && e.Timestamp > DateTime.UtcNow.AddHours(-1))
                };

                await _auditService.LogAsync(User.GetUserId(), "VIEW_SYSTEM_STATS", "Admin", 
                    GetClientIpAddress(), $"SuperAdmin {User.GetUsername()} viewed system statistics", true);

                return Ok(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting system statistics");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        #region Helper Methods

        private string GetClientIpAddress()
        {
            var forwardedHeader = Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedHeader))
            {
                return forwardedHeader.Split(',')[0].Trim();
            }

            var realIpHeader = Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIpHeader))
            {
                return realIpHeader;
            }

            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        #endregion
    }
}