using Microsoft.AspNetCore.Mvc;
using SafeVault.Security;
using SafeVault.Services;
using System.Data;
using Microsoft.Data.SqlClient;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private const string CONNECTION_STRING = "Server=(localdb)\\MSSQLLocalDB;Database=SafeVaultDb;Trusted_Connection=true;TrustServerCertificate=true;";
        private readonly IAuditService _auditService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IAuditService auditService, ILogger<UsersController> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// Submit user data (requires authentication)
        /// </summary>
        [HttpPost("submit")]
        [SafeVaultAuthorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Submit([FromForm] string username, [FromForm] string email)
        {
            try
            {
                var currentUserId = User.GetUserId();
                var currentUsername = User.GetUsername();
                var ipAddress = GetClientIpAddress();

                _logger.LogInformation("User {CurrentUsername} (ID: {CurrentUserId}) submitting data for username: {Username}", 
                    currentUsername, currentUserId, username);

                var u = InputSanitizer.SanitizeUsername(username);
                var e = InputSanitizer.SanitizeEmail(email);

                if (!u.IsValid || !e.IsValid)
                {
                    await _auditService.LogAsync(currentUserId, "SUBMIT_FAILED", "Users", ipAddress,
                        $"Invalid input: {string.Join(", ", new[] { u.Error, e.Error }.Where(x => !string.IsNullOrWhiteSpace(x)))}", false);

                    return BadRequest(new
                    {
                        success = false,
                        errors = new[] { u.Error, e.Error }.Where(x => !string.IsNullOrWhiteSpace(x))
                    });
                }

                var user = await GetByUserNameAsync(u.Sanitized);

                await _auditService.LogAsync(currentUserId, "SUBMIT_SUCCESS", "Users", ipAddress,
                    $"Successfully processed submission for username: {u.Sanitized}", true);

                return Ok(new
                {
                    success = true,
                    message = "Data submitted successfully",
                    user = user,
                    submittedBy = currentUsername
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing submit request");
                return StatusCode(500, new { success = false, message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get user by username (requires User role or higher)
        /// </summary>
        [HttpGet("{username}")]
        [RequireUserRole]
        public async Task<ActionResult<User>> GetUserByUsername(string username)
        {
            try
            {
                var currentUserId = User.GetUserId();
                var currentUsername = User.GetUsername();
                var currentRole = User.GetRole();
                var ipAddress = GetClientIpAddress();

                // Users can only view their own profile, admins can view any profile
                if (currentRole == "User" && currentUsername != username)
                {
                    await _auditService.LogAsync(currentUserId, "ACCESS_DENIED", "Users", ipAddress,
                        $"User {currentUsername} tried to access profile of {username}", false);
                    
                    return Forbid("You can only view your own profile");
                }

                var sanitizedUsername = InputSanitizer.SanitizeUsername(username);
                if (!sanitizedUsername.IsValid)
                {
                    return BadRequest(new { message = sanitizedUsername.Error });
                }

                var user = await GetByUserNameAsync(sanitizedUsername.Sanitized);
                
                if (user == null)
                {
                    await _auditService.LogAsync(currentUserId, "USER_NOT_FOUND", "Users", ipAddress,
                        $"User {currentUsername} searched for non-existent user: {sanitizedUsername.Sanitized}", false);
                    
                    return NotFound(new { message = "User not found" });
                }

                await _auditService.LogAsync(currentUserId, "VIEW_USER", "Users", ipAddress,
                    $"User {currentUsername} viewed profile of {user.Username}", true);

                return Ok(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by username: {Username}", username);
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Get all users (Admin and SuperAdmin only)
        /// </summary>
        [HttpGet]
        [RequireAdminRole]
        public async Task<ActionResult<List<User>>> GetAllUsers()
        {
            try
            {
                var currentUserId = User.GetUserId();
                var currentUsername = User.GetUsername();
                var ipAddress = GetClientIpAddress();

                var users = await GetAllUsersFromDatabaseAsync();

                await _auditService.LogAsync(currentUserId, "VIEW_ALL_USERS", "Users", ipAddress,
                    $"Admin {currentUsername} viewed all users list", true);

                return Ok(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all users");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Delete user (SuperAdmin only)
        /// </summary>
        [HttpDelete("{userId}")]
        [RequireSuperAdminRole]
        public async Task<IActionResult> DeleteUser(int userId)
        {
            try
            {
                var currentUserId = User.GetUserId();
                var currentUsername = User.GetUsername();
                var ipAddress = GetClientIpAddress();

                // Prevent self-deletion
                if (userId == currentUserId)
                {
                    await _auditService.LogAsync(currentUserId, "DELETE_USER_DENIED", "Users", ipAddress,
                        $"SuperAdmin {currentUsername} tried to delete own account", false);
                    
                    return BadRequest(new { message = "Cannot delete your own account" });
                }

                var success = await DeleteUserFromDatabaseAsync(userId);

                if (success)
                {
                    await _auditService.LogAsync(currentUserId, "DELETE_USER_SUCCESS", "Users", ipAddress,
                        $"SuperAdmin {currentUsername} deleted user ID: {userId}", true);

                    _logger.LogInformation("User deleted: UserId={UserId}, DeletedBy={AdminUsername}", 
                        userId, currentUsername);

                    return Ok(new { message = "User deleted successfully" });
                }
                else
                {
                    return NotFound(new { message = "User not found" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user: UserId={UserId}", userId);
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        #region Private Methods

        private async Task<User?> GetByUserNameAsync(string username)
        {
            try
            {
                await using var conn = new SqlConnection(CONNECTION_STRING);
                await conn.OpenAsync();

                const string sql = @"
                    SELECT UserID, Username, Email
                    FROM dbo.Users
                    WHERE Username = @username AND IsActive = 1;
                ";

                await using var cmd = new SqlCommand(sql, conn);
                cmd.Parameters.Add("@username", SqlDbType.NVarChar, 256).Value = username ?? string.Empty;

                await using var reader = await cmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync()) return null;

                return new User
                {
                    UserID = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2),
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by username: {Username}", username);
                return null;
            }
        }

        private async Task<List<User>> GetAllUsersFromDatabaseAsync()
        {
            try
            {
                var users = new List<User>();
                await using var conn = new SqlConnection(CONNECTION_STRING);
                await conn.OpenAsync();

                const string sql = @"
                    SELECT UserID, Username, Email, Role, CreatedAt, LastLoginAt, IsActive
                    FROM dbo.Users
                    WHERE IsActive = 1
                    ORDER BY CreatedAt DESC;
                ";

                await using var cmd = new SqlCommand(sql, conn);
                await using var reader = await cmd.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    users.Add(new User
                    {
                        UserID = reader.GetInt32("UserID"),
                        Username = reader.GetString("Username"),
                        Email = reader.GetString("Email"),
                        Role = reader.GetString("Role"),
                        CreatedAt = reader.GetDateTime("CreatedAt"),
                        LastLoginAt = reader.IsDBNull("LastLoginAt") ? DateTime.MinValue : reader.GetDateTime("LastLoginAt"),
                        IsActive = reader.GetBoolean("IsActive")
                    });
                }

                return users;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving all users");
                return new List<User>();
            }
        }

        private async Task<bool> DeleteUserFromDatabaseAsync(int userId)
        {
            try
            {
                await using var conn = new SqlConnection(CONNECTION_STRING);
                await conn.OpenAsync();

                // Soft delete - set IsActive to false instead of actual deletion
                const string sql = @"
                    UPDATE dbo.Users 
                    SET IsActive = 0, 
                        RefreshToken = NULL, 
                        RefreshTokenExpiryTime = NULL
                    WHERE UserID = @userId;
                ";

                await using var cmd = new SqlCommand(sql, conn);
                cmd.Parameters.Add("@userId", SqlDbType.Int).Value = userId;

                var rowsAffected = await cmd.ExecuteNonQueryAsync();
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user: UserId={UserId}", userId);
                return false;
            }
        }

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
