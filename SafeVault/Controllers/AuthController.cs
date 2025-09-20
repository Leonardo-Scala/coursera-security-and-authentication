using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models.DTOs;
using SafeVault.Security;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IAuditService _auditService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, IAuditService auditService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user and return access token
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new AuthResponse 
                    { 
                        Success = false, 
                        Message = "Invalid input data",
                    });
                }

                var ipAddress = GetClientIpAddress();
                var userAgent = Request.Headers.UserAgent.ToString();

                var response = await _authService.LoginAsync(request, ipAddress, userAgent);

                if (response.Success)
                {
                    _logger.LogInformation("Successful login for user: {Username} from IP: {IpAddress}", request.Username, ipAddress);
                    return Ok(response);
                }
                else
                {
                    _logger.LogWarning("Failed login attempt for user: {Username} from IP: {IpAddress}", request.Username, ipAddress);
                    return Unauthorized(response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing login request for user: {Username}", request.Username);
                return StatusCode(500, new AuthResponse 
                { 
                    Success = false, 
                    Message = "Internal server error during login" 
                });
            }
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new AuthResponse 
                    { 
                        Success = false, 
                        Message = "Invalid input data" 
                    });
                }

                var ipAddress = GetClientIpAddress();
                var response = await _authService.RegisterAsync(request, ipAddress);

                if (response.Success)
                {
                    _logger.LogInformation("Successful registration for user: {Username}", request.Username);
                    return CreatedAtAction(nameof(Register), response);
                }
                else
                {
                    _logger.LogWarning("Failed registration attempt for user: {Username} - {Reason}", request.Username, response.Message);
                    return BadRequest(response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing registration request for user: {Username}", request.Username);
                return StatusCode(500, new AuthResponse 
                { 
                    Success = false, 
                    Message = "Internal server error during registration" 
                });
            }
        }

        /// <summary>
        /// Refresh access token using refresh token
        /// </summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new AuthResponse 
                    { 
                        Success = false, 
                        Message = "Invalid refresh token" 
                    });
                }

                var ipAddress = GetClientIpAddress();
                var response = await _authService.RefreshTokenAsync(request, ipAddress);

                if (response.Success)
                {
                    _logger.LogInformation("Token refreshed successfully from IP: {IpAddress}", ipAddress);
                    return Ok(response);
                }
                else
                {
                    _logger.LogWarning("Failed token refresh attempt from IP: {IpAddress}", ipAddress);
                    return Unauthorized(response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing token refresh request");
                return StatusCode(500, new AuthResponse 
                { 
                    Success = false, 
                    Message = "Internal server error during token refresh" 
                });
            }
        }

        /// <summary>
        /// Logout user and invalidate tokens
        /// </summary>
        [HttpPost("logout")]
        [SafeVaultAuthorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var username = User.GetUsername();
                var sessionToken = GetSessionToken();

                if (string.IsNullOrEmpty(sessionToken))
                {
                    return BadRequest(new { message = "Session token not found" });
                }

                var success = await _authService.LogoutAsync(username, sessionToken);

                if (success)
                {
                    _logger.LogInformation("User {Username} logged out successfully", username);
                    return Ok(new { message = "Logout successful" });
                }
                else
                {
                    _logger.LogWarning("Failed logout attempt for user: {Username}", username);
                    return BadRequest(new { message = "Logout failed" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing logout request");
                return StatusCode(500, new { message = "Internal server error during logout" });
            }
        }

        /// <summary>
        /// Change user password
        /// </summary>
        [HttpPost("change-password")]
        [SafeVaultAuthorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid input data" });
                }

                var username = User.GetUsername();
                var success = await _authService.ChangePasswordAsync(username, request);

                if (success)
                {
                    _logger.LogInformation("Password changed successfully for user: {Username}", username);
                    return Ok(new { message = "Password changed successfully" });
                }
                else
                {
                    _logger.LogWarning("Failed password change attempt for user: {Username}", username);
                    return BadRequest(new { message = "Failed to change password. Please check your current password." });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing password change request");
                return StatusCode(500, new { message = "Internal server error during password change" });
            }
        }

        /// <summary>
        /// Get current user profile
        /// </summary>
        [HttpGet("profile")]
        [SafeVaultAuthorize]
        public async Task<ActionResult<UserInfo>> GetProfile()
        {
            try
            {
                var username = User.GetUsername();
                var user = await _authService.GetUserByUsernameAsync(username);

                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                var userInfo = new UserInfo
                {
                    UserID = user.UserID,
                    Username = user.Username,
                    Email = user.Email,
                    Role = user.Role,
                    LastLoginAt = user.LastLoginAt
                };

                return Ok(userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user profile");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        /// <summary>
        /// Validate current token
        /// </summary>
        [HttpGet("validate")]
        [SafeVaultAuthorize]
        public IActionResult ValidateToken()
        {
            return Ok(new 
            { 
                valid = true, 
                user = new UserInfo
                {
                    UserID = User.GetUserId(),
                    Username = User.GetUsername(),
                    Email = User.GetEmail(),
                    Role = User.GetRole()
                }
            });
        }

        #region Helper Methods

        private string GetClientIpAddress()
        {
            // Check for X-Forwarded-For header (when behind a proxy/load balancer)
            var forwardedHeader = Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedHeader))
            {
                return forwardedHeader.Split(',')[0].Trim();
            }

            // Check for X-Real-IP header (Nginx proxy)
            var realIpHeader = Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIpHeader))
            {
                return realIpHeader;
            }

            // Fall back to remote IP address
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        private string GetSessionToken()
        {
            var authHeader = Request.Headers.Authorization.FirstOrDefault();
            if (authHeader != null && authHeader.StartsWith("Bearer "))
            {
                return authHeader["Bearer ".Length..];
            }
            return string.Empty;
        }

        #endregion
    }
}