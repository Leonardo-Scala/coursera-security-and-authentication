using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using SafeVault.Security;

namespace SafeVault.Services
{
    public interface IAuthService
    {
        Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
        Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress);
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress);
        Task<bool> LogoutAsync(string username, string sessionToken);
        Task<bool> ChangePasswordAsync(string username, ChangePasswordRequest request);
        Task<User?> GetUserByUsernameAsync(string username);
        Task<bool> UpdateUserRoleAsync(int userId, string role, string adminUsername);
        Task<List<UserInfo>> GetAllUsersAsync();
        Task<bool> DeactivateUserAsync(int userId, string adminUsername);
    }

    public class AuthService : IAuthService
    {
        private readonly SafeVaultDbContext _context;
        private readonly IJwtService _jwtService;
        private readonly IAuditService _auditService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(SafeVaultDbContext context, IJwtService jwtService, IAuditService auditService, ILogger<AuthService> logger)
        {
            _context = context;
            _jwtService = jwtService;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
        {
            try
            {
                _logger.LogInformation("Login attempt for username: {Username} from IP: {IpAddress}", request.Username, ipAddress);

                // Sanitize input
                var sanitizedUsername = InputSanitizer.SanitizeUsername(request.Username);
                if (!sanitizedUsername.IsValid)
                {
                    await _auditService.LogAsync(null, "LOGIN_ATTEMPT", "Auth", ipAddress, 
                        $"Invalid username format: {sanitizedUsername.Error}", false);
                    return new AuthResponse { Success = false, Message = "Invalid username format" };
                }

                // Find user
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Username == sanitizedUsername.Sanitized && u.IsActive);

                if (user == null)
                {
                    await _auditService.LogAsync(null, "LOGIN_FAILED", "Auth", ipAddress, 
                        $"User not found: {sanitizedUsername.Sanitized}", false);
                    return new AuthResponse { Success = false, Message = "Invalid username or password" };
                }

                // Verify password
                if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    await _auditService.LogAsync(user.UserID, "LOGIN_FAILED", "Auth", ipAddress, 
                        "Invalid password", false);
                    return new AuthResponse { Success = false, Message = "Invalid username or password" };
                }

                // Generate tokens
                var accessToken = _jwtService.GenerateAccessToken(user);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // Update user login info
                user.LastLoginAt = DateTime.UtcNow;
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // 7 days for refresh token

                // Create session
                var session = new UserSession
                {
                    UserID = user.UserID,
                    SessionToken = accessToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1), // 1 hour for access token
                    IPAddress = ipAddress,
                    UserAgent = userAgent,
                    IsActive = true
                };

                _context.UserSessions.Add(session);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.UserID, "LOGIN_SUCCESS", "Auth", ipAddress, 
                    $"User {user.Username} logged in successfully", true);

                _logger.LogInformation("User {Username} (ID: {UserId}) logged in successfully", user.Username, user.UserID);

                return new AuthResponse
                {
                    Success = true,
                    Message = "Login successful",
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    User = new UserInfo
                    {
                        UserID = user.UserID,
                        Username = user.Username,
                        Email = user.Email,
                        Role = user.Role,
                        LastLoginAt = user.LastLoginAt
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for username: {Username}", request.Username);
                return new AuthResponse { Success = false, Message = "Login failed due to system error" };
            }
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress)
        {
            try
            {
                _logger.LogInformation("Registration attempt for username: {Username}, email: {Email}", request.Username, request.Email);

                // Sanitize input
                var sanitizedUsername = InputSanitizer.SanitizeUsername(request.Username);
                var sanitizedEmail = InputSanitizer.SanitizeEmail(request.Email);

                if (!sanitizedUsername.IsValid)
                {
                    await _auditService.LogAsync(null, "REGISTRATION_FAILED", "Auth", ipAddress, 
                        $"Invalid username format: {sanitizedUsername.Error}", false);
                    return new AuthResponse { Success = false, Message = sanitizedUsername.Error! };
                }

                if (!sanitizedEmail.IsValid)
                {
                    await _auditService.LogAsync(null, "REGISTRATION_FAILED", "Auth", ipAddress, 
                        $"Invalid email format: {sanitizedEmail.Error}", false);
                    return new AuthResponse { Success = false, Message = sanitizedEmail.Error! };
                }

                // Check if user already exists
                var existingUser = await _context.Users
                    .AnyAsync(u => u.Username == sanitizedUsername.Sanitized || u.Email == sanitizedEmail.Sanitized);

                if (existingUser)
                {
                    await _auditService.LogAsync(null, "REGISTRATION_FAILED", "Auth", ipAddress, 
                        "Username or email already exists", false);
                    return new AuthResponse { Success = false, Message = "Username or email already exists" };
                }

                // Create new user
                var user = new User
                {
                    Username = sanitizedUsername.Sanitized,
                    Email = sanitizedEmail.Sanitized,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password, workFactor: 12),
                    Role = "User", // Default role
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.UserID, "REGISTRATION_SUCCESS", "Auth", ipAddress, 
                    $"User {user.Username} registered successfully", true);

                _logger.LogInformation("User {Username} (ID: {UserId}) registered successfully", user.Username, user.UserID);

                return new AuthResponse
                {
                    Success = true,
                    Message = "Registration successful",
                    User = new UserInfo
                    {
                        UserID = user.UserID,
                        Username = user.Username,
                        Email = user.Email,
                        Role = user.Role,
                        LastLoginAt = user.LastLoginAt
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for username: {Username}", request.Username);
                return new AuthResponse { Success = false, Message = "Registration failed due to system error" };
            }
        }

        public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress)
        {
            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken && u.IsActive);

                if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                {
                    await _auditService.LogAsync(null, "REFRESH_TOKEN_FAILED", "Auth", ipAddress, 
                        "Invalid or expired refresh token", false);
                    return new AuthResponse { Success = false, Message = "Invalid or expired refresh token" };
                }

                // Generate new tokens
                var newAccessToken = _jwtService.GenerateAccessToken(user);
                var newRefreshToken = _jwtService.GenerateRefreshToken();

                // Update user tokens
                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.UserID, "TOKEN_REFRESH_SUCCESS", "Auth", ipAddress, 
                    $"Tokens refreshed for user {user.Username}", true);

                return new AuthResponse
                {
                    Success = true,
                    Message = "Tokens refreshed successfully",
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(1)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return new AuthResponse { Success = false, Message = "Token refresh failed" };
            }
        }

        public async Task<bool> LogoutAsync(string username, string sessionToken)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
                if (user == null) return false;

                // Invalidate session
                var session = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionToken == sessionToken && s.UserID == user.UserID);

                if (session != null)
                {
                    session.IsActive = false;
                }

                // Clear refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.UserID, "LOGOUT_SUCCESS", "Auth", "", 
                    $"User {user.Username} logged out", true);

                _logger.LogInformation("User {Username} logged out successfully", username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout for username: {Username}", username);
                return false;
            }
        }

        public async Task<bool> ChangePasswordAsync(string username, ChangePasswordRequest request)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username && u.IsActive);
                if (user == null) return false;

                // Verify current password
                if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
                {
                    await _auditService.LogAsync(user.UserID, "PASSWORD_CHANGE_FAILED", "Auth", "", 
                        "Invalid current password", false);
                    return false;
                }

                // Update password
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword, workFactor: 12);

                // Invalidate all sessions (force re-login)
                var sessions = await _context.UserSessions.Where(s => s.UserID == user.UserID && s.IsActive).ToListAsync();
                foreach (var session in sessions)
                {
                    session.IsActive = false;
                }

                // Clear refresh token
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.UserID, "PASSWORD_CHANGE_SUCCESS", "Auth", "", 
                    $"Password changed for user {user.Username}", true);

                _logger.LogInformation("Password changed successfully for user {Username}", username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password for username: {Username}", username);
                return false;
            }
        }

        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                return await _context.Users
                    .FirstOrDefaultAsync(u => u.Username == username && u.IsActive);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by username: {Username}", username);
                return null;
            }
        }

        public async Task<bool> UpdateUserRoleAsync(int userId, string role, string adminUsername)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return false;

                var oldRole = user.Role;
                user.Role = role;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync(userId, "ROLE_UPDATE", "User", "", 
                    $"Role changed from {oldRole} to {role} by {adminUsername}", true);

                _logger.LogInformation("Role updated for user {Username} (ID: {UserId}) from {OldRole} to {NewRole} by {AdminUsername}", 
                    user.Username, userId, oldRole, role, adminUsername);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating role for user ID: {UserId}", userId);
                return false;
            }
        }

        public async Task<List<UserInfo>> GetAllUsersAsync()
        {
            try
            {
                return await _context.Users
                    .Where(u => u.IsActive)
                    .Select(u => new UserInfo
                    {
                        UserID = u.UserID,
                        Username = u.Username,
                        Email = u.Email,
                        Role = u.Role,
                        LastLoginAt = u.LastLoginAt
                    })
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all users");
                return new List<UserInfo>();
            }
        }

        public async Task<bool> DeactivateUserAsync(int userId, string adminUsername)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return false;

                user.IsActive = false;

                // Invalidate all sessions
                var sessions = await _context.UserSessions.Where(s => s.UserID == userId && s.IsActive).ToListAsync();
                foreach (var session in sessions)
                {
                    session.IsActive = false;
                }

                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync(userId, "USER_DEACTIVATED", "User", "", 
                    $"User {user.Username} deactivated by {adminUsername}", true);

                _logger.LogInformation("User {Username} (ID: {UserId}) deactivated by {AdminUsername}", 
                    user.Username, userId, adminUsername);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deactivating user ID: {UserId}", userId);
                return false;
            }
        }
    }
}