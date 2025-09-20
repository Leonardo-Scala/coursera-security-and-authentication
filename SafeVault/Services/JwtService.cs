using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SafeVault.Services
{
    public interface IJwtService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
        bool ValidateToken(string token);
    }

    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtService> _logger;

        public JwtService(IConfiguration configuration, ILogger<JwtService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public string GenerateAccessToken(User user)
        {
            try
            {
                var secretKey = _configuration["JwtSettings:SecretKey"] ?? "SafeVault_Super_Secret_Key_That_Should_Be_Changed_In_Production_2024!";
                var issuer = _configuration["JwtSettings:Issuer"] ?? "SafeVault";
                var audience = _configuration["JwtSettings:Audience"] ?? "SafeVault-Users";
                var expiryMinutes = int.Parse(_configuration["JwtSettings:ExpiryMinutes"] ?? "60");

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserID.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("userId", user.UserID.ToString()),
                    new Claim("username", user.Username),
                    new Claim("role", user.Role),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
                };

                var token = new JwtSecurityToken(
                    issuer: issuer,
                    audience: audience,
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                    signingCredentials: credentials
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                _logger.LogInformation("Access token generated for user {Username} (ID: {UserId})", user.Username, user.UserID);
                
                return tokenString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating access token for user {Username}", user.Username);
                throw new InvalidOperationException("Failed to generate access token", ex);
            }
        }

        public string GenerateRefreshToken()
        {
            try
            {
                var randomNumber = new byte[64];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(randomNumber);
                var refreshToken = Convert.ToBase64String(randomNumber);
                
                _logger.LogInformation("Refresh token generated");
                return refreshToken;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating refresh token");
                throw new InvalidOperationException("Failed to generate refresh token", ex);
            }
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            try
            {
                var secretKey = _configuration["JwtSettings:SecretKey"] ?? "SafeVault_Super_Secret_Key_That_Should_Be_Changed_In_Production_2024!";
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateLifetime = false // Don't validate expiry for refresh token scenario
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new SecurityTokenException("Invalid token");
                }

                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting principal from expired token");
                return null;
            }
        }

        public bool ValidateToken(string token)
        {
            try
            {
                var secretKey = _configuration["JwtSettings:SecretKey"] ?? "SafeVault_Super_Secret_Key_That_Should_Be_Changed_In_Production_2024!";
                var issuer = _configuration["JwtSettings:Issuer"] ?? "SafeVault";
                var audience = _configuration["JwtSettings:Audience"] ?? "SafeVault-Users";

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Token validation failed");
                return false;
            }
        }
    }
}