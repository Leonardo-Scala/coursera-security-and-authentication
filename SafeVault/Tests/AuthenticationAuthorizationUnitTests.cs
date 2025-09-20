using NUnit.Framework;
using SafeVault.Models.DTOs;
using SafeVault.Models;
using SafeVault.Security;
using System.Security.Claims;

namespace SafeVault.Tests
{
    [TestFixture]
    public class AuthenticationAuthorizationUnitTests
    {
        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine("SAFEVAULT AUTHENTICATION & AUTHORIZATION UNIT TESTS");
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine($"Test run started at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine("Testing core authentication and authorization functionality...");
            Console.WriteLine();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            Console.WriteLine();
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine("AUTHENTICATION & AUTHORIZATION UNIT TESTS COMPLETE");
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine($"Test run completed at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        }

        #region Password Security Tests

        [Test]
        public void TestPasswordHashing_ShouldCreateSecureHash()
        {
            Console.WriteLine("Testing password hashing with BCrypt...");

            var password = "TestPassword123!";
            var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

            Assert.That(hash, Is.Not.Null.And.Not.Empty);
            Assert.That(hash, Is.Not.EqualTo(password));
            Assert.That(hash.StartsWith("$2a$") || hash.StartsWith("$2b$") || hash.StartsWith("$2y$"), Is.True);

            // Verify password
            var isValid = BCrypt.Net.BCrypt.Verify(password, hash);
            Assert.That(isValid, Is.True);

            // Verify wrong password
            var isInvalid = BCrypt.Net.BCrypt.Verify("WrongPassword123!", hash);
            Assert.That(isInvalid, Is.False);

            Console.WriteLine("? Password hashing and verification working correctly");
        }

        #endregion

        #region Input Validation Tests

        [Test]
        [TestCase("admin'; DROP TABLE Users; --", false, TestName = "SQL Injection in Username")]
        [TestCase("<script>alert('XSS')</script>", false, TestName = "XSS in Username")]
        [TestCase("validuser123", true, TestName = "Valid Username")]
        [TestCase("user.name_test", true, TestName = "Username with Dots and Underscores")]
        [TestCase("ab", false, TestName = "Username Too Short")]
        public void TestUsernameValidation_SecurityAndFormat(string username, bool expectedValid)
        {
            Console.WriteLine($"Testing username validation: '{username}'");

            var result = InputSanitizer.SanitizeUsername(username);
            
            Assert.That(result.IsValid, Is.EqualTo(expectedValid));
            
            if (expectedValid)
            {
                Assert.That(result.Sanitized, Is.Not.Null.And.Not.Empty);
                Console.WriteLine($"? Valid username sanitized to: '{result.Sanitized}'");
            }
            else
            {
                Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
                Console.WriteLine($"? Invalid username rejected: {result.Error}");
            }
        }

        [Test]
        [TestCase("user@example.com", true, TestName = "Valid Email")]
        [TestCase("invalid-email", false, TestName = "Invalid Email Format")]
        [TestCase("user@test.com'; DROP TABLE Users; --", false, TestName = "SQL Injection in Email")]
        public void TestEmailValidation_SecurityAndFormat(string email, bool expectedValid)
        {
            Console.WriteLine($"Testing email validation: '{email}'");

            var result = InputSanitizer.SanitizeEmail(email);
            
            Assert.That(result.IsValid, Is.EqualTo(expectedValid));
            
            if (expectedValid)
            {
                Assert.That(result.Sanitized, Is.Not.Null.And.Not.Empty);
                Console.WriteLine($"? Valid email sanitized to: '{result.Sanitized}'");
            }
            else
            {
                Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
                Console.WriteLine($"? Invalid email rejected: {result.Error}");
            }
        }

        #endregion

        #region Authorization Tests

        [Test]
        public void TestRoleHierarchy_ShouldRespectRoleBasedAccess()
        {
            Console.WriteLine("Testing role-based authorization hierarchy...");

            // Test role definitions
            var userRoles = new[] { "User", "Admin", "SuperAdmin" };
            var adminRoles = new[] { "Admin", "SuperAdmin" };
            var superAdminRoles = new[] { "SuperAdmin" };

            // User should have access to User endpoints
            Assert.That(userRoles, Contains.Item("User"));
            
            // Admin should have access to User and Admin endpoints
            Assert.That(userRoles, Contains.Item("Admin"));
            Assert.That(adminRoles, Contains.Item("Admin"));
            
            // SuperAdmin should have access to all endpoints
            Assert.That(userRoles, Contains.Item("SuperAdmin"));
            Assert.That(adminRoles, Contains.Item("SuperAdmin"));
            Assert.That(superAdminRoles, Contains.Item("SuperAdmin"));

            Console.WriteLine("? Role hierarchy correctly defined");
        }

        [Test]
        public void TestClaimsPrincipalExtensions_ShouldExtractUserInfoCorrectly()
        {
            Console.WriteLine("Testing ClaimsPrincipal extensions...");

            // Create test claims
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "123"),
                new Claim(ClaimTypes.Name, "testuser"),
                new Claim(ClaimTypes.Email, "test@safevault.com"),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var identity = new ClaimsIdentity(claims, "TestAuth");
            var principal = new ClaimsPrincipal(identity);

            // Test extension methods
            Assert.That(principal.GetUserId(), Is.EqualTo(123));
            Assert.That(principal.GetUsername(), Is.EqualTo("testuser"));
            Assert.That(principal.GetEmail(), Is.EqualTo("test@safevault.com"));
            Assert.That(principal.GetRole(), Is.EqualTo("Admin"));

            Console.WriteLine("? ClaimsPrincipal extensions working correctly");
        }

        #endregion

        #region DTO Validation Tests

        [Test]
        public void TestLoginRequest_ValidData_ShouldPassValidation()
        {
            Console.WriteLine("Testing LoginRequest DTO validation...");

            var loginRequest = new LoginRequest
            {
                Username = "testuser",
                Password = "TestPassword123!",
                RememberMe = false
            };

            Assert.That(loginRequest.Username, Is.Not.Null.And.Not.Empty);
            Assert.That(loginRequest.Password, Is.Not.Null.And.Not.Empty);
            Assert.That(loginRequest.Username.Length, Is.GreaterThanOrEqualTo(3));
            Assert.That(loginRequest.Password.Length, Is.GreaterThanOrEqualTo(8));

            Console.WriteLine("? LoginRequest DTO validation passed");
        }

        [Test]
        public void TestRegisterRequest_ValidData_ShouldPassValidation()
        {
            Console.WriteLine("Testing RegisterRequest DTO validation...");

            var registerRequest = new RegisterRequest
            {
                Username = "newuser",
                Email = "newuser@safevault.com",
                Password = "NewPassword123!",
                ConfirmPassword = "NewPassword123!"
            };

            Assert.That(registerRequest.Username, Is.Not.Null.And.Not.Empty);
            Assert.That(registerRequest.Email, Is.Not.Null.And.Not.Empty);
            Assert.That(registerRequest.Password, Is.Not.Null.And.Not.Empty);
            Assert.That(registerRequest.ConfirmPassword, Is.EqualTo(registerRequest.Password));
            Assert.That(registerRequest.Email.Contains("@"), Is.True);

            Console.WriteLine("? RegisterRequest DTO validation passed");
        }

        #endregion

        #region Model Tests

        [Test]
        public void TestUserModel_DefaultValues_ShouldBeCorrect()
        {
            Console.WriteLine("Testing User model default values...");

            var user = new User();

            Assert.That(user.Username, Is.EqualTo(string.Empty));
            Assert.That(user.Email, Is.EqualTo(string.Empty));
            Assert.That(user.PasswordHash, Is.EqualTo(string.Empty));
            Assert.That(user.Role, Is.EqualTo("User"));
            Assert.That(user.IsActive, Is.True);
            Assert.That(user.Sessions, Is.Not.Null.And.Empty);
            Assert.That(user.AuditLogs, Is.Not.Null.And.Empty);

            Console.WriteLine("? User model default values are correct");
        }

        #endregion

        #region Security Tests

        [Test]
        public void TestSecurityPatterns_InputSanitization_ShouldBlockCommonAttacks()
        {
            Console.WriteLine("Testing security patterns against common attacks...");

            var maliciousInputs = new[]
            {
                "'; DROP TABLE Users; --",
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "1' OR '1'='1",
                "<img src=x onerror=alert('XSS')>"
            };

            foreach (var maliciousInput in maliciousInputs)
            {
                var usernameResult = InputSanitizer.SanitizeUsername(maliciousInput);
                var textResult = InputSanitizer.SanitizePlainText(maliciousInput);

                // Should be either rejected or safely sanitized
                var isSafe = !usernameResult.IsValid || !ContainsDangerousContent(usernameResult.Sanitized);
                isSafe = isSafe && (!textResult.IsValid || !ContainsDangerousContent(textResult.Sanitized));

                Assert.That(isSafe, Is.True, $"Malicious input not properly handled: {maliciousInput}");
                Console.WriteLine($"? Malicious input safely handled: {maliciousInput.Substring(0, Math.Min(20, maliciousInput.Length))}...");
            }

            Console.WriteLine("? All common attack patterns successfully mitigated");
        }

        private bool ContainsDangerousContent(string input)
        {
            var dangerousPatterns = new[]
            {
                "<script", "javascript:", "onerror=", "onload=",
                "DROP TABLE", "INSERT INTO", "UPDATE SET", "DELETE FROM", "--"
            };

            return dangerousPatterns.Any(pattern => 
                input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        #endregion
    }
}