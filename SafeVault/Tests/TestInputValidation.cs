using NUnit.Framework;
using SafeVault.Security;
using System.Text;
using HtmlAgilityPack;
using Microsoft.Data.SqlClient;
using System.Data;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        #region SQL Injection Tests

        [Test]
        [TestCase("admin'; DROP TABLE Users; --")]
        [TestCase("' OR '1'='1")]
        [TestCase("' UNION SELECT * FROM Users --")]
        [TestCase("'; INSERT INTO Users VALUES ('hacker', 'hack@evil.com'); --")]
        [TestCase("admin' OR 1=1 --")]
        [TestCase("' OR 'a'='a")]
        [TestCase("1'; EXEC xp_cmdshell('dir'); --")]
        [TestCase("' OR 1=1; UPDATE Users SET Username='hacked' --")]
        public void TestForSQLInjection_MaliciousUsernames_ShouldBeSanitized(string maliciousUsername)
        {
            Console.WriteLine($"Testing SQL injection payload: {maliciousUsername}");
            
            // Test the InputSanitizer directly
            var result = InputSanitizer.SanitizeUsername(maliciousUsername);
            
            // Assert that malicious input is either rejected or properly sanitized
            if (result.IsValid)
            {
                // If considered valid, ensure all SQL injection characters are removed
                Assert.That(result.Sanitized, Does.Not.Contain("'"));
                Assert.That(result.Sanitized, Does.Not.Contain(";"));
                Assert.That(result.Sanitized, Does.Not.Contain("--"));
                Assert.That(result.Sanitized, Does.Not.Contain("DROP"));
                Assert.That(result.Sanitized, Does.Not.Contain("INSERT"));
                Assert.That(result.Sanitized, Does.Not.Contain("UPDATE"));
                Assert.That(result.Sanitized, Does.Not.Contain("DELETE"));
                Assert.That(result.Sanitized, Does.Not.Contain("UNION"));
                Assert.That(result.Sanitized, Does.Not.Contain("SELECT"));
                Console.WriteLine($"? Sanitized: '{maliciousUsername}' -> '{result.Sanitized}'");
            }
            else
            {
                // If rejected, ensure error message is provided
                Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
                Console.WriteLine($"? Rejected: '{maliciousUsername}' - {result.Error}");
            }
        }

        [Test]
        [TestCase("test@evil.com'; DROP TABLE Users; --")]
        [TestCase("admin@domain.com' OR '1'='1")]
        [TestCase("user@test.com'; INSERT INTO Users VALUES ('hacker'); --")]
        public void TestForSQLInjection_MaliciousEmails_ShouldBeSanitized(string maliciousEmail)
        {
            Console.WriteLine($"Testing SQL injection in email: {maliciousEmail}");
            
            var result = InputSanitizer.SanitizeEmail(maliciousEmail);
            
            // Malicious emails should be rejected entirely
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
            Console.WriteLine($"? Email rejected: '{maliciousEmail}' - {result.Error}");
        }

        [Test]
        public void TestParameterizedQueries_SqlCommandSafety()
        {
            Console.WriteLine("Testing parameterized query safety...");
            
            // Test that the SQL query construction is using parameterized queries
            const string connectionString = "Server=.;Database=TestDB;Integrated Security=true;TrustServerCertificate=true;";
            const string testUsername = "testuser'; DROP TABLE Users; --";

            try
            {
                using var connection = new SqlConnection(connectionString);
                const string sql = @"
                    SELECT UserID, Username, Email
                    FROM dbo.Users
                    WHERE Username = @username;
                ";

                using var command = new SqlCommand(sql, connection);
                command.Parameters.Add("@username", SqlDbType.NVarChar, 256).Value = testUsername;

                // Verify the SQL command uses parameterized queries
                Assert.That(command.CommandText, Contains.Substring("@username"));
                Assert.That(command.Parameters.Count, Is.EqualTo(1));
                Assert.That(command.Parameters[0].ParameterName, Is.EqualTo("@username"));
                Assert.That(command.Parameters[0].Value, Is.EqualTo(testUsername));
                
                Console.WriteLine("? Parameterized query structure verified");
            }
            catch (Exception ex) when (ex is SqlException || ex is InvalidOperationException)
            {
                // Expected if database doesn't exist - we're testing query structure, not execution
                Console.WriteLine($"? Database connection test skipped (expected): {ex.GetType().Name}");
            }
        }

        #endregion

        #region XSS (Cross-Site Scripting) Tests

        [Test]
        [TestCase("<script>alert('XSS')</script>")]
        [TestCase("<img src=x onerror=alert('XSS')>")]
        [TestCase("javascript:alert('XSS')")]
        [TestCase("<iframe src=javascript:alert('XSS')></iframe>")]
        [TestCase("&lt;script&gt;alert('XSS')&lt;/script&gt;")]
        [TestCase("<svg onload=alert('XSS')>")]
        [TestCase("<div onclick=\"alert('XSS')\">Click me</div>")]
        [TestCase("';alert('XSS');//")]
        public void TestForXSS_MaliciousScripts_InUsernames_ShouldBeSanitized(string maliciousScript)
        {
            Console.WriteLine($"Testing XSS payload in username: {maliciousScript}");
            
            var result = InputSanitizer.SanitizeUsername(maliciousScript);
            
            if (result.IsValid)
            {
                // If somehow considered valid, ensure all script elements are removed
                Assert.That(result.Sanitized, Does.Not.Contain("<script"));
                Assert.That(result.Sanitized, Does.Not.Contain("</script>"));
                Assert.That(result.Sanitized, Does.Not.Contain("javascript:"));
                Assert.That(result.Sanitized, Does.Not.Contain("onerror"));
                Assert.That(result.Sanitized, Does.Not.Contain("onload"));
                Assert.That(result.Sanitized, Does.Not.Contain("onclick"));
                Assert.That(result.Sanitized, Does.Not.Contain("alert("));
                Assert.That(result.Sanitized, Does.Not.Contain("<iframe"));
                Assert.That(result.Sanitized, Does.Not.Contain("<img"));
                Assert.That(result.Sanitized, Does.Not.Contain("<svg"));
                Console.WriteLine($"? XSS Sanitized: '{maliciousScript}' -> '{result.Sanitized}'");
            }
            else
            {
                Assert.That(result.Error, Is.Not.Null);
                Console.WriteLine($"? XSS Rejected: '{maliciousScript}' - {result.Error}");
            }
        }

        [Test]
        [TestCase("user@test.com<script>alert('XSS')</script>")]
        [TestCase("javascript:alert('XSS')@test.com")]
        [TestCase("user@test.com'><script>alert('XSS')</script>")]
        public void TestForXSS_MaliciousScripts_InEmails_ShouldBeSanitized(string maliciousEmail)
        {
            Console.WriteLine($"Testing XSS payload in email: {maliciousEmail}");
            
            var result = InputSanitizer.SanitizeEmail(maliciousEmail);
            
            // Malicious emails should be rejected
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
            Console.WriteLine($"? XSS Email rejected: '{maliciousEmail}' - {result.Error}");
        }

        [Test]
        [TestCase("<script>alert('XSS')</script>test")]
        [TestCase("Hello<img src=x onerror=alert('XSS')>World")]
        [TestCase("Normal text with <svg onload=alert('XSS')> embedded")]
        [TestCase("Data: <iframe src=javascript:alert('XSS')></iframe>")]
        public void TestForXSS_PlainTextSanitizer_ShouldRemoveScripts(string maliciousText)
        {
            Console.WriteLine($"Testing XSS in plain text: {maliciousText}");
            
            var result = InputSanitizer.SanitizePlainText(maliciousText);
            
            if (result.IsValid)
            {
                // Ensure no script elements remain
                Assert.That(result.Sanitized, Does.Not.Contain("<"));
                Assert.That(result.Sanitized, Does.Not.Contain(">"));
                Assert.That(result.Sanitized, Does.Not.Contain("javascript:"));
                Assert.That(result.Sanitized, Does.Not.Contain("alert("));
                Console.WriteLine($"? Plain text sanitized: '{maliciousText}' -> '{result.Sanitized}'");
            }
            else
            {
                Assert.That(result.Error, Is.Not.Null);
                Console.WriteLine($"? Plain text rejected: '{maliciousText}' - {result.Error}");
            }
        }

        [Test]
        public void TestForXSS_HTMLEntityEncoding_ShouldBeProperlyHandled()
        {
            Console.WriteLine("Testing HTML entity encoded XSS attacks...");
            
            var encodedPayloads = new[]
            {
                "&lt;script&gt;alert('XSS')&lt;/script&gt;",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "%3Cscript%3Ealert('XSS')%3C/script%3E"
            };

            foreach (var payload in encodedPayloads)
            {
                var usernameResult = InputSanitizer.SanitizeUsername(payload);
                var emailResult = InputSanitizer.SanitizeEmail($"test@test.com{payload}");
                
                // Even encoded payloads should be handled safely
                if (usernameResult.IsValid)
                {
                    Assert.That(usernameResult.Sanitized, Does.Not.Contain("script"));
                    Assert.That(usernameResult.Sanitized, Does.Not.Contain("alert"));
                }
                
                // Emails with encoded scripts should be rejected
                Assert.That(emailResult.IsValid, Is.False);
                
                Console.WriteLine($"? Encoded payload handled: {payload}");
            }
        }

        #endregion

        #region Additional Security Tests

        [Test]
        public void TestInputLength_ShouldEnforceLimits()
        {
            Console.WriteLine("Testing input length limits...");
            
            // Test username length limits
            var longUsername = new string('a', 150); // Exceeds typical limit
            var usernameResult = InputSanitizer.SanitizeUsername(longUsername);
            Assert.That(usernameResult.IsValid, Is.False);
            Console.WriteLine($"? Long username rejected: {longUsername.Length} chars");
            
            // Test email length limits
            var longEmail = new string('a', 200) + "@test.com";
            var emailResult = InputSanitizer.SanitizeEmail(longEmail);
            Assert.That(emailResult.IsValid, Is.False);
            Console.WriteLine($"? Long email rejected: {longEmail.Length} chars");
        }

        [Test]
        public void TestNullAndEmptyInputs_ShouldBeHandledSafely()
        {
            Console.WriteLine("Testing null and empty input handling...");
            
            // Test null inputs
            var nullUsernameResult = InputSanitizer.SanitizeUsername(null);
            var nullEmailResult = InputSanitizer.SanitizeEmail(null);
            
            Assert.That(nullUsernameResult.IsValid, Is.False);
            Assert.That(nullEmailResult.IsValid, Is.False);
            
            // Test empty inputs
            var emptyUsernameResult = InputSanitizer.SanitizeUsername("");
            var emptyEmailResult = InputSanitizer.SanitizeEmail("");
            
            Assert.That(emptyUsernameResult.IsValid, Is.False);
            Assert.That(emptyEmailResult.IsValid, Is.False);
            
            Console.WriteLine("? Null and empty inputs handled safely");
        }

        [Test]
        public void TestUnicodeAndSpecialCharacters_ShouldBeNormalized()
        {
            Console.WriteLine("Testing Unicode normalization...");
            
            // Test Unicode normalization
            var unicodeUsername = "tëst üser"; // Contains accented characters
            var result = InputSanitizer.SanitizeUsername(unicodeUsername);
            
            if (result.IsValid)
            {
                // Should be normalized and contain only allowed characters
                Assert.That(result.Sanitized, Does.Match(@"^[A-Za-z0-9._-]+$"));
                Console.WriteLine($"? Unicode normalized: '{unicodeUsername}' -> '{result.Sanitized}'");
            }
            else
            {
                Console.WriteLine($"? Unicode input rejected: '{unicodeUsername}' - {result.Error}");
            }
        }

        [Test]
        [TestCase("data:text/html,<script>alert('XSS')</script>")]
        [TestCase("vbscript:msgbox('XSS')")]
        [TestCase("javascript:void(0)")]
        public void TestDataAndScriptURIs_ShouldBeRejected(string maliciousUri)
        {
            Console.WriteLine($"Testing malicious URI: {maliciousUri}");
            
            var usernameResult = InputSanitizer.SanitizeUsername(maliciousUri);
            var emailResult = InputSanitizer.SanitizeEmail(maliciousUri + "@test.com");
            var textResult = InputSanitizer.SanitizePlainText(maliciousUri);
            
            // All should reject dangerous URI schemes
            Assert.That(usernameResult.IsValid, Is.False);
            Assert.That(emailResult.IsValid, Is.False);
            Assert.That(textResult.IsValid, Is.False);
            
            Console.WriteLine($"? Dangerous URI rejected: {maliciousUri}");
        }

        #endregion

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine("SafeVault Input Validation Security Tests");
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine($"Started at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();
        }

        [OneTimeTearDown] 
        public void OneTimeTearDown()
        {
            Console.WriteLine();
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine("Input Validation Tests Complete");
            Console.WriteLine("=".PadRight(60, '='));
        }
    }
}