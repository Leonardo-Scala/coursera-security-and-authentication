using NUnit.Framework;
using SafeVault.Security;
using System.Text.Json;
using System.Text;
using Microsoft.Data.SqlClient;

namespace SafeVault.Tests
{
    [TestFixture]
    public class AdvancedSecurityTests
    {
        #region Advanced SQL Injection Tests

        [Test]
        [TestCase("admin'; WAITFOR DELAY '00:00:05'; --", "Time-based blind SQL injection")]
        [TestCase("admin'; IF (1=1) WAITFOR DELAY '00:00:01'; --", "Conditional time-based injection")]
        [TestCase("'; SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END; --", "Boolean-based blind injection")]
        [TestCase("admin' AND (SELECT COUNT(*) FROM Users) > 0 --", "Information disclosure attempt")]
        [TestCase("'; DECLARE @x VARCHAR(8000); SET @x=:; EXEC(@x); --", "Dynamic SQL execution attempt")]
        public void TestAdvancedSQLInjection_BlindAndTimeBased_ShouldBeBlocked(string payload, string description)
        {
            Console.WriteLine($"Testing: {description}");
            Console.WriteLine($"Payload: {payload}");
            
            var result = InputSanitizer.SanitizeUsername(payload);
            
            // These advanced payloads should be rejected
            Assert.That(result.IsValid, Is.False, $"Advanced SQL injection should be blocked: {description}");
            Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
            
            Console.WriteLine($"? Blocked: {description}");
        }

        [Test]
        [TestCase("1' UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema='dbo'--")]
        [TestCase("1' UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='Users'--")]
        [TestCase("admin'; SELECT @@version; --")]
        [TestCase("'; SELECT USER_NAME(); --")]
        public void TestSQLInjection_InformationSchema_ShouldBeBlocked(string payload)
        {
            Console.WriteLine($"Testing information schema attack: {payload}");
            
            var result = InputSanitizer.SanitizeUsername(payload);
            
            Assert.That(result.IsValid, Is.False, "Information schema injection should be blocked");
            
            // Ensure no information disclosure keywords pass through
            if (result.IsValid)
            {
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("information_schema"));
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("table_name"));
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("column_name"));
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("@@version"));
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("user_name"));
            }
            
            Console.WriteLine($"? Information schema attack blocked: {payload.Substring(0, Math.Min(50, payload.Length))}...");
        }

        [Test]
        public void TestSQLInjection_StackedQueries_ShouldBeBlocked()
        {
            Console.WriteLine("Testing stacked query attacks...");
            
            var stackedQueries = new[]
            {
                "admin'; CREATE TABLE hacked (id INT); --",
                "user'; DROP TABLE Users; CREATE TABLE Users (id INT); --",
                "test'; ALTER TABLE Users ADD hacked_column VARCHAR(50); --",
                "admin'; EXEC sp_addlogin 'hacker', 'password'; --"
            };

            foreach (var query in stackedQueries)
            {
                var result = InputSanitizer.SanitizeUsername(query);
                Assert.That(result.IsValid, Is.False, $"Stacked query should be blocked: {query}");
                Console.WriteLine($"? Blocked stacked query: {query.Substring(0, Math.Min(40, query.Length))}...");
            }
        }

        #endregion

        #region Advanced XSS Tests

        [Test]
        [TestCase("&lt;img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))&gt;", "Base64 encoded XSS")]
        [TestCase("<script>window['ale'+'rt']('XSS')</script>", "String concatenation XSS")]
        [TestCase("<img src=\"javascript:alert(String.fromCharCode(88,83,83))\">", "Character code XSS")]
        [TestCase("<svg><script>alert&#40;'XSS'&#41;</script></svg>", "HTML entity encoded XSS")]
        [TestCase("<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>", "Iframe srcdoc XSS")]
        public void TestAdvancedXSS_EncodingEvasion_ShouldBeBlocked(string payload, string description)
        {
            Console.WriteLine($"Testing: {description}");
            Console.WriteLine($"Payload: {payload}");
            
            var usernameResult = InputSanitizer.SanitizeUsername(payload);
            var textResult = InputSanitizer.SanitizePlainText(payload);
            
            // Advanced XSS should be blocked or completely sanitized
            if (usernameResult.IsValid)
            {
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("script"));
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("alert"));
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("javascript"));
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("eval"));
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("atob"));
                Assert.That(usernameResult.Sanitized, Does.Not.Contain("fromCharCode"));
                Console.WriteLine($"? Advanced XSS sanitized: {description}");
            }
            else
            {
                Console.WriteLine($"? Advanced XSS blocked: {description}");
            }
            
            if (textResult.IsValid)
            {
                Assert.That(textResult.Sanitized, Does.Not.Contain("<"));
                Assert.That(textResult.Sanitized, Does.Not.Contain(">"));
                Assert.That(textResult.Sanitized, Does.Not.Contain("javascript"));
            }
        }

        [Test]
        [TestCase("java\u0000script:alert('XSS')", "Null byte injection")]
        [TestCase("java\tscript:alert('XSS')", "Tab character evasion")]
        [TestCase("java\nscript:alert('XSS')", "Newline character evasion")]
        [TestCase("java\rscript:alert('XSS')", "Carriage return evasion")]
        [TestCase("java\u00A0script:alert('XSS')", "Non-breaking space evasion")]
        public void TestXSS_WhitespaceAndControlCharEvasion_ShouldBeBlocked(string payload, string description)
        {
            Console.WriteLine($"Testing: {description}");
            Console.WriteLine($"Payload representation: {string.Join("", payload.Select(c => c < 32 ? $"\\u{(int)c:X4}" : c.ToString()))}");
            
            var result = InputSanitizer.SanitizeUsername(payload);
            
            if (result.IsValid)
            {
                // Should not contain javascript after normalization
                Assert.That(result.Sanitized.ToLower(), Does.Not.Contain("javascript"));
                Assert.That(result.Sanitized, Does.Not.Contain("alert"));
                Console.WriteLine($"? Control character evasion sanitized: {description}");
            }
            else
            {
                Assert.That(result.Error, Is.Not.Null);
                Console.WriteLine($"? Control character evasion blocked: {description}");
            }
        }

        [Test]
        public void TestXSS_EventHandlers_ShouldBeBlocked()
        {
            Console.WriteLine("Testing various XSS event handlers...");
            
            var eventHandlers = new[]
            {
                "<img onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details ontoggle=alert('XSS') open>",
                "<marquee onstart=alert('XSS')>",
                "<meter onmouseenter=alert('XSS')>"
            };

            foreach (var handler in eventHandlers)
            {
                var result = InputSanitizer.SanitizePlainText(handler);
                
                if (result.IsValid)
                {
                    Assert.That(result.Sanitized, Does.Not.Contain("on"));
                    Assert.That(result.Sanitized, Does.Not.Contain("alert"));
                    Assert.That(result.Sanitized, Does.Not.Contain("<"));
                    Assert.That(result.Sanitized, Does.Not.Contain(">"));
                }
                
                Console.WriteLine($"? Event handler blocked: {handler.Substring(0, Math.Min(30, handler.Length))}...");
            }
        }

        #endregion

        #region Input Validation Edge Cases

        [Test]
        [TestCase("\u202E\u202D\u202C", "Bidirectional override characters")]
        [TestCase("\uFEFF\u200B\u200C\u200D", "Zero-width characters")]
        [TestCase("admin\u0000\u0001\u0002", "Control characters")]
        [TestCase("test\u00AD\u034F\u061C", "Soft hyphen and invisible chars")]
        public void TestInputValidation_UnicodeAttacks_ShouldBeNormalized(string payload, string description)
        {
            Console.WriteLine($"Testing: {description}");
            Console.WriteLine($"Payload (hex): {string.Join("", payload.Select(c => $"\\u{(int)c:X4}"))}");
            
            var result = InputSanitizer.SanitizeUsername(payload);
            
            if (result.IsValid)
            {
                // Should not contain problematic Unicode characters
                Assert.That(result.Sanitized, Does.Not.Contain("\u202E"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u202D"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u202C"));
                Assert.That(result.Sanitized, Does.Not.Contain("\uFEFF"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u200B"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u0000"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u0001"));
                Assert.That(result.Sanitized, Does.Not.Contain("\u0002"));
                Console.WriteLine($"? Unicode attack normalized: {description}");
            }
            else
            {
                Console.WriteLine($"? Unicode attack rejected: {description}");
            }
        }

        [Test]
        public void TestInputValidation_IDNHomographAttack_ShouldBeHandled()
        {
            Console.WriteLine("Testing IDN homograph attacks...");
            
            // Test Internationalized Domain Name (IDN) homograph attacks
            var homographEmails = new[]
            {
                "test@g??gle.com", // Greek omicron instead of 'o'
                "admin@micros?ft.com", // Mixed Greek and Latin
                "user@?pple.com", // Cyrillic '?' instead of 'a'
                "test@f?cebook.com" // Mixed Cyrillic and Latin
            };

            foreach (var email in homographEmails)
            {
                var result = InputSanitizer.SanitizeEmail(email);
                
                if (result.IsValid)
                {
                    // Should be converted to ASCII (Punycode) format
                    Assert.That(result.Sanitized, Does.Not.Contain("??")); // Greek chars
                    Assert.That(result.Sanitized, Does.Not.Contain("?")); // Cyrillic 'a'
                    Console.WriteLine($"? IDN normalized: {email} -> {result.Sanitized}");
                }
                else
                {
                    Console.WriteLine($"? IDN rejected: {email} - {result.Error}");
                }
            }
        }

        #endregion

        #region Performance and DoS Protection Tests

        [Test]
        public void TestInputValidation_LargeInput_ShouldBeRejectedQuickly()
        {
            Console.WriteLine("Testing large input handling...");
            
            // Test very large inputs that could cause DoS
            var largeInput = new string('a', 100000); // 100KB string
            
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var result = InputSanitizer.SanitizeUsername(largeInput);
            stopwatch.Stop();
            
            // Should reject large input quickly (within reasonable time)
            Assert.That(result.IsValid, Is.False);
            Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(1000), 
                "Large input validation should complete quickly");
            
            Console.WriteLine($"? Large input ({largeInput.Length:N0} chars) rejected in {stopwatch.ElapsedMilliseconds}ms");
        }

        [Test]
        public void TestInputValidation_RepeatedCharacters_ShouldBeHandledEfficiently()
        {
            Console.WriteLine("Testing repeated character patterns...");
            
            // Test inputs designed to cause regex catastrophic backtracking
            var repeatedPatterns = new[]
            {
                new string('a', 1000) + "!",
                new string('<', 500) + new string('>', 500),
                string.Join("", Enumerable.Repeat("ab", 1000)) + "!"
            };

            foreach (var pattern in repeatedPatterns)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                var result = InputSanitizer.SanitizePlainText(pattern);
                stopwatch.Stop();
                
                Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(500), 
                    $"Pattern should be processed efficiently: {pattern.Substring(0, Math.Min(50, pattern.Length))}...");
                
                Console.WriteLine($"? Pattern ({pattern.Length} chars) processed in {stopwatch.ElapsedMilliseconds}ms");
            }
        }

        #endregion

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine("SafeVault Advanced Security Tests");
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine($"Started at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();
        }

        [OneTimeTearDown] 
        public void OneTimeTearDown()
        {
            Console.WriteLine();
            Console.WriteLine("=".PadRight(60, '='));
            Console.WriteLine("Advanced Security Tests Complete");
            Console.WriteLine("=".PadRight(60, '='));
        }
    }
}