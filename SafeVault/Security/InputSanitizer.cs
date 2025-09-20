using System;
using System.Globalization;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    public sealed class SanitizationResult
    {
        public bool IsValid { get; init; }
        public string Sanitized { get; init; } = string.Empty;
        public string? Error { get; init; }

        public static SanitizationResult Valid(string value) => new() { IsValid = true, Sanitized = value };
        public static SanitizationResult Invalid(string error) => new() { IsValid = false, Error = error, Sanitized = string.Empty };
    }

    /// <summary>
    /// Input sanitizer for common web form fields.
    /// Strategy:
    /// 1) Normalize Unicode
    /// 2) Remove control & zero-width chars
    /// 3) Strip HTML tags
    /// 4) Field-specific whitelisting and validation
    /// </summary>
    public static class InputSanitizer
    {
        // Fast compiled regexes
        private static readonly Regex HtmlTagRegex = new(@"<[^>]*>", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ZeroWidthRegex = new(@"[\u200B-\u200F\u202A-\u202E\uFEFF]", RegexOptions.Compiled);
        private static readonly Regex ControlCharsRegex = new(@"[\u0000-\u001F\u007F]", RegexOptions.Compiled);
        private static readonly Regex MultiWhitespaceRegex = new(@"\s{2,}", RegexOptions.Compiled);

        // Disallowed "script-y" tokens (defense-in-depth; not a replacement for output encoding)
        private static readonly Regex DangerousTokenRegex = new(@"(?i)(?:<|>|javascript:|data:|vbscript:|on\w+\s*=|script\b)", RegexOptions.Compiled);

        // Username whitelist: letters, digits, dot, underscore, hyphen; length enforced later
        private static readonly Regex UsernameWhitelistRemove = new(@"[^A-Za-z0-9._-]", RegexOptions.Compiled);

        /// <summary>Normalize and remove typical troublemakers.</summary>
        private static string Canonicalize(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return string.Empty;
            var s = input.Normalize(NormalizationForm.FormKC).Trim();

            // Remove zero-width and control characters
            s = ZeroWidthRegex.Replace(s, string.Empty);
            s = ControlCharsRegex.Replace(s, string.Empty);

            // Strip naive HTML tags
            s = HtmlTagRegex.Replace(s, string.Empty);

            // Collapse runs of whitespace to a single space
            s = MultiWhitespaceRegex.Replace(s, " ");

            return s;
        }

        /// <summary>
        /// Sanitize a username by canonicalizing and removing disallowed chars.
        /// Rejects if result doesn't meet policy (length, allowed set).
        /// </summary>
        public static SanitizationResult SanitizeUsername(string? raw, int minLen = 3, int maxLen = 100)
        {
            var s = Canonicalize(raw);

            // Hard reject obvious script/injection tokens before whitelisting
            if (DangerousTokenRegex.IsMatch(s))
                return SanitizationResult.Invalid("Username contains dangerous sequences.");

            // Whitelist-only characters
            s = UsernameWhitelistRemove.Replace(s, string.Empty);

            if (s.Length < minLen || s.Length > maxLen)
                return SanitizationResult.Invalid($"Username length must be between {minLen} and {maxLen} characters.");

            if (string.IsNullOrEmpty(s))
                return SanitizationResult.Invalid("Username cannot be empty after sanitization.");

            return SanitizationResult.Valid(s);
        }

        /// <summary>
        /// Sanitize & validate email:
        /// - Canonicalize, strip tags
        /// - Reject if dangerous tokens present
        /// - Normalize IDN domains to ASCII (Punycode)
        /// - Validate using MailAddress
        /// Does NOT "strip" arbitrary characters to avoid changing the address meaning.
        /// </summary>
        public static SanitizationResult SanitizeEmail(string? raw, int maxLen = 100)
        {
            var s = Canonicalize(raw);

            if (string.IsNullOrWhiteSpace(s))
                return SanitizationResult.Invalid("Email is required.");

            if (DangerousTokenRegex.IsMatch(s))
                return SanitizationResult.Invalid("Email contains dangerous sequences.");

            // Basic guard: exactly one '@'
            var atIndex = s.IndexOf('@');
            if (atIndex <= 0 || atIndex != s.LastIndexOf('@') || atIndex == s.Length - 1)
                return SanitizationResult.Invalid("Email format is invalid.");

            var local = s[..atIndex];
            var domain = s[(atIndex + 1)..];

            // IDN domain -> ASCII (Punycode)
            try
            {
                var idn = new IdnMapping();
                var asciiDomain = idn.GetAscii(domain);
                s = $"{local}@{asciiDomain}";
            }
            catch
            {
                return SanitizationResult.Invalid("Email domain is invalid.");
            }

            // Final validation with MailAddress
            try
            {
                var addr = new MailAddress(s);
                if (!addr.Address.Equals(s, StringComparison.OrdinalIgnoreCase))
                    return SanitizationResult.Invalid("Email format failed canonical validation.");
            }
            catch
            {
                return SanitizationResult.Invalid("Email format is invalid.");
            }

            if (s.Length > maxLen)
                return SanitizationResult.Invalid($"Email must be at most {maxLen} characters.");

            return SanitizationResult.Valid(s);
        }

        /// <summary>
        /// Generic text sanitizer for fields that allow spaces/letters but must not contain markup or code.
        /// Uses canonicalization and then removes a conservative set of risky punctuation.
        /// Prefer rejecting when too much is removed to preserve data integrity.
        /// </summary>
        public static SanitizationResult SanitizePlainText(string? raw, int maxLen = 500)
        {
            var s = Canonicalize(raw);

            if (DangerousTokenRegex.IsMatch(s))
                return SanitizationResult.Invalid("Input contains potentially harmful content.");

            // Remove often-problematic punctuation for plain text contexts
            var removed = 0;
            var sb = new StringBuilder(s.Length);
            foreach (var ch in s)
            {
                if ("<>\"'`\\;(){}[]|".IndexOf(ch) >= 0)
                {
                    removed++;
                    continue;
                }
                sb.Append(ch);
            }
            s = sb.ToString();

            if (s.Length == 0)
                return SanitizationResult.Invalid("Input became empty after sanitization.");

            if (s.Length > maxLen)
                return SanitizationResult.Invalid($"Input exceeds maximum length of {maxLen} characters.");

            // If too much content was dropped, consider rejecting instead of silently altering user data
            if (removed > 10) // adjustable threshold
                return SanitizationResult.Invalid("Input contained too many disallowed characters.");

            return SanitizationResult.Valid(s);
        }
    }
}
