using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SafeVault.Services;
using System.Security.Claims;

namespace SafeVault.Security
{
    /// <summary>
    /// Custom authorization attribute for role-based access control
    /// </summary>
    public class SafeVaultAuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private readonly string[] _roles;
        private readonly bool _requireAuthentication;

        public SafeVaultAuthorizeAttribute(params string[] roles)
        {
            _roles = roles ?? throw new ArgumentNullException(nameof(roles));
            _requireAuthentication = true;
        }

        public SafeVaultAuthorizeAttribute(bool requireAuthentication = true)
        {
            _roles = Array.Empty<string>();
            _requireAuthentication = requireAuthentication;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // Skip authorization if action is decorated with AllowAnonymous
            if (context.ActionDescriptor.EndpointMetadata.Any(em => em.GetType() == typeof(AllowAnonymousAttribute)))
            {
                return;
            }

            var user = context.HttpContext.User;

            // Check if user is authenticated
            if (_requireAuthentication && !user.Identity!.IsAuthenticated)
            {
                context.Result = new UnauthorizedObjectResult(new { message = "Authentication required" });
                return;
            }

            // If roles are specified, check user role
            if (_roles.Any())
            {
                var userRole = user.FindFirst(ClaimTypes.Role)?.Value ?? user.FindFirst("role")?.Value;
                
                if (string.IsNullOrEmpty(userRole) || !_roles.Contains(userRole))
                {
                    context.Result = new ForbidResult();
                    return;
                }
            }

            // Log authorization attempt
            var auditService = context.HttpContext.RequestServices.GetService<IAuditService>();
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user.FindFirst("userId")?.Value;
            var ipAddress = context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var action = context.ActionDescriptor.DisplayName ?? "Unknown";

            if (auditService != null && int.TryParse(userId, out int userIdInt))
            {
                _ = Task.Run(async () =>
                {
                    await auditService.LogAsync(userIdInt, "AUTHORIZATION_SUCCESS", action, ipAddress, 
                        $"User authorized for roles: {string.Join(", ", _roles)}", true);
                });
            }
        }
    }

    /// <summary>
    /// Specific authorization attributes for different roles
    /// </summary>
    public class RequireUserRoleAttribute : SafeVaultAuthorizeAttribute
    {
        public RequireUserRoleAttribute() : base("User", "Admin", "SuperAdmin") { }
    }

    public class RequireAdminRoleAttribute : SafeVaultAuthorizeAttribute
    {
        public RequireAdminRoleAttribute() : base("Admin", "SuperAdmin") { }
    }

    public class RequireSuperAdminRoleAttribute : SafeVaultAuthorizeAttribute
    {
        public RequireSuperAdminRoleAttribute() : base("SuperAdmin") { }
    }

    /// <summary>
    /// Helper extensions for user claims
    /// </summary>
    public static class ClaimsPrincipalExtensions
    {
        public static int GetUserId(this ClaimsPrincipal user)
        {
            var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user.FindFirst("userId")?.Value;
            return int.TryParse(userIdClaim, out int userId) ? userId : 0;
        }

        public static string GetUsername(this ClaimsPrincipal user)
        {
            return user.FindFirst(ClaimTypes.Name)?.Value ?? user.FindFirst("username")?.Value ?? "Unknown";
        }

        public static string GetRole(this ClaimsPrincipal user)
        {
            return user.FindFirst(ClaimTypes.Role)?.Value ?? user.FindFirst("role")?.Value ?? "User";
        }

        public static string GetEmail(this ClaimsPrincipal user)
        {
            return user.FindFirst(ClaimTypes.Email)?.Value ?? "Unknown";
        }

        public static bool IsInRole(this ClaimsPrincipal user, params string[] roles)
        {
            var userRole = user.GetRole();
            return roles.Contains(userRole);
        }

        public static bool IsAdmin(this ClaimsPrincipal user)
        {
            return user.IsInRole("Admin", "SuperAdmin");
        }

        public static bool IsSuperAdmin(this ClaimsPrincipal user)
        {
            return user.IsInRole("SuperAdmin");
        }
    }

    /// <summary>
    /// Custom policy requirements for more complex authorization scenarios
    /// </summary>
    public class ResourceOwnerRequirement : IAuthorizationRequirement
    {
        public string ResourceIdParameter { get; }

        public ResourceOwnerRequirement(string resourceIdParameter = "id")
        {
            ResourceIdParameter = resourceIdParameter;
        }
    }

    public class ResourceOwnerHandler : AuthorizationHandler<ResourceOwnerRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public ResourceOwnerHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            ResourceOwnerRequirement requirement)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                context.Fail();
                return Task.CompletedTask;
            }

            var currentUserId = context.User.GetUserId();
            var userRole = context.User.GetRole();

            // Super admins can access any resource
            if (userRole == "SuperAdmin")
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Admins can access most resources
            if (userRole == "Admin")
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Regular users can only access their own resources
            if (httpContext.Request.RouteValues.TryGetValue(requirement.ResourceIdParameter, out var resourceIdValue))
            {
                if (int.TryParse(resourceIdValue?.ToString(), out int resourceId) && resourceId == currentUserId)
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
            }

            context.Fail();
            return Task.CompletedTask;
        }
    }
}