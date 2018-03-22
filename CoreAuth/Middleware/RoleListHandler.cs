using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace CoreAuth.Middleware
{
    public class RoleListHandler : AuthorizationHandler<RoleListRequirement>
    {
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleListRequirement requirement)
        {
            if (context.User.HasClaim(claim => claim.Type == ClaimTypes.Role) && requirement.Roles.Any(context.User.IsInRole))
            {
                context.Succeed(requirement);
            }

            await Task.CompletedTask;
        }
    }
}
