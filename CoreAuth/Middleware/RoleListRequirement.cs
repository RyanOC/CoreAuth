using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace CoreAuth.Middleware
{
    public class RoleListRequirement : IAuthorizationRequirement
    {
        public RoleListRequirement(ICollection<string> roles)
        {
            Roles = roles;
        }

        public ICollection<string> Roles { get; }
    }
}
